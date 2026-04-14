"""
OSINT Intelligence Engine
=========================
Modular adapter-based data acquisition system.

Adapters (orchestration order):
  1. DNSWhoisAdapter — Technical Infrastructure
  2. GitHubAdapter            — Technical Infrastructure
  3. LinkedInSeleniumAdapter — Social (Bing HTML + optional Selenium)
  4. GoogleSeleniumAdapter    — Social (Bing HTML + optional Selenium)
  5. WebPresenceAdapter       — Social & Public Footprint
  6. ContextualAdapter        — Contextual & Regulatory
  7. HIBPSeleniumAdapter      — Technical Infrastructure (runs last; uses target email or
                               first email discovered by LinkedIn/Google scrapers)

Each adapter subclasses BaseAdapter and implements:
    async run(target, session) -> list[Finding]
"""

import asyncio
import json
import logging
import os
import random
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote_plus, urlparse


# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)


import aiohttp

from html_search import (
    bing_html_results,
    duckduckgo_html_results,
    emails_from_result_rows,
    filter_rows_by_name,
    filter_rows_require_full_name,
    google_html_results,
    linkedin_urls_from_results,
)
from selenium_scrapers import (
    scrape_bing_search_urls,
    scrape_google_person,
    scrape_hibp_email,
    scrape_linkedin_by_name,
    scrape_social_photo,
)

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv:
    load_dotenv(Path(__file__).resolve().parent / ".env")


# ---------------------------------------------------------------------------
# Core Data Structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    category: str
    source: str
    source_url: str
    data: dict
    confidence: float        # 0.0 – 1.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_false_positive: bool = False
    notes: str = ""


@dataclass
class InvestigationReport:
    target: str
    started_at: str
    completed_at: str = ""
    findings: list = field(default_factory=list)
    executive_summary: str = ""
    entity_map: dict = field(default_factory=dict)
    adapters_used: list = field(default_factory=list)
    total_sources: int = 0


# ---------------------------------------------------------------------------
# Base Adapter
# ---------------------------------------------------------------------------

class BaseAdapter:
    name = "BaseAdapter"
    category = "uncategorized"

    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ]

    def get_headers(self) -> dict:
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

    async def fetch(self, session: aiohttp.ClientSession, url: str, **kwargs) -> Optional[str]:
        """OPSEC-aware GET: randomised jitter delay + rotated User-Agent."""
        try:
            await asyncio.sleep(random.uniform(0.3, 1.2))
            async with session.get(
                url,
                headers=self.get_headers(),
                timeout=aiohttp.ClientTimeout(total=12),
                **kwargs,
            ) as resp:
                if resp.status == 200:
                    return await resp.text()
        except Exception:
            pass
        return None

    async def run(self, target: str,
                  session: aiohttp.ClientSession) -> list[Finding]:
        raise NotImplementedError


def _extract_email_from_target(target: str) -> Optional[str]:
    m = re.search(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
        target,
    )
    return m.group(0) if m else None


def _merge_search_rows(dst: list[dict], extra: list[dict]) -> None:
    seen = {r.get("url") for r in dst if r.get("url")}
    for r in extra:
        u = r.get("url")
        if u and u not in seen:
            seen.add(u)
            dst.append(r)


def _first_email_from_findings(findings: list[Finding]) -> Optional[str]:
    for f in findings:
        if f.is_false_positive:
            continue
        d = f.data
        if d.get("email"):
            return str(d["email"])
        for e in d.get("emails") or []:
            if e:
                return str(e)
    return None


def _filter_empty_profile_discoveries(findings: list[Finding]) -> list[Finding]:
    """
    Remove profile discovery findings that found no results.
    Keeps findings that either:
    - Have profile_urls with items (true positives)
    - Don't have profile_urls key (other finding types like Web Presence, emails, etc.)
    
    Filters out:
    - Profile discovery adapters that returned empty profile_urls AND have an error
    """
    filtered: list[Finding] = []
    for f in findings:
        data = f.data or {}
        
        # Keep if it doesn't have profile_urls (different finding type)
        if "profile_urls" not in data:
            filtered.append(f)
            continue
        
        # Keep if profile_urls has items (true positive discovery)
        profile_urls = data.get("profile_urls", [])
        if profile_urls:
            filtered.append(f)
            continue
        
        # Filter out empty profile_urls with errors (failed discovery)
        # These are failed discovery attempts, not true positive findings
        if data.get("error"):
            logger.debug(f"Filtering out empty discovery: {f.source} - {data.get('error', '')[:60]}")
            continue
        
        # Keep if no error (edge case, but keep it)
        filtered.append(f)
    
    return filtered


def _extract_platform_profile_urls(rows: list[dict], platform: str, limit: int = 8) -> list[str]:
    patterns = {
        "facebook": re.compile(
            r'https?://(?:[\w.-]+\.)?facebook\.com/(?:profile\.php\?id=\d+|people/[^/\s]+/\d+|[A-Za-z0-9.\-_%]+)/?',
            re.I,
        ),
        "instagram": re.compile(
            r'https?://(?:www\.)?instagram\.com/[A-Za-z0-9._]+/?',
            re.I,
        ),
        "youtube": re.compile(
            r'https?://(?:www\.)?youtube\.com/(?:@[^/\s]+|channel/[A-Za-z0-9_-]+|c/[^/\s]+|user/[^/\s]+)/?',
            re.I,
        ),
    }
    pat = patterns.get(platform.lower())
    if not pat:
        return []

    out: list[str] = []
    seen: set[str] = set()
    for r in rows:
        blob = f"{r.get('url', '')} {r.get('title', '')} {r.get('snippet', '')}"
        for m in pat.finditer(blob):
            u = m.group(0).split("?")[0].rstrip("/")
            if u and u not in seen:
                seen.add(u)
                out.append(u)
                if len(out) >= limit:
                    return out
    return out





# ---------------------------------------------------------------------------
# Adapter 2 — GitHub
# ---------------------------------------------------------------------------

class GitHubAdapter(BaseAdapter):
    name = "GitHub Adapter"
    category = "Technical Infrastructure"
    BASE = "https://api.github.com"

    async def run(self, target, session) -> list[Finding]:
        findings: list[Finding] = []
        query = quote_plus(target)
        gh_headers = {**self.get_headers(), "Accept": "application/vnd.github.v3+json"}
        timeout = aiohttp.ClientTimeout(total=10)

        # User / org search
        try:
            url = f"{self.BASE}/search/users?q={query}&per_page=5"
            async with session.get(url, headers=gh_headers, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("items", [])[:3]:
                        profile: dict = {}
                        try:
                            async with session.get(item["url"], headers=gh_headers, timeout=timeout) as pr:
                                if pr.status == 200:
                                    profile = await pr.json()
                        except Exception:
                            pass

                        repos: list = []
                        try:
                            async with session.get(
                                item.get("repos_url", "") + "?per_page=5&sort=updated",
                                headers=gh_headers, timeout=timeout,
                            ) as rr:
                                if rr.status == 200:
                                    rd = await rr.json()
                                    repos = [
                                        {
                                            "name":        r.get("name"),
                                            "language":    r.get("language"),
                                            "stars":       r.get("stargazers_count"),
                                            "description": r.get("description"),
                                        }
                                        for r in rd
                                    ]
                        except Exception:
                            pass

                        name_match = target.lower() in item.get("login", "").lower()
                        confidence = 0.80 if name_match else 0.45
                        email = profile.get("email", "")

                        photo_url = profile.get("avatar_url") or item.get("avatar_url", "")
                        
                        findings.append(Finding(
                            category="Technical Infrastructure",
                            source=self.name,
                            source_url=item.get("html_url", ""),
                            data={
                                "username":     item.get("login"),
                                "type":         item.get("type"),
                                "photo_url":    photo_url,
                                "public_repos": profile.get("public_repos", 0),
                                "followers":    profile.get("followers", 0),
                                "company":      profile.get("company", ""),
                                "blog":         profile.get("blog", ""),
                                "location":     profile.get("location", ""),
                                "bio":          profile.get("bio", ""),
                                "email":        email,
                                "top_repos":    repos,
                            },
                            confidence=confidence,
                            notes="Public email exposed on GitHub profile" if email else "",
                        ))
        except Exception:
            pass

        # Repository search
        try:
            url = f"{self.BASE}/search/repositories?q={query}&per_page=5&sort=stars"
            async with session.get(url, headers=gh_headers, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    repo_list = [
                        {
                            "name":         r.get("full_name"),
                            "description":  r.get("description"),
                            "stars":        r.get("stargazers_count"),
                            "language":     r.get("language"),
                            "url":          r.get("html_url"),
                            "last_updated": r.get("updated_at"),
                        }
                        for r in data.get("items", [])[:5]
                    ]
                    if repo_list:
                        findings.append(Finding(
                            category="Technical Infrastructure",
                            source=f"{self.name} (Repositories)",
                            source_url=f"https://github.com/search?q={query}&type=repositories",
                            data={"repositories": repo_list},
                            confidence=0.70,
                            notes="Public repositories identified",
                        ))
        except Exception:
            pass

        return findings


# ---------------------------------------------------------------------------
class HIBPSeleniumAdapter(BaseAdapter):
    name = "Breach Intelligence Adapter (HIBP UI)"
    category = "Technical Infrastructure"

    async def run(self, target, session) -> list[Finding]:
        findings: list[Finding] = []
        email = _extract_email_from_target(target)
        if not email:
            findings.append(
                Finding(
                    category="Technical Infrastructure",
                    source=self.name,
                    source_url="https://haveibeenpwned.com",
                    data={
                        "status": "Skipped — no email in target string",
                        "recommendation": "Include an email address in the target (e.g. "
                        '"Jane Doe jane@company.com") to run the Have I Been Pwned check.',
                    },
                    confidence=0.75,
                    notes="HIBP check requires an email address in the search string",
                )
            )
            return findings

        result = await asyncio.to_thread(scrape_hibp_email, email)
        if not result.get("ok"):
            findings.append(
                Finding(
                    category="Technical Infrastructure",
                    source=self.name,
                    source_url="https://haveibeenpwned.com",
                    data={
                        "email": email,
                        "status": "HIBP UI scrape failed",
                        "error": result.get("error", ""),
                    },
                    confidence=0.55,
                    notes="Could not complete HIBP email check",
                )
            )
            return findings

        pwned = result.get("pwned")
        summary = (result.get("summary") or "")[:4000]
        if pwned is True:
            findings.append(
                Finding(
                    category="Technical Infrastructure",
                    source=self.name,
                    source_url="https://haveibeenpwned.com",
                    data={
                        "email": email,
                        "pwned": True,
                        "hibp_excerpt": summary,
                        "method": "selenium_public_ui",
                    },
                    confidence=0.88,
                    notes="Email identified in one or more data breaches",
                )
            )
        elif pwned is False:
            findings.append(
                Finding(
                    category="Technical Infrastructure",
                    source=self.name,
                    source_url="https://haveibeenpwned.com",
                    data={
                        "email": email,
                        "pwned": False,
                        "hibp_excerpt": summary[:1200],
                        "method": "selenium_public_ui",
                    },
                    confidence=0.82,
                    notes="No known breaches reported for this email address",
                )
            )
        else:
            findings.append(
                Finding(
                    category="Technical Infrastructure",
                    source=self.name,
                    source_url="https://haveibeenpwned.com",
                    data={
                        "email": email,
                        "pwned": None,
                        "hibp_excerpt": summary[:2000],
                        "parse_error": result.get("error", ""),
                        "method": "selenium_public_ui",
                    },
                    confidence=0.50,
                    notes="HIBP result could not be parsed; verify manually",
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Adapter 3 — LinkedIn (Bing HTML search; optional Selenium)
# ---------------------------------------------------------------------------

class LinkedInSeleniumAdapter(BaseAdapter):
    name = "LinkedIn Profile Discovery"
    category = "Social & Public Footprint"

    async def run(self, target, session) -> list[Finding]:
        name = target.strip()
        if not name:
            return []
        hdrs = self.get_headers()
        engines: list[str] = []
        rows: list[dict] = []

        q1 = f"{name} site:linkedin.com/in"
        b1 = await bing_html_results(session, q1, hdrs)
        _merge_search_rows(rows, b1)
        engines.append("bing_html")
        if len(linkedin_urls_from_results(rows)) < 3:
            b2 = await bing_html_results(session, f'"{name}" linkedin profile', hdrs)
            _merge_search_rows(rows, b2)
        if len(linkedin_urls_from_results(rows)) < 3:
            b3 = await bing_html_results(session, f'"{name}" "linkedin.com/in"', hdrs)
            _merge_search_rows(rows, b3)

        rows = filter_rows_by_name(rows, name, min_score=3)
        profile_urls = [{"url": u, "photo_url": None} for u in linkedin_urls_from_results(rows)]
        emails = emails_from_result_rows(rows)
        sel_note = ""
        if os.environ.get("SELENIUM_LINKEDIN", "").lower() in ("1", "true", "yes"):
            engines.append("selenium_linkedin.com")
            s = await asyncio.to_thread(scrape_linkedin_by_name, name)
            
            # Merge Selenium profiles (possibly with photos) into profile_urls
            existing_urls = {p["url"] for p in profile_urls}
            for p in (s.get("profile_urls") or []):
                u = p["url"]
                if u not in existing_urls:
                    profile_urls.append(p)
                    existing_urls.add(u)
                else:
                    # If URL exists, try to update it with a photo if we found one now
                    for orig in profile_urls:
                        if orig["url"] == u:
                            if not orig.get("photo_url") and p.get("photo_url"):
                                orig["photo_url"] = p["photo_url"]
                            if not orig.get("local_path") and p.get("local_path"):
                                orig["local_path"] = p["local_path"]

            for e in s.get("emails") or []:
                if e not in emails:
                    emails.append(e)
            if s.get("error"):
                sel_note = f" Optional Selenium pass: {s['error']}"

        data = {
            "query": name,
            "profile_urls": profile_urls,
            "emails": emails,
            "engines_used": engines,
            "result_rows_sample": rows[:8],
            "error": "",
        }
        if not profile_urls and not emails:
            data["error"] = (
                "No LinkedIn /in URLs from Bing search results. "
                "LinkedIn blocks bots on-site; discovery uses Bing index results instead. "
                "Set SELENIUM_LINKEDIN=1 to try browser automation (often still login-walled)."
            )
            return [
                Finding(
                    category=self.category,
                    source=self.name,
                    source_url=f"https://www.bing.com/search?q={quote_plus(q1)}",
                    data=data,
                    confidence=0.55,
                    notes=data["error"],
                )
            ]
        conf = 0.78 if profile_urls else 0.55
        return [
            Finding(
                category=self.category,
                source=self.name,
                source_url=f"https://www.bing.com/search?q={quote_plus(q1)}",
                data=data,
                confidence=conf,
                notes=(
                    "LinkedIn /in URLs discovered (via Bing index results). "
                    + sel_note
                ),
            )
        ]


# ---------------------------------------------------------------------------
# Adapter 4 — Open-web people search (Bing HTML; optional Google Selenium)
# ---------------------------------------------------------------------------

class GoogleSeleniumAdapter(BaseAdapter):
    name = "Open Web People Search"
    category = "Social & Public Footprint"

    async def run(self, target, session) -> list[Finding]:
        name = target.strip()
        if not name:
            return []
        hdrs = self.get_headers()
        engines: list[str] = []
        rows: list[dict] = []

        q = f'"{name}" email OR contact OR linkedin'
        rows = await bing_html_results(session, q, hdrs)
        engines.append("bing_html")
        if len(rows) < 4:
            b2 = await bing_html_results(session, f'"{name}" contact', hdrs)
            _merge_search_rows(rows, b2)

        rows = filter_rows_by_name(rows, name, min_score=3)
        result_urls: list[str] = []
        seen_u: set[str] = set()
        snippets: list[str] = []
        for r in rows:
            u = (r.get("url") or "").split("&")[0]
            if u.startswith("http") and u not in seen_u:
                seen_u.add(u)
                result_urls.append(u)
            sn = (r.get("snippet") or "").strip()
            if sn and sn not in snippets:
                snippets.append(sn[:600])
        emails = emails_from_result_rows(rows)

        sel_note = ""
        if os.environ.get("SELENIUM_GOOGLE", "").lower() in ("1", "true", "yes"):
            engines.append("selenium_google.com")
            s = await asyncio.to_thread(scrape_google_person, name)
            for u in s.get("result_urls") or []:
                if u not in result_urls:
                    result_urls.append(u)
            for e in s.get("emails") or []:
                if e not in emails:
                    emails.append(e)
            for sn in s.get("snippets") or []:
                if sn not in snippets:
                    snippets.append(sn[:600])
            if s.get("error"):
                sel_note = f" Optional Google Selenium: {s['error']}"

        data = {
            "query": name,
            "result_urls": result_urls[:18],
            "emails": emails,
            "snippets": snippets[:10],
            "engines_used": engines,
            "error": "",
        }
        has_hits = bool(result_urls or emails)
        if not has_hits:
            data["error"] = (
                "No results from Bing search feed. "
                "Google.com via Selenium often triggers CAPTCHA; use SELENIUM_GOOGLE=1 if you accept that risk."
            )
            return [
                Finding(
                    category=self.category,
                    source=self.name,
                    source_url=f"https://www.bing.com/search?q={quote_plus(q)}",
                    data=data,
                    confidence=0.50,
                    notes=data["error"],
                )
            ]
        return [
            Finding(
                category=self.category,
                source=self.name,
                source_url=f"https://www.bing.com/search?q={quote_plus(q)}",
                data=data,
                confidence=0.72 if has_hits else 0.45,
                notes=(
                    "General web hits/contact links discovered. "
                    + sel_note
                ),
            )
        ]


# ---------------------------------------------------------------------------
# Adapter 5/6/7 — Social platform adapters
# ---------------------------------------------------------------------------

class _SocialPlatformAdapter(BaseAdapter):
    name = "Social Platform Discovery"
    category = "Social & Public Footprint"
    platform = ""
    platform_domain = ""
    supports_photo_scrape = False

    async def run(self, target, session) -> list[Finding]:
        name = target.strip()
        if not name:
            return []
        hdrs = self.get_headers()
        rows: list[dict] = []
        engines = ["bing_html"]
        q_unquoted = f"{name} site:{self.platform_domain}"
        q_quoted = f'"{name}" site:{self.platform_domain}'

        def _platform_relevance_count(candidates: list[dict]) -> int:
            d = self.platform_domain.lower()
            count = 0
            for r in candidates:
                blob = f"{r.get('url','')} {r.get('title','')} {r.get('snippet','')}".lower()
                if d in blob:
                    count += 1
            return count

        b1 = await bing_html_results(session, q_unquoted, hdrs, limit=15)
        _merge_search_rows(rows, b1)
        if len(rows) < 4 or _platform_relevance_count(rows) < 2:
            b2 = await bing_html_results(session, q_quoted, hdrs, limit=15)
            _merge_search_rows(rows, b2)
            engines.append("bing_html_quoted_fallback")
        if len(rows) < 4 or _platform_relevance_count(rows) < 2:
            _merge_search_rows(rows, await duckduckgo_html_results(session, q_unquoted, hdrs, limit=15))
            _merge_search_rows(rows, await duckduckgo_html_results(session, f"{name} {self.platform}", hdrs, limit=15))
            engines.append("duckduckgo_html")
        if len(rows) < 3 or _platform_relevance_count(rows) < 1:
            _merge_search_rows(rows, await google_html_results(session, q_unquoted, hdrs, limit=10))
            engines.append("google_html")

        strict_rows = filter_rows_require_full_name(rows, name)
        profile_urls = [{"url": u, "photo_url": None} for u in _extract_platform_profile_urls(strict_rows, self.platform)]
        if not profile_urls:
            relaxed_rows = filter_rows_by_name(rows, name, min_score=2)
            profile_urls = [{"url": u, "photo_url": None} for u in _extract_platform_profile_urls(relaxed_rows, self.platform)]
            if profile_urls:
                strict_rows = relaxed_rows
                engines.append("relaxed_name_filter")
        if not profile_urls:
            profile_urls = [{"url": u, "photo_url": None} for u in _extract_platform_profile_urls(rows, self.platform)]
            if profile_urls:
                strict_rows = rows
                engines.append("raw_row_fallback")
        if not profile_urls:
            bing_sel = await asyncio.to_thread(scrape_bing_search_urls, q_unquoted)
            if bing_sel.get("ok"):
                engines.append("selenium_bing_search")
                sel_rows = [{"url": u, "title": "", "snippet": ""} for u in (bing_sel.get("result_urls") or [])]
                profile_urls = [{"url": u, "photo_url": None} for u in _extract_platform_profile_urls(sel_rows, self.platform)]
                if profile_urls:
                    strict_rows = sel_rows
            if bing_sel.get("error"):
                engines.append("selenium_bing_error")
        emails = emails_from_result_rows(rows)
        sel_note = ""

        if self.supports_photo_scrape and profile_urls:
            first_url = profile_urls[0]["url"]
            photo = await asyncio.to_thread(scrape_social_photo, first_url, self.platform)
            if photo.get("photo_url"):
                profile_urls[0]["photo_url"] = photo["photo_url"]
            if photo.get("local_path"):
                profile_urls[0]["local_path"] = photo["local_path"]
            if photo.get("error"):
                sel_note = f" Photo scrape note: {photo['error']}"

        data = {
            "query": name,
            "platform": self.platform.title(),
            "profile_urls": profile_urls,
            "emails": emails,
            "engines_used": engines,
            "result_rows_sample": strict_rows[:8],
            "error": "",
        }
        if not profile_urls:
            data["error"] = f"No {self.platform.title()} profile URLs discovered from search engines."
            return [
                Finding(
                    category=self.category,
                    source=self.name,
                    source_url=f"https://www.bing.com/search?q={quote_plus(q_unquoted)}",
                    data=data,
                    confidence=0.50,
                    notes=data["error"],
                )
            ]
        return [
            Finding(
                category=self.category,
                source=self.name,
                source_url=f"https://www.bing.com/search?q={quote_plus(q_unquoted)}",
                data=data,
                confidence=0.76,
                notes=f"{self.platform.title()} profile discovery completed." + sel_note,
            )
        ]


class FacebookSeleniumAdapter(_SocialPlatformAdapter):
    name = "Facebook Profile Discovery"
    platform = "facebook"
    platform_domain = "facebook.com"
    supports_photo_scrape = True


class InstagramSeleniumAdapter(_SocialPlatformAdapter):
    """
    Instagram Profile Discovery
    
    Note: Instagram blocks crawler indexing, so site:instagram.com queries return no results.
    Instead, we search for the name + "instagram" and extract URLs from general web results.
    This catches links to Instagram profiles mentioned on other websites.
    """
    name = "Instagram Profile Discovery"
    platform = "instagram"
    platform_domain = "instagram.com"
    supports_photo_scrape = True

    async def run(self, target, session) -> list[Finding]:
        name = target.strip()
        if not name:
            return []
        hdrs = self.get_headers()
        rows: list[dict] = []
        engines = []
        
        # Instagram blocks crawling, so we cannot use site:instagram.com queries
        # Instead, search for name + instagram to find public mentions of their profile
        search_queries = [
            f"{name} instagram",
            f'"{name}" instagram',
            f"{name} instagram profile",
        ]
        
        # Try Bing HTML for general "name instagram" queries
        for query in search_queries:
            b_results = await bing_html_results(session, query, hdrs, limit=15)
            if b_results:
                _merge_search_rows(rows, b_results)
                engines.append(f"bing_html:{query}")
                break
        
        # Fallback to DuckDuckGo
        if len(rows) < 4:
            for query in search_queries:
                dd_results = await duckduckgo_html_results(session, query, hdrs, limit=15)
                if dd_results:
                    _merge_search_rows(rows, dd_results)
                    engines.append(f"duckduckgo_html:{query}")
                    break
        
        # Fallback to Google
        if len(rows) < 3:
            for query in search_queries:
                g_results = await google_html_results(session, query, hdrs, limit=10)
                if g_results:
                    _merge_search_rows(rows, g_results)
                    engines.append(f"google_html:{query}")
                    break
        
        # Extract Instagram profile URLs from all rows
        strict_rows = filter_rows_require_full_name(rows, name)
        profile_urls = [{"url": u, "photo_url": None} for u in _extract_platform_profile_urls(strict_rows, self.platform)]
        
        if not profile_urls:
            relaxed_rows = filter_rows_by_name(rows, name, min_score=2)
            profile_urls = [{"url": u, "photo_url": None} for u in _extract_platform_profile_urls(relaxed_rows, self.platform)]
            if profile_urls:
                strict_rows = relaxed_rows
                engines.append("relaxed_name_filter")
        
        if not profile_urls:
            profile_urls = [{"url": u, "photo_url": None} for u in _extract_platform_profile_urls(rows, self.platform)]
            if profile_urls:
                strict_rows = rows
                engines.append("raw_row_fallback")
        
        # If still no results, try Selenium to access JavaScript-rendered content
        if not profile_urls:
            for query in search_queries:
                bing_sel = await asyncio.to_thread(scrape_bing_search_urls, query)
                if bing_sel.get("ok"):
                    engines.append(f"selenium_bing_search:{query}")
                    sel_rows = [{"url": u, "title": "", "snippet": ""} for u in (bing_sel.get("result_urls") or [])]
                    profile_urls = [{"url": u, "photo_url": None} for u in _extract_platform_profile_urls(sel_rows, self.platform)]
                    if profile_urls:
                        strict_rows = sel_rows
                        break
                if bing_sel.get("error"):
                    engines.append(f"selenium_bing_error:{query}")
        
        emails = emails_from_result_rows(rows)
        sel_note = ""
        
        # Try to scrape profile photo if URL found
        if self.supports_photo_scrape and profile_urls:
            first_url = profile_urls[0]["url"]
            photo = await asyncio.to_thread(scrape_social_photo, first_url, self.platform)
            if photo.get("photo_url"):
                profile_urls[0]["photo_url"] = photo["photo_url"]
            if photo.get("local_path"):
                profile_urls[0]["local_path"] = photo["local_path"]
            if photo.get("error"):
                sel_note = f" Photo scrape note: {photo['error']}"
        
        data = {
            "query": name,
            "platform": self.platform.title(),
            "profile_urls": profile_urls,
            "emails": emails,
            "engines_used": engines,
            "result_rows_sample": strict_rows[:8],
            "error": "",
        }
        
        if not profile_urls:
            data["error"] = f"No Instagram profile URLs discovered. Instagram blocks crawler indexing, so profile discovery requires the target's Instagram handle to be mentioned publicly online."
            return [
                Finding(
                    category=self.category,
                    source=self.name,
                    source_url=f"https://www.bing.com/search?q={quote_plus(name + ' instagram')}",
                    data=data,
                    confidence=0.40,
                    notes=data["error"],
                )
            ]
        
        return [
            Finding(
                category=self.category,
                source=self.name,
                source_url=f"https://www.bing.com/search?q={quote_plus(name + ' instagram')}",
                data=data,
                confidence=0.75,
                notes=f"Instagram profile discovery completed." + sel_note,
            )
        ]


class YouTubeSeleniumAdapter(_SocialPlatformAdapter):
    name = "YouTube Profile Discovery"
    platform = "youtube"
    platform_domain = "youtube.com"
    supports_photo_scrape = False


# ---------------------------------------------------------------------------
# Adapter 8 — Web Presence / Dorking
# ---------------------------------------------------------------------------

class WebPresenceAdapter(BaseAdapter):
    name = "Web Presence Adapter"
    category = "Social & Public Footprint"

    SOCIAL_PLATFORMS = {
        "linkedin.com":  "LinkedIn",
        "twitter.com":   "Twitter/X",
        "x.com":         "Twitter/X",
        "facebook.com":  "Facebook",
        "instagram.com": "Instagram",
        "youtube.com":   "YouTube",
        "reddit.com":    "Reddit",
        "github.com":    "GitHub",
        "medium.com":    "Medium",
        "substack.com":  "Substack",
    }

    async def run(self, target, session) -> list[Finding]:
        findings: list[Finding] = []
        results: list[dict] = []
        rows = await bing_html_results(session, f'"{target}"', self.get_headers(), limit=15)
        rows = filter_rows_require_full_name(rows, target)
        for r in rows:
            link = r.get("url", "")
            if not link:
                continue
            results.append({
                "url":      link,
                "platform": urlparse(link).netloc.replace("www.", ""),
                "title":    r.get("title", ""),
                "snippet":  r.get("snippet", ""),
            })

        for result in results:
            for domain, name in self.SOCIAL_PLATFORMS.items():
                if domain in result["url"]:
                    findings.append(Finding(
                        category="Social & Public Footprint",
                        source=f"{self.name} ({name})",
                        source_url=result["url"],
                        data={
                            "platform": name,
                            "url":      result["url"],
                            "title":    result["title"],
                            "snippet":  result["snippet"],
                        },
                        confidence=0.75,
                        notes=f"Confirmed presence on {name}",
                    ))
                    break

        if results:
            findings.append(Finding(
                category="Social & Public Footprint",
                source=self.name,
                source_url=f"https://www.bing.com/search?q={quote_plus(chr(34)+target+chr(34))}",
                data={
                    "query":         target,
                    "total_results": len(results),
                    "top_results":   results[:8],
                },
                confidence=0.65,
            ))

        dork_templates = [
            (f'"{target}" filetype:pdf',           "Exposed PDF documents"),
            (f'"{target}" site:pastebin.com',      "Pastebin mentions"),
            (f'"{target}" "email" OR "contact"',   "Contact information exposure"),
            (f'"{target}" site:linkedin.com',      "LinkedIn profile"),
            (f'"{target}" inurl:resume OR inurl:cv', "Resume / CV exposure"),
        ]
        findings.append(Finding(
            category="Social & Public Footprint",
            source=f"{self.name} (Dork Templates)",
            source_url=f"https://www.google.com/search?q={quote_plus(chr(34)+target+chr(34))}",
            data={"dork_queries": [{"query": d[0], "purpose": d[1]} for d in dork_templates]},
            confidence=0.50,
            notes="Dork queries identified for manual verification",
        ))

        return findings


# ---------------------------------------------------------------------------
# Adapter 6 — Contextual & Regulatory
# ---------------------------------------------------------------------------

class ContextualAdapter(BaseAdapter):
    name = "Contextual & Regulatory Adapter"
    category = "Contextual & Regulatory"

    NEGATIVE_KEYWORDS = [
        "lawsuit", "fraud", "breach", "hack", "leak", "scandal",
        "arrest", "investigation", "fine", "penalty", "violation",
        "indicted", "charged", "criminal", "bankrupt",
    ]

    async def run(self, target, session) -> list[Finding]:
        findings: list[Finding] = []
        q = quote_plus(target)

        # Wikipedia
        wiki_url = (
            "https://en.wikipedia.org/api/rest_v1/page/summary/"
            + quote_plus(target.replace(" ", "_"))
        )
        wiki_text = await self.fetch(session, wiki_url)
        if wiki_text:
            try:
                wd = json.loads(wiki_text)
                if wd.get("type") != "disambiguation" and wd.get("extract"):
                    findings.append(Finding(
                        category="Contextual & Regulatory",
                        source=f"{self.name} (Wikipedia)",
                        source_url=wd.get("content_urls", {}).get("desktop", {}).get("page", ""),
                        data={
                            "title":       wd.get("title"),
                            "extract":     wd.get("extract", "")[:500],
                            "description": wd.get("description", ""),
                        },
                        confidence=0.90,
                        notes="Public Wikipedia profile identified",
                    ))
            except Exception:
                pass

        # OpenCorporates
        oc_url = f"https://api.opencorporates.com/v0.4/companies/search?q={q}&format=json"
        oc_text = await self.fetch(session, oc_url)
        if oc_text:
            try:
                oc_data   = json.loads(oc_text)
                companies = oc_data.get("results", {}).get("companies", [])
                corp_list = [
                    {
                        "name":               c["company"].get("name"),
                        "jurisdiction":       c["company"].get("jurisdiction_code"),
                        "company_number":     c["company"].get("company_number"),
                        "incorporation_date": c["company"].get("incorporation_date"),
                        "company_type":       c["company"].get("company_type"),
                        "status":             c["company"].get("current_status"),
                        "url":                c["company"].get("opencorporates_url"),
                    }
                    for c in companies[:5]
                ]
                if corp_list:
                    findings.append(Finding(
                        category="Contextual & Regulatory",
                        source=f"{self.name} (OpenCorporates)",
                        source_url=f"https://opencorporates.com/companies?q={q}",
                        data={"companies": corp_list},
                        confidence=0.85,
                        notes=f"Found {len(corp_list)} registered corporate entity records",
                    ))
            except Exception:
                pass

        # News search
        news_html = await self.fetch(
            session,
            f"https://html.duckduckgo.com/html/?q={q}+news&ia=news",
        )
        news_items: list[dict] = []
        if news_html:
            titles   = re.findall(r'<a class="result__a"[^>]*>([^<]+)</a>', news_html)
            links    = re.findall(r'href="(https?://[^"]+)"', news_html)
            snippets = re.findall(r'<a class="result__snippet"[^>]*>([^<]+)</a>', news_html)
            seen: set = set()
            for i, title in enumerate(titles[:8]):
                link = links[i] if i < len(links) else ""
                if not link or "duckduckgo" in link or link in seen:
                    continue
                seen.add(link)
                news_items.append({
                    "title":   title.strip(),
                    "url":     link,
                    "snippet": snippets[i].strip() if i < len(snippets) else "",
                })

        if news_items:
            combined     = " ".join(
                (it["title"] + " " + it["snippet"]).lower() for it in news_items
            )
            negative_hits = [kw for kw in self.NEGATIVE_KEYWORDS if kw in combined]
            findings.append(Finding(
                category="Contextual & Regulatory",
                source=f"{self.name} (News)",
                source_url=f"https://duckduckgo.com/?q={quote_plus(target+' news')}&ia=news",
                data={"news_items": news_items},
                confidence=0.70,
                notes=f"Identified {len(news_items)} recent news mentions",
            ))

        return findings


# ---------------------------------------------------------------------------
# Scoring and Filtering
# ---------------------------------------------------------------------------

CONFIDENCE_THRESHOLD = 0.40


def flag_false_positives(findings: list[Finding], target: str) -> list[Finding]:
    target_lower = target.lower()
    target_words = {w for w in target_lower.split() if len(w) > 3}

    for f in findings:
        if f.confidence < CONFIDENCE_THRESHOLD:
            f.is_false_positive = True
            f.notes += " [LOW CONFIDENCE – possible false positive]"
            continue

        data_str    = json.dumps(f.data, default=str).lower()
        name_present = target_lower in data_str or any(w in data_str for w in target_words)
        if not name_present and f.confidence < 0.65:
            f.is_false_positive = True
            f.notes += " [Target name not found in data – likely false positive]"

    return findings


def build_entity_map(findings: list[Finding], target: str) -> dict:
    em: dict = {
        "target":                  target,
        "domains":                 [],
        "ips":                     [],
        "emails":                  [],
        "social_profiles":         [],
        "github_handles":          [],
        "corporate_registrations": [],
    }

    def add_unique(lst, val):
        if val and val not in lst:
            lst.append(val)

    for f in findings:
        if f.is_false_positive:
            continue
        d = f.data
        if "domain" in d:
            add_unique(em["domains"], d["domain"])
        for ip in d.get("dns", {}).get("A", []):
            add_unique(em["ips"], ip)
        for email in d.get("whois", {}).get("emails", []):
            add_unique(em["emails"], email)
        if d.get("email"):
            add_unique(em["emails"], d["email"])
        for email in d.get("emails") or []:
            add_unique(em["emails"], email)
        for p in d.get("profile_urls") or []:
            url = p["url"] if isinstance(p, dict) else p
            photo = p.get("photo_url") if isinstance(p, dict) else None
            local_path = p.get("local_path") if isinstance(p, dict) else None
            platform_name = d.get("platform", "LinkedIn") if isinstance(d, dict) else "LinkedIn"
            p_obj = {
                "platform": platform_name,
                "url": url,
                "photo_url": photo,
                "photo_local_path": local_path,
            }
            if p_obj not in em["social_profiles"]:
                em["social_profiles"].append(p_obj)
        if "username" in d and f.category == "Technical Infrastructure":
            add_unique(em["github_handles"], d["username"])
        if "platform" in d:
            p = {"platform": d.get("platform"), "url": d.get("url", ""), "photo_url": d.get("photo_url")}
            if p not in em["social_profiles"]:
                em["social_profiles"].append(p)
        for co in d.get("companies", []):
            if co not in em["corporate_registrations"]:
                em["corporate_registrations"].append(co)

    # Pick a primary photo: prefer LinkedIn images first, then fallback to GitHub/other sources
    primary = None
    primary_local = None

    # Prefer a downloaded LinkedIn image file first
    for p in em["social_profiles"]:
        if p.get("platform") == "LinkedIn" and p.get("photo_local_path"):
            primary_local = p["photo_local_path"]
            break

    # Prefer a LinkedIn URL if no local LinkedIn image is available
    if not primary_local:
        for p in em["social_profiles"]:
            if p.get("platform") == "LinkedIn" and p.get("photo_url"):
                primary = p["photo_url"]
                break

    # Fallback to any downloaded image file when no LinkedIn local image exists
    if not primary_local:
        for p in em["social_profiles"]:
            if p.get("photo_local_path"):
                primary_local = p["photo_local_path"]
                break

    # Fallback to any photo URL when no LinkedIn URL exists
    if not primary:
        for p in em["social_profiles"]:
            if p.get("photo_url"):
                primary = p["photo_url"]
                break

    # Check Tech findings for GitHub photos if needed
    if not primary:
        for f in findings:
            if not f.is_false_positive and "photo_url" in f.data and f.data["photo_url"]:
                primary = f.data["photo_url"]
                break

    em["primary_photo"] = primary
    em["primary_photo_local"] = primary_local

    return em


def generate_executive_summary(
    target: str,
    findings: list,
    entity_map: dict,
) -> str:
    def attr(f, key):
        return f.get(key) if isinstance(f, dict) else getattr(f, key, None)

    valid      = [f for f in findings if not attr(f, "is_false_positive")]
    categories = list({attr(f, "category") for f in valid})
    domains    = entity_map.get("domains", [])
    emails     = entity_map.get("emails",  [])
    socials    = entity_map.get("social_profiles", [])
    github     = entity_map.get("github_handles",  [])
    corps      = entity_map.get("corporate_registrations", [])
    ips        = entity_map.get("ips", [])

    parts = [
        f"This report presents an automated intelligence gathering deep-dive into **{target}**.",
        f"Data was aggregated across {len(categories)} intelligence categories: {', '.join(categories)}.",
        f"A total of {len(valid)} validated intelligence points were identified.",
    ]
    if domains:
        parts.append(f"Identified {len(domains)} associated domain(s): {', '.join(domains[:5])}.")
    if ips:
        parts.append(f"Resolved infrastructure IP address(es): {', '.join(ips[:5])}.")
    if emails:
        parts.append(f"Publicly exposed email(s) discovered: {', '.join(emails[:5])}.")
    if socials:
        platforms = list({s['platform'] for s in socials})
        parts.append(f"Intelligence confirmed on platforms: {', '.join(platforms)}.")
    if github:
        parts.append(f"Technical presence identified on GitHub: {', '.join(github[:3])}.")
    if corps:
        parts.append(f"Corporate entity records identified in {len(corps)} jurisdiction(s).")

    parts.append(
        "All findings include source URLs and timestamps for full audit traceability. "
        "Confidence-based filtering has been applied to ensure high-fidelity remains."
    )
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

async def run_investigation(
    target: str,
    progress_cb=None,
) -> InvestigationReport:
    report = InvestigationReport(
        target=target,
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    adapters = [
        GoogleSeleniumAdapter(),
        GitHubAdapter(),
        LinkedInSeleniumAdapter(),
        InstagramSeleniumAdapter(),
        FacebookSeleniumAdapter(),
        YouTubeSeleniumAdapter(),
        WebPresenceAdapter(),
        ContextualAdapter(),
    ]
    hibp_adapter = HIBPSeleniumAdapter()
    total_steps = len(adapters) + 1

    connector = aiohttp.TCPConnector(ssl=False, limit=5)
    async with aiohttp.ClientSession(connector=connector) as session:
        for i, adapter in enumerate(adapters):
            if progress_cb:
                progress_cb(adapter.name, i + 1, total_steps)
            try:
                new_findings = await adapter.run(target, session)
                report.findings.extend(new_findings)
                report.adapters_used.append(adapter.name)
            except Exception:
                pass

        if progress_cb:
            progress_cb(hibp_adapter.name, total_steps, total_steps)
        try:
            hibp_target = target
            if not _extract_email_from_target(target):
                discovered = _first_email_from_findings(report.findings)
                if discovered:
                    hibp_target = f"{target} {discovered}"
            hibp_findings = await hibp_adapter.run(hibp_target, session)
            report.findings.extend(hibp_findings)
            report.adapters_used.append(hibp_adapter.name)
        except Exception:
            pass

    report.findings              = flag_false_positives(report.findings, target)
    report.findings              = _filter_empty_profile_discoveries(report.findings)
    report.entity_map            = build_entity_map(report.findings, target)
    report.executive_summary     = generate_executive_summary(
        target, report.findings, report.entity_map,
    )
    report.completed_at          = datetime.now(timezone.utc).isoformat()
    report.total_sources         = len(report.findings)

    return report


def run_investigation_sync(target: str) -> InvestigationReport:
    """Convenience wrapper for synchronous callers."""
    return asyncio.run(run_investigation(target))
