"""
Lightweight HTML search (DuckDuckGo + Bing) for OSINT adapters.

Avoids LinkedIn login walls and Google CAPTCHAs that block headless Selenium.
"""

from __future__ import annotations

import base64
import html
import logging
import re
from typing import Any
from urllib.parse import parse_qs, quote_plus, unquote, urlparse
import xml.etree.ElementTree as ET

import aiohttp

from selenium_scrapers import extract_emails_from_text

logger = logging.getLogger(__name__)


def _strip_tags(s: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", " ", s or ""))


def _name_tokens(name: str) -> list[str]:
    return [t.lower() for t in re.findall(r"[a-zA-Z0-9]+", name) if len(t) > 1]


def row_relevance(row: dict[str, Any], name: str) -> int:
    """
    Score how likely a row belongs to the requested person.
    """
    tokens = _name_tokens(name)
    if not tokens:
        return 0
    blob = f"{row.get('title', '')} {row.get('snippet', '')} {row.get('url', '')}".lower()
    score = 0
    for t in tokens:
        if t in blob:
            score += 2
    if len(tokens) >= 2 and all(t in blob for t in tokens[:2]):
        score += 3
    return score


def filter_rows_by_name(rows: list[dict[str, Any]], name: str, min_score: int = 3) -> list[dict[str, Any]]:
    scored: list[tuple[int, dict[str, Any]]] = []
    for r in rows:
        s = row_relevance(r, name)
        if s >= min_score:
            scored.append((s, r))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [r for _, r in scored]


def filter_rows_require_full_name(rows: list[dict[str, Any]], full_name: str) -> list[dict[str, Any]]:
    """
    Keep only rows that match the full name (not just one token).
    Rule:
      - exact phrase match (normalized whitespace) OR
      - at least the first and last token both appear
    """
    tokens = _name_tokens(full_name)
    if len(tokens) < 2:
        return filter_rows_by_name(rows, full_name, min_score=3)
    first, last = tokens[0], tokens[-1]
    phrase = " ".join(tokens)
    out: list[dict[str, Any]] = []
    for r in rows:
        blob = f"{r.get('title', '')} {r.get('snippet', '')} {r.get('url', '')}".lower()
        blob_norm = re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", blob)).strip()
        if phrase in blob_norm or (first in blob_norm and last in blob_norm):
            out.append(r)
    return out


def normalize_linkedin_profile_url(url: str) -> str | None:
    if not url or "linkedin.com" not in url.lower():
        return None
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    hostname = parsed.netloc.lower()
    if "linkedin.com" not in hostname:
        return None
    path = parsed.path or ""
    if not (path.startswith("/in/") or path.startswith("/pub/")):
        return None
    normalized = f"{parsed.scheme}://{parsed.netloc}{path.rstrip('/')}"
    return normalized


def linkedin_urls_from_results(rows: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    pat = re.compile(
        r'https?://(?:[\w.-]+\.)?linkedin\.com/(?:in|pub)/[^"\s]+',
        re.I,
    )
    logger.debug(f"Searching {len(rows)} rows for LinkedIn URLs")
    for r in rows:
        blob = f"{r.get('url', '')} {r.get('title', '')} {r.get('snippet', '')}"
        for m in pat.finditer(blob):
            nu = normalize_linkedin_profile_url(m.group(0))
            if nu and nu not in seen:
                seen.add(nu)
                out.append(nu)
                logger.debug(f"Found LinkedIn profile URL: {nu}")
        if len(out) >= 15:
            break
    logger.debug(f"Total LinkedIn profile URLs extracted: {len(out)}")
    return out


def emails_from_result_rows(rows: list[dict[str, Any]]) -> list[str]:
    blob = " ".join(
        f"{r.get('title', '')} {r.get('snippet', '')} {r.get('url', '')}" for r in rows
    )
    return extract_emails_from_text(blob)


async def duckduckgo_html_results(
    session: aiohttp.ClientSession,
    query: str,
    headers: dict[str, str],
    limit: int = 15,
) -> list[dict[str, Any]]:
    url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
    try:
        async with session.get(
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                return []
            html = await resp.text()
    except Exception:
        return []

    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for block in re.findall(
        r'<div class="result(?:__body)?".*?</div>\s*</div>',
        html,
        re.DOTALL | re.IGNORECASE,
    ):
        ma = re.search(
            r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
            block,
            re.DOTALL | re.IGNORECASE,
        )
        if not ma:
            continue
        href = html_unwrap_ddg_url(ma.group(1))
        if not href or not href.startswith("http"):
            continue
        if "duckduckgo.com" in urlparse(href).netloc.lower():
            continue
        if href in seen:
            continue
        seen.add(href)
        sm = re.search(
            r'class="result__snippet"[^>]*>(.*?)</a>',
            block,
            re.DOTALL | re.IGNORECASE,
        )
        out.append(
            {
                "url": href,
                "title": _strip_tags(ma.group(2)).strip(),
                "snippet": _strip_tags(sm.group(1)).strip() if sm else "",
            }
        )
        if len(out) >= limit:
            break
    return out


def html_unwrap_ddg_url(href: str) -> str:
    if not href:
        return ""
    if href.startswith("//"):
        href = "https:" + href
    if href.startswith("/"):
        try:
            q = parse_qs(urlparse("https://duckduckgo.com" + href).query)
            uddg = q.get("uddg", [None])[0]
            if uddg:
                return unquote(uddg)
        except Exception:
            return ""
    return html.unescape(href)


def _bing_unwrap_url(href: str) -> str:
    href = html.unescape(href or "")
    if href.startswith("/ck/a?"):
        href = "https://www.bing.com" + href
    if "bing.com/ck/a" not in href:
        return href
    try:
        u = parse_qs(urlparse(href).query).get("u", [None])[0]
        if not u:
            return href
        candidate = unquote(u)
        if candidate.startswith("http"):
            return candidate

        # Common Bing ck/a variant prefixes base64 URL payload with "a1".
        if candidate.startswith("a1"):
            candidate = candidate[2:]

        # Bing may encode the target URL in a URL-safe base64 token.
        for start in range(0, min(len(candidate), 4)):
            try:
                token = candidate[start:]
                token += "=" * (-len(token) % 4)
                decoded = base64.urlsafe_b64decode(token).decode("utf-8")
                if decoded.startswith("http"):
                    return decoded
            except Exception:
                continue
    except Exception:
        pass
    return href


async def bing_html_results(
    session: aiohttp.ClientSession,
    query: str,
    headers: dict[str, str],
    limit: int = 12,
) -> list[dict[str, Any]]:
    # Prefer Bing RSS format for stable parsing.
    rss_url = f"https://www.bing.com/search?format=rss&q={quote_plus(query)}&count={limit}"
    site_domain = None
    m_site = re.search(r"site:([a-z0-9.-]+)", query.lower())
    if m_site:
        site_domain = m_site.group(1).strip()
    try:
        async with session.get(
            rss_url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status == 200:
                body = await resp.text()
                root = ET.fromstring(body)
                out: list[dict[str, Any]] = []
                for item in root.findall("./channel/item"):
                    title = (item.findtext("title") or "").strip()
                    link_raw = (item.findtext("link") or "").strip()
                    link = _bing_unwrap_url(link_raw)
                    desc = (item.findtext("description") or "").strip()
                    if not link:
                        continue
                    out.append({
                        "url": link,
                        "title": _strip_tags(title),
                        "snippet": _strip_tags(desc)[:600],
                    })
                    if len(out) >= limit:
                        break
                if out:
                    if site_domain:
                        relevant = 0
                        for r in out:
                            blob = f"{r.get('url','')} {r.get('title','')} {r.get('snippet','')}".lower()
                            if site_domain in blob:
                                relevant += 1
                        if relevant == 0:
                            # RSS feed can be noisy/irrelevant for site-filtered queries.
                            # Fall through to HTML parser for better extraction.
                            pass
                        else:
                            return out
                    else:
                        return out
    except Exception:
        pass

    # Fallback to regular HTML parsing.
    url = f"https://www.bing.com/search?q={quote_plus(query)}&count=12"
    try:
        async with session.get(
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                return []
            html = await resp.text()
    except Exception:
        return []

    out: list[dict[str, Any]] = []
    for m in re.finditer(
        r'<li class="b_algo"[^>]*>(.*?)</li>',
        html,
        re.DOTALL | re.IGNORECASE,
    ):
        block = m.group(1)
        ma = re.search(
            r'<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>\s*([^<]+?)\s*</a>',
            block,
            re.DOTALL,
        )
        if not ma:
            continue
        href = _bing_unwrap_url(ma.group(1))
        title = _strip_tags(ma.group(2)).strip()
        sm = re.search(r"<p[^>]*>([\s\S]*?)</p>", block)
        snippet = _strip_tags(sm.group(1)).strip()[:600] if sm else ""
        out.append({"url": href, "title": title, "snippet": snippet})
        if len(out) >= limit:
            break

    # Supplemental pass: capture additional Bing result cards (e.g. b_tpcn)
    # that may not be emitted as classic b_algo blocks.
    if len(out) < limit:
        seen_urls = {r.get("url") for r in out if r.get("url")}
        for m in re.finditer(r'href="((?:https?://www\.bing\.com)?/ck/a\?[^"]+)"', html, re.IGNORECASE):
            href = m.group(1)
            final = _bing_unwrap_url(href)
            if not final or not final.startswith("http"):
                continue
            if "bing.com" in urlparse(final).netloc.lower():
                continue
            if final in seen_urls:
                continue
            seen_urls.add(final)
            out.append({"url": final, "title": "", "snippet": ""})
            if len(out) >= limit:
                break
        
        # Additional pass: Look for direct Instagram URLs in HTML (especially from knowledge cards)
        # These might appear as cite text or in hidden divs
        if len(out) < limit:
            for m in re.finditer(r'https?://(?:www\.)?instagram\.com/[A-Za-z0-9._]+/?', html, re.IGNORECASE):
                url = m.group(0).rstrip("/")
                if url not in seen_urls and "bing.com" not in url.lower():
                    seen_urls.add(url)
                    out.append({"url": url, "title": "", "snippet": ""})
                    if len(out) >= limit:
                        break
        
        # Additional pass: Look for direct LinkedIn profile URLs in HTML
        # Catches cases where images appear on top of results with different HTML structure
        if len(out) < limit:
            for m in re.finditer(r'href="(https?://(?:[\w.-]+\.)?linkedin\.com/(?:in|pub)/[^"]+)"', html, re.IGNORECASE):
                url = m.group(1).split("?")[0].rstrip("/")
                if url not in seen_urls:
                    seen_urls.add(url)
                    out.append({"url": url, "title": "", "snippet": ""})
                    if len(out) >= limit:
                        break
    
    return out


async def google_html_results(
    session: aiohttp.ClientSession,
    query: str,
    headers: dict[str, str],
    limit: int = 10,
) -> list[dict[str, Any]]:
    """
    Attempt to fetch Google search results via HTML.
    Note: This is best-effort; Google heavily blocks automated access.
    Falls back gracefully if unavailable.
    """
    url = f"https://www.google.com/search?q={quote_plus(query)}&num={limit}"
    logger.debug(f"Fetching: {url}")
    try:
        async with session.get(
            url,
            headers={**headers, "Accept-Language": "en-US,en;q=0.9"},
            timeout=aiohttp.ClientTimeout(total=8),
        ) as resp:
            if resp.status != 200:
                logger.warning(f"HTTP {resp.status}")
                return []
            html = await resp.text()
            logger.debug(f"Got {len(html)} bytes of HTML")
    except Exception as e:
        logger.error(f"Fetch error: {e}")
        return []

    out: list[dict[str, Any]] = []
    
    # Google redirect URL unwrapper
    def unwrap_google_url(href: str) -> str | None:
        """Extract actual URL from Google's /url?q= redirect."""
        if not href:
            return None
        # Skip non-http and internal Google URLs
        if href.startswith("/"):
            if "/url?q=" in href:
                try:
                    params = parse_qs(urlparse(f"https://google.com{href}").query)
                    result = params.get("q", [None])[0]
                    logger.debug(f"Unwrapped redirect: {result}")
                    return result
                except Exception as e:
                    logger.debug(f"Unwrap error: {e}")
                    return None
            return None
        if not href.startswith("http"):
            return None
        # Check if it's a Google/cache URL (skip these)
        parsed = urlparse(href)
        if "google.com" in parsed.netloc or "webcache.google" in parsed.netloc:
            if "/url?q=" in href:
                try:
                    params = parse_qs(parsed.query)
                    result = params.get("q", [None])[0]
                    logger.debug(f"Unwrapped Google URL: {result}")
                    return result
                except Exception:
                    pass
            return None
        logger.debug(f"Keeping direct URL: {href}")
        return href
    
    # Try to extract results from Google's HTML structure
    seen_urls: set[str] = set()
    
    # More comprehensive patterns to match actual Google HTML
    patterns = [
        # Direct href to LinkedIn (what we're seeing)
        r'<a[^>]+href="(https?://[a-z0-9.-]*linkedin\.com/in/[^"]+)"[^>]*>[^<]*<h[23][^>]*>([^<]+)</h[23]>',
        # href attribute before h3
        r'<a[^>]+href="(https?://[^"]+)"[^>]*>[^<]*<h3[^>]*>([^<]+)</h3>',
        # Google redirect format: /url?q=...
        r'<a\s+[^>]*href="(/url\?[^"]*q=([^&"]+)[^"]*)"[^>]*>[^<]*<h3[^>]*>([^<]+)</h3>',
        # Alternative: h3 before a href
        r'<h3[^>]*><a[^>]+href="(https?://[^"]+)"[^>]*>([^<]+)</a></h3>',
        # Catch all: any href with h3 nearby
        r'href="(https?://[^"]+)"[^>]*[^<]*<h3[^>]*>([^<]+)</h3>',
    ]
    
    for i, pattern in enumerate(patterns):
        if out:
            break
        logger.debug(f"Trying pattern {i+1}/{len(patterns)}")
        matching_count = 0
        
        for m in re.finditer(pattern, html, re.DOTALL | re.IGNORECASE):
            matching_count += 1
            try:
                groups = m.groups()
                if len(groups) >= 2:
                    href = groups[0]
                    title = groups[-1] if len(groups) > 1 else ""
                    
                    logger.debug(f"Found match: {href[:60]}... title={title[:40]}...")
                    
                    # Unwrap Google redirect URLs
                    final_url = unwrap_google_url(href)
                    
                    if final_url and final_url.startswith("http"):
                        if final_url not in seen_urls:
                            seen_urls.add(final_url)
                            out.append({
                                "url": final_url,
                                "title": _strip_tags(title).strip(),
                                "snippet": "",
                            })
                            logger.debug(f"Added URL: {final_url}")
                            if len(out) >= limit:
                                break
            except Exception as e:
                logger.debug(f"Match error: {e}")
                continue
        
        logger.debug(f"Pattern {i+1} matched {matching_count} times, got {len(out)} valid URLs")
    
    # Supplemental pass: If pattern matching didn't work well, try direct URL extraction
    # This catches cases where images appear on top of results (different HTML structure)
    if len(out) < limit // 2:
        logger.debug("Pattern matching yielded few results, trying direct URL extraction")
        # Look for direct LinkedIn URLs in href attributes (not Google redirects)
        for m in re.finditer(r'href="(https?://(?:[\w.-]+\.)?linkedin\.com/in/[^"]+)"', html, re.IGNORECASE):
            url = m.group(1).split("?")[0].rstrip("/")
            if url not in seen_urls:
                seen_urls.add(url)
                out.append({
                    "url": url,
                    "title": "",
                    "snippet": "",
                })
                logger.debug(f"Added direct LinkedIn URL: {url}")
                if len(out) >= limit:
                    break
    
    logger.info(f"Total URLs found: {len(out)}")
    return out
