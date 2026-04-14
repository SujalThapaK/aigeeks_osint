"""Sample LinkedIn profile finder.

This script reuses the existing OSINT tool components:
- LinkedInSeleniumAdapter from osint_engine (now prefers Bing search for LinkedIn discovery)

Note: LinkedIn image extraction has been removed from the codebase.
"""

import asyncio
from pathlib import Path
import os

import aiohttp

from osint_engine import LinkedInSeleniumAdapter
from selenium_scrapers import scrape_google_person, scrape_linkedin_by_name


async def find_linkedin_profile(name: str) -> dict | None:
    """Use the existing LinkedIn adapter to discover profile URLs."""
    adapter = LinkedInSeleniumAdapter()
    connector = aiohttp.TCPConnector(ssl=False, limit=5)
    async with aiohttp.ClientSession(connector=connector) as session:
        findings = await adapter.run(name, session)

    if findings and findings[0].data.get("profile_urls"):
        return findings[0].data

    print("No LinkedIn profile URLs found by the adapter. Trying Google Selenium search fallback...")
    google = await asyncio.to_thread(scrape_google_person, name)
    if google.get("ok"):
        profile_urls = []
        seen: set[str] = set()
        for url in google.get("result_urls", []):
            if "linkedin.com/in/" in url.lower() or "linkedin.com/pub/" in url.lower():
                clean = url.split("?")[0].rstrip("/")
                if clean not in seen:
                    seen.add(clean)
                    profile_urls.append({"url": clean, "photo_url": None})
        if profile_urls:
            return {
                "query": name,
                "profile_urls": profile_urls,
                "emails": google.get("emails", []),
                "engines_used": ["google_linkedin_selenium"],
                "error": google.get("error", ""),
            }

    print("Google Selenium search fallback failed or returned no LinkedIn URLs. Trying direct LinkedIn search...")
    direct = await asyncio.to_thread(scrape_linkedin_by_name, name)
    if direct.get("ok") and direct.get("profile_urls"):
        return {
            "query": name,
            "profile_urls": direct.get("profile_urls", []),
            "emails": direct.get("emails", []),
            "engines_used": ["linkedin_selenium_search"],
            "error": direct.get("error", ""),
        }

    return findings[0].data if findings else None


async def main() -> None:
    target = "Sarad Banjara"
    print(f"Searching for LinkedIn profiles for: {target}")

    result = await find_linkedin_profile(target)
    if not result:
        print("No profile discovery result returned.")
        return

    print("Search engines used:", result.get("engines_used"))
    print("Profile URLs found:")
    for item in result.get("profile_urls", []):
        print(" -", item.get("url"))

    profile_urls = result.get("profile_urls") or []
    if not profile_urls:
        print("No LinkedIn profile URLs were discovered.")
        return

    print(f"Found {len(profile_urls)} LinkedIn profile(s) for {target}")
    print("Note: LinkedIn image extraction has been removed from the codebase.")


if __name__ == "__main__":
    asyncio.run(main())
