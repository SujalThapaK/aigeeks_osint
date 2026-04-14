"""
Test file for LinkedIn search and image extraction functionality.

This test file iterates on LinkedIn discovery and image extraction logic
using the same technologies and approaches as the main code.

KEY STRATEGY:
  - Use Bing HTML search (NOT Selenium) for LinkedIn profile discovery
  - Disable undetected chromedriver for LinkedIn operations only
  - Use photo extraction Selenium only for discovered profile URLs
  - This approach avoids login walls that block direct Selenium searches

Test targets:
  - Prapanna bista
  - Travis Haasch

Usage:
  python test_linkedin_search.py --name "Prapanna bista"
  python test_linkedin_search.py --name "Travis Haasch"
  python test_linkedin_search.py --names "Prapanna bista,Travis Haasch"
  python test_linkedin_search.py --names "Prapanna bista" --debug
"""

import asyncio
import argparse
import logging
import sys
import json
import os
from pathlib import Path
from typing import Optional, Dict, List, Any
from urllib.parse import quote_plus

import aiohttp

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Disable undetected chromedriver for LinkedIn searches
# This is LinkedIn-specific; other adapters can use it
os.environ['SELENIUM_UNDETECTED'] = '0'

# Import from main codebase
from html_search import (
    bing_html_results,
    linkedin_urls_from_results,
)


def _merge_search_rows(dst: list[dict], extra: list[dict]) -> None:
    """Merge search results, avoiding duplicates."""
    seen = {r.get("url") for r in dst if r.get("url")}
    for r in extra:
        u = r.get("url")
        if u and u not in seen:
            seen.add(u)
            dst.append(r)


def _get_headers() -> dict:
    """Get default headers for web requests."""
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }


class LinkedInSearchTester:
    """Test harness for LinkedIn search and image extraction."""
    
    def __init__(self, output_dir: str = "test_output", debug: bool = False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results = {
            "test_run": [],
            "summary": {},
        }
        self.debug = debug
    
    def _name_tokens(self, name: str) -> list[str]:
        """Extract name tokens (first, last names)."""
        import re
        return [t.lower() for t in re.findall(r"[a-zA-Z0-9]+", name) if len(t) > 1]
    
    def _filter_profile_urls_by_name(self, profile_urls: list[dict], name: str) -> list[dict]:
        """
        Filter profile URLs to keep only those matching BOTH first and last name.
        This avoids accessing unrelated profiles with similar last names.
        """
        tokens = self._name_tokens(name)
        if len(tokens) < 2:
            # If name is too short, return as-is
            return profile_urls
        
        first_name, last_name = tokens[0], tokens[-1]
        filtered = []
        
        for profile in profile_urls:
            url = profile.get("url", "").lower()
            # Check if both first and last name appear in the URL
            if first_name in url and last_name in url:
                filtered.append(profile)
        
        logger.info(f"  Profile filtering: {len(filtered)} out of {len(profile_urls)} match both '{first_name}' and '{last_name}'")
        return filtered
    
    def _save_result(self, name: str, stage: str, data: Dict[str, Any]) -> None:
        """Save intermediate result to file."""
        result_file = self.output_dir / f"{name.replace(' ', '_')}_{stage}.json"
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"Saved {stage} result to {result_file}")
    
    async def test_linkedin_search(self, name: str) -> Dict[str, Any]:
        """
        Test Step 1: Search for LinkedIn profiles using Bing HTML search.
        Uses Bing as primary search engine to avoid login walls.
        """
        logger.info(f"=" * 60)
        logger.info(f"Testing LinkedIn search for: {name}")
        logger.info(f"=" * 60)
        
        test_result = {
            "name": name,
            "stage_1": {
                "bing_query1": None,
                "bing_query2": None,
                "duckduckgo_fallback": None,
            },
            "profiles_found": 0,
            "profile_urls": [],
            "errors": [],
        }
        
        session = aiohttp.ClientSession()
        hdrs = _get_headers()
        rows: list = []
        
        try:
            # Stage 1A: Bing search with primary query
            query1 = f'"{name}" site:linkedin.com/in'
            logger.info(f"[Stage 1A] Bing search: {query1}")
            
            bing_results_1 = await bing_html_results(session, query1, hdrs, limit=15)
            test_result["stage_1"]["bing_query1"] = {
                "query": query1,
                "results_count": len(bing_results_1),
            }
            
            if bing_results_1:
                logger.info(f"✓ Bing search 1 returned {len(bing_results_1)} results")
                _merge_search_rows(rows, bing_results_1)
            else:
                logger.info(f"✗ Bing search 1 returned 0 results")
            
            # Extract LinkedIn profiles from first results
            found_urls = linkedin_urls_from_results(rows)
            test_result["profile_urls"] = [{"url": u, "photo_url": None} for u in found_urls]
            logger.info(f"  Extracted {len(found_urls)} LinkedIn profile URLs")
            
            # Stage 1B: Secondary Bing query if results are low
            if len(test_result["profile_urls"]) < 3:
                query2 = f'"{name}" linkedin.com/in'
                logger.info(f"[Stage 1B] Bing search (retry 1): {query2}")
                
                bing_results_2 = await bing_html_results(session, query2, hdrs, limit=15)
                test_result["stage_1"]["bing_query2"] = {
                    "query": query2,
                    "results_count": len(bing_results_2),
                }
                
                if bing_results_2:
                    logger.info(f"✓ Bing search 2 returned {len(bing_results_2)} results")
                    _merge_search_rows(rows, bing_results_2)
                    
                    found_urls = linkedin_urls_from_results(rows)
                    test_result["profile_urls"] = [{"url": u, "photo_url": None} for u in found_urls]
                    logger.info(f"  Extracted {len(found_urls)} LinkedIn profile URLs total")
            
            # Stage 1C: Tertiary Bing query with /in/ site filter
            if len(test_result["profile_urls"]) < 1:
                query3 = f'"{name}" site:linkedin.com/in/'
                logger.info(f"[Stage 1C] Bing search (retry 2): {query3}")
                
                bing_results_3 = await bing_html_results(session, query3, hdrs, limit=15)
                
                if bing_results_3:
                    logger.info(f"✓ Bing search 3 returned {len(bing_results_3)} results")
                    _merge_search_rows(rows, bing_results_3)
                    
                    found_urls = linkedin_urls_from_results(rows)
                    test_result["profile_urls"] = [{"url": u, "photo_url": None} for u in found_urls]
                    logger.info(f"  Extracted {len(found_urls)} LinkedIn profile URLs total")
            
            test_result["profiles_found"] = len(test_result["profile_urls"])
            
            # Filter to only profiles matching BOTH first and last name
            filtered_profiles = self._filter_profile_urls_by_name(test_result["profile_urls"], name)
            test_result["profiles_matched_full_name"] = len(filtered_profiles)
            test_result["profile_urls"] = filtered_profiles  # Use filtered list for extraction
            
            # Log discovered profiles
            if test_result["profile_urls"]:
                logger.info(f"Profiles matching full name '{name}':")
                for idx, profile in enumerate(test_result["profile_urls"][:5], 1):  # Show first 5
                    logger.info(f"  {idx}. {profile['url']}")
                if len(test_result["profile_urls"]) > 5:
                    logger.info(f"  ... and {len(test_result['profile_urls']) - 5} more")
            else:
                logger.info(f"No profiles found matching full name '{name}'")
            
            self._save_result(name, "01_search", test_result)
            
        except Exception as e:
            logger.error(f"Exception during search: {e}", exc_info=True)
            test_result["errors"].append(str(e))
        finally:
            await session.close()
        
        return test_result
    
    async def test_name(self, name: str) -> Dict[str, Any]:
        """
        Full test sequence for a single name:
        1. Search for LinkedIn profiles
        2. Filter to profiles matching BOTH first and last name
        3. Extract photo from FIRST matching profile only
        4. Save results and report
        """
        logger.info(f"\n{'#' * 70}")
        logger.info(f"# TESTING NAME: {name}")
        logger.info(f"{'#' * 70}\n")
        
        complete_result = {
            "name": name,
            "search_result": None,
            "photos": [],
            "final_summary": {},
        }
        
        # Step 1: Search
        search_result = await self.test_linkedin_search(name)
        complete_result["search_result"] = search_result
        
        # Photo extraction removed - LinkedIn image logic removed
        
        # Summary
        complete_result["final_summary"] = {
            "total_profiles_found": search_result.get("profiles_found", 0),
            "profiles_matched_full_name": search_result.get("profiles_matched_full_name", 0),
            "photos_attempted": 0,  # No photo extraction
            "photos_extracted": 0,
            "photos_saved_locally": 0,
            "search_errors": search_result.get("errors", []),
        }
        
        self._save_result(name, "99_complete", complete_result)
        
        return complete_result
    
    async def run_tests(self, names: List[str]) -> None:
        """Run complete test suite for all names."""
        logger.info(f"\n{'*' * 70}")
        logger.info(f"* LINKEDIN SEARCH TEST SUITE")
        logger.info(f"* Testing {len(names)} name(s)")
        logger.info(f"* Output directory: {self.output_dir}")
        logger.info(f"{'*' * 70}\n")
        
        all_results = []
        for name in names:
            try:
                result = await self.test_name(name)
                all_results.append(result)
            except Exception as e:
                logger.error(f"Fatal error testing {name}: {e}", exc_info=True)
                all_results.append({
                    "name": name,
                    "error": str(e),
                })
        
        # Generate summary report
        summary_report = self._generate_summary(all_results)
        self._save_result("all_tests", "00_summary", summary_report)
        
        # Print summary to console
        logger.info(f"\n{'=' * 70}")
        logger.info("TEST SUITE SUMMARY")
        logger.info(f"{'=' * 70}")
        logger.info(json.dumps(summary_report, indent=2, default=str))
    
    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate high-level summary of all test results."""
        summary = {
            "total_names_tested": len(results),
            "successful_searches": 0,
            "total_profiles_found": 0,
            "total_profiles_matched_full_name": 0,
            "total_photos_attempted": 0,
            "total_photos_extracted": 0,
            "total_photos_saved": 0,
            "details_by_name": [],
        }
        
        for result in results:
            if result.get("error"):
                summary["details_by_name"].append({
                    "name": result.get("name"),
                    "status": "FAILED",
                    "error": result.get("error"),
                })
                continue
            
            search_result = result.get("search_result", {})
            photos = result.get("photos", [])
            final_summary = result.get("final_summary", {})
            
            if search_result.get("profiles_matched_full_name", 0) > 0:
                summary["successful_searches"] += 1
            
            summary["total_profiles_found"] += final_summary.get("total_profiles_found", 0)
            summary["total_profiles_matched_full_name"] += final_summary.get("profiles_matched_full_name", 0)
            # Photo extraction removed - set to 0
            summary["total_photos_attempted"] += 0
            summary["total_photos_extracted"] += 0
            summary["total_photos_saved"] += 0
            
            summary["details_by_name"].append({
                "name": result.get("name"),
                "status": "SUCCESS",
                "total_profiles_found": final_summary.get("total_profiles_found", 0),
                "profiles_matched_full_name": final_summary.get("profiles_matched_full_name", 0),
                "photos_attempted": 0,  # No photo extraction
                "photos_extracted": 0,
                "photos_saved": 0,
                "search_errors": final_summary.get("search_errors", []),
            })
        
        return summary


async def main():
    """Entry point for test script."""
    parser = argparse.ArgumentParser(
        description="Test LinkedIn search and image extraction using Bing HTML search"
    )
    parser.add_argument(
        "--name",
        type=str,
        help="Single name to test"
    )
    parser.add_argument(
        "--names",
        type=str,
        help="Comma-separated list of names to test"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="test_output",
        help="Output directory for test results"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    args = parser.parse_args()
    
    # Determine which names to test
    names_to_test = []
    if args.name:
        names_to_test = [args.name]
    elif args.names:
        names_to_test = [n.strip() for n in args.names.split(",")]
    else:
        # Default test targets
        names_to_test = ["Prapanna bista", "Travis Haasch"]
    
    # Run tests
    tester = LinkedInSearchTester(output_dir=args.output_dir, debug=args.debug)
    await tester.run_tests(names_to_test)


if __name__ == "__main__":
    asyncio.run(main())
