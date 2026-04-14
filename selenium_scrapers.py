"""
Blocking Selenium scrapers for OSINT adapters.
Run via asyncio.to_thread() from async adapter code.

Requires Google Chrome installed locally. ChromeDriver is resolved via
webdriver-manager when available, otherwise Selenium Manager is used.
"""

from __future__ import annotations

import logging
import os
import re
import time
import html
from typing import Optional
from urllib.parse import parse_qs, urlparse, quote_plus

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException

logger = logging.getLogger(__name__)

try:
    from webdriver_manager.chrome import ChromeDriverManager
    _HAS_WDM = True
except ImportError:
    _HAS_WDM = False

try:
    import undetected_chromedriver as uc
    _HAS_UC = True
except ImportError:
    uc = None
    _HAS_UC = False

EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}")


def extract_emails_from_text(text: str, limit: int = 25) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in EMAIL_RE.finditer(text or ""):
        e = m.group(0)
        low = e.lower()
        if low in seen:
            continue
        seen.add(low)
        out.append(e)
        if len(out) >= limit:
            break
    return out


def _chrome_options() -> webdriver.ChromeOptions:
    opts = webdriver.ChromeOptions()
    if os.environ.get("SELENIUM_HEADLESS", "1").lower() not in ("0", "false", "no"):
        opts.add_argument("--headless=new")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    # Chrome 147+ rejects legacy "excludeSwitches" capability in some setups.
    # Avoid setting it to keep Selenium startup stable across local environments.
    opts.add_argument(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    opts.add_argument("--lang=en-US")
    return opts


def _create_driver() -> webdriver.Chrome:
    opts = _chrome_options()
    
    # Check if we should use cookie-based auth
    use_cookie_auth = os.environ.get("SELENIUM_USE_COOKIE", "0").lower() not in ("0", "false", "no")
    li_at_cookie = os.environ.get("LINKEDIN_LI_AT", "")
    
    use_undetected = os.environ.get("SELENIUM_UNDETECTED", "1").lower() not in ("0", "false", "no")

    driver = None
    
    if use_undetected and _HAS_UC:
        logger.info("Creating undetected Chrome driver via undetected_chromedriver")
        try:
            # For undetected_chromedriver, we need to handle options differently
            if hasattr(uc, 'Chrome'):
                driver = uc.Chrome(options=opts)
            else:
                driver = uc.Chrome()
            logger.info("Successfully created undetected Chrome driver")
        except Exception as exc:
            logger.warning(
                "undetected_chromedriver startup failed, falling back to normal Selenium Chrome: %s",
                exc,
            )
            driver = None

    if driver is None:
        try:
            if _HAS_WDM:
                service = Service(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=opts)
            else:
                driver = webdriver.Chrome(options=opts)
            logger.info("Successfully created normal Chrome driver")
        except Exception as exc:
            if _HAS_UC and not use_undetected:
                logger.warning(
                    "Normal Selenium Chrome startup failed, falling back to undetected_chromedriver: %s",
                    exc,
                )
                driver = uc.Chrome(options=opts)
            else:
                raise

    # Add cookie authentication if provided
    if use_cookie_auth and li_at_cookie and driver:
        try:
            driver.get("https://www.linkedin.com")
            time.sleep(2)
            driver.add_cookie({
                "name": "li_at",
                "value": li_at_cookie,
                "domain": ".linkedin.com",
                "path": "/"
            })
            logger.info("Added li_at cookie for authentication")
            driver.refresh()
            time.sleep(2)
        except Exception as e:
            logger.warning(f"Failed to add authentication cookie: {e}")

    return driver


def _normalize_google_href(href: str) -> Optional[str]:
    if not href or not href.startswith("http"):
        return None
    if "google.com/url" in href:
        try:
            q = parse_qs(urlparse(href).query).get("q", [None])[0]
            return q
        except Exception:
            return None
    return href.split("#")[0]


def _dismiss_common_banners(driver: webdriver.Chrome) -> None:
    for sel in (
        "button#ccc-notify-accept",
        "button[aria-label*='Accept']",
        "button.cookie-accept",
    ):
        try:
            els = driver.find_elements(By.CSS_SELECTOR, sel)
            if els and els[0].is_displayed():
                els[0].click()
                time.sleep(0.4)
                return
        except Exception:
            continue


def scrape_hibp_email(email: str, timeout: int = 30) -> dict:
    """Drive haveibeenpwned.com email check (no API key)."""
    driver: Optional[webdriver.Chrome] = None
    out: dict = {
        "ok": False,
        "pwned": None,
        "summary": "",
        "error": "",
    }
    try:
        driver = _create_driver()
        driver.set_page_load_timeout(timeout)
        driver.get("https://haveibeenpwned.com/")
        wait = WebDriverWait(driver, timeout)
        _dismiss_common_banners(driver)

        inp = None
        selectors = (
            (By.ID, "Account"),
            (By.CSS_SELECTOR, "input#Account"),
            (By.CSS_SELECTOR, "input[type='email']"),
            (By.CSS_SELECTOR, "input[name='Account']"),
            (
                By.XPATH,
                "//input[contains(translate(@placeholder,'EMAIL','email'),'email')]",
            ),
        )
        for by, sel in selectors:
            try:
                inp = wait.until(EC.element_to_be_clickable((by, sel)))
                break
            except TimeoutException:
                continue
        if not inp:
            out["error"] = "Could not find email input on Have I Been Pwned"
            return out

        inp.click()
        try:
            inp.clear()
        except Exception:
            inp.send_keys(Keys.CONTROL, "a")
            inp.send_keys(Keys.BACKSPACE)
        inp.send_keys(email.strip())
        inp.send_keys(Keys.RETURN)

        def _result_ready(d: webdriver.Chrome) -> bool:
            try:
                t = d.find_element(By.TAG_NAME, "body").text.lower()
            except Exception:
                return False
            return ("oh no" in t and "pwned" in t) or (
                "good news" in t and "no pwnage found" in t
            )

        try:
            WebDriverWait(driver, timeout).until(_result_ready)
        except TimeoutException:
            time.sleep(2.0)

        body = driver.find_element(By.TAG_NAME, "body").text
        out["ok"] = True
        out["summary"] = body[:6000]
        low = body.lower()
        if "oh no" in low and "pwned" in low:
            out["pwned"] = True
        elif "good news" in low and "no pwnage found" in low:
            out["pwned"] = False
        else:
            out["pwned"] = None
            if not out["error"]:
                out["error"] = "Could not parse HIBP result text (layout change or CAPTCHA)"
    except Exception as exc:
        out["error"] = str(exc)[:500]
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
    return out


def scrape_linkedin_by_name(name: str, timeout: int = 30) -> dict:
    """LinkedIn people search by keywords (often login-walled)."""
    driver: Optional[webdriver.Chrome] = None
    out: dict = {
        "ok": False,
        "query": name.strip(),
        "profile_urls": [],
        "emails": [],
        "page_excerpt": "",
        "error": "",
    }
    try:
        driver = _create_driver()
        driver.set_page_load_timeout(timeout)
        q = quote_plus(name.strip())
        driver.get(f"https://www.linkedin.com/search/results/people/?keywords={q}")
        time.sleep(3.0)
        _dismiss_common_banners(driver)

        src = driver.page_source
        body = driver.find_element(By.TAG_NAME, "body").text
        out["page_excerpt"] = body[:3500]
        out["emails"] = extract_emails_from_text(body + src)

        seen_urls: set[str] = set()
        containers = driver.find_elements(By.CSS_SELECTOR, ".reusable-search__result-container, .entity-result")
        
        if containers:
            for container in containers:
                try:
                    link_el = container.find_element(By.CSS_SELECTOR, "a[href*='linkedin.com/in/']")
                    href = link_el.get_attribute("href") or ""
                    clean = href.split("?")[0].rstrip("/")
                    
                    if clean and clean not in seen_urls:
                        seen_urls.add(clean)
                        photo_url = None
                        try:
                            img_el = container.find_element(By.TAG_NAME, "img")
                            photo_url = img_el.get_attribute("src")
                        except:
                            pass
                        
                        out["profile_urls"].append({
                            "url": clean,
                            "photo_url": photo_url
                        })
                except:
                    continue
                if len(out["profile_urls"]) >= 10:
                    break
        else:
            for a in driver.find_elements(By.CSS_SELECTOR, "a[href*='linkedin.com/in/']"):
                href = a.get_attribute("href") or ""
                clean = href.split("?")[0].rstrip("/")
                if clean and clean not in seen_urls:
                    seen_urls.add(clean)
                    out["profile_urls"].append({"url": clean, "photo_url": None})
                if len(out["profile_urls"]) >= 10:
                    break

        out["ok"] = True
        low = body.lower()
        if ("sign in" in low or "join now" in low) and not out["profile_urls"]:
            out["error"] = "LinkedIn blocked or login required; no /in/ profile URLs extracted."
    except Exception as exc:
        out["error"] = str(exc)[:500]
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
    return out


def scrape_google_person(name: str, timeout: int = 30) -> dict:
    """Google open-web search for a person's name (contact / LinkedIn hints)."""
    driver: Optional[webdriver.Chrome] = None
    out: dict = {
        "ok": False,
        "query": name.strip(),
        "result_urls": [],
        "emails": [],
        "snippets": [],
        "error": "",
    }
    try:
        driver = _create_driver()
        driver.set_page_load_timeout(timeout)
        query = quote_plus(f'"{name.strip()}" (email OR contact OR linkedin)')
        driver.get(f"https://www.google.com/search?q={query}&num=10&hl=en")
        time.sleep(2.5)

        body = driver.find_element(By.TAG_NAME, "body").text
        src = driver.page_source
        out["emails"] = extract_emails_from_text(body + src)

        snippets: list[str] = []
        for sel in ("div.VwiC3b", "span.aCOpRe", "div[data-sncf='1']"):
            for el in driver.find_elements(By.CSS_SELECTOR, sel)[:15]:
                t = (el.text or "").strip()
                if t and t not in snippets:
                    snippets.append(t[:600])
            if len(snippets) >= 6:
                break
        out["snippets"] = snippets[:8]

        seen: set[str] = set()
        for a in driver.find_elements(By.CSS_SELECTOR, "a[href^='http'], a[href^='/url']"):
            href = a.get_attribute("href") or ""
            norm = _normalize_google_href(href) or href
            if not norm or not norm.startswith("http"):
                continue
            if "google." in urlparse(norm).netloc.lower():
                continue
            base = norm.split("&")[0]
            if base not in seen:
                seen.add(base)
                out["result_urls"].append(base)
            if len(out["result_urls"]) >= 15:
                break

        out["ok"] = True
        low = body.lower()
        if "unusual traffic" in low or "captcha" in low:
            out["error"] = "Google CAPTCHA or rate limit; results may be incomplete."
    except Exception as exc:
        out["error"] = str(exc)[:500]
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
    return out


def scrape_social_photo(url: str, platform: str, timeout: int = 25) -> dict:
    """
    Extract profile photo URL for Facebook/Instagram pages and save locally.
    Uses best-effort public selectors and OpenGraph image fallback.
    """
    driver: Optional[webdriver.Chrome] = None
    result: dict = {
        "photo_url": None,
        "local_path": None,
        "error": ""
    }
    platform_l = (platform or "").strip().lower()
    if platform_l not in ("facebook", "instagram"):
        result["error"] = "Unsupported platform for social photo scrape"
        return result

    try:
        driver = _create_driver()
        driver.set_page_load_timeout(timeout)
        driver.get(url)
        time.sleep(3.0)
        _dismiss_common_banners(driver)

        if platform_l == "instagram":
            selectors = [
                "meta[property='og:image']",
                "img[alt*='profile picture']",
                "img[alt*='profile photo']",
                "img[src*='instagram'][src*='profile']",
                "img[role='img'][alt*=name]",
                "header img",
                "img[src*='instagram']",
            ]
            blocked_markers = ("log in", "sign up", "login", "please log in", "your account")
        else:
            selectors = [
                "meta[property='og:image']",
                "image[xlink\\:href]",
                "img[aria-label*='profile']",
                "img[src*='scontent']",
            ]
            blocked_markers = ("log in", "sign up", "facebook")

        body_text = ""
        try:
            body_text = (driver.find_element(By.TAG_NAME, "body").text or "").lower()
        except Exception:
            pass
        if not body_text:
            body_text = (driver.title or "").lower()

        selected = None
        for sel in selectors:
            try:
                for el in driver.find_elements(By.CSS_SELECTOR, sel):
                    src = (
                        el.get_attribute("content")
                        or el.get_attribute("src")
                        or el.get_attribute("xlink:href")
                        or ""
                    ).strip()
                    if src.startswith("http") and "data:image" not in src.lower():
                        selected = src
                        break
                if selected:
                    break
            except Exception:
                continue

        if not selected and any(m in body_text for m in blocked_markers):
            if platform_l == "instagram":
                result["error"] = "Instagram profile requires login; profile photo not accessible from public URLs (Instagram restricts profile photo downloads for non-followers)"
            else:
                result["error"] = f"{platform.title()} returned login wall; no public profile image found"
            return result

        if not selected:
            result["error"] = f"No suitable {platform.title()} profile photo found"
            return result

        result["photo_url"] = selected

        import requests
        from pathlib import Path

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "image/webp,image/apng,image/*,*/*;q=0.8",
            "Referer": url,
        }
        resp = requests.get(selected, timeout=10, headers=headers)
        resp.raise_for_status()

        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        handle = re.sub(r"[^\w\-_. ]", "_", urlparse(url).path.strip("/").split("/")[-1] or platform_l)
        local_path = output_dir / f"{platform_l}_{handle}.jpg"
        with open(local_path, "wb") as f:
            f.write(resp.content)
        result["local_path"] = str(local_path)
        return result
    except Exception as exc:
        result["error"] = str(exc)[:500]
        return result
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def scrape_bing_search_urls(query: str, timeout: int = 25, max_urls: int = 20) -> dict:
    """Run a Bing search in Selenium and return discovered outbound URLs."""
    driver: Optional[webdriver.Chrome] = None
    out = {"ok": False, "query": query, "result_urls": [], "error": ""}
    def _decode_bing_ck(href: str) -> str:
        href = html.unescape((href or "").strip())
        if href.startswith("/ck/a?"):
            href = "https://www.bing.com" + href
        if "bing.com/ck/a" not in href:
            return href
        try:
            u = parse_qs(urlparse(href).query).get("u", [""])[0]
            if not u:
                return href
            if u.startswith("http"):
                return u
            if u.startswith("a1"):
                u = u[2:]
            import base64
            token = u + "=" * (-len(u) % 4)
            decoded = base64.urlsafe_b64decode(token).decode("utf-8", errors="ignore")
            return decoded if decoded.startswith("http") else href
        except Exception:
            return href

    try:
        driver = _create_driver()
        driver.set_page_load_timeout(timeout)
        driver.get(f"https://www.bing.com/search?q={quote_plus(query)}")
        time.sleep(3.0)
        _dismiss_common_banners(driver)
        page_text = ""
        try:
            page_text = (driver.find_element(By.TAG_NAME, "body").text or "").lower()
        except Exception:
            pass
        if "please solve the challenge" in page_text or "one last step" in page_text:
            out["error"] = "Bing bot challenge/CAPTCHA page detected; no result URLs available."
            return out

        seen: set[str] = set()
        # First pass: parse page source for Bing cards like b_tpcn with ck/a links.
        source = driver.page_source or ""
        for m in re.finditer(r'href="((?:https?://www\.bing\.com)?/ck/a\?[^"]+)"', source, re.IGNORECASE):
            href = _decode_bing_ck(m.group(1))
            if not href.startswith("http"):
                continue
            host = urlparse(href).netloc.lower()
            if "bing.com" in host or "microsoft.com" in host:
                continue
            if href in seen:
                continue
            seen.add(href)
            out["result_urls"].append(href)
            if len(out["result_urls"]) >= max_urls:
                out["ok"] = True
                return out

        # Second pass: visible anchors.
        for a in driver.find_elements(By.CSS_SELECTOR, "a[href]"):
            href = (a.get_attribute("href") or "").strip()
            if not href:
                continue
            href = _decode_bing_ck(href)
            if not href.startswith("http"):
                continue
            host = urlparse(href).netloc.lower()
            if "bing.com" in host or "microsoft.com" in host:
                continue
            if href in seen:
                continue
            seen.add(href)
            out["result_urls"].append(href)
            if len(out["result_urls"]) >= max_urls:
                break

        # Third pass: parse rendered text for Instagram handles.
        # Bing sometimes shows card content with handle text but hides outbound hrefs.
        body_text = ""
        try:
            body_text = driver.find_element(By.TAG_NAME, "body").text or ""
        except Exception:
            pass
        if "instagram" in query.lower() and body_text:
            # Extract @handles from the page
            for m in re.finditer(r"@([A-Za-z0-9._]{2,30})", body_text):
                handle = m.group(1).rstrip(".,:;!?)]}\"'")
                if not handle or len(handle) < 2:
                    continue
                url = f"https://www.instagram.com/{handle}/"
                if url not in seen:
                    seen.add(url)
                    out["result_urls"].append(url)
                    if len(out["result_urls"]) >= max_urls:
                        out["ok"] = True
                        return out
        
        # Fourth pass: extract direct instagram.com URLs from page source
        # These might be visible text links or citations that weren't in href attributes
        if "instagram" in query.lower():
            source = driver.page_source or ""
            # Look for instagram.com/username patterns in the HTML
            for m in re.finditer(r'(?:href="|>|\s)(https?://(?:www\.)?instagram\.com/[A-Za-z0-9._]+/?)["\s<]', source, re.IGNORECASE):
                url = m.group(1).rstrip("/")
                if url not in seen and "bing.com" not in url.lower():
                    seen.add(url)
                    out["result_urls"].append(url)
                    if len(out["result_urls"]) >= max_urls:
                        out["ok"] = True
                        return out
        
        out["ok"] = True
    except Exception as exc:
        out["error"] = str(exc)[:500]
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
    return out