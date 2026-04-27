"""
DuckDuckGo HTML search scraper for Brand Shield.
No API key required — uses DuckDuckGo's public HTML endpoint.
Rate limit: be polite; 1-2 second delays between queries.
"""
import time
import logging
import re
from urllib.parse import urlparse, urlencode, quote_plus

logger = logging.getLogger(__name__)

DDG_HTML_URL = "https://html.duckduckgo.com/html/"
DDG_LITE_URL = "https://lite.duckduckgo.com/lite/"

# Per-request timeout (seconds). Kept tight so a blocked endpoint doesn't
# burn the whole scan window — with ~24 queries × old 20s timeout the
# free-tier scan was 8+ minutes of pure timeouts.
REQUEST_TIMEOUT = 8

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.9",
    # NOTE: Do NOT include 'br' (brotli) — requests can't decode brotli without
    # the brotli package, and DDG will serve brotli if we advertise support.
    "Accept-Encoding": "gzip, deflate",
    "Referer": "https://duckduckgo.com/",
    "DNT": "1",
}


def detect_platform(url: str) -> str:
    """Detect which platform a URL belongs to."""
    domain = urlparse(url).netloc.lower()
    platform_map = {
        "instagram.com": "instagram",
        "tiktok.com": "tiktok",
        "twitter.com": "twitter",
        "x.com": "twitter",
        "youtube.com": "youtube",
        "youtu.be": "youtube",
        "facebook.com": "facebook",
        "fb.com": "facebook",
        "amazon.co.uk": "amazon",
        "amazon.com": "amazon",
        "ebay.co.uk": "ebay",
        "ebay.com": "ebay",
        "etsy.com": "etsy",
        "shopify.com": "shopify",
        "myshopify.com": "shopify",
        "teespring.com": "merch",
        "redbubble.com": "merch",
        "aliexpress.com": "aliexpress",
        "wish.com": "wish",
    }
    for key, platform in platform_map.items():
        if key in domain:
            return platform
    return "web"


def _unwrap_ddg_url(raw_url: str) -> str:
    """Unwrap DDG redirect URLs (l/?uddg=...) into the real destination."""
    from urllib.parse import parse_qs, urlparse as _up
    if not raw_url:
        return ""
    if "duckduckgo.com/l/" in raw_url or raw_url.startswith("/l/?"):
        full = raw_url if raw_url.startswith("http") else "https://duckduckgo.com" + raw_url
        try:
            qs = parse_qs(_up(full).query)
            return qs.get("uddg", [raw_url])[0]
        except Exception:
            return raw_url
    return raw_url


def _parse_html_results(html: str, num_results: int) -> list:
    """Parse the html.duckduckgo.com response into result dicts."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    out = []
    for div in soup.find_all("div", class_="result"):
        if len(out) >= num_results:
            break
        if "result--ad" in (div.get("class") or []):
            continue
        title_tag = div.find("a", class_="result__a")
        if not title_tag:
            continue
        title = title_tag.get_text(strip=True)
        real_url = _unwrap_ddg_url(title_tag.get("href", ""))
        if not real_url or real_url.startswith("javascript") or "duckduckgo.com" in real_url:
            continue
        snippet_tag = div.find("a", class_="result__snippet")
        snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
        out.append({
            "title": title,
            "url": real_url,
            "snippet": snippet,
            "platform": detect_platform(real_url),
        })
    return out


def _parse_lite_results(html: str, num_results: int) -> list:
    """Parse the lite.duckduckgo.com response. Lite uses a flat <table> layout
    with result links on rows whose first <a> is the title; the snippet is in
    the next row's td.
    """
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    out = []
    seen = set()
    # Lite results: each result link has class "result-link" in modern lite,
    # or is the first <a> in a row with non-empty href in older variants.
    anchors = soup.select("a.result-link") or [
        a for a in soup.find_all("a") if a.get("href", "").startswith(("/l/?", "http"))
    ]
    for a in anchors:
        if len(out) >= num_results:
            break
        real_url = _unwrap_ddg_url(a.get("href", ""))
        if not real_url or real_url in seen:
            continue
        if real_url.startswith("javascript") or "duckduckgo.com" in real_url:
            continue
        seen.add(real_url)
        title = a.get_text(strip=True)
        if not title:
            continue
        # Snippet usually lives a couple of siblings down — best-effort.
        snippet = ""
        parent_tr = a.find_parent("tr")
        if parent_tr is not None:
            nxt = parent_tr.find_next_sibling("tr")
            if nxt is not None:
                td = nxt.find("td", class_="result-snippet") or nxt.find("td")
                if td:
                    snippet = td.get_text(strip=True)
        out.append({
            "title": title,
            "url": real_url,
            "snippet": snippet,
            "platform": detect_platform(real_url),
        })
    return out


def _ddg_search(query: str, num_results: int = 10) -> list:
    """
    Execute a DuckDuckGo search and parse results.
    Tries the HTML endpoint first, falls back to the LITE endpoint when the
    HTML endpoint returns 0 parseable results (which happens when DDG serves
    a CAPTCHA, an empty SERP for the bot UA, or a 202 anti-bot interstitial).

    Returns list of {title, url, snippet, platform} dicts.
    Raises RuntimeError when BOTH endpoints fail in a way the caller should
    surface (network error or zero parseable results from both).
    """
    import requests

    last_error = None
    params = {"q": query, "kl": "uk-en", "kp": "-1"}

    # Attempt 1: html endpoint
    try:
        response = requests.post(
            DDG_HTML_URL,
            data=params,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        response.raise_for_status()
        results = _parse_html_results(response.text, num_results)
        if results:
            return results
        # If html returned 0 parseable results, treat as soft-block and try lite.
        logger.info(f"DDG html returned 0 results for '{query[:60]}' — trying lite")
    except requests.exceptions.RequestException as e:
        last_error = e
        logger.warning(f"DDG html failed for '{query[:60]}': {e}")
    except Exception as e:
        last_error = e
        logger.error(f"DDG html parse error for '{query[:60]}': {e}")

    # Attempt 2: lite endpoint
    try:
        response = requests.post(
            DDG_LITE_URL,
            data=params,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        response.raise_for_status()
        results = _parse_lite_results(response.text, num_results)
        if results:
            return results
        logger.warning(f"DDG lite also returned 0 results for '{query[:60]}'")
    except requests.exceptions.RequestException as e:
        last_error = e
        logger.warning(f"DDG lite failed for '{query[:60]}': {e}")
    except Exception as e:
        last_error = e
        logger.error(f"DDG lite parse error for '{query[:60]}': {e}")

    # Both endpoints failed or returned nothing parseable.
    if last_error is not None:
        raise RuntimeError(f"DDG both endpoints failed: {last_error}")
    return []


def build_search_queries(brand_key: str, brand_config: dict) -> list:
    """Build targeted search queries for a brand."""
    queries = []
    display_name = brand_config.get("display_name", brand_key)
    handles = brand_config.get("platform_handles", {})
    keywords = brand_config.get("keywords", [])
    product_names = brand_config.get("product_names", [])
    verified_urls = brand_config.get("verified_urls", [])

    # Build exclusion list from verified domains
    exclusions = ""
    for url in verified_urls:
        domain = urlparse(url).netloc.replace("www.", "")
        if domain:
            exclusions += f" -site:{domain}"

    # Exclude official handles on each platform
    for platform, handle in handles.items():
        if platform == "instagram":
            exclusions += f" -site:instagram.com/{handle}"
        elif platform == "twitter":
            exclusions += f" -site:twitter.com/{handle} -site:x.com/{handle}"
        elif platform == "tiktok":
            exclusions += f" -site:tiktok.com/@{handle}"
        elif platform == "youtube":
            exclusions += f" -site:youtube.com/@{handle}"

    # 1. Name impersonation on social platforms
    queries.append({
        "q": f'"{display_name}" site:instagram.com{exclusions}',
        "type": "impersonation",
        "brand": brand_key,
    })
    queries.append({
        "q": f'"{display_name}" site:tiktok.com{exclusions}',
        "type": "impersonation",
        "brand": brand_key,
    })
    queries.append({
        "q": f'"{display_name}" (fake OR scam OR unofficial OR impersonat*)',
        "type": "impersonation",
        "brand": brand_key,
    })

    # 2. Username variation impersonation
    brand_clean = brand_key.strip("@")
    queries.append({
        "q": (
            f'("{brand_clean}" OR "{brand_clean} official" OR "real {brand_clean}") '
            f'site:instagram.com{exclusions}'
        ),
        "type": "impersonation",
        "brand": brand_key,
    })

    # 3. Counterfeit products (for @byerim)
    for product in product_names[:3]:
        queries.append({
            "q": f'"{product}" (buy OR shop OR order OR price OR "for sale"){exclusions}',
            "type": "counterfeit",
            "brand": brand_key,
        })
        queries.append({
            "q": f'"{product}" site:amazon.co.uk OR site:amazon.com OR site:ebay.co.uk',
            "type": "counterfeit",
            "brand": brand_key,
        })
        queries.append({
            "q": f'"{product}" site:etsy.com OR site:aliexpress.com OR site:wish.com',
            "type": "counterfeit",
            "brand": brand_key,
        })

    # 4. Fake shop detection
    queries.append({
        "q": f'"{brand_clean}" (shop OR store OR buy) -site:byerim.com{exclusions}',
        "type": "counterfeit",
        "brand": brand_key,
    })

    # 5. Content theft / unauthorized use
    queries.append({
        "q": f'"{display_name}" (content OR video OR photo) -site:byerim.com{exclusions}',
        "type": "content_theft",
        "brand": brand_key,
    })

    # 6. Keyword-based
    if keywords:
        top_kws = keywords[:3]
        kw_str = " OR ".join(f'"{k}"' for k in top_kws)
        queries.append({
            "q": f'({kw_str}) (counterfeit OR fake OR replica OR unauthorized)',
            "type": "content_theft",
            "brand": brand_key,
        })

    return queries


class DDGBackendBlocked(RuntimeError):
    """Raised when both DDG endpoints fail/return-empty for the whole batch.
    The scanner uses this to mark the scan as failed instead of silently completing.
    """


def search_brand(brand_key: str, brand_config: dict, rate_delay: float = 2.0) -> list:
    """
    Run all DDG search queries for a brand and return aggregated results.

    Returns list of dicts:
        [{url, title, snippet, platform, query_type, brand}, ...]

    Raises DDGBackendBlocked if every query in the batch failed/returned 0
    results — signals the caller that the search backend is unreachable so a
    silent "0 threats found" result isn't recorded as a successful scan.
    """
    queries = build_search_queries(brand_key, brand_config)
    all_results = []
    seen_urls: set = set()

    failures = 0
    empty_returns = 0

    logger.info(f"[DDG] Starting {len(queries)} queries for {brand_key}")

    for i, query_info in enumerate(queries):
        q = query_info["q"]
        logger.info(f"[DDG] Query {i+1}/{len(queries)}: {q[:80]}...")

        try:
            results = _ddg_search(q, num_results=10)
        except RuntimeError as e:
            failures += 1
            logger.warning(f"[DDG] Query {i+1} hard-failed: {e}")
            results = []

        if not results:
            empty_returns += 1

        for result in results:
            url = result.get("url", "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            result["query_type"] = query_info["type"]
            result["brand"] = query_info["brand"]
            all_results.append(result)

        # Polite rate limiting — avoid DDG blocks
        if i < len(queries) - 1:
            time.sleep(rate_delay)

    logger.info(
        f"[DDG] Found {len(all_results)} unique results for {brand_key} "
        f"(failures={failures}, empty={empty_returns}/{len(queries)})"
    )

    # If every single query came back empty AND at least one hard-failed,
    # treat the whole batch as a backend outage so the scan is marked failed.
    if not all_results and queries and (failures > 0 or empty_returns == len(queries)):
        raise DDGBackendBlocked(
            f"DDG returned no results for any of {len(queries)} queries "
            f"({failures} hard failures, {empty_returns} empty)"
        )

    return all_results
