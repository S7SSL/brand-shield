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


def _ddg_search(query: str, num_results: int = 10) -> list:
    """
    Execute a DuckDuckGo HTML search and parse results.
    Returns list of {title, url, snippet, platform} dicts.
    """
    import requests
    from bs4 import BeautifulSoup
    from urllib.parse import parse_qs, urlparse as _up

    results = []
    try:
        params = {"q": query, "kl": "uk-en", "kp": "-1"}
        response = requests.post(
            DDG_HTML_URL,
            data=params,
            headers=HEADERS,
            timeout=20,
            allow_redirects=True,
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        # DDG HTML structure: div.result (organic) — exclude div.result--ad
        for div in soup.find_all("div", class_="result"):
            if len(results) >= num_results:
                break
            # Skip ads
            div_classes = div.get("class", [])
            if "result--ad" in div_classes:
                continue

            title_tag = div.find("a", class_="result__a")
            if not title_tag:
                continue

            title = title_tag.get_text(strip=True)
            raw_url = title_tag.get("href", "")

            # DDG wraps results in redirect URLs — unwrap them
            real_url = raw_url
            if "duckduckgo.com/l/" in raw_url or "/l/?" in raw_url:
                parsed = _up(raw_url if raw_url.startswith("http") else "https://duckduckgo.com" + raw_url)
                qs = parse_qs(parsed.query)
                real_url = qs.get("uddg", [raw_url])[0]
            elif raw_url.startswith("/l/?"):
                parsed = _up("https://duckduckgo.com" + raw_url)
                qs = parse_qs(parsed.query)
                real_url = qs.get("uddg", [raw_url])[0]

            if not real_url or real_url.startswith("javascript") or "duckduckgo.com" in real_url:
                continue

            snippet_tag = div.find("a", class_="result__snippet")
            snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""

            results.append({
                "title": title,
                "url": real_url,
                "snippet": snippet,
                "platform": detect_platform(real_url),
            })

    except requests.exceptions.RequestException as e:
        logger.warning(f"DDG search failed for '{query[:60]}': {e}")
    except Exception as e:
        logger.error(f"DDG parse error for '{query[:60]}': {e}")

    return results


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


def search_brand(brand_key: str, brand_config: dict, rate_delay: float = 2.0) -> list:
    """
    Run all DDG search queries for a brand and return aggregated results.

    Returns list of dicts:
        [{url, title, snippet, platform, query_type, brand}, ...]
    """
    queries = build_search_queries(brand_key, brand_config)
    all_results = []
    seen_urls: set = set()

    logger.info(f"[DDG] Starting {len(queries)} queries for {brand_key}")

    for i, query_info in enumerate(queries):
        q = query_info["q"]
        logger.info(f"[DDG] Query {i+1}/{len(queries)}: {q[:80]}...")

        results = _ddg_search(q, num_results=10)

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

    logger.info(f"[DDG] Found {len(all_results)} unique results for {brand_key}")
    return all_results
