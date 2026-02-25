"""
Google Custom Search scraper for Brand Shield.
Uses Google Custom Search JSON API to find potential brand infringers.
"""
import time
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def detect_platform(url):
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
        "teespring.com": "merch",
        "redbubble.com": "merch",
        "aliexpress.com": "aliexpress",
    }
    for key, platform in platform_map.items():
        if key in domain:
            return platform
    return "web"


def build_search_queries(brand_key, brand_config):
    """Build search queries for a brand based on its config."""
    queries = []
    display_name = brand_config.get("display_name", brand_key)
    handles = brand_config.get("platform_handles", {})
    keywords = brand_config.get("keywords", [])
    product_names = brand_config.get("product_names", [])
    verified_urls = brand_config.get("verified_urls", [])

    # Build exclusion list from verified URLs
    exclusions = ""
    for url in verified_urls:
        domain = urlparse(url).netloc
        if domain:
            exclusions += f" -site:{domain}"

    # Exclude official handles
    for platform, handle in handles.items():
        if platform == "instagram":
            exclusions += f" -site:instagram.com/{handle}"
        elif platform == "twitter":
            exclusions += f" -site:twitter.com/{handle} -site:x.com/{handle}"
        elif platform == "youtube":
            exclusions += f" -site:youtube.com/{handle}"

    # Query 1: Name impersonation
    queries.append({
        "q": f'"{display_name}"{exclusions}',
        "type": "impersonation",
        "brand": brand_key,
    })

    # Query 2: Brand handle variations (fake accounts)
    for platform, handle in handles.items():
        queries.append({
            "q": f'"{handle}" ({platform} OR profile OR account) -site:{platform}.com/{handle}',
            "type": "impersonation",
            "brand": brand_key,
        })

    # Query 3: Counterfeit products
    for product in product_names[:3]:  # Limit to top 3 products
        queries.append({
            "q": f'"{product}" (buy OR shop OR order OR price){exclusions}',
            "type": "counterfeit",
            "brand": brand_key,
        })

    # Query 4: Scam/fake detection
    queries.append({
        "q": f'"{display_name}" OR "{brand_key}" (fake OR scam OR unofficial OR replica)',
        "type": "content_theft",
        "brand": brand_key,
    })

    # Query 5: Keyword-based search
    if keywords:
        kw_string = " OR ".join(f'"{k}"' for k in keywords[:3])
        queries.append({
            "q": f'({kw_string}) (impersonat* OR fake OR counterfeit){exclusions}',
            "type": "content_theft",
            "brand": brand_key,
        })

    return queries


def run_google_search(api_key, cx, query, num_results=10):
    """Execute a Google Custom Search API query."""
    import requests

    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": api_key,
        "cx": cx,
        "q": query,
        "num": min(num_results, 10),
    }

    try:
        response = requests.get(url, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()

        results = []
        for item in data.get("items", []):
            results.append({
                "title": item.get("title", ""),
                "url": item.get("link", ""),
                "snippet": item.get("snippet", ""),
                "display_url": item.get("displayLink", ""),
                "platform": detect_platform(item.get("link", "")),
            })
        return results

    except requests.exceptions.HTTPError as e:
        if e.response and e.response.status_code == 429:
            logger.warning("Google API rate limit hit")
            return []
        logger.error(f"Google API error: {e}")
        return []
    except Exception as e:
        logger.error(f"Google search failed: {e}")
        return []


def search_brand(brand_key, brand_config, api_key, cx, rate_delay=2.0):
    """
    Run all search queries for a brand and return aggregated results.

    Returns list of dicts:
        [{url, title, snippet, platform, query_type, brand}, ...]
    """
    queries = build_search_queries(brand_key, brand_config)
    all_results = []
    seen_urls = set()

    for query_info in queries:
        logger.info(f"Searching: {query_info['q'][:80]}...")

        results = run_google_search(api_key, cx, query_info["q"])

        for result in results:
            # Deduplicate by URL
            if result["url"] in seen_urls:
                continue
            seen_urls.add(result["url"])

            result["query_type"] = query_info["type"]
            result["brand"] = query_info["brand"]
            all_results.append(result)

        # Respect rate limits
        time.sleep(rate_delay)

    logger.info(f"Found {len(all_results)} unique results for {brand_key}")
    return all_results
