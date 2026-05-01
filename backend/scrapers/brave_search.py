"""
Brave Search API scraper for Brand Shield.

Brave's Web Search API is the primary search backend now that Google's
Custom Search JSON API was blocked at the byerim.com Workspace org level.
It has a free tier of 2000 queries/month and doesn't tie us to a Workspace
org, which is a much better fit for this app's deployment.

Endpoint:    GET https://api.search.brave.com/res/v1/web/search
Auth:        X-Subscription-Token: <api-key> header
Free tier:   2000 queries/month (Data for Search plan)
Docs:        https://api.search.brave.com/app/documentation/web-search/
"""
import time
import logging
from urllib.parse import urlparse

# Reuse the verified-URL filter we already wrote for google_search so the
# brand's own profiles (instagram.com/erim, twitter.com/erimkaur, etc.)
# don't get flagged as threats.
from backend.scrapers.google_search import _is_verified_url, detect_platform

logger = logging.getLogger(__name__)

BRAVE_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"

# Per-request timeout. Brave's API is fast (sub-second normally) so we keep
# this tight — a slow query is almost always a sign of a network issue.
REQUEST_TIMEOUT = 10


class BraveBackendError(RuntimeError):
    """Raised when the Brave Search backend is unreachable / mis-configured.
    Surfaced to the scanner so the scan_history row gets status='failed'
    rather than silently 'completed' with 0 items.
    """


def build_search_queries(brand_key, brand_config):
    """Build Brave search queries for a brand.

    Brave's query syntax accepts the standard `site:domain.com` operator and
    quoted phrases, but we deliberately avoid `-site:` exclusions for whole
    platforms — those bit us hard with Google CSE because the engine's site
    allow-list combined with a `-site:instagram.com` exclusion produced an
    empty intersection. Verified profiles are filtered POST-search by
    `_is_verified_url()` instead, where path-aware matching actually works.
    """
    queries = []
    display_name = brand_config.get("display_name", brand_key)
    handles = brand_config.get("platform_handles", {})
    keywords = brand_config.get("keywords", [])
    product_names = brand_config.get("product_names", [])

    # 1. Broad name impersonation
    queries.append({
        "q": f'"{display_name}"',
        "type": "impersonation",
        "brand": brand_key,
    })

    # 2. Per-platform handle search
    domain_map = {
        "instagram": "instagram.com",
        "tiktok": "tiktok.com",
        "twitter": "twitter.com",
        "youtube": "youtube.com",
        "facebook": "facebook.com",
    }
    for platform, handle in handles.items():
        domain = domain_map.get(platform)
        if domain:
            queries.append({
                "q": f'"{handle}" site:{domain}',
                "type": "impersonation",
                "brand": brand_key,
            })

    # 3. Counterfeit product searches
    for product in product_names[:3]:
        queries.append({
            "q": f'"{product}" (buy OR shop OR order OR price OR replica)',
            "type": "counterfeit",
            "brand": brand_key,
        })

    # 4. Scam / fake / impersonator detection
    queries.append({
        "q": f'"{display_name}" (fake OR scam OR unofficial OR replica OR impersonator)',
        "type": "content_theft",
        "brand": brand_key,
    })

    # 5. Keyword-based broad sweep
    if keywords:
        kw_string = " OR ".join(f'"{k}"' for k in keywords[:3])
        queries.append({
            "q": f"({kw_string}) (impersonat* OR fake OR counterfeit OR replica)",
            "type": "content_theft",
            "brand": brand_key,
        })

    return queries


def run_brave_search(api_key, query, num_results=10):
    """Execute a Brave Web Search API query.

    Returns list of {title, url, snippet, platform, display_url} dicts on
    success. Raises BraveBackendError on auth/quota/config errors so the
    caller can distinguish a real outage from "search succeeded but matched
    nothing".
    """
    import requests

    params = {
        "q": query,
        "count": min(num_results, 20),
        "country": "GB",          # ByErim's primary market is UK
        "search_lang": "en",
        "safesearch": "moderate",
    }
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "X-Subscription-Token": api_key,
    }

    try:
        response = requests.get(
            BRAVE_SEARCH_URL,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.RequestException as e:
        raise BraveBackendError(f"Brave Search network error: {e}") from e

    # Distinguish hard backend errors from "0 results"
    if response.status_code == 429:
        raise BraveBackendError("Brave Search quota/rate-limit hit (HTTP 429)")
    if response.status_code in (401, 403):
        raise BraveBackendError(
            f"Brave Search auth error (HTTP {response.status_code}): "
            f"{response.text[:200]}"
        )
    if response.status_code >= 400:
        raise BraveBackendError(
            f"Brave Search error (HTTP {response.status_code}): "
            f"{response.text[:200]}"
        )

    try:
        data = response.json()
    except ValueError as e:
        raise BraveBackendError(f"Brave Search invalid JSON: {e}") from e

    web_results = (data.get("web") or {}).get("results", [])
    out = []
    for item in web_results:
        url = item.get("url", "")
        if not url:
            continue
        out.append({
            "title": item.get("title", ""),
            "url": url,
            "snippet": item.get("description", ""),
            "display_url": item.get("meta_url", {}).get("hostname", "") if isinstance(item.get("meta_url"), dict) else "",
            "platform": detect_platform(url),
        })
    return out


def search_brand(brand_key, brand_config, api_key, rate_delay=1.0):
    """Run all Brave search queries for a brand and aggregate results.

    Returns list of dicts:
        [{url, title, snippet, platform, query_type, brand}, ...]

    Raises BraveBackendError if every query in the batch hit a hard backend
    error. A scan that runs successfully but matches nothing returns an empty
    list — that's a legitimate "no threats found" signal, not a failure.
    """
    queries = build_search_queries(brand_key, brand_config)
    all_results = []
    seen_urls = set()

    verified_urls = brand_config.get("verified_urls", [])
    handles = brand_config.get("platform_handles", {})

    backend_errors = 0
    successful_queries = 0
    raw_total = 0
    filtered_verified = 0

    logger.info(f"[Brave] Starting {len(queries)} queries for {brand_key}")

    for i, query_info in enumerate(queries):
        q = query_info["q"]
        logger.info(f"[Brave] Query {i+1}/{len(queries)}: {q[:100]}")

        try:
            results = run_brave_search(api_key, q)
            successful_queries += 1
        except BraveBackendError as e:
            backend_errors += 1
            logger.warning(f"[Brave] Query {i+1} failed: {e}")
            results = []

        raw_total += len(results)

        for result in results:
            url = result.get("url", "")
            if not url or url in seen_urls:
                continue
            if _is_verified_url(url, verified_urls, handles):
                filtered_verified += 1
                logger.debug(f"  Skipping verified URL: {url[:80]}")
                continue
            seen_urls.add(url)
            result["query_type"] = query_info["type"]
            result["brand"] = query_info["brand"]
            all_results.append(result)

        # Brave's free tier rate-limit is 1 request/sec; default rate_delay
        # of 1.0s keeps us comfortably under that.
        time.sleep(rate_delay)

    logger.info(
        f"[Brave] {brand_key}: {len(all_results)} results "
        f"(raw={raw_total}, filtered_verified={filtered_verified}, "
        f"successful_queries={successful_queries}/{len(queries)}, "
        f"backend_errors={backend_errors})"
    )

    if queries and backend_errors == len(queries):
        raise BraveBackendError(
            f"All {len(queries)} Brave queries failed with backend errors"
        )

    return all_results
