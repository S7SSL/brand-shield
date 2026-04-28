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
    """Build search queries for a brand based on its config.

    Note on exclusions: previously this function appended `-site:` exclusions
    for every verified URL's full domain (e.g. -site:www.instagram.com), which
    silently wiped out the entire Instagram/TikTok/Twitter platforms from the
    Google CSE results — the CSE's site allow-list already contains those
    platforms, so the intersection became empty and every scan returned 0.
    Google's `site:` operator is also domain-only, so handle-specific
    exclusions like `-site:instagram.com/erim` don't actually work.

    Verified URLs and the brand's own handles are now filtered POST-search in
    `_is_verified_url()` instead, where path-aware matching actually works.
    """
    queries = []
    display_name = brand_config.get("display_name", brand_key)
    handles = brand_config.get("platform_handles", {})
    keywords = brand_config.get("keywords", [])
    product_names = brand_config.get("product_names", [])

    # Query 1: Name impersonation (broad)
    queries.append({
        "q": f'"{display_name}"',
        "type": "impersonation",
        "brand": brand_key,
    })

    # Query 2: Brand handle on each platform (look for impersonators using the
    # handle name; the brand's own profile is removed in post-filtering)
    for platform, handle in handles.items():
        # Map platform → domain(s) used in site: filter
        domain_map = {
            "instagram": "instagram.com",
            "tiktok": "tiktok.com",
            "twitter": "twitter.com",
            "youtube": "youtube.com",
            "facebook": "facebook.com",
        }
        domain = domain_map.get(platform)
        if domain:
            queries.append({
                "q": f'"{handle}" site:{domain}',
                "type": "impersonation",
                "brand": brand_key,
            })

    # Query 3: Counterfeit products
    for product in product_names[:3]:
        queries.append({
            "q": f'"{product}" (buy OR shop OR order OR price OR replica)',
            "type": "counterfeit",
            "brand": brand_key,
        })

    # Query 4: Scam/fake detection
    queries.append({
        "q": f'"{display_name}" (fake OR scam OR unofficial OR replica OR impersonator)',
        "type": "content_theft",
        "brand": brand_key,
    })

    # Query 5: Keyword-based search
    if keywords:
        kw_string = " OR ".join(f'"{k}"' for k in keywords[:3])
        queries.append({
            "q": f"({kw_string}) (impersonat* OR fake OR counterfeit OR replica)",
            "type": "content_theft",
            "brand": brand_key,
        })

    return queries


def _is_verified_url(url, verified_urls, handles):
    """Return True if a URL is the brand's own verified profile/site.
    Path-aware (so e.g. instagram.com/erim is matched but instagram.com/some_imposter is not).
    """
    if not url:
        return False
    try:
        p = urlparse(url.lower())
    except Exception:
        return False
    norm = (p.netloc + p.path).rstrip("/").replace("www.", "", 1)

    # Match against verified_urls
    for vu in verified_urls or []:
        if not vu:
            continue
        try:
            vp = urlparse(vu.lower())
        except Exception:
            continue
        v_norm = (vp.netloc + vp.path).rstrip("/").replace("www.", "", 1)
        if not v_norm:
            continue
        if norm == v_norm or norm.startswith(v_norm + "/"):
            return True

    # Match against the brand's own handles per platform (handle pages only)
    handle_url_patterns = []
    for platform, handle in (handles or {}).items():
        if not handle:
            continue
        h = handle.lstrip("@").lower()
        if platform == "instagram":
            handle_url_patterns.append(f"instagram.com/{h}")
        elif platform == "tiktok":
            handle_url_patterns.append(f"tiktok.com/@{h}")
        elif platform == "twitter":
            handle_url_patterns.append(f"twitter.com/{h}")
            handle_url_patterns.append(f"x.com/{h}")
        elif platform == "youtube":
            handle_url_patterns.append(f"youtube.com/@{h}")
            handle_url_patterns.append(f"youtube.com/c/{h}")
        elif platform == "facebook":
            handle_url_patterns.append(f"facebook.com/{h}")
    for pat in handle_url_patterns:
        if norm == pat or norm.startswith(pat + "/"):
            return True

    return False


class GoogleBackendError(RuntimeError):
    """Raised when the Google CSE backend is unreachable / mis-configured.
    Surfaced to the scanner so the scan_history row gets status='failed' rather
    than silently 'completed' with 0 items.
    """


def run_google_search(api_key, cx, query, num_results=10):
    """Execute a Google Custom Search API query.

    Returns list of result dicts on success.
    Raises GoogleBackendError on auth/quota/config errors so the caller can
    distinguish a real outage from "search succeeded but matched nothing".
    """
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
    except requests.exceptions.RequestException as e:
        raise GoogleBackendError(f"Google CSE network error: {e}") from e

    # Treat 4xx/5xx as backend errors (auth/quota/config) — empty result lists
    # come back as HTTP 200 with no `items`, which IS a legitimate "no match".
    if response.status_code == 429:
        raise GoogleBackendError("Google CSE quota exceeded (HTTP 429)")
    if response.status_code in (401, 403):
        raise GoogleBackendError(
            f"Google CSE auth/permission error (HTTP {response.status_code}): "
            f"{response.text[:200]}"
        )
    if response.status_code >= 400:
        raise GoogleBackendError(
            f"Google CSE error (HTTP {response.status_code}): {response.text[:200]}"
        )

    try:
        data = response.json()
    except ValueError as e:
        raise GoogleBackendError(f"Google CSE invalid JSON: {e}") from e

    # Surface API-reported errors even on HTTP 200
    if isinstance(data, dict) and data.get("error"):
        err = data["error"]
        raise GoogleBackendError(
            f"Google CSE API error: {err.get('code')} {err.get('message')}"
        )

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


def search_brand(brand_key, brand_config, api_key, cx, rate_delay=2.0):
    """
    Run all search queries for a brand and return aggregated results.

    Returns list of dicts:
        [{url, title, snippet, platform, query_type, brand}, ...]

    Raises GoogleBackendError if every query in the batch hit a hard backend
    error (auth/quota/network). A scan that runs successfully but matches
    nothing returns an empty list — that's a legitimate "no threats found"
    signal, not a backend failure.
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

    logger.info(f"[Google CSE] Starting {len(queries)} queries for {brand_key}")

    for i, query_info in enumerate(queries):
        q = query_info["q"]
        logger.info(f"[Google CSE] Query {i+1}/{len(queries)}: {q[:100]}")

        try:
            results = run_google_search(api_key, cx, q)
            successful_queries += 1
        except GoogleBackendError as e:
            backend_errors += 1
            logger.warning(f"[Google CSE] Query {i+1} failed: {e}")
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

        # Respect rate limits between queries
        time.sleep(rate_delay)

    logger.info(
        f"[Google CSE] {brand_key}: {len(all_results)} results "
        f"(raw={raw_total}, filtered_verified={filtered_verified}, "
        f"successful_queries={successful_queries}/{len(queries)}, "
        f"backend_errors={backend_errors})"
    )

    # Mark the whole batch as a backend failure ONLY if every query errored.
    # If some queries succeeded with 0 results, that's just "no threats found".
    if queries and backend_errors == len(queries):
        raise GoogleBackendError(
            f"All {len(queries)} CSE queries failed with backend errors"
        )

    return all_results
