"""
Tavily Search API scraper for BrandShield.

Tavily is the primary search backend: 1,000 free API credits/month with no
card on file (basic search = 1 credit). Google's Programmable Search Engine
deprecated "Search the entire web" for new engines in 2026, and Brave moved
to metered billing, so Tavily-first + Brave-overflow keeps the twice-daily
scan cadence at $0/month.

Endpoint:  POST https://api.tavily.com/search
Auth:      Authorization: Bearer <api-key>
Free tier: 1,000 credits/month (docs.tavily.com/documentation/api-credits)
"""
import re
import time
import logging

# Reuse the shared verified-URL filter / platform detection so the brand's
# own profiles don't get flagged as threats.
from backend.scrapers.google_search import _is_verified_url, detect_platform
# The query set is backend-agnostic; reuse Brave's builder.
from backend.scrapers.brave_search import build_search_queries

logger = logging.getLogger(__name__)

TAVILY_SEARCH_URL = "https://api.tavily.com/search"
REQUEST_TIMEOUT = 15

_SITE_RE = re.compile(r"site:([^\s]+)")


class TavilyBackendError(RuntimeError):
    """Raised when the Tavily backend is unreachable / mis-configured, so the
    scanner can distinguish a real outage from 'no results matched'."""


def _split_site_operator(query):
    """Tavily doesn't parse the `site:` operator — it expects an
    `include_domains` list instead. Extract any site: terms and return
    (clean_query, include_domains)."""
    domains = _SITE_RE.findall(query)
    clean = _SITE_RE.sub("", query).strip()
    # Collapse leftover double spaces from the removal
    clean = re.sub(r"\s{2,}", " ", clean)
    return clean or query, [d.strip("/") for d in domains]


def run_tavily_search(api_key, query, num_results=10, safesearch_off=False):
    """Execute one Tavily search. Returns a list of result dicts on success.
    Raises TavilyBackendError on auth/quota/network errors."""
    import requests

    clean_query, include_domains = _split_site_operator(query)
    payload = {
        "query": clean_query,
        "search_depth": "basic",       # 1 credit; 'advanced' costs 2
        "max_results": min(num_results, 20),
        "include_answer": False,
        "include_raw_content": False,
    }
    if include_domains:
        payload["include_domains"] = include_domains

    try:
        response = requests.post(
            TAVILY_SEARCH_URL,
            json=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.RequestException as e:
        raise TavilyBackendError(f"Tavily network error: {e}") from e

    if response.status_code in (401, 403):
        raise TavilyBackendError(
            f"Tavily auth error (HTTP {response.status_code}): "
            f"{response.text[:200]}"
        )
    if response.status_code == 429:
        raise TavilyBackendError("Tavily quota/rate-limit hit (HTTP 429)")
    if response.status_code >= 400:
        raise TavilyBackendError(
            f"Tavily error (HTTP {response.status_code}): {response.text[:200]}"
        )

    try:
        data = response.json()
    except ValueError as e:
        raise TavilyBackendError(f"Tavily invalid JSON: {e}") from e

    out = []
    for item in data.get("results", []):
        url = item.get("url", "")
        if not url:
            continue
        out.append({
            "title": item.get("title", ""),
            "url": url,
            "snippet": item.get("content", "")[:400],
            "display_url": "",
            "platform": detect_platform(url),
        })
    return out


def search_brand(brand_key, brand_config, api_key, rate_delay=1.0):
    """Run the full brand query set through Tavily and aggregate results.

    Same contract as the Brave/Google scrapers: returns a list of result
    dicts; raises TavilyBackendError only if EVERY query hit a hard backend
    error (a clean run with zero matches is a legitimate empty list).
    """
    queries = build_search_queries(brand_key, brand_config)
    all_results = []
    seen_urls = set()

    verified_urls = brand_config.get("verified_urls", [])
    handles = brand_config.get("platform_handles", {})

    backend_errors = 0
    raw_total = 0
    filtered_verified = 0

    logger.info(f"[Tavily] Starting {len(queries)} queries for {brand_key}")

    for i, query_info in enumerate(queries):
        q = query_info["q"]
        try:
            results = run_tavily_search(api_key, q)
        except TavilyBackendError as e:
            backend_errors += 1
            logger.warning(f"[Tavily] Query {i+1} failed: {e}")
            results = []

        raw_total += len(results)
        for result in results:
            url = result.get("url", "")
            if not url or url in seen_urls:
                continue
            if _is_verified_url(url, verified_urls, handles):
                filtered_verified += 1
                continue
            seen_urls.add(url)
            result["query_type"] = query_info["type"]
            result["brand"] = query_info["brand"]
            all_results.append(result)

        time.sleep(rate_delay)

    logger.info(
        f"[Tavily] {brand_key}: {len(all_results)} results "
        f"(raw={raw_total}, filtered_verified={filtered_verified}, "
        f"backend_errors={backend_errors}/{len(queries)})"
    )

    if queries and backend_errors == len(queries):
        raise TavilyBackendError(
            f"All {len(queries)} Tavily queries failed with backend errors"
        )

    return all_results
