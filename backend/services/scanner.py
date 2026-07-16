"""
Scan orchestrator for Brand Shield.
Coordinates scrapers and detection services to find and log threats.
"""
import json
import logging
from datetime import datetime

from backend.database import query, execute
from backend.config import BRANDS

logger = logging.getLogger(__name__)

# Minimum confidence to create a threat
MIN_THREAT_CONFIDENCE = 0.35

# Minimum confidence to flag as suspicious account
MIN_SUSPECT_CONFIDENCE = 0.50


def _get_api_keys():
    """Load Google API keys from config."""
    from backend.config import (
        GOOGLE_CUSTOM_SEARCH_API_KEY,
        GOOGLE_CUSTOM_SEARCH_CX,
    )
    return GOOGLE_CUSTOM_SEARCH_API_KEY, GOOGLE_CUSTOM_SEARCH_CX


def _get_brave_api_key():
    """Load Brave Search API key from env."""
    import os
    return os.getenv("BRAVE_API_KEY", "").strip()


def _get_tavily_api_key():
    """Load Tavily API key from env."""
    import os
    return os.getenv("TAVILY_API_KEY", "").strip()


def _get_weights():
    """Load detection weights from config."""
    try:
        from backend.config import IMPERSONATION_WEIGHTS
        return IMPERSONATION_WEIGHTS
    except ImportError:
        return None


def _get_rate_delay():
    """Get rate limit delay from config."""
    try:
        from backend.config import RATE_LIMITS
        return RATE_LIMITS.get("google_search", {}).get("delay_seconds", 2.0)
    except (ImportError, AttributeError):
        return 2.0


def _url_already_tracked(url):
    """Check if a URL is already in the threats or suspects table."""
    existing_threat = query(
        "SELECT id FROM threats WHERE detected_url = ?", (url,), one=True
    )
    if existing_threat:
        return True
    existing_suspect = query(
        "SELECT id FROM suspicious_accounts WHERE profile_url = ?", (url,), one=True
    )
    return existing_suspect is not None


def _create_threat(brand, result, score_data, profile_data=None):
    """Insert a new threat into the database."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    username = ""
    if profile_data:
        username = profile_data.get("username", "") or ""
    if not username:
        username = _extract_username_from_url(result.get("url", ""))

    execute(
        """INSERT INTO threats
           (brand, threat_type, severity, platform, detected_url,
            infringer_username, confidence, evidence_json, status, detected_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)""",
        (
            brand,
            score_data["threat_type"],
            score_data["severity"],
            result.get("platform", "web"),
            result["url"],
            username,
            score_data["confidence"],
            json.dumps(score_data["evidence"]),
            now,
        ),
    )
    logger.info(
        f"  + Threat: {username or result['url'][:60]} "
        f"({score_data['severity']}, {score_data['confidence']:.0%})"
    )


def _create_suspect(brand, result, score_data, profile_data):
    """Insert a suspicious account into the database."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    red_flags = []
    ev = score_data.get("evidence", {})
    if ev.get("username_match", 0) > 0.5:
        red_flags.append(f"Username similarity: {ev['username_match']:.0%}")
    if ev.get("bio_similarity", 0) > 0.5:
        red_flags.append(f"Bio similarity: {ev['bio_similarity']:.0%}")
    if ev.get("name_match", 0) > 0.5:
        red_flags.append(f"Display name match: {ev['name_match']:.0%}")

    execute(
        """INSERT INTO suspicious_accounts
           (brand, platform, username, profile_url, display_name,
            bio_text, follower_count, risk_score,
            detection_reasons_json, status, detected_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'suspected', ?)""",
        (
            brand,
            profile_data.get("platform", result.get("platform", "web")),
            profile_data.get("username", ""),
            result["url"],
            profile_data.get("display_name", ""),
            profile_data.get("bio", ""),
            profile_data.get("follower_count", 0),
            score_data["confidence"],
            json.dumps(red_flags),
            now,
        ),
    )
    logger.info(
        f"  + Suspect: {profile_data.get('username', 'unknown')} "
        f"on {profile_data.get('platform', '?')} ({score_data['confidence']:.0%})"
    )


def _extract_username_from_url(url):
    """Try to extract a username from a social media URL."""
    from urllib.parse import urlparse

    path = urlparse(url).path.strip("/")
    parts = path.split("/")
    if parts and parts[0]:
        username = parts[0]
        if username.startswith("@"):
            username = username[1:]
        # Skip common non-username paths
        skip = {"search", "explore", "hashtag", "p", "reel", "watch", "channel", "c"}
        if username.lower() not in skip:
            return username
    return ""


def _start_scan_record(scan_type, brand=None, platform=None):
    """Create a scan_history entry and return its ID."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    execute(
        """INSERT INTO scan_history
           (scan_type, brand, platform, status, started_at)
           VALUES (?, ?, ?, 'running', ?)""",
        (scan_type, brand, platform, now),
    )
    row = query(
        "SELECT id FROM scan_history ORDER BY id DESC LIMIT 1", one=True
    )
    return row["id"] if row else None


def _complete_scan_record(scan_id, items_scanned, threats_found, error=None):
    """Update a scan_history entry with results."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    started = query(
        "SELECT started_at FROM scan_history WHERE id = ?", (scan_id,), one=True
    )
    exec_time = 0.0
    if started:
        try:
            start_dt = datetime.strptime(started["started_at"], "%Y-%m-%d %H:%M:%S")
            exec_time = (datetime.now() - start_dt).total_seconds()
        except Exception:
            pass

    status = "failed" if error else "completed"
    execute(
        """UPDATE scan_history
           SET items_scanned = ?, threats_found = ?,
               execution_time_seconds = ?, status = ?,
               error_message = ?, completed_at = ?
           WHERE id = ?""",
        (items_scanned, threats_found, exec_time, status, error, now, scan_id),
    )


def run_brand_scan(brand_key, brand_config):
    """
    Run a full scan for a single brand.
    Returns (items_scanned, threats_found).

    Search backend priority:
      1. Tavily (TAVILY_API_KEY) — primary: 1,000 free credits/mo, no card.
         (Google CSE deprecated "search the entire web" for new engines in
         2026, so a CSE is no longer viable for broad brand monitoring.)
      2. Google CSE (GOOGLE_CSE_API_KEY + GOOGLE_CSE_CX) — only useful for
         grandfathered entire-web engines; kept for compatibility.
      3. Brave Search API (BRAVE_API_KEY) — metered overflow ($5/mo credit
         ≈ 1,000 free requests, then $5/1k).
      4. DuckDuckGo HTML scraper — last-resort, no key required.
    Each level falls through on failure; an outage never kills the scan.
    """
    from backend.scrapers.web_scraper import extract_profile_data
    from backend.services.detector import score_result

    weights = _get_weights()
    rate_delay = _get_rate_delay()

    brave_key = _get_brave_api_key()
    google_key, google_cx = _get_api_keys()

    logger.info(f"Scanning brand: {brand_key}")

    # Step 1: Choose search backend — cascade with automatic fallback.
    # Google CSE is primary (100 free queries/day — covers the twice-daily
    # cadence at zero cost; key created under a personal account, sidestepping
    # the byerim.com Workspace org block). Brave is the paid fallback
    # ($5/1k metered, $5/mo credit), and the keyless DuckDuckGo scraper is
    # last resort. A backend failure must NOT kill discovery — we fall
    # through. (Previously a single-backend outage raised straight out of
    # the scan, marking it 'failed' with 0 items and halting all discovery.)
    results = None
    backend_used = None
    search_errors = []
    tavily_key = _get_tavily_api_key()

    if tavily_key and tavily_key not in ("", "YOUR_KEY_HERE"):
        try:
            from backend.scrapers.tavily_search import search_brand as _tavily_search
            logger.info(f"[Scanner] Using Tavily for {brand_key}")
            results = _tavily_search(brand_key, brand_config, tavily_key, rate_delay=rate_delay)
            backend_used = "tavily"
        except Exception as e:
            search_errors.append(f"tavily: {e}")
            logger.warning(f"[Scanner] Tavily failed for {brand_key}; falling back: {e}")
            results = None

    if results is None and google_key and google_cx and google_key not in ("", "YOUR_KEY_HERE"):
        try:
            from backend.scrapers.google_search import search_brand as _google_search
            logger.info(f"[Scanner] Using Google CSE for {brand_key}")
            results = _google_search(brand_key, brand_config, google_key, google_cx, rate_delay)
            backend_used = "google_cse"
        except Exception as e:
            search_errors.append(f"google: {e}")
            logger.warning(f"[Scanner] Google CSE failed for {brand_key}; falling back: {e}")
            results = None

    if results is None and brave_key and brave_key not in ("", "YOUR_KEY_HERE"):
        try:
            from backend.scrapers.brave_search import search_brand as _brave_search
            logger.info(f"[Scanner] Falling back to Brave Search for {brand_key}")
            results = _brave_search(brand_key, brand_config, brave_key, rate_delay=rate_delay)
            backend_used = "brave"
        except Exception as e:
            search_errors.append(f"brave: {e}")
            logger.warning(f"[Scanner] Brave failed for {brand_key}; falling back: {e}")
            results = None

    if results is None:
        try:
            from backend.scrapers.duckduckgo_search import search_brand as _ddg_search
            logger.info(f"[Scanner] Falling back to DuckDuckGo (keyless) for {brand_key}")
            results = _ddg_search(brand_key, brand_config, rate_delay=rate_delay)
            backend_used = "duckduckgo"
        except Exception as e:
            search_errors.append(f"ddg: {e}")
            logger.error(f"[Scanner] All search backends failed for {brand_key}: {search_errors}")
            results = []

    logger.info(
        f"[Scanner] {brand_key}: backend={backend_used or 'none'}, "
        f"{len(results)} raw results"
    )
    items_scanned = len(results)
    threats_found = 0

    for result in results:
        url = result.get("url", "")

        # Skip already-tracked URLs
        if _url_already_tracked(url):
            logger.debug(f"  Skipping (already tracked): {url[:80]}")
            continue

        # Step 2: Try to get profile data for social media URLs
        profile_data = None
        platform = result.get("platform", "web")
        if platform in ("instagram", "twitter", "tiktok", "youtube", "facebook"):
            try:
                profile_data = extract_profile_data(url)
            except Exception as e:
                logger.warning(f"  Profile scrape failed for {url[:60]}: {e}")

        # Step 3: Score the result
        score_data = score_result(
            result, brand_key, brand_config, profile_data, weights
        )

        # Step 4: Create threat if above threshold
        if score_data["confidence"] >= MIN_THREAT_CONFIDENCE:
            _create_threat(brand_key, result, score_data, profile_data)
            threats_found += 1

            # Also create suspect entry for impersonation on social platforms
            if (
                score_data["threat_type"] == "impersonation"
                and score_data["confidence"] >= MIN_SUSPECT_CONFIDENCE
                and profile_data
                and profile_data.get("username")
            ):
                _create_suspect(brand_key, result, score_data, profile_data)

            # Step 5: AUTO-TAKEDOWN for high-confidence, high-severity threats.
            # Guarded so we never fire a sworn legal notice on a weak/algorithmic
            # match (that would risk a §512(f) misrepresentation claim). Lower-
            # confidence finds are just logged for the daily digest.
            _maybe_auto_takedown(brand_key, url, result, score_data)

    logger.info(
        f"Scan complete for {brand_key}: "
        f"{items_scanned} items scanned, {threats_found} threats found"
    )
    return items_scanned, threats_found


def _maybe_auto_takedown(brand_key, url, result, score_data):
    """Auto-generate + auto-send a takedown for a strong match, if enabled.

    Controlled by:
      AUTO_TAKEDOWN_ON_SCAN      (default 'true')  — master switch
      AUTO_TAKEDOWN_MIN_CONFIDENCE (default '0.9')  — confidence floor
    Only critical/high severity qualify. Sending itself is still gated by
    AUTO_SEND_TAKEDOWNS + claimant identity fields inside create_takedown.
    """
    import os
    if os.getenv("AUTO_TAKEDOWN_ON_SCAN", "true").lower() != "true":
        return
    try:
        floor = float(os.getenv("AUTO_TAKEDOWN_MIN_CONFIDENCE", "0.9"))
    except ValueError:
        floor = 0.9
    conf = score_data.get("confidence", 0) or 0
    sev = score_data.get("severity", "")
    if conf < floor or sev not in ("critical", "high"):
        return
    try:
        from backend.services.takedown import create_takedown, send_ops_alert
        res = create_takedown(url, brand=brand_key, send=True)
        sent = any(n.get("sent_now") for n in res.get("notices", []))
        logger.info(f"[AUTO-TD] {url[:70]} -> {'SENT' if sent else 'draft'} "
                    f"(conf {conf:.0%}, {sev})")
        send_ops_alert(
            f"Auto-takedown {'SENT' if sent else 'drafted'}: {url[:70]}",
            f"BrandShield auto-actioned a high-confidence threat found by scan.\n\n"
            f"URL: {url}\nBrand: {brand_key}\nConfidence: {int(conf*100)}%  "
            f"Severity: {sev}\nRoute: {res.get('basis')}\n"
            f"Recipient: {res['recipient'].get('email') or res['recipient'].get('form_url')}\n"
            f"Status: {'notice sent, deadline running' if sent else 'draft (needs recipient/config)'}\n"
            + ("\nWarnings:\n- " + "\n- ".join(res['warnings']) if res.get('warnings') else "")
            + "\n\nDashboard: https://brand-shield.onrender.com/")
    except Exception as e:
        logger.error(f"[AUTO-TD] failed for {url[:70]}: {e}")


def _leak_search(query, num_results=10):
    """Generic web search for leak-site sweeps. Cascade mirrors the brand
    scan: Tavily → Google CSE → Brave (safesearch off) → DDG. Tavily
    translates `site:` operators into include_domains automatically."""
    tavily_key = _get_tavily_api_key()
    if tavily_key and tavily_key not in ("", "YOUR_KEY_HERE"):
        try:
            from backend.scrapers.tavily_search import run_tavily_search
            results = run_tavily_search(tavily_key, query, num_results)
            if results:
                return [{"title": r.get("title", ""), "url": r.get("url", ""),
                         "snippet": r.get("snippet", "")} for r in results]
        except Exception as e:
            logger.warning(f"[LEAK-SCAN] Tavily search failed: {e}")
    google_key, google_cx = _get_api_keys()
    if google_key and google_cx and google_key not in ("", "YOUR_KEY_HERE"):
        try:
            from backend.scrapers.google_search import run_google_search
            results = run_google_search(google_key, google_cx, query, num_results)
            if results:
                return [{"title": r.get("title", ""), "url": r.get("url", ""),
                         "snippet": r.get("snippet", "")} for r in results]
        except Exception as e:
            logger.warning(f"[LEAK-SCAN] Google CSE search failed: {e}")
    brave_key = _get_brave_api_key()
    if brave_key and brave_key not in ("", "YOUR_KEY_HERE"):
        import requests
        try:
            resp = requests.get(
                "https://api.search.brave.com/res/v1/web/search",
                params={"q": query, "count": min(num_results, 20),
                        "country": "GB", "search_lang": "en", "safesearch": "off"},
                headers={"Accept": "application/json",
                         "X-Subscription-Token": brave_key},
                timeout=15,
            )
            if resp.status_code == 200:
                return [{"title": r.get("title", ""), "url": r.get("url", ""),
                         "snippet": r.get("description", "")}
                        for r in resp.json().get("web", {}).get("results", [])]
        except Exception as e:
            logger.warning(f"[LEAK-SCAN] Brave search failed: {e}")
    try:
        from backend.scrapers.duckduckgo_search import _ddg_search
        return _ddg_search(query, num_results)
    except Exception as e:
        logger.warning(f"[LEAK-SCAN] DDG search failed: {e}")
        return []


def run_leak_site_scan(brand=None):
    """
    Sweep known leak/adult sites for brand content and auto-open takedowns.

    For every hit on a leak-site domain: creates a critical 'leaked_content'
    threat and runs the takedown pipeline (NCII/DMCA route auto-selected).
    Notices are auto-SENT via Resend when AUTO_SEND_TAKEDOWNS=true, the
    recipient is known from the registry/TAKEDOWN_CONTACTS, and the claimant
    details (DMCA_SIGNER_NAME etc.) are configured — otherwise they are left
    as drafts and flagged in the alert email.
    """
    import os
    from backend.services.takedown import (
        create_takedown, registrable_domain, ADULT_SITE_HINTS, LEAK_SCAN_SITES,
    )

    auto_send = os.getenv("AUTO_SEND_TAKEDOWNS", "true").lower() == "true"
    scan_id = _start_scan_record("leak_site_scan", brand)
    items, found = 0, 0
    try:
        brands = {brand: BRANDS[brand]} if brand and brand in BRANDS else BRANDS
        for brand_key, cfg in brands.items():
            names = [cfg.get("display_name", ""), brand_key.lstrip("@")]
            names += cfg.get("keywords", [])[:2]
            terms = [n for n in dict.fromkeys(names) if n]
            queries = []
            for site in LEAK_SCAN_SITES:
                queries.append(f'"{terms[0]}" site:{site}')
            queries.append(f'"{terms[0]}" leaked')
            if len(terms) > 1:
                queries.append(f'"{terms[1]}" leaked album')

            for q in queries:
                results = _leak_search(q)
                items += len(results)
                for r in results:
                    url = r.get("url", "")
                    domain = registrable_domain(url) if url else ""
                    if not url or not any(h in domain for h in ADULT_SITE_HINTS):
                        continue
                    if _url_already_tracked(url):
                        continue
                    try:
                        res = create_takedown(url, brand=brand_key, send=auto_send)
                        found += 1
                        sent = any(n.get("sent_now") for n in res["notices"])
                        logger.info(f"[LEAK-SCAN] {url[:70]} -> "
                                    f"{'notice SENT' if sent else 'draft (needs recipient/config)'}")
                        from backend.services.takedown import send_ops_alert
                        send_ops_alert(
                            f"Leak-site hit: {url[:80]}",
                            f"BrandShield found brand content on a leak site and "
                            f"{'SENT takedown notice(s) automatically' if sent else 'created DRAFT notice(s) — action needed'}.\n\n"
                            f"URL: {url}\nBrand: {brand_key}\nRoute: {res['basis']}\n"
                            f"Recipient: {res['recipient'].get('email') or 'UNRESOLVED — ' + str(res['recipient'].get('form_url'))}\n"
                            + ("\nWarnings:\n- " + "\n- ".join(res["warnings"]) if res["warnings"] else "")
                            + "\n\nDashboard: https://brand-shield.onrender.com/")
                    except Exception as e:
                        logger.error(f"[LEAK-SCAN] takedown failed for {url[:70]}: {e}")
        _complete_scan_record(scan_id, items, found)
    except Exception as e:
        logger.error(f"[LEAK-SCAN] failed: {e}", exc_info=True)
        _complete_scan_record(scan_id, items, found, str(e))
    return {"scan_id": scan_id, "items_scanned": items, "threats_found": found}


def run_full_scan(brand=None, platform=None):
    """
    Run a complete scan across all (or specified) brands.
    This is the main entry point called by the API and scheduler.
    """
    scan_type = "full_scan"
    if brand and platform:
        scan_type = "platform_scan"
    elif brand:
        scan_type = "brand_scan"

    scan_id = _start_scan_record(scan_type, brand, platform)
    total_items = 0
    total_threats = 0

    try:
        brands_to_scan = {}
        if brand and brand in BRANDS:
            brands_to_scan[brand] = BRANDS[brand]
        elif brand:
            # Try with @ prefix
            key = f"@{brand}" if not brand.startswith("@") else brand
            if key in BRANDS:
                brands_to_scan[key] = BRANDS[key]
            else:
                raise ValueError(f"Unknown brand: {brand}")
        else:
            brands_to_scan = BRANDS

        for brand_key, brand_config in brands_to_scan.items():
            items, threats = run_brand_scan(brand_key, brand_config)
            total_items += items
            total_threats += threats

        # Leak-site sweep (adult/leak domains) — end-to-end: hits become
        # threats + notices, auto-sent when config allows.
        if not platform:
            leak = run_leak_site_scan(brand=brand if brand in BRANDS else None)
            total_items += leak.get("items_scanned", 0)
            total_threats += leak.get("threats_found", 0)

        _complete_scan_record(scan_id, total_items, total_threats)
        logger.info(
            f"Full scan complete: {total_items} items, {total_threats} threats"
        )

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        _complete_scan_record(scan_id, total_items, total_threats, str(e))

    return {
        "scan_id": scan_id,
        "items_scanned": total_items,
        "threats_found": total_threats,
    }
