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
    """
    from backend.scrapers.google_search import search_brand
    from backend.scrapers.web_scraper import extract_profile_data
    from backend.services.detector import score_result

    api_key, cx = _get_api_keys()
    weights = _get_weights()
    rate_delay = _get_rate_delay()

    if not api_key or not cx or api_key == "YOUR_KEY_HERE":
        logger.warning(f"Google API keys not configured, skipping {brand_key}")
        return 0, 0

    logger.info(f"Scanning brand: {brand_key}")

    # Step 1: Google search
    results = search_brand(brand_key, brand_config, api_key, cx, rate_delay)
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

    logger.info(
        f"Scan complete for {brand_key}: "
        f"{items_scanned} items scanned, {threats_found} threats found"
    )
    return items_scanned, threats_found


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
