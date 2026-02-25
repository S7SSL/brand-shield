"""
Threat detection and scoring for Brand Shield.
Analyzes search results and profile data to calculate threat confidence.
"""
import re
import logging
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)

# Default weights (can be overridden from config)
DEFAULT_WEIGHTS = {
    "profile_pic_match": 0.30,
    "bio_similarity": 0.20,
    "username_pattern": 0.20,
    "content_overlap": 0.20,
    "name_match": 0.10,
}

# Severity thresholds
SEVERITY_THRESHOLDS = {
    "critical": 0.90,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.0,
}


def text_similarity(text1, text2):
    """Calculate similarity ratio between two strings (0.0 to 1.0)."""
    if not text1 or not text2:
        return 0.0
    return SequenceMatcher(None, text1.lower(), text2.lower()).ratio()


def check_username_similarity(username, brand_handles, brand_key):
    """
    Score how similar a username is to the brand's official handles.
    Returns score 0.0 to 1.0.
    """
    if not username:
        return 0.0

    username_lower = username.lower().strip("@")
    brand_clean = brand_key.lower().strip("@")
    max_score = 0.0

    # Check against all official handles
    all_handles = list(brand_handles.values()) + [brand_clean]
    for handle in all_handles:
        handle_lower = handle.lower()

        # Exact match (shouldn't happen for threats, but just in case)
        if username_lower == handle_lower:
            continue  # This is the real account, skip

        # High similarity
        sim = text_similarity(username_lower, handle_lower)
        max_score = max(max_score, sim)

        # Common impersonation patterns
        patterns = [
            f"{handle_lower}_official",
            f"{handle_lower}official",
            f"{handle_lower}_real",
            f"the_real_{handle_lower}",
            f"thereal{handle_lower}",
            f"{handle_lower}_uk",
            f"{handle_lower}uk",
            f"{handle_lower}_shop",
            f"{handle_lower}shop",
            f"{handle_lower}_store",
            f"{handle_lower}2",
            f"{handle_lower}_backup",
            f"real_{handle_lower}",
            f"{handle_lower}.official",
            f"official.{handle_lower}",
        ]

        for pattern in patterns:
            if username_lower == pattern or pattern in username_lower:
                max_score = max(max_score, 0.85)
                break

        # Contains the handle name
        if handle_lower in username_lower and username_lower != handle_lower:
            max_score = max(max_score, 0.6)

    return min(max_score, 1.0)


def check_bio_similarity(bio_text, brand_config):
    """
    Score how similar a bio is to the brand's known phrases.
    Returns score 0.0 to 1.0.
    """
    if not bio_text:
        return 0.0

    bio_lower = bio_text.lower()
    bio_phrases = brand_config.get("bio_phrases", [])
    keywords = brand_config.get("keywords", [])

    scores = []

    # Check bio phrases
    for phrase in bio_phrases:
        sim = text_similarity(phrase.lower(), bio_lower)
        scores.append(sim)

        # Direct substring match is a strong signal
        if phrase.lower() in bio_lower:
            scores.append(0.85)

    # Check keywords
    keyword_hits = 0
    for kw in keywords:
        if kw.lower() in bio_lower:
            keyword_hits += 1
    if keywords:
        scores.append(min(keyword_hits / max(len(keywords), 1), 1.0) * 0.7)

    return max(scores) if scores else 0.0


def check_name_match(display_name, brand_config):
    """
    Score how closely a display name matches the brand.
    Returns score 0.0 to 1.0.
    """
    if not display_name:
        return 0.0

    official_name = brand_config.get("display_name", "")
    if not official_name:
        return 0.0

    sim = text_similarity(display_name, official_name)

    # Exact name match is highly suspicious
    if display_name.lower().strip() == official_name.lower().strip():
        return 0.95

    # Contains the full name
    if official_name.lower() in display_name.lower():
        return max(sim, 0.8)

    return sim


def check_content_overlap(snippet, brand_config):
    """
    Score content overlap between a search snippet and brand content.
    Returns score 0.0 to 1.0.
    """
    if not snippet:
        return 0.0

    snippet_lower = snippet.lower()
    keywords = brand_config.get("keywords", [])
    product_names = brand_config.get("product_names", [])

    hits = 0
    total = len(keywords) + len(product_names)
    if total == 0:
        return 0.0

    for kw in keywords:
        if kw.lower() in snippet_lower:
            hits += 1

    for product in product_names:
        if product.lower() in snippet_lower:
            hits += 1.5  # Product name matches are stronger signals

    return min(hits / max(total, 1), 1.0)


def classify_threat_type(result, profile_data=None):
    """Determine the type of threat based on available evidence."""
    snippet = (result.get("snippet", "") + " " + result.get("title", "")).lower()
    platform = result.get("platform", "web")
    query_type = result.get("query_type", "")

    # Check for counterfeit indicators
    counterfeit_signals = ["buy", "shop", "order", "price", "sale", "discount",
                          "free shipping", "cheap", "replica", "dupe"]
    if any(s in snippet for s in counterfeit_signals):
        return "counterfeit"

    # Check for impersonation
    if profile_data and profile_data.get("username"):
        return "impersonation"
    if platform in ("instagram", "twitter", "tiktok", "youtube", "facebook"):
        if any(s in snippet for s in ["profile", "account", "follow", "official"]):
            return "impersonation"

    # Check for content theft
    if any(s in snippet for s in ["copy", "stolen", "repost", "credit"]):
        return "content_theft"

    # Default based on query type
    return query_type if query_type else "content_theft"


def calculate_severity(confidence):
    """Assign severity level based on confidence score."""
    for severity, threshold in SEVERITY_THRESHOLDS.items():
        if confidence >= threshold:
            return severity
    return "low"


def score_result(result, brand_key, brand_config, profile_data=None, weights=None):
    """
    Calculate overall threat score for a search result.

    Args:
        result: dict with url, title, snippet, platform, query_type, brand
        brand_key: str like "@erim"
        brand_config: dict from config BRANDS
        profile_data: optional dict from web_scraper.extract_profile_data()
        weights: optional dict overriding DEFAULT_WEIGHTS

    Returns:
        dict with: confidence, severity, threat_type, evidence
    """
    w = weights or DEFAULT_WEIGHTS
    handles = brand_config.get("platform_handles", {})

    # Calculate individual scores
    username = (profile_data or {}).get("username", "")
    username_score = check_username_similarity(username, handles, brand_key)

    bio = (profile_data or {}).get("bio", "") or result.get("snippet", "")
    bio_score = check_bio_similarity(bio, brand_config)

    display_name = (profile_data or {}).get("display_name", "") or result.get("title", "")
    name_score = check_name_match(display_name, brand_config)

    content_score = check_content_overlap(result.get("snippet", ""), brand_config)

    # Profile pic match requires image analysis — use 0 for now
    pic_score = 0.0

    # Weighted confidence
    confidence = (
        w.get("profile_pic_match", 0.3) * pic_score +
        w.get("bio_similarity", 0.2) * bio_score +
        w.get("username_pattern", 0.2) * username_score +
        w.get("content_overlap", 0.2) * content_score +
        w.get("name_match", 0.1) * name_score
    )

    # Boost: if username is very similar, boost overall confidence
    if username_score > 0.8:
        confidence = max(confidence, 0.7)

    # Boost: if display name is exact match, boost confidence
    if name_score > 0.9:
        confidence = max(confidence, 0.65)

    # Cap at 1.0
    confidence = min(round(confidence, 3), 1.0)

    threat_type = classify_threat_type(result, profile_data)
    severity = calculate_severity(confidence)

    evidence = {
        "username_match": round(username_score, 3),
        "bio_similarity": round(bio_score, 3),
        "name_match": round(name_score, 3),
        "content_overlap": round(content_score, 3),
        "profile_pic_match": round(pic_score, 3),
    }

    return {
        "confidence": confidence,
        "severity": severity,
        "threat_type": threat_type,
        "evidence": evidence,
    }
