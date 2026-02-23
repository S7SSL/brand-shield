"""
Brand Shield Configuration
Settings for monitoring @erim and @byerim brand protection.
"""
import os
from pathlib import Path

# Base paths - relative to project root for Render.com compatibility
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
ASSETS_DIR = DATA_DIR / "assets"
EVIDENCE_DIR = DATA_DIR / "evidence"
DMCA_DIR = DATA_DIR / "dmca_notices"
DB_PATH = DATA_DIR / "brand_shield.db"

# Ensure directories exist
for d in [ASSETS_DIR / "originals", ASSETS_DIR / "thumbnails", EVIDENCE_DIR, DMCA_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Database
SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_PATH}"

# Flask
SECRET_KEY = os.getenv("SECRET_KEY", "brand-shield-dev-key-change-in-production")
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

# ─── Brand Configuration ───────────────────────────────────────────────
BRANDS = {
    "@erim": {
        "display_name": "Erim Kaur",
        "platform_handles": {
            "instagram": "erim",
            "tiktok": "erim",
            "twitter": "erimkaur",
            "youtube": "erimkaur",
        },
        "verified_urls": [
            "https://www.instagram.com/erim/",
            "https://www.tiktok.com/@erim",
            "https://twitter.com/erimkaur",
            "https://www.byerim.com/pages/my-story",
        ],
        "keywords": [
            "erim kaur", "erim", "erimkaur", "erim_kaur",
            "UK sikh influencer", "middle east beauty influencer",
        ],
        "bio_phrases": [
            "doing it for those who grew up without a mum or sisters",
            "fragrance hair beauty business",
            "london dubai",
        ],
    },
    "@byerim": {
        "display_name": "ByErim",
        "platform_handles": {
            "instagram": "byerim",
            "tiktok": "byerim",
            "twitter": "byerim",
        },
        "verified_urls": [
            "https://www.instagram.com/byerim/",
            "https://www.byerim.com/",
        ],
        "website": "https://www.byerim.com",
        "keywords": [
            "byerim", "by erim", "by_erim", "byerim hair oil",
            "byerim luxury hair", "byerim beard oil",
            "luxury hair beard oil", "byerim official",
        ],
        "product_names": [
            "Luxury Hair & Beard Oil",
            "ByErim Hair Oil",
            "ByErim Beard Oil",
        ],
        "bio_phrases": [
            "100% natural clinically proven vegan unisex",
            "luxury hair beard care",
            "as seen in vogue marie claire",
        ],
    },
}

# All verified account usernames (never flag these)
VERIFIED_ACCOUNTS = {
    "instagram": ["erim", "byerim"],
    "tiktok": ["erim", "byerim"],
    "twitter": ["erimkaur", "byerim"],
}

# ─── Impersonation Detection ──────────────────────────────────────────
SUSPICIOUS_USERNAME_PATTERNS = [
    "erim", "erimkaur", "erim_kaur", "erim.kaur", "erimk",
    "byerim", "by_erim", "by.erim", "byerim_official",
    "byerim.official", "byerimofficial", "theerim",
    "real_erim", "realerim", "erim_official", "officialerim",
    "byerimstore", "byerimshop", "byerim_uk", "byerim_dubai",
]

# ─── Monitoring Settings ──────────────────────────────────────────────
SCAN_INTERVAL_HOURS = 6
MAX_DAILY_SEARCHES = 100
HASH_DISTANCE_THRESHOLD = 12
TEXT_SIMILARITY_THRESHOLD = 0.75
IMPERSONATION_RISK_THRESHOLD = 0.7

IMPERSONATION_WEIGHTS = {
    "profile_pic_match": 0.30,
    "bio_similarity": 0.20,
    "username_pattern": 0.20,
    "content_overlap": 0.20,
    "name_match": 0.10,
}

# ─── DMCA Configuration ──────────────────────────────────────────────
DMCA_CLAIMANT = {
    "name": "Erim Kaur",
    "company": "ByErim Ltd",
    "email": "legal@byerim.com",
    "address": "London, United Kingdom",
    "website": "https://www.byerim.com",
}

# ─── API Keys (Free Tier) ────────────────────────────────────────────
GOOGLE_CUSTOM_SEARCH_API_KEY = os.getenv("GOOGLE_CSE_API_KEY", "")
GOOGLE_CUSTOM_SEARCH_CX = os.getenv("GOOGLE_CSE_CX", "")

# ─── Rate Limiting ────────────────────────────────────────────────────
RATE_LIMITS = {
    "google_search": {"max_per_day": 100, "delay_seconds": 2},
    "instagram": {"max_per_hour": 60, "delay_seconds": 3},
    "tiktok": {"max_per_hour": 30, "delay_seconds": 5},
    "general_web": {"max_per_hour": 120, "delay_seconds": 1},
}
