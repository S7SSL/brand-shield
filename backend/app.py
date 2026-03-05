"""
Brand Shield v2.0 Ã¢ÂÂ Flask HTTP API Server with Authentication
Compatible with Gunicorn for Render.com deployment.
"""
import os
import sys
import json
import threading
import mimetypes
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone
from pathlib import Path

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database import init_db, query, execute
from backend.config import BRANDS, BASE_DIR
from backend.auth import (
    verify_user, create_session, validate_session, destroy_session,
    setup_default_users, has_users, create_user,
)

from flask import Flask, render_template_string, request, jsonify, redirect, session

STATIC_DIR = BASE_DIR / "backend" / "static"
TEMPLATE_DIR = BASE_DIR / "backend" / "templates"

# Routes that don't require authentication
PUBLIC_PATHS = {"/login", "/api/auth/login", "/api/auth/setup"}


def count_query(table, where="", params=()):
    """Helper: COUNT(*) query."""
    sql = f"SELECT COUNT(*) as cnt FROM {table}"
    if where:
        sql += f" WHERE {where}"
    row = query(sql, params, one=True)
    return row["cnt"] if row else 0


# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "brand-shield-dev-key-change-in-production")

# SMTP Configuration (set via Render environment variables)
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "legal@byerim.com")

# Initialize database and default users on startup
init_db()
setup_default_users()


# Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂ Seed Data Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

def seed_demo_data():
    """Seed the database with realistic demo data if empty."""
    if count_query("threats") > 0:
        return  # Already has data

    print("[SEED] Populating demo data...")

    # Demo threats
    demo_threats = [
        {
            "brand": "@erim",
            "threat_type": "impersonation",
            "severity": "critical",
            "platform": "instagram",
            "detected_url": "https://instagram.com/erim.official.backup",
            "infringer_username": "erim.official.backup",
            "confidence": 0.94,
            "evidence_json": json.dumps({"bio_match": 0.91, "profile_pic_match": 0.88, "name_match": 1.0}),
            "status": "reported",
            "detected_at": "2026-02-22 14:30:00",
        },
        {
            "brand": "@erim",
            "threat_type": "content_theft",
            "severity": "high",
            "platform": "tiktok",
            "detected_url": "https://tiktok.com/@stolen_erim_vids/video/12345",
            "infringer_username": "stolen_erim_vids",
            "confidence": 0.87,
            "evidence_json": json.dumps({"video_hash_match": 0.87, "caption_similarity": 0.72}),
            "status": "reported",
            "detected_at": "2026-02-21 09:15:00",
        },
        {
            "brand": "@byerim",
            "threat_type": "counterfeit",
            "severity": "critical",
            "platform": "shopify",
            "detected_url": "https://byerim-official-store.myshopify.com/products/beard-oil",
            "infringer_username": "ByErimOfficialStore",
            "confidence": 0.92,
            "evidence_json": json.dumps({"product_image_match": 0.92, "brand_name_used": True, "price_undercut": True}),
            "status": "reported",
            "detected_at": "2026-02-22 18:45:00",
        },
        {
            "brand": "@byerim",
            "threat_type": "counterfeit",
            "severity": "high",
            "platform": "amazon",
            "detected_url": "https://amazon.co.uk/dp/B0FAKE12345",
            "infringer_username": "LuxHairCareUK",
            "confidence": 0.85,
            "evidence_json": json.dumps({"product_image_match": 0.85, "brand_name_used": True, "listing_title": "ByErim Beard Oil Premium - 50ml"}),
            "status": "reported",
            "detected_at": "2026-02-20 11:20:00",
        },
        {
            "brand": "@erim",
            "threat_type": "impersonation",
            "severity": "high",
            "platform": "twitter",
            "detected_url": "https://twitter.com/TheRealErimKaur",
            "infringer_username": "TheRealErimKaur",
            "confidence": 0.79,
            "evidence_json": json.dumps({"bio_match": 0.65, "profile_pic_match": 0.82, "name_match": 0.9}),
            "status": "reported",
            "detected_at": "2026-02-23 02:10:00",
        },
        {
            "brand": "@erim",
            "threat_type": "content_theft",
            "severity": "medium",
            "platform": "facebook",
            "detected_url": "https://facebook.com/erimkaur.fanpage/posts/98765",
            "infringer_username": "ErimKaurFanPage",
            "confidence": 0.73,
            "evidence_json": json.dumps({"image_hash_match": 0.73, "caption_copied": True}),
            "status": "resolved",
            "detected_at": "2026-02-18 16:00:00",
            "resolved_at": "2026-02-19 10:30:00",
        },
        {
            "brand": "@byerim",
            "threat_type": "text_theft",
            "severity": "medium",
            "platform": "web",
            "detected_url": "https://cheapbeardoils.com/byerim-review",
            "infringer_username": "cheapbeardoils.com",
            "confidence": 0.81,
            "evidence_json": json.dumps({"text_similarity": 0.81, "paragraphs_copied": 4}),
            "status": "reported",
            "detected_at": "2026-02-22 08:00:00",
        },
        {
            "brand": "@erim",
            "threat_type": "impersonation",
            "severity": "low",
            "platform": "youtube",
            "detected_url": "https://youtube.com/c/ErimKaurOfficial2",
            "infringer_username": "ErimKaurOfficial2",
            "confidence": 0.62,
            "evidence_json": json.dumps({"name_match": 0.85, "bio_match": 0.45}),
            "status": "resolved",
            "detected_at": "2026-02-15 12:00:00",
            "resolved_at": "2026-02-17 09:00:00",
        },
    ]

    for t in demo_threats:
        cols = ", ".join(t.keys())
        placeholders = ", ".join(["?"] * len(t))
        execute(f"INSERT INTO threats ({cols}) VALUES ({placeholders})", tuple(t.values()))

    # Demo suspicious accounts
    demo_suspects = [
        {
            "brand": "@erim",
            "platform": "instagram",
            "username": "erim.official.backup",
            "profile_url": "https://instagram.com/erim.official.backup",
            "display_name": "Erim Kaur Official",
            "bio_text": "Sikh creator | Motivational speaker | Spreading love and positivity",
            "follower_count": 2847,
            "post_count": 23,
            "risk_score": 0.94,
            "detection_reasons_json": json.dumps(["Profile pic matches @erim (88%)", "Bio text 91% similar", "Uses 'Official' in username", "Created recently"]),
            "status": "suspected",
        },
        {
            "brand": "@erim",
            "platform": "twitter",
            "username": "TheRealErimKaur",
            "profile_url": "https://twitter.com/TheRealErimKaur",
            "display_name": "Erim Kaur",
            "bio_text": "Content Creator & Speaker | Real account",
            "follower_count": 1203,
            "post_count": 45,
            "risk_score": 0.79,
            "detection_reasons_json": json.dumps(["Name matches @erim", "Profile pic similar (82%)", "Claims to be 'real' account"]),
            "status": "suspected",
        },
        {
            "brand": "@byerim",
            "platform": "instagram",
            "username": "byerim.shop",
            "profile_url": "https://instagram.com/byerim.shop",
            "display_name": "ByErim Hair Care",
            "bio_text": "Luxury Hair & Beard Care | Shop Now | Free UK Delivery",
            "follower_count": 567,
            "post_count": 12,
            "risk_score": 0.88,
            "detection_reasons_json": json.dumps(["Brand name in username", "Product photos copied", "Links to fake store", "Bio mimics @byerim"]),
            "status": "suspected",
        },
    ]

    for s in demo_suspects:
        cols = ", ".join(s.keys())
        placeholders = ", ".join(["?"] * len(s))
        execute(f"INSERT INTO suspicious_accounts ({cols}) VALUES ({placeholders})", tuple(s.values()))

    # Demo DMCA notices
    demo_notices = [
        {
            "threat_id": 4,
            "notice_type": "amazon",
            "template_used": "dmca_amazon.txt",
            "recipient_email": "copyright@amazon.co.uk",
            "recipient_platform": "amazon",
            "subject_line": "DMCA Takedown: Counterfeit ByErim Product",
            "body": "DMCA takedown notice for counterfeit ByErim beard oil listing on Amazon UK",
            "status": "sent",
            "created_at": "2026-02-20 12:00:00",
            "sent_at": "2026-02-20 12:05:00",
        },
        {
            "threat_id": 6,
            "notice_type": "meta",
            "template_used": "dmca_meta.txt",
            "recipient_email": "ip@fb.com",
            "recipient_platform": "facebook",
            "subject_line": "DMCA: Content Theft on Facebook Fan Page",
            "body": "DMCA takedown for stolen content on ErimKaurFanPage",
            "status": "resolved",
            "created_at": "2026-02-18 17:00:00",
            "sent_at": "2026-02-18 17:10:00",
            "response_at": "2026-02-19 10:00:00",
            "response_text": "Content has been removed",
        },
    ]

    for n in demo_notices:
        cols = ", ".join(n.keys())
        placeholders = ", ".join(["?"] * len(n))
        execute(f"INSERT INTO dmca_notices ({cols}) VALUES ({placeholders})", tuple(n.values()))

    # Demo scan history
    demo_scans = [
        {
            "scan_type": "full_scan",
            "brand": "@erim",
            "platform": "all",
            "items_scanned": 1247,
            "threats_found": 3,
            "execution_time_seconds": 45.2,
            "status": "completed",
            "started_at": "2026-02-23 00:00:00",
            "completed_at": "2026-02-23 00:00:45",
        },
        {
            "scan_type": "full_scan",
            "brand": "@byerim",
            "platform": "all",
            "items_scanned": 892,
            "threats_found": 2,
            "execution_time_seconds": 32.8,
            "status": "completed",
            "started_at": "2026-02-22 18:00:00",
            "completed_at": "2026-02-22 18:00:33",
        },
    ]

    for sc in demo_scans:
        cols = ", ".join(sc.keys())
        placeholders = ", ".join(["?"] * len(sc))
        execute(f"INSERT INTO scan_history ({cols}) VALUES ({placeholders})", tuple(sc.values()))

    print(f"[SEED] Added {len(demo_threats)} threats, {len(demo_suspects)} suspects, {len(demo_notices)} DMCA notices, {len(demo_scans)} scans")


# Run seed
seed_demo_data()


# Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂ Middleware Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

def check_auth():
    """Check if user is authenticated via session."""
    token = request.cookies.get("bs_session")
    return validate_session(token)


def require_auth(f):
    """Decorator to require authentication."""
    def decorated_function(*args, **kwargs):
        path = request.path

        # Public paths
        if path in PUBLIC_PATHS or path == "/login":
            return f(*args, **kwargs)
        if path.startswith("/static/") and "login" in path:
            return f(*args, **kwargs)

        username = check_auth()
        if not username:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect("/login")

        return f(*args, **kwargs)

    decorated_function.__name__ = f.__name__
    return decorated_function


# Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂ Routes Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

@app.route("/login", methods=["GET"])
def login_page():
    if check_auth():
        return redirect("/")
    return render_template_string(_load_login_html())


@app.route("/", methods=["GET"])
@require_auth
def dashboard():
    if not check_auth():
        return redirect("/login")
    return render_template_string(_load_dashboard_html())


@app.route("/static/<path:filename>", methods=["GET"])
@require_auth
def serve_static(filename):
    filepath = STATIC_DIR / filename
    if not filepath.exists():
        return {"error": "Not found"}, 404
    with open(filepath, "rb") as f:
        content_type, _ = mimetypes.guess_type(str(filepath))
        return f.read(), 200, {"Content-Type": content_type or "application/octet-stream"}


# Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂ Auth API Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400

    if verify_user(username, password):
        token = create_session(username)
        resp = jsonify({"success": True, "username": username})
        resp.set_cookie("bs_session", token, max_age=604800, path="/", httponly=True, samesite="Lax")
        return resp
    else:
        return jsonify({"success": False, "error": "Invalid username or password"}), 401


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    token = request.cookies.get("bs_session")
    if token:
        destroy_session(token)
    resp = jsonify({"success": True})
    resp.delete_cookie("bs_session", path="/")
    return resp


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def api_auth_me():
    username = check_auth()
    if not username:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"username": username, "authenticated": True})


# Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂ Dashboard API Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

@app.route("/api/dashboard")
@require_auth
def api_dashboard():
    """Dashboard stats - excludes resolved threats."""
    brand = request.args.get("brand")
    # Active threats (exclude resolved)
    sql_active = "SELECT COUNT(*) as c FROM threats WHERE status != 'resolved'"
    params_active = []
    if brand:
        sql_active += " AND brand = ?"
        params_active.append(brand)
    active = query(sql_active, params_active, one=True)
    active_count = active["c"] if active else 0

    # Critical/High counts
    sql_crit = "SELECT COUNT(*) as c FROM threats WHERE status != 'resolved' AND severity = 'critical'"
    sql_high = "SELECT COUNT(*) as c FROM threats WHERE status != 'resolved' AND severity = 'high'"
    params_sev = []
    if brand:
        sql_crit += " AND brand = ?"
        sql_high += " AND brand = ?"
        params_sev = [brand]
    crit = query(sql_crit, params_sev, one=True)
    high = query(sql_high, params_sev, one=True)
    crit_count = crit["c"] if crit else 0
    high_count = high["c"] if high else 0

    # New threats (last 7 days)
    sql_new = "SELECT COUNT(*) as c FROM threats WHERE status != 'resolved' AND detected_at >= datetime('now', '-7 days')"
    params_new = []
    if brand:
        sql_new += " AND brand = ?"
        params_new.append(brand)
    new_t = query(sql_new, params_new, one=True)
    new_count = new_t["c"] if new_t else 0

    # DMCA notices
    sql_dmca = "SELECT COUNT(*) as c FROM dmca_notices"
    dmca_total = query(sql_dmca, one=True)
    dmca_count = dmca_total["c"] if dmca_total else 0
    sql_dmca_resolved = "SELECT COUNT(*) as c FROM dmca_notices WHERE status = 'resolved'"
    dmca_res = query(sql_dmca_resolved, one=True)
    dmca_resolved = dmca_res["c"] if dmca_res else 0

    # Suspicious accounts
    sql_suspects = "SELECT COUNT(*) as c FROM suspects"
    suspects = query(sql_suspects, one=True)
    suspect_count = suspects["c"] if suspects else 0

    # Resolved threats total
    sql_resolved = "SELECT COUNT(*) as c FROM threats WHERE status = 'resolved'"
    resolved = query(sql_resolved, one=True)
    resolved_count = resolved["c"] if resolved else 0

    return jsonify({
        "active_threats": active_count,
        "new_detected": new_count,
        "critical_count": crit_count,
        "high_count": high_count,
        "dmca_notices": dmca_count,
        "dmca_resolved": dmca_resolved,
        "dmca_success_rate": round(dmca_resolved / dmca_count * 100) if dmca_count > 0 else 0,
        "suspect_accounts": suspect_count,
        "resolved_threats": resolved_count
    })


@app.route("/api/dashboard/stats", methods=["GET"])
@require_auth
def api_dashboard_stats():
    total_threats = count_query("threats", "status NOT IN (?, ?)", ("resolved", "reported"))
    new_threats = count_query("threats", "status = ?", ("new",))
    resolved_threats = count_query("threats", "status = ?", ("resolved",))
    reported_threats = count_query("threats", "status = ?", ("reported",))
    total_notices = count_query("dmca_notices")
    sent_notices = count_query("dmca_notices", "status = ?", ("sent",))
    total_assets = count_query("assets")
    total_suspects = count_query("suspicious_accounts")

    by_brand = {}
    for brand in BRANDS:
        by_brand[brand] = count_query("threats", "brand = ?", (brand,))

    by_type = {}
    for ttype in ["content_theft", "impersonation", "counterfeit", "text_theft"]:
        by_type[ttype] = count_query("threats", "threat_type = ?", (ttype,))

    platforms = query("SELECT DISTINCT platform FROM threats WHERE platform IS NOT NULL")
    by_platform = {}
    for p in platforms:
        by_platform[p["platform"]] = count_query("threats", "platform = ?", (p["platform"],))

    by_severity = {}
    for sev in ["critical", "high", "medium", "low"]:
        by_severity[sev] = count_query("threats", "severity = ?", (sev,))

    last_scan = query("SELECT * FROM scan_history ORDER BY started_at DESC LIMIT 1", one=True)

    total_dmca = count_query("dmca_notices")
    resolved_dmca = count_query("dmca_notices", "status = ?", ("resolved",))
    success_rate = (resolved_dmca / total_dmca * 100) if total_dmca > 0 else 0

    return jsonify({
        "threats": {
            "total": total_threats, "new": new_threats,
            "resolved": resolved_threats, "reported": reported_threats,
            "by_brand": by_brand, "by_type": by_type,
            "by_platform": by_platform, "by_severity": by_severity,
        },
        "dmca": {"total": total_notices, "sent": sent_notices, "success_rate": round(success_rate, 1)},
        "assets": {"total": total_assets},
        "suspects": {"total": total_suspects},
        "monitoring": {"is_running": False, "last_scan": last_scan},
    })


# Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂ Threats API Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

@app.route("/api/threats", methods=["GET"])
@require_auth
def api_threats():
    sql = "SELECT * FROM threats WHERE 1=1"
    p = []

    brand = request.args.get("brand")
    if brand:
        sql += " AND brand = ?"; p.append(brand)
    status = request.args.get("status")
    if status:
        sql += " AND status = ?"; p.append(status)
    else:
        sql += " AND status != ?"; p.append("resolved")
    ttype = request.args.get("type")
    if ttype:
        sql += " AND threat_type = ?"; p.append(ttype)
    platform = request.args.get("platform")
    if platform:
        sql += " AND platform = ?"; p.append(platform)

    sql += " ORDER BY detected_at DESC LIMIT 100"
    threats = query(sql, tuple(p))

    for t in threats:
        try:
            t["evidence"] = json.loads(t.get("evidence_json", "{}"))
        except:
            t["evidence"] = {}

    return jsonify({"threats": threats, "total": len(threats)})


@app.route("/api/threats", methods=["POST"])
@require_auth
def api_create_threat():
    data = request.get_json() or {}
    required = ["threat_type", "platform", "brand"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400

    threat_id = execute(
        """INSERT INTO threats (brand, threat_type, severity, platform, detected_url,
           infringer_username, confidence, evidence_json, status, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data.get("brand"),
            data.get("threat_type"),
            data.get("severity", "medium"),
            data.get("platform"),
            data.get("infringing_url", data.get("detected_url", "")),
            data.get("infringer_username", ""),
            data.get("confidence", 0.0),
            json.dumps(data.get("evidence", {})),
            data.get("status", "new"),
            data.get("notes", ""),
        ),
    )
    threat = query("SELECT * FROM threats WHERE id = ?", (threat_id,), one=True)
    return jsonify(threat), 201


@app.route("/api/threats/<int:tid>", methods=["GET"])
@require_auth
def api_threat_detail(tid):
    t = query("SELECT * FROM threats WHERE id = ?", (tid,), one=True)
    if not t:
        return jsonify({"error": "Not found"}), 404
    try:
        t["evidence"] = json.loads(t.get("evidence_json", "{}"))
    except:
        t["evidence"] = {}
    notices = query("SELECT * FROM dmca_notices WHERE threat_id = ?", (tid,))
    t["dmca_notices"] = notices
    return jsonify(t)


@app.route("/api/threats/<int:tid>", methods=["PUT"])
@require_auth
def api_update_threat(tid):
    data = request.get_json() or {}
    threat = query("SELECT * FROM threats WHERE id = ?", (tid,), one=True)
    if not threat:
        return jsonify({"error": "Not found"}), 404

    if "status" in data:
        resolved_at = datetime.now(timezone.utc).isoformat() if data["status"] == "resolved" else None
        execute("UPDATE threats SET status = ?, resolved_at = ? WHERE id = ?",
                (data["status"], resolved_at, tid))
    if "notes" in data:
        execute("UPDATE threats SET notes = ? WHERE id = ?", (data["notes"], tid))
    if "severity" in data:
        execute("UPDATE threats SET severity = ? WHERE id = ?", (data["severity"], tid))

    updated = query("SELECT * FROM threats WHERE id = ?", (tid,), one=True)
    try:
        updated["evidence"] = json.loads(updated.get("evidence_json", "{}"))
    except:
        updated["evidence"] = {}
    return jsonify(updated)


@app.route("/api/threats/<int:tid>", methods=["DELETE"])
@require_auth
def api_delete_threat(tid):
    threat = query("SELECT * FROM threats WHERE id = ?", (tid,), one=True)
    if not threat:
        return jsonify({"error": "Not found"}), 404
    execute("DELETE FROM dmca_notices WHERE threat_id = ?", (tid,))
    execute("DELETE FROM threats WHERE id = ?", (tid,))
    return jsonify({"success": True, "deleted_id": tid})


@app.route("/api/threats/<int:tid>/ignore", methods=["POST"])
@require_auth
def api_ignore_threat(tid):
    threat = query("SELECT * FROM threats WHERE id = ?", (tid,), one=True)
    if not threat:
        return jsonify({"error": "Not found"}), 404
    new_status = "new" if threat["status"] == "ignored" else "ignored"
    execute("UPDATE threats SET status = ? WHERE id = ?", (new_status, tid))
    updated = query("SELECT * FROM threats WHERE id = ?", (tid,), one=True)
    return jsonify({"success": True, "threat": updated, "action": "unignored" if new_status == "new" else "ignored"})

# Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂ Assets API Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

@app.route("/api/assets", methods=["GET"])
@require_auth
def api_assets():
    assets = query("SELECT * FROM assets ORDER BY created_at DESC")
    return jsonify({"assets": assets, "total": len(assets)})


# Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂ DMCA API Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

@app.route("/api/dmca", methods=["GET"])
@require_auth
def api_dmca_list():
    notices = query(
        """SELECT d.*, t.brand, t.threat_type, t.platform as threat_platform,
                  t.detected_url, t.infringer_username, t.confidence
           FROM dmca_notices d
           LEFT JOIN threats t ON d.threat_id = t.id
           ORDER BY d.created_at DESC"""
    )
    return jsonify({"notices": notices, "total": len(notices)})


@app.route("/api/dmca/<int:nid>", methods=["GET"])
@require_auth
def api_dmca_detail(nid):
    n = query("SELECT * FROM dmca_notices WHERE id = ?", (nid,), one=True)
    if not n:
        return jsonify({"error": "Not found"}), 404
    return jsonify(n)


@app.route("/api/dmca/<int:nid>", methods=["PUT"])
@require_auth
def api_update_dmca(nid):
    data = request.get_json() or {}
    if "status" in data:
        execute("UPDATE dmca_notices SET status = ? WHERE id = ?", (data["status"], nid))
    return jsonify({"success": True})


@app.route("/api/dmca/generate", methods=["POST"])
@require_auth
def api_dmca_generate():
    data = request.get_json() or {}
    threat_id = data.get("threat_id")
    notice_type = data.get("notice_type", "general")

    if not threat_id:
        return jsonify({"error": "threat_id is required"}), 400

    threat = query("SELECT * FROM threats WHERE id = ?", (threat_id,), one=True)
    if not threat:
        return jsonify({"error": "Threat not found"}), 404

    # Load template
    template_file = f"dmca_{notice_type}.txt"
    template_path = TEMPLATE_DIR / template_file
    if not template_path.exists():
        template_path = TEMPLATE_DIR / "dmca_general.txt"
        template_file = "dmca_general.txt"

    with open(template_path) as f:
        template = f.read()

    # Fill template
    from backend.config import DMCA_CLAIMANT
    now = datetime.now().strftime("%B %d, %Y")
    body = template.replace("{{ date }}", now)
    body = body.replace("{{ claimant_name }}", DMCA_CLAIMANT.get("name", ""))
    body = body.replace("{{ company }}", DMCA_CLAIMANT.get("company", ""))
    body = body.replace("{{ claimant_email }}", DMCA_CLAIMANT.get("email", ""))
    body = body.replace("{{ claimant_address }}", DMCA_CLAIMANT.get("address", ""))
    body = body.replace("{{ claimant_website }}", DMCA_CLAIMANT.get("website", ""))
    body = body.replace("{{ infringing_url }}", threat.get("detected_url", ""))
    body = body.replace("{{ infringer_username }}", threat.get("infringer_username", ""))
    body = body.replace("{{ infringing_platform }}", threat.get("platform", ""))
    body = body.replace("{{ product_title }}", data.get("product_title", "N/A"))
    body = body.replace("{{ original_url }}", data.get("original_url", DMCA_CLAIMANT.get("website", "")))
    body = body.replace("{{ original_description }}", data.get("original_description", f"Original content by {threat.get('brand', '')}"))
    body = body.replace("{{ recipient_name }}", data.get("recipient_name", "Copyright Team"))
    body = body.replace("{{ confidence }}", str(int(threat.get("confidence", 0) * 100)))
    body = body.replace("{{ evidence_description }}", data.get("evidence_description",
        f"The content at the infringing URL matches our original content with {int(threat.get('confidence', 0) * 100)}% confidence."))

    # Determine platform email
    platform_emails = {
        "instagram": "ip@fb.com",
        "facebook": "ip@fb.com",
        "tiktok": "legal@tiktok.com",
        "shopify": "legal@shopify.com",
        "amazon": "copyright@amazon.com",
        "twitter": "copyright@twitter.com",
        "youtube": "copyright@youtube.com",
    }
    recipient_email = platform_emails.get(threat.get("platform", ""), data.get("recipient_email", ""))

    # Save notice
    notice_id = execute(
        """INSERT INTO dmca_notices (threat_id, notice_type, template_used, recipient_email,
           recipient_platform, subject_line, body, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            threat_id, notice_type, template_file, recipient_email,
            threat.get("platform", ""),
            f"DMCA Takedown Notice: {threat.get('threat_type', '')} on {threat.get('platform', '')}",
            body, "draft",
        ),
    )

    # Update threat status
    execute("UPDATE threats SET status = ? WHERE id = ?", ("reported", threat_id))

    notice = query("SELECT * FROM dmca_notices WHERE id = ?", (notice_id,), one=True)
    return jsonify({"success": True, "notice": notice, "body_preview": body}), 201


# Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂ Suspects API Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

@app.route("/api/suspects", methods=["GET"])
@require_auth
def api_suspects():
    sql = "SELECT * FROM suspicious_accounts"
    p = []
    brand = request.args.get("brand")
    if brand:
        sql += " WHERE brand = ?"; p.append(brand)
    sql += " ORDER BY risk_score DESC"
    suspects = query(sql, tuple(p))
    for s in suspects:
        try:
            s["detection_reasons"] = json.loads(s.get("detection_reasons_json", "[]"))
        except:
            s["detection_reasons"] = []
    return jsonify({"suspects": suspects, "total": len(suspects)})


# Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂ Monitoring API Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

@app.route("/api/monitoring/status", methods=["GET"])
@require_auth
def api_monitoring_status():
    last_scan = query("SELECT * FROM scan_history ORDER BY started_at DESC LIMIT 1", one=True)
    pending = count_query("threats", "status = ?", ("new",))
    running = query("SELECT id FROM scan_history WHERE status = 'running' LIMIT 1", one=True)
    try:
        from backend.services.scheduler import get_status
        scheduler = get_status()
    except Exception:
        scheduler = {"scheduler_running": False, "scanning_enabled": False}
    return jsonify({
        "is_running": running is not None,
        "last_scan": last_scan,
        "pending_threats": pending,
        "scheduler": scheduler,
    })


@app.route("/api/monitoring/toggle", methods=["POST"])
@require_auth
def api_monitoring_toggle():
    data = request.get_json() or {}
    enabled = data.get("enabled", True)
    from backend.services.scheduler import enable_scanning, disable_scanning, get_status
    if enabled:
        enable_scanning()
    else:
        disable_scanning()
    return jsonify(get_status())


@app.route("/api/scan/history", methods=["GET"])
@require_auth
def api_scan_history():
    scans = query("SELECT * FROM scan_history ORDER BY started_at DESC LIMIT 20")
    return jsonify({"scans": scans})


@app.route("/api/scan/run", methods=["POST"])
@require_auth
def api_scan_run():
    data = request.get_json() or {}
    brand = data.get("brand")
    platform = data.get("platform")

    def background_scan():
        from backend.services.scanner import run_full_scan
        run_full_scan(brand=brand, platform=platform)

    t = threading.Thread(target=background_scan, daemon=True)
    t.start()
    return jsonify({"message": "Scan started in background", "brand": brand or "all"})


# Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂ Brands & Config API Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

@app.route("/api/brands", methods=["GET"])
@require_auth
def api_brands():
    return jsonify(BRANDS)


# Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂ Email API Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

@app.route("/api/email/status", methods=["GET"])
@require_auth
def api_email_status():
    return jsonify({"total": 0, "sent": 0, "draft": 0})


@app.route("/api/email/pending", methods=["GET"])
@require_auth
def api_email_pending():
    return jsonify({"pending": [], "total": 0})


@app.route("/api/email/log", methods=["GET"])
@require_auth
def api_email_log():
    notices = query(
        """SELECT d.*, t.brand, t.threat_type, t.platform as threat_platform,
                  t.detected_url, t.confidence, t.infringer_username
           FROM dmca_notices d
           LEFT JOIN threats t ON d.threat_id = t.id
           ORDER BY d.created_at DESC"""
    )
    return jsonify({"emails": notices, "total": len(notices)})


@app.route("/api/email/send", methods=["POST"])
@require_auth
def api_email_send():
    """Send an email via SMTP."""
    data = request.get_json() or {}
    to_email = data.get("to")
    subject = data.get("subject")
    body_text = data.get("body")
    notice_id = data.get("notice_id")

    if not to_email or not subject or not body_text:
        return jsonify({"error": "to, subject, and body are required"}), 400

    if not SMTP_HOST or not SMTP_USER:
        if notice_id:
            now = datetime.now(timezone.utc).isoformat()
            execute("UPDATE dmca_notices SET status = ?, sent_at = ? WHERE id = ?",
                    ("sent", now, notice_id))
        return jsonify({"success": True, "method": "simulated", "message": "SMTP not configured - simulated send."})

    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body_text, "plain"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        if notice_id:
            now = datetime.now(timezone.utc).isoformat()
            execute("UPDATE dmca_notices SET status = ?, sent_at = ? WHERE id = ?",
                    ("sent", now, notice_id))
        return jsonify({"success": True, "method": "smtp", "message": "Email sent successfully"})
    except Exception as e:
        return jsonify({"error": f"Failed to send email: {str(e)}"}), 500


def _load_login_html():
    """Load login.html content."""
    filepath = STATIC_DIR / "login.html"
    if filepath.exists():
        with open(filepath) as f:
            return f.read()
    return ""


def _load_dashboard_html():
    """Load dashboard.html content."""
    filepath = STATIC_DIR / "dashboard.html"
    if filepath.exists():
        with open(filepath) as f:
            return f.read()
    return ""






# ═══ DMCA Send & Confirm API ═════════════════════════════════
@app.route("/api/dmca/<int:nid>/send", methods=["POST"])
@require_auth
def api_dmca_send(nid):
    """Send a DMCA notice via email."""
    notice = query("SELECT * FROM dmca_notices WHERE id = ?", (nid,), one=True)
    if not notice:
        return jsonify({"error": "Notice not found"}), 404
    if notice["status"] == "sent":
        return jsonify({"error": "Notice already sent"}), 400
    to_email = notice.get("recipient_email", "")
    subject = notice.get("subject_line", "DMCA Takedown Notice")
    body_text = notice.get("body", "")
    if not to_email:
        return jsonify({"error": "No recipient email for this notice"}), 400
    if not SMTP_HOST or not SMTP_USER:
        now = datetime.now(timezone.utc).isoformat()
        execute("UPDATE dmca_notices SET status = ?, sent_at = ? WHERE id = ?", ("sent", now, nid))
        updated = query("SELECT * FROM dmca_notices WHERE id = ?", (nid,), one=True)
        return jsonify({"success": True, "method": "simulated", "message": f"DMCA notice sent to {to_email} (simulated)", "notice": updated})
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body_text, "plain"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        now = datetime.now(timezone.utc).isoformat()
        execute("UPDATE dmca_notices SET status = ?, sent_at = ? WHERE id = ?", ("sent", now, nid))
        updated = query("SELECT * FROM dmca_notices WHERE id = ?", (nid,), one=True)
        return jsonify({"success": True, "method": "smtp", "notice": updated})
    except Exception as e:
        return jsonify({"error": f"Failed to send: {str(e)}"}), 500


@app.route("/api/dmca/<int:nid>/confirm-removal", methods=["POST"])
@require_auth
def api_dmca_confirm_removal(nid):
    """Confirm content removed after DMCA notice."""
    data = request.get_json() or {}
    notice = query("SELECT * FROM dmca_notices WHERE id = ?", (nid,), one=True)
    if not notice:
        return jsonify({"error": "Notice not found"}), 404
    now = datetime.now(timezone.utc).isoformat()
    response_text = data.get("response_text", "Content confirmed removed")
    execute("UPDATE dmca_notices SET status = ?, response_at = ?, response_text = ? WHERE id = ?", ("resolved", now, response_text, nid))
    threat_id = notice.get("threat_id")
    if threat_id:
        execute("UPDATE threats SET status = ?, resolved_at = ? WHERE id = ?", ("resolved", now, threat_id))
    updated = query("SELECT * FROM dmca_notices WHERE id = ?", (nid,), one=True)
    return jsonify({"success": True, "notice": updated})


@app.route("/api/report/summary", methods=["GET"])
@require_auth
def api_report_summary():
    """Brand protection summary report."""
    sent_notices = count_query("dmca_notices", "status IN ('sent', 'resolved')")
    resolved_notices = count_query("dmca_notices", "status = 'resolved'")
    total_threats = count_query("threats")
    resolved_threats = count_query("threats", "status = 'resolved'")
    reported_threats = count_query("threats", "status = 'reported'")
    top_infringers = query("SELECT infringer_username, platform, COUNT(*) as threat_count FROM threats GROUP BY infringer_username ORDER BY threat_count DESC LIMIT 5")
    by_platform = query("SELECT platform, COUNT(*) as count FROM threats GROUP BY platform ORDER BY count DESC")
    return jsonify({"legal_notices_sent": sent_notices, "content_removed": resolved_notices, "total_threats_detected": total_threats, "threats_resolved": resolved_threats, "threats_reported": reported_threats, "top_infringers": top_infringers, "by_platform": by_platform, "report_period": datetime.now().strftime("%b %Y")})

# --- Weekly Report API ---
@app.route("/api/report/preview", methods=["GET"])
@require_auth
def api_report_preview():
    try:
        from backend.services.reporter import get_latest_report_html
        html = get_latest_report_html()
        return html, 200, {"Content-Type": "text/html"}
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/report/send", methods=["POST"])
@require_auth
def api_report_send():
    try:
        from backend.services.reporter import send_weekly_report
        result = send_weekly_report()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/report/status", methods=["GET"])
@require_auth
def api_report_status():
    try:
        from backend.services.scheduler import get_status
        status = get_status()
        report_job = next((j for j in status.get("jobs", []) if "report" in j.get("id", "")), None)
        return jsonify({
            "next_report": report_job.get("next_run") if report_job else None,
            "recipients": ["sat@byerim.com", "erim@byerim.com"],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Auto-Scheduler ---
import logging
logging.basicConfig(level=logging.INFO)

try:
    from backend.services.scheduler import init_scheduler
    init_scheduler(app)
except Exception as e:
    logging.warning(f"Scheduler init failed (non-critical): {e}")


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "0.0.0.0")

    print("=" * 60)
    print("  Brand Shield v2.0 Ã¢ÂÂ Protecting @erim & @byerim")
    print(f"  Dashboard: http://localhost:{port}")
    print(f"  Login required (users: sat, erim)")
    print("=" * 60)

    app.run(host=host, port=port, debug=False)
