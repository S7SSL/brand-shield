"""
Brand Shield v2.0 â Flask HTTP API Server with Authentication
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

# Initialize database and default users on startup
init_db()
setup_default_users()


# âââ Seed Data ââââââââââââââââââââââââââââââââââââââââââââââââ

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
            "status": "new",
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
            "status": "new",
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
            "status": "new",
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
            "status": "new",
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
            "status": "new",
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


# âââ Middleware âââââââââââââââââââââââââââââââââââââââââââââââ

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


# âââ Routes âââââââââââââââââââââââââââââââââââââââââââââââââââ

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


# âââ Auth API ââââââââââââââââââââââââââââââââââââââââââââââââââ

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


# âââ Dashboard API ââââââââââââââââââââââââââââââââââââââââââââ

@app.route("/api/dashboard/stats", methods=["GET"])
@require_auth
def api_dashboard_stats():
    total_threats = count_query("threats")
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


# âââ Threats API âââââââââââââââââââââââââââââââââââââââââââââââ

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


# âââ Assets API ââââââââââââââââââââââââââââââââââââââââââââââââ

@app.route("/api/assets", methods=["GET"])
@require_auth
def api_assets():
    assets = query("SELECT * FROM assets ORDER BY created_at DESC")
    return jsonify({"assets": assets, "total": len(assets)})


# âââ DMCA API ââââââââââââââââââââââââââââââââââââââââââââââââââ

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


# âââ Suspects API ââââââââââââââââââââââââââââââââââââââââââââââ

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


# âââ Monitoring API ââââââââââââââââââââââââââââââââââââââââââââ

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


# âââ Brands & Config API âââââââââââââââââââââââââââââââââââââââ

@app.route("/api/brands", methods=["GET"])
@require_auth
def api_brands():
    return jsonify(BRANDS)


# âââ Email API ââââââââââââââââââââââââââââââââââââââââââââââââ

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
    return jsonify({"error": "Email sending requires SMTP configuration"}), 501


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
    print("  Brand Shield v2.0 â Protecting @erim & @byerim")
    print(f"  Dashboard: http://localhost:{port}")
    print(f"  Login required (users: sat, erim)")
    print("=" * 60)

    app.run(host=host, port=port, debug=False)
