"""
Brand Shield v2.0 — Flask HTTP API Server with Authentication
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
PUBLIC_PATHS = {"/login", "/api/auth/login", "/api/auth/setup"}


def count_query(table, where="", params=()):
    sql = f"SELECT COUNT(*) as cnt FROM {table}"
    if where:
        sql += f" WHERE {where}"
    row = query(sql, params, one=True)
    return row["cnt"] if row else 0


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "brand-shield-dev-key-change-in-production")

init_db()
setup_default_users()


def check_auth():
    token = request.cookies.get("bs_session")
    return validate_session(token)


def require_auth(f):
    def decorated_function(*args, **kwargs):
        path = request.path
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
        "threats": {"total": total_threats, "new": new_threats, "resolved": resolved_threats, "reported": reported_threats, "by_brand": by_brand, "by_type": by_type, "by_platform": by_platform, "by_severity": by_severity},
        "dmca": {"total": total_notices, "sent": sent_notices, "success_rate": round(success_rate, 1)},
        "assets": {"total": total_assets},
        "suspects": {"total": total_suspects},
        "monitoring": {"is_running": False, "last_scan": last_scan},
    })


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
        execute("UPDATE threats SET status = ?, resolved_at = ? WHERE id = ?", (data["status"], resolved_at, tid))
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


@app.route("/api/assets", methods=["GET"])
@require_auth
def api_assets():
    assets = query("SELECT * FROM assets ORDER BY created_at DESC")
    return jsonify({"assets": assets, "total": len(assets)})


@app.route("/api/dmca", methods=["GET"])
@require_auth
def api_dmca_list():
    notices = query("SELECT * FROM dmca_notices ORDER BY created_at DESC")
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
    return jsonify({"error": "DMCA generation requires full app"}), 501


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


@app.route("/api/monitoring/status", methods=["GET"])
@require_auth
def api_monitoring_status():
    last_scan = query("SELECT * FROM scan_history ORDER BY started_at DESC LIMIT 1", one=True)
    pending = count_query("threats", "status = ?", ("new",))
    return jsonify({"is_running": False, "last_scan": last_scan, "pending_threats": pending})


@app.route("/api/scan/history", methods=["GET"])
@require_auth
def api_scan_history():
    scans = query("SELECT * FROM scan_history ORDER BY started_at DESC LIMIT 20")
    return jsonify({"scans": scans})


@app.route("/api/scan/run", methods=["POST"])
@require_auth
def api_scan_run():
    return jsonify({"message": "Scan started in background"})


@app.route("/api/brands", methods=["GET"])
@require_auth
def api_brands():
    return jsonify(BRANDS)


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
    return jsonify({"error": "Email sending requires full app"}), 501


def _load_login_html():
    filepath = STATIC_DIR / "login.html"
    if filepath.exists():
        with open(filepath) as f:
            return f.read()
    return ""


def _load_dashboard_html():
    filepath = STATIC_DIR / "dashboard.html"
    if filepath.exists():
        with open(filepath) as f:
            return f.read()
    return ""


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "0.0.0.0")
    print("=" * 60)
    print("  Brand Shield v2.0 — Protecting @erim & @byerim")
    print(f"  Dashboard: http://localhost:{port}")
    print(f"  Login required (users: sat, erim)")
    print("=" * 60)
    app.run(host=host, port=port, debug=False)
