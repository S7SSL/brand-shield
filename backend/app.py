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


# ─── Middleware ───────────────────────────────────────────────

def check_auth():
    """Check if user is authenticated via session."""
    token = request.cookies.get("bs_session")
    return validate_session(token)


def require_auth(f):
    """Decorator to require authentication."""
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


# ─── Routes ───────────────────────────────────────────────────

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


# ─── Auth API ──────────────────────────────────────────────────

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
