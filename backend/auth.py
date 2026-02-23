"""
Brand Shield — Authentication Module
Session-based auth with hashed passwords. Zero external dependencies.
"""
import hashlib
import secrets
import os
import json
import time
from pathlib import Path

# ─── Config ──────────────────────────────────────────────────────
AUTH_DIR = Path(__file__).resolve().parent.parent / "data"
USERS_FILE = AUTH_DIR / "users.json"
SESSION_EXPIRY = 86400 * 7  # 7 days

# In-memory session store
_sessions = {}


def _hash_password(password: str, salt: str = None) -> tuple:
    """Hash password with SHA-256 + salt."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return hashed, salt


def _load_users() -> dict:
    """Load users from JSON file."""
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    if USERS_FILE.exists():
        with open(USERS_FILE) as f:
            return json.load(f)
    return {}


def _save_users(users: dict):
    """Save users to JSON file."""
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def create_user(username: str, password: str, role: str = "admin") -> bool:
    """Create a new user."""
    users = _load_users()
    if username in users:
        return False
    hashed, salt = _hash_password(password)
    users[username] = {
        "password_hash": hashed,
        "salt": salt,
        "role": role,
        "created_at": time.time(),
    }
    _save_users(users)
    return True


def verify_user(username: str, password: str) -> bool:
    """Verify username/password."""
    users = _load_users()
    user = users.get(username)
    if not user:
        return False
    hashed, _ = _hash_password(password, user["salt"])
    return hashed == user["password_hash"]


def create_session(username: str) -> str:
    """Create a new session token."""
    token = secrets.token_hex(32)
    _sessions[token] = {
        "username": username,
        "created_at": time.time(),
    }
    return token


def validate_session(token: str) -> str | None:
    """Validate session token, return username or None."""
    if not token:
        return None
    session = _sessions.get(token)
    if not session:
        return None
    if time.time() - session["created_at"] > SESSION_EXPIRY:
        del _sessions[token]
        return None
    return session["username"]


def destroy_session(token: str):
    """Destroy a session."""
    _sessions.pop(token, None)


def has_users() -> bool:
    """Check if any users exist."""
    return bool(_load_users())


def setup_default_users():
    """Create default admin users if none exist."""
    if not has_users():
        create_user("sat", "BrandShield2026!", "admin")
        create_user("erim", "ByErim2026!", "admin")
        print("[AUTH] Default users created: sat, erim")
