"""
Database layer using sqlite3 (no external dependencies).
"""
import sqlite3
import json
from pathlib import Path
from backend.config import DB_PATH

DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_connection():
    """Get a database connection with row factory."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            brand TEXT NOT NULL,
            content_type TEXT NOT NULL DEFAULT 'image',
            title TEXT,
            description TEXT,
            source_url TEXT,
            source_platform TEXT,
            file_path TEXT,
            file_hash_md5 TEXT UNIQUE,
            phash TEXT,
            thumbnail_path TEXT,
            metadata_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            brand TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            platform TEXT,
            detected_url TEXT,
            infringer_username TEXT,
            confidence REAL DEFAULT 0.0,
            evidence_json TEXT DEFAULT '{}',
            status TEXT DEFAULT 'new',
            notes TEXT,
            detected_at TEXT DEFAULT (datetime('now')),
            resolved_at TEXT,
            FOREIGN KEY (asset_id) REFERENCES assets(id)
        );

        CREATE TABLE IF NOT EXISTS dmca_notices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id INTEGER NOT NULL,
            notice_type TEXT NOT NULL,
            template_used TEXT,
            recipient_email TEXT,
            recipient_platform TEXT,
            subject_line TEXT,
            body TEXT NOT NULL,
            pdf_path TEXT,
            status TEXT DEFAULT 'draft',
            created_at TEXT DEFAULT (datetime('now')),
            sent_at TEXT,
            response_at TEXT,
            response_text TEXT,
            FOREIGN KEY (threat_id) REFERENCES threats(id)
        );

        CREATE TABLE IF NOT EXISTS suspicious_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            brand TEXT NOT NULL,
            platform TEXT NOT NULL,
            username TEXT NOT NULL,
            profile_url TEXT,
            profile_pic_url TEXT,
            display_name TEXT,
            bio_text TEXT,
            follower_count INTEGER,
            post_count INTEGER,
            risk_score REAL DEFAULT 0.0,
            detection_reasons_json TEXT DEFAULT '[]',
            status TEXT DEFAULT 'suspected',
            detected_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            brand TEXT,
            platform TEXT,
            items_scanned INTEGER DEFAULT 0,
            threats_found INTEGER DEFAULT 0,
            execution_time_seconds REAL,
            status TEXT DEFAULT 'running',
            error_message TEXT,
            started_at TEXT DEFAULT (datetime('now')),
            completed_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_threats_brand ON threats(brand);
        CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
        CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(threat_type);
        CREATE INDEX IF NOT EXISTS idx_suspects_brand ON suspicious_accounts(brand);
    """)
    conn.commit()
    conn.close()
    print(f"[DB] Database initialized at {DB_PATH}")


def row_to_dict(row):
    """Convert sqlite3.Row to dict."""
    if row is None:
        return None
    return dict(row)


def rows_to_dicts(rows):
    """Convert list of sqlite3.Row to list of dicts."""
    return [dict(r) for r in rows]


def query(sql, params=(), one=False):
    """Execute a query and return results."""
    conn = get_connection()
    try:
        cursor = conn.execute(sql, params)
        if one:
            row = cursor.fetchone()
            return row_to_dict(row)
        return rows_to_dicts(cursor.fetchall())
    finally:
        conn.close()


def execute(sql, params=()):
    """Execute a write operation and return lastrowid."""
    conn = get_connection()
    try:
        cursor = conn.execute(sql, params)
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()
