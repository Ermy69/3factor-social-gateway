"""
database.py — SQLite persistence layer
Stores users (credentials + public key) and active challenge tokens.
"""

import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "3fa.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables on first run."""
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username        TEXT PRIMARY KEY,
                hashed_password TEXT NOT NULL,
                totp_secret     TEXT NOT NULL,
                public_key_jwk  TEXT          -- stored after device registration (Factor 3)
            );

            CREATE TABLE IF NOT EXISTS challenges (
                username    TEXT PRIMARY KEY,
                challenge   TEXT NOT NULL,
                created_at  REAL NOT NULL      -- Unix timestamp for expiry checks
            );
        """)


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------

def create_user(username: str, hashed_password: str, totp_secret: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, hashed_password, totp_secret) VALUES (?, ?, ?)",
            (username, hashed_password, totp_secret),
        )

def get_user(username: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row:
            d = dict(row)
            if d.get("public_key_jwk"):
                d["public_key_jwk"] = json.loads(d["public_key_jwk"])
            return d
    return None

def save_public_key(username: str, public_key_jwk: dict):
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET public_key_jwk = ? WHERE username = ?",
            (json.dumps(public_key_jwk), username),
        )

def user_exists(username: str) -> bool:
    with get_conn() as conn:
        row = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        return row is not None


# ---------------------------------------------------------------------------
# Challenge helpers
# ---------------------------------------------------------------------------

import time

def store_challenge(username: str, challenge: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO challenges (username, challenge, created_at) VALUES (?, ?, ?)",
            (username, challenge, time.time()),
        )

def get_and_clear_challenge(username: str) -> str | None:
    """
    Retrieve the challenge and immediately delete it (one-time use).
    Returns None if not found or older than 5 minutes.
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT challenge, created_at FROM challenges WHERE username = ?", (username,)
        ).fetchone()
        if not row:
            return None
        # Expire after 5 minutes
        if time.time() - row["created_at"] > 300:
            conn.execute("DELETE FROM challenges WHERE username = ?", (username,))
            return None
        conn.execute("DELETE FROM challenges WHERE username = ?", (username,))
        return row["challenge"]
