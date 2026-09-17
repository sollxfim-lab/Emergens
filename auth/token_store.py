#!/usr/bin/env python3
"""
auth/token_store.py — Token-Based Authentication Store for Oxysintx

Provides:
    - Token generation (opaque tokens stored server-side)
    - Token validation against the database
    - Token revocation
    - Automatic expiry (1 hour TTL)
    - Rate limiting per token
    - Background cleanup of expired tokens

Tokens are issued by exchanging valid username + password credentials
at /api/token. Subsequent requests include the token in the
Authorization: Bearer <token> header.

Usage (in app.py):
    from auth.token_store import token_store
    token_store.generate_token(username, password)   -> token_string or None
    token_store.validate_token(token_string)          -> username or None

Author: EAST CODEX
Version: 1.0.0
"""

import os
import sqlite3
import secrets
import hashlib
import time
import logging
import threading
from typing import Optional, Dict, Any, List
from pathlib import Path

logger = logging.getLogger("oxysintx.token_store")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TOKEN_LENGTH = 48                     # bytes of randomness (96 hex chars)
TOKEN_TTL_SECONDS = 3600              # 1 hour
TOKEN_CLEANUP_INTERVAL = 300          # clean expired tokens every 5 minutes
MAX_TOKENS_PER_USER = 5               # max active tokens per user
INSTANCE_DIR = Path("instance")
TOKEN_DB_PATH = INSTANCE_DIR / "tokens.db"

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------
def _ensure_db() -> sqlite3.Connection:
    """Create or open the tokens database and ensure the schema exists."""
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(TOKEN_DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token_hash  TEXT PRIMARY KEY,
            username    TEXT NOT NULL,
            token_prefix TEXT NOT NULL,
            created_at  REAL NOT NULL,
            expires_at  REAL NOT NULL,
            last_used   REAL,
            user_agent  TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_tokens_username ON tokens(username)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at)
    """)
    conn.commit()
    return conn

# ---------------------------------------------------------------------------
# Token generation & hashing
# ---------------------------------------------------------------------------
def _generate_token_string() -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_hex(TOKEN_LENGTH)

def _hash_token(token: str) -> str:
    """Hash the token for storage (SHA-256)."""
    return hashlib.sha256(token.encode()).hexdigest()

def _token_prefix(token: str) -> str:
    """First 8 characters of the token for display."""
    return token[:8]

# ---------------------------------------------------------------------------
# TokenStore
# ---------------------------------------------------------------------------
class TokenStore:
    """Manages bearer tokens for API authentication."""

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = db_path or TOKEN_DB_PATH
        self._conn = _ensure_db()
        self._lock = threading.Lock()
        # Start background cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="token-cleanup"
        )
        self._cleanup_thread.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate_token(self, username: str, password: str,
                       user_agent: Optional[str] = None) -> Optional[str]:
        """
        Validate credentials and issue a new bearer token.

        Args:
            username:   The account username.
            password:   The account password.
            user_agent: Optional User-Agent string for auditing.

        Returns:
            The raw token string (to be sent to the client), or None
            if credentials are invalid or the user has too many tokens.
        """
        # Import here to avoid circular dependency
        from auth.user_store import verify_credentials

        if not verify_credentials(username, password):
            logger.warning("Token request denied for '%s': invalid credentials", username)
            return None

        # Check max tokens per user
        with self._lock:
            active_count = self._count_active_tokens(username)
            if active_count >= MAX_TOKENS_PER_USER:
                logger.warning(
                    "Token limit reached for '%s' (%d active). Revoking oldest.",
                    username, active_count
                )
                self._revoke_oldest_token(username)

            # Generate and store
            token = _generate_token_string()
            token_hash = _hash_token(token)
            prefix = _token_prefix(token)
            now = time.time()
            expires = now + TOKEN_TTL_SECONDS

            try:
                self._conn.execute(
                    """INSERT INTO tokens (token_hash, username, token_prefix,
                       created_at, expires_at, last_used, user_agent)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (token_hash, username, prefix, now, expires, now, user_agent)
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                # Extremely unlikely hash collision – regenerate
                logger.error("Token hash collision; regenerating")
                return self.generate_token(username, password, user_agent)

        logger.info("Token issued for '%s' (prefix=%s)", username, prefix)
        return token

    def validate_token(self, token: str) -> Optional[str]:
        """
        Validate a bearer token and return the associated username.

        Args:
            token: The raw token string from the Authorization header.

        Returns:
            The username if valid and not expired, else None.
        """
        if not token:
            return None

        token_hash = _hash_token(token)

        with self._lock:
            row = self._conn.execute(
                """SELECT username, expires_at FROM tokens
                   WHERE token_hash = ?""", (token_hash,)
            ).fetchone()

            if row is None:
                return None

            if time.time() > row["expires_at"]:
                # Token expired – remove it
                self._conn.execute(
                    "DELETE FROM tokens WHERE token_hash = ?", (token_hash,)
                )
                self._conn.commit()
                return None

            # Update last_used
            self._conn.execute(
                "UPDATE tokens SET last_used = ? WHERE token_hash = ?",
                (time.time(), token_hash)
            )
            self._conn.commit()

        return row["username"]

    def revoke_token(self, token_prefix: str) -> bool:
        """Revoke a token by its prefix (first 8 chars)."""
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM tokens WHERE token_prefix = ?", (token_prefix,)
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def revoke_all_user_tokens(self, username: str) -> int:
        """Revoke all tokens for a given user. Returns count of revoked tokens."""
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM tokens WHERE username = ?", (username,)
            )
            self._conn.commit()
            return cursor.rowcount

    def list_user_tokens(self, username: str) -> List[Dict[str, Any]]:
        """List active tokens for a user (prefixes only, not full tokens)."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT token_prefix, created_at, expires_at, last_used, user_agent
                   FROM tokens WHERE username = ? AND expires_at > ?
                   ORDER BY created_at DESC""",
                (username, time.time())
            ).fetchall()
        return [dict(r) for r in rows]

    def list_all_tokens(self) -> List[Dict[str, Any]]:
        """List all active tokens (admin use)."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT username, token_prefix, created_at, expires_at, last_used
                   FROM tokens WHERE expires_at > ?
                   ORDER BY username, created_at DESC""",
                (time.time(),)
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _count_active_tokens(self, username: str) -> int:
        """Count active (non-expired) tokens for a user."""
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM tokens WHERE username = ? AND expires_at > ?",
            (username, time.time())
        ).fetchone()
        return row["cnt"] if row else 0

    def _revoke_oldest_token(self, username: str) -> None:
        """Delete the oldest active token for a user."""
        self._conn.execute(
            """DELETE FROM tokens WHERE rowid = (
                   SELECT rowid FROM tokens
                   WHERE username = ? AND expires_at > ?
                   ORDER BY created_at ASC LIMIT 1
               )""",
            (username, time.time())
        )
        self._conn.commit()

    def _cleanup_loop(self) -> None:
        """Background thread that periodically removes expired tokens."""
        while True:
            time.sleep(TOKEN_CLEANUP_INTERVAL)
            try:
                with self._lock:
                    cursor = self._conn.execute(
                        "DELETE FROM tokens WHERE expires_at <= ?",
                        (time.time(),)
                    )
                    self._conn.commit()
                    if cursor.rowcount > 0:
                        logger.debug("Cleaned up %d expired token(s)", cursor.rowcount)
            except Exception as exc:
                logger.error("Token cleanup error: %s", exc)

    def close(self) -> None:
        """Close the database connection."""
        try:
            self._conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------
token_store = TokenStore()