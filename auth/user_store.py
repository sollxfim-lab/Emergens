"""
auth/user_store.py — Username + password authentication, with roles and API keys.

Accounts are created only by the system (first run) or by an Owner from
the in-app Settings page.  API keys are stored per user.

Supports:
    - Secure password hashing (werkzeug)
    - Role-based access control (owner, analyst, viewer)
    - API key generation and revocation
    - User CRUD operations
    - Default owner creation on first run
    - Owner deletion protection (cannot delete the last owner)

Author: Yanxzyx
Version: 2.0.0
"""

import sqlite3
import secrets
import datetime
import logging
from typing import Optional, List, Dict, Tuple, Any

from werkzeug.security import generate_password_hash, check_password_hash

from config import Config

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_USERNAME = "Yanxzyx"
VALID_ROLES = ("owner", "analyst", "viewer")

logger = logging.getLogger("oxysintx.user_store")


# ---------------------------------------------------------------------------
# UserStore class
# ---------------------------------------------------------------------------
class UserStore:
    """Handles user accounts, authentication, and API key management."""

    def __init__(self, db_path: str = Config.USERS_DB):
        self.db_path = db_path
        self._init_db()

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        """Create a new database connection with WAL mode and foreign keys."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        """Create tables and run migrations if needed."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    username        TEXT UNIQUE NOT NULL,
                    password_hash   TEXT NOT NULL,
                    role            TEXT NOT NULL DEFAULT 'analyst',
                    api_key         TEXT,
                    api_key_created TEXT,
                    created_at      TEXT NOT NULL
                )
            """)
            # Migration: add missing columns for older databases
            existing_columns = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
            if "api_key" not in existing_columns:
                conn.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
            if "api_key_created" not in existing_columns:
                conn.execute("ALTER TABLE users ADD COLUMN api_key_created TEXT")
            conn.commit()
        logger.debug("User database initialised at %s", self.db_path)

    # ------------------------------------------------------------------
    # User existence checks
    # ------------------------------------------------------------------
    def has_any_user(self) -> bool:
        """Return True if at least one user exists in the database."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()
            return row["cnt"] > 0

    def user_exists(self, username: str) -> bool:
        """Return True if the given username exists."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
            return row is not None

    # ------------------------------------------------------------------
    # User CRUD
    # ------------------------------------------------------------------
    def create_user(self, username: str, role: str = "analyst",
                    password: Optional[str] = None) -> str:
        """
        Create a new user or reset an existing one.

        Args:
            username: The username (must be unique).
            role: One of 'owner', 'analyst', 'viewer'.
            password: Optional plaintext password. If None, a random 16-char
                      password is generated.

        Returns:
            The plaintext password (new or generated).

        Raises:
            ValueError: If the role is invalid or username is empty.
        """
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role: {role!r} (must be one of {VALID_ROLES})")

        username = username.strip()
        if not username:
            raise ValueError("Username is required")
        if len(username) < 2:
            raise ValueError("Username must be at least 2 characters")

        password = password or secrets.token_urlsafe(16)
        password_hash = generate_password_hash(password)
        now_iso = datetime.datetime.utcnow().isoformat()

        with self._connect() as conn:
            conn.execute("""
                INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password_hash = excluded.password_hash,
                    role          = excluded.role,
                    created_at    = excluded.created_at
            """, (username, password_hash, role, now_iso))
            conn.commit()

        logger.info("User '%s' created/updated (role=%s)", username, role)
        return password

    def verify_credentials(self, username: str, password: str) -> bool:
        """Check if the given username + password combination is valid."""
        if not username or not password:
            return False
        with self._connect() as conn:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()
        return row is not None and check_password_hash(row["password_hash"], password)

    def get_role(self, username: str) -> Optional[str]:
        """Return the role for the given username, or None if not found."""
        if not username:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT role FROM users WHERE username = ?", (username,)
            ).fetchone()
        return row["role"] if row else None

    def list_users(self) -> List[Dict[str, Any]]:
        """Return all users (username, role, created_at, has_api_key)."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT username, role, created_at,
                          CASE WHEN api_key IS NOT NULL THEN 1 ELSE 0 END AS has_api_key
                   FROM users
                   ORDER BY created_at ASC"""
            ).fetchall()
            return [dict(r) for r in rows]

    def delete_user(self, username: str) -> Tuple[bool, Optional[str]]:
        """
        Delete a user. Returns (success, error_message).

        Prevents deletion of the last remaining owner account.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT role FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not row:
                return False, "User not found"

            if row["role"] == "owner":
                owner_count = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM users WHERE role = 'owner'"
                ).fetchone()["cnt"]
                if owner_count <= 1:
                    return False, "Cannot delete the only remaining owner account"

            conn.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()

        logger.info("User '%s' deleted", username)
        return True, None

    def ensure_default_user(self) -> Optional[str]:
        """
        Create the default owner account if no users exist.

        Returns:
            The generated password if a new user was created, None otherwise.
        """
        if self.has_any_user():
            return None
        return self.create_user(DEFAULT_USERNAME, role="owner")

    # ------------------------------------------------------------------
    # API key management
    # ------------------------------------------------------------------
    def get_api_keys(self) -> List[Dict[str, str]]:
        """Return all users that have an API key, with masked prefix."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT username, api_key, api_key_created, created_at
                   FROM users
                   WHERE api_key IS NOT NULL
                   ORDER BY api_key_created DESC"""
            ).fetchall()
            return [{
                "prefix": r["api_key"][:20] + "****" if r["api_key"] else "—",
                "username": r["username"],
                "created": (r["api_key_created"] or r["created_at"])[:10],
                "last_used": "Active",
            } for r in rows]

    def generate_api_key(self, username: str) -> str:
        """
        Generate a new API key for the given user.

        Returns:
            The full API key string. Save it — it will not be retrievable again.
        """
        api_key = "oxy_sk_live_" + secrets.token_hex(20)
        now_iso = datetime.datetime.utcnow().isoformat()
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET api_key = ?, api_key_created = ? WHERE username = ?",
                (api_key, now_iso, username)
            )
            conn.commit()
        logger.info("API key generated for '%s'", username)
        return api_key

    def revoke_api_key(self, prefix: str) -> bool:
        """
        Revoke the API key matching the given prefix.

        Args:
            prefix: The first part of the key (e.g. 'oxy_sk_live_abc123').

        Returns:
            True if a key was revoked, False otherwise.
        """
        clean_prefix = prefix.replace("****", "")
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE users SET api_key = NULL, api_key_created = NULL WHERE api_key LIKE ?",
                (clean_prefix + "%",)
            )
            conn.commit()
            revoked = cursor.rowcount > 0
        if revoked:
            logger.info("API key revoked (prefix=%s...)", clean_prefix[:20])
        return revoked

    def count_api_keys(self) -> int:
        """Return the total number of active API keys."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM users WHERE api_key IS NOT NULL"
            ).fetchone()
            return row["cnt"] if row else 0


# ---------------------------------------------------------------------------
# Module-level convenience functions (preserve the original public API)
# ---------------------------------------------------------------------------

_store = UserStore(Config.USERS_DB)

has_any_user        = _store.has_any_user
create_user         = _store.create_user
verify_credentials  = _store.verify_credentials
get_role            = _store.get_role
list_users          = _store.list_users
delete_user         = _store.delete_user
ensure_default_user = _store.ensure_default_user