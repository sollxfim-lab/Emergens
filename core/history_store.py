"""
core/history_store.py — persistent scan history backed by SQLite.

Supports:
    - Adding a new entry (returns entry ID)
    - Updating an entry (status, result JSON, error message)
    - Listing all entries (newest first, with optional limit)
    - Getting a single entry by ID
    - Deleting an entry
    - Clearing all entries
    - Auto‑migration: adds missing columns to existing databases
"""

import sqlite3
import json
import time
import logging
from typing import Optional, List, Dict, Any
from pathlib import Path

logger = logging.getLogger("oxysintx.history_store")

INSTANCE_DIR = Path("instance")
HISTORY_DB = INSTANCE_DIR / "history.db"


class HistoryStore:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or HISTORY_DB
        self._init_db()

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        """Create the table and apply any missing columns."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target      TEXT NOT NULL,
                    mode        TEXT NOT NULL DEFAULT 'basic',
                    tools       TEXT NOT NULL DEFAULT '[]',
                    status      TEXT NOT NULL DEFAULT 'pending',
                    result      TEXT,
                    error       TEXT,
                    created_at  TEXT NOT NULL
                )
            """)
            # Auto-migration for missing columns
            existing = [row[1] for row in conn.execute("PRAGMA table_info(history)").fetchall()]
            if "error" not in existing:
                conn.execute("ALTER TABLE history ADD COLUMN error TEXT")
                logger.info("Added 'error' column to history table")
            conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def add_entry(self, target: str, mode: str, tools: List[str],
                  status: str = "running") -> int:
        """Insert a new scan entry. Returns the new entry's ID."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        tools_json = json.dumps(tools)
        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO history (target, mode, tools, status, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (target, mode, tools_json, status, now)
            )
            conn.commit()
            entry_id = cursor.lastrowid
        logger.debug("History entry %d created for %s", entry_id, target)
        return entry_id

    def update_entry(self, entry_id: int, status: Optional[str] = None,
                     result: Optional[Dict[str, Any]] = None,
                     error: Optional[str] = None) -> None:
        """
        Update an existing history entry.

        Args:
            entry_id: The ID returned by add_entry.
            status: New status string (e.g. 'completed', 'cancelled').
            result: Dict of scan results (will be stored as JSON).
            error: Error message if the scan failed.
        """
        with self._connect() as conn:
            if status is not None:
                conn.execute("UPDATE history SET status = ? WHERE id = ?", (status, entry_id))
            if result is not None:
                conn.execute("UPDATE history SET result = ? WHERE id = ?",
                             (json.dumps(result), entry_id))
            if error is not None:
                conn.execute("UPDATE history SET error = ? WHERE id = ?", (error, entry_id))
            conn.commit()
        logger.debug("History entry %d updated (status=%s, error=%s)", entry_id, status, error)

    def get(self, entry_id: int) -> Optional[Dict[str, Any]]:
        """Return a single history entry as a dict, or None."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM history WHERE id = ?", (entry_id,)).fetchone()
        if not row:
            return None
        entry = dict(row)
        entry["tools"] = json.loads(entry.get("tools", "[]"))
        entry["result"] = json.loads(entry.get("result", "{}")) if entry.get("result") else None
        return entry

    def list_all(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return all history entries, newest first. Optional limit."""
        query = "SELECT id, target, mode, tools, status, created_at, error FROM history ORDER BY id DESC"
        if limit:
            query += f" LIMIT {int(limit)}"
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        return [{
            "id": r["id"],
            "target": r["target"],
            "mode": r["mode"],
            "tools": json.loads(r["tools"]),
            "status": r["status"],
            "created_at": r["created_at"],
            "error": r["error"],
        } for r in rows]

    def delete(self, entry_id: int) -> None:
        """Delete a single history entry."""
        with self._connect() as conn:
            conn.execute("DELETE FROM history WHERE id = ?", (entry_id,))
            conn.commit()
        logger.debug("History entry %d deleted", entry_id)

    def clear_all(self) -> None:
        """Delete all history entries."""
        with self._connect() as conn:
            conn.execute("DELETE FROM history")
            conn.commit()
        logger.info("All history entries deleted")

    def flush(self) -> None:
        """No-op for SQLite; kept for graceful shutdown compatibility."""
        pass