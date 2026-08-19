#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
quick_menu.py — Emergens Quick Menu Flask Blueprint

Integrates with the main Oxysintx Flask application (app.py) as a Blueprint.
Provides REST API endpoints for the Quick Menu Settings page and Android clients.

This module runs INSIDE the main Flask server — no separate HTTP server needed.
It registers as `quick_menu_bp` and exposes the following endpoints:

    GET  /api/quick_menu/status
    GET  /api/quick_menu/menu
    GET  /api/quick_menu/actions
    POST /api/quick_menu/action

All endpoints require a valid session (same cookie as the rest of app.py).

Author: Yanxzyx
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request, session

VERSION = "2.0.0"
SERVICE_NAME = "quick_menu"
MAX_ACTION_LOG = 200

logger = logging.getLogger("oxysintx.quick_menu")

# ---------------------------------------------------------------------------
# Shared state — guarded by a lock for thread safety across Flask workers
# ---------------------------------------------------------------------------
class MenuState:
    """Holds the quick-menu definition and a rolling log of triggered actions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started_at = time.time()
        self.request_count = 0
        self.action_log: List[Dict[str, Any]] = []
        self.items: List[Dict[str, str]] = [
            {"id": "scan-basic", "label": "Basic Scan", "icon": "bolt"},
            {"id": "scan-expert", "label": "Expert Scan", "icon": "shield-halved"},
            {"id": "history", "label": "History", "icon": "clock-rotate-left"},
            {"id": "console", "label": "System Console", "icon": "terminal"},
            {"id": "chat", "label": "AI Assistant", "icon": "robot"},
            {"id": "telegram", "label": "Telegram Bot", "icon": "telegram"},
        ]
        self.valid_action_ids = {item["id"] for item in self.items}

    def uptime_seconds(self) -> float:
        return round(time.time() - self.started_at, 1)

    def touch(self) -> None:
        with self._lock:
            self.request_count += 1

    def record_action(self, action: str, source: str, username: str = "anonymous") -> Dict[str, Any]:
        with self._lock:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "action": action,
                "source": source or "unknown",
                "username": username,
            }
            self.action_log.append(entry)
            if len(self.action_log) > MAX_ACTION_LOG:
                self.action_log = self.action_log[-MAX_ACTION_LOG:]
            return entry

    def recent_actions(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.action_log[-limit:])

    def get_menu(self) -> List[Dict[str, str]]:
        with self._lock:
            return list(self.items)

    def add_item(self, item: Dict[str, str]) -> bool:
        with self._lock:
            item_id = item.get("id", "").strip()
            if not item_id:
                return False
            if any(i["id"] == item_id for i in self.items):
                return False
            self.items.append(item)
            self.valid_action_ids.add(item_id)
            return True

    def remove_item(self, item_id: str) -> bool:
        with self._lock:
            if item_id not in self.valid_action_ids:
                return False
            self.items = [i for i in self.items if i["id"] != item_id]
            self.valid_action_ids.discard(item_id)
            return True


STATE = MenuState()


# ---------------------------------------------------------------------------
# Authentication helper
# ---------------------------------------------------------------------------
def _require_auth():
    """Check if user is authenticated; return username or None."""
    if session.get("authenticated"):
        return session.get("username", "anonymous")
    return None


# ---------------------------------------------------------------------------
# Flask Blueprint
# ---------------------------------------------------------------------------
quick_menu_bp = Blueprint("quick_menu", __name__)


@quick_menu_bp.route("/api/quick_menu/status", methods=["GET"])
def quick_menu_status():
    """Health check endpoint."""
    STATE.touch()
    username = _require_auth()
    if not username:
        return jsonify({"error": "unauthorized"}), 401

    return jsonify({
        "status": "online",
        "service": SERVICE_NAME,
        "version": VERSION,
        "uptime_seconds": STATE.uptime_seconds(),
        "requests_served": STATE.request_count,
        "user": username,
    })


@quick_menu_bp.route("/api/quick_menu/menu", methods=["GET"])
def quick_menu_get_menu():
    """Return the list of quick-menu items."""
    STATE.touch()
    username = _require_auth()
    if not username:
        return jsonify({"error": "unauthorized"}), 401

    return jsonify({
        "items": STATE.get_menu(),
        "total": len(STATE.get_menu()),
    })


@quick_menu_bp.route("/api/quick_menu/actions", methods=["GET"])
def quick_menu_get_actions():
    """Return the most recent triggered actions."""
    STATE.touch()
    username = _require_auth()
    if not username:
        return jsonify({"error": "unauthorized"}), 401

    limit = min(request.args.get("limit", 50, type=int), 200)
    if limit < 1:
        limit = 50

    return jsonify({
        "actions": STATE.recent_actions(limit),
        "total": len(STATE.recent_actions(limit)),
    })


@quick_menu_bp.route("/api/quick_menu/action", methods=["POST"])
def quick_menu_trigger_action():
    """Record that an action was triggered."""
    STATE.touch()
    username = _require_auth()
    if not username:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    action = (data.get("action") or "").strip()
    source = (data.get("source") or "web").strip()

    if not action:
        return jsonify({"error": "action_required"}), 400

    if action not in STATE.valid_action_ids:
        return jsonify({
            "error": "unknown_action",
            "received": action,
            "valid_actions": sorted(STATE.valid_action_ids),
        }), 400

    entry = STATE.record_action(action, source, username)
    logger.info("Quick menu action triggered: %s (source=%s, user=%s)",
                action, source, username)

    return jsonify({
        "ok": True,
        "recorded": entry,
    })


# ===== Menu management (add/remove items) =====
@quick_menu_bp.route("/api/quick_menu/items", methods=["POST"])
def quick_menu_add_item():
    """Add a new menu item (admin only)."""
    STATE.touch()
    username = _require_auth()
    if not username:
        return jsonify({"error": "unauthorized"}), 401

    # Only owners can modify menu items
    if session.get("role") != "owner":
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    new_item = {
        "id": (data.get("id") or "").strip(),
        "label": (data.get("label") or "").strip(),
        "icon": (data.get("icon") or "bolt").strip(),
    }

    if not new_item["id"] or not new_item["label"]:
        return jsonify({"error": "id_and_label_required"}), 400

    if STATE.add_item(new_item):
        logger.info("Quick menu item added: %s by %s", new_item["id"], username)
        return jsonify({"ok": True, "item": new_item})
    else:
        return jsonify({"error": "duplicate_or_invalid_item"}), 400


@quick_menu_bp.route("/api/quick_menu/items/<item_id>", methods=["DELETE"])
def quick_menu_remove_item(item_id: str):
    """Remove a menu item (admin only)."""
    STATE.touch()
    username = _require_auth()
    if not username:
        return jsonify({"error": "unauthorized"}), 401

    if session.get("role") != "owner":
        return jsonify({"error": "forbidden"}), 403

    if STATE.remove_item(item_id):
        logger.info("Quick menu item removed: %s by %s", item_id, username)
        return jsonify({"ok": True, "removed": item_id})
    else:
        return jsonify({"error": "item_not_found"}), 404


# ---------------------------------------------------------------------------
# Direct-run fallback (optional, for testing outside Flask)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"{SERVICE_NAME} v{VERSION}")
    print("This module is designed to run as a Flask Blueprint inside app.py.")
    print("Run the main Flask server instead: python app.py")
    print("\nAvailable endpoints (when integrated):")
    print("  GET  /api/quick_menu/status")
    print("  GET  /api/quick_menu/menu")
    print("  GET  /api/quick_menu/actions")
    print("  POST /api/quick_menu/action")
    print("  POST /api/quick_menu/items")
    print("  DELETE /api/quick_menu/items/<item_id>")