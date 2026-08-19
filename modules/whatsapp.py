"""
whatsapp.py — Oxysintx WhatsApp Integration Module (v6.1.0) · Full Sync & Log Handling
===============================================================================
Flask blueprint providing:

  1. GET  /webps.html              → serve the creds.json upload & status page
  2. POST /api/pair                 → request a WhatsApp pairing code
  3. POST /api/upload-creds         → receive creds.json (session‑based OR
                                      machine sync with X-Sync-API-Key header)
  4. GET  /api/bot-status           → JSON bot status
  5. GET  /api/bot-logs             → JSON tail logs + chat previews (from file)
  6. GET  /api/node-health          → proxy to Node.js /health
  7. POST /api/generate-sync-key    → generate a new SYNC_API_KEY after verifying
                                      Oxysintx credentials (username + password)
  8. GET  /api/validate-sync-key    → check if a given key is currently valid
  9. POST /api/ingest-logs          → accept log & chat data from the bot
                                      (authorized via X-Sync-API-Key)
 10. Helper `get_startup_status()`  → used by app.py for startup banner

Author: Yanxzyx
===============================================================================
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Blueprint, jsonify, render_template, request, session, url_for

from auth.decorators import api_login_required

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NODE_SERVER_HOST = os.environ.get("NODE_SERVER_HOST", "51.68.234.157")
NODE_SERVER_PORT = int(os.environ.get("NODE_SERVER_PORT", "20113"))

if NODE_SERVER_HOST in ("0.0.0.0", "::", "[::]"):
    logging.getLogger("oxysintx.whatsapp").warning(
        "NODE_SERVER_HOST is '%s' – falling back to 127.0.0.1", NODE_SERVER_HOST
    )
    NODE_SERVER_HOST = "127.0.0.1"

PAIR_PATH  = "/code"
CREDS_PATH = "/creds"
HEALTH_PATH = "/health"

REQUEST_TIMEOUT_SECONDS = 20
RATE_LIMIT_MAX_REQUESTS   = 3
RATE_LIMIT_WINDOW_SECONDS = 300

# Oxysintx API base (used for credential verification)
OXYSINTX_API_BASE = os.environ.get("OXYSINTX_API_BASE", "http://node1.lunes.host:2393")

# Path for persisting the current sync API key
SYNC_KEY_FILE = Path(os.environ.get("SYNC_KEY_FILE", "sync_key.txt"))

# Path for ingested logs & chats
INGESTED_LOG_FILE = Path("userdata") / "ingested_logs.json"

logger = logging.getLogger("oxysintx.whatsapp")
whatsapp_bp = Blueprint("whatsapp", __name__)


# ---------------------------------------------------------------------------
# Helper to retrieve the active sync API key
# ---------------------------------------------------------------------------
def _get_active_sync_key() -> str:
    """Return the sync key from file (if present) else from environment."""
    if SYNC_KEY_FILE.exists():
        try:
            with open(SYNC_KEY_FILE, "r", encoding="utf-8") as f:
                key = f.read().strip()
                if key:
                    return key
        except Exception:
            pass
    return os.environ.get("SYNC_API_KEY", "")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _build_node_url(path: str) -> str:
    host = NODE_SERVER_HOST.strip()
    port = NODE_SERVER_PORT
    if not host:
        raise RuntimeError("NODE_SERVER_HOST is empty.")
    if port < 1 or port > 65535:
        raise RuntimeError(f"NODE_SERVER_PORT '{port}' out of range.")
    if not path.startswith("/"):
        path = "/" + path
    return f"http://{host}:{port}{path}"

try:
    PAIR_URL  = _build_node_url(PAIR_PATH)
    CREDS_URL = _build_node_url(CREDS_PATH)
    HEALTH_URL = _build_node_url(HEALTH_PATH)
    logger.info("WhatsApp module active – pair: %s  creds: %s  health: %s",
                PAIR_URL, CREDS_URL, HEALTH_URL)
except Exception as exc:
    logger.critical("Invalid Node.js URL configuration: %s", exc)
    raise


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
_recent_requests: Dict[str, deque] = defaultdict(deque)

def _is_rate_limited(key: str) -> bool:
    now = time.time()
    hits = _recent_requests[key]
    while hits and now - hits[0] > RATE_LIMIT_WINDOW_SECONDS:
        hits.popleft()
    if len(hits) >= RATE_LIMIT_MAX_REQUESTS:
        return True
    hits.append(now)
    return False


# ---------------------------------------------------------------------------
# Number cleaner
# ---------------------------------------------------------------------------
def clean_number(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    digits = re.sub(r"[^0-9]", "", raw)
    if 6 <= len(digits) <= 19:
        return digits
    return None


# ---------------------------------------------------------------------------
# Pairing code request
# ---------------------------------------------------------------------------
def request_pairing_code(number: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        resp = requests.get(PAIR_URL, params={"number": number}, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.ConnectionError:
        return None, "Could not connect to the pairing server. Ensure Node.js is running."
    except requests.Timeout:
        return None, "The pairing server took too long to respond."
    except requests.RequestException as exc:
        logger.error("Pairing request failed: %s", exc)
        return None, "Could not reach the pairing service."

    if resp.status_code != 200:
        return None, f"Pairing server returned status {resp.status_code}."

    try:
        data = resp.json()
    except ValueError:
        return None, "Invalid response from pairing server."

    code = data.get("code") if isinstance(data, dict) else None
    if not code:
        return None, "No pairing code received."
    if code == "Service Unavailable":
        return None, "Service is currently unavailable."

    return code, None


# ---------------------------------------------------------------------------
# Bot profile management (per user)
# ---------------------------------------------------------------------------
def _profile_path(username: str) -> Path:
    return Path("userdata") / username / "bot_profile.json"

def _load_bot_profile(username: str) -> Dict[str, Any]:
    path = _profile_path(username)
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error("Failed to load bot profile for '%s': %s", username, e)
        return {}

def _save_bot_profile(username: str, profile: Dict[str, Any]) -> None:
    folder = Path("userdata") / username
    folder.mkdir(parents=True, exist_ok=True)
    with open(folder / "bot_profile.json", "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2)
    logger.info("Bot profile updated for '%s'", username)

def _extract_phone_from_creds(creds: Dict[str, Any]) -> Optional[str]:
    me = creds.get("me") or {}
    jid = me.get("id") or me.get("jid") or ""
    if ":" in jid:
        jid = jid.split(":")[0]
    number = re.sub(r"[^0-9]", "", jid)
    if len(number) >= 6:
        return number
    return None


# ---------------------------------------------------------------------------
# Node.js health query
# ---------------------------------------------------------------------------
def _fetch_node_health() -> Dict[str, Any]:
    try:
        resp = requests.get(HEALTH_URL, timeout=5)
        if resp.ok:
            return resp.json()
    except Exception as e:
        logger.error("Node /health failed: %s", e)
    return {}

def _get_bot_phone_from_node() -> Optional[str]:
    health = _fetch_node_health()
    bot_jid = health.get("botJid", "")
    if bot_jid:
        number = re.sub(r"[^0-9]", "", bot_jid.split("@")[0] if "@" in bot_jid else bot_jid)
        if len(number) >= 6:
            return number
    return None


# ============================================================================
# Routes
# ============================================================================

@whatsapp_bp.route("/webps.html")
def webps_page():
    return render_template("webps.html")


# ---- Pairing ----
@whatsapp_bp.route("/api/pair", methods=["POST"])
@api_login_required
def api_pair():
    body = request.get_json(silent=True) or {}
    number = clean_number(body.get("number"))
    if not number:
        return jsonify({"error": "Enter a valid WhatsApp number (6-19 digits)."}), 400

    if _is_rate_limited(number):
        return jsonify({"error": "Too many requests. Wait a few minutes."}), 429

    code, error = request_pairing_code(number)
    if error:
        return jsonify({"error": error}), 502

    logger.info("Pairing code for ****%s", number[-4:])
    return jsonify({"code": code, "number": number})


# ---- Credentials upload (supports sync key) ----
@whatsapp_bp.route("/api/upload-creds", methods=["POST"])
def api_upload_creds():
    """
    Receive a Baileys creds.json file.
    Authentication:
      - Session login (via @api_login_required) OR
      - X-Sync-API-Key header with a valid key.
    """
    sync_key = request.headers.get("X-Sync-API-Key", "")
    active_sync_key = _get_active_sync_key()

    if sync_key and active_sync_key and sync_key == active_sync_key:
        username = "whatsapp-bot"
    else:
        if not session.get("username"):
            return jsonify({"error": "Unauthorized. Provide a valid session or sync API key."}), 401
        username = session["username"]

    if "creds" not in request.files:
        return jsonify({"error": "No file provided. Use form field 'creds'."}), 400

    file = request.files["creds"]
    if file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    if not file.filename.lower().endswith(".json"):
        return jsonify({"error": "Only .json files are accepted."}), 400

    try:
        content = file.read()
        creds_data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return jsonify({"error": "Invalid JSON file."}), 400

    # ----- Save file locally -----
    user_dir = Path("userdata") / username
    user_dir.mkdir(parents=True, exist_ok=True)
    creds_path = user_dir / "creds.json"
    with open(creds_path, "wb") as f:
        f.write(content)

    # ----- Extract & store profile -----
    phone_number = _extract_phone_from_creds(creds_data)
    name = (creds_data.get("me") or {}).get("name", "")
    profile = {
        "phone": phone_number,
        "name": name,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "filename": file.filename,
    }
    _save_bot_profile(username, profile)

    # ----- Forward to Node.js -----
    try:
        resp = requests.post(CREDS_URL, json=creds_data, timeout=REQUEST_TIMEOUT_SECONDS)
        if not resp.ok:
            logger.error("Node /creds returned HTTP %s: %s", resp.status_code, resp.text[:300])
    except requests.RequestException as exc:
        logger.error("Could not reach Node.js /creds: %s", exc)

    logger.info("creds.json uploaded by '%s' – phone=%s", username, phone_number or "N/A")
    return jsonify({
        "success": True,
        "filename": file.filename,
        "size": len(content),
        "username": username,
        "phone": phone_number,
    })


# ---- Bot status ----
@whatsapp_bp.route("/api/bot-status")
@api_login_required
def api_bot_status():
    username = session.get("username", "unknown")
    profile = _load_bot_profile(username)
    phone = profile.get("phone")
    name = profile.get("name") or phone or "Unknown"

    online = False
    node_uptime = ""
    if phone:
        node_phone = _get_bot_phone_from_node()
        if node_phone and node_phone == phone:
            online = True
            health = _fetch_node_health()
            node_uptime = health.get("uptime", "")

    return jsonify({
        "phone": phone,
        "name": name,
        "online": online,
        "uptime": node_uptime,
        "last_upload": profile.get("uploaded_at", ""),
        "logs_url": url_for("whatsapp.api_bot_logs"),
    })


# ---- Bot logs (reads ingested data) ----
@whatsapp_bp.route("/api/bot-logs")
@api_login_required
def api_bot_logs():
    if INGESTED_LOG_FILE.exists():
        try:
            with open(INGESTED_LOG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return jsonify(data)
        except Exception:
            pass
    return jsonify({"logs": [], "chats": []})


# ---- Node.js health proxy ----
@whatsapp_bp.route("/api/node-health")
@api_login_required
def api_node_health():
    health = _fetch_node_health()
    return jsonify(health)


# ---- Generate Sync API Key ----
@whatsapp_bp.route("/api/generate-sync-key", methods=["POST"])
@api_login_required
def api_generate_sync_key():
    """
    Generate a new SYNC_API_KEY for machine‑to‑machine communication.
    Requires valid Oxysintx credentials (username + password).
    On success, returns the new key and profile info.
    """
    body = request.get_json(silent=True) or {}
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    # 1. Verify credentials against Oxysintx API
    try:
        token_resp = requests.post(
            f"{OXYSINTX_API_BASE}/api/token",
            json={"username": username, "password": password},
            timeout=15
        )
        if token_resp.status_code != 200:
            return jsonify({"error": "Invalid Oxysintx credentials."}), 401
        token_data = token_resp.json()
        if not token_data.get("token"):
            return jsonify({"error": "No token returned."}), 502
        oxy_username = token_data.get("username", username)
        oxy_role = token_data.get("role", "user")
    except requests.RequestException as e:
        logger.error("Oxysintx token request failed: %s", e)
        return jsonify({"error": "Could not reach Oxysintx API."}), 502

    # 2. Generate a new sync key
    new_key = secrets.token_hex(32)  # 64 hex chars

    # 3. Save key to file
    try:
        with open(SYNC_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(new_key)
        logger.info("New sync key generated and saved to %s", SYNC_KEY_FILE)
    except IOError as e:
        logger.error("Failed to write sync key file: %s", e)
        return jsonify({"error": "Could not persist the key. Check file permissions."}), 500

    return jsonify({
        "success": True,
        "sync_key": new_key,
        "profile": {
            "username": oxy_username,
            "role": oxy_role
        }
    })


# ---- Validate Sync API Key ----
@whatsapp_bp.route("/api/validate-sync-key")
def api_validate_sync_key():
    """Check if a given key matches the active sync API key."""
    key = request.args.get("key", "").strip()
    active = _get_active_sync_key()
    valid = bool(key and active and key == active)
    return jsonify({"valid": valid})


# ---- Ingest logs & chats from the bot ----
@whatsapp_bp.route("/api/ingest-logs", methods=["POST"])
def api_ingest_logs():
    """
    Receive logs and chat messages from the bot (authorized via sync key).
    The data is persisted to a file so the dashboard can display it later.
    """
    sync_key = request.headers.get("X-Sync-API-Key", "")
    active_key = _get_active_sync_key()
    if not active_key or sync_key != active_key:
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    logs = body.get("logs", [])
    chats = body.get("chats", [])

    INGESTED_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(INGESTED_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "logs": logs,
                "chats": chats,
                "updated": datetime.now(timezone.utc).isoformat()
            }, f, indent=2)
    except IOError as e:
        logger.error("Failed to write ingested logs: %s", e)
        return jsonify({"error": "Could not save logs"}), 500

    logger.info("Received %d logs, %d chats from bot", len(logs), len(chats))
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# Startup status helper
# ---------------------------------------------------------------------------
def get_startup_status() -> dict:
    status = {
        "status": "unknown",
        "pair_url": PAIR_URL,
        "creds_url": CREDS_URL,
        "node_host": NODE_SERVER_HOST,
        "node_port": NODE_SERVER_PORT,
        "sync_key_set": bool(_get_active_sync_key()),
        "ingested_logs": INGESTED_LOG_FILE.exists(),
    }
    try:
        resp = requests.get(HEALTH_URL, timeout=5)
        if resp.ok:
            status["status"] = "connected"
        else:
            status["status"] = f"Node.js returned HTTP {resp.status_code}"
    except Exception as e:
        status["status"] = f"unreachable – {e}"
    return status