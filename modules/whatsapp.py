"""
whatsapp.py — Emergens WhatsApp Integration Module (v6.2.0)
===============================================================================
Flask blueprint providing:

  1. GET  /webps.html              → serve the creds.json upload & status page
  2. POST /api/pair                → request a WhatsApp pairing code
  3. POST /api/upload-creds        → receive creds.json (session-based OR
                                     machine sync with X-Sync-API-Key header)
  4. GET  /api/bot-status          → JSON bot status
  5. GET  /api/bot-logs            → JSON tail logs + chat previews
  6. GET  /api/node-health         → proxy to Node.js /health
  7. POST /api/generate-sync-key   → generate a new SYNC_API_KEY after verifying
                                     Emergens credentials (username + password)
  8. GET  /api/validate-sync-key   → check if a given key is currently valid
  9. POST /api/ingest-logs         → accept log & chat data from the bot
                                     (authorized via X-Sync-API-Key)
 10. Helper `get_startup_status()` → used by app.py for startup banner

Author: Yanxzyx
===============================================================================
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Blueprint, jsonify, render_template, request, session, url_for

from auth.decorators import api_login_required

# ═══════════════════════════════════════════════════════════════════════════
# LOGGING — isolated, no duplicate output with Flask/root handlers
# ═══════════════════════════════════════════════════════════════════════════
logger = logging.getLogger("emergens.whatsapp")
logger.propagate = False
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_handler)
logger.setLevel(logging.INFO)

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
NODE_SERVER_HOST = os.environ.get("NODE_SERVER_HOST", "51.68.234.157")
NODE_SERVER_PORT = int(os.environ.get("NODE_SERVER_PORT", "20113"))

if NODE_SERVER_HOST in ("0.0.0.0", "::", "[::]"):
    logger.warning(
        "NODE_SERVER_HOST is '%s' — falling back to 127.0.0.1", NODE_SERVER_HOST
    )
    NODE_SERVER_HOST = "127.0.0.1"

PAIR_PATH   = "/code"
CREDS_PATH  = "/creds"
HEALTH_PATH = "/health"

REQUEST_TIMEOUT_SECONDS   = 20
HEALTH_TIMEOUT_SECONDS    = 5
RATE_LIMIT_MAX_REQUESTS   = 3
RATE_LIMIT_WINDOW_SECONDS = 300

# Emergens API base — used for credential verification during sync-key generation
EMERGENS_API_BASE = os.environ.get("EMERGENS_API_BASE", "http://node1.lunes.host:2393")

# Filesystem paths
PROJECT_ROOT  = Path(os.path.dirname(os.path.abspath(__file__))).parent
USERDATA_DIR  = PROJECT_ROOT / "userdata"
SYNC_KEY_FILE = Path(os.environ.get("SYNC_KEY_FILE", PROJECT_ROOT / "sync_key.txt"))
INGESTED_LOG_FILE = USERDATA_DIR / "ingested_logs.json"

# Hard limits (DoS protection)
MAX_UPLOAD_BYTES   = 2 * 1024 * 1024          # 2 MB creds.json cap
MAX_INGEST_LOGS    = 5000                      # max log entries accepted
MAX_INGEST_CHATS   = 5000                      # max chat entries accepted
MAX_LOG_ITEM_LEN   = 4000                      # max characters per log/chat item

USERDATA_DIR.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════
# BLUEPRINT
# ═══════════════════════════════════════════════════════════════════════════
whatsapp_bp = Blueprint("whatsapp", __name__)


# ═══════════════════════════════════════════════════════════════════════════
# SYNC KEY MANAGEMENT (cached + thread-safe)
# ═══════════════════════════════════════════════════════════════════════════
_sync_key_lock = threading.Lock()
_sync_key_cache: Dict[str, Any] = {"key": None, "mtime": 0.0}


def _get_active_sync_key() -> str:
    """
    Return the current sync key.
    Reads from SYNC_KEY_FILE if it exists and is non-empty, otherwise
    falls back to the SYNC_API_KEY environment variable. Cached by mtime
    so repeated lookups during a request cycle don't hammer the disk.
    """
    with _sync_key_lock:
        try:
            if SYNC_KEY_FILE.exists():
                mtime = SYNC_KEY_FILE.stat().st_mtime
                if _sync_key_cache["key"] and _sync_key_cache["mtime"] == mtime:
                    return _sync_key_cache["key"]
                with open(SYNC_KEY_FILE, "r", encoding="utf-8") as f:
                    key = f.read().strip()
                if key:
                    _sync_key_cache["key"] = key
                    _sync_key_cache["mtime"] = mtime
                    return key
        except OSError as e:
            logger.warning("Could not read sync key file: %s", e)
    return os.environ.get("SYNC_API_KEY", "")


def _set_active_sync_key(new_key: str) -> None:
    """Write the sync key atomically and update the cache."""
    tmp = str(SYNC_KEY_FILE) + ".tmp"
    with _sync_key_lock:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(new_key)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, SYNC_KEY_FILE)
        _sync_key_cache["key"] = new_key
        try:
            _sync_key_cache["mtime"] = SYNC_KEY_FILE.stat().st_mtime
        except OSError:
            _sync_key_cache["mtime"] = 0.0


def _constant_time_equals(a: Optional[str], b: Optional[str]) -> bool:
    """Timing-safe string comparison."""
    if not a or not b:
        return False
    return hmac.compare_digest(str(a), str(b))


# ═══════════════════════════════════════════════════════════════════════════
# NODE.JS URL BUILDER
# ═══════════════════════════════════════════════════════════════════════════
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
    PAIR_URL   = _build_node_url(PAIR_PATH)
    CREDS_URL  = _build_node_url(CREDS_PATH)
    HEALTH_URL = _build_node_url(HEALTH_PATH)
    logger.info("WhatsApp module active — pair: %s  creds: %s  health: %s",
                PAIR_URL, CREDS_URL, HEALTH_URL)
except Exception as exc:
    logger.critical("Invalid Node.js URL configuration: %s", exc)
    raise


# ═══════════════════════════════════════════════════════════════════════════
# RATE LIMITER (thread-safe, bounded)
# ═══════════════════════════════════════════════════════════════════════════
_recent_requests: Dict[str, deque] = defaultdict(deque)
_rate_lock = threading.Lock()
_RATE_MAP_MAX_KEYS = 10_000


def _is_rate_limited(key: str) -> bool:
    now = time.time()
    with _rate_lock:
        # Prune expired entries every so often to prevent unbounded growth
        if len(_recent_requests) > _RATE_MAP_MAX_KEYS:
            stale = [
                k for k, v in _recent_requests.items()
                if not v or now - v[-1] > RATE_LIMIT_WINDOW_SECONDS
            ]
            for k in stale[: len(stale) // 2]:
                _recent_requests.pop(k, None)

        hits = _recent_requests[key]
        while hits and now - hits[0] > RATE_LIMIT_WINDOW_SECONDS:
            hits.popleft()
        if len(hits) >= RATE_LIMIT_MAX_REQUESTS:
            return True
        hits.append(now)
        return False


# ═══════════════════════════════════════════════════════════════════════════
# NUMBER CLEANER
# ═══════════════════════════════════════════════════════════════════════════
def clean_number(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    digits = re.sub(r"\D", "", str(raw))
    if 6 <= len(digits) <= 19:
        return digits
    return None


# ═══════════════════════════════════════════════════════════════════════════
# PAIRING CODE REQUEST
# ═══════════════════════════════════════════════════════════════════════════
def request_pairing_code(number: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        resp = requests.get(
            PAIR_URL, params={"number": number}, timeout=REQUEST_TIMEOUT_SECONDS
        )
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


# ═══════════════════════════════════════════════════════════════════════════
# BOT PROFILE MANAGEMENT (per user)
# ═══════════════════════════════════════════════════════════════════════════
def _safe_username(username: str) -> str:
    """Reject path-traversal style usernames (defence-in-depth)."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", str(username or ""))[:64]
    if not cleaned or cleaned in (".", ".."):
        raise ValueError("Invalid username.")
    return cleaned


def _profile_path(username: str) -> Path:
    return USERDATA_DIR / _safe_username(username) / "bot_profile.json"


def _load_bot_profile(username: str) -> Dict[str, Any]:
    path = _profile_path(username)
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.error("Failed to load bot profile for '%s': %s", username, e)
        return {}


def _save_bot_profile(username: str, profile: Dict[str, Any]) -> None:
    folder = USERDATA_DIR / _safe_username(username)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "bot_profile.json"
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2, ensure_ascii=False)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, path)
    logger.info("Bot profile updated for '%s'", username)


def _extract_phone_from_creds(creds: Dict[str, Any]) -> Optional[str]:
    me = creds.get("me") or {}
    jid = me.get("id") or me.get("jid") or ""
    if ":" in jid:
        jid = jid.split(":")[0]
    if "@" in jid:
        jid = jid.split("@")[0]
    number = re.sub(r"\D", "", jid)
    if len(number) >= 6:
        return number
    return None


# ═══════════════════════════════════════════════════════════════════════════
# NODE.JS HEALTH QUERY
# ═══════════════════════════════════════════════════════════════════════════
def _fetch_node_health() -> Dict[str, Any]:
    try:
        resp = requests.get(HEALTH_URL, timeout=HEALTH_TIMEOUT_SECONDS)
        if resp.ok:
            data = resp.json()
            return data if isinstance(data, dict) else {}
    except (requests.RequestException, ValueError) as e:
        logger.debug("Node /health failed: %s", e)
    return {}


def _get_bot_phone_from_node() -> Optional[str]:
    health = _fetch_node_health()
    bot_jid = health.get("botJid", "")
    if bot_jid:
        raw = bot_jid.split("@")[0] if "@" in bot_jid else bot_jid
        number = re.sub(r"\D", "", raw)
        if len(number) >= 6:
            return number
    return None


# ═══════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@whatsapp_bp.route("/webps.html")
def webps_page():
    return render_template("webps.html")


# ─── Pairing ──────────────────────────────────────────────────────────────
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


# ─── Credentials upload (session or sync key) ────────────────────────────
@whatsapp_bp.route("/api/upload-creds", methods=["POST"])
def api_upload_creds():
    """
    Receive a Baileys creds.json file.
    Authentication:
      - Session login (via @api_login_required) OR
      - X-Sync-API-Key header with a valid key.
    """
    sync_key = request.headers.get("X-Sync-API-Key", "").strip()
    active_sync_key = _get_active_sync_key()

    if sync_key and _constant_time_equals(sync_key, active_sync_key):
        username = "whatsapp-bot"
    else:
        session_user = session.get("username")
        if not session_user:
            return jsonify({
                "error": "Unauthorized. Provide a valid session or sync API key."
            }), 401
        username = session_user

    if "creds" not in request.files:
        return jsonify({"error": "No file provided. Use form field 'creds'."}), 400

    file = request.files["creds"]
    if not file.filename:
        return jsonify({"error": "No file selected."}), 400
    if not file.filename.lower().endswith(".json"):
        return jsonify({"error": "Only .json files are accepted."}), 400

    try:
        content = file.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            return jsonify({
                "error": f"File too large (max {MAX_UPLOAD_BYTES // 1024} KB)."
            }), 413
        creds_data = json.loads(content)
        if not isinstance(creds_data, dict):
            return jsonify({"error": "creds.json must be a JSON object."}), 400
    except (json.JSONDecodeError, UnicodeDecodeError):
        return jsonify({"error": "Invalid JSON file."}), 400
    except OSError as e:
        logger.error("Failed to read uploaded creds.json: %s", e)
        return jsonify({"error": "Could not read the uploaded file."}), 500

    # Persist locally
    try:
        user_dir = USERDATA_DIR / _safe_username(username)
        user_dir.mkdir(parents=True, exist_ok=True)
        creds_path = user_dir / "creds.json"
        tmp = str(creds_path) + ".tmp"
        with open(tmp, "wb") as f:
            f.write(content)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, creds_path)
    except (OSError, ValueError) as e:
        logger.error("Failed to persist creds.json: %s", e)
        return jsonify({"error": "Could not save creds.json on the server."}), 500

    # Extract + store profile
    phone_number = _extract_phone_from_creds(creds_data)
    name = (creds_data.get("me") or {}).get("name", "") or ""
    profile = {
        "phone": phone_number,
        "name": name,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "filename": file.filename,
    }
    try:
        _save_bot_profile(username, profile)
    except (OSError, ValueError) as e:
        logger.error("Failed to save bot profile: %s", e)

    # Forward to Node.js (best-effort)
    node_forward_error: Optional[str] = None
    try:
        resp = requests.post(
            CREDS_URL, json=creds_data, timeout=REQUEST_TIMEOUT_SECONDS
        )
        if not resp.ok:
            node_forward_error = f"HTTP {resp.status_code}"
            logger.error(
                "Node /creds returned HTTP %s: %s",
                resp.status_code, resp.text[:300],
            )
    except requests.RequestException as exc:
        node_forward_error = str(exc)
        logger.error("Could not reach Node.js /creds: %s", exc)

    logger.info(
        "creds.json uploaded by '%s' — phone=%s", username, phone_number or "N/A"
    )

    response: Dict[str, Any] = {
        "success": True,
        "filename": file.filename,
        "size": len(content),
        "username": username,
        "phone": phone_number,
    }
    if node_forward_error:
        response["warning"] = (
            f"Saved locally, but the Node.js bot could not be notified "
            f"({node_forward_error})."
        )
    return jsonify(response)


# ─── Bot status ──────────────────────────────────────────────────────────
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
            node_uptime = health.get("uptime", "") or ""

    return jsonify({
        "phone": phone,
        "name": name,
        "online": online,
        "uptime": node_uptime,
        "last_upload": profile.get("uploaded_at", ""),
        "logs_url": url_for("whatsapp.api_bot_logs"),
    })


# ─── Bot logs (reads ingested data) ──────────────────────────────────────
@whatsapp_bp.route("/api/bot-logs")
@api_login_required
def api_bot_logs():
    if INGESTED_LOG_FILE.exists():
        try:
            with open(INGESTED_LOG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return jsonify(data)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Could not read ingested logs: %s", e)
    return jsonify({"logs": [], "chats": []})


# ─── Node.js health proxy ────────────────────────────────────────────────
@whatsapp_bp.route("/api/node-health")
@api_login_required
def api_node_health():
    return jsonify(_fetch_node_health())


# ─── Generate Sync API Key ───────────────────────────────────────────────
@whatsapp_bp.route("/api/generate-sync-key", methods=["POST"])
@api_login_required
def api_generate_sync_key():
    """
    Generate a new SYNC_API_KEY for machine-to-machine communication.
    Requires valid Emergens credentials (username + password).
    On success, returns the new key and profile info.
    """
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    # 1. Verify credentials against the Emergens API
    try:
        token_resp = requests.post(
            f"{EMERGENS_API_BASE}/api/token",
            json={"username": username, "password": password},
            timeout=15,
        )
        if token_resp.status_code != 200:
            return jsonify({"error": "Invalid Emergens credentials."}), 401
        token_data = token_resp.json()
        if not token_data.get("token"):
            return jsonify({"error": "No token returned by the API."}), 502
        emergens_username = token_data.get("username", username)
        emergens_role = token_data.get("role", "user")
    except (requests.RequestException, ValueError) as e:
        logger.error("Emergens token request failed: %s", e)
        return jsonify({"error": "Could not reach the Emergens API."}), 502

    # 2. Generate a new sync key
    new_key = secrets.token_hex(32)  # 64 hex chars

    # 3. Persist atomically
    try:
        _set_active_sync_key(new_key)
        logger.info("New sync key generated for user '%s'", emergens_username)
    except OSError as e:
        logger.error("Failed to write sync key file: %s", e)
        return jsonify({
            "error": "Could not persist the key. Check file permissions."
        }), 500

    return jsonify({
        "success": True,
        "sync_key": new_key,
        "profile": {
            "username": emergens_username,
            "role": emergens_role,
        },
    })


# ─── Validate Sync API Key ───────────────────────────────────────────────
@whatsapp_bp.route("/api/validate-sync-key")
def api_validate_sync_key():
    """Check whether a given key matches the active sync API key."""
    key = (request.args.get("key") or "").strip()
    active = _get_active_sync_key()
    valid = bool(active) and _constant_time_equals(key, active)
    return jsonify({"valid": valid})


# ─── Ingest logs & chats from the bot ────────────────────────────────────
@whatsapp_bp.route("/api/ingest-logs", methods=["POST"])
def api_ingest_logs():
    """
    Receive logs and chat messages from the bot (authorized via sync key).
    Data is persisted to a file so the dashboard can display it later.
    """
    sync_key = request.headers.get("X-Sync-API-Key", "").strip()
    active_key = _get_active_sync_key()
    if not active_key or not _constant_time_equals(sync_key, active_key):
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    raw_logs = body.get("logs", [])
    raw_chats = body.get("chats", [])

    if not isinstance(raw_logs, list) or not isinstance(raw_chats, list):
        return jsonify({"error": "logs and chats must be arrays."}), 400

    # Trim and bound
    logs = [str(item)[:MAX_LOG_ITEM_LEN] for item in raw_logs[:MAX_INGEST_LOGS]]
    chats = [str(item)[:MAX_LOG_ITEM_LEN] for item in raw_chats[:MAX_INGEST_CHATS]]

    payload = {
        "logs": logs,
        "chats": chats,
        "updated": datetime.now(timezone.utc).isoformat(),
        "log_count": len(logs),
        "chat_count": len(chats),
        "truncated": (
            len(raw_logs) > MAX_INGEST_LOGS or len(raw_chats) > MAX_INGEST_CHATS
        ),
    }

    INGESTED_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = str(INGESTED_LOG_FILE) + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, INGESTED_LOG_FILE)
    except OSError as e:
        logger.error("Failed to write ingested logs: %s", e)
        return jsonify({"error": "Could not save logs"}), 500

    logger.info("Received %d logs, %d chats from bot", len(logs), len(chats))
    return jsonify({
        "success": True,
        "log_count": len(logs),
        "chat_count": len(chats),
        "truncated": payload["truncated"],
    })


# ═══════════════════════════════════════════════════════════════════════════
# STARTUP STATUS HELPER
# ═══════════════════════════════════════════════════════════════════════════
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
        resp = requests.get(HEALTH_URL, timeout=HEALTH_TIMEOUT_SECONDS)
        if resp.ok:
            status["status"] = "connected"
        else:
            status["status"] = f"Node.js returned HTTP {resp.status_code}"
    except Exception as e:
        status["status"] = f"unreachable — {e}"
    return status
