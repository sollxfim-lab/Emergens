"""
Oxysintx - Main Flask Application (v3.3.0)

Routing only lives here; actual logic is split across auth/, core/,
modules/, and ai_chat/.

Authentication:
    - Session-based: login via /api/login, browser uses cookie.
    - Token-based: POST /api/token with username+password, receive bearer token.
    - API keys: Legacy, stored per user.
    - ADB access: POST /api/adb_login with access code, bypasses password.

Author: Yanxzyx
"""

import sys
import time
import os
import logging
from functools import wraps
from datetime import datetime, timedelta, timezone
from collections import defaultdict

from flask import Flask, render_template, request, jsonify, session, redirect

from config import Config
from auth.user_store import (
    UserStore, ensure_default_user, verify_credentials, create_user, get_role,
    list_users, delete_user, DEFAULT_USERNAME, VALID_ROLES,
)
from auth.token_store import token_store
from core.logger_setup import setup_logging
from core.history_store import HistoryStore
from core.system_monitor import get_system_stats
from modules.scan_orchestrator import ScanOrchestrator, TOOL_MAP
from modules.source_viewer import run as fetch_source
from modules.telegram import (
    connect_bot, disconnect_bot, get_bot_status,
    update_bot_settings, broadcast_message, auto_restart_bot,
    set_orchestrator, set_history_store,
)
from modules.whatsapp import whatsapp_bp

# Import the downloader backend (TikTok & Pinterest)
try:
    from modules.downsea import downsea_bp
    _downsea_available = True
except ImportError:
    _downsea_available = False

from ai_chat.chat_handler import ChatHandler

# Import the testing module (for code execution & file operations)
try:
    from modules import testing as code_test_module
    _testing_available = True
except ImportError:
    _testing_available = False

# Import the DDoS module (adios)
try:
    from modules import adios as adios_module
    _adios_available = True
except ImportError:
    _adios_available = False

# Import the analytic manager (exploit repository, brute force, SQLi, XSS)
try:
    from modules.analytic_manager import AnalyticDataManager
    _analytic_available = True
except ImportError:
    _analytic_available = False

# Import the quick menu module (Flask Blueprint version)
_quick_menu_bp = None
try:
    from modules import quick_menu
    if hasattr(quick_menu, 'quick_menu_bp'):
        _quick_menu_bp = quick_menu.quick_menu_bp
        _quick_menu_available = True
    elif hasattr(quick_menu, 'bp'):
        _quick_menu_bp = quick_menu.bp
        _quick_menu_available = True
    else:
        _quick_menu_available = False
except ImportError:
    _quick_menu_available = False

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
app.permanent_session_lifetime = timedelta(hours=8)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# Register WhatsApp blueprint (webps.html, /api/pair, /api/upload-creds, etc.)
app.register_blueprint(whatsapp_bp)

# Register downloader blueprint (TikTok & Pinterest backend)
if _downsea_available:
    app.register_blueprint(downsea_bp)

# Register quick menu blueprint (if available)
if _quick_menu_available and _quick_menu_bp is not None:
    app.register_blueprint(_quick_menu_bp)

setup_logging(Config.SERVER_LOG_FILE)
logger = logging.getLogger("oxysintx")

# ---------------------------------------------------------------------------
# Backing services
# ---------------------------------------------------------------------------
history_store = HistoryStore()
chat_handler = ChatHandler(api_key=Config.ANTHROPIC_API_KEY)
user_store = UserStore()
scan_orchestrator = ScanOrchestrator()

set_orchestrator(scan_orchestrator)
set_history_store(history_store)

# ---------------------------------------------------------------------------
# Ensure required directories exist
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
for d in ["userdata", "listschool", os.path.join("static", "data")]:
    os.makedirs(os.path.join(PROJECT_ROOT, d), exist_ok=True)

# ---------------------------------------------------------------------------
# Login rate limiting
# ---------------------------------------------------------------------------
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
_failed_attempts = defaultdict(list)

def _is_locked_out(ip: str) -> bool:
    now = time.time()
    _failed_attempts[ip] = [t for t in _failed_attempts[ip] if now - t < LOCKOUT_SECONDS]
    return len(_failed_attempts[ip]) >= MAX_LOGIN_ATTEMPTS

def _record_failed_attempt(ip: str):
    _failed_attempts[ip].append(time.time())

# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------
def _extract_bearer_token() -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return ""

def _authenticate_request() -> bool:
    if session.get("authenticated"):
        return True
    token = _extract_bearer_token()
    if token:
        username = token_store.validate_token(token)
        if username:
            session["authenticated"] = True
            session["username"] = username
            session["role"] = get_role(username)
            session.permanent = True
            return True
    return False

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _authenticate_request():
            return redirect(f"/login.html?next={request.path}")
        return f(*args, **kwargs)
    return wrapper

def api_login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _authenticate_request():
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not _authenticate_request():
                return jsonify({"error": "unauthorized"}), 401
            if session.get("role") not in allowed_roles:
                return jsonify({"error": "forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if _authenticate_request():
        return redirect("/dashboard.html")
    return render_template("get-started.html")

@app.route("/get-started.html")
def get_started_page():
    if _authenticate_request():
        return redirect("/dashboard.html")
    return render_template("get-started.html")

@app.route("/login.html")
def login_page():
    if _authenticate_request():
        return redirect("/dashboard.html")
    return render_template("login.html")

@app.route("/dashboard.html")
@login_required
def dashboard_page():
    return render_template(
        "dashboard.html",
        username=session.get("username", DEFAULT_USERNAME),
        role=session.get("role", "owner"),
    )

# ===== API Key Request Token page (renamed from request.html) =====
@app.route("/api_key_request_token.html")
def api_key_request_token_page():
    """Self-service API page for external users."""
    return render_template("api_key_request_token.html")

# Alias for /api/api_key_request_token.html
@app.route("/api/api_key_request_token.html")
def api_key_request_token_api_page():
    """Alias for API key request token page."""
    return render_template("api_key_request_token.html")

# ===== Downloader Pinterest & TikTok page (renamed from data_main.html) =====
@app.route("/downloader_pinterest_tiktok.html")
@login_required
def downloader_pinterest_tiktok_page():
    """TikTok & Pinterest downloader page."""
    return render_template("downloader_pinterest_tiktok.html")

# Keep old data_main.html as redirect for backward compatibility
@app.route("/data_main.html")
@login_required
def data_main_redirect():
    return redirect("/downloader_pinterest_tiktok.html")

@app.route("/code_test.html")
def code_test_page():
    return render_template("code_test.html")

@app.route("/remote_access.html")
@login_required
def remote_access_page():
    return render_template("remote_access.html")

@app.route("/frame-work-stres-testing.html")
@login_required
def frame_work_stres_testing_page():
    return render_template("frame-work-stres-testing.html")

@app.route("/MyEspT.html")
@login_required
def MyEspT_page():
    return render_template("MyEspT.html")

@app.route("/quick_menu_setting.html")
@login_required
def quick_menu_setting_page():
    return render_template("quick_menu_setting.html")

# ---------------------------------------------------------------------------
# Quick Menu compatibility routes
# ---------------------------------------------------------------------------
if _quick_menu_available:
    @app.route("/status")
    def qm_status_compat():
        quick_menu.STATE.touch()
        return jsonify({
            "status": "online",
            "service": "quick_menu",
            "version": getattr(quick_menu, "VERSION", "2.0.0"),
            "uptime_seconds": quick_menu.STATE.uptime_seconds(),
            "requests_served": quick_menu.STATE.request_count,
        })

    @app.route("/menu")
    def qm_menu_compat():
        quick_menu.STATE.touch()
        return jsonify({"items": quick_menu.STATE.get_menu()})

    @app.route("/actions")
    def qm_actions_compat():
        quick_menu.STATE.touch()
        return jsonify({"actions": quick_menu.STATE.recent_actions()})

    @app.route("/action", methods=["POST"])
    def qm_action_compat():
        quick_menu.STATE.touch()
        data = request.get_json(silent=True) or {}
        action = (data.get("action") or "").strip()
        if action not in quick_menu.STATE.valid_action_ids:
            return jsonify({
                "error": "unknown_action",
                "received": action,
                "valid_actions": sorted(quick_menu.STATE.valid_action_ids),
            }), 400
        source = (data.get("source") or "web").strip()
        entry = quick_menu.STATE.record_action(action, source, session.get("username", "anonymous"))
        return jsonify({"ok": True, "recorded": entry})

# ---------------------------------------------------------------------------
# ADB Login Endpoint
# ---------------------------------------------------------------------------
ADB_ACCESS_CODE = "ZYXN"
ADB_USERNAME = "Yanxzyx"
ADB_ROLE = "owner"

@app.route("/api/adb_login", methods=["POST"])
def api_adb_login():
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip().upper()
    if not code:
        return jsonify({"error": "code_required"}), 400
    if code != ADB_ACCESS_CODE:
        _record_failed_attempt(request.remote_addr or "unknown")
        return jsonify({"error": "invalid_code"}), 401
    if not user_store.user_exists(ADB_USERNAME):
        try:
            create_user(ADB_USERNAME, role=ADB_ROLE, password="admin123")
        except ValueError:
            pass
    session["authenticated"] = True
    session["username"] = ADB_USERNAME
    session["role"] = ADB_ROLE
    session.permanent = True
    return jsonify({"success": True, "username": ADB_USERNAME, "role": ADB_ROLE})

# ---------------------------------------------------------------------------
# Auth API
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def api_login():
    ip = request.remote_addr or "unknown"
    if _is_locked_out(ip):
        return jsonify({"error": "too_many_attempts"}), 429
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if verify_credentials(username, password):
        session["authenticated"] = True
        session["username"] = username
        session["role"] = get_role(username)
        session.permanent = True
        return jsonify({"success": True})
    _record_failed_attempt(ip)
    return jsonify({"error": "invalid_credentials"}), 401

@app.route("/api/logout", methods=["POST"])
def api_logout():
    token = _extract_bearer_token()
    if token:
        token_store.revoke_token(token[:8])
    session.clear()
    return jsonify({"success": True})

@app.route("/api/token", methods=["POST"])
def api_get_token():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or data.get("address") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username_and_password_required"}), 400
    token = token_store.generate_token(username, password,
                                       user_agent=request.headers.get("User-Agent", ""))
    if token is None:
        return jsonify({"error": "invalid_credentials"}), 401
    return jsonify({
        "token": token,
        "token_prefix": token[:8] + "****",
        "expires_in": 3600,
        "username": username,
        "role": get_role(username),
    })

@app.route("/api/me")
@api_login_required
def api_me():
    return jsonify({"username": session.get("username"), "role": session.get("role")})

# ---------------------------------------------------------------------------
# Settings / Account management
# ---------------------------------------------------------------------------
@app.route("/api/settings/users")
@role_required("owner")
def api_list_users():
    return jsonify(list_users())

@app.route("/api/settings/create-account", methods=["POST"])
@role_required("owner")
def api_create_account():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    role = data.get("role") or ""
    if not username:
        return jsonify({"error": "username_required"}), 400
    if role not in VALID_ROLES:
        return jsonify({"error": "invalid_role"}), 400
    try:
        password = create_user(username, role=role)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"username": username, "password": password, "role": role})

@app.route("/api/settings/users/<username>", methods=["DELETE"])
@role_required("owner")
def api_delete_user(username):
    if username == session.get("username"):
        return jsonify({"error": "cannot delete your own account"}), 400
    ok, err = delete_user(username)
    if not ok:
        return jsonify({"error": err}), 400
    token_store.revoke_all_user_tokens(username)
    return jsonify({"success": True})

# ---------------------------------------------------------------------------
# API Key management
# ---------------------------------------------------------------------------
@app.route("/api/settings/api-keys")
@role_required("owner", "analyst")
def api_list_api_keys():
    return jsonify(user_store.get_api_keys())

@app.route("/api/settings/api-keys", methods=["POST"])
@role_required("owner", "analyst")
def api_generate_api_key():
    role = session.get("role", "")
    if role == "analyst":
        if len(user_store.get_api_keys()) >= 2:
            return jsonify({"error": "api_key_limit_reached", "limit": 2}), 403
    key = user_store.generate_api_key(session.get("username"))
    return jsonify({"key": key, "prefix": key[:20] + "****"})

@app.route("/api/settings/api-keys/<prefix>", methods=["DELETE"])
@role_required("owner", "analyst")
def api_revoke_api_key(prefix):
    if user_store.revoke_api_key(prefix):
        return jsonify({"success": True})
    return jsonify({"error": "not_found"}), 404

# ---------------------------------------------------------------------------
# Tools / Scan API
# ---------------------------------------------------------------------------
@app.route("/api/tools")
@api_login_required
def api_tools():
    tools = [t for t in scan_orchestrator.list_tools() if "school" not in t.lower()]
    return jsonify(tools)

@app.route("/api/scan/start", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_start():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    mode = data.get("mode", "basic")
    tools = data.get("tools", [])
    if not target:
        return jsonify({"error": "target_required"}), 400
    if mode not in ("basic", "expert"):
        mode = "basic"
    job_id = scan_orchestrator.start_scan(target, mode, tools, history_store)
    return jsonify({"job_id": job_id})

@app.route("/api/scan/<job_id>/status")
@api_login_required
def api_scan_status(job_id):
    progress = scan_orchestrator.get_progress(job_id)
    if progress is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(progress)

# ---------------------------------------------------------------------------
# DIRECT TOOL ENDPOINTS
# ---------------------------------------------------------------------------
@app.route("/api/scan/<tool_name>", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_tool_direct(tool_name):
    if tool_name not in TOOL_MAP:
        return jsonify({"error": "unknown_tool", "available": list(TOOL_MAP.keys())}), 404
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    mode = data.get("mode", "basic")
    if not target:
        return jsonify({"error": "target_required"}), 400
    if mode not in ("basic", "expert"):
        mode = "basic"
    tool_module = TOOL_MAP[tool_name]
    try:
        result = tool_module.run(target, mode)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": "tool_execution_failed", "detail": str(e)}), 500

# ---------------------------------------------------------------------------
# History API
# ---------------------------------------------------------------------------
@app.route("/api/history")
@api_login_required
def api_history():
    return jsonify(history_store.list_all())

@app.route("/api/history/<int:entry_id>")
@api_login_required
def api_history_detail(entry_id):
    entry = history_store.get(entry_id)
    if entry is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(entry)

@app.route("/api/history/<int:entry_id>", methods=["DELETE"])
@role_required("owner", "analyst")
def api_history_delete(entry_id):
    history_store.delete(entry_id)
    return jsonify({"success": True})

# ---------------------------------------------------------------------------
# System / Console API
# ---------------------------------------------------------------------------
@app.route("/api/system/stats")
@api_login_required
def api_system_stats():
    return jsonify(get_system_stats())

@app.route("/api/logs")
@api_login_required
def api_logs():
    lines = int(request.args.get("lines", 100))
    try:
        with open(Config.SERVER_LOG_FILE, "r") as f:
            content = f.readlines()[-lines:]
        return jsonify({"lines": [c.rstrip("\n") for c in content]})
    except FileNotFoundError:
        return jsonify({"lines": []})

# ---------------------------------------------------------------------------
# Source / Code Viewer API
# ---------------------------------------------------------------------------
@app.route("/api/fetch-source", methods=["POST"])
@api_login_required
def api_fetch_source():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    extract = data.get("extract", False)
    if not url:
        return jsonify({"error": "url_required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        result = fetch_source(url, extract=extract)
    except Exception as e:
        return jsonify({"error": "fetch_failed", "detail": str(e)}), 500
    if "error" in result:
        return jsonify(result), 500
    return jsonify(result)

# ---------------------------------------------------------------------------
# AI Chat API
# ---------------------------------------------------------------------------
@app.route("/api/chat", methods=["POST"])
@role_required("owner", "analyst")
def api_chat():
    data = request.get_json(silent=True) or {}
    return jsonify(chat_handler.send(data.get("message", "")))

@app.route("/api/chat/history")
@api_login_required
def api_chat_history():
    return jsonify(chat_handler.get_history())

@app.route("/api/chat/clear", methods=["POST"])
@role_required("owner", "analyst")
def api_chat_clear():
    chat_handler.clear_history()
    return jsonify({"success": True})

# ---------------------------------------------------------------------------
# School Search API (hidden)
# ---------------------------------------------------------------------------
@app.route("/api/school/search")
@api_login_required
def api_school_search():
    from modules import scan_school
    query = request.args.get("q", "").strip()
    result = scan_school.run(query)
    return jsonify(result["data"])

# ---------------------------------------------------------------------------
# Telegram Bot API
# ---------------------------------------------------------------------------
@app.route("/api/telegram/status")
@api_login_required
def api_telegram_status():
    return jsonify(get_bot_status())

@app.route("/api/telegram/connect", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_connect():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    username = (data.get("username") or "").strip()
    owner_id = (data.get("owner_id") or "").strip()
    public_mode = data.get("public_mode", True)
    if not token or not username:
        return jsonify({"error": "token_and_username_required"}), 400
    success, message = connect_bot(token, username, owner_id, public_mode)
    if not success:
        return jsonify({"error": message}), 500
    return jsonify(get_bot_status())

@app.route("/api/telegram/disconnect", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_disconnect():
    disconnect_bot()
    return jsonify({"status": "disconnected"})

@app.route("/api/telegram/update-settings", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_update_settings():
    data = request.get_json(silent=True) or {}
    settings = {}
    if "owner_id" in data:
        settings["owner_id"] = str(data["owner_id"]).strip()
    if "public_mode" in data:
        settings["public_mode"] = bool(data["public_mode"])
    if not settings:
        return jsonify({"error": "no_settings_provided"}), 400
    result = update_bot_settings(**settings)
    return jsonify(result)

@app.route("/api/telegram/broadcast", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_broadcast():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message_required"}), 400
    result = broadcast_message(message)
    return jsonify(result)

# ===================================================================
# Code Test Workspace API
# ===================================================================
@app.route("/api/code_test/read")
@login_required
def api_read_file():
    if not _testing_available:
        return jsonify({"error": "Testing module not available"}), 503
    file_path = request.args.get("path", "").strip()
    if not file_path:
        return jsonify({"error": "path required"}), 400
    return jsonify(code_test_module.read_file(file_path))

@app.route("/api/code_test/write", methods=["POST"])
@login_required
def api_write_file():
    if not _testing_available:
        return jsonify({"error": "Testing module not available"}), 503
    data = request.get_json(silent=True) or {}
    file_path = data.get("file_path", "").strip()
    content = data.get("content", "")
    if not file_path:
        return jsonify({"error": "file_path required"}), 400
    return jsonify(code_test_module.write_file(file_path, content))

@app.route("/api/code_test/run", methods=["POST"])
@login_required
def api_run_code_test():
    if not _testing_available:
        return jsonify({"error": "Testing module is not installed"}), 503
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")
    if not code:
        return jsonify({"error": "No code provided"}), 400
    try:
        results = code_test_module.run_tests(code, data.get("test_cases", []))
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": f"Execution error: {str(e)}"}), 500

@app.route("/api/code_test/files")
@login_required
def api_list_code_test_files():
    if not _testing_available:
        return jsonify({"error": "Testing module not available"}), 503
    try:
        files = code_test_module.list_project_files()
        return jsonify({"files": files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/code_test/backup", methods=["POST"])
@login_required
def api_backup_file():
    if not _testing_available:
        return jsonify({"error": "Testing module not available"}), 503
    data = request.get_json(silent=True) or {}
    file_path = data.get("file_path")
    if not file_path:
        return jsonify({"error": "file_path required"}), 400
    return jsonify(code_test_module.backup_file(file_path))

@app.route("/api/code_test/backup_all", methods=["POST"])
@login_required
def api_backup_all():
    if not _testing_available:
        return jsonify({"error": "Testing module not available"}), 503
    return jsonify(code_test_module.backup_all_source_files())

@app.route("/api/code_test/workspace_info")
@login_required
def api_workspace_info():
    if not _testing_available:
        return jsonify({"error": "Testing module not available"}), 503
    return jsonify(code_test_module.get_workspace_info())

@app.route("/api/code_test/scan", methods=["POST"])
@login_required
def api_code_test_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    mode = data.get("mode", "basic")
    tools = data.get("tools", [])
    if not target:
        return jsonify({"error": "target_required"}), 400
    if mode not in ("basic", "expert"):
        mode = "basic"
    job_id = scan_orchestrator.start_scan(target, mode, tools, history_store)
    return jsonify({"job_id": job_id})

# ===================================================================
# DDoS Attack Panel (adios) endpoints
# ===================================================================
@app.route("/api/adios/portscan")
@login_required
def adios_portscan():
    target = request.args.get("target", "").strip()
    ports_arg = request.args.get("ports", "file").strip()
    if not target:
        return jsonify({"success": False, "error": "Target required"}), 400
    if not _adios_available:
        return jsonify({"success": False, "error": "Adios module not available"}), 503
    ports = adios_module.parse_ports_arg(ports_arg)
    if not ports:
        return jsonify({"success": False, "error": "Invalid port specification"}), 400
    open_ports = adios_module.port_scan(target, ports)
    return jsonify({"success": True, "target": target, "open_ports": open_ports})

@app.route("/api/adios/scrape_proxies", methods=["GET", "POST"])
@login_required
def adios_scrape_proxies():
    if not _adios_available:
        return jsonify({"success": False, "error": "Adios module not available"}), 503
    result = adios_module.scrape_proxies()
    if result.get("success"):
        return jsonify(result)
    return jsonify(result), 500

@app.route("/api/adios/export_proxies", methods=["GET", "POST"])
@login_required
def adios_export_proxies():
    if not _adios_available:
        return jsonify({"success": False, "error": "Adios module not available"}), 503
    result = adios_module.export_proxies()
    if result.get("success"):
        return jsonify(result)
    return jsonify(result), 500

@app.route("/api/adios/proxy_count")
@login_required
def adios_proxy_count():
    if not _adios_available:
        return jsonify({"count": 0})
    return jsonify({"count": adios_module.get_proxy_count()})

@app.route("/api/adios/start", methods=["POST"])
@login_required
def adios_start():
    if not _adios_available:
        return jsonify({"error": "Adios module not available"}), 503
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400
    result = adios_module.start_attack(
        target=target,
        method=data.get("method", "udp-flood"),
        threads=data.get("threads", 10),
        packet_size=data.get("packet_size", 1024),
        dns_server=data.get("dns_server", ""),
        ntp_server=data.get("ntp_server", ""),
        target_port=data.get("target_port"),
        spoof_ip=data.get("spoof_ip", ""),
        bypass=data.get("bypass", False),
        random_ua=data.get("random_ua", False),
        use_proxy=data.get("use_proxy", False),
        fragment=data.get("fragment", False),
        zero_day=data.get("zero_day", False),
        memcache_server=data.get("memcache_server", ""),
    )
    return jsonify(result)

@app.route("/api/adios/stop", methods=["POST"])
@login_required
def adios_stop():
    if not _adios_available:
        return jsonify({"error": "Adios module not available"}), 503
    return jsonify(adios_module.stop_attack())

@app.route("/api/adios/status")
@login_required
def adios_status():
    if not _adios_available:
        return jsonify({"error": "Adios module not available"}), 503
    return jsonify(adios_module.get_attack_status())

# ===================================================================
# Remote Access / C2 endpoints
# ===================================================================
_lock_state = {"locked": True, "locked_by": None, "locked_at": None}
_c2_devices = []
_c2_activities = []

@app.route("/api/c2/status")
@login_required
def c2_status():
    return jsonify({
        "authenticated": True,
        "username": session.get("username"),
        "role": session.get("role"),
        "lock_state": _lock_state,
    })

@app.route("/api/c2/toggle_lock", methods=["POST"])
@login_required
def c2_toggle_lock():
    _lock_state["locked"] = not _lock_state["locked"]
    if _lock_state["locked"]:
        _lock_state["locked_by"] = session.get("username")
        _lock_state["locked_at"] = datetime.now(timezone.utc).isoformat()
    else:
        _lock_state["locked_by"] = None
        _lock_state["locked_at"] = None
    return jsonify({"success": True, "lock_state": _lock_state})

@app.route("/api/c2/devices")
@login_required
def c2_devices():
    return jsonify({"devices": _c2_devices})

@app.route("/api/c2/activities")
@login_required
def c2_activities():
    limit = min(request.args.get("limit", 50, type=int), 200)
    return jsonify({"activities": _c2_activities[-limit:]})

@app.route("/api/c2/register_device", methods=["POST"])
@login_required
def c2_register_device():
    data = request.get_json(silent=True) or {}
    device_id = data.get("id", "").strip()
    if not device_id:
        return jsonify({"error": "Device ID is required"}), 400
    device = {
        "id": device_id,
        "name": data.get("name", device_id),
        "model": data.get("model", ""),
        "serial": data.get("serial", ""),
        "android": data.get("android", ""),
        "status": "online",
        "battery": data.get("battery"),
        "location": data.get("location", ""),
        "temperature": data.get("temperature", ""),
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    for i, d in enumerate(_c2_devices):
        if d["id"] == device_id:
            _c2_devices[i] = device
            break
    else:
        _c2_devices.append(device)
    return jsonify({"success": True, "device": device})

@app.route("/api/c2/log_activity", methods=["POST"])
@login_required
def c2_log_activity():
    data = request.get_json(silent=True) or {}
    device_id = data.get("device_id", "").strip()
    action = data.get("action", "").strip()
    if not device_id or not action:
        return jsonify({"error": "device_id and action are required"}), 400
    device_name = next((d["name"] for d in _c2_devices if d["id"] == device_id), device_id)
    _c2_activities.append({
        "device_id": device_id,
        "device_name": device_name,
        "action": action,
        "timestamp": data.get("timestamp") or datetime.now(timezone.utc).isoformat(),
    })
    return jsonify({"success": True})

# ===================================================================
# Analytic Data / Exploit Manager endpoints
# ===================================================================
@app.route("/api/exploit/stats")
@login_required
def api_exploit_stats():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    try:
        manager = AnalyticDataManager()
        return jsonify(manager.get_statistics())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/exploit/list")
@login_required
def api_exploit_list():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    try:
        manager = AnalyticDataManager()
        return jsonify({"exploits": manager.list_exploits(
            category=request.args.get("category"),
            service=request.args.get("service")
        )})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/exploit/search", methods=["POST"])
@login_required
def api_exploit_search():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    data = request.get_json(silent=True) or {}
    query = data.get("query", "")
    if not query:
        return jsonify({"error": "Query required"}), 400
    try:
        manager = AnalyticDataManager()
        return jsonify({"exploits": manager.search_exploits(query)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/exploit/bruteforce", methods=["POST"])
@login_required
def api_exploit_bruteforce():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    try:
        manager = AnalyticDataManager()
        return jsonify({"results": manager.run_brute_force(
            target,
            data.get("protocols", ["http", "ftp", "ssh"]),
            data.get("username_file", "data1.txt"),
            data.get("password_file", "data1.txt")
        )})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/exploit/bruteforce/stop", methods=["POST"])
@login_required
def api_exploit_bruteforce_stop():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    try:
        manager = AnalyticDataManager()
        manager.stop_brute_force()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/exploit/sql_inject", methods=["POST"])
@login_required
def api_exploit_sql_inject():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL required"}), 400
    try:
        manager = AnalyticDataManager()
        return jsonify({"results": manager.run_sql_injection_scan(
            url, data.get("method", "GET"), data.get("params")
        )})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/exploit/xss", methods=["POST"])
@login_required
def api_exploit_xss():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL required"}), 400
    try:
        manager = AnalyticDataManager()
        return jsonify({"results": manager.run_xss_scan(
            url, data.get("method", "GET"), data.get("params")
        )})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------------------------------------------------------
# 404 Error Handler - Custom Lost Area Page
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    username = session.get("username") if session.get("authenticated") else "Guest"
    html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LOST AREA</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background-color: #000000;
            background-image:
                radial-gradient(ellipse at 20% 20%, rgba(255,255,255,0.05) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 80%, rgba(255,255,255,0.05) 0%, transparent 50%),
                repeating-linear-gradient(45deg, rgba(255,255,255,0.02) 0px, rgba(255,255,255,0.02) 1px, transparent 1px, transparent 30px),
                repeating-linear-gradient(-45deg, rgba(255,255,255,0.02) 0px, rgba(255,255,255,0.02) 1px, transparent 1px, transparent 30px);
            color: #ffffff;
            font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 100vh;
            position: relative;
            overflow: hidden;
        }
        body::before {
            content: "";
            position: absolute;
            inset: 0;
            background: radial-gradient(ellipse at center, rgba(255,255,255,0.04) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite;
            pointer-events: none;
        }
        @keyframes pulse {
            0%, 100% { opacity: 0.5; transform: scale(1); }
            50% { opacity: 1; transform: scale(1.08); }
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .center-content {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            flex: 1;
            animation: fadeIn 1.5s ease-out;
        }
        .username {
            font-size: 0.9rem;
            letter-spacing: 0.2em;
            color: #aaaaaa;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        .main-title {
            font-size: clamp(1.2rem, 3.5vw, 2.5rem);
            font-weight: 300;
            letter-spacing: 0.35em;
            text-align: center;
            text-transform: uppercase;
            color: #ffffff;
            text-shadow: 0 0 30px rgba(255,255,255,0.15);
        }
        .sad-face {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 0px;
            margin-top: 25px;
            font-size: clamp(1.5rem, 5vw, 3rem);
            color: #ffffff;
            text-shadow: 0 0 20px rgba(255,255,255,0.2);
            animation: slightFloat 3s ease-in-out infinite;
            line-height: 0.45;
        }
        .sleep-colon,
        .sleep-mouth {
            display: inline-block;
            transform: rotate(90deg);
            transform-origin: center;
            animation: breathe 2.5s ease-in-out infinite;
        }
        .sleep-mouth {
            margin-top: -0.1em;
        }
        @keyframes breathe {
            0%, 100% { transform: rotate(90deg) scale(1); }
            50% { transform: rotate(90deg) scale(0.9); }
        }
        @keyframes slightFloat {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-5px); }
        }
        .bottom-bar {
            position: absolute;
            bottom: 20px;
            left: 0;
            right: 0;
            text-align: center;
            padding: 15px;
            animation: fadeIn 2s ease-out;
        }
        .url-not-found {
            font-size: 0.8rem;
            letter-spacing: 0.25em;
            color: #888888;
            text-transform: uppercase;
        }
        .url-address {
            font-size: 0.7rem;
            letter-spacing: 0.1em;
            color: #aaaaaa;
            margin-top: 8px;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="center-content">
        <div class="username" id="usernameDisplay">__USERNAME__</div>
        <div class="main-title">Lost Area</div>
        <div class="sad-face">
            <span class="sleep-colon">:</span>
            <span class="sleep-mouth">(</span>
        </div>
    </div>
    <div class="bottom-bar">
        <div class="url-not-found">URL Not Found</div>
        <div class="url-address" id="currentUrl"></div>
    </div>

    <script>
        document.getElementById('currentUrl').textContent = window.location.href;
    </script>
</body>
</html>"""
    html = html.replace("__USERNAME__", username)
    return html, 404

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
def _banner(*lines):
    print("=" * 64, flush=True)
    for line in lines:
        print(line, flush=True)
    print("=" * 64, flush=True)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "reset-password":
        existing_role = get_role(DEFAULT_USERNAME) or "owner"
        new_password = create_user(DEFAULT_USERNAME, role=existing_role)
        _banner(
            f"Password reset for user '{DEFAULT_USERNAME}' (role={existing_role}):",
            f"  Username: {DEFAULT_USERNAME}",
            f"  Password: {new_password}",
            "Copy it now - it will not be shown again.",
        )
        sys.exit(0)

    new_password = ensure_default_user()
    if new_password:
        _banner(
            "First run - account created automatically:",
            f"  Username: {DEFAULT_USERNAME}",
            f"  Password: {new_password}",
            "  Role:     owner",
            "Save this password now - you will need it to log in.",
        )
    else:
        _banner(
            f"Account '{DEFAULT_USERNAME}' already exists (password not shown again).",
            "Lost it or need a new one?  Stop the server and run:",
            "    python app.py reset-password",
        )

    restored = auto_restart_bot()
    if restored:
        status = get_bot_status()
        _banner(
            "Telegram bot auto-restarted:",
            f"  Username: {status.get('username', 'unknown')}",
            f"  Mode:     {'Public' if status.get('public_mode') else 'Private'}",
            f"  Chats:    {len(status.get('chat_ids', []))}",
        )

    try:
        from modules.whatsapp import get_startup_status as wp_status
        status = wp_status()
        if status["status"] == "ok":
            _banner(
                "WhatsApp module:",
                f"  Pair URL : {status['pair_url']}",
                f"  Creds URL: {status['creds_url']}",
            )
    except Exception:
        pass

    if _downsea_available:
        _banner("Downloader backend (TikTok & Pinterest) is available at /downloader_pinterest_tiktok.html")
    else:
        _banner("Downsea module NOT available - place modules/downsea.py to enable.")

    if _testing_available:
        _banner("CodeTest workspace is available at /code_test.html")
    else:
        _banner("CodeTest module NOT available - place modules/testing.py to enable.")

    if _adios_available:
        _banner("Stress Testing panel is available at /frame-work-stres-testing.html")
    else:
        _banner("Adios module NOT available - place modules/adios.py to enable.")

    if _analytic_available:
        _banner("Analytic Data module available at /MyEspT.html")
    else:
        _banner("Analytic Data module NOT available - place modules/analytic_manager.py to enable.")

    if _quick_menu_available:
        _banner("Quick Menu module available at /quick_menu_setting.html")
        _banner("Quick Menu bridge (root-level) available at /status, /menu, /actions, /action")
    else:
        _banner("Quick Menu module NOT available - place modules/quick_menu.py to enable.")

    port = int(Config.PORT) if hasattr(Config, 'PORT') else 3052
    print(f"Starting Oxysintx at http://localhost:{port} ...", flush=True)
    tool_count = len(scan_orchestrator.list_tools())
    print(f"{tool_count} tools loaded successfully.", flush=True)
    app.run(host="0.0.0.0", port=port, debug=False)