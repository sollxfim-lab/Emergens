#!/usr/bin/env python3
"""
Opencode — Main Flask Application (v4.4.2-professional)

Integrated stack:
  • scan_apikey v6.1.2    — Cloudflare bypass + strict FP filter
  • scan_xss v2.0.0        — Wordlist-based XSS scanner
  • sql_map v3.0.0         — Nation-grade SQLi scanner
  • scan_ssl v3.3.0        — Full chain cert inspector
  • scan_ip_info v5.0.0    — Dual-mode IP intelligence
  • scan_tech_fingerprint v3.0.0 — DNS + favicon + multi-path
  • scan_headers v3.2.0    — Advanced header analyzer + CF bypass
  • port_scan v4.0.0       — Wordlist-driven port scanner (patched → 4.0.1)
  • lfi_rfi v1.0.2         — Local/Remote File Inclusion scanner
  • modules.fixes          — Runtime patch for port_scan

v4.4.2 changelog
  • FIX   — Ctrl+C at the port prompt now exits cleanly with
            "⊘ Cancelled by user" and exit code 130 (standard SIGINT).
            Previously a raw Python traceback was printed.
  • FIX   — Ctrl+C while the Flask server is running shuts down
            gracefully with "⊘ Server stopped by user".
  • FIX   — Non-TTY stdin (docker / pipe / CI) now auto-falls back
            to the default port on EOFError instead of crashing.
  • CHG   — Default port is now 8080.

v4.4.1 changelog
  • FIX   — _boot_screen() accepts the bootstrap outcome and stops
            re-invoking ensure_default_user() / auto_restart_bot().
  • FIX   — bootstrap_once() result is threaded through to the boot
            screen so first-run password only appears once.

v4.4.0 changelog
  • NEW   — LFI/RFI scanner fully integrated.
  • FIX   — Bootstrap no longer duplicates inner log lines.
  • FIX   — logger namespace switched from "oxysintx" to "opencode".
  • FIX   — _get_chat_cached() mtime race.
  • FIX   — SSE Response import is now explicit at module top.
  • FIX   — _client_ip() honours X-Forwarded-For only when TRUST_PROXY=1.
  • FIX   — _read_bounded() closes the response in a finally block.
  • FIX   — 404 page HTML cached as compiled string.
  • Removed /downloader_pinterest_tiktok.html and /data_main.html.

Author: Yanxzyx
"""

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
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from importlib import import_module
from pathlib import Path
from subprocess import Popen, PIPE
from typing import Any, Callable, Optional, Tuple

import psutil
import requests
from bs4 import BeautifulSoup
from flask import (
    Flask, render_template, request, jsonify, session, redirect,
    send_from_directory, Response, g, stream_with_context
)
from werkzeug.security import generate_password_hash, check_password_hash

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
    connect_bot, disconnect_bot, get_bot_status,
    update_bot_settings, broadcast_message, auto_restart_bot,
    set_orchestrator, set_history_store,
)

# ── Runtime patches (port_scan hardening) ─────────────────────────────────
try:
    from modules import fixes as _opencode_fixes
    _fixes_available = True
except Exception:
    _opencode_fixes = None
    _fixes_available = False

# ═══════════════════════════════════════════════════════════════════════════
# ANSI colour engine
# ═══════════════════════════════════════════════════════════════════════════
class _Ansi:
    RESET      = "\033[0m"
    BOLD       = "\033[1m"
    DIM        = "\033[2m"
    BLUE       = "\033[38;5;39m"
    BLUE_HI    = "\033[38;5;45m"
    BLUE_DEEP  = "\033[38;5;27m"
    BLUE_LIGHT = "\033[38;5;117m"
    CYAN       = "\033[38;5;51m"
    GREEN      = "\033[38;5;42m"
    RED        = "\033[38;5;203m"
    YELLOW     = "\033[38;5;220m"
    GRAY       = "\033[38;5;244m"
    GRAY_DIM   = "\033[38;5;240m"
    WHITE      = "\033[97m"


def _supports_color() -> bool:
    if os.getenv("NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _enable_windows_vt() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


_USE_COLOR = _supports_color()
if _USE_COLOR:
    _enable_windows_vt()


def _c(text: str, color: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{color}{text}{_Ansi.RESET}"


_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
_SPINNER_INTERVAL = 0.06


def _print_step(label: str, *, ok: bool = True, detail: str = "") -> None:
    mark = _c("✓", _Ansi.GREEN) if ok else _c("✗", _Ansi.RED)
    detail_str = f"  {_c(detail, _Ansi.GRAY_DIM)}" if detail else ""
    sys.stdout.write(f"  {mark} {label}{detail_str}\n")
    sys.stdout.flush()


def _run_with_spinner(
    label: str,
    fn: Callable[[], Any],
    *,
    success_detail: Optional[Callable[[Any], str]] = None,
    error_detail: Optional[Callable[[BaseException], str]] = None,
) -> Tuple[bool, Any]:
    box: dict = {"ok": False, "value": None, "err": None}

    def _worker():
        try:
            box["value"] = fn()
            box["ok"] = True
        except BaseException as exc:  # noqa: BLE001
            box["err"] = exc

    if not _USE_COLOR:
        _worker()
        if box["ok"]:
            detail = ""
            if success_detail is not None:
                try:
                    detail = success_detail(box["value"]) or ""
                except Exception:
                    detail = ""
            _print_step(label, ok=True, detail=detail)
        else:
            detail = ""
            if error_detail is not None:
                try:
                    detail = error_detail(box["err"]) or ""
                except Exception:
                    detail = str(box["err"])
            else:
                detail = str(box["err"]) if box["err"] else ""
            _print_step(label, ok=False, detail=detail)
        return box["ok"], box["value"] if box["ok"] else box["err"]

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    i = 0
    while t.is_alive():
        frame = _SPINNER_FRAMES[i % len(_SPINNER_FRAMES)]
        line = f"  {_c(frame, _Ansi.BLUE)} {_c(label, _Ansi.GRAY)}"
        sys.stdout.write("\r" + line + " " * 10)
        sys.stdout.flush()
        i += 1
        time.sleep(_SPINNER_INTERVAL)
    t.join(timeout=1.0)
    sys.stdout.write("\r" + " " * (len(label) + 20) + "\r")
    sys.stdout.flush()

    if box["ok"]:
        detail = ""
        if success_detail is not None:
            try:
                detail = success_detail(box["value"]) or ""
            except Exception:
                detail = ""
        _print_step(label, ok=True, detail=detail)
    else:
        detail = ""
        if error_detail is not None:
            try:
                detail = error_detail(box["err"]) or ""
            except Exception:
                detail = str(box["err"])
        else:
            detail = str(box["err"]) if box["err"] else ""
        _print_step(label, ok=False, detail=detail)
    return box["ok"], box["value"] if box["ok"] else box["err"]


def _print_banner(text: str, color: str = _Ansi.BLUE) -> None:
    if not _USE_COLOR:
        print(text)
        return
    print("\n".join(_c(line, color) for line in text.split("\n")))


# ═══════════════════════════════════════════════════════════════════════════
# Optional modules — each guarded
# ═══════════════════════════════════════════════════════════════════════════

# ── Port scan ─────────────────────────────────────────────────────────────
try:
    from modules.port_scan import (
        run as port_scan_run,
        run_streaming as port_scan_stream,
        load_basic_ports as port_scan_load_basic,
        load_ports_from_folder as port_scan_load_expert,
        to_csv as port_scan_to_csv,
        to_nmap_xml as port_scan_to_nmap,
        to_sarif as port_scan_to_sarif,
        TOOL_INFO as PORT_SCAN_INFO,
    )
    _port_scan_available = True
except ImportError as _e:
    _port_scan_available = False
    _port_scan_err = str(_e)

# ── Dirfuzz ───────────────────────────────────────────────────────────────
try:
    from modules.dirfuzz import (
        run as dirfuzz_run,
        run_streaming as dirfuzz_stream,
        list_wordlists as dirfuzz_list_wordlists,
    )
    _dirfuzz_available = True
except ImportError:
    _dirfuzz_available = False

# ── SQLi Engine ───────────────────────────────────────────────────────────
try:
    from modules.sqli_engine import (
        run as sqli_run,
        run_streaming as sqli_stream,
        ensure_wordlists as sqli_ensure_wordlists,
        WORDLIST_SOURCES as SQLI_WORDLIST_SOURCES,
    )
    _sqli_engine_available = True
except ImportError:
    _sqli_engine_available = False

# ── SQLMap ────────────────────────────────────────────────────────────────
try:
    from modules import sql_map as sql_map_module
    from modules.sql_map import (
        ensure_wordlists as sqlmap_ensure_wordlists,
        load_sqli_wordlist as sqlmap_load_wordlist,
        TOOL_INFO as SQLMAP_TOOL_INFO,
    )
    _sql_map_available = True
    _sqlmap_wordlist_available = True
except ImportError as _e:
    sql_map_module = None
    _sql_map_available = False
    _sqlmap_wordlist_available = False
    _sqlmap_import_err = str(_e)

# ── Lightweight SQL injection ─────────────────────────────────────────────
try:
    from modules import sql_injection as sql_injection_module
    _sql_injection_available = True
except ImportError:
    _sql_injection_available = False

# ── XSS exploiter ─────────────────────────────────────────────────────────
try:
    from modules.xss_exploiter import (
        run as xss_exploiter_run,
        run_streaming as xss_exploiter_stream,
        ensure_wordlist as xss_exploiter_ensure_wordlist,
    )
    _xss_exploiter_available = True
except ImportError:
    _xss_exploiter_available = False

# ── XSS ───────────────────────────────────────────────────────────────────
try:
    from modules import xss as xss_module
    from modules.xss import (
        ensure_wordlists as xss_ensure_wordlists,
        load_xss_wordlist as xss_load_wordlist,
        TOOL_INFO as XSS_TOOL_INFO,
    )
    _xss_available = True
    _xss_wordlist_available = True
except ImportError as _e:
    xss_module = None
    _xss_available = False
    _xss_wordlist_available = False
    _xss_import_err = str(_e)

# ── Sniper ────────────────────────────────────────────────────────────────
try:
    from modules.sniper import (
        run as sniper_run,
        run_streaming as sniper_stream,
    )
    _sniper_available = True
except ImportError:
    _sniper_available = False

# ── Wordlist scraper ──────────────────────────────────────────────────────
try:
    from modules.git_scraper_wordlist import (
        sync           as wordlist_sync,
        sync_streaming as wordlist_sync_stream,
        list_wordlists as wordlist_list,
        get_manifest   as wordlist_manifest,
        reload_caches  as wordlist_reload_caches,
    )
    _wordlist_scraper_available = True
except ImportError:
    _wordlist_scraper_available = False

# ── Downsea blueprint ─────────────────────────────────────────────────────
try:
    from modules.downsea import downsea_bp
    _downsea_available = True
except ImportError:
    _downsea_available = False

# ── AI Chat ───────────────────────────────────────────────────────────────
from ai_chat.chat_handler import ChatHandler

# ── Analytic manager ──────────────────────────────────────────────────────
try:
    from modules.analytic_manager import AnalyticDataManager
    _analytic_available = True
except ImportError:
    _analytic_available = False

# ── scan_apikey ───────────────────────────────────────────────────────────
try:
    from modules import scan_apikey as apikey_module
    from modules.scan_apikey import (
        APIScanner               as apikey_scanner_cls,
        load_wordlist            as apikey_load_wordlist,
        ensure_wordlists         as apikey_ensure_wordlists,
        ensure_proxies           as apikey_ensure_proxies,
        get_proxy_manager        as apikey_get_proxy_manager,
        _HAS_CURL_CFFI           as apikey_has_curl_cffi,
        _HAS_CLOUDSCRAPER        as apikey_has_cloudscraper,
        FLARESOLVERR_URL         as apikey_flaresolverr_url,
        __version__              as apikey_version,
    )
    _apikey_available = True
except ImportError as _e:
    apikey_module = None
    _apikey_available = False
    _apikey_import_err = str(_e)

# ── scan_ssl ──────────────────────────────────────────────────────────────
try:
    from modules import scan_ssl as ssl_module
    from modules.scan_ssl import (
        run as ssl_run,
        run_streaming as ssl_stream,
        TOOL_INFO as SSL_TOOL_INFO,
    )
    _ssl_available = True
except ImportError as _e:
    ssl_module = None
    _ssl_available = False
    _ssl_import_err = str(_e)

# ── scan_ip_info ──────────────────────────────────────────────────────────
try:
    from modules import scan_ip_info as ipinfo_module
    from modules.scan_ip_info import (
        run as ipinfo_run,
        run_streaming as ipinfo_stream,
        TOOL_INFO as IPINFO_TOOL_INFO,
    )
    _ipinfo_available = True
except ImportError as _e:
    ipinfo_module = None
    _ipinfo_available = False
    _ipinfo_import_err = str(_e)

# ── scan_tech_fingerprint ────────────────────────────────────────────────
try:
    from modules import scan_tech_fingerprint as techfp_module
    from modules.scan_tech_fingerprint import (
        run as techfp_run,
        TOOL_INFO as TECHFP_TOOL_INFO,
    )
    _techfp_available = True
except ImportError as _e:
    techfp_module = None
    _techfp_available = False
    _techfp_import_err = str(_e)

# ── scan_headers ─────────────────────────────────────────────────────────
try:
    from modules import scan_headers as headers_module
    from modules.scan_headers import (
        run as headers_run,
        run_streaming as headers_stream,
        TOOL_INFO as HEADERS_TOOL_INFO,
        _HAS_CURL_CFFI as headers_has_curl_cffi,
        _HAS_CLOUDSCRAPER as headers_has_cloudscraper,
    )
    _headers_available = True
except ImportError as _e:
    headers_module = None
    _headers_available = False
    _headers_import_err = str(_e)

# ── LFI/RFI Scanner v1.0.2 ───────────────────────────────────────────────
try:
    from modules import lfi_rfi as lfi_rfi_module
    from modules.lfi_rfi import (
        run as lfi_rfi_run,
        run_streaming as lfi_rfi_stream,
        TOOL_INFO as LFI_RFI_TOOL_INFO,
    )
    _lfi_rfi_available = True
except ImportError as _e:
    lfi_rfi_module = None
    _lfi_rfi_available = False
    _lfi_rfi_import_err = str(_e)


# ═══════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════
BANNER = r"""
                                                                                                      
▐▓▄                         ▐▓▄           ▄ ▄▄▄░▒▄              ▐▓▄                                   
 ▒ ▄▄▀▀▀▒▓▄   ■▄█▄▓ ▄█▀▒▓▄   ▒ ▄▄▀▀▀▒▓▄  ▓▒▀▓ ▀  ▓▌  ■▄█▄▓▀▀▒▓▄  ▒ ▄▄▀▀▀▒▓▄   ■▄█▄▓▀▀▒▓▄    ▀▄▄▀▀▀▒▓▄ 
▐░▄▀         ▄░▄▀░▀██   ░▒▌ ▐░▄▀         ▐░▓    ▄▒▀ ▄░▄▀░       ▐░▄▀         ▄░▄▀░    ░▒▌ ▄░▄▀        
 ░ ▄▀▀░▓      ░    ▓▌  ▄▐█░  ░ ▄▀▀░▓       ▌ ▄█▀▀    ░           ░ ▄▀▀░▓      ░      ▄▐█░  ▀▀▄▀▄░▓▓▄▄ 
▐█           ▐█    ░   ▄▀▄▌ ▐█            ░   ▓█    ▐█  ▀▀▀▀█▓▀ ▐█           ▐█      ▄▀▄▌ ▄▄      ▀░░▌
██▄      ▄▄▌ ▐█▌       ▄█░▀ ██▄      ▄▄▌ ▐▒    ▒▌   ▐█▌     ▓▒░ ██▄      ▄▄▌ ▐█▌     ▄█░▀ ▄█▄     ▄█░▌
▀█  ▄▄▄▒▓▀    ▀░      ▐▓▀   ▀█  ▄▄▄▒▓▀   ▀▓▀  ▀▓▀    ▀██▄▄▄▒▓▀▒ ▀█  ▄▄▄▒▓▀    ▀░    ▐▓▀   ▀██▀▀▄▄▒▓▀  
"""


# ═══════════════════════════════════════════════════════════════════════════
# MHDDoS engine
# ═══════════════════════════════════════════════════════════════════════════
MHDDOS_SCRIPT = Path(__file__).parent / "start.py"
_mhddos_processes = {}
_mhddos_lock = threading.Lock()
_mhddos_history = []
_MHDDOS_HISTORY_LIMIT = 500

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
    cmd = [sys.executable, str(MHDDOS_SCRIPT)]
    if method in _MHDDOS_LAYER7:
        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        cmd.extend([method, url, str(proxy_type), str(threads),
                    proxy_file, str(rpc), str(duration)])
    else:
        ip_port = target
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$", ip_port):
            try:
                from socket import gethostbyname
                hostname, port = ip_port.rsplit(":", 1)
                ip_port = f"{gethostbyname(hostname)}:{port}"
            except Exception:
                pass
        cmd.extend([method, ip_port, str(threads), str(duration)])
        if method in _MHDDOS_AMP:
            cmd.append(reflector_file if reflector_file else "reflectors.txt")
    if debug:
        cmd.append("debug")
    return cmd


def _mhddos_start_attack(attack_id, method, target, threads, duration,
                         proxy_type, proxy_file, rpc, reflector_file, debug):
    cmd = _mhddos_build_command(method, target, threads, duration,
                                proxy_type, proxy_file, rpc, debug, reflector_file)
    try:
        process = Popen(
            cmd, stdout=PIPE, stderr=PIPE, text=True,
            creationflags=0, cwd=str(Path(__file__).parent),
        )
        with _mhddos_lock:
            _mhddos_processes[attack_id] = {
                "process": process, "method": method, "target": target,
                "threads": threads, "duration": duration,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "status": "running", "attack_id": attack_id,
            }
            _mhddos_history.append({
                "attack_id": attack_id, "method": method, "target": target,
                "threads": threads, "duration": duration,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "status": "running",
            })
            if len(_mhddos_history) > _MHDDOS_HISTORY_LIMIT:
                del _mhddos_history[:-_MHDDOS_HISTORY_LIMIT]
        threading.Thread(target=_mhddos_monitor, args=(attack_id,), daemon=True).start()
        return {"success": True, "attack_id": attack_id}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _mhddos_monitor(attack_id):
    with _mhddos_lock:
        info = _mhddos_processes.get(attack_id)
        if not info:
            return
        process = info["process"]
    try:
        timeout = info["duration"] + 15
        process.wait(timeout=timeout)
        status = "completed" if process.returncode == 0 else "failed"
    except Exception:
        status = "timeout"
        try:
            process.kill()
        except Exception:
            pass
    with _mhddos_lock:
        if attack_id in _mhddos_processes:
            _mhddos_processes[attack_id]["status"] = status
            _mhddos_processes[attack_id]["ended_at"] = datetime.now(timezone.utc).isoformat()
        for entry in _mhddos_history:
            if entry["attack_id"] == attack_id:
                entry["status"] = status
                entry["ended_at"] = datetime.now(timezone.utc).isoformat()
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


def _mhddos_get_status(attack_id=None):
    with _mhddos_lock:
        if attack_id:
            return _mhddos_processes.get(attack_id, None)
        running = [v for v in _mhddos_processes.values() if v["status"] == "running"]
        return {
            "running": running,
            "history": list(_mhddos_history[-50:]),
            "available": True,
            "methods": sorted(_MHDDOS_METHODS),
            "layer7": sorted(_MHDDOS_LAYER7),
            "layer4": sorted(_MHDDOS_LAYER4),
        }


# ═══════════════════════════════════════════════════════════════════════════
# GitHub Profile Scraper
# ═══════════════════════════════════════════════════════════════════════════
GITHUB_URL = "https://github.com"
GITHUB_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
GITHUB_TIMEOUT = 15
GITHUB_CACHE_TTL = 60
_GITHUB_CACHE_MAX = 500
_github_cache = OrderedDict()


def github_fetch_html(url):
    if url in _github_cache:
        ts, html = _github_cache[url]
        if time.time() - ts < GITHUB_CACHE_TTL:
            _github_cache.move_to_end(url)
            return html, None
        del _github_cache[url]
    headers = {"User-Agent": GITHUB_USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}
    try:
        resp = requests.get(url, headers=headers, timeout=GITHUB_TIMEOUT)
    except requests.exceptions.RequestException as e:
        return None, f"Network error: {e}"
    if resp.status_code == 200:
        html = resp.text
        _github_cache[url] = (time.time(), html)
        if len(_github_cache) > _GITHUB_CACHE_MAX:
            _github_cache.popitem(last=False)
        return html, None
    elif resp.status_code == 404:
        return None, "GitHub user not found."
    elif resp.status_code == 403:
        return None, "GitHub is rate-limiting requests. Try again later."
    elif resp.status_code == 503:
        return None, "GitHub is temporarily unavailable."
    return None, f"GitHub returned status {resp.status_code}."


def github_extract_embedded_json(html):
    if not html:
        return {}
    for pattern in (
        r'<script type="application/json" data-target="react-app\.embeddedData">(.*?)</script>',
        r'<script type="application/json" data-target="react-app\.embeddedData"[^>]*>(.*?)</script>',
    ):
        match = re.search(pattern, html, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                continue
    return {}


def github_parse_profile_from_embedded(embedded):
    payload = embedded.get("payload", {})
    user = payload.get("user", {}) or payload.get("profile", {})
    if not user:
        return {}
    def get_count(data, key, default=0):
        val = data.get(key, default)
        if isinstance(val, dict):
            return val.get("totalCount", default)
        return val if val is not None else default
    return {
        "login": user.get("login", ""), "name": user.get("name", ""),
        "bio": user.get("bio", ""), "avatar_url": user.get("avatarUrl", ""),
        "followers": get_count(user, "followers"),
        "following": get_count(user, "following"),
        "company": user.get("company", ""), "location": user.get("location", ""),
        "blog": user.get("websiteUrl", "") or user.get("blog", ""),
        "twitter_username": user.get("twitterUsername", ""),
        "created_at": user.get("createdAt", ""),
        "public_repos": get_count(user, "repositories"),
    }


def github_parse_repos_from_embedded(embedded):
    payload = embedded.get("payload", {})
    repos_data = payload.get("repositories", {})
    nodes = repos_data.get("nodes", []) if isinstance(repos_data, dict) else (
        repos_data if isinstance(repos_data, list) else []
    )
    repos = []
    for repo in nodes:
        if not isinstance(repo, dict):
            continue
        repo_url = repo.get("url", "")
        if repo_url and repo_url.startswith("/"):
            repo_url = GITHUB_URL + repo_url
        primary = repo.get("primaryLanguage", {})
        language = primary.get("name", "") if isinstance(primary, dict) else repo.get("language", "")
        stars = repo.get("stargazerCount", 0)
        if isinstance(stars, dict):
            stars = stars.get("totalCount", 0)
        license_info = repo.get("licenseInfo", {})
        license_name = license_info.get("spdxId", "") if isinstance(license_info, dict) else ""
        repos.append({
            "name": repo.get("name", ""), "html_url": repo_url,
            "description": repo.get("description") or "", "language": language,
            "stargazers_count": stars, "forks_count": repo.get("forkCount", 0),
            "updated_at": repo.get("updatedAt", ""), "license": license_name,
        })
    repos.sort(key=lambda r: r["stargazers_count"], reverse=True)
    return repos


def github_scrape_profile(username):
    url = f"{GITHUB_URL}/{username}"
    html, error = github_fetch_html(url)
    if error:
        return None, error
    embedded = github_extract_embedded_json(html)
    if embedded:
        profile = github_parse_profile_from_embedded(embedded)
        if profile:
            return profile, None
    soup = BeautifulSoup(html, "html.parser")
    username_el = soup.find("span", {"class": "p-nickname"})
    scraped_username = username_el.get_text(strip=True) if username_el else username
    name_el = soup.find("span", {"class": "p-name"})
    name = name_el.get_text(strip=True) if name_el else ""
    bio_el = soup.find("div", {"class": "p-note"})
    bio = bio_el.get_text(strip=True) if bio_el else ""
    avatar_el = soup.find("img", {"class": "avatar-user"})
    avatar_url = avatar_el.get("src") if avatar_el else ""
    if avatar_url and avatar_url.startswith("//"):
        avatar_url = "https:" + avatar_url
    followers = following = 0
    for link in soup.find_all("a", href=True):
        href = link["href"]
        if href == f"/{username}?tab=followers":
            num_el = link.find("span")
            if num_el:
                followers = int(re.sub(r"[^\d]", "", num_el.get_text()) or 0)
        elif href == f"/{username}?tab=following":
            num_el = link.find("span")
            if num_el:
                following = int(re.sub(r"[^\d]", "", num_el.get_text()) or 0)
    company = location = blog = twitter = ""
    for li in soup.find_all("li", {"itemprop": True}):
        prop = li.get("itemprop")
        text = " ".join(li.get_text(strip=True).split())
        if prop == "worksFor":
            company = text
        elif prop == "homeLocation":
            location = text
        elif prop == "url":
            a = li.find("a")
            if a and "twitter" in a.get("href", ""):
                twitter = a.get("href").split("/")[-1]
            else:
                blog = text
    return {
        "login": scraped_username, "name": name, "bio": bio,
        "avatar_url": avatar_url, "followers": followers, "following": following,
        "company": company, "location": location, "blog": blog,
        "twitter_username": twitter, "created_at": "", "public_repos": 0,
    }, None


def github_scrape_repositories(username):
    url = f"{GITHUB_URL}/{username}?tab=repositories"
    html, error = github_fetch_html(url)
    if error:
        return None, error
    embedded = github_extract_embedded_json(html)
    if embedded:
        repos = github_parse_repos_from_embedded(embedded)
        if repos:
            return repos, None
    soup = BeautifulSoup(html, "html.parser")
    repos = []
    for li in soup.find_all("li", class_="col-12"):
        h3 = li.find("h3")
        if not h3 or not h3.find("a"):
            continue
        name_el = h3.find("a")
        repo_name = name_el.get_text(strip=True)
        repo_url = name_el.get("href", "")
        if repo_url.startswith("/"):
            repo_url = GITHUB_URL + repo_url
        desc_el = li.find("p", itemprop="description")
        description = desc_el.get_text(strip=True) if desc_el else ""
        lang_el = li.find("span", itemprop="programmingLanguage")
        language = lang_el.get_text(strip=True) if lang_el else ""
        stars_el = li.find("a", href=re.compile(r"/stargazers$"))
        stars = int(re.sub(r"[^\d]", "", stars_el.get_text()) or 0) if stars_el else 0
        forks_el = li.find("a", href=re.compile(r"/forks$"))
        forks = int(re.sub(r"[^\d]", "", forks_el.get_text()) or 0) if forks_el else 0
        updated_el = li.find("relative-time")
        updated = updated_el.get("datetime", "") if updated_el else ""
        repos.append({
            "name": repo_name, "html_url": repo_url, "description": description,
            "language": language, "stargazers_count": stars, "forks_count": forks,
            "updated_at": updated, "license": "",
        })
    repos.sort(key=lambda r: r["stargazers_count"], reverse=True)
    return repos, None


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
)

if _downsea_available:
    app.register_blueprint(downsea_bp)

setup_logging(Config.SERVER_LOG_FILE)
logger = logging.getLogger("opencode")


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
# Directories
# ═══════════════════════════════════════════════════════════════════════════
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
for d in ["userdata", "listschool", os.path.join("static", "data"),
          "files", os.path.join("files", "proxies"), "wordlist", "porttxt"]:
    os.makedirs(os.path.join(PROJECT_ROOT, d), exist_ok=True)

DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
LOG_DIR = os.path.join(PROJECT_ROOT, 'logs')
UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')
TEMPLATES_DIR = os.path.join(PROJECT_ROOT, 'templates')
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════
# Thread-safe JSON I/O
# ═══════════════════════════════════════════════════════════════════════════
_json_locks = defaultdict(threading.Lock)


def _load_json(name, default):
    path = os.path.join(DATA_DIR, f'{name}.json')
    with _json_locks[name]:
        if not os.path.exists(path):
            return default
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return default


def _save_json(name, data):
    path = os.path.join(DATA_DIR, f'{name}.json')
    tmp = path + '.tmp'
    with _json_locks[name]:
        with open(tmp, 'w', encoding='utf-8') as f:
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


_TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"


def _client_ip():
    if _TRUST_PROXY:
        fwd = request.headers.get('X-Forwarded-For', '')
        if fwd:
            return fwd.split(',')[0].strip()
        real = request.headers.get('X-Real-IP', '').strip()
        if real:
            return real
    return request.remote_addr or 'unknown'


# ═══════════════════════════════════════════════════════════════════════════
# Request counters
# ═══════════════════════════════════════════════════════════════════════════
_request_log_lock = threading.Lock()
_request_timestamps = []
_total_requests_seen = 0


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


def _inbound_stats():
    with _request_log_lock:
        return _total_requests_seen, len(_request_timestamps)


# ═══════════════════════════════════════════════════════════════════════════
# API-key helper
# ═══════════════════════════════════════════════════════════════════════════
def _hash_api_key(raw_key):
    return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()


def _public_key_view(k):
    return {
        'prefix': k.get('prefix') or k.get('key_prefix'),
        'created': k.get('created_at') or k.get('created'),
        'last_used': k.get('last_used'),
        'request_count': k.get('request_count', 0),
    }


def _record_server_activity(key_prefix, username, req):
    reported_name = (
        req.headers.get('X-Server-Name')
        or (req.get_json(silent=True) or {}).get('server_name')
        or None
    )
    ip = req.headers.get('X-Forwarded-For', req.remote_addr) or 'unknown'
    with _json_lock('servers'):
        servers = _load_json('servers', [])
        entry = next((s for s in servers if s['key_prefix'] == key_prefix), None)
        if entry:
            entry['last_seen'] = _now_iso()
            entry['requests'] = entry.get('requests', 0) + 1
            entry['ip'] = ip
            if reported_name:
                entry['server_name'] = reported_name
        else:
            servers.append({
                'server_name': reported_name or f'Unnamed ({key_prefix})',
                'key_prefix': key_prefix, 'ip': ip,
                'last_seen': _now_iso(), 'requests': 1,
            })
        _save_json('servers', servers)


def _find_api_key_owner(raw_key):
    try:
        keys = user_store.get_api_keys()
    except Exception:
        keys = []
    key_hash = _hash_api_key(raw_key)
    for k in keys:
        stored_hash = k.get('key_hash') or k.get('hash')
        if stored_hash and secrets.compare_digest(stored_hash, key_hash):
            return k
        if k.get('key') and secrets.compare_digest(k.get('key', ''), raw_key):
            return k
    return None


def _api_key_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        raw_key = request.headers.get('X-API-Key', '').strip()
        if not raw_key:
            return jsonify({'error': 'Missing X-API-Key header'}), 401
        record = _find_api_key_owner(raw_key)
        if not record:
            return jsonify({'error': 'Invalid API key'}), 401
        prefix = record.get('prefix') or record.get('key_prefix') or raw_key[:20]
        owner = record.get('owner_username') or record.get('username') or 'unknown'
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


def _load_plans():
    if os.path.exists(PAYMENT_PLANS_FILE):
        try:
            with open(PAYMENT_PLANS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            logger.warning("Failed to load payment plans, using defaults.")
    return _default_plans.copy()


def _save_plans(plans):
    try:
        with _payment_lock:
            with open(PAYMENT_PLANS_FILE, "w") as f:
                json.dump(plans, f, indent=2)
        return True
    except IOError:
        logger.error("Failed to save payment plans.")
        return False


def _load_payments():
    if os.path.exists(PAYMENT_DATA_FILE):
        try:
            with open(PAYMENT_DATA_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            logger.warning("Failed to load payment data, starting empty.")
    return []


def _save_payments(payments):
    try:
        with _payment_lock:
            with open(PAYMENT_DATA_FILE, "w") as f:
                json.dump(payments, f, indent=2)
        return True
    except IOError:
        logger.error("Failed to save payment data.")
        return False


payment_plans = _load_plans()


# ═══════════════════════════════════════════════════════════════════════════
# Login rate limiting
# ═══════════════════════════════════════════════════════════════════════════
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
_failed_attempts = defaultdict(list)
_failed_lock = threading.Lock()


def _is_locked_out(ip):
    now = time.time()
    with _failed_lock:
        _failed_attempts[ip] = [t for t in _failed_attempts[ip] if now - t < LOCKOUT_SECONDS]
        return len(_failed_attempts[ip]) >= MAX_LOGIN_ATTEMPTS


def _record_failed_attempt(ip):
    with _failed_lock:
        _failed_attempts[ip].append(time.time())


# ═══════════════════════════════════════════════════════════════════════════
# Auth decorators
# ═══════════════════════════════════════════════════════════════════════════
def _extract_bearer_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return ""


def _authenticate_request():
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


def current_user():
    username = session.get("username")
    if not username:
        return None
    role = get_role(username)
    if role is None:
        return None
    return {'username': username, 'role': role}


def owner_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            return jsonify({'error': 'Not authenticated'}), 401
        if u.get('role') != 'owner':
            return jsonify({'error': 'Owner access required'}), 403
        return f(*args, **kwargs)
    return wrapper


# ═══════════════════════════════════════════════════════════════════════════
# SSE helpers
# ═══════════════════════════════════════════════════════════════════════════
def _sse_format(event: dict) -> str:
    try:
        payload = json.dumps(event, ensure_ascii=False, default=str)
    except Exception:
        payload = json.dumps({"type": "error", "message": "serialization failed"})
    return f"data: {payload}\n\n"


def _sse_response(generator, headers: dict = None):
    base_headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    if headers:
        base_headers.update(headers)
    return Response(stream_with_context(generator), headers=base_headers)


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


@app.route("/remote_access.html")
@login_required
def remote_access_page():
    return render_template("remote_access.html")


@app.route("/MyEspT.html")
@login_required
def MyEspT_page():
    return render_template("MyEspT.html")


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
# Static asset delivery
# ═══════════════════════════════════════════════════════════════════════════
_ALLOWED_ASSET_EXTS = {
    '.js', '.mjs', '.cjs', '.css', '.map',
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
    '.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico',
    '.json', '.txt', '.webmanifest',
}


@app.route('/<path:filename>')
def serve_template_assets(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext not in _ALLOWED_ASSET_EXTS:
        return page_not_found(None)
    safe_path = os.path.abspath(os.path.join(TEMPLATES_DIR, filename))
    if not safe_path.startswith(os.path.abspath(TEMPLATES_DIR) + os.sep):
        logger.warning('Blocked traversal attempt: %s', filename)
        return page_not_found(None)
    if not os.path.isfile(safe_path):
        logger.debug('Static asset missing: %s', filename)
        return page_not_found(None)
    response = send_from_directory(TEMPLATES_DIR, filename)
    response.cache_control.public = True
    response.cache_control.max_age = 3600 if ext in ('.js', '.css', '.map') else 86400
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


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
    data = request.get_json(silent=True) or {}
    plan = data.get("plan", "").strip()
    amount = data.get("amount", "").strip()
    payment_method = data.get("payment_method", "card")
    requested_username = data.get("requested_username", "").strip()
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
        "payment_id": payment_id, "user": username,
        "requested_username": requested_username, "plan": plan,
        "amount": amount, "payment_method": payment_method,
        "card_last4": card_last4, "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "generated_username": None, "generated_password": None,
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
                    "payment_id": record["payment_id"], "status": record["status"],
                    "generated_username": record["generated_username"],
                    "generated_password": record["generated_password"],
                    "plan": record["plan"], "amount": record["amount"],
                })
            return jsonify({"payment_id": record["payment_id"], "status": record["status"]})
    return jsonify({"error": "Payment not found"}), 404


@app.route("/api/payment/history", methods=["GET"])
def get_payment_history():
    user = session.get("username") if session.get("authenticated") else "guest"
    payments = _load_payments()
    user_payments = [p for p in payments if p["user"] == user]
    for p in user_payments:
        if not (p["status"] == "approved" and p.get("generated_password")
                and (p["user"] == session.get("username") or session.get("role") == "owner")):
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
    data = request.get_json(silent=True) or {}
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
                create_user(record["requested_username"], role="analyst", password=generated_password)
                record["generated_username"] = record["requested_username"]
                record["generated_password"] = generated_password
                record["status"] = "approved"
                record["updated_at"] = datetime.now(timezone.utc).isoformat()
                _save_payments(payments)
                logger.info(f"Payment {payment_id} approved. User {record['requested_username']} created.")
                return jsonify({
                    "success": True, "payment_id": record["payment_id"],
                    "generated_username": record["generated_username"],
                    "generated_password": record["generated_password"],
                    "role": "analyst",
                })
            except Exception as e:
                logger.error(f"Failed to create user for payment {payment_id}: {e}")
                return jsonify({"error": f"User creation failed: {str(e)}"}), 500
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
            record["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_payments(payments)
            return jsonify({"success": True})
    return jsonify({"error": "Payment not found"}), 404


# ═══════════════════════════════════════════════════════════════════════════
# OSINT endpoints
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/osint/github")
@api_login_required
def api_osint_github():
    username = request.args.get("username", "").strip()
    if not username:
        return jsonify({"status": False, "error": "Username required"}), 400
    profile, profile_error = github_scrape_profile(username)
    if profile_error:
        return jsonify({"status": False, "error": profile_error}), 404 if "not found" in profile_error else 500
    repos, _ = github_scrape_repositories(username)
    return jsonify({
        "status": True,
        "data": {"profile": profile, "repositories": repos or [], "repos_count": len(repos or [])},
    })


def _proxy_osint(endpoint_slug, username):
    try:
        resp = requests.get(
            f"https://api.siputzx.my.id/api/stalk/{endpoint_slug}",
            params={"q": username, "username": username},
            timeout=15,
            headers={"User-Agent": "Opencode/4.4.2"},
        )
        if resp.status_code == 200:
            return jsonify(resp.json())
        return jsonify({"status": False, "error": f"Upstream API returned {resp.status_code}"}), 502
    except requests.exceptions.RequestException as e:
        return jsonify({"status": False, "error": f"Network error: {e}"}), 500


@app.route("/api/osint/youtube")
@api_login_required
def api_osint_youtube():
    username = request.args.get("username", "").strip()
    if not username:
        return jsonify({"status": False, "error": "Username required"}), 400
    return _proxy_osint("youtube", username)


@app.route("/api/osint/twitter")
@api_login_required
def api_osint_twitter():
    username = request.args.get("username", "").strip()
    if not username:
        return jsonify({"status": False, "error": "Username required"}), 400
    return _proxy_osint("twitter", username)


@app.route("/api/stalk/twitter")
@api_login_required
def api_stalk_twitter():
    return api_osint_twitter()


# ═══════════════════════════════════════════════════════════════════════════
# ADB login
# ═══════════════════════════════════════════════════════════════════════════
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
    return jsonify({"success": True, "username": ADB_USERNAME, "role": ADB_ROLE})


# ═══════════════════════════════════════════════════════════════════════════
# Auth API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/login", methods=["POST"])
def api_login():
    ip = _client_ip()
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
    token = token_store.generate_token(
        username, password, user_agent=request.headers.get("User-Agent", "")
    )
    if token is None:
        return jsonify({"error": "invalid_credentials"}), 401
    return jsonify({
        "token": token, "token_prefix": token[:8] + "****",
        "expires_in": 3600, "username": username, "role": get_role(username),
    })


@app.route("/api/me")
@api_login_required
def api_me():
    return jsonify({"username": session.get("username"), "role": session.get("role")})


# ═══════════════════════════════════════════════════════════════════════════
# Register API
# ═══════════════════════════════════════════════════════════════════════════
def _is_valid_email(email):
    real_email = re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email)
    emergens_email = re.match(r"^[a-zA-Z0-9._-]+@emergens\.id$", email)
    return bool(real_email or emergens_email)


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
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
        return jsonify({
            "success": True, "username": username, "role": "analyst",
            "email": email, "name": name,
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Registration failed: {e}")
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
_INTERNAL_TOOL_KEYS = {"_availability", "__availability__", "availability",
                       "count", "error", "raw", "version"}


@app.route("/api/tools")
@api_login_required
def api_tools():
    try:
        raw_tools = scan_orchestrator.list_tools() or {}
    except Exception as exc:
        logger.error("Failed to list scan tools: %s", exc, exc_info=True)
        raw_tools = {}

    tools = {}
    for name, info in raw_tools.items():
        if not name or not isinstance(name, str):
            continue
        if name.startswith("_") or name in _INTERNAL_TOOL_KEYS:
            continue
        if "school" in name.lower():
            continue
        tools[name] = info

    availability = {
        "dirfuzz":          _dirfuzz_available,
        "sqli_engine":      _sqli_engine_available,
        "sql_map":          _sql_map_available,
        "sql_injection":    _sql_injection_available,
        "xss_exploiter":    _xss_exploiter_available,
        "xss":              _xss_available,
        "sniper":           _sniper_available,
        "wordlist_scraper": _wordlist_scraper_available,
        "analytic":         _analytic_available,
        "downsea":          _downsea_available,
        "apikey":           _apikey_available,
        "ssl":              _ssl_available,
        "ipinfo":           _ipinfo_available,
        "techfp":           _techfp_available,
        "headers":          _headers_available,
        "port_scan":        _port_scan_available,
        "lfi_rfi":          _lfi_rfi_available,
    }

    return jsonify({
        "tools":        tools,
        "availability": availability,
        "count":        len(tools),
    })


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
    try:
        return jsonify(TOOL_MAP[tool_name].run(target, mode))
    except Exception as e:
        logger.error(f"scan tool {tool_name} failed: {e}", exc_info=True)
        return jsonify({"error": "tool_execution_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# API Key Scanner
# ═══════════════════════════════════════════════════════════════════════════
def _apikey_unavailable_response():
    return jsonify({
        "error": "apikey module not available",
        "detail": _apikey_import_err if not _apikey_available else "",
    }), 503


@app.route("/api/apikey/status")
@api_login_required
def api_apikey_status():
    if not _apikey_available:
        return _apikey_unavailable_response()
    try:
        proxy_mgr = apikey_get_proxy_manager(auto_sync=False)
        proxy_stats = proxy_mgr.stats() if proxy_mgr else None
    except Exception:
        proxy_stats = None
    return jsonify({
        "available":    True,
        "version":      apikey_version,
        "cf_bypass": {
            "enabled":         True,
            "curl_cffi":       apikey_has_curl_cffi,
            "cloudscraper":    apikey_has_cloudscraper,
            "flaresolverr":    bool(apikey_flaresolverr_url),
        },
        "proxy": proxy_stats,
        "filter_config": {
            "min_key_length":  getattr(apikey_module, "MIN_EXTRACTED_LENGTH", 10),
            "min_entropy":     getattr(apikey_module, "MIN_SECRET_ENTROPY", 2.8),
            "keyword_min_len": getattr(apikey_module, "KEYWORD_MIN_LENGTH", 8),
        },
    })


@app.route("/api/apikey/cf-status")
@api_login_required
def api_apikey_cf_status():
    if not _apikey_available:
        return _apikey_unavailable_response()
    strategies = []
    if apikey_has_curl_cffi:
        strategies.append("curl_cffi (TLS impersonate Chrome)")
    if apikey_has_cloudscraper:
        strategies.append("cloudscraper (JS solver)")
    if apikey_flaresolverr_url:
        strategies.append("flaresolverr (external)")
    strategies.append("manual (headers + UA + cookies)")
    return jsonify({
        "curl_cffi_available":    apikey_has_curl_cffi,
        "cloudscraper_available": apikey_has_cloudscraper,
        "flaresolverr_url":       apikey_flaresolverr_url or "(not set)",
        "strategies":             strategies,
        "version":                apikey_version,
    })


@app.route("/api/apikey/wordlists")
@api_login_required
def api_apikey_wordlists():
    if not _apikey_available:
        return _apikey_unavailable_response()
    try:
        return jsonify(apikey_ensure_wordlists(force=False))
    except Exception as e:
        logger.error(f"apikey wordlists status failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/apikey/wordlists/sync", methods=["POST"])
@role_required("owner", "analyst")
def api_apikey_wordlists_sync():
    if not _apikey_available:
        return _apikey_unavailable_response()
    try:
        return jsonify(apikey_ensure_wordlists(force=True))
    except Exception as e:
        logger.error(f"apikey wordlists sync failed: {e}", exc_info=True)
        return jsonify({"error": "sync_failed", "detail": str(e)}), 500


@app.route("/api/apikey/proxies")
@api_login_required
def api_apikey_proxies():
    if not _apikey_available:
        return _apikey_unavailable_response()
    try:
        proxy_mgr = apikey_get_proxy_manager(auto_sync=False)
        return jsonify({
            "directory": str(proxy_mgr.proxy_dir) if proxy_mgr else "",
            "all_file":  str(proxy_mgr.all_path) if proxy_mgr else "",
            "meta_file": str(proxy_mgr.meta_path) if proxy_mgr else "",
            "stats":     proxy_mgr.stats() if proxy_mgr else None,
        })
    except Exception as e:
        logger.error(f"apikey proxy status failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/apikey/proxies/sync", methods=["POST"])
@role_required("owner", "analyst")
def api_apikey_proxies_sync():
    if not _apikey_available:
        return _apikey_unavailable_response()
    try:
        return jsonify(apikey_ensure_proxies(force=True))
    except Exception as e:
        logger.error(f"apikey proxies sync failed: {e}", exc_info=True)
        return jsonify({"error": "sync_failed", "detail": str(e)}), 500


@app.route("/api/apikey/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_apikey_scan():
    if not _apikey_available:
        return _apikey_unavailable_response()
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    mode = data.get("mode", "basic")
    if mode not in ("basic", "expert"):
        mode = "basic"
    try:
        if "min_key_length" in data:
            apikey_module.MIN_EXTRACTED_LENGTH = max(4, int(data["min_key_length"]))
        if "min_entropy" in data:
            apikey_module.MIN_SECRET_ENTROPY = max(0.0, float(data["min_entropy"]))
    except (ValueError, TypeError):
        pass
    try:
        scanner = apikey_scanner_cls(
            mode=mode,
            entropy_threshold=float(data.get("entropy_threshold", 4.5)),
            deduplicate=True,
            follow_symlinks=False,
            include_external=True,
            use_proxy=not bool(data.get("no_proxy", False)),
            max_proxy_attempts=int(data.get("max_proxy_attempts", 4)),
            use_cloudflare_bypass=not bool(data.get("no_cf_bypass", False)),
        )
        return jsonify(scanner.run(target))
    except Exception as e:
        logger.error(f"apikey scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# SSL scanner
# ═══════════════════════════════════════════════════════════════════════════
def _ssl_unavailable():
    return jsonify({"error": "ssl module not available",
                    "detail": _ssl_import_err if not _ssl_available else ""}), 503


@app.route("/api/ssl/status")
@api_login_required
def api_ssl_status():
    if not _ssl_available:
        return _ssl_unavailable()
    return jsonify({
        "available": True,
        "version":   SSL_TOOL_INFO.get("version", "?"),
        "name":      SSL_TOOL_INFO.get("name", "SSL/TLS"),
    })


@app.route("/api/ssl/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_ssl_scan():
    if not _ssl_available:
        return _ssl_unavailable()
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    try:
        return jsonify(ssl_run(
            target, mode=data.get("mode", "basic"),
            port=int(data.get("port", 443)),
            timeout=float(data.get("timeout", 8.0)),
            verify=bool(data.get("verify", False)),
            sni=bool(data.get("sni", True)),
        ))
    except Exception as e:
        logger.error(f"ssl scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/ssl/scan/stream")
@role_required("owner", "analyst")
def api_ssl_scan_stream():
    if not _ssl_available:
        return _ssl_unavailable()
    target = (request.args.get("target") or request.args.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    cancel_event = threading.Event()
    options = {
        "mode":   request.args.get("mode", "basic"),
        "port":   int(request.args.get("port", 443)),
        "timeout": float(request.args.get("timeout", 8.0)),
        "verify": request.args.get("verify", "0") == "1",
        "sni":    request.args.get("sni", "1") == "1",
    }
    def _gen():
        try:
            for ev in ssl_stream(target, options, cancel_event):
                yield _sse_format(ev)
        except GeneratorExit:
            cancel_event.set()
        except Exception as e:
            logger.error(f"ssl stream failed: {e}", exc_info=True)
            yield _sse_format({"type": "error", "message": str(e)})
    return _sse_response(_gen())


# ═══════════════════════════════════════════════════════════════════════════
# IP Info scanner
# ═══════════════════════════════════════════════════════════════════════════
def _ipinfo_unavailable():
    return jsonify({"error": "ipinfo module not available",
                    "detail": _ipinfo_import_err if not _ipinfo_available else ""}), 503


@app.route("/api/ipinfo/status")
@api_login_required
def api_ipinfo_status():
    if not _ipinfo_available:
        return _ipinfo_unavailable()
    return jsonify({
        "available": True,
        "version":   IPINFO_TOOL_INFO.get("version", "?"),
        "name":      IPINFO_TOOL_INFO.get("name", "IP & ASN Info"),
    })


@app.route("/api/ipinfo/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_ipinfo_scan():
    if not _ipinfo_available:
        return _ipinfo_unavailable()
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("ip") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    mode = data.get("mode", "basic")
    kwargs = {
        "cache_ttl":      int(data.get("cache_ttl", 3600)),
        "include_rdns":   bool(data.get("include_rdns", True)),
        "include_asn":    bool(data.get("include_asn", True)),
        "include_local":  bool(data.get("include_local", mode == "expert")),
        "include_threat": bool(data.get("include_threat", True)),
        "use_cf_bypass":  bool(data.get("use_cf_bypass", True)),
        "offline":        bool(data.get("offline", False)),
        "ipinfo_token":   data.get("ipinfo_token"),
    }
    try:
        return jsonify(ipinfo_run(target, mode=mode, **kwargs))
    except Exception as e:
        logger.error(f"ipinfo scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/ipinfo/scan/stream")
@role_required("owner", "analyst")
def api_ipinfo_scan_stream():
    if not _ipinfo_available:
        return _ipinfo_unavailable()
    target = (request.args.get("target") or request.args.get("ip") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    cancel_event = threading.Event()
    options = {
        "mode":           request.args.get("mode", "basic"),
        "include_local":  request.args.get("local", "1") == "1",
        "include_threat": request.args.get("threat", "1") == "1",
        "use_cf_bypass":  request.args.get("cf_bypass", "1") == "1",
        "offline":        request.args.get("offline", "0") == "1",
    }
    def _gen():
        try:
            for ev in ipinfo_stream(target, options, cancel_event):
                yield _sse_format(ev)
        except GeneratorExit:
            cancel_event.set()
        except Exception as e:
            logger.error(f"ipinfo stream failed: {e}", exc_info=True)
            yield _sse_format({"type": "error", "message": str(e)})
    return _sse_response(_gen())


# ═══════════════════════════════════════════════════════════════════════════
# Tech fingerprint
# ═══════════════════════════════════════════════════════════════════════════
def _techfp_unavailable():
    return jsonify({"error": "tech_fingerprint module not available",
                    "detail": _techfp_import_err if not _techfp_available else ""}), 503


@app.route("/api/techfp/status")
@api_login_required
def api_techfp_status():
    if not _techfp_available:
        return _techfp_unavailable()
    return jsonify({
        "available": True,
        "version":   TECHFP_TOOL_INFO.get("version", "?"),
        "name":      TECHFP_TOOL_INFO.get("name", "Tech Fingerprint"),
    })


@app.route("/api/techfp/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_techfp_scan():
    if not _techfp_available:
        return _techfp_unavailable()
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    try:
        return jsonify(techfp_run(
            target,
            mode=data.get("mode", "basic"),
            timeout=int(data.get("timeout", 8)),
            check_favicon=bool(data.get("check_favicon", True)),
            probe_extra=bool(data.get("probe_extra", True)),
        ))
    except Exception as e:
        logger.error(f"techfp scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Headers scanner
# ═══════════════════════════════════════════════════════════════════════════
def _headers_unavailable():
    return jsonify({"error": "headers module not available",
                    "detail": _headers_import_err if not _headers_available else ""}), 503


@app.route("/api/headers/status")
@api_login_required
def api_headers_status():
    if not _headers_available:
        return _headers_unavailable()
    return jsonify({
        "available": True,
        "version":   HEADERS_TOOL_INFO.get("version", "?"),
        "cf_bypass": {
            "curl_cffi":   headers_has_curl_cffi,
            "cloudscraper": headers_has_cloudscraper,
        },
    })


@app.route("/api/headers/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_headers_scan():
    if not _headers_available:
        return _headers_unavailable()
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    try:
        return jsonify(headers_run(
            target,
            mode=data.get("mode", "basic"),
            timeout=float(data.get("timeout", 12.0)),
            verify_ssl=bool(data.get("verify_ssl", True)),
            check_paths=bool(data.get("check_paths", False)),
            check_discovery=bool(data.get("check_discovery", True)),
            use_cf_bypass=bool(data.get("use_cf_bypass", True)),
        ))
    except Exception as e:
        logger.error(f"headers scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/headers/scan/stream")
@role_required("owner", "analyst")
def api_headers_scan_stream():
    if not _headers_available:
        return _headers_unavailable()
    target = (request.args.get("target") or request.args.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    cancel_event = threading.Event()
    options = {
        "mode":            request.args.get("mode", "basic"),
        "check_paths":     request.args.get("check_paths", "0") == "1",
        "check_discovery": request.args.get("check_discovery", "0") == "1",
        "use_cf_bypass":   request.args.get("cf_bypass", "1") == "1",
    }
    def _gen():
        try:
            for ev in headers_stream(target, options, cancel_event):
                yield _sse_format(ev)
        except GeneratorExit:
            cancel_event.set()
        except Exception as e:
            logger.error(f"headers stream failed: {e}", exc_info=True)
            yield _sse_format({"type": "error", "message": str(e)})
    return _sse_response(_gen())


# ═══════════════════════════════════════════════════════════════════════════
# LFI/RFI Scanner (v1.0.2)
# ═══════════════════════════════════════════════════════════════════════════
def _lfi_rfi_unavailable():
    return jsonify({
        "error": "lfi_rfi module not available",
        "detail": _lfi_rfi_import_err if not _lfi_rfi_available else "",
    }), 503


@app.route("/api/lfi_rfi/status")
@api_login_required
def api_lfi_rfi_status():
    if not _lfi_rfi_available:
        return _lfi_rfi_unavailable()
    return jsonify({
        "available": True,
        "version":   LFI_RFI_TOOL_INFO.get("version", "?"),
        "name":      LFI_RFI_TOOL_INFO.get("name", "LFI / RFI Scanner"),
        "category":  LFI_RFI_TOOL_INFO.get("category", "Web Security"),
        "intrusive": True,
    })


@app.route("/api/lfi_rfi/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_lfi_rfi_scan():
    if not _lfi_rfi_available:
        return _lfi_rfi_unavailable()
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    try:
        return jsonify(lfi_rfi_run(
            target,
            mode=data.get("mode", "basic"),
            timeout=float(data.get("timeout", 10.0)),
            concurrency=int(data.get("concurrency", 12)),
            rate_limit=float(data.get("rate_limit", 40.0)),
            max_duration=float(data.get("max_duration", 120.0)),
            verify_ssl=bool(data.get("verify_ssl", False)),
            follow_redirects=bool(data.get("follow_redirects", True)),
            params=data.get("params"),
            callback_url=data.get("callback_url"),
            test_rfi=bool(data.get("test_rfi", True)),
            headers=data.get("headers"),
            cookies=data.get("cookies"),
            proxies=data.get("proxies"),
        ))
    except Exception as e:
        logger.error(f"lfi_rfi scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/lfi_rfi/scan/stream")
@role_required("owner", "analyst")
def api_lfi_rfi_scan_stream():
    if not _lfi_rfi_available:
        return _lfi_rfi_unavailable()
    target = (request.args.get("target") or request.args.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    cancel_event = threading.Event()
    options = {
        "mode":         request.args.get("mode", "basic"),
        "timeout":      float(request.args.get("timeout", 10.0)),
        "concurrency":  int(request.args.get("concurrency", 12)),
        "rate_limit":   float(request.args.get("rate_limit", 40.0)),
        "max_duration": float(request.args.get("max_duration", 120.0)),
        "verify_ssl":   request.args.get("verify_ssl", "0") == "1",
        "test_rfi":     request.args.get("test_rfi", "1") == "1",
        "callback_url": request.args.get("callback_url"),
    }
    def _gen():
        try:
            for ev in lfi_rfi_stream(target, options, cancel_event):
                yield _sse_format(ev)
        except GeneratorExit:
            cancel_event.set()
        except Exception as e:
            logger.error(f"lfi_rfi stream failed: {e}", exc_info=True)
            yield _sse_format({"type": "error", "message": str(e)})
    return _sse_response(_gen())


@app.route("/api/lfi_rfi/payloads")
@api_login_required
def api_lfi_rfi_payloads():
    if not _lfi_rfi_available:
        return _lfi_rfi_unavailable()
    mode = (request.args.get("mode") or "basic").lower()
    if mode not in ("basic", "expert"):
        mode = "basic"
    try:
        return jsonify(lfi_rfi_module.list_payloads(mode))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Port scan
# ═══════════════════════════════════════════════════════════════════════════
def _port_scan_unavailable():
    return jsonify({"error": "port_scan module not available",
                    "detail": _port_scan_err if not _port_scan_available else ""}), 503


@app.route("/api/portscan/status")
@api_login_required
def api_portscan_status():
    if not _port_scan_available:
        return _port_scan_unavailable()
    return jsonify({
        "available": True,
        "version":   PORT_SCAN_INFO.get("version", "?"),
        "patched":   _fixes_available,
        "fixes":     ({} if not _fixes_available else _opencode_fixes.check())
                     if _fixes_available else {},
    })


@app.route("/api/portscan/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_portscan_scan():
    if not _port_scan_available:
        return _port_scan_unavailable()
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    kwargs = {
        "timeout":     float(data.get("timeout", 0.4)),
        "max_workers": int(data.get("max_workers", 400)),
        "banner":      bool(data.get("banner", False)),
        "tls":         bool(data.get("tls", False)),
        "rdns":        bool(data.get("rdns", False)),
        "rate_limit":  float(data.get("rate_limit", 0.0)),
    }
    try:
        return jsonify(port_scan_run(target, mode=data.get("mode", "basic"), **kwargs))
    except Exception as e:
        logger.error(f"port scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/portscan/scan/stream")
@role_required("owner", "analyst")
def api_portscan_scan_stream():
    if not _port_scan_available:
        return _port_scan_unavailable()
    target = (request.args.get("target") or request.args.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    cancel_event = threading.Event()
    options = {
        "timeout":     float(request.args.get("timeout", 0.4)),
        "max_workers": int(request.args.get("max_workers", 400)),
        "banner":      request.args.get("banner", "0") == "1",
        "tls":         request.args.get("tls", "0") == "1",
        "rdns":        request.args.get("rdns", "0") == "1",
        "rate_limit":  float(request.args.get("rate_limit", 0.0)),
    }
    def _gen():
        try:
            for ev in port_scan_stream(target, request.args.get("mode", "basic"),
                                       options, cancel_event):
                yield _sse_format(ev)
        except GeneratorExit:
            cancel_event.set()
        except Exception as e:
            logger.error(f"port scan stream failed: {e}", exc_info=True)
            yield _sse_format({"type": "error", "message": str(e)})
    return _sse_response(_gen())


@app.route("/api/portscan/validate")
@api_login_required
def api_portscan_validate():
    if not _port_scan_available:
        return _port_scan_unavailable()
    try:
        basic, b_meta = port_scan_load_basic(None)
        expert, e_meta = port_scan_load_expert(None)
        return jsonify({
            "basic":  {"count": len(basic), **b_meta},
            "expert": {"count": len(expert), **e_meta},
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Leak Data Search
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/leakdata/search", methods=["GET", "POST"])
@api_login_required
def api_leakdata_search():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        target = data.get("target", data.get("query", ""))
    else:
        target = request.args.get("q", "")
    target = target.strip()
    if not target:
        return jsonify({"error": "query_required"}), 400
    try:
        return jsonify(search_user_run(target))
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
# System stats / logs
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/system/stats")
@api_login_required
def api_system_stats():
    total_seen, last_minute = _inbound_stats()
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
    except Exception as e:
        logger.error(f'psutil read failed: {e}')
        cpu = mem = disk = 0.0
    return jsonify({
        'cpu_percent': cpu, 'memory_percent': mem, 'disk_percent': disk,
        'network_in': total_seen, 'network_in_rate': last_minute,
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


# ═══════════════════════════════════════════════════════════════════════════
# AI Chat
# ═══════════════════════════════════════════════════════════════════════════
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


# ═══════════════════════════════════════════════════════════════════════════
# School search
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/school/search")
@api_login_required
def api_school_search():
    from modules import scan_school
    query = request.args.get("q", "").strip()
    result = scan_school.run(query)
    return jsonify(result["data"])


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
    return jsonify(update_bot_settings(**settings))


@app.route("/api/telegram/broadcast", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_broadcast():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message_required"}), 400
    return jsonify(broadcast_message(message))


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
    })


@app.route("/api/mhddos/start", methods=["POST"])
@login_required
def mhddos_start():
    data = request.get_json(silent=True) or {}
    method = (data.get("method") or "").strip().upper()
    target = (data.get("target") or "").strip()
    threads = int(data.get("threads", 10))
    duration = int(data.get("duration", 60))
    proxy_type = int(data.get("proxy_type", 0))
    proxy_file = (data.get("proxy_file") or "proxies.txt").strip()
    rpc = int(data.get("rpc", 1))
    reflector_file = (data.get("reflector_file") or "").strip()
    debug = bool(data.get("debug", False))
    if not method or not target:
        return jsonify({"error": "method and target are required"}), 400
    if method not in _MHDDOS_METHODS:
        return jsonify({"error": f"Unknown method: {method}"}), 400
    if threads < 1 or threads > 1000:
        return jsonify({"error": "threads must be between 1 and 1000"}), 400
    if duration < 1 or duration > 3600:
        return jsonify({"error": "duration must be between 1 and 3600 seconds"}), 400
    attack_id = "MHD-" + uuid.uuid4().hex[:8].upper()
    result = _mhddos_start_attack(
        attack_id, method, target, threads, duration,
        proxy_type, proxy_file, rpc, reflector_file, debug
    )
    return jsonify(result), (201 if result.get("success") else 500)


@app.route("/api/mhddos/stop", methods=["POST"])
@login_required
def mhddos_stop():
    data = request.get_json(silent=True) or {}
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
    return jsonify({"history": _mhddos_history[-limit:]})


# ═══════════════════════════════════════════════════════════════════════════
# Remote Access / C2
# ═══════════════════════════════════════════════════════════════════════════
_lock_state = {"locked": True, "locked_by": None, "locked_at": None}
_c2_devices = []
_c2_activities = []
_c2_lock = threading.Lock()


@app.route("/api/c2/status")
@login_required
def c2_status():
    return jsonify({
        "authenticated": True, "username": session.get("username"),
        "role": session.get("role"), "lock_state": _lock_state,
    })


@app.route("/api/c2/toggle_lock", methods=["POST"])
@login_required
def c2_toggle_lock():
    with _c2_lock:
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
        "id": device_id, "name": data.get("name", device_id),
        "model": data.get("model", ""), "serial": data.get("serial", ""),
        "android": data.get("android", ""), "status": "online",
        "battery": data.get("battery"), "location": data.get("location", ""),
        "temperature": data.get("temperature", ""),
        "last_seen": datetime.now(timezone.utc).isoformat(),
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
    data = request.get_json(silent=True) or {}
    device_id = data.get("device_id", "").strip()
    action = data.get("action", "").strip()
    if not device_id or not action:
        return jsonify({"error": "device_id and action are required"}), 400
    device_name = next((d["name"] for d in _c2_devices if d["id"] == device_id), device_id)
    with _c2_lock:
        _c2_activities.append({
            "device_id": device_id, "device_name": device_name,
            "action": action,
            "timestamp": data.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        })
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════════════════════
# Exploit / Analytic endpoints
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
    data = request.get_json(silent=True) or {}
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
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    try:
        return jsonify({"results": AnalyticDataManager().run_brute_force(
            target, data.get("protocols", ["http", "ftp", "ssh"]),
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
        return jsonify({"results": AnalyticDataManager().run_sql_injection_scan(
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
        return jsonify({"results": AnalyticDataManager().run_xss_scan(
            url, data.get("method", "GET"), data.get("params")
        )})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Directory Fuzzer API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/dirfuzz/wordlists")
@api_login_required
def api_dirfuzz_wordlists():
    if not _dirfuzz_available:
        return jsonify({"error": "dirfuzz module not available"}), 503
    try:
        return jsonify({"wordlists": dirfuzz_list_wordlists()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/dirfuzz/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_dirfuzz_scan():
    if not _dirfuzz_available:
        return jsonify({"error": "dirfuzz module not available"}), 503
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    options = {
        "wordlist_name": data.get("wordlist_name", "lottery-dirs.txt"),
        "wordlist": data.get("wordlist"),
        "max_paths": int(data.get("max_paths", 300)),
        "concurrency": int(data.get("concurrency", 24)),
        "rate_limit": float(data.get("rate_limit", 40.0)),
        "timeout": float(data.get("timeout", 4.0)),
        "max_duration": float(data.get("max_duration", 90.0)),
        "follow_redirects": bool(data.get("follow_redirects", False)),
    }
    try:
        return jsonify(dirfuzz_run(target, options))
    except Exception as e:
        logger.error(f"dirfuzz scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/dirfuzz/scan/stream")
@role_required("owner", "analyst")
def api_dirfuzz_scan_stream():
    if not _dirfuzz_available:
        return jsonify({"error": "dirfuzz module not available"}), 503
    target = (request.args.get("target") or request.args.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    cancel_event = threading.Event()
    options = {
        "wordlist_name": request.args.get("wordlist_name", "lottery-dirs.txt"),
        "max_paths": int(request.args.get("max_paths", 300)),
        "concurrency": int(request.args.get("concurrency", 24)),
        "rate_limit": float(request.args.get("rate_limit", 40.0)),
        "timeout": float(request.args.get("timeout", 4.0)),
        "max_duration": float(request.args.get("max_duration", 90.0)),
        "follow_redirects": request.args.get("follow_redirects", "0") == "1",
        "cancel_event": cancel_event,
    }
    def _gen():
        try:
            for event in dirfuzz_stream(target, options, cancel_event=cancel_event):
                yield _sse_format(event)
        except GeneratorExit:
            cancel_event.set()
        except Exception as e:
            logger.error(f"dirfuzz stream failed: {e}", exc_info=True)
            yield _sse_format({"type": "error", "message": str(e)})
    return _sse_response(_gen())


# ═══════════════════════════════════════════════════════════════════════════
# SQLi Engine API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/sqli/wordlists")
@api_login_required
def api_sqli_wordlists():
    if not _sqli_engine_available:
        return jsonify({"error": "sqli_engine module not available"}), 503
    try:
        return jsonify(sqli_ensure_wordlists())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sqli/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_sqli_scan():
    if not _sqli_engine_available:
        return jsonify({"error": "sqli_engine module not available"}), 503
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    techniques = data.get("techniques") or ["error", "boolean", "time", "union"]
    options = {
        "techniques": techniques, "params": data.get("params"),
        "max_params": int(data.get("max_params", 10)),
        "concurrency": int(data.get("concurrency", 8)),
        "rate_limit": float(data.get("rate_limit", 20.0)),
        "timeout": float(data.get("timeout", 8.0)),
        "max_duration": float(data.get("max_duration", 90.0)),
        "method": data.get("method", "GET"),
        "headers": data.get("headers"), "cookies": data.get("cookies"),
    }
    try:
        return jsonify(sqli_run(target, options))
    except Exception as e:
        logger.error(f"sqli scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/sqli/scan/stream")
@role_required("owner", "analyst")
def api_sqli_scan_stream():
    if not _sqli_engine_available:
        return jsonify({"error": "sqli_engine module not available"}), 503
    target = (request.args.get("target") or request.args.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    tech_arg = request.args.get("techniques", "error,boolean,time,union")
    techniques = [t.strip() for t in tech_arg.split(",") if t.strip()]
    cancel_event = threading.Event()
    options = {
        "techniques": techniques,
        "max_params": int(request.args.get("max_params", 10)),
        "concurrency": int(request.args.get("concurrency", 8)),
        "rate_limit": float(request.args.get("rate_limit", 20.0)),
        "timeout": float(request.args.get("timeout", 8.0)),
        "max_duration": float(request.args.get("max_duration", 90.0)),
        "method": request.args.get("method", "GET"),
        "cancel_event": cancel_event,
    }
    def _gen():
        try:
            for event in sqli_stream(target, options, cancel_event=cancel_event):
                yield _sse_format(event)
        except GeneratorExit:
            cancel_event.set()
        except Exception as e:
            logger.error(f"sqli stream failed: {e}", exc_info=True)
            yield _sse_format({"type": "error", "message": str(e)})
    return _sse_response(_gen())


# ═══════════════════════════════════════════════════════════════════════════
# SQLMap API
# ═══════════════════════════════════════════════════════════════════════════
def _sqlmap_unavailable_response():
    return jsonify({
        "error": "sql_map module not available",
        "detail": _sqlmap_import_err if not _sql_map_available else "",
    }), 503


@app.route("/api/sqlmap/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_sqlmap_scan():
    if not _sql_map_available:
        return _sqlmap_unavailable_response()
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    mode = data.get("mode", "basic")
    if mode not in ("basic", "expert"):
        mode = "basic"
    kwargs = {
        "method": data.get("method", "GET"),
        "params": data.get("params"),
        "timeout": float(data.get("timeout", 5.0)),
        "max_threads": int(data.get("max_threads", 10)),
        "verify_ssl": bool(data.get("verify_ssl", False)),
        "headers": data.get("headers"),
        "cookies": data.get("cookies"),
        "proxies": data.get("proxies"),
        "max_duration": float(data.get("max_duration", 120.0)),
        "rate_limit": float(data.get("rate_limit", 25.0)),
    }
    try:
        return jsonify(sql_map_module.run(target, mode, **kwargs))
    except Exception as e:
        logger.error(f"sql_map scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/sqlmap/scan/stream")
@role_required("owner", "analyst")
def api_sqlmap_scan_stream():
    if not _sql_map_available:
        return _sqlmap_unavailable_response()
    target = (request.args.get("target") or request.args.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    mode = request.args.get("mode", "basic")
    if mode not in ("basic", "expert"):
        mode = "basic"
    cancel_event = threading.Event()
    options = {
        "method": request.args.get("method", "GET"),
        "timeout": float(request.args.get("timeout", 5.0)),
        "max_threads": int(request.args.get("max_threads", 10)),
        "max_duration": float(request.args.get("max_duration", 120.0)),
        "rate_limit": float(request.args.get("rate_limit", 25.0)),
    }
    def _gen():
        try:
            for event in sql_map_module.run_streaming(
                target, mode=mode, options=options, cancel_event=cancel_event
            ):
                yield _sse_format(event)
        except GeneratorExit:
            cancel_event.set()
        except Exception as e:
            logger.error(f"sqlmap stream failed: {e}", exc_info=True)
            yield _sse_format({"type": "error", "message": str(e)})
    return _sse_response(_gen())


@app.route("/api/sqlmap/wordlists")
@api_login_required
def api_sqlmap_wordlists():
    if not _sqlmap_wordlist_available:
        return jsonify({"error": "sql_map wordlist helpers not available"}), 503
    try:
        return jsonify(sqlmap_ensure_wordlists(force=False))
    except Exception as e:
        logger.error(f"sqlmap wordlists status failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/sqlmap/wordlists/sync", methods=["POST"])
@role_required("owner", "analyst")
def api_sqlmap_wordlists_sync():
    if not _sqlmap_wordlist_available:
        return jsonify({"error": "sql_map wordlist helpers not available"}), 503
    try:
        sqlmap_load_wordlist(force_download=True, auto_sync=True)
        return jsonify(sqlmap_ensure_wordlists(force=True))
    except Exception as e:
        logger.error(f"sqlmap wordlists sync failed: {e}", exc_info=True)
        return jsonify({"error": "sync_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Lightweight SQL Injection
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/sql_injection/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_sql_injection_scan():
    if not _sql_injection_available:
        return jsonify({"error": "sql_injection module not available"}), 503
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    try:
        return jsonify(sql_injection_module.run_sql_injection(
            target, method=data.get("method", "GET"),
            params=data.get("params") or {},
        ))
    except Exception as e:
        logger.error(f"sql_injection scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# XSS Exploiter API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/xss/wordlist")
@api_login_required
def api_xss_wordlist():
    if not _xss_exploiter_available:
        return jsonify({"error": "xss_exploiter module not available"}), 503
    try:
        return jsonify(xss_exploiter_ensure_wordlist())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/xss/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_xss_scan():
    if not _xss_exploiter_available:
        return jsonify({"error": "xss_exploiter module not available"}), 503
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    options = {
        "max_payloads": int(data.get("max_payloads", 30)),
        "max_params": int(data.get("max_params", 10)),
        "concurrency": int(data.get("concurrency", 8)),
        "rate_limit": float(data.get("rate_limit", 20.0)),
        "timeout": float(data.get("timeout", 8.0)),
        "waf_bypass": bool(data.get("waf_bypass", False)),
        "params": data.get("params"), "method": data.get("method", "GET"),
        "max_duration": data.get("max_duration"),
    }
    try:
        return jsonify(xss_exploiter_run(target, options))
    except Exception as e:
        logger.error(f"xss scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/xss/scan/stream")
@role_required("owner", "analyst")
def api_xss_scan_stream():
    if not _xss_exploiter_available:
        return jsonify({"error": "xss_exploiter module not available"}), 503
    target = (request.args.get("target") or request.args.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    cancel_event = threading.Event()
    options = {
        "max_payloads": int(request.args.get("max_payloads", 30)),
        "max_params": int(request.args.get("max_params", 10)),
        "concurrency": int(request.args.get("concurrency", 8)),
        "rate_limit": float(request.args.get("rate_limit", 20.0)),
        "timeout": float(request.args.get("timeout", 8.0)),
        "waf_bypass": request.args.get("waf_bypass", "0") == "1",
        "method": request.args.get("method", "GET"),
        "cancel_event": cancel_event,
    }
    def _gen():
        try:
            for event in xss_exploiter_stream(target, options, cancel_event=cancel_event):
                yield _sse_format(event)
        except GeneratorExit:
            cancel_event.set()
        except Exception as e:
            logger.error(f"xss stream failed: {e}", exc_info=True)
            yield _sse_format({"type": "error", "message": str(e)})
    return _sse_response(_gen())


# ═══════════════════════════════════════════════════════════════════════════
# Lightweight XSS
# ═══════════════════════════════════════════════════════════════════════════
def _xss_unavailable_response():
    return jsonify({
        "error": "xss module not available",
        "detail": _xss_import_err if not _xss_available else "",
    }), 503


@app.route("/api/xss_simple/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_xss_simple_scan():
    if not _xss_available:
        return _xss_unavailable_response()
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    mode = data.get("mode", "basic")
    if mode not in ("basic", "expert"):
        mode = "basic"
    kwargs = {
        "method": data.get("method", "GET"),
        "params": data.get("params"),
        "timeout": float(data.get("timeout", 6.0)),
        "max_threads": int(data.get("max_threads", 10)),
        "verify_ssl": bool(data.get("verify_ssl", False)),
        "mutate": bool(data.get("mutate", False)),
        "max_payloads": int(data.get("max_payloads", 400)),
    }
    try:
        return jsonify(xss_module.run(target, mode, **kwargs))
    except Exception as e:
        logger.error(f"xss module scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/xss/wordlists")
@api_login_required
def api_xss_wordlists():
    if not _xss_wordlist_available:
        return jsonify({"error": "xss wordlist helpers not available"}), 503
    try:
        return jsonify(xss_ensure_wordlists(force=False))
    except Exception as e:
        logger.error(f"xss wordlists status failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/xss/wordlists/sync", methods=["POST"])
@role_required("owner", "analyst")
def api_xss_wordlists_sync():
    if not _xss_wordlist_available:
        return jsonify({"error": "xss wordlist helpers not available"}), 503
    try:
        xss_load_wordlist(force_download=True, auto_sync=True)
        return jsonify(xss_ensure_wordlists(force=True))
    except Exception as e:
        logger.error(f"xss wordlists sync failed: {e}", exc_info=True)
        return jsonify({"error": "sync_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Sniper
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/sniper/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_sniper_scan():
    if not _sniper_available:
        return jsonify({"error": "sniper module not available"}), 503
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    options = {
        "module_timeout": float(data.get("module_timeout", 90.0)),
        "global_budget": float(data.get("global_budget", 150.0)),
        "dirfuzz_wordlist": data.get("dirfuzz_wordlist", "lottery-dirs.txt"),
        "dirfuzz_max_paths": int(data.get("dirfuzz_max_paths", 80)),
        "xss_max_payloads": int(data.get("xss_max_payloads", 20)),
        "takeover_enumerate": bool(data.get("takeover_enumerate", True)),
        "takeover_max_hosts": int(data.get("takeover_max_hosts", 120)),
    }
    try:
        return jsonify(sniper_run(target, options))
    except Exception as e:
        logger.error(f"sniper scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


@app.route("/api/sniper/scan/stream")
@role_required("owner", "analyst")
def api_sniper_scan_stream():
    if not _sniper_available:
        return jsonify({"error": "sniper module not available"}), 503
    target = (request.args.get("target") or request.args.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    options = {
        "module_timeout": float(request.args.get("module_timeout", 90.0)),
        "global_budget": float(request.args.get("global_budget", 150.0)),
        "dirfuzz_wordlist": request.args.get("dirfuzz_wordlist", "lottery-dirs.txt"),
        "dirfuzz_max_paths": int(request.args.get("dirfuzz_max_paths", 80)),
        "xss_max_payloads": int(request.args.get("xss_max_payloads", 20)),
        "takeover_enumerate": request.args.get("takeover_enumerate", "1") == "1",
        "takeover_max_hosts": int(request.args.get("takeover_max_hosts", 120)),
    }
    def _gen():
        try:
            for event in sniper_stream(target, options):
                yield _sse_format(event)
        except GeneratorExit:
            pass
        except Exception as e:
            logger.error(f"sniper stream failed: {e}", exc_info=True)
            yield _sse_format({"type": "error", "message": str(e)})
    return _sse_response(_gen())


# ═══════════════════════════════════════════════════════════════════════════
# Wordlist Scraper API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/wordlists/status")
@api_login_required
def api_wordlists_status():
    if not _wordlist_scraper_available:
        return jsonify({"error": "wordlist scraper not available"}), 503
    try:
        return jsonify(wordlist_list())
    except Exception as e:
        logger.error(f"wordlist status failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/wordlists/manifest")
@api_login_required
def api_wordlists_manifest():
    if not _wordlist_scraper_available:
        return jsonify({"error": "wordlist scraper not available"}), 503
    try:
        return jsonify(wordlist_manifest())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/wordlists/sync", methods=["POST"])
@role_required("owner", "analyst")
def api_wordlists_sync():
    if not _wordlist_scraper_available:
        return jsonify({"error": "wordlist scraper not available"}), 503
    data = request.get_json(silent=True) or {}
    modules = data.get("modules")
    if isinstance(modules, str):
        modules = [m.strip() for m in modules.split(",") if m.strip()]
    force = bool(data.get("force", False))
    workers = int(data.get("workers", 4))
    timeout = float(data.get("timeout", 25.0))
    try:
        return jsonify(wordlist_sync(modules, force=force, workers=workers, timeout=timeout))
    except Exception as e:
        logger.error(f"wordlist sync failed: {e}", exc_info=True)
        return jsonify({"error": "sync_failed", "detail": str(e)}), 500


@app.route("/api/wordlists/sync/stream")
@role_required("owner", "analyst")
def api_wordlists_sync_stream():
    if not _wordlist_scraper_available:
        return jsonify({"error": "wordlist scraper not available"}), 503
    mod_arg = request.args.get("modules", "").strip()
    modules = [m.strip() for m in mod_arg.split(",") if m.strip()] or None
    force = request.args.get("force", "0") == "1"
    workers = int(request.args.get("workers", 4))
    timeout = float(request.args.get("timeout", 25.0))
    cancel_event = threading.Event()
    def _gen():
        try:
            for ev in wordlist_sync_stream(
                modules, force=force, workers=workers, timeout=timeout,
                cancel_event=cancel_event,
            ):
                yield _sse_format(ev)
        except GeneratorExit:
            cancel_event.set()
        except Exception as e:
            logger.error(f"wordlist stream failed: {e}", exc_info=True)
            yield _sse_format({"type": "error", "message": str(e)})
    return _sse_response(_gen())


@app.route("/api/wordlists/reload", methods=["POST"])
@api_login_required
def api_wordlists_reload():
    if not _wordlist_scraper_available:
        return jsonify({"error": "wordlist scraper not available"}), 503
    try:
        return jsonify({"success": True, "reload": wordlist_reload_caches()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# 404 handler — cached compiled HTML
# ═══════════════════════════════════════════════════════════════════════════
_NOT_FOUND_HTML = """<!DOCTYPE html>
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
                radial-gradient(ellipse at 20% 20%, rgba(90,160,255,0.06) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 80%, rgba(90,160,255,0.06) 0%, transparent 50%),
                repeating-linear-gradient(45deg, rgba(90,160,255,0.03) 0px, rgba(90,160,255,0.03) 1px, transparent 1px, transparent 30px),
                repeating-linear-gradient(-45deg, rgba(90,160,255,0.03) 0px, rgba(90,160,255,0.03) 1px, transparent 1px, transparent 30px);
            color: #e6f0ff;
            font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            display: flex; flex-direction: column;
            justify-content: center; align-items: center;
            height: 100vh; position: relative; overflow: hidden;
        }
        body::before {
            content: ""; position: absolute; inset: 0;
            background: radial-gradient(ellipse at center, rgba(90,160,255,0.06) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite; pointer-events: none;
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
            display: flex; flex-direction: column; align-items: center;
            justify-content: center; flex: 1; animation: fadeIn 1.5s ease-out;
        }
        .username {
            font-size: 0.9rem; letter-spacing: 0.2em; color: #7aa7dd;
            text-transform: uppercase; margin-bottom: 10px;
        }
        .main-title {
            font-size: clamp(1.2rem, 3.5vw, 2.5rem); font-weight: 300;
            letter-spacing: 0.35em; text-align: center; text-transform: uppercase;
            color: #8fc0ff; text-shadow: 0 0 30px rgba(90,160,255,0.35);
        }
        .sad-face {
            display: flex; flex-direction: column; align-items: center;
            justify-content: center; gap: 0px; margin-top: 25px;
            font-size: clamp(1.5rem, 5vw, 3rem); color: #8fc0ff;
            text-shadow: 0 0 20px rgba(90,160,255,0.4);
            animation: slightFloat 3s ease-in-out infinite; line-height: 0.45;
        }
        .sleep-colon, .sleep-mouth {
            display: inline-block; transform: rotate(90deg);
            transform-origin: center; animation: breathe 2.5s ease-in-out infinite;
        }
        .sleep-mouth { margin-top: -0.1em; }
        @keyframes breathe {
            0%, 100% { transform: rotate(90deg) scale(1); }
            50% { transform: rotate(90deg) scale(0.9); }
        }
        @keyframes slightFloat {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-5px); }
        }
        .bottom-bar {
            position: absolute; bottom: 20px; left: 0; right: 0;
            text-align: center; padding: 15px; animation: fadeIn 2s ease-out;
        }
        .url-not-found {
            font-size: 0.8rem; letter-spacing: 0.25em;
            color: #6a8cba; text-transform: uppercase;
        }
        .url-address {
            font-size: 0.7rem; letter-spacing: 0.1em; color: #8fb2dd;
            margin-top: 8px; word-break: break-all;
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


@app.errorhandler(404)
def page_not_found(e):
    username = session.get("username") if session.get("authenticated") else "Guest"
    return _NOT_FOUND_HTML.replace("__USERNAME__", username), 404


# ═══════════════════════════════════════════════════════════════════════════
# Additional endpoints
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/api/settings/server-name', methods=['GET', 'POST'])
@login_required
def server_name():
    if request.method == 'GET':
        settings = _load_json('settings', {})
        return jsonify({'name': settings.get('server_name', '')})
    u = current_user()
    if u and u.get('role') != 'owner':
        return jsonify({'error': 'Owner access required'}), 403
    body = request.get_json(silent=True) or {}
    with _json_lock('settings'):
        settings = _load_json('settings', {})
        settings['server_name'] = (body.get('name') or '').strip()
        _save_json('settings', settings)
    logger.info(f'Server name set to "{settings["server_name"]}" by "{session.get("username")}"')
    return jsonify({'name': settings['server_name']})


@app.route('/api/settings/servers')
@owner_required
def panel_manager():
    return jsonify(_load_json('servers', []))


ALLOWED_IMAGE_TYPES = {'image/png', 'image/jpeg', 'image/gif', 'image/webp'}


@app.route('/api/profile/photo', methods=['POST'])
@login_required
def profile_photo():
    u = current_user()
    if not u:
        return jsonify({'error': 'Not authenticated'}), 401
    body = request.get_json(silent=True) or {}
    with _json_lock('profiles'):
        profiles = _load_json('profiles', {})
        profile = profiles.setdefault(u['username'], {})
        if body.get('remove'):
            profile['avatar_url'] = None
            _save_json('profiles', profiles)
            return jsonify({'ok': True, 'avatar_url': None})
        if body.get('url'):
            url = body['url'].strip()
            if not (url.startswith('http://') or url.startswith('https://')):
                return jsonify({'error': 'Please provide a valid http(s) image URL.'}), 400
            profile['avatar_url'] = url
            _save_json('profiles', profiles)
            return jsonify({'ok': True, 'avatar_url': url})
        if body.get('image_base64'):
            data_url = body['image_base64']
            try:
                header, encoded = data_url.split(',', 1)
                mime = header.split(';')[0].replace('data:', '')
                if mime not in ALLOWED_IMAGE_TYPES:
                    return jsonify({'error': 'Unsupported image type.'}), 400
                raw = base64.b64decode(encoded)
                if len(raw) > 5 * 1024 * 1024:
                    return jsonify({'error': 'Image is too large (max 5MB).'}), 400
                ext = mime.split('/')[1]
                filename = f'{u["username"]}_{uuid.uuid4().hex[:8]}.{ext}'
                with open(os.path.join(UPLOAD_DIR, filename), 'wb') as f:
                    f.write(raw)
                profile['avatar_url'] = f'/api/profile/photo/{filename}'
                _save_json('profiles', profiles)
                return jsonify({'ok': True, 'avatar_url': profile['avatar_url']})
            except (ValueError, binascii.Error):
                return jsonify({'error': 'Could not decode that image.'}), 400
    return jsonify({'error': 'Provide image_base64, url, or remove:true.'}), 400


@app.route('/api/profile/photo/<path:filename>')
def serve_profile_photo(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# ═══════════════════════════════════════════════════════════════════════════
# Global Chat
# ═══════════════════════════════════════════════════════════════════════════
CHAT_HISTORY_LIMIT = 300
_chat_cache = {'data': None, 'mtime': 0.0}
_chat_cache_lock = threading.Lock()


def _get_chat_cached():
    path = os.path.join(DATA_DIR, 'chat.json')
    try:
        mtime_before = os.path.getmtime(path)
    except OSError:
        return {'messages': [], 'locked': False}
    with _chat_cache_lock:
        if _chat_cache['data'] is not None and _chat_cache['mtime'] == mtime_before:
            return _chat_cache['data']
    data = _load_json('chat', {'messages': [], 'locked': False})
    try:
        mtime_after = os.path.getmtime(path)
    except OSError:
        mtime_after = mtime_before
    with _chat_cache_lock:
        _chat_cache['data'] = data
        _chat_cache['mtime'] = mtime_after
    return data


@app.route('/api/chat/messages')
@login_required
def chat_messages():
    chat = _get_chat_cached()
    profiles = _load_json('profiles', {})
    users_by_name = {u['username']: u for u in _load_json('users', [])}
    enriched = []
    for m in chat.get('messages', []):
        u = users_by_name.get(m.get('username'))
        enriched.append({
            **m,
            'role': u.get('role') if u else m.get('role', '--'),
            'avatar_url': profiles.get(m.get('username'), {}).get('avatar_url'),
        })
    return jsonify({'messages': enriched, 'locked': chat.get('locked', False)})


@app.route('/api/chat/send', methods=['POST'])
@login_required
def chat_send():
    u = current_user()
    if not u:
        return jsonify({'error': 'Not authenticated'}), 401
    body = request.get_json(silent=True) or {}
    text = (body.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'Message text is required.'}), 400
    text = text[:500]
    with _json_lock('chat'):
        chat = _load_json('chat', {'messages': [], 'locked': False})
        if chat.get('locked') and u.get('role') != 'owner':
            return jsonify({'error': 'Chat is locked by the Owner.'}), 423
        message = {
            'id': uuid.uuid4().hex, 'username': u['username'],
            'role': u['role'], 'text': text, 'timestamp': _now_iso(),
        }
        chat['messages'].append(message)
        chat['messages'] = chat['messages'][-CHAT_HISTORY_LIMIT:]
        _save_json('chat', chat)
    return jsonify({'ok': True, 'id': message['id']})


@app.route('/api/chat/lock', methods=['POST'])
@owner_required
def chat_lock():
    body = request.get_json(silent=True) or {}
    with _json_lock('chat'):
        chat = _load_json('chat', {'messages': [], 'locked': False})
        chat['locked'] = bool(body.get('locked'))
        chat['messages'].append({
            'id': uuid.uuid4().hex, 'is_system': True,
            'text': f'{session.get("username")} {"locked" if chat["locked"] else "unlocked"} Global Chat.',
            'timestamp': _now_iso(),
        })
        _save_json('chat', chat)
    return jsonify({'ok': True, 'locked': chat['locked']})


# ═══════════════════════════════════════════════════════════════════════════
# OSINT module contract
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/api/osint/search', methods=['POST'])
@login_required
def osint_search():
    body = request.get_json(silent=True) or {}
    method = body.get('method')
    query = (body.get('query') or '').strip()
    if method not in ('username', 'email', 'number') or not query:
        return jsonify({'error': 'method and query are required.'}), 400
    try:
        osint_module = import_module('modules.osint')
    except ModuleNotFoundError:
        return jsonify({'error': 'modules/osint.py not found on the server yet.'}), 404
    try:
        results = osint_module.search(method, query)
    except Exception as e:
        logger.error(f'modules.osint.search raised: {e}')
        return jsonify({'error': f'OSINT module error: {e}'}), 500
    logger.info(f'OSINT search ({method}) by "{session.get("username")}": {query}')
    return jsonify({'sources': results})


# ═══════════════════════════════════════════════════════════════════════════
# External API v1
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/api/v1/ping', methods=['POST'])
@_api_key_required
def v1_ping():
    return jsonify({'ok': True, 'server_time': _now_iso(), 'owner': g.api_key_owner})


@app.route('/api/v1/scan', methods=['POST'])
@_api_key_required
def v1_scan_start():
    body = request.get_json(silent=True) or {}
    target = (body.get('target') or '').strip()
    mode = body.get('mode') or 'basic'
    tools = body.get('tools') or []
    if not target:
        return jsonify({'error': 'A target is required.'}), 400
    return jsonify({'job_id': scan_orchestrator.start_scan(target, mode, tools, history_store)})


@app.route('/api/v1/scan/<job_id>')
@_api_key_required
def v1_scan_status(job_id):
    progress = scan_orchestrator.get_progress(job_id)
    if progress is None:
        return jsonify({'error': 'not_found'}), 404
    return jsonify(progress)


@app.route('/api/v1/apikey/scan', methods=['POST'])
@_api_key_required
def v1_apikey_scan():
    if not _apikey_available:
        return jsonify({'error': 'apikey module not available'}), 503
    body = request.get_json(silent=True) or {}
    target = (body.get('target') or body.get('url') or '').strip()
    if not target:
        return jsonify({'error': 'target_required'}), 400
    mode = body.get('mode', 'basic')
    if mode not in ('basic', 'expert'):
        mode = 'basic'
    try:
        scanner = apikey_scanner_cls(
            mode=mode,
            entropy_threshold=float(body.get('entropy_threshold', 4.5)),
            deduplicate=True,
            use_proxy=not bool(body.get('no_proxy', False)),
            max_proxy_attempts=int(body.get('max_proxy_attempts', 4)),
            use_cloudflare_bypass=not bool(body.get('no_cf_bypass', False)),
        )
        return jsonify(scanner.run(target))
    except Exception as e:
        logger.error(f"v1 apikey scan failed: {e}", exc_info=True)
        return jsonify({'error': 'scan_failed', 'detail': str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Module status
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/modules/status")
@api_login_required
def api_modules_status():
    apikey_status = {"available": _apikey_available}
    if _apikey_available:
        apikey_status.update({
            "version":      apikey_version,
            "curl_cffi":    apikey_has_curl_cffi,
            "cloudscraper": apikey_has_cloudscraper,
            "flaresolverr": bool(apikey_flaresolverr_url),
            "cf_bypass":    True,
        })

    xss_status = {"available": _xss_available}
    if _xss_available:
        xss_status["version"] = XSS_TOOL_INFO.get("version", "?")
        if _xss_wordlist_available:
            try:
                xss_status["wordlists"] = xss_ensure_wordlists(force=False)
            except Exception as e:
                xss_status["wordlists_error"] = str(e)

    sqlmap_status = {"available": _sql_map_available}
    if _sql_map_available:
        sqlmap_status["version"] = SQLMAP_TOOL_INFO.get("version", "?")
        if _sqlmap_wordlist_available:
            try:
                sqlmap_status["wordlists"] = sqlmap_ensure_wordlists(force=False)
            except Exception as e:
                sqlmap_status["wordlists_error"] = str(e)

    ssl_status = {"available": _ssl_available}
    if _ssl_available:
        ssl_status["version"] = SSL_TOOL_INFO.get("version", "?")

    ipinfo_status = {"available": _ipinfo_available}
    if _ipinfo_available:
        ipinfo_status["version"] = IPINFO_TOOL_INFO.get("version", "?")

    techfp_status = {"available": _techfp_available}
    if _techfp_available:
        techfp_status["version"] = TECHFP_TOOL_INFO.get("version", "?")

    headers_status = {"available": _headers_available}
    if _headers_available:
        headers_status.update({
            "version":      HEADERS_TOOL_INFO.get("version", "?"),
            "curl_cffi":    headers_has_curl_cffi,
            "cloudscraper": headers_has_cloudscraper,
        })

    lfi_rfi_status = {"available": _lfi_rfi_available}
    if _lfi_rfi_available:
        lfi_rfi_status.update({
            "version":   LFI_RFI_TOOL_INFO.get("version", "?"),
            "name":      LFI_RFI_TOOL_INFO.get("name", "LFI / RFI Scanner"),
            "category":  LFI_RFI_TOOL_INFO.get("category", "Web Security"),
            "intrusive": True,
        })

    portscan_status = {"available": _port_scan_available}
    if _port_scan_available:
        portscan_status["version"] = PORT_SCAN_INFO.get("version", "?")
        portscan_status["patched"] = _fixes_available

    fixes_status = {"available": _fixes_available}
    if _fixes_available:
        try:
            fixes_status.update(_opencode_fixes.check())
        except Exception as e:
            fixes_status["error"] = str(e)

    return jsonify({
        "dirfuzz":          {"available": _dirfuzz_available},
        "sqli_engine":      {"available": _sqli_engine_available,
                             "sources": list(SQLI_WORDLIST_SOURCES.keys()) if _sqli_engine_available else []},
        "sql_map":          sqlmap_status,
        "sql_injection":    {"available": _sql_injection_available},
        "xss_exploiter":    {"available": _xss_exploiter_available},
        "xss":              xss_status,
        "sniper":           {"available": _sniper_available},
        "wordlist_scraper": {"available": _wordlist_scraper_available},
        "analytic":         {"available": _analytic_available},
        "downsea":          {"available": _downsea_available},
        "apikey":           apikey_status,
        "ssl":              ssl_status,
        "ipinfo":           ipinfo_status,
        "techfp":           techfp_status,
        "headers":          headers_status,
        "lfi_rfi":          lfi_rfi_status,
        "port_scan":        portscan_status,
        "fixes":            fixes_status,
    })


# ═══════════════════════════════════════════════════════════════════════════
# Startup helpers
# ═══════════════════════════════════════════════════════════════════════════
def _discover_wordlists_summary() -> str:
    bits = []
    if _xss_available and _xss_wordlist_available:
        try:
            st = xss_ensure_wordlists(force=False)
            files = st.get("files", []) if isinstance(st, dict) else []
            ok = sum(1 for f in files if f.get("exists") and f.get("payloads"))
            total = sum(int(f.get("payloads", 0)) for f in files)
            bits.append(f"XSS {ok}/{len(files)} ({total}p)")
        except Exception:
            bits.append("XSS n/a")
    if _sql_map_available and _sqlmap_wordlist_available:
        try:
            st = sqlmap_ensure_wordlists(force=False)
            files = st.get("files", []) if isinstance(st, dict) else []
            ok = sum(1 for f in files if f.get("exists") and f.get("payloads"))
            total = sum(int(f.get("payloads", 0)) for f in files)
            bits.append(f"SQLMap {ok}/{len(files)} ({total}p)")
        except Exception:
            bits.append("SQLMap n/a")
    return " · ".join(bits)


def _loaded_modules_list() -> str:
    mods = []
    if _dirfuzz_available:          mods.append("dirfuzz")
    if _sqli_engine_available:      mods.append("sqli_engine")
    if _sql_map_available:          mods.append("sql_map")
    if _sql_injection_available:    mods.append("sql_injection")
    if _xss_exploiter_available:    mods.append("xss_exploiter")
    if _xss_available:              mods.append("xss")
    if _sniper_available:           mods.append("sniper")
    if _wordlist_scraper_available: mods.append("wordlist_scraper")
    if _analytic_available:         mods.append("analytic")
    if _downsea_available:          mods.append("downsea")
    if _apikey_available:           mods.append("apikey")
    if _ssl_available:              mods.append("ssl")
    if _ipinfo_available:           mods.append("ipinfo")
    if _techfp_available:           mods.append("techfp")
    if _headers_available:          mods.append("headers")
    if _port_scan_available:        mods.append("port_scan")
    if _lfi_rfi_available:          mods.append("lfi_rfi")
    return ", ".join(mods) if mods else "(none)"


def _cf_bypass_summary() -> str:
    if not _apikey_available:
        return "unavailable"
    parts = []
    if apikey_has_curl_cffi:    parts.append("curl_cffi")
    if apikey_has_cloudscraper: parts.append("cloudscraper")
    if apikey_flaresolverr_url: parts.append("flaresolverr")
    parts.append("manual")
    return "+".join(parts)


def _print_header(port: Optional[int] = None) -> None:
    _print_banner(BANNER, color=_Ansi.BLUE)
    if _USE_COLOR:
        rule = "─" * 74
        sys.stdout.write(f"  {_c(rule, _Ansi.BLUE_DEEP)}\n\n")
    else:
        sys.stdout.write("  " + "─" * 74 + "\n\n")
    sys.stdout.flush()


def _print_ready(port: int) -> None:
    if _USE_COLOR:
        arrow = _c("▸", _Ansi.BLUE_HI)
        label = _c("Server ready", _Ansi.BOLD + _Ansi.WHITE)
        url = _c(f"http://localhost:{port}", _Ansi.BLUE_HI)
        sys.stdout.write(f"  {arrow} {label}  {url}\n\n")
    else:
        sys.stdout.write(f"  > Server ready  http://localhost:{port}\n\n")
    sys.stdout.flush()


def _boot_screen(bootstrap_result: Optional[dict] = None) -> None:
    """
    Claude-Code-style animated boot sequence in bright blue.

    v4.4.1 — Accepts the bootstrap_once() outcome so that
    ensure_default_user() and auto_restart_bot() are never called twice.
    """
    bootstrap_result = bootstrap_result or {}

    # 1) Scan orchestrator discovery
    def _list_tools():
        return scan_orchestrator.list_tools() or {}

    _run_with_spinner(
        "Discovering scan modules",
        _list_tools,
        success_detail=lambda t: f"{len(t)} tool(s) registered",
        error_detail=lambda e: f"orchestrator error: {e}",
    )

    # 2) Port-scan patch status
    def _check_fixes():
        if not _fixes_available:
            raise RuntimeError("patch module not loaded")
        return _opencode_fixes.check()

    _run_with_spinner(
        "Applying port-scan hardening",
        _check_fixes,
        success_detail=lambda info: (
            f"patched={info.get('patched', False)} · "
            f"v{info.get('port_scan_version', '?')}"
        ),
        error_detail=lambda e: "no patch applied (optional)",
    )

    # 3) Default-user verification — read from bootstrap outcome only
    first_run = bool(bootstrap_result.get("first_run"))
    pwd = bootstrap_result.get("created_password")
    if first_run:
        _print_step(
            "Verifying default account",
            ok=True,
            detail="first run — new password issued",
        )
    else:
        _print_step(
            "Verifying default account",
            ok=True,
            detail=f"username: {DEFAULT_USERNAME}",
        )

    if pwd:
        sys.stdout.write("\n")
        sys.stdout.write(
            f"  {_c('*', _Ansi.YELLOW)} "
            f"{_c('First run detected — save this password now:', _Ansi.YELLOW)}\n"
        )
        sys.stdout.write(f"      username: {_c(DEFAULT_USERNAME, _Ansi.WHITE)}\n")
        sys.stdout.write(f"      password: {_c(pwd, _Ansi.YELLOW + _Ansi.BOLD)}\n\n")
        sys.stdout.flush()

    # 4) Telegram bot — read from bootstrap outcome only
    bot_ok = bool(bootstrap_result.get("bot_restarted"))
    if bot_ok:
        _print_step(
            "Starting Telegram bot",
            ok=True,
            detail="auto-restart invoked",
        )
    else:
        _print_step(
            "Starting Telegram bot",
            ok=False,
            detail="skipped (no bot configured or failed)",
        )

    # 5) Static summary lines
    wl_summary = _discover_wordlists_summary()
    if wl_summary:
        _print_step("Wordlists loaded", ok=True, detail=wl_summary)

    _print_step("Loaded modules", ok=True, detail=_loaded_modules_list())
    _print_step("Cloudflare bypass", ok=True, detail=_cf_bypass_summary())

    sys.stdout.write("\n")
    sys.stdout.flush()


# ═══════════════════════════════════════════════════════════════════════════
# Bootstrap
# ═══════════════════════════════════════════════════════════════════════════
def bootstrap(verbose: bool = True) -> dict:
    """
    Run first-run setup tasks once.
    Inner functions own the INFO records; this wrapper logs at DEBUG.
    """
    outcome = {
        "default_username": DEFAULT_USERNAME,
        "first_run":        False,
        "created_password": None,
        "bot_restarted":    False,
        "errors":           [],
    }

    try:
        new_password = ensure_default_user()
        if new_password:
            outcome["first_run"] = True
            outcome["created_password"] = new_password
        logger.debug(
            "bootstrap: default user check complete (username=%s, first_run=%s)",
            DEFAULT_USERNAME, outcome["first_run"],
        )
    except Exception as exc:
        outcome["errors"].append(f"ensure_default_user: {exc}")
        logger.error("bootstrap: ensure_default_user failed: %s", exc, exc_info=True)

    try:
        auto_restart_bot()
        outcome["bot_restarted"] = True
        logger.debug("bootstrap: telegram bot auto-restart invoked")
    except Exception as exc:
        outcome["errors"].append(f"auto_restart_bot: {exc}")
        logger.error("bootstrap: auto_restart_bot failed: %s", exc, exc_info=True)

    return outcome


_bootstrap_lock = threading.Lock()
_bootstrap_done = False
_bootstrap_result = None


def bootstrap_once(verbose: bool = True) -> dict:
    """Thread-safe, run-once wrapper around bootstrap()."""
    global _bootstrap_done, _bootstrap_result
    with _bootstrap_lock:
        if _bootstrap_done and _bootstrap_result is not None:
            return _bootstrap_result
        _bootstrap_result = bootstrap(verbose=verbose)
        _bootstrap_done = True
        return _bootstrap_result


# ═══════════════════════════════════════════════════════════════════════════
# Entrypoint
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # ── CLI: password reset ────────────────────────────────────────────
    if len(sys.argv) > 1 and sys.argv[1] == "reset-password":
        existing_role = get_role(DEFAULT_USERNAME) or "owner"
        new_password = create_user(DEFAULT_USERNAME, role=existing_role)
        _print_banner(BANNER, color=_Ansi.BLUE)
        print(f"  Password reset for '{DEFAULT_USERNAME}' (role={existing_role})")
        print(f"  Password: {new_password}")
        print("  Copy it now — it will not be shown again.")
        sys.exit(0)

    # ── Port resolution ────────────────────────────────────────────────
    # Default port is now 8080 (was 3052).
    DEFAULT_PORT = 8080

    env_port = os.getenv("PORT")
    if env_port:
        try:
            port = int(env_port)
        except ValueError:
            print(_c(f"  ! Invalid PORT env value: {env_port!r} — using 8080",
                     _Ansi.YELLOW))
            port = DEFAULT_PORT
    else:
        default_port = DEFAULT_PORT
        if hasattr(Config, "PORT"):
            try:
                cfg_port = int(Config.PORT)
                if 1 <= cfg_port <= 65535:
                    default_port = cfg_port
            except (TypeError, ValueError):
                pass

        _print_header()

        # Non-interactive stdin (pipe, docker run without -it, CI) — skip
        # the prompt and use the default port instead of crashing.
        if not sys.stdin.isatty():
            port = default_port
            sys.stdout.write(
                f"  {_c('!', _Ansi.YELLOW)} "
                f"{_c('No TTY detected — using default port', _Ansi.YELLOW)} "
                f"{_c(str(default_port), _Ansi.WHITE)}\n"
            )
            sys.stdout.flush()
        else:
            while True:
                try:
                    prompt = (
                        f"  {_c('?', _Ansi.BLUE_HI)} "
                        f"{_c(f'Enter port (default {default_port}):', _Ansi.GRAY)} "
                    )
                    port_input = input(prompt).strip()
                except KeyboardInterrupt:
                    # Ctrl+C at the port prompt — exit cleanly with the
                    # standard SIGINT exit code (130).
                    sys.stdout.write("\n")
                    sys.stdout.write(
                        f"  {_c('⊘', _Ansi.YELLOW)} "
                        f"{_c('Cancelled by user', _Ansi.YELLOW)}\n"
                    )
                    sys.stdout.flush()
                    sys.exit(130)
                except EOFError:
                    # stdin closed mid-prompt — fall back to the default.
                    sys.stdout.write("\n")
                    sys.stdout.write(
                        f"  {_c('!', _Ansi.YELLOW)} "
                        f"{_c('EOF on stdin — using default port', _Ansi.YELLOW)} "
                        f"{_c(str(default_port), _Ansi.WHITE)}\n"
                    )
                    sys.stdout.flush()
                    port = default_port
                    break

                if port_input == "":
                    port = default_port
                    break
                try:
                    port = int(port_input)
                except ValueError:
                    print(_c("  Invalid input. Enter a valid port number.",
                             _Ansi.RED))
                    continue
                if port < 1 or port > 65535:
                    print(_c("  Port must be between 1 and 65535.", _Ansi.RED))
                    continue
                break

        print()

    # ── Print banner + run animated boot sequence ──────────────────────
    _print_header(port=None)
    result = bootstrap_once(verbose=False)
    _boot_screen(bootstrap_result=result)
    _print_ready(port)

    # ── Launch ─────────────────────────────────────────────────────────
    try:
        app.run(host="0.0.0.0", port=port, debug=True, threaded=True)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.write(
            f"  {_c('⊘', _Ansi.YELLOW)} "
            f"{_c('Server stopped by user', _Ansi.YELLOW + _Ansi.BOLD)}\n"
        )
        sys.stdout.flush()
        sys.exit(0)