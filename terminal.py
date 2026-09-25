#!/usr/bin/env python3
"""
Emergens — Terminal Launcher (v5.0.0)

Interactive boot + menu launcher for the Oxysintx Flask stack.
Blue-themed UI.

Changelog v5.0.0
────────────────
  • NEW: "Scan All" mode — drives /api/scan/start (ScanOrchestrator),
    runs every registered scanner in one background job, polls
    /api/scan/<job_id>/status, and renders a per-module results table.
  • NEW: live progress bar with spinner + ETA estimate.
  • NEW: per-module result grid (module · status · findings · time).
  • Preserved: single-scanner flows (Port/SSL/Headers/.../Sniper),
    Tools, MHDDoS, Exploit, Downloader, Webhost, Server.
  • Boot display: banner restored, #credit bottom-left, bullet+spinner.

#credit ~ Yanxzyx
"""

import os
import sys
import time
import json
import shutil
import socket
import threading
import platform
from pathlib import Path
from datetime import datetime

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    requests = None
    _HAS_REQUESTS = False


# ═══════════════════════════════════════════════════════════════════════════
# COLORS
# ═══════════════════════════════════════════════════════════════════════════
class C:
    RESET      = "\033[0m"
    BOLD       = "\033[1m"
    DIM        = "\033[2m"

    BLUE       = "\033[38;5;39m"
    BLUE_DARK  = "\033[38;5;27m"
    BLUE_LIGHT = "\033[38;5;75m"
    BLUE_SOFT  = "\033[38;5;111m"
    BLUE_NAVY  = "\033[38;5;25m"
    CYAN       = "\033[38;5;51m"

    WHITE      = "\033[38;5;255m"
    GREY       = "\033[38;5;245m"
    GREY_DARK  = "\033[38;5;240m"

    GREEN      = "\033[38;5;46m"
    YELLOW     = "\033[38;5;220m"
    RED        = "\033[38;5;203m"
    MAGENTA    = "\033[38;5;171m"
    ORANGE     = "\033[38;5;214m"


VERSION             = "5.0.0"
AUTO_LOGIN_CODE     = "ZYXN"
AUTO_LOGIN_USERNAME = "Yanxzyx"
AUTO_LOGIN_ROLE     = "owner"
AUTO_LOGIN_ENDPOINT = "/api/adb_login"

_server_thread = None
_server_app    = None
_server_port   = None

_CLR_EOL = "\033[K"
FRAMES   = ["◐", "◓", "◑", "◒"]


def supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if platform.system() == "Windows":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            return False
    return True


_USE_COLOR = supports_color()


def c(text, color="", bold=False, dim=False):
    if not _USE_COLOR:
        return text
    prefix = ""
    if bold:
        prefix += C.BOLD
    if dim:
        prefix += C.DIM
    return f"{prefix}{color}{text}{C.RESET}"


def term_width(default=100):
    try:
        return min(shutil.get_terminal_size((default, 24)).columns, 160)
    except Exception:
        return default


def clear_screen():
    if _USE_COLOR:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def _clr_line():
    return "\r" + (_CLR_EOL if _USE_COLOR else " " * 160 + "\r")


def visible_len(s):
    import re
    return len(re.sub(r"\033\[[0-9;]*[A-Za-z]", "", s))


def prompt(text):
    try:
        return input("  " + c("▸", C.BLUE, bold=True) + " " + text).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def pause(msg="Press ENTER to continue…"):
    try:
        input("  " + c(msg, C.GREY, dim=True))
    except (EOFError, KeyboardInterrupt):
        print()


# ═══════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════
BANNER_LINES = [
    r"▐▓▄                         ▐▓▄           ▄ ▄▄▄░▒▄              ▐▓▄                                   ",
    r" ▒ ▄▄▀▀▀▒▓▄   ■▄█▄▓ ▄█▀▒▓▄   ▒ ▄▄▀▀▀▒▓▄  ▓▒▀▓ ▀  ▓▌  ■▄█▄▓▀▀▒▓▄  ▒ ▄▄▀▀▀▒▓▄   ■▄█▄▓▀▀▒▓▄    ▀▄▄▀▀▀▒▓▄ ",
    r"▐░▄▀         ▄░▄▀░▀██   ░▒▌ ▐░▄▀         ▐░▓    ▄▒▀ ▄░▄▀░       ▐░▄▀         ▄░▄▀░    ░▒▌ ▄░▄▀        ",
    r" ░ ▄▀▀░▓      ░    ▓▌  ▄▐█░  ░ ▄▀▀░▓       ▌ ▄█▀▄▄    ░           ░ ▄▀▀░▓      ░      ▄▐█░  ▀▀▄▀▄░▓▓▄▄ ",
    r"▐█           ▐█    ░   ▄▀▄▌ ▐█            ░   ▓█    ▐█  ▀▀▀▀█▓▀ ▐█           ▐█      ▄▀▄▌ ▄▄      ▀░░▌",
    r"██▄      ▄▄▌ ▐█▌       ▄█░▀ ██▄      ▄▄▌ ▐▒    ▒▌   ▐█▌     ▓▒░ ██▄      ▄▄▌ ▐█▌     ▄█░▀ ▄█▄     ▄█░▌",
    r"▀█  ▄▄▄▒▓▀    ▀░      ▐▓▀   ▀█  ▄▄▄▒▓▀   ▀▓▀  ▀▓▀    ▀██▄▄▄▒▓▀▒ ▀█  ▄▄▄▒▓▀    ▀░    ▐▓▀   ▀██▀▀▄▄▒▓▀  ",
]


def _gradient_color(idx):
    palette = [C.BLUE_LIGHT, C.BLUE, C.BLUE, C.BLUE_DARK,
               C.BLUE_NAVY, C.BLUE_NAVY, C.BLUE_NAVY]
    return palette[idx % len(palette)]


def print_banner():
    tw = term_width()
    banner_width = max(len(line) for line in BANNER_LINES) + 2
    print()
    if tw >= banner_width + 4:
        for i, line in enumerate(BANNER_LINES):
            print("  " + c(line.rstrip(), _gradient_color(i), bold=True))
    else:
        for line in [
            "  ╔═╗╔╦╗╔═╗╦═╗╔═╗╔═╗╔╗╔╔═╗",
            "  ║╣ ║║║║╣ ╠╦╝║ ╦║╣ ║║║╚═╗",
            "  ╚═╝╩ ╩╚═╝╩╚═╚═╝╚═╝╝╚╝╚═╝",
        ]:
            print("  " + c(line, C.BLUE_LIGHT, bold=True))
    print()
    print("  " + c("#credit ~ Yanxzyx", C.BLUE_SOFT, dim=True))
    print()


def print_banner_mini():
    print()
    print("  " + c(f"● Emergens v{VERSION}", C.BLUE_LIGHT, bold=True)
          + c("   ·   ", C.GREY_DARK, dim=True)
          + c("#credit ~ Yanxzyx", C.BLUE_SOFT, dim=True))
    print()


# ═══════════════════════════════════════════════════════════════════════════
# BOX / SECTION HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def _section(title, width=72):
    inner = f"── {title} "
    remain = max(0, width - len(inner))
    print()
    print("  " + c(inner, C.BLUE, bold=True) + c("─" * remain, C.BLUE_DARK))


def draw_box(title, rows, width=72):
    tl, tr, bl, br = "╭", "╮", "╰", "╯"
    h, v = "─", "│"
    inner_w = width - 2
    title_txt = f" {title} "
    title_len = len(title_txt)
    left_pad = 2
    right_pad = max(1, inner_w - title_len - left_pad)
    print("  " + c(tl, C.BLUE_DARK) + c(h * left_pad, C.BLUE_DARK)
          + c(title_txt, C.BLUE, bold=True)
          + c(h * right_pad, C.BLUE_DARK) + c(tr, C.BLUE_DARK))
    for label, value, value_color in rows:
        label_txt = str(label); value_txt = str(value)
        visible = 1 + 16 + 1 + len(value_txt)
        pad = max(0, inner_w - visible - 1)
        print("  " + c(v, C.BLUE_DARK) + " "
              + c(label_txt.ljust(16), C.BLUE_SOFT) + " "
              + c(value_txt, value_color) + " " * pad + c(v, C.BLUE_DARK))
    print("  " + c(bl, C.BLUE_DARK) + c(h * inner_w, C.BLUE_DARK)
          + c(br, C.BLUE_DARK))


# ═══════════════════════════════════════════════════════════════════════════
# MODULE PROBES
# ═══════════════════════════════════════════════════════════════════════════
MODULE_PROBES = [
    ("apikey",            "modules.scan_apikey",           "__version__",
     "scan_apikey",           "API key extractor · CF bypass"),
    ("xss",               "modules.xss",                    "TOOL_INFO",
     "scan_xss",              "Wordlist XSS scanner"),
    ("sql_map",           "modules.sql_map",                "TOOL_INFO",
     "sql_map",               "Nation-grade SQLi scanner"),
    ("ssl",               "modules.scan_ssl",               "TOOL_INFO",
     "scan_ssl",              "Full chain cert inspector"),
    ("ipinfo",            "modules.scan_ip_info",           "TOOL_INFO",
     "scan_ip_info",          "Dual-mode IP intelligence"),
    ("techfp",            "modules.scan_tech_fingerprint",  "TOOL_INFO",
     "scan_tech_fingerprint", "DNS + favicon fingerprint"),
    ("headers",           "modules.scan_headers",           "TOOL_INFO",
     "scan_headers",          "Advanced header analyzer"),
    ("port_scan",         "modules.port_scan",              "TOOL_INFO",
     "port_scan",             "Wordlist port scanner"),
    ("fixes",             "modules.fixes",                  None,
     "runtime_patches",       "port_scan runtime patch"),
    ("dirfuzz",           "modules.dirfuzz",                "__version__",
     "dirfuzz",               "Directory & file fuzzer"),
    ("sqli_engine",       "modules.sqli_engine",            "__version__",
     "sqli_engine",           "SQLi engine · 4 techniques"),
    ("sql_injection",     "modules.sql_injection",          "__version__",
     "sql_injection",         "Lightweight SQLi probe"),
    ("xss_exploiter",     "modules.xss_exploiter",          "__version__",
     "xss_exploiter",         "Professional XSS exploiter"),
    ("sniper",            "modules.sniper",                 "__version__",
     "sniper",                "Auto-Exploiter orchestrator"),
    ("wordlist_scraper",  "modules.git_scraper_wordlist",   "__version__",
     "wordlist_scraper",      "Git wordlist auto-sync"),
    ("downsea",           "modules.downsea",                None,
     "downsea",               "Pinterest / TikTok downloader"),
    ("analytic",          "modules.analytic_manager",       None,
     "analytic_manager",      "Exploit data + bruteforce"),
    ("quick_menu",        "modules.quick_menu",             "VERSION",
     "quick_menu",            "Quick menu Flask blueprint"),
    ("telegram",          "modules.telegram",               None,
     "telegram",              "Telegram bot bridge"),
    ("subdomain_takeover","modules.subdomain_takeover",     "__version__",
     "subdomain_takeover",    "Multi-signal takeover"),
    ("whois_lookup",      "modules.whois_lookup",           "TOOL_INFO",
     "whois_lookup",          "Domain registration data"),
    ("dns_lookup",        "modules.dns_lookup",             "TOOL_INFO",
     "dns_lookup",            "DNS record resolver"),
    ("ssl_check",         "modules.ssl_check",              "TOOL_INFO",
     "ssl_check",             "SSL/TLS certificate probe"),
    ("headers_check",     "modules.headers_check",          "TOOL_INFO",
     "headers_check",         "HTTP security headers"),
    ("ip_info",           "modules.ip_info",                "TOOL_INFO",
     "ip_info",               "IP & ASN intelligence"),
    ("connectivity_check","modules.connectivity_check",     "TOOL_INFO",
     "connectivity_check",    "TCP RTT reachability"),
    ("email_security",    "modules.email_security",         "TOOL_INFO",
     "email_security",        "SPF / DKIM / DMARC audit"),
    ("subdomain_enum",    "modules.subdomain_enum",         "TOOL_INFO",
     "subdomain_enum",        "crt.sh + DNS enum"),
    ("tech_fingerprint",  "modules.tech_fingerprint",       "TOOL_INFO",
     "tech_fingerprint",      "CMS / CDN fingerprint"),
    ("scan_school",       "modules.scan_school",            "TOOL_INFO",
     "scan_school",           "Malaysian school search"),
    ("search_user",       "modules.search_user",            "TOOL_INFO",
     "search_user",           "OSINT leak-data search"),
    ("source_viewer",     "modules.source_viewer",          None,
     "source_viewer",         "URL source fetcher"),
    ("brute_force",       "modules.brute_force",            "TOOL_INFO",
     "brute_force",           "Multi-protocol bruteforce"),
    ("exploit_repository","modules.exploit_repository",     None,
     "exploit_repository",    "Exploit catalogue"),
    ("scan_orchestrator", "modules.scan_orchestrator",      "__version__",
     "scan_orchestrator",     "Background job manager"),
]


def detect_modules():
    result = {key: False for key, *_ in MODULE_PROBES}
    result["versions"] = {}
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        import importlib
        for key, mod_path, ver_attr, *_ in MODULE_PROBES:
            try:
                mod = importlib.import_module(mod_path)
                result[key] = True
                if ver_attr:
                    attr = getattr(mod, ver_attr, None)
                    if isinstance(attr, dict):
                        v = attr.get("version")
                        if v:
                            result["versions"][key] = str(v)
                    elif isinstance(attr, str):
                        result["versions"][key] = attr
            except Exception:
                result[key] = False
    except Exception:
        pass
    return result


def detect_app():
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        import importlib
        for candidate in ("app", "main", "server", "run"):
            try:
                mod = importlib.import_module(candidate)
                if getattr(mod, "app", None) is not None:
                    return candidate
            except Exception:
                continue
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════════
# BOOT SEQUENCE
# ═══════════════════════════════════════════════════════════════════════════
def _boot_line(label, ok, desc="", ver=""):
    tw = term_width()
    col_width = max(30, tw - 46)
    dot = c("●", C.GREEN if ok else C.RED)
    label_txt = label + (f"  v{ver}" if ver else "")
    tail = "✓" if ok else "✗"
    tail_col = C.GREEN if ok else C.RED
    block = f"{label_txt}  ·  {desc}" if desc else label_txt
    if len(block) > col_width:
        block = block[: col_width - 1] + "…"
    print("  " + dot + "  " + c(block.ljust(col_width), C.BLUE_SOFT)
          + "  " + c(tail, tail_col, bold=True))


def display_boot_sequence(modules, app_name):
    _section("BOOT SEQUENCE", width=72)
    core_steps = [
        ("Initializing core runtime",    True),
        ("Loading configuration",        True),
        ("Mounting scan orchestrator",   True),
        ("Wiring history store",         True),
        ("Binding authentication layer", True),
        ("Attaching OSINT modules",      True),
        (f"Linking Flask app  ({app_name or 'not found'})",
                                          app_name is not None),
    ]
    for label, ok in core_steps:
        _boot_line(label, ok)
        time.sleep(0.02)

    _section("MODULE MATRIX", width=72)
    loaded = 0
    total = len(MODULE_PROBES)
    for key, _mp, _va, label, desc in MODULE_PROBES:
        ok = modules.get(key, False)
        ver = modules.get("versions", {}).get(key, "")
        if ok:
            loaded += 1
        _boot_line(label, ok, desc=desc, ver=ver)

    _section("BOOT SUMMARY", width=72)
    print("  " + c("●", C.GREEN if loaded == total else C.YELLOW)
          + "  " + c(f"{loaded} / {total} modules loaded",
                       C.WHITE, bold=True))


# ═══════════════════════════════════════════════════════════════════════════
# NETWORK HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def normalize_url(url):
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def parse_host_port(url):
    try:
        from urllib.parse import urlparse
        p = urlparse(normalize_url(url))
        host = p.hostname or "localhost"
        if p.port:
            return host, int(p.port)
        return host, 443 if p.scheme == "https" else 80
    except Exception:
        return "localhost", 8080


def port_is_open(host, port, timeout=0.6):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def wait_for_server(url, timeout=20.0, poll_interval=0.4):
    probe = url.rstrip("/") + "/api/me"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(probe, timeout=2.0, allow_redirects=False)
            if r.status_code < 500:
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(poll_interval)
    return False


def find_free_port(start_port, max_attempts=10):
    for i in range(max_attempts):
        p = start_port + i
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return None


# ═══════════════════════════════════════════════════════════════════════════
# LOCAL SERVER
# ═══════════════════════════════════════════════════════════════════════════
def _load_flask_app():
    sys.path.insert(0, str(Path(__file__).parent))
    import importlib
    for candidate in ("app", "main", "server", "run"):
        try:
            mod = importlib.import_module(candidate)
            app = getattr(mod, "app", None)
            if app is None:
                continue
            bootstrap_once = getattr(mod, "bootstrap_once", None)
            bootstrap = getattr(mod, "bootstrap", None)
            try:
                if callable(bootstrap_once):
                    bootstrap_once(verbose=False)
                elif callable(bootstrap):
                    bootstrap(verbose=False)
            except Exception:
                pass
            return app
        except Exception:
            continue
    return None


def _default_port():
    env = os.getenv("PORT")
    if env:
        try:
            return int(env)
        except ValueError:
            pass
    try:
        from config import Config  # type: ignore
        return int(getattr(Config, "PORT", 8080))
    except Exception:
        return 8080


def start_local_server(port=None, bind_host="127.0.0.1"):
    global _server_thread, _server_app, _server_port
    if _server_thread is not None and _server_thread.is_alive():
        return True, _server_port, "server already running"
    if port is None:
        port = _default_port()
    if port_is_open(bind_host, port, timeout=0.3):
        new_port = find_free_port(port + 1, max_attempts=10)
        if new_port is None:
            return False, port, f"port {port} is busy and no free port found"
        port = new_port
    app = _load_flask_app()
    if app is None:
        return False, port, "could not import the Flask app (app.py missing?)"
    os.environ.setdefault("PORT", str(port))

    def _runner():
        try:
            app.run(host=bind_host, port=port, debug=False,
                    threaded=True, use_reloader=False)
        except Exception as exc:
            sys.stderr.write(f"\n  [server] crashed: {exc}\n")

    thread = threading.Thread(target=_runner, daemon=True,
                               name=f"emergens-server-{port}")
    thread.start()
    _server_thread = thread
    _server_app = app
    _server_port = port
    return True, port, "started"


# ═══════════════════════════════════════════════════════════════════════════
# API CLIENT
# ═══════════════════════════════════════════════════════════════════════════
class APIClient:
    def __init__(self, base_url):
        self.base_url = normalize_url(base_url)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": f"Emergens-Terminal/{VERSION}",
            "Accept": "application/json",
        })
        self.token = None
        self.username = None
        self.role = None
        self.auth_mode = None

    def adb_login(self, code=AUTO_LOGIN_CODE):
        try:
            r = self.session.post(
                f"{self.base_url}{AUTO_LOGIN_ENDPOINT}",
                json={"code": code}, timeout=10,
            )
        except requests.exceptions.ConnectionError as e:
            return False, "connection_refused", str(e)
        except requests.exceptions.Timeout:
            return False, "timeout", "request timed out"
        except requests.exceptions.RequestException as e:
            return False, "network_error", str(e)

        if r.status_code == 200:
            try:
                data = r.json()
            except Exception:
                return False, "invalid_response", "invalid JSON"
            if data.get("success"):
                self.username = data.get("username") or AUTO_LOGIN_USERNAME
                self.role = data.get("role") or AUTO_LOGIN_ROLE
                self.auth_mode = "adb"
                return True, "ok", "auto-login success"
            return False, "rejected", data.get("error", "adb_login rejected")
        if r.status_code == 401:
            return False, "auth_denied", "invalid ADB code"
        if r.status_code == 400:
            return False, "bad_request", "code_required"
        return False, "http_error", f"HTTP {r.status_code}"

    def login(self, username, password):
        try:
            r = self.session.post(
                f"{self.base_url}/api/token",
                json={"username": username, "password": password},
                timeout=15,
            )
        except requests.exceptions.RequestException as e:
            return False, "network_error", str(e)
        if r.status_code == 200:
            try:
                data = r.json()
            except Exception:
                return False, "invalid_response", "invalid JSON"
            self.token = data.get("token")
            self.username = data.get("username", username)
            self.role = data.get("role")
            self.auth_mode = "password"
            return True, "ok", "login success"
        try:
            err = r.json().get("error", f"HTTP {r.status_code}")
        except Exception:
            err = f"HTTP {r.status_code}"
        return False, "auth_denied", err

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def get(self, path, timeout=30, **kwargs):
        try:
            return self.session.get(f"{self.base_url}{path}",
                                     headers=self._headers(),
                                     timeout=timeout, **kwargs)
        except requests.exceptions.RequestException:
            return None

    def post(self, path, timeout=300, **kwargs):
        try:
            return self.session.post(f"{self.base_url}{path}",
                                      headers=self._headers(),
                                      timeout=timeout, **kwargs)
        except requests.exceptions.RequestException:
            return None

    def describe(self):
        if not self.username:
            return c("unauthenticated", C.YELLOW)
        mode = f" [{self.auth_mode}]" if self.auth_mode else ""
        return (c(f"{self.username} ({self.role})", C.GREEN, bold=True)
                + c(mode, C.GREY_DARK, dim=True))


_client = None


def get_client():
    return _client


# ═══════════════════════════════════════════════════════════════════════════
# CONNECTION FLOW
# ═══════════════════════════════════════════════════════════════════════════
BACK_KEYS = {"b", "back", "q", "quit", "0"}


def _try_auto_login(url):
    client = APIClient(url)
    ok, kind, msg = client.adb_login(code=AUTO_LOGIN_CODE)
    return ok, client, kind, msg


def _spinner_msg(label, seconds=1.0):
    n_frames = max(3, int(seconds / 0.08))
    for i in range(n_frames):
        frame = FRAMES[i % len(FRAMES)]
        sys.stdout.write(_clr_line() + "  "
                          + c(f"{frame} {label}…", C.BLUE_SOFT))
        if _USE_COLOR:
            sys.stdout.write(_CLR_EOL)
        sys.stdout.flush()
        time.sleep(0.08)
    sys.stdout.write(_clr_line())
    sys.stdout.flush()


def auto_connect(url=None, auto_launch=True, silent=False):
    global _client
    env_url = os.getenv("EMERGENS_URL", "").strip()
    url = normalize_url(url or env_url or "http://localhost:8080")

    if not silent:
        _section("SERVER CONNECTION", width=72)
        print("  " + c("▸ Auto-login", C.BLUE, bold=True)
              + " " + c(f"as {AUTO_LOGIN_USERNAME}", C.BLUE_SOFT)
              + c(f"  →  {url}", C.GREY_DARK, dim=True))
        print()

    _spinner_msg(f"connecting to {url}", 0.5)

    ok, client, kind, msg = _try_auto_login(url)

    if ok:
        _client = client
        print("  " + c("●", C.GREEN) + " "
              + c(f"Auto-login successful  →  "
                  f"{_client.username} ({_client.role})",
                  C.GREEN, bold=True))
        return True

    if kind == "connection_refused" and auto_launch:
        print("  " + c("●", C.YELLOW) + " "
              + c(f"Server offline at {url}", C.YELLOW))
        _, port = parse_host_port(url)
        print("  " + c(f"→ Auto-launching local Flask server on port {port}…",
                        C.BLUE_SOFT))
        print()

        ok2, actual_port, launch_msg = start_local_server(port)
        if not ok2:
            print("  " + c("●", C.RED) + " "
                  + c(f"Launch failed: {launch_msg}", C.RED))
            return _password_fallback(client) if not silent else False

        if actual_port != port:
            print("  " + c(f"  (port {port} busy → using {actual_port})",
                            C.GREY, dim=True))
            url = f"http://localhost:{actual_port}"

        ready = False
        deadline = time.monotonic() + 15.0
        i = 0
        while time.monotonic() < deadline:
            if port_is_open("127.0.0.1", actual_port, timeout=0.3):
                ready = True
                break
            frame = FRAMES[i % len(FRAMES)]
            sys.stdout.write(_clr_line() + "  "
                              + c(f"{frame} waiting for server to bind…",
                                    C.BLUE_SOFT))
            if _USE_COLOR:
                sys.stdout.write(_CLR_EOL)
            sys.stdout.flush()
            time.sleep(0.15)
            i += 1
        sys.stdout.write(_clr_line()); sys.stdout.flush()

        if not ready:
            print("  " + c("●", C.RED) + " "
                  + c("Server did not bind within 15s.", C.RED))
            return _password_fallback(client) if not silent else False

        if not wait_for_server(url, timeout=8.0):
            print("  " + c("●", C.RED) + " "
                  + c("Server bound but HTTP not responding.", C.RED))
            return _password_fallback(client) if not silent else False

        print("  " + c("●", C.GREEN) + " "
              + c(f"Server ready  →  {url}", C.GREEN, bold=True))
        print()

        print("  " + c("▸ Retrying auto-login", C.BLUE, bold=True))
        _spinner_msg("authenticating", 0.4)

        ok3, client2, kind2, msg2 = _try_auto_login(url)
        if ok3:
            _client = client2
            print("  " + c("●", C.GREEN) + " "
                  + c(f"Auto-login successful  →  "
                      f"{_client.username} ({_client.role})",
                      C.GREEN, bold=True))
            return True

        print("  " + c("●", C.RED) + " "
              + c(f"Auto-login failed ({kind2}): {msg2}", C.YELLOW))
        return _password_fallback(client2) if not silent else False

    if not silent:
        print("  " + c("●", C.RED) + " "
              + c(f"Auto-login failed ({kind}): {msg}", C.YELLOW))
        return _password_fallback(client)
    return False


def _password_fallback(client):
    print()
    print("  " + c("Fallback: username + password login.", C.BLUE_SOFT))
    env_user = os.getenv("EMERGENS_USER", "").strip()
    env_pass = os.getenv("EMERGENS_PASS", "").strip()
    default_user = env_user or AUTO_LOGIN_USERNAME

    raw_user = prompt(c("Username", C.BLUE_SOFT)
                      + " " + c(f"[{default_user}]", C.GREY) + " › ")
    if raw_user.lower() in BACK_KEYS:
        return False
    username = raw_user or default_user

    if env_pass:
        password = env_pass
    else:
        try:
            import getpass
            password = getpass.getpass(
                "  " + c("▸", C.BLUE, bold=True) + " "
                + c("Password", C.BLUE_SOFT) + " › ")
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        except Exception:
            password = prompt(c("Password", C.BLUE_SOFT) + " › ")

    print()
    print("  " + c(f"▸ Authenticating as {username} …", C.BLUE_SOFT))
    ok, kind, msg = client.login(username, password)
    if ok:
        global _client
        _client = client
        print("  " + c("●", C.GREEN) + " "
              + c(f"Authenticated as {_client.username} ({_client.role})",
                   C.GREEN, bold=True))
        return True

    print("  " + c("●", C.RED) + " "
          + c(f"Login failed ({kind}): {msg}", C.RED))
    retry = prompt(c("Continue unauthenticated anyway?", C.BLUE_SOFT)
                   + " " + c("[y/N]", C.GREY) + " › ").lower()
    if retry in ("y", "yes"):
        _client = client
        return True
    return False


# ═══════════════════════════════════════════════════════════════════════════
# RESPONSE DISPLAY
# ═══════════════════════════════════════════════════════════════════════════
def section_header(title, width=72):
    _section(title, width=width)


def sev_color(sev):
    s = (sev or "").lower()
    return {
        "critical": C.RED, "high": C.ORANGE, "medium": C.YELLOW,
        "low": C.GREEN, "info": C.BLUE_SOFT, "safe": C.GREEN,
    }.get(s, C.GREY)


def sev_badge(sev):
    s = (sev or "").upper()
    return c(f"[{s:^8}]", sev_color(sev), bold=True)


def _truncate(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def show_response(resp, title="Result", max_bytes=6000):
    print()
    print("  " + c(f"── {title} " + "─" * max(0, 60 - len(title)),
                    C.BLUE, bold=True))
    if resp is None:
        print("  " + c("✖ No response — server unreachable", C.RED))
        return
    if resp.status_code >= 400:
        print("  " + c(f"✖ HTTP {resp.status_code}", C.RED, bold=True))
        try:
            text = json.dumps(resp.json(), indent=2, ensure_ascii=False)
        except Exception:
            text = resp.text or ""
        if len(text) > max_bytes:
            text = text[:max_bytes] + "\n... [truncated]"
        print("  " + c(text, C.GREY))
        return
    try:
        text = json.dumps(resp.json(), indent=2, ensure_ascii=False)
    except Exception:
        text = resp.text or ""
    if len(text) > max_bytes:
        text = text[:max_bytes] + "\n... [truncated]"
    print("  " + c(text, C.BLUE_LIGHT))


def _summary_header(title, resp, elapsed, extra=None):
    status = resp.status_code if resp is not None else 0
    ok = resp is not None and 200 <= status < 400
    status_txt = f"HTTP {status}" if resp is not None else "NO RESPONSE"
    status_col = C.GREEN if ok else C.RED
    rows = [
        ("Scanner", title, C.BLUE_LIGHT),
        ("Status", status_txt, status_col),
        ("Elapsed", f"{elapsed:.2f} s", C.CYAN),
        ("Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), C.BLUE_SOFT),
    ]
    if extra:
        rows.extend(extra)
    draw_box("SCAN RESULT", rows, width=72)


# ═══════════════════════════════════════════════════════════════════════════
# SCANNER-SPECIFIC RENDERERS
# ═══════════════════════════════════════════════════════════════════════════
def _render_portscan(data, title):
    d = data.get("data") if "data" in data else data
    if isinstance(d, dict) and "data" in d:
        d = d["data"]
    section_header("PORT SCAN", width=72)
    rows = [
        ("Target",   _truncate(data.get("target") or d.get("resolved_ip", "?"), 50), C.CYAN),
        ("Resolved", d.get("resolved_ip", "?"), C.BLUE_LIGHT),
        ("Checked",  str(d.get("ports_checked", 0)), C.BLUE_LIGHT),
        ("Open",     str(d.get("open_count", 0)),
         C.GREEN if d.get("open_count", 0) else C.GREY),
        ("Scan time",f"{d.get('scan_time', 0):.2f} s", C.CYAN),
    ]
    draw_box("PORT SCAN", rows)
    ports = d.get("open_ports_details", []) or []
    if ports:
        print()
        for p in ports[:30]:
            port = str(p.get("port"))
            risky = p.get("port") in (21, 23, 25, 135, 139, 445, 3389, 5900)
            print("  " + c(port.ljust(7), C.RED if risky else C.GREEN, bold=True)
                  + c(str(p.get("state", "")).ljust(9), C.GREEN)
                  + c(_truncate(p.get("service", "?"), 18).ljust(20), C.CYAN)
                  + c(f"{p.get('response_time', 0):.3f}s".ljust(10), C.BLUE_SOFT)
                  + c(_truncate(p.get("banner", ""), 24), C.GREY))


def _render_ssl(data, title):
    d = data.get("data") if "data" in data else data
    if isinstance(d, dict) and "data" in d:
        d = d["data"]
    subj = d.get("subject", {}) or {}
    iss  = d.get("issuer", {})  or {}
    exp  = d.get("days_until_expiry")
    if d.get("is_expired"):
        status_txt, status_col = "EXPIRED", C.RED
    elif d.get("expiring_soon"):
        status_txt, status_col = f"EXPIRES IN {exp} DAYS", C.YELLOW
    elif exp is not None:
        status_txt, status_col = f"VALID · {exp} days left", C.GREEN
    else:
        status_txt, status_col = "UNKNOWN", C.GREY
    section_header("SSL / TLS", width=72)
    rows = [
        ("Subject CN", subj.get("commonName", "?"), C.CYAN),
        ("Issuer",     iss.get("organizationName", "?"), C.BLUE_LIGHT),
        ("Status",     status_txt, status_col),
        ("Protocol",   d.get("protocol", "?"),
         C.RED if d.get("protocol_weak") else C.GREEN),
        ("Cipher",     _truncate(d.get("cipher_suite", "?"), 40), C.BLUE_SOFT),
        ("Valid from", (d.get("valid_from") or "?")[:19], C.GREY),
        ("Valid until",(d.get("valid_until") or "?")[:19], C.GREY),
    ]
    draw_box("SSL / TLS", rows)


def _render_headers(data, title):
    d = data.get("data") if "data" in data else data
    if isinstance(d, dict) and "data" in d:
        d = d["data"]
    grade = d.get("grade", "?")
    score = d.get("score_percent", 0)
    risk  = d.get("risk", {}) or {}
    grade_col = (C.GREEN if str(grade).startswith(("A", "B"))
                 else C.YELLOW if str(grade).startswith("C")
                 else C.RED)
    section_header("HTTP SECURITY HEADERS", width=72)
    rows = [
        ("URL",     _truncate(d.get("url", "?"), 50), C.CYAN),
        ("Server",  d.get("server", "?"), C.BLUE_SOFT),
        ("Grade",   grade, grade_col),
        ("Score",   f"{score}%", grade_col),
        ("Risk",    f"{risk.get('label', '?')} ({risk.get('score', '?')}/10)",
         sev_color(risk.get("label", ""))),
    ]
    draw_box("SECURITY HEADERS", rows)
    missing = d.get("missing_headers", []) or []
    if missing:
        print()
        for m in missing[:15]:
            print("  " + sev_badge(m.get("severity", "info")) + " "
                  + c(m.get("header", "?"), C.BLUE_LIGHT, bold=True))


def _render_techfp(data, title):
    d = data.get("data") if "data" in data else data
    if isinstance(d, dict) and "data" in d:
        d = d["data"]
    section_header("TECH FINGERPRINT", width=72)
    rows = [
        ("URL",     _truncate(d.get("final_url", "?"), 50), C.CYAN),
        ("Server",  d.get("server_header") or "—", C.BLUE_SOFT),
        ("Powered", d.get("powered_by") or "—", C.BLUE_SOFT),
    ]
    draw_box("TECH FINGERPRINT", rows)
    for det in (d.get("detections", []) or [])[:30]:
        conf = det.get("confidence", "?")
        col = {"high": C.GREEN, "medium": C.YELLOW, "low": C.GREY}.get(conf, C.GREY)
        ver = det.get("version")
        print("  " + c("●", col) + " "
              + c(det.get("name", "?"), C.BLUE_LIGHT, bold=True)
              + (c(f" v{ver}", C.CYAN) if ver else "")
              + c(f"  ·  {det.get('category', '')}", C.GREY_DARK, dim=True))


def _render_ipinfo(data, title):
    d = data.get("data") if "data" in data else data
    if isinstance(d, dict) and "data" in d:
        d = d["data"]
    section_header("IP / ASN INTELLIGENCE", width=72)
    rows = [
        ("IP",       d.get("ip", "?"), C.CYAN),
        ("rDNS",     d.get("reverse_dns", "—"), C.BLUE_LIGHT),
        ("Country",  d.get("country", "—"), C.BLUE_LIGHT),
        ("City",     d.get("city", "—"), C.BLUE_SOFT),
        ("ASN",      d.get("asn", "—"), C.BLUE_SOFT),
        ("ISP",      _truncate(d.get("isp", "—"), 50), C.BLUE_SOFT),
    ]
    draw_box("IP INFO", rows)
    flags = [(k, v) for k in ("is_proxy", "is_hosting", "is_mobile",
                                "is_tor", "is_vpn", "is_abuse")
             if (v := d.get(k)) is not None]
    if flags:
        print()
        for k, v in flags:
            col = C.RED if v else C.GREEN
            print("  " + c("▸", C.BLUE_DARK) + " "
                  + c(k.replace("is_", "").title().ljust(15), C.BLUE_SOFT)
                  + c(str(v), col, bold=True))


def _render_apikey(data, title):
    d = data.get("data") if "data" in data else data
    if isinstance(d, dict) and "data" in d:
        d = d["data"]
    stats = d.get("stats", {}) or {}
    findings = d.get("findings", []) or []
    by_sev = stats.get("by_severity", {}) or {}
    section_header("API KEY SCANNER", width=72)
    rows = [
        ("Target",   _truncate(d.get("scanned", "?"), 50), C.CYAN),
        ("Findings", str(stats.get("total", len(findings))),
         C.RED if findings else C.GREEN),
        ("Critical", str(by_sev.get("critical", 0)), C.RED),
        ("High",     str(by_sev.get("high", 0)), C.ORANGE),
        ("Medium",   str(by_sev.get("medium", 0)), C.YELLOW),
    ]
    draw_box("API KEY SCAN", rows)
    for i, f in enumerate(findings[:15], 1):
        print()
        print("  " + c(f"{i:>2}.", C.BLUE_DARK, bold=True) + " "
              + sev_badge(f.get("severity", "medium")) + " "
              + c(_truncate(f.get("pattern_name", "?"), 40),
                   C.BLUE_LIGHT, bold=True))
        if f.get("extracted_key"):
            print("       " + c("Key", C.BLUE_SOFT) + " "
                  + c(_truncate(f["extracted_key"], 60), C.YELLOW, bold=True))


def _render_xss(data, title):
    d = data.get("data") if "data" in data else data
    if isinstance(d, dict) and "data" in d:
        d = d["data"]
    section_header("XSS SCANNER", width=72)
    vuln = d.get("vulnerable", False)
    rows = [
        ("URL",        _truncate(d.get("url", "?"), 50), C.CYAN),
        ("Vulnerable", "YES" if vuln else "no", C.RED if vuln else C.GREEN),
        ("Executable", str(d.get("executable_count", 0)), C.RED),
        ("Likely",     str(d.get("likely_count", 0)), C.ORANGE),
    ]
    draw_box("XSS SCAN", rows)
    for f in (d.get("findings", []) or [])[:15]:
        exploit = f.get("exploitability", "dormant")
        col = {"executable": C.RED, "likely": C.ORANGE,
               "encoded": C.YELLOW, "dormant": C.GREY}.get(exploit, C.GREY)
        print("  " + c(f"[{exploit.upper():^10}]", col, bold=True) + " "
              + c(f.get("parameter", "?"), C.BLUE_LIGHT, bold=True))


def _render_sqlmap(data, title):
    d = data.get("data") if "data" in data else data
    if isinstance(d, dict) and "data" in d:
        d = d["data"]
    section_header("SQL INJECTION", width=72)
    vuln = d.get("vulnerable", False)
    rows = [
        ("URL",       _truncate(d.get("url", "?"), 50), C.CYAN),
        ("Vulnerable","YES" if vuln else "no", C.RED if vuln else C.GREEN),
        ("DBMS",      d.get("database_hint") or "—", C.MAGENTA),
        ("Requests",  str(d.get("requests_sent", 0)), C.BLUE_SOFT),
    ]
    draw_box("SQL INJECTION", rows)
    for f in (d.get("findings", []) or [])[:15]:
        print("  " + sev_badge(f.get("severity", "medium")) + " "
              + c(f.get("technique", "?"), C.BLUE_LIGHT, bold=True)
              + c(f"  param={f.get('parameter', '?')}", C.GREY))


def _render_dirfuzz(data, title):
    d = data.get("data") if "data" in data else data
    if isinstance(d, dict) and "data" in d:
        d = d["data"]
    section_header("DIRFUZZ", width=72)
    rows = [
        ("Base",   _truncate(d.get("base", "?"), 50), C.CYAN),
        ("Tried",  str(d.get("tried", 0)), C.BLUE_SOFT),
        ("Hits",   str(d.get("hits_count", 0)),
         C.RED if d.get("hits_count", 0) else C.GREEN),
    ]
    draw_box("DIRFUZZ", rows)
    for h in (d.get("hits", []) or [])[:25]:
        print("  " + sev_badge(h.get("severity", "info")) + " "
              + c(str(h.get("status", "?")).ljust(5),
                  C.GREEN if h.get("status") == 200 else C.YELLOW)
              + "  " + c(_truncate(h.get("path", "?"), 48), C.BLUE_LIGHT))


def _render_sniper(data, title):
    d = data.get("data") if "data" in data else data
    if isinstance(d, dict) and "data" in d:
        d = d["data"]
    section_header("SNIPER", width=72)
    risk = d.get("risk_level", "unknown")
    rows = [
        ("Target",  _truncate(d.get("target", "?"), 50), C.CYAN),
        ("Risk",    f"{d.get('risk_score', 0)}/100 ({risk.upper()})",
         sev_color(risk)),
        ("Elapsed", f"{d.get('elapsed', 0):.2f} s", C.CYAN),
    ]
    draw_box("SNIPER", rows)
    for m in (d.get("modules", []) or []):
        ok = m.get("ok", False)
        tmo = m.get("timed_out", False)
        if ok:
            status, col = "OK", C.GREEN
        elif tmo:
            status, col = "TIMEOUT", C.ORANGE
        else:
            status, col = "FAIL", C.RED
        print("  " + c(_truncate(m.get("name", "?"), 22).ljust(24),
                        C.BLUE_LIGHT)
              + c(status.ljust(10), col, bold=True)
              + c(str(m.get("findings_count", 0)).ljust(10), C.CYAN)
              + c(f"{m.get('elapsed', 0):.2f}s", C.BLUE_SOFT))


RENDERERS = {
    "/api/portscan/scan": _render_portscan,
    "/api/ssl/scan":      _render_ssl,
    "/api/headers/scan":  _render_headers,
    "/api/techfp/scan":   _render_techfp,
    "/api/ipinfo/scan":   _render_ipinfo,
    "/api/apikey/scan":   _render_apikey,
    "/api/xss/scan":      _render_xss,
    "/api/sqlmap/scan":   _render_sqlmap,
    "/api/dirfuzz/scan":  _render_dirfuzz,
    "/api/sniper/scan":   _render_sniper,
}


def render_result(resp, endpoint, label):
    if resp is None:
        section_header("RESULT", width=72)
        print("  " + c("✖ No response.", C.RED, bold=True)); return
    if resp.status_code >= 400:
        section_header("RESULT · ERROR", width=72)
        print("  " + c(f"✖ HTTP {resp.status_code}", C.RED, bold=True))
        try:
            print("  " + c(json.dumps(resp.json(), indent=2,
                                       ensure_ascii=False)[:2000], C.GREY))
        except Exception:
            print("  " + c((resp.text or "")[:2000], C.GREY))
        return
    try:
        data = resp.json()
    except Exception:
        section_header(label, width=72)
        print("  " + c((resp.text or "")[:4000], C.BLUE_LIGHT)); return
    renderer = RENDERERS.get(endpoint)
    if renderer is None:
        section_header(label, width=72)
        print("  " + c(_truncate(json.dumps(data, indent=2,
                                              ensure_ascii=False), 8000),
                        C.BLUE_LIGHT))
    else:
        renderer(data, label)


# ═══════════════════════════════════════════════════════════════════════════
# ⭐ SCAN ALL — orchestrator-backed multi-scanner flow
# ═══════════════════════════════════════════════════════════════════════════
def _progress_bar(percent, width=30):
    """Return a colored progress bar string."""
    filled = max(0, min(width, int(width * percent / 100)))
    empty  = width - filled
    bar = c("█" * filled, C.BLUE, bold=True) + c("░" * empty, C.BLUE_DARK)
    return f"[{bar}] {percent:3d}%"


def scan_all_flow():
    """
    Drive the ScanOrchestrator via /api/scan/start and poll
    /api/scan/<job_id>/status until completion. Renders the per-module
    results table.
    """
    if not _client_required():
        return

    while True:
        clear_screen()
        print_banner()
        section_header("SCAN ALL · FULL PIPELINE", width=72)
        print("  " + c("Runs every registered scanner in one background job.",
                        C.BLUE_SOFT))
        print("  " + c("Progress and per-module results are streamed live.",
                        C.GREY, dim=True))
        print()

        target = ask_target("target (domain / URL / IP)")
        if target is None:
            return
        mode = ask_mode()
        if mode is None:
            continue

        # ── Dispatch ────────────────────────────────────────────────
        clear_screen()
        print_banner()
        section_header("SCAN ALL · DISPATCHING", width=72)
        print("  " + c(f"Target : {target}", C.BLUE_LIGHT))
        print("  " + c(f"Mode   : {mode}", C.MAGENTA if mode == "expert"
                                              else C.GREEN))
        print("  " + c("Endpoint: POST /api/scan/start", C.GREY_DARK, dim=True))
        print()

        # POST /api/scan/start  → {job_id}
        _spinner_msg("submitting scan job", 0.4)
        t0 = time.monotonic()
        resp = _client.post(
            "/api/scan/start",
            json={"target": target, "mode": mode, "tools": []},
            timeout=60,
        )
        if resp is None:
            print("  " + c("●", C.RED) + " "
                  + c("No response from /api/scan/start", C.RED, bold=True))
            pause(); continue
        if resp.status_code >= 400:
            print("  " + c("●", C.RED) + " "
                  + c(f"HTTP {resp.status_code} on /api/scan/start", C.RED))
            try:
                print("  " + c(json.dumps(resp.json(), indent=2)[:1200],
                                C.GREY))
            except Exception:
                print("  " + c((resp.text or "")[:1200], C.GREY))
            pause(); continue

        try:
            start_data = resp.json()
        except Exception:
            print("  " + c("●", C.RED) + " "
                  + c("Invalid JSON from server.", C.RED))
            pause(); continue

        job_id = start_data.get("job_id")
        if not job_id:
            print("  " + c("●", C.RED) + " "
                  + c(f"Server did not return job_id: {start_data}", C.RED))
            pause(); continue

        print("  " + c("●", C.GREEN) + " "
              + c(f"Job dispatched  →  id={job_id}", C.GREEN, bold=True))
        print()

        # ── Poll loop ───────────────────────────────────────────────
        section_header("SCAN ALL · PROGRESS", width=72)
        print("  " + c(f"job_id : {job_id}", C.GREY_DARK, dim=True))
        print()

        job = None
        last_status = None
        last_tool = None
        last_pct = -1
        poll_interval = 1.2
        max_wait = 900.0   # 15 min hard cap
        start_mono = time.monotonic()
        frame_idx = 0

        def _render_progress_line(job_dict, elapsed):
            nonlocal frame_idx
            pct = int(job_dict.get("percent") or 0)
            status = job_dict.get("status", "running")
            current = job_dict.get("current_tool") or "…"
            frame = FRAMES[frame_idx % len(FRAMES)]
            frame_idx += 1

            # line 1: spinner + status
            line1 = (
                "  " + c(frame, C.CYAN, bold=True) + "  "
                + c("status : ", C.BLUE_SOFT)
                + c(str(status).ljust(10),
                    C.GREEN if status == "running" else C.BLUE_LIGHT)
                + c(" │ ", C.GREY_DARK, dim=True)
                + c("elapsed ", C.BLUE_SOFT)
                + c(f"{elapsed:6.1f}s", C.CYAN)
                + c(" │ ", C.GREY_DARK, dim=True)
                + c("job_id ", C.BLUE_SOFT)
                + c(job_id[:12], C.GREY)
            )
            # line 2: progress bar
            line2 = "  " + c("progress: ", C.BLUE_SOFT) + _progress_bar(pct)
            # line 3: current tool
            line3 = ("  " + c("running: ", C.BLUE_SOFT)
                     + c(_truncate(current, 60), C.BLUE_LIGHT, bold=True))
            return line1, line2, line3

        try:
            sys.stdout.write("\033[?25l")  # hide cursor
            sys.stdout.flush()
            while True:
                elapsed = time.monotonic() - start_mono
                if elapsed > max_wait:
                    print()
                    print("  " + c("●", C.YELLOW) + " "
                          + c(f"Polling timed out after {max_wait:.0f}s.",
                              C.YELLOW))
                    break

                r = _client.get(f"/api/scan/{job_id}/status", timeout=15)
                if r is None:
                    time.sleep(poll_interval)
                    continue
                if r.status_code == 404:
                    print()
                    print("  " + c("●", C.RED) + " "
                          + c("Job not found (expired?).", C.RED))
                    break
                if r.status_code >= 400:
                    time.sleep(poll_interval)
                    continue
                try:
                    job = r.json()
                except Exception:
                    time.sleep(poll_interval)
                    continue

                status  = job.get("status", "running")
                pct     = int(job.get("percent") or 0)
                current = job.get("current_tool") or "…"

                line1, line2, line3 = _render_progress_line(job, elapsed)
                # Redraw 3-line block in place
                sys.stdout.write(_clr_line() + line1
                                  + (_CLR_EOL if _USE_COLOR else "") + "\n")
                sys.stdout.write(_clr_line() + line2
                                  + (_CLR_EOL if _USE_COLOR else "") + "\n")
                sys.stdout.write(_clr_line() + line3
                                  + (_CLR_EOL if _USE_COLOR else ""))
                sys.stdout.flush()
                # Move cursor up 2 lines to overwrite next iteration
                if _USE_COLOR:
                    sys.stdout.write("\033[2A")
                    sys.stdout.flush()

                last_status = status
                last_tool = current
                last_pct = pct

                if status in ("completed", "cancelled", "timeout", "error"):
                    break
                time.sleep(poll_interval)
        finally:
            if _USE_COLOR:
                sys.stdout.write("\033[?25h")  # restore cursor
                sys.stdout.write("\033[3B")    # move below the 3-line block
                sys.stdout.flush()

        print()
        if job is None:
            print("  " + c("✖ No job state collected.", C.RED))
            pause(); continue

        elapsed_total = time.monotonic() - t0
        final_status = job.get("status", "unknown")

        # ── Final summary ───────────────────────────────────────────
        clear_screen()
        print_banner()
        _summary_header(
            "Scan All (Orchestrator)",
            resp=None,               # we didn't fetch a single HTTP result
            elapsed=elapsed_total,
            extra=[
                ("Target",  _truncate(target, 50), C.CYAN),
                ("Mode",    mode, C.MAGENTA if mode == "expert" else C.GREEN),
                ("Job ID",  job_id, C.GREY),
                ("Status",  final_status.upper(),
                 C.GREEN if final_status == "completed" else
                 C.YELLOW if final_status in ("cancelled", "timeout") else
                 C.RED),
            ],
        )

        if job.get("error"):
            print()
            print("  " + c("●", C.RED) + " "
                  + c(f"Error: {job['error']}", C.RED, bold=True))

        # ── Module table ────────────────────────────────────────────
        results = job.get("results") or {}
        tools_planned = job.get("tools") or []

        section_header("SCAN ALL · MODULE RESULTS", width=72)

        if not results and not tools_planned:
            print("  " + c("No tools were executed.", C.GREY))
            pause(); continue

        # Column widths
        col_mod = 24
        col_sta = 10
        col_fnd = 10
        col_tim = 10

        print("  " + c("MODULE".ljust(col_mod), C.BLUE, bold=True)
              + c("STATUS".ljust(col_sta), C.BLUE, bold=True)
              + c("FINDINGS".ljust(col_fnd), C.BLUE, bold=True)
              + c("TIME".ljust(col_tim), C.BLUE, bold=True))
        print("  " + c("─" * 68, C.BLUE_DARK))

        total_findings = 0
        ok_count = 0
        err_count = 0

        # Show planned order, prefer results
        ordered = list(results.keys())
        if not ordered:
            ordered = tools_planned

        for tool_name in ordered:
            result = results.get(tool_name) or {}
            err = result.get("error") if isinstance(result, dict) else None
            data = (result.get("data") or {}) if isinstance(result, dict) else {}

            if err:
                status, status_col = "FAIL", C.RED
                err_count += 1
            elif result:
                status, status_col = "OK", C.GREEN
                ok_count += 1
            else:
                status, status_col = "PENDING", C.GREY

            findings = 0
            if isinstance(data, dict):
                for key in ("findings", "hits", "detections", "open_ports",
                            "open_ports_details", "subdomains"):
                    v = data.get(key)
                    if isinstance(v, list):
                        findings = max(findings, len(v))
                # Some modules nest under data["data"]
                inner = data.get("data")
                if isinstance(inner, dict):
                    for key in ("findings", "hits", "detections"):
                        v = inner.get(key)
                        if isinstance(v, list):
                            findings = max(findings, len(v))
                # Scalar counts
                for key in ("findings_count", "hits_count", "critical_count",
                            "open_count", "vulnerable_count"):
                    v = data.get(key)
                    if isinstance(v, int):
                        findings = max(findings, v)
            total_findings += findings

            elapsed_tool = result.get("elapsed") if isinstance(result, dict) else None
            time_txt = f"{elapsed_tool:.2f}s" if isinstance(elapsed_tool, (int, float)) else "—"

            line = ("  "
                    + c(_truncate(tool_name, col_mod - 2).ljust(col_mod),
                         C.BLUE_LIGHT)
                    + c(status.ljust(col_sta), status_col, bold=True)
                    + c(str(findings).ljust(col_fnd), C.CYAN)
                    + c(time_txt.ljust(col_tim), C.BLUE_SOFT))
            if err:
                line += "  " + c(_truncate(str(err), 40), C.RED, dim=True)
            print(line)

        print("  " + c("─" * 68, C.BLUE_DARK))

        summary_line = ("  " + c("TOTAL".ljust(col_mod), C.BLUE, bold=True)
                        + c(f"{ok_count} OK / {err_count} FAIL".ljust(22),
                             C.GREEN if err_count == 0 else C.YELLOW)
                        + c(f"{total_findings} finding(s)", C.CYAN, bold=True))
        print(summary_line)

        # ── Actions ─────────────────────────────────────────────────
        print()
        act = prompt(
            c("Actions", C.BLUE_SOFT)
            + " " + c("[v]iew detail  [s]ave JSON  [b]ack  [Enter] skip", C.GREY)
            + " › "
        ).lower()

        if act == "v":
            _scan_all_view_details(job)
        elif act == "s":
            _scan_all_save_json(job, job_id)
        # anything else → back

        print()
        pause()


def _scan_all_view_details(job):
    """Render every module's full result using the per-scanner renderer."""
    results = job.get("results") or {}
    if not results:
        print("  " + c("No results to display.", C.GREY)); return

    ENDPOINT_MAP = {
        "port_scan":        "/api/portscan/scan",
        "scan_ssl":         "/api/ssl/scan",
        "ssl_check":        "/api/ssl/scan",
        "scan_headers":     "/api/headers/scan",
        "headers_check":    "/api/headers/scan",
        "scan_tech_fingerprint": "/api/techfp/scan",
        "tech_fingerprint": "/api/techfp/scan",
        "scan_ip_info":     "/api/ipinfo/scan",
        "ip_info":          "/api/ipinfo/scan",
        "scan_apikey":      "/api/apikey/scan",
        "xss":              "/api/xss/scan",
        "sql_map":          "/api/sqlmap/scan",
        "dirfuzz":          "/api/dirfuzz/scan",
        "sniper":           "/api/sniper/scan",
    }

    for tool_name, result in results.items():
        print()
        section_header(f"{tool_name.upper()}", width=72)
        if not isinstance(result, dict):
            print("  " + c(str(result), C.GREY)); continue
        err = result.get("error")
        if err:
            print("  " + c("●", C.RED) + " "
                  + c(f"ERROR: {err}", C.RED, bold=True))
            continue
        endpoint = ENDPOINT_MAP.get(tool_name)
        if endpoint and endpoint in RENDERERS:
            RENDERERS[endpoint](result, tool_name)
        else:
            # Generic JSON fallback
            pretty = json.dumps(result, indent=2, ensure_ascii=False)[:4000]
            for line in pretty.splitlines():
                print("  " + c(line, C.BLUE_LIGHT))


def _scan_all_save_json(job, job_id):
    """Save the full job JSON to disk."""
    try:
        filename = f"scan_all_{job_id[:8]}_{int(time.time())}.json"
        path = Path.cwd() / filename
        path.write_text(json.dumps(job, indent=2, default=str,
                                    ensure_ascii=False), encoding="utf-8")
        print("  " + c("●", C.GREEN) + " "
              + c(f"Saved  →  {path}", C.GREEN, bold=True))
    except Exception as e:
        print("  " + c("●", C.RED) + " "
              + c(f"Save failed: {e}", C.RED))


# ═══════════════════════════════════════════════════════════════════════════
# MENUS
# ═══════════════════════════════════════════════════════════════════════════
MAIN_MENU = [
    ("1", "Scan",       "scan",       "Port / SSL / Headers / XSS / SQLi / API-key"),
    ("2", "Scan All",   "scan_all",   "Run every scanner via orchestrator"),
    ("3", "Tools",      "tools",      "Wordlists · module status · sync"),
    ("4", "MHDDoS",     "mhddos",     "DDoS panel · Layer4 / Layer7 methods"),
    ("5", "Exploit",    "exploit",    "Exploit DB · Bruteforce · SQLi / XSS"),
    ("6", "Downloader", "downsea",    "Pinterest / TikTok downloader"),
    ("7", "Webhost",    "webhost",    "Launch local Flask server"),
    ("8", "Server",     "server",     "Reconnect / re-login"),
]


def _menu_render(title, items, width=72):
    print()
    print("  " + c("╭─ " + title + " "
                    + "─" * max(0, width - len(title) - 5) + "╮",
                    C.BLUE_DARK))
    for key, label, hint in items:
        num = c(f"[{key}]", C.CYAN, bold=True)
        name = c(label.ljust(13), C.BLUE_LIGHT, bold=True)
        h = c(hint, C.GREY_DARK, dim=True)
        visible = 2 + 3 + 2 + 13 + 1 + len(hint)
        pad = max(0, width - visible - 3)
        print("  " + c("│", C.BLUE_DARK) + f"  {num}  {name} {h}"
              + " " * pad + c("│", C.BLUE_DARK))
    print("  " + c("╰" + "─" * (width - 2) + "╯", C.BLUE_DARK))
    print()


def print_main_menu():
    items = [(k, l, h) for k, l, _slug, h in MAIN_MENU]
    items.append(("0", "Exit", "Close terminal launcher"))
    _menu_render("MAIN MENU", items)


# ═══════════════════════════════════════════════════════════════════════════
# ASK HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def ask_target(what="target"):
    raw = prompt(c(what.capitalize(), C.BLUE_SOFT) + " › ")
    if raw.lower() in BACK_KEYS or not raw:
        return None
    return raw


def ask_mode():
    print()
    print("    " + c("[1]", C.CYAN, bold=True) + " "
          + c("Basic".ljust(10), C.BLUE_LIGHT, bold=True)
          + c("fast, minimal probes", C.GREY))
    print("    " + c("[2]", C.CYAN, bold=True) + " "
          + c("Expert".ljust(10), C.BLUE_LIGHT, bold=True)
          + c("deep, all probes + extended wordlists", C.GREY))
    print("    " + c("[b]", C.CYAN, bold=True) + " "
          + c("Back".ljust(10), C.BLUE_LIGHT, bold=True)
          + c("cancel", C.GREY))
    while True:
        raw = prompt(c("Mode", C.BLUE_SOFT) + " › ").lower()
        if raw in BACK_KEYS:
            return None
        if raw in ("1", "basic"):  return "basic"
        if raw in ("2", "expert"): return "expert"


def _client_required():
    if not _HAS_REQUESTS:
        print(); print("  " + c("✖ 'requests' not installed.",
                                  C.RED, bold=True))
        print("  " + c("  pip install requests", C.GREY))
        pause(); return False
    if _client is None:
        print(); print("  " + c("✖ No API server configured.",
                                  C.YELLOW, bold=True))
        print("  " + c("  Attempting auto-connect…", C.GREY))
        if not auto_connect(auto_launch=True, silent=False):
            pause(); return False
    return True


def ask_port(default=None):
    if default is None:
        default = _default_port()
    print("  " + c("Server port configuration", C.BLUE, bold=True))
    print("  " + c(f"Press ENTER for default ({default}), 'b' to go back.",
                    C.GREY, dim=True))
    print()
    while True:
        raw = prompt(c("Port", C.BLUE_SOFT) + " "
                     + c(f"[{default}]", C.GREY) + " › ")
        if raw.lower() in BACK_KEYS: return None
        if raw == "": return default
        try:
            p = int(raw)
            if 1 <= p <= 65535: return p
            print("  " + c("✖ Port must be 1–65535.", C.RED))
        except ValueError:
            print("  " + c("✖ Invalid input.", C.RED))


# ═══════════════════════════════════════════════════════════════════════════
# WEBHOST
# ═══════════════════════════════════════════════════════════════════════════
def webhost_flow():
    clear_screen()
    print_banner()
    section_header("WEBHOST", width=72)
    print("  " + c("Launch the Emergens Flask server locally.",
                    C.BLUE_SOFT))
    print()
    port = ask_port()
    if port is None: return
    clear_screen(); print_banner()
    print()
    print("  " + c(f"Port  : {port}", C.CYAN))
    print("  " + c(f"URL   : http://localhost:{port}/dashboard.html", C.CYAN))
    print("  " + c(f"Bind  : 0.0.0.0:{port}", C.BLUE_LIGHT))
    print()
    confirm = prompt(c("Launch server now?", C.BLUE_SOFT)
                     + " " + c("[Y/n]", C.GREY) + " › ").lower()
    if confirm in ("n", "no"): return
    print()
    print("  " + c("Starting Emergens server…", C.BLUE, bold=True))
    time.sleep(0.3)
    app = _load_flask_app()
    if app is None:
        print("  " + c("✖ Could not import Flask app.",
                        C.RED, bold=True))
        pause(); return
    os.environ.setdefault("PORT", str(port))
    print()
    print("  " + c("▲  EMERGENS READY", C.WHITE, bold=True)
          + "   " + c("→", C.BLUE) + "   "
          + c(f"http://localhost:{port}/dashboard.html",
               C.CYAN, bold=True))
    print()
    try:
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
    except KeyboardInterrupt:
        print(); print("  " + c("◼ Shutdown.", C.BLUE_LIGHT)); print()


# ═══════════════════════════════════════════════════════════════════════════
# SCAN (single)
# ═══════════════════════════════════════════════════════════════════════════
SCANNERS = [
    ("1", "Port Scan",        "/api/portscan/scan",  "portscan"),
    ("2", "SSL Check",        "/api/ssl/scan",       "ssl"),
    ("3", "Headers",          "/api/headers/scan",   "headers"),
    ("4", "Tech Fingerprint", "/api/techfp/scan",    "techfp"),
    ("5", "IP Info",          "/api/ipinfo/scan",    "ipinfo"),
    ("6", "API Key Scanner",  "/api/apikey/scan",    "apikey"),
    ("7", "XSS",              "/api/xss/scan",       "xss"),
    ("8", "SQLi (sql_map)",   "/api/sqlmap/scan",    "sqlmap"),
    ("9", "Directory Fuzzer", "/api/dirfuzz/scan",   "dirfuzz"),
    ("A", "Sniper (full)",    "/api/sniper/scan",    "sniper"),
]

_SCAN_STAGES = [
    "resolving target", "connecting", "probing endpoints",
    "analyzing response", "collecting findings", "scoring severity",
    "finalizing report",
]


def scan_flow():
    if not _client_required(): return
    while True:
        clear_screen(); print_banner()
        _menu_render("SCAN · SELECT SCANNER",
                     [(k, l, "") for k, l, _e, _s in SCANNERS]
                     + [("B", "Back", "return to main menu")])
        choice = prompt(c("Scanner", C.BLUE_SOFT) + " › ").strip().upper()
        if choice in ("B", "") or choice.lower() in BACK_KEYS: return
        matched = None
        for k, label, endpoint, slug in SCANNERS:
            if choice == k:
                matched = (label, endpoint, slug); break
        if not matched:
            print("  " + c("✖ Invalid.", C.RED)); time.sleep(0.8); continue
        label, endpoint, _slug = matched
        target = ask_target("target")
        if target is None: continue
        mode = ask_mode()
        if mode is None: continue

        clear_screen(); print_banner()
        section_header(f"{label.upper()} · RUNNING", width=72)
        print("  " + c(f"Target : {target}", C.BLUE_LIGHT))
        print("  " + c(f"Mode   : {mode}", C.BLUE_LIGHT))
        print("  " + c(f"POST   : {endpoint}", C.GREY_DARK, dim=True))
        print()

        result = {"resp": None, "error": None, "done": False}
        t0 = time.monotonic()

        def _worker():
            try:
                result["resp"] = _client.post(
                    endpoint,
                    json={"target": target, "mode": mode}, timeout=300)
            except Exception as e:
                result["error"] = str(e)
            finally:
                result["done"] = True

        threading.Thread(target=_worker, daemon=True).start()
        frame_idx = 0; stage_idx = 0
        last_stage = time.monotonic()
        tw = term_width()

        while not result["done"]:
            elapsed = time.monotonic() - t0
            if time.monotonic() - last_stage > 1.1:
                stage_idx = min(stage_idx + 1, len(_SCAN_STAGES) - 1)
                last_stage = time.monotonic()
            frame = FRAMES[frame_idx % len(FRAMES)]; frame_idx += 1
            stage = _SCAN_STAGES[stage_idx]
            dots = "." * ((frame_idx // 2) % 4)
            line = (c(f"{elapsed:6.2f}s", C.GREY_DARK) + "  "
                    + c(frame, C.CYAN, bold=True) + "  "
                    + c(label, C.BLUE_LIGHT, bold=True) + "  "
                    + c("·", C.BLUE_DARK) + "  "
                    + c(_truncate(target, 30), C.CYAN) + "  "
                    + c("·", C.BLUE_DARK) + "  "
                    + c(stage + dots, C.BLUE_SOFT))
            if visible_len(line) > tw - 2:
                line = line[:tw - 3]
            sys.stdout.write(_clr_line() + "  " + line
                              + (_CLR_EOL if _USE_COLOR else ""))
            sys.stdout.flush()
            time.sleep(0.08)

        sys.stdout.write(_clr_line()); sys.stdout.flush()
        elapsed = time.monotonic() - t0
        resp = result["resp"]

        clear_screen(); print_banner()
        extra = [("Target", _truncate(target, 50), C.CYAN),
                 ("Mode", mode, C.MAGENTA if mode == "expert" else C.GREEN)]
        _summary_header(label, resp, elapsed, extra=extra)
        if result["error"]:
            print(); print("  " + c(f"✖ Error: {result['error']}", C.RED))
            pause(); continue
        render_result(resp, endpoint, label)
        print(); pause()


# ═══════════════════════════════════════════════════════════════════════════
# TOOLS
# ═══════════════════════════════════════════════════════════════════════════
def tools_flow():
    if not _client_required(): return
    TOOLS_ITEMS = [
        ("1", "List tools",         "GET",  "/api/tools"),
        ("2", "Module status",      "GET",  "/api/modules/status"),
        ("3", "System stats",       "GET",  "/api/system/stats"),
        ("4", "Recent logs",        "GET",  "/api/logs?lines=80"),
        ("5", "Wordlist status",    "GET",  "/api/wordlists/status"),
        ("6", "Wordlist sync",      "POST", "/api/wordlists/sync"),
        ("7", "API-key wordlists",  "GET",  "/api/apikey/wordlists"),
        ("8", "API-key proxies",    "GET",  "/api/apikey/proxies"),
        ("9", "Port scan validate", "GET",  "/api/portscan/validate"),
    ]
    while True:
        clear_screen(); print_banner()
        _menu_render("TOOLS · SYSTEM & CONTENT",
                     [(k, l, e) for k, l, _m, e in TOOLS_ITEMS]
                     + [("B", "Back", "return to main menu")])
        choice = prompt(c("Tool", C.BLUE_SOFT) + " › ").strip().upper()
        if choice in ("B", "") or choice.lower() in BACK_KEYS: return
        matched = None
        for k, label, method, endpoint in TOOLS_ITEMS:
            if choice == k:
                matched = (label, method, endpoint); break
        if not matched:
            print("  " + c("✖ Invalid.", C.RED)); time.sleep(0.8); continue
        label, method, endpoint = matched
        clear_screen(); print_banner()
        section_header(label.upper(), width=72)
        print("  " + c(f"{method}  {endpoint}", C.GREY_DARK, dim=True))
        print()
        t0 = time.monotonic()
        resp = (_client.post(endpoint, json={}, timeout=300)
                if method == "POST"
                else _client.get(endpoint, timeout=60))
        elapsed = time.monotonic() - t0
        _summary_header(label, resp, elapsed)
        show_response(resp, label); print(); pause()


# ═══════════════════════════════════════════════════════════════════════════
# MHDDOS
# ═══════════════════════════════════════════════════════════════════════════
def mhddos_flow():
    if not _client_required(): return
    while True:
        clear_screen(); print_banner()
        _menu_render("MHDDOS · ATTACK PANEL", [
            ("1", "List methods", "Layer4 / Layer7 catalogue"),
            ("2", "Start attack", "POST /api/mhddos/start"),
            ("3", "Stop attack",  "POST /api/mhddos/stop"),
            ("4", "Stop all",     "POST /api/mhddos/stop_all"),
            ("5", "Status",       "GET  /api/mhddos/status"),
            ("6", "History",      "GET  /api/mhddos/history"),
            ("B", "Back",         "return to main menu"),
        ])
        choice = prompt(c("Action", C.BLUE_SOFT) + " › ").strip().upper()
        if choice in ("B", "") or choice.lower() in BACK_KEYS: return
        if choice == "1":
            show_response(_client.get("/api/mhddos/methods", timeout=30),
                          "MHDDoS methods"); pause(); continue
        if choice == "2":
            method = prompt(c("Method (GET/TCP/UDP…)", C.BLUE_SOFT)
                            + " › ").strip().upper()
            if not method or method.lower() in BACK_KEYS: continue
            target = ask_target("target (host:port or URL)")
            if target is None: continue
            try: threads = int(prompt(c("Threads [10]", C.BLUE_SOFT)
                                      + " › ") or 10)
            except ValueError: threads = 10
            try: duration = int(prompt(c("Duration [60]", C.BLUE_SOFT)
                                       + " › ") or 60)
            except ValueError: duration = 60
            payload = {"method": method, "target": target,
                       "threads": threads, "duration": duration}
            show_response(_client.post("/api/mhddos/start", json=payload,
                                        timeout=120),
                          f"MHDDoS start · {method} {target}")
            pause(); continue
        if choice == "3":
            aid = prompt(c("Attack ID", C.BLUE_SOFT) + " › ").strip()
            if not aid or aid.lower() in BACK_KEYS: continue
            show_response(_client.post("/api/mhddos/stop",
                                        json={"attack_id": aid}, timeout=60),
                          f"MHDDoS stop · {aid}")
            pause(); continue
        if choice == "4":
            show_response(_client.post("/api/mhddos/stop_all",
                                        json={}, timeout=60),
                          "MHDDoS stop all"); pause(); continue
        if choice == "5":
            show_response(_client.get("/api/mhddos/status", timeout=30),
                          "MHDDoS status"); pause(); continue
        if choice == "6":
            show_response(_client.get("/api/mhddos/history", timeout=30),
                          "MHDDoS history"); pause(); continue


# ═══════════════════════════════════════════════════════════════════════════
# EXPLOIT
# ═══════════════════════════════════════════════════════════════════════════
def exploit_flow():
    if not _client_required(): return
    while True:
        clear_screen(); print_banner()
        _menu_render("EXPLOIT · ANALYTIC MANAGER", [
            ("1", "Stats",       "GET  /api/exploit/stats"),
            ("2", "List",        "GET  /api/exploit/list"),
            ("3", "Search",      "POST /api/exploit/search"),
            ("4", "Bruteforce",  "POST /api/exploit/bruteforce"),
            ("5", "SQL inject",  "POST /api/exploit/sql_inject"),
            ("6", "XSS run",     "POST /api/exploit/xss"),
            ("B", "Back",        "return to main menu"),
        ])
        choice = prompt(c("Action", C.BLUE_SOFT) + " › ").strip().upper()
        if choice in ("B", "") or choice.lower() in BACK_KEYS: return
        if choice == "1":
            show_response(_client.get("/api/exploit/stats", timeout=30),
                          "Exploit stats"); pause(); continue
        if choice == "2":
            show_response(_client.get("/api/exploit/list", timeout=60),
                          "Exploit list"); pause(); continue
        if choice == "3":
            q = prompt(c("Search query", C.BLUE_SOFT) + " › ").strip()
            if not q or q.lower() in BACK_KEYS: continue
            show_response(_client.post("/api/exploit/search",
                                        json={"query": q}, timeout=60),
                          f"Search · {q}"); pause(); continue
        if choice == "4":
            target = ask_target("target")
            if target is None: continue
            show_response(_client.post("/api/exploit/bruteforce",
                                        json={"target": target}, timeout=300),
                          f"Bruteforce · {target}")
            pause(); continue
        if choice == "5":
            url = ask_target("url")
            if url is None: continue
            show_response(_client.post("/api/exploit/sql_inject",
                                        json={"url": url}, timeout=300),
                          f"SQLi · {url}"); pause(); continue
        if choice == "6":
            url = ask_target("url")
            if url is None: continue
            show_response(_client.post("/api/exploit/xss",
                                        json={"url": url}, timeout=300),
                          f"XSS · {url}"); pause(); continue


# ═══════════════════════════════════════════════════════════════════════════
# DOWNLOADER
# ═══════════════════════════════════════════════════════════════════════════
def downsea_flow():
    if not _client_required(): return
    while True:
        clear_screen(); print_banner()
        _menu_render("DOWNLOADER · DOWNSEA", [
            ("1", "TikTok download", "GET /api/downloader/tiktok"),
            ("2", "Pinterest search","GET /api/downloader/pinterest"),
            ("3", "Service health",  "GET /api/downloader/health"),
            ("B", "Back",            "return to main menu"),
        ])
        choice = prompt(c("Action", C.BLUE_SOFT) + " › ").strip().upper()
        if choice in ("B", "") or choice.lower() in BACK_KEYS: return
        from urllib.parse import quote
        if choice == "1":
            url = ask_target("tiktok url")
            if url is None: continue
            show_response(_client.get(
                f"/api/downloader/tiktok?url={quote(url, safe='')}",
                timeout=60), "TikTok download")
            pause(); continue
        if choice == "2":
            q = prompt(c("Search query", C.BLUE_SOFT) + " › ").strip()
            if not q or q.lower() in BACK_KEYS: continue
            show_response(_client.get(
                f"/api/downloader/pinterest?q={quote(q, safe='')}",
                timeout=60), f"Pinterest · {q}")
            pause(); continue
        if choice == "3":
            show_response(_client.get("/api/downloader/health", timeout=15),
                          "Downsea health"); pause(); continue


def server_reconfig_flow():
    clear_screen(); print_banner()
    print("  " + c("Reconnect to a different Emergens server.",
                    C.BLUE_SOFT)); print()
    raw_url = prompt(c("Server URL", C.BLUE_SOFT)
                     + " " + c("[http://localhost:8080]", C.GREY) + " › ")
    if raw_url.lower() in BACK_KEYS: return
    url = normalize_url(raw_url) if raw_url else "http://localhost:8080"
    if auto_connect(url=url, auto_launch=True, silent=False):
        print("  " + c("✓ Server configured.", C.GREEN, bold=True))
    else:
        print("  " + c("◼ Cancelled.", C.YELLOW))
    pause()


# ═══════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════════════════
def main_menu_loop():
    while True:
        clear_screen(); print_banner()
        if _client is not None:
            tag = c(f"● {_client.base_url}", C.CYAN)
            who = _client.describe()
            backend = ""
            if _server_thread is not None and _server_thread.is_alive():
                backend = (c("   ·   ", C.GREY_DARK, dim=True)
                           + c("backend: local thread", C.BLUE_SOFT,
                                dim=True))
            print("  " + c("Server:", C.BLUE_SOFT) + " " + tag
                  + c("   ·   ", C.GREY_DARK, dim=True)
                  + c("User:", C.BLUE_SOFT) + " " + who + backend)
        else:
            print("  " + c("Server:", C.BLUE_SOFT) + " "
                  + c("● not configured", C.RED))
        print()
        print_main_menu()
        raw = prompt(c("Select menu", C.BLUE_SOFT) + " › ").strip().lower()
        if raw in BACK_KEYS or raw == "":
            print(); print("  " + c("◼ Exiting.", C.BLUE_LIGHT)); print()
            return
        if   raw == "1": scan_flow()
        elif raw == "2": scan_all_flow()
        elif raw == "3": tools_flow()
        elif raw == "4": mhddos_flow()
        elif raw == "5": exploit_flow()
        elif raw == "6": downsea_flow()
        elif raw == "7": webhost_flow()
        elif raw == "8": server_reconfig_flow()
        else:
            print("  " + c("✖ Invalid.", C.RED)); time.sleep(0.8)


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY
# ═══════════════════════════════════════════════════════════════════════════
def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("--help", "-h"):
        clear_screen()
        print_banner()
        print("  " + c("Usage:", C.BLUE, bold=True) + " python3 terminal.py")
        print("  " + c("Env:", C.BLUE, bold=True)
              + "   EMERGENS_URL, EMERGENS_USER, EMERGENS_PASS, PORT")
        print(); return

    env_port = os.getenv("PORT")
    if env_port:
        try: port = int(env_port)
        except ValueError: port = _default_port()
        clear_screen()
        print_banner()
        modules = detect_modules(); app_name = detect_app()
        display_boot_sequence(modules, app_name)
        print()
        app = _load_flask_app()
        if app is None:
            print("  " + c("✖ Could not import Flask app.",
                            C.RED, bold=True))
            sys.exit(1)
        print()
        print("  " + c("▲  EMERGENS READY", C.WHITE, bold=True)
              + "   " + c("→", C.BLUE) + "   "
              + c(f"http://localhost:{port}/dashboard.html",
                   C.CYAN, bold=True))
        print()
        try:
            app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
        except KeyboardInterrupt:
            print(); print("  " + c("◼ Shutdown.", C.BLUE_LIGHT))
        return

    clear_screen()
    print_banner()
    modules = detect_modules()
    app_name = detect_app()
    display_boot_sequence(modules, app_name)

    auto_connect(auto_launch=True, silent=False)
    main_menu_loop()


if __name__ == "__main__":
    main()