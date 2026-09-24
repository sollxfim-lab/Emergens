#!/usr/bin/env python3
"""
Oxysintx — API Key / Secret Scanner Module (v6.1.1)
====================================================

Fixes vs v6.1.0:
  • FIXED: `global MIN_EXTRACTED_LENGTH, MIN_SECRET_ENTROPY` moved to top of main()
  • FIXED: `looks_like_secret()` / `_char_diversity_ok()` resolve min_len at CALL time
  • FIXED: `_rule_can_produce_secret()` removed dead loop
  • Strict plaintext keyword parser: plain words → \bword\b, <8 chars discarded
  • Auto-invoke Cloudflare bypass when CF is detected

Pengarang: Yanxzyx
"""

from __future__ import annotations

import os
import re
import csv
import io
import math
import json
import time
import random
import shutil
import hashlib
import logging
import argparse
import fnmatch
import tempfile
import zipfile
import tarfile
import threading
import requests
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Iterable, Set, Callable
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ── TOML parser ────────────────────────────────────────────────────────────
try:
    import tomllib as _toml               # type: ignore
    _HAS_TOML = True
except ImportError:
    _toml = None
    _HAS_TOML = False
    try:
        import toml as _toml              # type: ignore
        _HAS_TOML = True
    except ImportError:
        try:
            import tomli as _toml         # type: ignore
            _HAS_TOML = True
        except ImportError:
            _HAS_TOML = False

# ── Cloudflare bypass libraries (all optional) ────────────────────────────
try:
    from curl_cffi import requests as curl_requests   # type: ignore
    _HAS_CURL_CFFI = True
except ImportError:
    curl_requests = None
    _HAS_CURL_CFFI = False

try:
    import cloudscraper                                 # type: ignore
    _HAS_CLOUDSCRAPER = True
except ImportError:
    cloudscraper = None
    _HAS_CLOUDSCRAPER = False


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════
logger = logging.getLogger("oxysintx.scan_apikey")
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
# METADATA
# ═══════════════════════════════════════════════════════════════════════════
__version__ = "6.1.1"
__author__ = "Yanxzyx"

TOOL_INFO = {
    "name": "API Key / Secret Scanner",
    "version": __version__,
    "description": (
        "Professional-grade secret scanner with GitHub wordlist + proxy "
        "auto-sync, multi-layer Cloudflare bypass, and strict "
        "false-positive filtering."
    ),
    "category": "Web Vulnerability",
    "author": __author__,
}
TOOL_KIND = "scanner"


# ═══════════════════════════════════════════════════════════════════════════
# PATHS
# ═══════════════════════════════════════════════════════════════════════════
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORDLIST_DIR  = _PROJECT_ROOT / "wordlist"
PROXY_DIR     = _PROJECT_ROOT / "proxy"
CF_CACHE_DIR  = _PROJECT_ROOT / "data" / "cf_cache"


# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
MAX_FILE_SIZE         = 5 * 1024 * 1024
MAX_URL_RESPONSE_SIZE = 10 * 1024 * 1024
MAX_ARCHIVE_UNPACKED  = 200 * 1024 * 1024
MAX_ARCHIVE_ENTRIES   = 10_000
MAX_ARCHIVE_RATIO     = 100
MAX_LINE_LENGTH       = 20_000
LINE_OVERLAP          = 512
DEFAULT_TIMEOUT       = 20
DEFAULT_USER_AGENT    = f"Oxysintx-APIScanner/{__version__} (+https://oxysintx.local)"
SCANNER_VERSION       = __version__

PROXY_DOWNLOAD_COOLDOWN  = 300.0
PROXY_DOWNLOAD_RETRIES   = 3
PROXY_DOWNLOAD_BACKOFF   = 1.5
PROXY_DOWNLOAD_TIMEOUT   = 25.0
PROXY_BREAKER_FAIL_LIMIT = 3
PROXY_MAX_BLACKLIST      = 200
DEFAULT_MAX_PROXY_ATTEMPTS = 4

DOWNLOAD_COOLDOWN     = 300.0
DOWNLOAD_RETRIES      = 3
DOWNLOAD_BACKOFF      = 1.5
DOWNLOAD_TIMEOUT      = 25.0
BREAKER_FAIL_LIMIT    = 3
MIN_ACCEPTABLE_RULES  = 3

CF_MAX_ATTEMPTS       = 3
CF_CHALLENGE_TIMEOUT  = 30
CF_COOKIE_TTL         = 3600
CF_CACHE_TTL          = 1800
FLARESOLVERR_URL      = os.getenv("FLARESOLVERR_URL", "").strip()
FLARESOLVERR_TIMEOUT  = 60

# ── Match validation (v6.1.1) ─────────────────────────────────────────────
MIN_EXTRACTED_LENGTH     = 10
MIN_SECRET_ENTROPY       = 2.8
KEYWORD_MIN_LENGTH       = 8
CHAR_DIVERSITY_MIN_RATIO = 0.25

SKIP_BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".svg",
    ".pdf", ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".jar",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".ogg", ".webm",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pyc", ".pyo", ".o", ".a", ".obj",
    ".iso", ".img", ".dmg", ".msi", ".deb", ".rpm",
}

_HTML_RE = re.compile(
    rb"^\s*(?:<!DOCTYPE\s+html|<html|<head|<\?xml|<title)",
    re.IGNORECASE,
)

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

_PROXY_LINE_RE = re.compile(
    r"^(?:(?P<scheme>https?|socks4|socks5)://)?"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{2,5})$"
)

_PLAIN_KEYWORD_RE = re.compile(r"[A-Za-z0-9_\-]+$")


# ═══════════════════════════════════════════════════════════════════════════
# BROWSER HEADERS + STATUS SETS
# ═══════════════════════════════════════════════════════════════════════════
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) "
    "Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
]

_BROWSER_UA_PRIMARY = _UA_POOL[0]
_BROWSER_UA_SECONDARY = _UA_POOL[4]

_BROWSER_HEADERS = {
    "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language":           "en-US,en;q=0.9",
    "Accept-Encoding":           "gzip, deflate, br",
    "Cache-Control":             "no-cache",
    "Pragma":                    "no-cache",
    "DNT":                       "1",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest":            "document",
    "Sec-Fetch-Mode":            "navigate",
    "Sec-Fetch-Site":            "none",
    "Sec-Fetch-User":            "?1",
    "Connection":                "keep-alive",
}

_SOFT_FAIL_CODES      = {401, 403, 405, 410, 451}
_PROXY_TRIGGER_CODES  = {403, 429, 500, 502, 503, 504}


# ═══════════════════════════════════════════════════════════════════════════
# CLOUDFLARE DETECTION
# ═══════════════════════════════════════════════════════════════════════════
_CF_HEADER_MARKERS = (
    "cf-ray", "cf-cache-status", "cf-request-id", "server: cloudflare",
)

_CF_BODY_MARKERS = (
    b"just a moment", b"checking your browser", b"cf-browser-verification",
    b"cf_chl_opt", b"__cf_chl_jschl_tk__", b"cf-challenge",
    b"challenge-platform", b"cf_chl_prog", b"turnstile", b"cf_chl_captcha",
)

_CF_CHALLENGE_STATUS_CODES = {403, 429, 503}

_CF_PROTECTION_TYPES = {
    "uam":          "Cloudflare Under Attack Mode",
    "js_challenge": "Cloudflare JS Challenge",
    "managed":      "Cloudflare Managed Challenge",
    "turnstile":    "Cloudflare Turnstile",
    "waf_block":    "Cloudflare WAF Block (not bypassable)",
    "rate_limit":   "Cloudflare Rate Limit",
    "unknown":      "Cloudflare (unknown)",
}


def _detect_cloudflare(
    resp_headers: Dict[str, str],
    body: bytes,
    status: int,
) -> Optional[str]:
    headers_lower = {k.lower(): (v or "").lower()
                     for k, v in (resp_headers or {}).items()}
    server = headers_lower.get("server", "")
    has_cf_header = "cloudflare" in server or any(
        m in headers_lower for m in _CF_HEADER_MARKERS
    )
    body_lower = (body or b"")[:8192].lower()
    if b"turnstile" in body_lower or b"cf-chl-captcha" in body_lower:
        return "turnstile"
    if b"cf_chl_opt" in body_lower or b"managed challenge" in body_lower:
        return "managed"
    if any(m in body_lower for m in (
        b"just a moment", b"checking your browser",
        b"cf-browser-verification", b"challenge-platform",
    )):
        return "js_challenge"
    if status == 503 and has_cf_header:
        return "uam"
    if status == 429 and has_cf_header:
        return "rate_limit"
    if status == 403 and has_cf_header:
        return "waf_block"
    if has_cf_header and status in _CF_CHALLENGE_STATUS_CODES:
        return "unknown"
    return None


# ═══════════════════════════════════════════════════════════════════════════
# WORDLIST SOURCES + PROXY SOURCES
# ═══════════════════════════════════════════════════════════════════════════
APIKEY_WORDLIST_SOURCES: Dict[str, Dict[str, Any]] = {
    "gitleaks.toml": {
        "url": "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml",
        "source": "gitleaks/gitleaks",
        "license": "MIT", "format": "toml", "min_rules": 50,
    },
    "gitleaks_legacy.toml": {
        "url": "https://raw.githubusercontent.com/zricethezav/gitleaks/master/config/gitleaks.toml",
        "source": "zricethezav/gitleaks",
        "license": "MIT", "format": "toml", "min_rules": 20,
    },
    "trufflehog_regexes.json": {
        "url": "https://raw.githubusercontent.com/dxa4481/truffleHogRegexes/master/truffleHogRegexes/regexes.json",
        "source": "dxa4481/truffleHogRegexes",
        "license": "GPL-3.0", "format": "json", "min_rules": 5,
    },
    "seclists_apikeys.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/objects.txt",
        "source": "danielmiessler/SecLists",
        "license": "MIT", "format": "txt", "min_rules": 5,
    },
}

PROXY_SOURCES: Dict[str, List[str]] = {
    "http": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    ],
    "socks4": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
    ],
    "socks5": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    ],
}

_BUNDLED_PROXIES: List[str] = [
    "8.219.97.248:80",   "20.219.177.116:8080", "47.74.226.4:8888",
    "103.152.112.162:80","103.152.112.145:80",  "104.248.90.104:8080",
    "116.206.244.42:8080","119.3.186.150:80",   "128.199.202.123:8080",
    "165.232.152.237:8080","167.71.5.83:8080",  "178.128.158.238:8080",
    "188.166.83.18:3128","185.199.229.156:80",  "34.81.160.132:80",
    "35.185.224.160:80", "3.122.84.72:80",      "52.196.158.170:80",
    "52.198.85.219:80",  "54.37.24.114:8080",
]


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class Finding:
    source:         str
    line:           int
    pattern_name:   str
    confidence:     str
    match:          str
    extracted_key:  str
    context:        str = ""
    file_type:      str = "text"
    column:         int = 0
    rule_id:        str = ""
    description:    str = ""
    severity:       str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def fingerprint(self) -> str:
        raw = f"{self.source}:{self.line}:{self.pattern_name}:{self.extracted_key}"
        return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:16]


def _p(name: str, regex: str, confidence: str, severity: str,
       desc: str = "") -> Dict[str, Any]:
    return {
        "name": name, "regex": regex,
        "confidence": confidence, "severity": severity,
        "description": desc or name,
    }


# ═══════════════════════════════════════════════════════════════════════════
# BUNDLED PATTERN DATABASE
# ═══════════════════════════════════════════════════════════════════════════
API_KEY_PATTERNS: List[Dict[str, Any]] = [
    _p("AWS Access Key ID", r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b", "high", "critical"),
    _p("AWS Secret Access Key", r"(?i)aws(?:.{0,20})?(?:secret|sk|key)(?:.{0,20})?['\"]([0-9a-zA-Z/+]{40})['\"]", "high", "critical"),
    _p("AWS Session Token", r"(?i)aws(?:.{0,20})?session(?:.{0,20})?['\"]([A-Za-z0-9/+=]{100,})['\"]", "high", "critical"),
    _p("AWS MWS Key", r"\bamzn\.mws\.[0-9a-f\-]{36}\b", "high", "high"),
    _p("Google API Key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "high", "high"),
    _p("Google OAuth Client ID", r"\b[0-9]{10,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", "high", "medium"),
    _p("Google OAuth Client Secret", r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b", "high", "high"),
    _p("Google Service Account JSON", r"\"type\"\s*:\s*\"service_account\"", "medium", "high"),
    _p("Firebase Cloud Messaging Key", r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b", "high", "high"),
    _p("Azure Storage Connection String", r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;EndpointSuffix=core\.windows\.net", "high", "critical"),
    _p("Azure Storage Account Key", r"AccountKey=([A-Za-z0-9+/=]{88})", "high", "critical"),
    _p("GitHub PAT (classic)", r"\bghp_[0-9A-Za-z]{36}\b", "high", "critical"),
    _p("GitHub OAuth Token", r"\bgho_[0-9A-Za-z]{36}\b", "high", "critical"),
    _p("GitHub User-to-Server", r"\bghu_[0-9A-Za-z]{36}\b", "high", "critical"),
    _p("GitHub Server-to-Server", r"\bghs_[0-9A-Za-z]{36}\b", "high", "critical"),
    _p("GitHub Refresh Token", r"\bghr_[0-9A-Za-z]{36}\b", "high", "critical"),
    _p("GitHub Fine-grained PAT", r"\bgithub_pat_[0-9A-Za-z_]{82}\b", "high", "critical"),
    _p("GitLab PAT", r"\bglpat-[0-9A-Za-z\-_]{20}\b", "high", "critical"),
    _p("GitLab Deploy Token", r"\bgldt-[0-9A-Za-z\-_]{20,}\b", "high", "critical"),
    _p("GitLab Runner Token", r"\bglrt-[0-9A-Za-z\-_]{20,}\b", "high", "high"),
    _p("Bitbucket App Password", r"(?i)bitbucket(?:.{0,20})?(?:app[_-]?password|password)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9]{20,})['\"]", "medium", "high"),
    _p("Stripe Live Secret Key", r"\bsk_live_[0-9A-Za-z]{24,}\b", "high", "critical"),
    _p("Stripe Test Secret Key", r"\bsk_test_[0-9A-Za-z]{24,}\b", "high", "high"),
    _p("Stripe Restricted Key", r"\brk_live_[0-9A-Za-z]{24,}\b", "high", "critical"),
    _p("Stripe Publishable Key", r"\bpk_(?:live|test)_[0-9A-Za-z]{24,}\b", "medium", "low"),
    _p("Stripe Webhook Secret", r"\bwhsec_[0-9A-Za-z]{32,}\b", "high", "high"),
    _p("PayPal Braintree Production", r"\baccess_token\$production\$[0-9a-f]{16}\$[0-9a-f]{32}\b", "high", "critical"),
    _p("Square Access Token", r"\bsq0atp-[0-9A-Za-z\-_]{22}\b", "high", "critical"),
    _p("Square OAuth Secret", r"\bsq0csp-[0-9A-Za-z\-_]{43}\b", "high", "critical"),
    _p("Razorpay Key ID", r"\brzp_(?:live|test)_[A-Za-z0-9]{14}\b", "high", "high"),
    _p("OpenAI API Key", r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b", "high", "critical"),
    _p("OpenAI Project Key", r"\bsk-proj-[A-Za-z0-9_\-]{40,}\b", "high", "critical"),
    _p("Anthropic API Key", r"\bsk-ant-(?:api|sid)[0-9]{2}-[A-Za-z0-9_\-]{80,}\b", "high", "critical"),
    _p("Hugging Face Token", r"\bhf_[A-Za-z0-9]{34,40}\b", "high", "high"),
    _p("Replicate API Token", r"\br8_[A-Za-z0-9]{38}\b", "high", "high"),
    _p("Groq API Key", r"\bgsk_[A-Za-z0-9]{52}\b", "high", "high"),
    _p("Perplexity API Key", r"\bpplx-[A-Za-z0-9]{40,}\b", "high", "high"),
    _p("Slack Bot Token", r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b", "high", "critical"),
    _p("Slack User Token", r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}\b", "high", "critical"),
    _p("Slack App Token", r"\bxapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{13}-[a-f0-9]{64}\b", "high", "critical"),
    _p("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}", "high", "high"),
    _p("Discord Bot Token", r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b", "high", "critical"),
    _p("Discord Webhook", r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,}", "high", "high"),
    _p("Telegram Bot Token", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", "high", "critical"),
    _p("Twilio Account SID", r"\bAC[a-f0-9]{32}\b", "high", "high"),
    _p("Twilio API Key SID", r"\bSK[0-9a-fA-F]{32}\b", "high", "high"),
    _p("SendGrid API Key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "high", "critical"),
    _p("Mailgun API Key", r"\bkey-[0-9a-zA-Z]{32}\b", "high", "high"),
    _p("Mailchimp API Key", r"\b[0-9a-f]{32}-us\d{1,2}\b", "high", "high"),
    _p("MySQL Connection String", r"mysql://[^\s:@]+:[^\s@]+@[^\s/]+(?:/\S*)?", "medium", "high"),
    _p("PostgreSQL Connection String", r"postgres(?:ql)?://[^\s:@]+:[^\s@]+@[^\s/]+(?:/\S*)?", "medium", "high"),
    _p("MongoDB Connection String", r"mongodb(?:\+srv)?://[^\s:@]+:[^\s@]+@[^\s/]+", "high", "critical"),
    _p("Redis Connection String", r"rediss?://[^\s:@]+:[^\s@]+@[^\s/]+", "medium", "high"),
    _p("Databricks Token", r"\bdapi[a-f0-9]{32}\b", "high", "critical"),
    _p("Supabase Service Key", r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b(?=.*supabase)", "medium", "critical"),
    _p("Firebase Service Account", r'"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----', "high", "critical"),
    _p("PlanetScale Token", r"\bpscale_tkn_[A-Za-z0-9_\-]{40,}\b", "high", "high"),
    _p("Neon API Key", r"\bnapi_[A-Za-z0-9]{40,}\b", "high", "high"),
    _p("Cloudflare Origin CA Key", r"\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b", "high", "critical"),
    _p("DigitalOcean PAT", r"\bdop_v1_[a-f0-9]{64}\b", "high", "critical"),
    _p("DigitalOcean OAuth", r"\bdoo_v1_[a-f0-9]{64}\b", "high", "high"),
    _p("Pulumi Access Token", r"\bpul-[a-f0-9]{40}\b", "high", "high"),
    _p("Terraform Cloud Token", r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}\b", "high", "critical"),
    _p("JFrog Artifactory Token", r"\bAKCp[A-Za-z0-9]{60,}\b", "high", "critical"),
    _p("NPM Access Token", r"\bnpm_[A-Za-z0-9]{36}\b", "high", "high"),
    _p("PyPI Upload Token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b", "high", "critical"),
    _p("Docker Hub PAT", r"\bdckr_pat_[A-Za-z0-9_\-]{27}\b", "high", "high"),
    _p("Grafana API Key", r"\beyJrIjoi[A-Za-z0-9_\-]{60,}\b", "high", "high"),
    _p("Grafana Service Account", r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b", "high", "high"),
    _p("Sentry DSN", r"https://[a-f0-9]{32}@[a-z0-9.\-]+\.ingest\.sentry\.io/\d+", "high", "medium"),
    _p("Sentry Auth Token", r"\bsntrys_[A-Za-z0-9_\-]{64,}\b", "high", "high"),
    _p("Notion Integration Token", r"\bsecret_[A-Za-z0-9]{43}\b", "high", "high"),
    _p("Notion Internal Token", r"\bntn_[A-Za-z0-9]{40,}\b", "high", "high"),
    _p("Airtable PAT", r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b", "high", "high"),
    _p("Asana PAT", r"\b[0-9]/[0-9]{16}/[0-9]{16}:[a-f0-9]{32}\b", "high", "high"),
    _p("Atlassian API Token", r"\bATATT3[A-Za-z0-9_\-=]{180,}\b", "high", "critical"),
    _p("ClickUp API Token", r"\bpk_[0-9]{8}_[A-Z0-9]{32}\b", "high", "high"),
    _p("Linear API Key", r"\blin_api_[A-Za-z0-9]{40}\b", "high", "high"),
    _p("HubSpot API Key", r"\bpat-(?:na1|eu1)-[a-f0-9\-]{36}\b", "high", "high"),
    _p("Salesforce Token", r"\b00D[a-zA-Z0-9]{12}![A-Za-z0-9._]{90,}\b", "high", "critical"),
    _p("Shopify Access Token", r"\bshpat_[a-f0-9]{32}\b", "high", "critical"),
    _p("Shopify Custom App Token", r"\bshpca_[a-f0-9]{32}\b", "high", "critical"),
    _p("Shopify Private App Password", r"\bshppa_[a-f0-9]{32}\b", "high", "critical"),
    _p("WooCommerce Consumer Key", r"\bck_[a-f0-9]{40}\b", "high", "high"),
    _p("WooCommerce Consumer Secret", r"\bcs_[a-f0-9]{40}\b", "high", "high"),
    _p("Bitcoin Private Key (WIF)", r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b", "medium", "critical"),
    _p("Ethereum Private Key (hex)", r"\b(?:private[_-]?key|privkey)['\"]?\s*[:=]\s*['\"]?(?:0x)?([a-fA-F0-9]{64})['\"]?", "medium", "critical"),
    _p("BIP39 Mnemonic (12 words)", r"\b(?:[a-z]{3,8}\s+){11}[a-z]{3,8}\b(?=.*(?:seed|mnemonic|wallet))", "low", "critical"),
    _p("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "high", "critical"),
    _p("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "high", "critical"),
    _p("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "high", "critical"),
    _p("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "high", "critical"),
    _p("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "high", "critical"),
    _p("JWT Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "medium", "medium"),
    _p("Apple App-Specific Password", r"\b[a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4}\b(?=.*apple)", "low", "high"),
    _p("Android Keystore Password", r"(?i)(?:keystore|key)[_-]?password['\"]?\s*[:=]\s*['\"]([^\s'\"]{6,})['\"]", "low", "medium"),
    _p("Base32-Crockford Token (16)", r"\b[A-HJ-NP-Z2-9]{16}\b", "low", "medium"),
    _p("Base32-Crockford Token (24+)", r"\b[A-HJ-NP-Z2-9]{24,}\b", "low", "high"),
    _p("Base32-Crockford Grouped", r"\b[A-HJ-NP-Z2-9]{4,8}(?:-[A-HJ-NP-Z2-9]{4,8}){2,}\b", "medium", "medium"),
    _p("Generic API Key Assignment", r"(?i)\b(?:api[_-]?key|apikey|api[_-]?secret|app[_-]?key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,64})['\"]", "medium", "high"),
    _p("Generic Bearer Token", r"(?i)\b(?:bearer|authorization)\s*[:=]\s*['\"]?Bearer\s+([a-zA-Z0-9_\-\.]{20,})['\"]?", "medium", "high"),
    _p("Generic Password in Config", r"(?i)\bpassword['\"]?\s*[:=]\s*['\"]([^\s'\"]{8,})['\"]", "low", "medium"),
    _p("Generic Client Secret", r"(?i)\bclient[_-]?secret['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]", "medium", "high"),
    _p("Generic Access Token", r"(?i)\baccess[_-]?token['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]", "medium", "high"),
    _p("Generic Private Key", r"(?i)\bprivate[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9+/=_\-]{20,})['\"]", "medium", "critical"),
    _p("Password in URL", r"https?://[^:\s/]+:[^@\s/]+@[^\s/]+", "medium", "high"),
    _p("Base64 Encoded Secret Hint", r"(?i)(?:secret|token|key)\s*[:=]\s*['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]", "low", "medium"),
]


_PLACEHOLDER_TOKENS = {
    "example", "changeme", "placeholder", "todo", "dummy", "sample",
    "testing", "test", "fake", "invalid", "null", "none", "undefined",
    "localhost", "qwerty", "xxxxx", "aaaaa", "11111", "00000",
    "your_api_key", "your_secret", "your_token", "replace_me",
}


# ═══════════════════════════════════════════════════════════════════════════
# ENTROPY + SECRET VALIDATION (v6.1.1 — dynamic min_len)
# ═══════════════════════════════════════════════════════════════════════════
def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts: Dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _char_diversity_ok(s: str, min_len: Optional[int] = None) -> bool:
    """v6.1.1: min_len resolved at CALL time (CLI-tuning aware)."""
    if min_len is None:
        min_len = MIN_EXTRACTED_LENGTH
    if len(s) < min_len:
        return False
    return (len(set(s)) / len(s)) >= CHAR_DIVERSITY_MIN_RATIO


def looks_like_secret(s: str, min_len: Optional[int] = None) -> bool:
    """Strict validation. v6.1.1: min_len resolved at CALL time."""
    if min_len is None:
        min_len = MIN_EXTRACTED_LENGTH

    if not s or len(s) < min_len:
        return False
    if len(set(s)) <= 2:
        return False
    if not _char_diversity_ok(s, min_len):
        return False

    lowered = s.lower()
    tokens = re.split(r"[_\-./\s]+", lowered)
    if any(tok in _PLACEHOLDER_TOKENS for tok in tokens):
        return False

    classes = sum([
        any(c.islower() for c in s),
        any(c.isupper() for c in s),
        any(c.isdigit() for c in s),
        any(not c.isalnum() for c in s),
    ])
    if classes < 2:
        return False

    if shannon_entropy(s) < MIN_SECRET_ENTROPY:
        return False
    return True


def _rule_can_produce_secret(regex_src: str) -> bool:
    """v6.1.1: cleaned up, no dead loop."""
    src = (regex_src or "").strip()
    if not src:
        return False

    if _PLAIN_KEYWORD_RE.fullmatch(src):
        return len(src) >= KEYWORD_MIN_LENGTH

    expansions = 0
    for m in re.finditer(r"(\+|\*|\{\s*\d+\s*,\s*(\d*)\s*\})", src):
        token = m.group(0)
        if token in ("+", "*"):
            expansions += 1
            continue
        hi = m.group(2)
        if not hi or int(hi) >= MIN_EXTRACTED_LENGTH:
            expansions += 1

    if expansions == 0:
        stripped = re.sub(r"[\\^$.|?*+()\[\]{}]", "", src)
        if len(stripped) < MIN_EXTRACTED_LENGTH:
            return False
    return True


def looks_like_bare_domain(s: str) -> bool:
    if not s or " " in s:
        return False
    candidate = s.strip().split("/", 1)[0].split(":", 1)[0]
    return bool(candidate and _DOMAIN_RE.match(candidate))


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════════════════
# CIRCUIT BREAKER
# ═══════════════════════════════════════════════════════════════════════════
class _SourceBreaker:
    def __init__(self, cooldown: float, fail_limit: int):
        self.cooldown   = cooldown
        self.fail_limit = fail_limit
        self._lock      = threading.Lock()
        self._fails:      Dict[str, int]   = {}
        self._open_until: Dict[str, float] = {}

    def is_open(self, url: str) -> bool:
        with self._lock:
            return time.monotonic() < self._open_until.get(url, 0.0)

    def record_success(self, url: str) -> None:
        with self._lock:
            self._fails.pop(url, None)
            self._open_until.pop(url, None)

    def record_failure(self, url: str) -> None:
        with self._lock:
            n = self._fails.get(url, 0) + 1
            self._fails[url] = n
            if n >= self.fail_limit:
                self._open_until[url] = time.monotonic() + self.cooldown
                logger.warning("[apikey] circuit breaker OPEN for %s", url)


_wordlist_breaker = _SourceBreaker(DOWNLOAD_COOLDOWN, BREAKER_FAIL_LIMIT)
_proxy_breaker    = _SourceBreaker(PROXY_DOWNLOAD_COOLDOWN, PROXY_BREAKER_FAIL_LIMIT)


# ═══════════════════════════════════════════════════════════════════════════
# LOW-LEVEL DOWNLOAD HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def _looks_like_html(raw: bytes) -> bool:
    return bool(_HTML_RE.search(raw[:512]))


def _atomic_write(target: Path, content: str) -> None:
    tmp = target.with_suffix(target.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, target)


def _download_raw(
    url: str, name: str, breaker: _SourceBreaker,
    retries: int, backoff: float, timeout: float,
) -> Optional[bytes]:
    if breaker.is_open(url):
        logger.info("[apikey] breaker open, skip %s", name)
        return None
    last_err: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            logger.info("[apikey] fetching %s (attempt %d/%d)",
                        name, attempt + 1, retries + 1)
            r = requests.get(
                url, timeout=timeout,
                headers={"User-Agent": _BROWSER_UA_PRIMARY},
            )
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            raw = r.content
            if not raw or len(raw) < 32:
                raise RuntimeError("empty response")
            if _looks_like_html(raw):
                raise RuntimeError("HTML page returned, not a data file")
            breaker.record_success(url)
            return raw
        except Exception as exc:
            last_err = exc
            if attempt < retries:
                time.sleep(backoff * (2 ** attempt))
    logger.warning("[apikey] %s failed: %s", name, last_err)
    breaker.record_failure(url)
    return None


# ═══════════════════════════════════════════════════════════════════════════
# WORDLIST PARSERS
# ═══════════════════════════════════════════════════════════════════════════
_wordlist_lock = threading.RLock()
_wordlist_loaded_cache: Optional[List[Dict[str, Any]]] = None


def _ensure_wordlist_dir() -> None:
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)


def _parse_gitleaks_toml(text: str) -> List[Dict[str, Any]]:
    if not _HAS_TOML or _toml is None:
        return []
    try:
        data = _toml.loads(text)
    except Exception as exc:
        logger.warning("[apikey] gitleaks TOML parse failed: %s", exc)
        return []
    rules_in = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules_in, list):
        return []
    out: List[Dict[str, Any]] = []
    for rule in rules_in:
        if not isinstance(rule, dict):
            continue
        rid = rule.get("id")
        regex = rule.get("regex") or rule.get("secretRegex")
        if not rid or not regex:
            continue
        try:
            re.compile(regex)
        except re.error:
            continue
        if not _rule_can_produce_secret(str(regex)):
            continue
        severity = "high"
        tags = rule.get("tags") or []
        if isinstance(tags, list):
            tags_l = [str(t).lower() for t in tags]
            for sev in ("critical", "high", "medium", "low"):
                if sev in tags_l:
                    severity = sev
                    break
        out.append(_p(str(rid), str(regex), "high", severity,
                      str(rule.get("description") or rid)))
    return out


def _parse_trufflehog_json(text: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning("[apikey] truffleHog JSON parse failed: %s", exc)
        return []
    if not isinstance(data, dict):
        return []
    out: List[Dict[str, Any]] = []
    for name, regex in data.items():
        if not isinstance(regex, str):
            continue
        try:
            re.compile(regex)
        except re.error:
            continue
        if not _rule_can_produce_secret(regex):
            continue
        out.append(_p(f"TruffleHog · {name}", regex, "high", "high",
                      f"TruffleHog detector: {name}"))
    return out


def _parse_plaintext_regex_list(text: str) -> List[Dict[str, Any]]:
    """
    v6.1.1 STRICT parser.

    Plain keywords become word-boundary regexes and are discarded if
    shorter than KEYWORD_MIN_LENGTH. This kills the classic FP where
    'B', 'c', 'id', 'v1' matched single characters on any HTML/JS page.
    """
    out: List[Dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "//", ";", "!")):
            continue

        if _PLAIN_KEYWORD_RE.fullmatch(line):
            if len(line) < KEYWORD_MIN_LENGTH:
                continue
            regex = r"\b" + re.escape(line) + r"\b"
            name = f"Keyword · {line}"
            out.append(_p(name, regex, "medium", "low",
                          f"Keyword match: {line}"))
            continue

        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 2:
            name, regex = parts[0], parts[1]
            severity = parts[2] if len(parts) >= 3 else "high"
        else:
            regex = parts[0]
            name = f"Custom · {hashlib.md5(regex.encode()).hexdigest()[:6]}"
            severity = "high"

        try:
            re.compile(regex)
        except re.error:
            continue
        if not _rule_can_produce_secret(regex):
            continue
        out.append(_p(name, regex, "high", severity, name))
    return out


def _extract_rules_from_file(path: Path, fmt: str) -> List[Dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if fmt == "toml":
        return _parse_gitleaks_toml(text)
    if fmt == "json":
        return _parse_trufflehog_json(text)
    if fmt == "txt":
        return _parse_plaintext_regex_list(text)
    return []


def load_wordlist(force_download: bool = False,
                  auto_sync: bool = True) -> List[Dict[str, Any]]:
    global _wordlist_loaded_cache
    with _wordlist_lock:
        if _wordlist_loaded_cache is not None and not force_download:
            return list(_wordlist_loaded_cache)
        _ensure_wordlist_dir()
        rules: List[Dict[str, Any]] = []
        for name, meta in APIKEY_WORDLIST_SOURCES.items():
            path = WORDLIST_DIR / name
            if force_download or not path.exists() or path.stat().st_size < 64:
                if not auto_sync:
                    continue
                raw = _download_raw(
                    meta["url"], meta["source"], _wordlist_breaker,
                    DOWNLOAD_RETRIES, DOWNLOAD_BACKOFF, DOWNLOAD_TIMEOUT,
                )
                if raw is None:
                    continue
                try:
                    header = (
                        f"# {name} — auto-downloaded from {meta['source']}\n"
                        f"# License: {meta.get('license', 'unknown')}\n"
                        f"# Fetched: {_now_iso()}\n"
                        f"# Format : {meta.get('format', 'txt')}\n\n"
                    )
                    _atomic_write(path, header + raw.decode("utf-8", errors="replace"))
                except OSError:
                    continue
            try:
                file_rules = _extract_rules_from_file(path, meta.get("format", "txt"))
            except Exception:
                continue
            min_rules = meta.get("min_rules", MIN_ACCEPTABLE_RULES)
            if len(file_rules) < min_rules:
                logger.debug("[apikey] %s only yielded %d rules (< %d) — skipped",
                             name, len(file_rules), min_rules)
                continue
            rules.extend(file_rules)
        seen: Set[Tuple[str, str]] = set()
        deduped: List[Dict[str, Any]] = []
        for r in rules:
            key = (r["name"], r["regex"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(r)
        _wordlist_loaded_cache = deduped
        logger.info("[apikey] loaded %d external rule(s)", len(deduped))
        return list(deduped)


def ensure_wordlists(force: bool = False) -> Dict[str, Any]:
    _ensure_wordlist_dir()
    out: Dict[str, Any] = {
        "directory": str(WORDLIST_DIR),
        "exists":    WORDLIST_DIR.exists(),
        "sources":   APIKEY_WORDLIST_SOURCES,
        "files":     [],
        "version":   __version__,
    }
    for name, meta in APIKEY_WORDLIST_SOURCES.items():
        path = WORDLIST_DIR / name
        if force and not path.exists():
            raw = _download_raw(
                meta["url"], meta["source"], _wordlist_breaker,
                DOWNLOAD_RETRIES, DOWNLOAD_BACKOFF, DOWNLOAD_TIMEOUT,
            )
            if raw:
                try:
                    _atomic_write(path, raw.decode("utf-8", errors="replace"))
                except OSError:
                    pass
        rules = _extract_rules_from_file(path, meta.get("format", "txt")) \
            if path.exists() else []
        out["files"].append({
            "name": name, "source": meta["source"],
            "format": meta.get("format", "txt"),
            "license": meta.get("license", ""),
            "exists": path.exists(),
            "size": path.stat().st_size if path.exists() else 0,
            "rules": len(rules),
        })
    return out


def reload_cache() -> None:
    global _wordlist_loaded_cache
    with _wordlist_lock:
        _wordlist_loaded_cache = None


# ═══════════════════════════════════════════════════════════════════════════
# PROXY MANAGER
# ═══════════════════════════════════════════════════════════════════════════
class ProxyManager:
    def __init__(
        self,
        proxy_dir: Path = PROXY_DIR,
        auto_sync: bool = True,
        max_proxies: int = 500,
        max_attempts: int = DEFAULT_MAX_PROXY_ATTEMPTS,
    ):
        self.proxy_dir = Path(proxy_dir)
        self.max_proxies = max(1, int(max_proxies))
        self.max_attempts = max(1, int(max_attempts))
        self._lock = threading.RLock()
        self._proxies: List[Dict[str, Any]] = []
        self._cursor = 0
        self._blacklist: Set[str] = set()
        self._ensure_dirs()
        if auto_sync:
            try:
                self.ensure_proxies()
            except Exception as exc:
                logger.warning("[apikey] proxy sync failed: %s", exc)
        self._load()

    def _ensure_dirs(self) -> None:
        self.proxy_dir.mkdir(parents=True, exist_ok=True)

    @property
    def all_path(self) -> Path:
        return self.proxy_dir / "proxies.txt"

    @property
    def meta_path(self) -> Path:
        return self.proxy_dir / "meta.json"

    def _scheme_path(self, scheme: str) -> Path:
        return self.proxy_dir / f"{scheme}.txt"

    def ensure_proxies(self, force: bool = False) -> Dict[str, Any]:
        self._ensure_dirs()
        merged: List[str] = []
        source_meta: Dict[str, Any] = {}
        for scheme, urls in PROXY_SOURCES.items():
            scheme_file = self._scheme_path(scheme)
            ips: List[str] = []
            if not force and scheme_file.exists() and scheme_file.stat().st_size > 64:
                try:
                    for line in scheme_file.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines():
                        parsed = self._parse_proxy_line(line, scheme)
                        if parsed:
                            ips.append(parsed)
                except OSError:
                    pass
            if not ips:
                for url in urls:
                    raw = _download_raw(
                        url, url.split("/")[-3] + "/" + url.split("/")[-1],
                        _proxy_breaker,
                        PROXY_DOWNLOAD_RETRIES, PROXY_DOWNLOAD_BACKOFF,
                        PROXY_DOWNLOAD_TIMEOUT,
                    )
                    if raw is None:
                        continue
                    for line in raw.decode("utf-8", errors="replace").splitlines():
                        parsed = self._parse_proxy_line(line, scheme)
                        if parsed:
                            ips.append(parsed)
                    if ips:
                        break
                if ips:
                    try:
                        _atomic_write(scheme_file,
                                      "\n".join(sorted(set(ips))) + "\n")
                        logger.info("[apikey] saved %d %s proxies",
                                    len(set(ips)), scheme)
                    except OSError:
                        pass
            source_meta[scheme] = {"count": len(set(ips))}
            merged.extend(ips)
        if not merged:
            logger.warning("[apikey] all GitHub proxy sources failed — "
                           "using bundled fallback list")
            for entry in _BUNDLED_PROXIES:
                parsed = self._parse_proxy_line(entry, "http")
                if parsed:
                    merged.append(parsed)
        unique = sorted(set(merged))
        try:
            _atomic_write(self.all_path, "\n".join(unique) + "\n")
        except OSError:
            pass
        meta = {
            "version":    __version__,
            "updated_at": _now_iso(),
            "total":      len(unique),
            "by_scheme":  source_meta,
            "sources":    PROXY_SOURCES,
        }
        try:
            _atomic_write(self.meta_path, json.dumps(meta, indent=2))
        except OSError:
            pass
        return meta

    def _parse_proxy_line(self, line: str, default_scheme: str) -> Optional[str]:
        s = (line or "").strip()
        if not s or s.startswith(("#", "//", ";")):
            return None
        m = _PROXY_LINE_RE.match(s)
        if not m:
            return None
        scheme = m.group("scheme") or default_scheme
        ip = m.group("ip")
        port = int(m.group("port"))
        if port < 1 or port > 65535:
            return None
        for octet in ip.split("."):
            try:
                v = int(octet)
            except ValueError:
                return None
            if v < 0 or v > 255:
                return None
        return f"{scheme}://{ip}:{port}"

    def _load(self) -> None:
        with self._lock:
            self._proxies = []
            self._cursor = 0
            self._blacklist = set()
            if not self.all_path.exists():
                return
            try:
                lines = self.all_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                return
            for line in lines[: self.max_proxies]:
                url = self._parse_proxy_line(line, "http")
                if not url:
                    continue
                parsed = urlparse(url)
                self._proxies.append({
                    "url": url, "scheme": parsed.scheme,
                    "ip": parsed.hostname or "", "port": parsed.port or 0,
                    "ok": 0, "fail": 0,
                })
            logger.info("[apikey] loaded %d proxy(ies) from %s",
                        len(self._proxies), self.all_path)

    def has_proxies(self) -> bool:
        with self._lock:
            return bool(self._proxies)

    def get_next(self) -> Optional[Dict[str, str]]:
        with self._lock:
            if not self._proxies:
                return None
            n = len(self._proxies)
            for _ in range(n):
                idx = self._cursor % n
                self._cursor = (self._cursor + 1) % n
                p = self._proxies[idx]
                if p["url"] in self._blacklist:
                    continue
                return {"http": p["url"], "https": p["url"]}
            return None

    def mark_success(self, proxy_url: str) -> None:
        with self._lock:
            for p in self._proxies:
                if p["url"] == proxy_url:
                    p["ok"] += 1
                    return

    def mark_failure(self, proxy_url: str) -> None:
        with self._lock:
            for p in self._proxies:
                if p["url"] == proxy_url:
                    p["fail"] += 1
                    if len(self._blacklist) < PROXY_MAX_BLACKLIST and p["fail"] >= 2:
                        self._blacklist.add(proxy_url)
                    return

    def reload(self) -> None:
        self._load()

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total":     len(self._proxies),
                "blacklist": len(self._blacklist),
                "by_scheme": {
                    "http":   sum(1 for p in self._proxies if p["scheme"] == "http"),
                    "socks4": sum(1 for p in self._proxies if p["scheme"] == "socks4"),
                    "socks5": sum(1 for p in self._proxies if p["scheme"] == "socks5"),
                },
                "healthy": sum(1 for p in self._proxies if p["ok"] > p["fail"]),
            }


_proxy_manager: Optional[ProxyManager] = None
_proxy_manager_lock = threading.Lock()


def get_proxy_manager(auto_sync: bool = True) -> ProxyManager:
    global _proxy_manager
    with _proxy_manager_lock:
        if _proxy_manager is None:
            _proxy_manager = ProxyManager(auto_sync=auto_sync)
        return _proxy_manager


def ensure_proxies(force: bool = False) -> Dict[str, Any]:
    return get_proxy_manager().ensure_proxies(force=force)


def reload_proxy_cache() -> None:
    get_proxy_manager().reload()


# ═══════════════════════════════════════════════════════════════════════════
# CLOUDFLARE BYPASS ENGINE
# ═══════════════════════════════════════════════════════════════════════════
class CloudflareBypass:
    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        cf_timeout: int = CF_CHALLENGE_TIMEOUT,
        verify_tls: bool = False,
        proxy_dict: Optional[Dict[str, str]] = None,
        flaresolverr_url: str = FLARESOLVERR_URL,
    ):
        self.timeout = timeout
        self.cf_timeout = cf_timeout
        self.verify_tls = verify_tls
        self.proxy_dict = proxy_dict
        self.flaresolverr_url = flaresolverr_url

        self._lock = threading.RLock()
        self._cookie_cache: Dict[str, Dict[str, Any]] = {}
        CF_CACHE_DIR.mkdir(parents=True, exist_ok=True)

        self._cloudscraper_client = None
        self._curl_cffi_session = None

    def _get_cached_cookies(self, host: str) -> Optional[Dict[str, str]]:
        with self._lock:
            entry = self._cookie_cache.get(host)
            if not entry:
                return None
            if time.time() - entry["ts"] > CF_COOKIE_TTL:
                self._cookie_cache.pop(host, None)
                return None
            return dict(entry["cookies"])

    def _store_cookies(self, host: str, cookies: Dict[str, str]) -> None:
        if not cookies:
            return
        with self._lock:
            self._cookie_cache[host] = {
                "cookies": dict(cookies),
                "ts": time.time(),
            }

    def _get_curl_cffi(self):
        if not _HAS_CURL_CFFI:
            return None
        if self._curl_cffi_session is None:
            try:
                self._curl_cffi_session = curl_requests.Session()
                self._curl_cffi_session.headers.update(
                    {k: v for k, v in _BROWSER_HEADERS.items()
                     if k != "Accept-Encoding"}
                )
            except Exception as exc:
                logger.debug("[apikey/cf] curl_cffi init failed: %s", exc)
                return None
        return self._curl_cffi_session

    def _fetch_via_curl_cffi(
        self, url: str, host: str
    ) -> Optional[Tuple[bytes, Dict[str, str], int]]:
        sess = self._get_curl_cffi()
        if sess is None:
            return None
        try:
            r = sess.get(
                url,
                impersonate="chrome",
                timeout=self.timeout,
                verify=self.verify_tls,
                proxies=self.proxy_dict,
                allow_redirects=True,
                headers={"User-Agent": _BROWSER_UA_PRIMARY},
            )
            body = r.content or b""
            headers = dict(r.headers)
            cookies = {k: v for k, v in (r.cookies or {}).items()}
            self._store_cookies(host, cookies)
            return body, headers, r.status_code
        except Exception as exc:
            logger.debug("[apikey/cf] curl_cffi fetch failed: %s", exc)
            return None

    def _get_cloudscraper(self):
        if not _HAS_CLOUDSCRAPER:
            return None
        if self._cloudscraper_client is None:
            try:
                self._cloudscraper_client = cloudscraper.create_scraper(
                    browser={
                        "browser": "chrome",
                        "platform": "windows",
                        "mobile": False,
                        "desktop": True,
                    },
                    interpreter="native",
                    delay=3,
                )
                if self.proxy_dict:
                    self._cloudscraper_client.proxies.update(self.proxy_dict)
            except Exception as exc:
                logger.debug("[apikey/cf] cloudscraper init failed: %s", exc)
                return None
        return self._cloudscraper_client

    def _fetch_via_cloudscraper(
        self, url: str, host: str
    ) -> Optional[Tuple[bytes, Dict[str, str], int]]:
        client = self._get_cloudscraper()
        if client is None:
            return None
        try:
            cached = self._get_cached_cookies(host)
            r = client.get(
                url,
                timeout=self.cf_timeout,
                verify=self.verify_tls,
                allow_redirects=True,
                headers={"User-Agent": _BROWSER_UA_PRIMARY},
                cookies=cached or None,
            )
            body = r.content or b""
            headers = dict(r.headers)
            cookies = {k: v for k, v in (r.cookies or {}).items()}
            self._store_cookies(host, cookies)
            return body, headers, r.status_code
        except Exception as exc:
            logger.debug("[apikey/cf] cloudscraper fetch failed: %s", exc)
            return None

    def _fetch_via_flaresolverr(
        self, url: str, host: str
    ) -> Optional[Tuple[bytes, Dict[str, str], int]]:
        if not self.flaresolverr_url:
            return None
        try:
            payload = {
                "cmd": "request.get",
                "url": url,
                "maxTimeout": self.cf_timeout * 1000,
            }
            r = requests.post(
                self.flaresolverr_url.rstrip("/") + "/v1",
                json=payload,
                timeout=self.cf_timeout + 10,
            )
            if r.status_code != 200:
                return None
            data = r.json() if r.content else {}
            if data.get("status") != "ok":
                return None
            solution = data.get("solution") or {}
            body = (solution.get("response") or "").encode("utf-8", "ignore")
            status = int(solution.get("status") or 0)
            headers = solution.get("headers") or {}
            cookies_list = solution.get("cookies") or []
            cookies: Dict[str, str] = {}
            for c in cookies_list:
                name = c.get("name")
                value = c.get("value")
                if name and value is not None:
                    cookies[name] = value
            self._store_cookies(host, cookies)
            return body, headers, status
        except Exception as exc:
            logger.debug("[apikey/cf] flaresolverr fetch failed: %s", exc)
            return None

    def _fetch_manual(
        self, url: str, host: str
    ) -> Optional[Tuple[bytes, Dict[str, str], int]]:
        try:
            headers = dict(_BROWSER_HEADERS)
            headers["User-Agent"] = random.choice(_UA_POOL)
            cached = self._get_cached_cookies(host)
            s = requests.Session()
            r = s.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_tls,
                proxies=self.proxy_dict,
                allow_redirects=True,
                cookies=cached or None,
            )
            body = r.content or b""
            resp_headers = dict(r.headers)
            cookies = {k: v for k, v in (r.cookies or {}).items()}
            self._store_cookies(host, cookies)
            return body, resp_headers, r.status_code
        except Exception as exc:
            logger.debug("[apikey/cf] manual fetch failed: %s", exc)
            return None

    def fetch(
        self, url: str
    ) -> Tuple[Optional[bytes], Dict[str, str], int, str]:
        host = urlparse(url).hostname or ""

        strategies: List[Tuple[str, Callable[[str, str], Any]]] = []
        if _HAS_CURL_CFFI:
            strategies.append(("curl_cffi", self._fetch_via_curl_cffi))
        if _HAS_CLOUDSCRAPER:
            strategies.append(("cloudscraper", self._fetch_via_cloudscraper))
        if self.flaresolverr_url:
            strategies.append(("flaresolverr", self._fetch_via_flaresolverr))
        strategies.append(("manual", self._fetch_manual))

        last_body: Optional[bytes] = None
        last_headers: Dict[str, str] = {}
        last_status = 0

        for method_name, fn in strategies:
            result = fn(url, host)
            if result is None:
                continue

            body, headers, status = result
            protection = _detect_cloudflare(headers, body, status)

            if protection is None:
                logger.info("[apikey/cf] %s → %d via %s (no CF)",
                            url, status, method_name)
                return body, headers, status, method_name

            ptype = _CF_PROTECTION_TYPES.get(protection, protection)
            logger.info("[apikey/cf] %s → %d via %s — %s",
                        url, status, method_name, ptype)

            last_body, last_headers, last_status = body, headers, status

            if protection == "waf_block":
                logger.warning("[apikey/cf] %s WAF-blocked", url)
                return body, headers, status, method_name + " (waf_block)"

            if protection == "rate_limit":
                continue

        if last_body is not None:
            return last_body, last_headers, last_status, "failed-all"
        return None, {}, 0, "failed-all"


# ═══════════════════════════════════════════════════════════════════════════
# MAIN SCANNER
# ═══════════════════════════════════════════════════════════════════════════
class APIScanner:
    def __init__(
        self,
        mode: str = "basic",
        entropy_threshold: float = 4.5,
        exclude_patterns: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None,
        allow_files: Optional[List[str]] = None,
        deny_files: Optional[List[str]] = None,
        max_file_size: int = MAX_FILE_SIZE,
        context_chars: int = 40,
        follow_symlinks: bool = False,
        deduplicate: bool = True,
        skip_binary: bool = True,
        auto_sync: bool = True,
        include_bundled: bool = True,
        include_external: bool = True,
        use_proxy: bool = True,
        max_proxy_attempts: int = DEFAULT_MAX_PROXY_ATTEMPTS,
        use_cloudflare_bypass: bool = True,
    ):
        self.mode = mode
        self.entropy_threshold = entropy_threshold
        self.exclude_patterns = set(exclude_patterns or [])
        self.include_patterns = set(include_patterns or [])
        self.allow_files = allow_files or []
        self.deny_files = set(deny_files or [])
        self.max_file_size = max_file_size
        self.context_chars = context_chars
        self.follow_symlinks = follow_symlinks
        self.deduplicate = deduplicate
        self.skip_binary = skip_binary
        self.use_proxy = use_proxy
        self.max_proxy_attempts = max(0, int(max_proxy_attempts))
        self.use_cloudflare_bypass = use_cloudflare_bypass

        raw_patterns: List[Dict[str, Any]] = []
        if include_bundled:
            raw_patterns.extend(API_KEY_PATTERNS)
        if include_external:
            try:
                external = load_wordlist(auto_sync=auto_sync)
                if external:
                    logger.info("[apikey] loaded %d external rule(s)", len(external))
                    raw_patterns.extend(external)
            except Exception as exc:
                logger.warning("[apikey] external wordlist load failed: %s", exc)

        self.active_patterns: List[Dict[str, Any]] = []
        for pat in raw_patterns:
            if self.include_patterns and pat["name"] not in self.include_patterns:
                continue
            if pat["name"] in self.exclude_patterns:
                continue
            if self.mode == "basic" and pat["confidence"] not in ("high", "medium"):
                continue
            try:
                compiled = re.compile(pat["regex"])
            except re.error:
                continue
            self.active_patterns.append({**pat, "compiled": compiled})

        self.proxy_manager: Optional[ProxyManager] = None
        if self.use_proxy:
            try:
                self.proxy_manager = get_proxy_manager(auto_sync=auto_sync)
                if not self.proxy_manager.has_proxies():
                    self.proxy_manager = None
                else:
                    s = self.proxy_manager.stats()
                    logger.info("[apikey] proxy pool: %d total, %d healthy",
                                s["total"], s["healthy"])
            except Exception as exc:
                logger.warning("[apikey] proxy init failed: %s", exc)
                self.proxy_manager = None

        self._cf_bypass: Optional[CloudflareBypass] = None
        if use_cloudflare_bypass:
            self._cf_bypass = CloudflareBypass(
                timeout=DEFAULT_TIMEOUT,
                cf_timeout=CF_CHALLENGE_TIMEOUT,
                verify_tls=False,
                flaresolverr_url=FLARESOLVERR_URL,
            )

        self._entropy_re = re.compile(r'[A-Za-z0-9+/=_\-]{20,}')
        self._deny_regex_cache: Dict[str, Optional[re.Pattern]] = {}

        logger.info(
            "[apikey] ready: mode=%s patterns=%d entropy=%.2f "
            "proxy=%s cf-bypass=%s (curl_cffi=%s cloudscraper=%s flaresolverr=%s)",
            self.mode, len(self.active_patterns), self.entropy_threshold,
            "on" if self.proxy_manager else "off",
            "on" if self._cf_bypass else "off",
            "yes" if _HAS_CURL_CFFI else "no",
            "yes" if _HAS_CLOUDSCRAPER else "no",
            "yes" if FLARESOLVERR_URL else "no",
        )

    def _extract_context(self, line: str, s: int, e: int) -> str:
        start = max(0, s - self.context_chars)
        end = min(len(line), e + self.context_chars)
        return line[start:end]

    def _is_binary_path(self, path: Path) -> bool:
        return self.skip_binary and path.suffix.lower() in SKIP_BINARY_EXT

    @staticmethod
    def _glob_to_regex(pattern: str) -> re.Pattern:
        p = pattern.replace("\\", "/").strip("/")
        parts = p.split("/")
        regex_parts: List[str] = []
        for i, part in enumerate(parts):
            if part == "**":
                if i < len(parts) - 1:
                    regex_parts.append("(?:[^/]+/)*")
                else:
                    regex_parts.append("(?:[^/]+/)*[^/]*")
            else:
                sub = re.escape(part).replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
                regex_parts.append(sub + ("" if i == len(parts) - 1 else "/"))
        return re.compile("^" + "".join(regex_parts) + "$")

    def _is_denied(self, path: Path, root: Optional[Path] = None) -> bool:
        if not self.deny_files:
            return False
        try:
            rel = path.relative_to(root) if root else path
        except ValueError:
            rel = path
        rel_str = str(rel).replace("\\", "/")
        for pattern in self.deny_files:
            p = pattern.replace("\\", "/")
            if p not in self._deny_regex_cache:
                try:
                    self._deny_regex_cache[p] = self._glob_to_regex(p)
                except re.error:
                    self._deny_regex_cache[p] = None
            compiled = self._deny_regex_cache[p]
            if compiled is not None and compiled.match(rel_str):
                return True
            if "/" not in p and fnmatch.fnmatch(path.name, p):
                return True
            if p.startswith("**/") and fnmatch.fnmatch(rel_str, p[3:]):
                return True
            if p.endswith("/**") and (
                rel_str == p[:-3] or rel_str.startswith(p[:-3] + "/")
            ):
                return True
        return False

    def _validate_match(
        self,
        line: str,
        start: int,
        end: int,
        extracted: str,
        pattern_confidence: str,
    ) -> bool:
        if len(extracted) < MIN_EXTRACTED_LENGTH:
            return False
        if not looks_like_secret(extracted, MIN_EXTRACTED_LENGTH):
            return False
        if start > 0 and (line[start - 1].isalnum() or line[start - 1] in "_-"):
            return False
        if end < len(line) and (line[end].isalnum() or line[end] in "_-"):
            return False
        if pattern_confidence == "low" and len(extracted) < 16:
            return False
        return True

    def _scan_line_patterns(
        self, line: str, line_no: int, source: str, file_type: str
    ) -> List[Finding]:
        out: List[Finding] = []
        for pattern in self.active_patterns:
            try:
                for match in pattern["compiled"].finditer(line):
                    matched = match.group(0)
                    if match.lastindex and match.lastindex >= 1:
                        extracted = match.group(1) or matched
                    else:
                        extracted = matched
                    extracted = extracted.strip().strip("'\"`")

                    if not self._validate_match(
                        line, match.start(), match.end(),
                        extracted, pattern["confidence"],
                    ):
                        continue

                    context = self._extract_context(line, match.start(), match.end())
                    out.append(Finding(
                        source=source, line=line_no,
                        column=match.start() + 1,
                        pattern_name=pattern["name"],
                        confidence=pattern["confidence"],
                        severity=pattern.get("severity", "medium"),
                        description=pattern.get("description", ""),
                        rule_id=re.sub(r"[^A-Z0-9_]+", "_", pattern["name"].upper()),
                        match=matched[:500],
                        extracted_key=extracted[:500],
                        context=context[:500],
                        file_type=file_type,
                    ))
            except (re.error, RuntimeError):
                pass
        return out

    def _scan_line_entropy(
        self, line: str, line_no: int, source: str, file_type: str
    ) -> List[Finding]:
        if self.mode != "expert":
            return []
        out: List[Finding] = []
        for match in self._entropy_re.finditer(line):
            cand = match.group(0)
            if len(cand) > 100 or not looks_like_secret(cand, MIN_EXTRACTED_LENGTH):
                continue
            ent = shannon_entropy(cand)
            if ent >= self.entropy_threshold:
                ctx = self._extract_context(line, match.start(), match.end())
                out.append(Finding(
                    source=source, line=line_no, column=match.start() + 1,
                    pattern_name="High Entropy String",
                    confidence="entropy", severity="medium",
                    description=f"High-entropy string (Shannon={ent:.2f} bits/char)",
                    rule_id="HIGH_ENTROPY_STRING",
                    match=cand, extracted_key=cand,
                    context=ctx, file_type=file_type,
                ))
        return out

    def scan_content(
        self, content: str, source: str, file_type: str = "text"
    ) -> List[Finding]:
        out: List[Finding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            if len(line) <= MAX_LINE_LENGTH:
                out.extend(self._scan_line_patterns(line, line_no, source, file_type))
                out.extend(self._scan_line_entropy(line, line_no, source, file_type))
                continue
            step = MAX_LINE_LENGTH - LINE_OVERLAP
            for s in range(0, len(line), step):
                e = min(s + MAX_LINE_LENGTH, len(line))
                seg = line[s:e]
                out.extend(self._scan_line_patterns(seg, line_no, source, file_type))
                out.extend(self._scan_line_entropy(seg, line_no, source, file_type))
                if e >= len(line):
                    break
        return out

    def scan_file(self, file_path: Union[str, Path]) -> List[Finding]:
        path = Path(file_path)
        if not path.is_file() or self._is_binary_path(path):
            return []
        if not self.follow_symlinks and path.is_symlink():
            return []
        try:
            size = path.stat().st_size
        except OSError:
            return []
        if size == 0 or size > self.max_file_size:
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, UnicodeError):
            return []
        if "\x00" in content[:8192]:
            return []
        return self.scan_content(content, str(path), file_type="text")

    def _iter_files(self, directory: Path, recursive: bool) -> Iterable[Path]:
        if not self.allow_files:
            it = directory.rglob("*") if recursive else directory.glob("*")
            for p in it:
                if p.is_file():
                    yield p
            return
        seen: Set[Path] = set()
        for pattern in self.allow_files:
            if not recursive and "**" in pattern:
                it = directory.glob(pattern.replace("**/", ""))
            else:
                it = directory.glob(pattern)
            for p in it:
                if p.is_file() and p not in seen:
                    seen.add(p)
                    yield p

    def scan_directory(
        self, directory: Union[str, Path], recursive: bool = True
    ) -> List[Finding]:
        d = Path(directory)
        if not d.is_dir():
            return []
        files: List[Path] = []
        for f in self._iter_files(d, recursive):
            if self._is_denied(f, root=d):
                continue
            if not self.follow_symlinks and f.is_symlink():
                continue
            files.append(f)
        if not files:
            return []
        out: List[Finding] = []
        workers = min(os.cpu_count() or 4, 8)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(self.scan_file, f): f for f in files}
            for fut in as_completed(futures):
                try:
                    out.extend(fut.result())
                except Exception:
                    pass
        return out

    def _build_headers(self, ua: str) -> Dict[str, str]:
        return {**_BROWSER_HEADERS, "User-Agent": ua}

    def _fetch_basic(
        self, url: str, timeout: int, ua: str,
        session: Optional[requests.Session] = None,
        proxies: Optional[Dict[str, str]] = None,
    ) -> Tuple[Optional[bytes], Optional[str], int]:
        s = session or requests.Session()
        try:
            with s.get(
                url, headers=self._build_headers(ua), timeout=timeout,
                stream=True, allow_redirects=True, proxies=proxies,
            ) as resp:
                status = resp.status_code
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if status >= 400:
                    return None, ctype, status
                if not any(t in ctype for t in (
                    "text", "json", "xml", "javascript",
                    "x-sh", "x-python", "yaml", "plain", "html",
                )):
                    return None, ctype, status
                chunks: List[bytes] = []
                total = 0
                for chunk in resp.iter_content(chunk_size=65536):
                    total += len(chunk)
                    if total > MAX_URL_RESPONSE_SIZE:
                        break
                    chunks.append(chunk)
                return b"".join(chunks), ctype, status
        except requests.exceptions.RequestException:
            return None, None, 0

    def _should_use_proxy(self, status: int) -> bool:
        return status == 0 or status in _PROXY_TRIGGER_CODES

    def scan_url(self, url: str, timeout: int = DEFAULT_TIMEOUT) -> List[Finding]:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return []

        session = requests.Session()
        body: Optional[bytes] = None
        status = 0
        used = "direct"

        # ── Attempt 1: direct ─────────────────────────────────────────
        raw, _ct, status = self._fetch_basic(url, timeout, _BROWSER_UA_PRIMARY, session)
        if raw is not None:
            cf_type = _detect_cloudflare({}, raw, status)
            if cf_type is None:
                body = raw
            else:
                logger.info("[apikey] CF detected (%s) on %s — invoking bypass",
                            cf_type, url)

        # ── Attempt 2: CF bypass engine ───────────────────────────────
        if body is None and self._cf_bypass is not None:
            cf_body, cf_headers, cf_status, cf_method = self._cf_bypass.fetch(url)
            if cf_body is not None:
                body = cf_body
                status = cf_status
                used = f"cf-bypass:{cf_method}"

        # ── Attempt 3: Safari UA retry on 403 ─────────────────────────
        if body is None and status == 403:
            raw, _ct, status = self._fetch_basic(
                url, timeout, _BROWSER_UA_SECONDARY, session
            )
            if raw is not None:
                body = raw
                used = "direct-safari-ua"

        # ── Attempt 4: proxy rotation ─────────────────────────────────
        if body is None and self.proxy_manager and self._should_use_proxy(status):
            logger.info("[apikey] %s blocked — trying proxies", url)
            for attempt in range(self.max_proxy_attempts):
                proxy_dict = self.proxy_manager.get_next()
                if not proxy_dict:
                    break
                proxy_url = proxy_dict["http"]
                logger.info("[apikey] proxy attempt %d/%d: %s",
                            attempt + 1, self.max_proxy_attempts, proxy_url)
                if self._cf_bypass is not None:
                    self._cf_bypass.proxy_dict = proxy_dict
                    cf_body, cf_headers, cf_status, cf_method = \
                        self._cf_bypass.fetch(url)
                    if cf_body is not None:
                        body = cf_body
                        status = cf_status
                        used = f"proxy+cf:{proxy_url}:{cf_method}"
                        self.proxy_manager.mark_success(proxy_url)
                        break
                raw, _ct, status = self._fetch_basic(
                    url, timeout, _BROWSER_UA_PRIMARY, session,
                    proxies=proxy_dict,
                )
                if raw is not None:
                    body = raw
                    used = f"proxy:{proxy_url}"
                    self.proxy_manager.mark_success(proxy_url)
                    break
                self.proxy_manager.mark_failure(proxy_url)

        # ── Attempt 5: HTTPS → HTTP fallback ──────────────────────────
        if body is None and url.startswith("https://"):
            http_fb = url.replace("https://", "http://", 1)
            raw, _ct, _st = self._fetch_basic(
                http_fb, timeout, _BROWSER_UA_PRIMARY, session
            )
            if raw is not None:
                body = raw
                url = http_fb
                used = "http-fallback"

        if body is None:
            logger.warning("[apikey] all attempts failed for %s", url)
            return []

        text = body.decode("utf-8", errors="ignore")
        findings = self.scan_content(text, url, file_type="url")
        for f in findings:
            f.context = f"[via {used}] " + (f.context or "")
        return findings

    @staticmethod
    def _safe_extract_member(name: str, root: Path) -> Optional[Path]:
        parts = [p for p in Path(name).parts if p not in ("", ".", "..")]
        if not parts:
            return None
        target = root.joinpath(*parts).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError:
            return None
        return target

    def scan_archive(self, archive_path: Union[str, Path]) -> List[Finding]:
        path = Path(archive_path)
        out: List[Finding] = []
        temp = Path(tempfile.mkdtemp(prefix="oxysintx_"))
        total = 0
        entries = 0
        try:
            if path.suffix.lower() == ".zip":
                with zipfile.ZipFile(path, "r") as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        entries += 1
                        if entries > MAX_ARCHIVE_ENTRIES:
                            break
                        if info.compress_size > 0 and info.file_size > 1024 * 1024:
                            if info.file_size / info.compress_size > MAX_ARCHIVE_RATIO:
                                continue
                        total += info.file_size
                        if total > MAX_ARCHIVE_UNPACKED:
                            break
                        target = self._safe_extract_member(info.filename, temp)
                        if target is None:
                            continue
                        target.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            with zf.open(info) as src, open(target, "wb") as dst:
                                shutil.copyfileobj(src, dst, length=65536)
                        except (OSError, zipfile.BadZipFile):
                            continue
                        out.extend(self.scan_file(target))
            elif path.suffix.lower() in (".tar", ".gz", ".tgz", ".bz2", ".xz"):
                with tarfile.open(path, "r:*") as tf:
                    for member in tf.getmembers():
                        if not member.isfile():
                            continue
                        entries += 1
                        if entries > MAX_ARCHIVE_ENTRIES:
                            break
                        total += member.size
                        if total > MAX_ARCHIVE_UNPACKED:
                            break
                        target = self._safe_extract_member(member.name, temp)
                        if target is None:
                            continue
                        target.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            fobj = tf.extractfile(member)
                            if fobj is None:
                                continue
                            with open(target, "wb") as dst:
                                shutil.copyfileobj(fobj, dst, length=65536)
                        except (OSError, tarfile.TarError):
                            continue
                        out.extend(self.scan_file(target))
        except (zipfile.BadZipFile, tarfile.TarError, OSError) as e:
            logger.error("[apikey] archive error %s: %s", path, e)
        finally:
            shutil.rmtree(temp, ignore_errors=True)
        return out

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        seen: Set[str] = set()
        out: List[Finding] = []
        for f in findings:
            fp = f.fingerprint()
            if fp in seen:
                continue
            seen.add(fp)
            out.append(f)
        return out

    def run(self, target: Union[str, Path]) -> Dict[str, Any]:
        target_str = str(target).strip()
        findings: List[Finding] = []
        start = time.time()

        if not target_str.startswith(("http://", "https://")):
            if looks_like_bare_domain(target_str) and not os.path.exists(target_str):
                target_str = "https://" + target_str
                logger.info("[apikey] bare domain → %s", target_str)

        try:
            if target_str.startswith(("http://", "https://")):
                findings = self.scan_url(target_str)
            elif os.path.isfile(target_str):
                lower = target_str.lower()
                if lower.endswith((".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz")):
                    findings = self.scan_archive(target_str)
                else:
                    findings = self.scan_file(target_str)
            elif os.path.isdir(target_str):
                findings = self.scan_directory(target_str)
            else:
                logger.error("[apikey] unrecognized target: %s", target_str)
        except Exception as e:
            logger.exception("[apikey] scan error: %s", e)

        if self.deduplicate:
            findings = self._deduplicate(findings)

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (sev_order.get(f.severity, 9), f.source, f.line))

        stats: Dict[str, Any] = {
            "total": len(findings),
            "by_confidence": {"high": 0, "medium": 0, "low": 0, "entropy": 0},
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_pattern": {},
            "patterns_loaded": len(self.active_patterns),
            "proxy_enabled": self.proxy_manager is not None,
            "proxy_stats": self.proxy_manager.stats() if self.proxy_manager else None,
            "cf_bypass_enabled": self._cf_bypass is not None,
            "cf_bypass_methods": {
                "curl_cffi":    _HAS_CURL_CFFI,
                "cloudscraper": _HAS_CLOUDSCRAPER,
                "flaresolverr": bool(FLARESOLVERR_URL),
                "manual":       True,
            },
            "filter_config": {
                "min_key_length":  MIN_EXTRACTED_LENGTH,
                "min_entropy":     MIN_SECRET_ENTROPY,
                "min_diversity":   CHAR_DIVERSITY_MIN_RATIO,
                "keyword_min_len": KEYWORD_MIN_LENGTH,
            },
        }
        for f in findings:
            stats["by_confidence"][f.confidence] = \
                stats["by_confidence"].get(f.confidence, 0) + 1
            stats["by_severity"][f.severity] = \
                stats["by_severity"].get(f.severity, 0) + 1
            stats["by_pattern"][f.pattern_name] = \
                stats["by_pattern"].get(f.pattern_name, 0) + 1

        duration = round(time.time() - start, 3)
        result = {
            "findings": [f.to_dict() for f in findings],
            "stats": stats,
            "scanned": target_str,
            "duration_seconds": duration,
            "scanner_version": SCANNER_VERSION,
            "scan_type": "apikey",
        }
        logger.info("[apikey] done: %d finding(s) on %s (%.2fs)",
                    stats["total"], target_str, duration)
        return result


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
def run(target: str, mode: str = "basic") -> Dict[str, Any]:
    try:
        load_wordlist(auto_sync=True)
    except Exception:
        pass
    try:
        get_proxy_manager(auto_sync=True)
    except Exception:
        pass
    scanner = APIScanner(
        mode=mode,
        auto_sync=True,
        use_proxy=True,
        use_cloudflare_bypass=True,
    )
    return scanner.run(target)


# ═══════════════════════════════════════════════════════════════════════════
# OUTPUT FORMATTING
# ═══════════════════════════════════════════════════════════════════════════
def _format_output(result: Dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(result, indent=2, ensure_ascii=False)
    if fmt == "sarif":
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "Oxysintx API Scanner",
                    "version": result.get("scanner_version", SCANNER_VERSION),
                    "informationUri": "https://oxysintx.local",
                }},
                "results": [
                    {
                        "ruleId": f.get("rule_id") or f["pattern_name"],
                        "level": {
                            "critical": "error", "high": "error",
                            "medium": "warning", "low": "note", "info": "note",
                        }.get(f.get("severity", "medium"), "warning"),
                        "message": {"text": f"{f['pattern_name']}: {f.get('description', '')}"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": f["source"]},
                                "region": {
                                    "startLine": max(1, f.get("line", 1)),
                                    "startColumn": max(1, f.get("column", 1)),
                                },
                            }
                        }],
                    }
                    for f in result["findings"]
                ],
            }],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["severity", "confidence", "pattern", "source",
                    "line", "column", "key", "context"])
        for f in result["findings"]:
            w.writerow([
                f.get("severity", ""), f.get("confidence", ""),
                f.get("pattern_name", ""), f.get("source", ""),
                f.get("line", ""), f.get("column", ""),
                f.get("extracted_key", ""), f.get("context", ""),
            ])
        return buf.getvalue()
    lines = [
        f"Scan of {result['scanned']} — {result['stats']['total']} findings "
        f"({result.get('duration_seconds', 0)}s)"
    ]
    for f in result["findings"]:
        lines.append(
            f"  [{f.get('severity', 'medium').upper():<8}] "
            f"[{f['confidence']:<8}] {f['pattern_name']} "
            f"@ {f['source']}:{f['line']}:{f.get('column', 0)} "
            f"=> {f['extracted_key'][:80]}"
        )
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    # ▼ FIX v6.1.1: global declaration MUST be first statement
    global MIN_EXTRACTED_LENGTH, MIN_SECRET_ENTROPY

    p = argparse.ArgumentParser(
        description=f"Oxysintx API Key Scanner v{__version__} — "
                    "secret scanner with CF bypass + strict FP filter",
    )
    p.add_argument("target", nargs="?")
    p.add_argument("--mode", choices=["basic", "expert"], default="basic")
    p.add_argument("--output", choices=["json", "sarif", "text", "csv"], default="json")
    p.add_argument("--output-file")
    p.add_argument("--exclude", nargs="*", default=[])
    p.add_argument("--include", nargs="*", default=[])
    p.add_argument("--deny-files", nargs="*", default=[])
    p.add_argument("--allow-files", nargs="*", default=[])
    p.add_argument("--entropy-threshold", type=float, default=4.5)
    p.add_argument("--no-dedupe", action="store_true")
    p.add_argument("--follow-symlinks", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--no-proxy", action="store_true")
    p.add_argument("--no-cf-bypass", action="store_true")
    p.add_argument("--max-proxy-attempts", type=int, default=DEFAULT_MAX_PROXY_ATTEMPTS)

    p.add_argument("--min-key-length", type=int, default=MIN_EXTRACTED_LENGTH,
                   help="Minimum extracted key length (default: 10)")
    p.add_argument("--min-entropy", type=float, default=MIN_SECRET_ENTROPY,
                   help="Minimum Shannon entropy for extracted keys (default: 2.8)")

    p.add_argument("--wordlists-status", action="store_true")
    p.add_argument("--wordlists-sync", action="store_true")
    p.add_argument("--no-external", action="store_true")
    p.add_argument("--proxies-status", action="store_true")
    p.add_argument("--proxies-sync", action="store_true")
    p.add_argument("--cf-status", action="store_true",
                   help="Print Cloudflare bypass availability and exit")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Apply global tuning from CLI (global declared at top — safe now)
    MIN_EXTRACTED_LENGTH = max(4, int(args.min_key_length))
    MIN_SECRET_ENTROPY = max(0.0, float(args.min_entropy))

    if args.wordlists_status:
        print(json.dumps(ensure_wordlists(force=False), indent=2)); return
    if args.wordlists_sync:
        print(json.dumps(ensure_wordlists(force=True), indent=2)); return
    if args.proxies_status:
        pm = get_proxy_manager()
        print(json.dumps({
            "directory": str(pm.proxy_dir),
            "all_file":  str(pm.all_path),
            "meta_file": str(pm.meta_path),
            "stats":     pm.stats(),
        }, indent=2)); return
    if args.proxies_sync:
        print(json.dumps(ensure_proxies(force=True), indent=2)); return
    if args.cf_status:
        print(json.dumps({
            "curl_cffi_available":    _HAS_CURL_CFFI,
            "cloudscraper_available": _HAS_CLOUDSCRAPER,
            "flaresolverr_url":       FLARESOLVERR_URL or "(not set)",
            "strategies": [
                "curl_cffi (TLS impersonate Chrome)" if _HAS_CURL_CFFI else None,
                "cloudscraper (JS solver)"           if _HAS_CLOUDSCRAPER else None,
                "flaresolverr (external)"            if FLARESOLVERR_URL else None,
                "manual (headers + UA + cookies)",
            ],
            "filter_config": {
                "min_key_length":  MIN_EXTRACTED_LENGTH,
                "min_entropy":     MIN_SECRET_ENTROPY,
                "keyword_min_len": KEYWORD_MIN_LENGTH,
            },
            "version": __version__,
        }, indent=2)); return

    if not args.target:
        p.error("target required (unless using --*-status/sync)")

    scanner = APIScanner(
        mode=args.mode,
        entropy_threshold=args.entropy_threshold,
        exclude_patterns=args.exclude,
        include_patterns=args.include,
        deny_files=args.deny_files,
        allow_files=args.allow_files,
        deduplicate=not args.no_dedupe,
        follow_symlinks=args.follow_symlinks,
        include_external=not args.no_external,
        use_proxy=not args.no_proxy,
        max_proxy_attempts=args.max_proxy_attempts,
        use_cloudflare_bypass=not args.no_cf_bypass,
    )
    result = scanner.run(args.target)
    out = _format_output(result, args.output)
    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Output written to {args.output_file}")
    else:
        print(out)


if __name__ == "__main__":
    main()