# modules/search_user.py
"""
Osint Leak Data Search Tool v2.2.0
==================================

STANDALONE module — NOT part of the scan pipeline.

This module is intentionally EXCLUDED from the ScanOrchestrator's
auto-discovery. It only serves:

    - Dashboard "OSINT" panel   → POST /api/osint/search
    - Legacy leak-data search   → POST /api/leakdata/search
    - Direct Python import      → search_user.run(...)

Discovery flags
---------------
    MODULE_TYPE         = "standalone"
    EXCLUDE_FROM_SCAN   = True
    TOOL_INFO["scan_excluded"] = True

The orchestrator should skip any module where
`EXCLUDE_FROM_SCAN is True` OR `MODULE_TYPE == "standalone"`.

Search methods
--------------
    name      → nama_penuh, nama, name
    username  → username, user, handle, social media, email
    email     → email (local-part aware)
    number    → telepon, phone, no_hp, whatsapp, wa
    nik       → nik, ktp, npwp
    any       → all fields

Author : Yanxzyx
License: MIT
"""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import sys
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

logger = logging.getLogger("emergens.osint")

# ===========================================================================
# DISCOVERY FLAGS — orchestrator skips this module
# ===========================================================================

MODULE_TYPE: str = "standalone"          # NOT "scan"
EXCLUDE_FROM_SCAN: bool = True           # hard exclusion flag
SCAN_EXCLUDED: bool = True               # legacy alias

# ===========================================================================
# Metadata
# ===========================================================================

TOOL_INFO: Dict[str, Any] = {
    "name": "Osint",
    "description": (
        "Standalone multi-source OSINT lookup: name, username, "
        "email, phone, NIK. Not part of the scan pipeline."
    ),
    "version": "2.2.0",
    "category": "Data",
    "author": "Yanxzyx",
    "module_type": MODULE_TYPE,
    "scan_excluded": True,               # ← orchestrator checks this
    "exclude_from_scan": True,           # ← alias
    "capabilities": [
        "name", "username", "email", "number", "nik", "any",
        "fuzzy-search", "multi-field", "caching", "streaming",
    ],
}

__all__ = [
    "TOOL_INFO",
    "MODULE_TYPE",
    "EXCLUDE_FROM_SCAN",
    "SCAN_EXCLUDED",
    "run",
    "search",
    "clear_cache",
    "stats",
    "Osint",
    "SearchResult",
    "Config",
]


# ===========================================================================
# Configuration
# ===========================================================================

class Config:
    """Runtime configuration — override via `OSINT_*` env vars."""

    ENV_PREFIX = "OSINT_"

    PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
    USERDATA_DIR: Path = PROJECT_ROOT / "userdata"

    CACHE_TTL_SEC: float = 60.0
    RATE_LIMIT_RPS: float = 5.0
    RATE_LIMIT_BURST: int = 10

    MIN_QUERY_LEN: int = 2
    MAX_QUERY_LEN: int = 120
    DEFAULT_LIMIT: int = 50
    MAX_LIMIT: int = 1000
    DEFAULT_MIN_SCORE: float = 0.30
    DEEP_MIN_SCORE: float = 0.18

    FILE_READ_CONCURRENCY: int = 4
    STREAM_THRESHOLD_MB: float = 20.0
    MAX_FILE_SIZE_MB: float = 500.0

    SEARCHABLE_FIELDS: Tuple[str, ...] = (
        "nama_penuh", "nama", "name",
        "nik", "ktp", "npwp",
        "email",
        "telepon", "phone", "no_hp", "whatsapp", "wa",
        "alamat", "address",
        "username", "user", "handle",
        "twitter", "instagram", "facebook", "tiktok",
    )

    FIELD_WEIGHTS: Dict[str, float] = {
        "nama_penuh": 1.15, "nama": 1.10, "name": 1.10,
        "username": 1.10, "handle": 1.05, "user": 1.05,
        "email": 1.10,
        "nik": 1.15, "ktp": 1.15, "npwp": 1.10,
        "telepon": 1.05, "phone": 1.05, "no_hp": 1.05,
        "whatsapp": 1.05, "wa": 1.05,
        "alamat": 0.85, "address": 0.85,
    }

    @classmethod
    def apply_env_overrides(cls) -> None:
        def _env(name: str) -> Optional[str]:
            return os.environ.get(f"{cls.ENV_PREFIX}{name}")

        if v := _env("USERDATA_DIR"):
            cls.USERDATA_DIR = Path(v).expanduser().resolve()
        if v := _env("CACHE_TTL"):
            cls.CACHE_TTL_SEC = float(v)
        if v := _env("RATE_RPS"):
            cls.RATE_LIMIT_RPS = float(v)
        if v := _env("DEFAULT_LIMIT"):
            cls.DEFAULT_LIMIT = int(v)
        if v := _env("MIN_SCORE"):
            cls.DEFAULT_MIN_SCORE = float(v)


Config.apply_env_overrides()


# ===========================================================================
# Result envelope
# ===========================================================================

@dataclass
class SearchResult:
    tool: str = "osint"
    method: str = "name"
    query: str = ""
    results: List[Dict[str, Any]] = field(default_factory=list)
    count: int = 0
    total: int = 0
    offset: int = 0
    limit: int = 0
    took_ms: int = 0
    cache_stats: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "tool": self.tool,
            "method": self.method,
            "query": self.query,
            "target": self.query,          # legacy alias
            "standalone": True,            # informs clients
            "data": {
                "results": self.results,
                "count": self.count,
                "total": self.total,
                "offset": self.offset,
                "limit": self.limit,
                "tookMs": self.took_ms,
                "cache": self.cache_stats,
            },
        }
        if self.error:
            out["error"] = self.error
            out["data"]["error"] = self.error
        if self.message:
            out["message"] = self.message
        return out


# ===========================================================================
# Normalizer
# ===========================================================================

class Normalizer:
    _WS = re.compile(r"\s+")
    _NON_ALNUM = re.compile(r"[^a-z0-9@._\-\s]")

    @classmethod
    def normalize(cls, s: Any) -> str:
        if s is None:
            return ""
        if not isinstance(s, str):
            s = str(s)
        if not s:
            return ""
        s = unicodedata.normalize("NFKD", s)
        s = "".join(c for c in s if not unicodedata.combining(c))
        s = s.lower()
        s = cls._NON_ALNUM.sub(" ", s)
        return cls._WS.sub(" ", s).strip()

    @classmethod
    def tokenize(cls, s: Any) -> List[str]:
        return [t for t in cls.normalize(s).split(" ") if t]

    @staticmethod
    def phone(s: Any) -> str:
        return re.sub(r"\D", "", str(s or ""))

    @staticmethod
    def idnum(s: Any) -> str:
        return re.sub(r"\D", "", str(s or ""))


# ===========================================================================
# Matcher (fuzzy)
# ===========================================================================

class Matcher:
    @staticmethod
    def levenshtein(a: str, b: str) -> int:
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        if len(a) > len(b):
            a, b = b, a
        prev = list(range(len(a) + 1))
        for j in range(1, len(b) + 1):
            prev_diag = prev[0]
            prev[0] = j
            for i in range(1, len(a) + 1):
                cur = prev[i]
                cost = 0 if a[i - 1] == b[j - 1] else 1
                prev[i] = min(prev[i] + 1, prev[i - 1] + 1, prev_diag + cost)
                prev_diag = cur
        return prev[-1]

    @classmethod
    def ratio(cls, a: str, b: str) -> float:
        if not a and not b:
            return 1.0
        m = max(len(a), len(b))
        return 1.0 if m == 0 else 1.0 - cls.levenshtein(a, b) / m

    @classmethod
    def token_score(cls, q_tokens: List[str], t_tokens: List[str]) -> float:
        if not q_tokens or not t_tokens:
            return 0.0
        matched = 0.0
        for qt in q_tokens:
            if qt in t_tokens:
                matched += 1.0
                continue
            if any(tt.startswith(qt) or qt.startswith(tt) for tt in t_tokens):
                matched += 0.7
                continue
            best = max((cls.ratio(qt, tt) for tt in t_tokens), default=0.0)
            if best >= 0.75:
                matched += best * 0.6
        return matched / len(q_tokens)

    @classmethod
    def score(cls, query: str, target: str) -> float:
        q = Normalizer.normalize(query)
        t = Normalizer.normalize(target)
        if not q or not t:
            return 0.0
        if q in t:
            coverage = len(q) / max(1, len(t))
            return min(1.0, 0.75 + coverage * 0.25)
        fuzzy = cls.ratio(q, t)
        tok = cls.token_score(Normalizer.tokenize(q), Normalizer.tokenize(t))
        return min(1.0, fuzzy * 0.6 + tok * 0.4)


# ===========================================================================
# TTL Cache
# ===========================================================================

class _TTLCache:
    def __init__(self, ttl_sec: float) -> None:
        self.ttl = ttl_sec
        self._store: Dict[str, Tuple[float, Any, Optional[float]]] = {}
        self._lock = Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str, mtime: Optional[float] = None) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                self.misses += 1
                return None
            stored_at, value, stored_mtime = entry
            if time.time() - stored_at > self.ttl:
                del self._store[key]
                self.misses += 1
                return None
            if mtime is not None and stored_mtime != mtime:
                del self._store[key]
                self.misses += 1
                return None
            self.hits += 1
            return value

    def set(self, key: str, value: Any, mtime: Optional[float] = None) -> None:
        with self._lock:
            self._store[key] = (time.time(), value, mtime)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self.hits = 0
            self.misses = 0

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {"hits": self.hits, "misses": self.misses, "size": len(self._store)}


# ===========================================================================
# Rate limiter
# ===========================================================================

class _RateLimiter:
    def __init__(self, rps: float, burst: int) -> None:
        self.rps = max(0.1, rps)
        self.burst = max(1, burst)
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = Lock()

    def acquire(self, tokens: float = 1.0) -> float:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(
                self.burst,
                self._tokens + (now - self._last) * self.rps,
            )
            self._last = now
            if self._tokens >= tokens:
                self._tokens -= tokens
                return 0.0
            wait = (tokens - self._tokens) / self.rps
            self._tokens = 0.0
            return wait


# ===========================================================================
# Loader
# ===========================================================================

class _Loader:
    def __init__(self, config: type = Config) -> None:
        self.config = config
        self.cache = _TTLCache(config.CACHE_TTL_SEC)

    def discover(self) -> List[Path]:
        base = self.config.USERDATA_DIR
        if not base.is_dir():
            logger.warning("userdata directory not found: %s", base)
            return []

        seen: set = set()
        files: List[Path] = []
        for pattern in ("*.json", "*.JSON", "*.jsonl", "*.ndjson"):
            for p in sorted(glob.glob(str(base / pattern))):
                path = Path(p)
                if path not in seen and path.is_file():
                    seen.add(path)
                    files.append(path)
        return files

    def load_file(self, path: Path) -> List[Dict[str, Any]]:
        try:
            stat = path.stat()
        except OSError as exc:
            logger.warning("stat failed for %s: %s", path.name, exc)
            return []

        if stat.st_size > self.config.MAX_FILE_SIZE_MB * 1024 * 1024:
            logger.warning("skip %s (too large)", path.name)
            return []

        mtime = stat.st_mtime
        cached = self.cache.get(str(path), mtime=mtime)
        if cached is not None:
            return cached

        size_mb = stat.st_size / (1024 * 1024)
        try:
            if size_mb > self.config.STREAM_THRESHOLD_MB or path.suffix.lower() in (".jsonl", ".ndjson"):
                records = list(self._stream(path))
            else:
                records = self._parse(path)
        except Exception as exc:
            logger.warning("failed to load %s: %s", path.name, exc)
            return []

        self.cache.set(str(path), records, mtime=mtime)
        return records

    def _parse(self, path: Path) -> List[Dict[str, Any]]:
        with path.open("r", encoding="utf-8") as fh:
            text = fh.read()
        if not text.strip():
            return []
        try:
            return self._flatten(json.loads(text))
        except json.JSONDecodeError:
            out: List[Dict[str, Any]] = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        out.append(obj)
                except json.JSONDecodeError:
                    continue
            if not out:
                raise
            return out

    def _stream(self, path: Path) -> Iterator[Dict[str, Any]]:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    yield obj

    @staticmethod
    def _flatten(data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            for key in ("data", "records", "results", "items", "entries"):
                inner = data.get(key)
                if isinstance(inner, list):
                    return [x for x in inner if isinstance(x, dict)]
            return [data]
        return []

    def load_all(self) -> List[Dict[str, Any]]:
        files = self.discover()
        if not files:
            return []
        if self.config.FILE_READ_CONCURRENCY <= 1 or len(files) == 1:
            records: List[Dict[str, Any]] = []
            for path in files:
                records.extend(self.load_file(path))
            return records
        records = []
        with ThreadPoolExecutor(max_workers=self.config.FILE_READ_CONCURRENCY) as ex:
            futures = {ex.submit(self.load_file, p): p for p in files}
            for fut in as_completed(futures):
                try:
                    records.extend(fut.result())
                except Exception as exc:
                    logger.warning("worker failed for %s: %s", futures[fut].name, exc)
        return records


# ===========================================================================
# Main engine
# ===========================================================================

class Osint:
    """Standalone OSINT search engine."""

    METHOD_FIELDS: Dict[str, Tuple[str, ...]] = {
        "name":     ("nama_penuh", "nama", "name"),
        "username": ("username", "user", "handle", "twitter", "instagram",
                     "facebook", "tiktok", "email"),
        "email":    ("email", "username", "user"),
        "number":   ("telepon", "phone", "no_hp", "whatsapp", "wa"),
        "nik":      ("nik", "ktp", "npwp"),
        "any":      Config.SEARCHABLE_FIELDS,
    }

    ERROR_MESSAGES: Dict[str, str] = {
        "query_too_short": f"Query must be at least {Config.MIN_QUERY_LEN} characters.",
        "query_too_long":  f"Query too long (max {Config.MAX_QUERY_LEN}).",
        "invalid_email":   "Invalid email format.",
        "invalid_phone":   "Invalid phone number format.",
        "invalid_nik":     "Invalid NIK/ID number format.",
        "no_query":        "Query is required.",
    }

    def __init__(self) -> None:
        self.loader = _Loader(Config)
        self.limiter = _RateLimiter(Config.RATE_LIMIT_RPS, Config.RATE_LIMIT_BURST)

    @staticmethod
    def _validate(query: str, method: str) -> Optional[str]:
        q = (query or "").strip()
        if not q:
            return "no_query"
        if len(q) < Config.MIN_QUERY_LEN:
            return "query_too_short"
        if len(q) > Config.MAX_QUERY_LEN:
            return "query_too_long"
        if method == "email":
            if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$", q):
                return "invalid_email"
        elif method == "number":
            if not (6 <= len(Normalizer.phone(q)) <= 20):
                return "invalid_phone"
        elif method == "nik":
            if len(Normalizer.idnum(q)) < 8:
                return "invalid_nik"
        return None

    @staticmethod
    def _phone_score(query: str, val: str) -> float:
        q = Normalizer.phone(query)
        v = Normalizer.phone(val)
        if not q or not v:
            return 0.0
        if v == q:
            return 1.0
        if len(q) >= 8 and v.endswith(q[-8:]):
            return 0.95
        if v.endswith(q) and len(q) >= 6:
            return 0.90
        return 0.85 if q in v else 0.0

    @staticmethod
    def _id_score(query: str, val: str) -> float:
        q = Normalizer.idnum(query)
        v = Normalizer.idnum(val)
        if not q or not v:
            return 0.0
        if v == q:
            return 1.0
        return 0.90 if q in v else 0.0

    @staticmethod
    def _email_score(query: str, val: str) -> float:
        q = Normalizer.normalize(query)
        v = Normalizer.normalize(val)
        if not q or not v:
            return 0.0
        if v == q:
            return 1.0
        if q.split("@")[0] == v.split("@")[0]:
            return 0.92
        return 0.85 if q in v else Matcher.score(q, v)

    def _score_field(
        self, field_name: str, value: Any, query: str, method: str, exact: bool
    ) -> float:
        if value is None:
            return 0.0
        values = value if isinstance(value, (list, tuple)) else [value]
        best = 0.0
        for v in values:
            if v is None:
                continue
            s = str(v)
            if not s:
                continue
            if exact:
                score = 1.0 if Normalizer.normalize(query) in Normalizer.normalize(s) else 0.0
            elif method == "number" or field_name in ("telepon", "phone", "no_hp", "whatsapp", "wa"):
                score = self._phone_score(query, s)
            elif method == "nik" or field_name in ("nik", "ktp", "npwp"):
                score = self._id_score(query, s)
            elif field_name == "email" or method == "email":
                score = self._email_score(query, s)
            else:
                score = Matcher.score(query, s)
            weight = Config.FIELD_WEIGHTS.get(field_name, 1.0)
            best = max(best, min(1.0, score * weight))
        return best

    def _score_record(
        self,
        query: str,
        record: Dict[str, Any],
        fields: Sequence[str],
        method: str,
        exact: bool,
    ) -> Tuple[float, Optional[str], Optional[str]]:
        best = 0.0
        best_field: Optional[str] = None
        best_value: Optional[str] = None
        for f in fields:
            if f not in record:
                continue
            score = self._score_field(f, record[f], query, method, exact)
            if score > best:
                best = score
                best_field = f
                v = record[f]
                best_value = (
                    ", ".join(str(x) for x in v[:3])
                    if isinstance(v, (list, tuple))
                    else str(v)
                )
        return best, best_field, best_value

    def search(
        self,
        query: str,
        method: str = "name",
        limit: Optional[int] = None,
        offset: int = 0,
        min_score: Optional[float] = None,
        sort_by: str = "score",
        order: str = "desc",
        exact: bool = False,
        fields: Optional[Sequence[str]] = None,
        include_score: bool = True,
    ) -> SearchResult:
        started = time.time()
        query = (query or "").strip()
        method = (method or "name").lower()
        if method not in self.METHOD_FIELDS:
            method = "any"

        err = self._validate(query, method)
        if err:
            return SearchResult(
                method=method, query=query,
                error=err,
                message=self.ERROR_MESSAGES.get(err, err),
                took_ms=int((time.time() - started) * 1000),
                cache_stats=self.loader.cache.stats(),
            )

        limit = max(1, min(Config.MAX_LIMIT, int(limit or Config.DEFAULT_LIMIT)))
        offset = max(0, int(offset))
        min_score = float(min_score if min_score is not None else Config.DEFAULT_MIN_SCORE)
        min_score = max(0.0, min(1.0, min_score))

        wait = self.limiter.acquire()
        if wait > 0:
            logger.debug("rate-limited, waiting %.3fs", wait)
            time.sleep(wait)

        records = self.loader.load_all()
        if not records:
            return SearchResult(
                method=method, query=query,
                results=[], count=0, total=0,
                offset=offset, limit=limit,
                took_ms=int((time.time() - started) * 1000),
                cache_stats=self.loader.cache.stats(),
            )

        search_fields = tuple(fields) if fields else self.METHOD_FIELDS[method]

        scored: List[Tuple[float, str, str, Dict[str, Any]]] = []
        for rec in records:
            score, m_field, m_value = self._score_record(
                query, rec, search_fields, method, exact
            )
            if score >= min_score:
                scored.append((score, m_field or "", m_value or "", rec))

        reverse = order == "desc"
        if sort_by == "score":
            scored.sort(key=lambda x: x[0], reverse=reverse)
        else:
            scored.sort(
                key=lambda x: Normalizer.normalize(str(x[3].get(sort_by, ""))),
                reverse=reverse,
            )

        total = len(scored)
        page = scored[offset: offset + limit]

        results: List[Dict[str, Any]] = []
        for score, m_field, m_value, rec in page:
            row = dict(rec)
            if include_score:
                row["_score"] = round(score, 4)
                row["_matchedField"] = m_field
                if m_value and m_value != str(rec.get(m_field, "")):
                    row["_matchedValue"] = m_value
            results.append(row)

        return SearchResult(
            method=method,
            query=query,
            results=results,
            count=len(results),
            total=total,
            offset=offset,
            limit=limit,
            took_ms=int((time.time() - started) * 1000),
            cache_stats=self.loader.cache.stats(),
        )

    def clear_cache(self) -> None:
        self.loader.cache.clear()
        logger.info("cache cleared")

    def stats(self) -> Dict[str, Any]:
        return {
            "module_type": MODULE_TYPE,
            "scan_excluded": EXCLUDE_FROM_SCAN,
            "userdata_dir": str(Config.USERDATA_DIR),
            "cache": self.loader.cache.stats(),
            "config": {
                "cache_ttl_sec": Config.CACHE_TTL_SEC,
                "rate_limit_rps": Config.RATE_LIMIT_RPS,
                "default_limit": Config.DEFAULT_LIMIT,
                "default_min_score": Config.DEFAULT_MIN_SCORE,
            },
        }


# ===========================================================================
# Module singleton
# ===========================================================================

_engine = Osint()


def search(query: str, method: str = "name", **kwargs) -> Dict[str, Any]:
    """Direct search — returns JSON-ready dict."""
    return _engine.search(query, method=method, **kwargs).to_dict()


def clear_cache() -> None:
    _engine.clear_cache()


def stats() -> Dict[str, Any]:
    return _engine.stats()


# ===========================================================================
# Public entry point — STANDALONE ONLY (never called by scan orchestrator)
# ===========================================================================

def run(target: str, mode: str = "basic", **kwargs) -> Dict[str, Any]:
    """
    Standalone entry point — NOT used by the scan orchestrator.

    The orchestrator will skip this module because
    `EXCLUDE_FROM_SCAN is True` and `MODULE_TYPE == "standalone"`.

    Kwargs:
        method    : 'name' | 'username' | 'email' | 'number' | 'nik' | 'any'
        limit     : int
        offset    : int
        min_score / minScore : float (0..1)
        exact     : bool
        fields    : list[str]
        sort_by   : str
        order     : 'asc' | 'desc'
    """
    method = (kwargs.pop("method", "name") or "name").lower()
    if method not in _engine.METHOD_FIELDS:
        method = "any"

    # Camel → snake
    if "minScore" in kwargs:
        kwargs["min_score"] = kwargs.pop("minScore")
    if "sortBy" in kwargs:
        kwargs["sort_by"] = kwargs.pop("sortBy")

    # Mode defaults
    if mode == "deep":
        kwargs.setdefault("min_score", Config.DEEP_MIN_SCORE)
        kwargs.setdefault("limit", max(Config.DEFAULT_LIMIT, 200))
    else:
        kwargs.setdefault("min_score", Config.DEFAULT_MIN_SCORE)
        kwargs.setdefault("limit", Config.DEFAULT_LIMIT)

    result = _engine.search(target, method=method, **kwargs)
    return result.to_dict()


# ===========================================================================
# CLI
# ===========================================================================

def _cli(argv: Optional[List[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="search_user",
        description="Osint — standalone leak-data search CLI",
    )
    p.add_argument("query")
    p.add_argument(
        "-m", "--method",
        choices=("name", "username", "email", "number", "nik", "any"),
        default="name",
    )
    p.add_argument("-l", "--limit", type=int, default=20)
    p.add_argument("-o", "--offset", type=int, default=0)
    p.add_argument("-s", "--min-score", type=float, default=None)
    p.add_argument("--exact", action="store_true")
    p.add_argument("--fields", nargs="+")
    p.add_argument("--sort", default="score")
    p.add_argument("--order", choices=("asc", "desc"), default="desc")
    p.add_argument("--json", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--clear-cache", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="[%(levelname)s] %(name)s: %(message)s",
    )

    if args.clear_cache:
        clear_cache()
        print("cache cleared")
        return 0

    if args.stats:
        print(json.dumps(stats(), indent=2))
        return 0

    result = search(
        args.query,
        method=args.method,
        limit=args.limit,
        offset=args.offset,
        min_score=args.min_score,
        exact=args.exact,
        fields=args.fields,
        sort_by=args.sort,
        order=args.order,
    )

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    data = result.get("data", {})
    if result.get("error"):
        print(f"✗ [{result['error']}] {result.get('message', '')}", file=sys.stderr)
        return 1

    if not data.get("results"):
        print(f"No results for '{result['query']}' (method: {result['method']})")
        return 0

    print(f"\n┌─ Osint ─ {result['method']} · '{result['query']}'")
    print(f"│  {data['count']} / {data['total']} results  ·  {data['tookMs']} ms")
    print(f"└─{'─' * 60}\n")

    for i, row in enumerate(data["results"], 1):
        score = row.get("_score")
        match = row.get("_matchedField")
        header = f"[{i:>3}] "
        if isinstance(score, (int, float)):
            header += f"{int(score * 100):>3}% "
        if match:
            header += f"({match}) "
        print(header)
        for k, v in row.items():
            if k.startswith("_"):
                continue
            if v in (None, ""):
                continue
            val = ", ".join(map(str, v)) if isinstance(v, (list, tuple)) else str(v)
            if len(val) > 80:
                val = val[:79] + "…"
            print(f"      {k:<14} {val}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
