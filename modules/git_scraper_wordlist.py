#!/usr/bin/env python3
"""
modules/git_scraper_wordlist.py — v1.0.0
═══════════════════════════════════════════════════════════════════════════
Professional wordlist scraper for the Oxysintx / Emergens framework.

Pulls every wordlist required by the security modules from public GitHub
sources, validates content, dedupes, atomically writes to ``wordlist/``,
and invalidates the in-memory caches of the consumer modules.

Consumers
    • modules/xss_exploiter.py    → wordlist/xss_exploit.txt
    • modules/sqli_engine.py      → wordlist/sqli_*.txt   (8 files)
    • modules/dirfuzz.py          → wordlist/lottery-dirs.txt
                                    wordlist/common.txt
                                    wordlist/raft-small-directories.txt

Features
    ✔  Single manifest describing every source
    ✔  Concurrent downloads (thread pool, configurable)
    ✔  Per-source retry with exponential backoff
    ✔  Circuit-breaker (per-source cooldown after repeated failures)
    ✔  Content validation — rejects HTML error pages, empty files
    ✔  Multi-source merge + dedupe per target file
    ✔  Atomic writes (tmp → os.replace) — no partial files ever land
    ✔  Cache invalidation of consumer modules after sync
    ✔  Progress callback + cancel event (SSE-ready)
    ✔  Streaming API: yields 'start', 'file', 'progress', 'done', 'error'
    ✔  CLI: --modules, --force, --json, --stream, --list, --status
    ✔  Windows / macOS / Linux

Public API
    ─ sync(modules=None, force=False, **opts)               → dict report
    ─ sync_streaming(modules=None, force=False, ...)        → Iterator[dict]
    ─ list_wordlists()                                       → dict
    ─ get_manifest()                                         → dict
    ─ reload_caches()                                        → dict

Author: Yanxzyx
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set

import requests

try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    HTTPAdapter = None
    Retry = None


# ═══════════════════════════════════════════════════════════════════════════
# Metadata
# ═══════════════════════════════════════════════════════════════════════════
__version__ = "1.0.0"
__author__ = "Yanxzyx"
__framework__ = "Oxysintx / Emergens"

logger = logging.getLogger("oxysintx.wordlist_scraper")


# ═══════════════════════════════════════════════════════════════════════════
# Paths & tunables
# ═══════════════════════════════════════════════════════════════════════════
_PROJECT_ROOT  = Path(__file__).resolve().parent.parent
WORDLIST_DIR   = _PROJECT_ROOT / "wordlist"

DEFAULT_TIMEOUT       = 25.0     # per HTTP request
DEFAULT_RETRIES       = 3        # per source
DEFAULT_BACKOFF       = 1.5      # exponential backoff base
DEFAULT_WORKERS       = 4        # concurrent downloads
DEFAULT_MAX_LINES     = 50000    # cap per merged file
DOWNLOAD_COOLDOWN     = 300.0    # circuit-breaker cooldown (seconds)
BREAKER_FAIL_LIMIT    = 3        # failures in a row before breaker opens
MIN_ACCEPTABLE_LINES  = 5        # reject anything smaller

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36 Oxysintx-Wordlist-Scraper/" + __version__
)

_HTML_RE = re.compile(
    rb"^\s*(?:<!DOCTYPE\s+html|<html|<head|<\?xml|<title)",
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════
# Manifest — every file + every source
# ═══════════════════════════════════════════════════════════════════════════
MANIFEST: Dict[str, Dict[str, Any]] = {
    # ── XSS Exploiter ──────────────────────────────────────────────────
    "xss": {
        "description": "Reflected-XSS payloads used by modules/xss_exploiter.py",
        "files": {
            "xss_exploit.txt": {
                "description": "Primary XSS payload wordlist",
                "min_total_lines": 30,
                "max_total_lines": 8000,
                "merge": True,
                "sources": [
                    {
                        "name": "payload-box/xss-payload-list",
                        "url":  "https://raw.githubusercontent.com/payload-box/xss-payload-list/main/Payloads/All-In-One.txt",
                        "license": "MIT",
                        "min_lines": 20,
                    },
                    {
                        "name": "RenwaX23/XSS-Payloads",
                        "url":  "https://raw.githubusercontent.com/RenwaX23/XSS-Payloads/master/Payloads.txt",
                        "license": "MIT",
                        "min_lines": 15,
                    },
                    {
                        "name": "danielmiessler/SecLists (Jhaddix)",
                        "url":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt",
                        "license": "MIT",
                        "min_lines": 10,
                    },
                    {
                        "name": "danielmiessler/SecLists (Polyglots)",
                        "url":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Polyglots.txt",
                        "license": "MIT",
                        "min_lines": 5,
                    },
                ],
            },
        },
    },

    # ── SQLi Engine ────────────────────────────────────────────────────
    "sqli": {
        "description": "SQLi payloads used by modules/sqli_engine.py",
        "files": {
            "sqli_error_based.txt": {
                "description": "Error-based SQL injection payloads",
                "min_total_lines": 15,
                "max_total_lines": 3000,
                "merge": True,
                "sources": [
                    {
                        "name": "mad12wader/ffufwordlist — error-based",
                        "url":  "https://raw.githubusercontent.com/mad12wader/ffufwordlist/main/Generic%20Error%20Based%20Payloads",
                        "license": "unlicensed",
                        "min_lines": 8,
                    },
                    {
                        "name": "danielmiessler/SecLists — Generic-SQLi",
                        "url":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQL/Generic-SQLi.txt",
                        "license": "MIT",
                        "min_lines": 8,
                    },
                ],
            },
            "sqli_time_based.txt": {
                "description": "Time-based blind SQL injection payloads",
                "min_total_lines": 8,
                "max_total_lines": 1500,
                "merge": True,
                "sources": [
                    {
                        "name": "mad12wader/ffufwordlist — time-based",
                        "url":  "https://raw.githubusercontent.com/mad12wader/ffufwordlist/main/Generic%20Time%20Based%20SQL%20Injection%20Payloads",
                        "license": "unlicensed",
                        "min_lines": 5,
                    },
                ],
            },
            "sqli_union_select.txt": {
                "description": "UNION-based SQL injection payloads",
                "min_total_lines": 8,
                "max_total_lines": 1500,
                "merge": True,
                "sources": [
                    {
                        "name": "mad12wader/ffufwordlist — union select",
                        "url":  "https://raw.githubusercontent.com/mad12wader/ffufwordlist/main/Union%20Select%20Payloads",
                        "license": "unlicensed",
                        "min_lines": 5,
                    },
                ],
            },
            "sqli_auth_bypass.txt": {
                "description": "SQL auth-bypass payloads",
                "min_total_lines": 5,
                "max_total_lines": 1000,
                "merge": True,
                "sources": [
                    {
                        "name": "mad12wader/ffufwordlist — auth bypass",
                        "url":  "https://raw.githubusercontent.com/mad12wader/ffufwordlist/main/SQL%20Injection%20Auth%20Bypass%20Payloads",
                        "license": "unlicensed",
                        "min_lines": 3,
                    },
                ],
            },
            "sqli_seclists_generic.txt": {
                "description": "SecLists generic SQLi wordlist",
                "min_total_lines": 5,
                "max_total_lines": 3000,
                "merge": False,
                "sources": [
                    {
                        "name": "danielmiessler/SecLists — Generic-SQLi",
                        "url":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQL/Generic-SQLi.txt",
                        "license": "MIT",
                        "min_lines": 5,
                    },
                ],
            },
            "sqli_seclists_quick.txt": {
                "description": "SecLists quick SQLi wordlist",
                "min_total_lines": 5,
                "max_total_lines": 1000,
                "merge": False,
                "sources": [
                    {
                        "name": "danielmiessler/SecLists — quick-SQLi",
                        "url":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/quick-SQLi.txt",
                        "license": "MIT",
                        "min_lines": 5,
                    },
                ],
            },
            "sqli_seclists_polyglots.txt": {
                "description": "SecLists SQLi polyglot payloads",
                "min_total_lines": 3,
                "max_total_lines": 500,
                "merge": False,
                "sources": [
                    {
                        "name": "danielmiessler/SecLists — SQLi-Polyglots",
                        "url":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/SQLi-Polyglots.txt",
                        "license": "MIT",
                        "min_lines": 3,
                    },
                ],
            },
            "sqli_coffinxp.txt": {
                "description": "coffinxp all-sqli mega wordlist",
                "min_total_lines": 20,
                "max_total_lines": 20000,
                "merge": False,
                "sources": [
                    {
                        "name": "coffinxp/payloads — allsqli",
                        "url":  "https://raw.githubusercontent.com/coffinxp/payloads/main/allsqli.txt",
                        "license": "unlicensed",
                        "min_lines": 20,
                    },
                ],
            },
        },
    },

    # ── Dirfuzz ────────────────────────────────────────────────────────
    "dirfuzz": {
        "description": "Directory/file fuzzing wordlists used by modules/dirfuzz.py",
        "files": {
            "lottery-dirs.txt": {
                "description": "High-signal directory wordlist (sensitive paths first)",
                "min_total_lines": 40,
                "max_total_lines": 4000,
                "merge": True,
                "sources": [
                    {
                        "name": "danielmiessler/SecLists — common",
                        "url":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
                        "license": "MIT",
                        "min_lines": 30,
                    },
                    {
                        "name": "danielmiessler/SecLists — raft-small-directories",
                        "url":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
                        "license": "MIT",
                        "min_lines": 20,
                    },
                ],
            },
            "common.txt": {
                "description": "SecLists common.txt verbatim",
                "min_total_lines": 50,
                "max_total_lines": 10000,
                "merge": False,
                "sources": [
                    {
                        "name": "danielmiessler/SecLists — common",
                        "url":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
                        "license": "MIT",
                        "min_lines": 50,
                    },
                ],
            },
            "raft-small-directories.txt": {
                "description": "SecLists raft small directories",
                "min_total_lines": 30,
                "max_total_lines": 5000,
                "merge": False,
                "sources": [
                    {
                        "name": "danielmiessler/SecLists — raft-small-directories",
                        "url":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
                        "license": "MIT",
                        "min_lines": 30,
                    },
                ],
            },
        },
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class SourceResult:
    name: str
    url: str
    ok: bool = False
    status: str = "pending"     # pending | ok | failed | skipped | breaker
    lines: int = 0
    bytes: int = 0
    elapsed: float = 0.0
    error: str = ""


@dataclass
class FileReport:
    module: str
    filename: str
    description: str = ""
    path: str = ""
    ok: bool = False
    status: str = "pending"     # pending | ok | failed | skipped | unchanged
    source_results: List[SourceResult] = field(default_factory=list)
    merged_lines: int = 0
    merged_bytes: int = 0
    elapsed: float = 0.0
    error: str = ""

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "module":         self.module,
            "filename":       self.filename,
            "description":    self.description,
            "path":           self.path,
            "ok":             self.ok,
            "status":         self.status,
            "elapsed":        round(self.elapsed, 2),
            "merged_lines":   self.merged_lines,
            "merged_bytes":   self.merged_bytes,
            "error":          self.error,
            "sources":        [asdict(s) for s in self.source_results],
        }


@dataclass
class SyncReport:
    started_at: str
    finished_at: str = ""
    elapsed: float = 0.0
    modules_requested: List[str] = field(default_factory=list)
    total_files: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    cancelled: bool = False
    files: List[FileReport] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "started_at":   self.started_at,
            "finished_at":  self.finished_at,
            "elapsed":      round(self.elapsed, 2),
            "modules":      self.modules_requested,
            "total_files":  self.total_files,
            "succeeded":    self.succeeded,
            "failed":       self.failed,
            "skipped":      self.skipped,
            "cancelled":    self.cancelled,
            "files":        [f.to_public_dict() for f in self.files],
            "errors":       self.errors[:10],
            "version":      __version__,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════
def _ensure_dir() -> None:
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _filter_line(line: str) -> Optional[str]:
    """Return a cleaned, usable line or None if it should be dropped."""
    s = line.strip()
    if not s:
        return None
    if s.startswith(("#", "//", ";")):
        return None
    if len(s) > 800:
        return None
    return s


def _looks_like_html(raw: bytes) -> bool:
    head = raw[:512]
    return bool(_HTML_RE.search(head))


def _atomic_write(target: Path, content: str) -> None:
    """Write text to `target` atomically via a tmp file in the same dir."""
    tmp = target.with_suffix(target.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, target)


def _build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": _USER_AGENT, "Accept": "*/*"})
    if HTTPAdapter and Retry:
        adapter = HTTPAdapter(
            pool_connections=16, pool_maxsize=32,
            max_retries=Retry(
                total=1, backoff_factor=0.4,
                status_forcelist=(500, 502, 503, 504),
                allowed_methods=frozenset(["GET"]),
                raise_on_status=False,
            ),
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    return s


# ═══════════════════════════════════════════════════════════════════════════
# Circuit breaker (per source URL)
# ═══════════════════════════════════════════════════════════════════════════
class _CircuitBreaker:
    def __init__(self, cooldown: float = DOWNLOAD_COOLDOWN,
                 fail_limit: int = BREAKER_FAIL_LIMIT):
        self.cooldown   = cooldown
        self.fail_limit = fail_limit
        self._lock      = threading.Lock()
        self._fails: Dict[str, int]   = {}
        self._open_until: Dict[str, float] = {}

    def is_open(self, url: str) -> bool:
        with self._lock:
            until = self._open_until.get(url, 0.0)
            return time.monotonic() < until

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
                logger.warning("[scraper] circuit breaker opened for %s", url)


# ═══════════════════════════════════════════════════════════════════════════
# Scraper
# ═══════════════════════════════════════════════════════════════════════════
class WordlistScraper:

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
        workers: int = DEFAULT_WORKERS,
        max_lines: int = DEFAULT_MAX_LINES,
        cancel_event: Optional[threading.Event] = None,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
    ):
        self.timeout      = float(timeout)
        self.retries      = max(0, int(retries))
        self.backoff      = float(backoff)
        self.workers      = max(1, min(int(workers), 12))
        self.max_lines    = int(max_lines)
        self._stop        = cancel_event or threading.Event()
        self._progress_cb = progress_cb
        self._session     = _build_session()
        self._breaker     = _CircuitBreaker()
        self._file_lock   = threading.Lock()
        self._done        = 0
        self._total       = 0
        self._started     = 0.0

    # ── HTTP with retry + breaker ──────────────────────────────────────
    def _download(self, url: str) -> Optional[bytes]:
        if self._stop.is_set():
            return None
        if self._breaker.is_open(url):
            logger.info("[scraper] breaker open, skipping %s", url)
            return None

        last_err: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            if self._stop.is_set():
                return None
            try:
                r = self._session.get(url, timeout=self.timeout, stream=False)
                if r.status_code != 200:
                    last_err = RuntimeError(f"HTTP {r.status_code}")
                    raise last_err
                raw = r.content
                if not raw or len(raw) < 32:
                    last_err = RuntimeError("empty response")
                    raise last_err
                if _looks_like_html(raw):
                    last_err = RuntimeError("HTML page returned, not a wordlist")
                    raise last_err
                self._breaker.record_success(url)
                return raw
            except Exception as e:  # noqa: BLE001
                last_err = e
                if attempt < self.retries:
                    delay = self.backoff * (2 ** attempt)
                    time.sleep(min(delay, 8.0))

        logger.warning("[scraper] download failed: %s — %s", url, last_err)
        self._breaker.record_failure(url)
        return None

    # ── Content processing ─────────────────────────────────────────────
    def _process_source(
        self,
        source: Dict[str, Any],
        file_spec: Dict[str, Any],
    ) -> SourceResult:
        name      = source.get("name", "unknown")
        url       = source.get("url",  "")
        min_lines = int(source.get("min_lines", MIN_ACCEPTABLE_LINES))

        result = SourceResult(name=name, url=url)
        t0 = time.monotonic()

        raw = self._download(url)
        if raw is None:
            result.status  = "failed"
            result.error   = "download failed or breaker open"
            result.elapsed = time.monotonic() - t0
            return result

        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            result.status  = "failed"
            result.error   = f"decode error: {e}"
            result.elapsed = time.monotonic() - t0
            return result

        lines: List[str] = []
        for raw_line in text.splitlines():
            cleaned = _filter_line(raw_line)
            if cleaned:
                lines.append(cleaned)

        if len(lines) < min_lines:
            result.status  = "failed"
            result.error   = f"only {len(lines)} usable lines (need ≥{min_lines})"
            result.elapsed = time.monotonic() - t0
            return result

        result.lines   = len(lines)
        result.bytes   = len(raw)
        result.ok      = True
        result.status  = "ok"
        result.elapsed = time.monotonic() - t0
        # stash the parsed payloads on the result object for the merger
        setattr(result, "_payloads", lines)
        return result

    # ── Merge + write one file ─────────────────────────────────────────
    def _process_file(
        self,
        module: str,
        filename: str,
        spec: Dict[str, Any],
        *,
        force: bool,
    ) -> FileReport:
        report = FileReport(
            module=module,
            filename=filename,
            description=spec.get("description", ""),
            path=str(WORDLIST_DIR / filename),
        )
        t0 = time.monotonic()

        sources = spec.get("sources") or []
        if not sources:
            report.status = "failed"
            report.error  = "no sources declared in manifest"
            report.elapsed = time.monotonic() - t0
            return report

        # ── Skip existing file unless --force ──────────────────────────
        target = WORDLIST_DIR / filename
        if target.exists() and target.stat().st_size > 0 and not force:
            report.ok     = True
            report.status = "unchanged"
            report.merged_bytes = target.stat().st_size
            try:
                with open(target, "r", encoding="utf-8", errors="replace") as f:
                    report.merged_lines = sum(
                        1 for l in f if _filter_line(l)
                    )
            except OSError:
                pass
            report.elapsed = time.monotonic() - t0
            return report

        # ── Download every source concurrently ─────────────────────────
        source_results: List[SourceResult] = []
        merge = bool(spec.get("merge", True))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(self.workers, len(sources))
        ) as pool:
            futures = {
                pool.submit(self._process_source, s, spec): s
                for s in sources
            }
            for fut in concurrent.futures.as_completed(futures):
                if self._stop.is_set():
                    for f in futures: f.cancel()
                    break
                try:
                    source_results.append(fut.result())
                except Exception as e:  # noqa: BLE001
                    s = futures[fut]
                    source_results.append(SourceResult(
                        name=s.get("name", "unknown"),
                        url=s.get("url", ""),
                        status="failed", error=str(e),
                    ))

        report.source_results = source_results

        ok_results = [r for r in source_results if r.ok]
        if not ok_results:
            report.status  = "failed"
            report.error   = "all sources failed"
            report.elapsed = time.monotonic() - t0
            return report

        # ── Merge payloads ─────────────────────────────────────────────
        payloads: List[str] = []
        seen: Set[str] = set()
        for r in ok_results:
            for line in getattr(r, "_payloads", []) or []:
                if line in seen:
                    continue
                seen.add(line)
                payloads.append(line)
                if len(payloads) >= self.max_lines:
                    break
            if len(payloads) >= self.max_lines:
                break

        if not merge:
            # Non-merge: use the first successful source only
            payloads = list(getattr(ok_results[0], "_payloads", []) or [])[:self.max_lines]

        min_total = int(spec.get("min_total_lines", MIN_ACCEPTABLE_LINES))
        if len(payloads) < min_total:
            report.status  = "failed"
            report.error   = f"merged only {len(payloads)} lines (need ≥{min_total})"
            report.elapsed = time.monotonic() - t0
            return report

        # ── Compose file header ────────────────────────────────────────
        header_lines = [
            f"# {filename} — auto-synced by git_scraper_wordlist.py v{__version__}",
            f"# Module   : {module}",
            f"# Synced   : {_now_iso()}",
            f"# Sources  : {len(ok_results)} / {len(sources)}",
        ]
        for r in ok_results:
            header_lines.append(f"#   • {r.name} — {r.lines} lines")
        header_lines.append("")
        header_lines.append("")

        content = "\n".join(header_lines) + "\n".join(payloads) + "\n"

        try:
            _ensure_dir()
            _atomic_write(target, content)
        except OSError as e:
            report.status  = "failed"
            report.error   = f"write failed: {e}"
            report.elapsed = time.monotonic() - t0
            return report

        report.ok           = True
        report.status       = "ok"
        report.merged_lines = len(payloads)
        report.merged_bytes = len(content.encode("utf-8"))
        report.elapsed      = time.monotonic() - t0
        return report

    # ── Progress ───────────────────────────────────────────────────────
    def _emit(self, label: str) -> None:
        if not self._progress_cb:
            return
        try:
            self._progress_cb(self._done, self._total, label)
        except Exception:
            pass

    # ── Sync one module or all ─────────────────────────────────────────
    def sync(
        self,
        modules: Optional[List[str]] = None,
        *,
        force: bool = False,
    ) -> SyncReport:
        started = _now_iso()
        t0 = time.monotonic()
        self._started = t0

        wanted = [m for m in (modules or list(MANIFEST.keys())) if m in MANIFEST]
        if not wanted:
            wanted = list(MANIFEST.keys())

        report = SyncReport(
            started_at=started,
            modules_requested=list(wanted),
        )

        # Build task list
        tasks: List[tuple] = []
        for module in wanted:
            files = MANIFEST[module].get("files", {})
            for filename, spec in files.items():
                tasks.append((module, filename, spec))

        self._total = len(tasks)
        self._done  = 0

        # Run downloads concurrently (they're already network-bound)
        file_reports: List[FileReport] = []
        lock = threading.Lock()

        def _worker(task):
            module, filename, spec = task
            fr = self._process_file(module, filename, spec, force=force)
            with lock:
                self._done += 1
                self._emit(f"{module}/{filename} — {fr.status}")
            return fr

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(self.workers, max(1, len(tasks)))
        ) as pool:
            futures = [pool.submit(_worker, t) for t in tasks]
            for fut in concurrent.futures.as_completed(futures):
                if self._stop.is_set():
                    for f in futures: f.cancel()
                    break
                try:
                    file_reports.append(fut.result())
                except Exception as e:  # noqa: BLE001
                    report.errors.append(str(e))

        report.files        = file_reports
        report.total_files  = len(file_reports)
        report.succeeded    = sum(1 for f in file_reports if f.ok)
        report.skipped      = sum(1 for f in file_reports if f.status == "unchanged")
        report.failed       = sum(1 for f in file_reports if not f.ok)
        report.cancelled    = self._stop.is_set()
        report.finished_at  = _now_iso()
        report.elapsed      = time.monotonic() - t0
        return report


# ═══════════════════════════════════════════════════════════════════════════
# Cache invalidation for consumer modules
# ═══════════════════════════════════════════════════════════════════════════
def reload_caches() -> Dict[str, Any]:
    """
    Tell every consumer module to drop its in-memory wordlist cache.
    Returns a dict listing which modules were notified successfully.
    """
    out: Dict[str, Any] = {"reloaded": [], "missing": []}

    # xss_exploiter.py → module-level _wordlist_cache
    try:
        from modules import xss_exploiter  # type: ignore
        for attr in ("_wordlist_cache",):
            if hasattr(xss_exploiter, attr):
                try:
                    setattr(xss_exploiter, attr, None)
                except Exception:
                    pass
        out["reloaded"].append("xss_exploiter")
    except ImportError:
        out["missing"].append("xss_exploiter")

    # sqli_engine.py → module-level _wordlist_cache (dict) + lock
    try:
        from modules import sqli_engine  # type: ignore
        for attr in ("_wordlist_cache",):
            if hasattr(sqli_engine, attr):
                try:
                    cache = getattr(sqli_engine, attr)
                    if isinstance(cache, dict):
                        cache.clear()
                    else:
                        setattr(sqli_engine, attr, {})
                except Exception:
                    pass
        out["reloaded"].append("sqli_engine")
    except ImportError:
        out["missing"].append("sqli_engine")

    # dirfuzz.py — no persistent cache (reads disk each call), nothing to do
    try:
        from modules import dirfuzz  # noqa: F401  (import succeeds → OK)
        out["reloaded"].append("dirfuzz")
    except ImportError:
        out["missing"].append("dirfuzz")

    logger.info("[scraper] caches reloaded: %s", out["reloaded"])
    return out


# ═══════════════════════════════════════════════════════════════════════════
# Introspection API
# ═══════════════════════════════════════════════════════════════════════════
def _count_lines(path: Path) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for l in f if _filter_line(l))
    except OSError:
        return 0


def list_wordlists() -> Dict[str, Any]:
    """
    Return a manifest-driven status view of every known wordlist.
    Includes which files exist on disk and how many usable lines they hold.
    """
    _ensure_dir()
    out: Dict[str, Any] = {
        "directory": str(WORDLIST_DIR),
        "exists":    WORDLIST_DIR.exists(),
        "modules":   {},
        "version":   __version__,
    }
    for module, spec in MANIFEST.items():
        mod_entry: Dict[str, Any] = {
            "description": spec.get("description", ""),
            "files": [],
        }
        for filename, file_spec in (spec.get("files") or {}).items():
            p = WORDLIST_DIR / filename
            exists = p.exists() and p.stat().st_size > 0
            mod_entry["files"].append({
                "filename":    filename,
                "description": file_spec.get("description", ""),
                "path":        str(p),
                "exists":      exists,
                "size":        p.stat().st_size if exists else 0,
                "lines":       _count_lines(p) if exists else 0,
                "min_lines":   file_spec.get("min_total_lines", MIN_ACCEPTABLE_LINES),
                "sources":     [s.get("name") for s in (file_spec.get("sources") or [])],
            })
        out["modules"][module] = mod_entry
    return out


def get_manifest() -> Dict[str, Any]:
    """Return the raw manifest (useful for admin UI)."""
    return {
        "version":  __version__,
        "manifest": MANIFEST,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Public blocking API
# ═══════════════════════════════════════════════════════════════════════════
def sync(
    modules: Optional[List[str]] = None,
    *,
    force: bool = False,
    workers: int = DEFAULT_WORKERS,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Blocking sync. Returns a JSON-serialisable report."""
    scraper = WordlistScraper(workers=workers, timeout=timeout)
    report  = scraper.sync(modules, force=force)
    public  = report.to_public_dict()
    try:
        public["reload"] = reload_caches()
    except Exception as e:  # noqa: BLE001
        public["reload"] = {"error": str(e)}
    return public


# ═══════════════════════════════════════════════════════════════════════════
# Streaming API (SSE-ready)
# ═══════════════════════════════════════════════════════════════════════════
def sync_streaming(
    modules: Optional[List[str]] = None,
    *,
    force: bool = False,
    workers: int = DEFAULT_WORKERS,
    timeout: float = DEFAULT_TIMEOUT,
    cancel_event: Optional[threading.Event] = None,
) -> Iterator[Dict[str, Any]]:
    """
    Yield SSE-friendly events:
        {type:'start'}          — initial info
        {type:'file'}           — one file just finished
        {type:'progress'}       — counter tick
        {type:'complete', ...}  — final report
        {type:'error', ...}     — fatal error
    """
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

    scraper = WordlistScraper(
        workers=workers, timeout=timeout,
        cancel_event=cancel_event, progress_cb=_progress,
    )

    def _worker() -> None:
        try:
            holder["report"] = scraper.sync(modules, force=force)
        except Exception as e:  # noqa: BLE001
            holder["error"] = str(e)
        finally:
            done.set()

    threading.Thread(target=_worker, daemon=True,
                     name="wordlist-sync").start()

    wanted = [m for m in (modules or list(MANIFEST.keys())) if m in MANIFEST]
    yield {
        "type":    "start",
        "modules": wanted or list(MANIFEST.keys()),
        "force":   force,
        "version": __version__,
        "target":  str(WORDLIST_DIR),
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
        return

    report = holder.get("report")
    if report is None:
        yield {"type": "error", "message": "no report produced"}
        return

    public = report.to_public_dict()
    try:
        public["reload"] = reload_caches()
    except Exception as e:  # noqa: BLE001
        public["reload"] = {"error": str(e)}

    yield {"type": "complete", "report": public}


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def _cli() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    p = argparse.ArgumentParser(
        description="git_scraper_wordlist.py — sync wordlists from GitHub",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--modules", default="",
                   help="comma-separated module list (xss,sqli,dirfuzz)")
    p.add_argument("--force", action="store_true",
                   help="re-download even if the file already exists")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--json",   action="store_true", help="raw JSON output")
    p.add_argument("--stream", action="store_true", help="stream progress events")
    p.add_argument("--list",   action="store_true", help="print manifest and exit")
    p.add_argument("--status", action="store_true", help="print current status and exit")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args()

    if args.list:
        print(json.dumps(get_manifest(), indent=2))
        return 0

    if args.status:
        print(json.dumps(list_wordlists(), indent=2))
        return 0

    modules = [m.strip() for m in args.modules.split(",") if m.strip()] or None

    if args.stream:
        for ev in sync_streaming(
            modules, force=args.force,
            workers=args.workers, timeout=args.timeout,
        ):
            t = ev.get("type")
            if t == "start":
                print(f"[start] modules={ev['modules']} target={ev['target']}")
            elif t == "progress":
                print(f"[{ev['percent']:3d}%] {ev['label']}")
            elif t == "complete":
                r = ev["report"]
                print(f"[done] ok={r['succeeded']} "
                      f"failed={r['failed']} skipped={r['skipped']} "
                      f"elapsed={r['elapsed']}s")
                if args.json:
                    print(json.dumps(r, indent=2))
            elif t == "error":
                print(f"[error] {ev['message']}", file=sys.stderr)
        return 0

    report = sync(modules, force=args.force,
                  workers=args.workers, timeout=args.timeout)

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report["failed"] == 0 else 1

    print()
    print("═" * 72)
    print(f"  Wordlist Sync — {report['succeeded']} ok, "
          f"{report['failed']} failed, {report['skipped']} skipped "
          f"({report['elapsed']}s)")
    print("═" * 72)
    for f in report["files"]:
        mark = "✓" if f["ok"] else "✗"
        print(f"  [{mark}] {f['module']:8s} {f['filename']:28s} "
              f"{f['merged_lines']:6d} lines  ({f['status']})")
        if not f["ok"] and f["error"]:
            print(f"          error: {f['error']}")
    print()
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(_cli())
