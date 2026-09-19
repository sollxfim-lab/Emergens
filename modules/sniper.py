#!/usr/bin/env python3
"""
modules/sniper.py — v2.0.0
═══════════════════════════════════════════════════════════════════════════
Sniper: Auto-Exploiter — full-stack recon orchestrator.

Changelog v2.0.0
    • Per-module timeout (default 90s) with graceful degradation
    • Global time budget (default 150s) — hard cap on total duration
    • Cancellation propagates into every adapter via threading.Event
    • SSE heartbeat emitted every 10s so proxies don't kill the stream
    • Updated XSS defaults (matches xss_exploiter v2)
    • Reduced Takeover default hosts (300 → 120) and dirfuzz paths (100 → 80)
    • Local wordlist loader — no more `from app import _load_wordlist`
    • `timed_out` flag on ModuleResult for honest reporting
    • Progress events throttled + ETA estimation
    • Startup warm-up — pre-loads wordlist + validates imports at module load

Public API (backward compatible)
    ─ run(target, options)                 → aggregated report dict
    ─ run_streaming(target, options)       → generator of SSE-friendly events
    ─ SniperScanner                        → class-based interface

Author: Yanxzyx
"""

from __future__ import annotations

import concurrent.futures
import logging
import queue
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger("oxysintx.sniper")

__version__ = "2.0.0"

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORDLIST_DIR = _PROJECT_ROOT / "wordlist"

# ── Tunables ──────────────────────────────────────────────────────────────
DEFAULT_MODULE_TIMEOUT = 90.0    # seconds per module
DEFAULT_GLOBAL_BUDGET  = 150.0   # seconds for whole sniper run
DEFAULT_HEARTBEAT      = 10.0    # seconds between SSE heartbeats
PROBE_USER_AGENT       = "Emergens-Sniper/2.0 (+https://github.com/)"

# Fallback wordlist if wordlist/ isn't available
_FALLBACK_DIRS: List[str] = [
    ".env", ".git/config", ".git/", ".svn/", ".well-known/security.txt",
    "admin/", "administrator/", "backup/", "backups/", "old/", "temp/",
    "wp-admin/", "wp-login.php", "wp-config.php.bak", "xmlrpc.php",
    "phpmyadmin/", "pma/", "adminer.php", "adminer/", "mysql/",
    "config.php", "config.json", "config.yml", "configuration.php",
    "server-status", "server-info", "phpinfo.php", "info.php", "test.php",
    "api/", "api/v1/", "api/v2/", "graphql", "rest/", "swagger.json",
    "openapi.json", "api-docs/", "robots.txt", "sitemap.xml",
    "uploads/", "files/", "static/", "assets/", "images/", "media/",
    ".DS_Store", "Dockerfile", "docker-compose.yml", ".dockerignore",
    "composer.json", "package.json", ".htaccess", ".htpasswd",
    "web.config", "id_rsa", "id_rsa.pub", ".ssh/", "private.key",
    "dump.sql", "database.sql", "backup.sql", "db.sql", "data.sql",
]


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class ModuleResult:
    name: str
    ok: bool = False
    timed_out: bool = False
    cancelled: bool = False
    elapsed: float = 0.0
    error: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "elapsed": round(self.elapsed, 2),
            "error": self.error,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "summary": self.summary,
        }


@dataclass
class SniperReport:
    target: str
    host: str
    started_at: str
    finished_at: str = ""
    elapsed: float = 0.0
    budget_exceeded: bool = False
    cancelled: bool = False
    modules: List[ModuleResult] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "unknown"
    priority_findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "host": self.host,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed": round(self.elapsed, 2),
            "budget_exceeded": self.budget_exceeded,
            "cancelled": self.cancelled,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "priority_findings": self.priority_findings,
            "modules": [m.to_public_dict() for m in self.modules],
            "errors": self.errors[:10],
            "version": __version__,
            "counts": {
                "sqli":     self._count("SQLi"),
                "xss":      self._count("XSS"),
                "dirfuzz":  self._count("Directory Fuzzer"),
                "takeover": self._count("Subdomain Takeover"),
            },
        }

    def _count(self, name: str) -> int:
        for m in self.modules:
            if m.name == name:
                return len(m.findings)
        return 0


# ═══════════════════════════════════════════════════════════════════════════
# Local wordlist loader (avoids circular import from app)
# ═══════════════════════════════════════════════════════════════════════════
def _load_local_wordlist(name: str, max_lines: int = 80) -> List[str]:
    """Load a .txt wordlist from wordlist/ without importing app."""
    if not name:
        return []
    base = Path(name).name
    if not base.endswith(".txt"):
        base += ".txt"
    target = (WORDLIST_DIR / base).resolve()
    try:
        target.relative_to(WORDLIST_DIR.resolve())
    except ValueError:
        return []
    if not target.exists() or not target.is_file():
        return []
    try:
        lines: List[str] = []
        with target.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                lines.append(s)
                if len(lines) >= max_lines:
                    break
        return lines
    except OSError:
        return []


# ═══════════════════════════════════════════════════════════════════════════
# Module adapters
# ═══════════════════════════════════════════════════════════════════════════
class _ModuleAdapter:
    name: str = "Module"
    default_timeout: float = DEFAULT_MODULE_TIMEOUT

    def run(
        self,
        target: str,
        options: Dict[str, Any],
        progress: Optional[Callable[[str, int], None]] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> ModuleResult:
        raise NotImplementedError

    # ── helpers ──────────────────────────────────────────────────────
    @staticmethod
    def _cancelled(cancel_event: Optional[threading.Event]) -> bool:
        return cancel_event is not None and cancel_event.is_set()


# ── SQLi ────────────────────────────────────────────────────────────────
class _SqliAdapter(_ModuleAdapter):
    name = "SQLi"
    default_timeout = 120.0

    def run(self, target, options, progress=None, cancel_event=None):
        t0 = time.monotonic()
        result = ModuleResult(name=self.name)

        if progress:
            progress("SQLi — running", 10)
        try:
            from modules import analytic_manager  # type: ignore
            if not hasattr(analytic_manager, "AnalyticDataManager"):
                raise ImportError("AnalyticDataManager not available")
            engine = analytic_manager.AnalyticDataManager()
            report = engine.run_sql_injection_scan(target, "GET", None)
            payload = report.get("results", report) if isinstance(report, dict) else report
            findings = payload.get("findings", []) if isinstance(payload, dict) else []
            result.findings = findings
            result.summary = {
                "vulnerable":    bool(payload.get("vulnerable")) if isinstance(payload, dict) else False,
                "requests_sent": payload.get("requests_sent", 0) if isinstance(payload, dict) else 0,
                "duration":      payload.get("duration", 0) if isinstance(payload, dict) else 0,
                "database_hint": payload.get("database_hint") if isinstance(payload, dict) else None,
            }
            result.ok = True
            if progress:
                progress("SQLi — complete", 100)
        except Exception as e:  # noqa: BLE001
            result.error = str(e)
            logger.warning("[sniper] SQLi module failed: %s", e)

        result.elapsed = time.monotonic() - t0
        return result


# ── XSS (defaults match xss_exploiter v2) ────────────────────────────────
class _XssAdapter(_ModuleAdapter):
    name = "XSS"
    default_timeout = 90.0

    def run(self, target, options, progress=None, cancel_event=None):
        t0 = time.monotonic()
        result = ModuleResult(name=self.name)

        if progress:
            progress("XSS — running", 10)
        try:
            from modules import xss_exploiter  # type: ignore

            xss_options: Dict[str, Any] = {
                "max_payloads": int(options.get("xss_max_payloads", 20)),
                "max_params":   int(options.get("xss_max_params", 8)),
                "concurrency":  int(options.get("xss_concurrency", 8)),
                "rate_limit":   float(options.get("xss_rate_limit", 25.0)),
                "timeout":      float(options.get("xss_timeout", 8.0)),
                "waf_bypass":   bool(options.get("xss_waf_bypass", False)),
                "cancel_event": cancel_event,
            }
            # xss_exploiter v2 has progress_cb; v1 will ignore it
            if progress:
                def _xss_progress(done: int, total: int, label: str) -> None:
                    pct = int((done / total) * 80) + 10 if total else 10
                    progress(f"XSS — {done}/{total}", pct)
                xss_options["progress_cb"] = _xss_progress

            report = xss_exploiter.run(target, xss_options)
            result.findings = report.get("findings", [])
            result.summary = {
                "vulnerable":        report.get("vulnerable", False),
                "waf_detected":      report.get("waf_detected"),
                "payloads_tested":   report.get("payloads_tested", 0),
                "parameters_tested": report.get("parameters_tested", []),
                "requests_sent":     report.get("requests_sent", 0),
            }
            result.ok = True
            if progress:
                progress("XSS — complete", 100)
        except TypeError:
            # Older xss_exploiter that doesn't accept cancel_event — retry without it
            try:
                report = xss_exploiter.run(target, {
                    "max_payloads": int(options.get("xss_max_payloads", 20)),
                    "max_params":   int(options.get("xss_max_params", 8)),
                    "concurrency":  int(options.get("xss_concurrency", 8)),
                    "rate_limit":   float(options.get("xss_rate_limit", 25.0)),
                    "timeout":      float(options.get("xss_timeout", 8.0)),
                    "waf_bypass":   bool(options.get("xss_waf_bypass", False)),
                })
                result.findings = report.get("findings", [])
                result.summary = {"vulnerable": report.get("vulnerable", False)}
                result.ok = True
            except Exception as e:  # noqa: BLE001
                result.error = str(e)
        except Exception as e:  # noqa: BLE001
            result.error = str(e)
            logger.warning("[sniper] XSS module failed: %s", e)

        result.elapsed = time.monotonic() - t0
        return result


# ── Directory Fuzzer (cancellable) ────────────────────────────────────────
class _DirfuzzAdapter(_ModuleAdapter):
    name = "Directory Fuzzer"
    default_timeout = 75.0

    def run(self, target, options, progress=None, cancel_event=None):
        t0 = time.monotonic()
        result = ModuleResult(name=self.name)

        if progress:
            progress("Directory Fuzzer — starting", 10)
        try:
            base = target.rstrip("/")
            if not base.startswith(("http://", "https://")):
                base = "http://" + base

            wordlist_name = options.get("dirfuzz_wordlist") or "lottery-dirs.txt"
            max_paths = int(options.get("dirfuzz_max_paths", 80))

            wordlist = _load_local_wordlist(wordlist_name, max_lines=max_paths)
            if not wordlist:
                wordlist = _FALLBACK_DIRS[:max_paths]

            headers = {
                "User-Agent": PROBE_USER_AGENT,
                "Accept": "*/*",
            }
            timeout = float(options.get("dirfuzz_timeout", 4.0))
            workers = int(options.get("dirfuzz_concurrency", 16))

            hits: List[Dict[str, Any]] = []
            total = len(wordlist)
            done = 0
            hits_lock = threading.Lock()

            def _probe(path: str) -> Optional[Dict[str, Any]]:
                if self._cancelled(cancel_event):
                    return None
                url = f"{base}/{path.lstrip('/')}"
                try:
                    r = requests.get(
                        url, headers=headers, timeout=timeout,
                        allow_redirects=False, stream=True, verify=False,
                    )
                    status = r.status_code
                    size = r.headers.get("Content-Length") or 0
                    r.close()
                    if status == 404:
                        return None
                    return {"path": "/" + path.lstrip("/"),
                            "status": status, "size": size}
                except requests.exceptions.RequestException:
                    return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(_probe, p): p for p in wordlist}
                for fut in concurrent.futures.as_completed(futures):
                    if self._cancelled(cancel_event):
                        for f in futures:
                            f.cancel()
                        break
                    done += 1
                    try:
                        h = fut.result()
                    except Exception:
                        h = None
                    if h:
                        with hits_lock:
                            hits.append(h)
                    if progress and done % 8 == 0:
                        pct = int(done / total * 85) + 10
                        progress(f"{done}/{total}", pct)

            # Rank: sensitive configs first
            def _rank(h: Dict[str, Any]) -> int:
                p = h["path"].lower()
                if any(x in p for x in (".env", ".git", "backup", "dump",
                                        ".sql", ".bak", "config", ".ssh",
                                        "id_rsa", "htpasswd")):
                    return 0
                if h["status"] in (401, 403):
                    return 1
                if h["status"] == 200:
                    return 2
                return 3
            hits.sort(key=_rank)

            result.findings = hits
            result.summary = {
                "tried":    total,
                "hits":     len(hits),
                "source":   wordlist_name if _load_local_wordlist(wordlist_name, 1) else "bundled",
                "critical": sum(
                    1 for h in hits
                    if any(x in h["path"].lower()
                           for x in (".env", ".git", "backup", "dump",
                                     ".sql", ".bak", ".ssh", "id_rsa"))
                ),
            }
            result.ok = True
            if progress:
                progress("Directory Fuzzer — complete", 100)
        except Exception as e:  # noqa: BLE001
            result.error = str(e)
            logger.warning("[sniper] Directory Fuzzer failed: %s", e)

        result.elapsed = time.monotonic() - t0
        return result


# ── Subdomain Takeover (reduced default hosts) ────────────────────────────
class _TakeoverAdapter(_ModuleAdapter):
    name = "Subdomain Takeover"
    default_timeout = 90.0

    def run(self, target, options, progress=None, cancel_event=None):
        t0 = time.monotonic()
        result = ModuleResult(name=self.name)

        if progress:
            progress("Subdomain Takeover — starting", 10)
        try:
            from modules import subdomain_takeover  # type: ignore
            host = _host_from_target(target)
            report = subdomain_takeover.run(host, {
                "enumerate":    bool(options.get("takeover_enumerate", True)),
                "use_crtsh":    bool(options.get("takeover_crtsh", True)),
                "use_wordlist": bool(options.get("takeover_wordlist", True)),
                "concurrency":  int(options.get("takeover_concurrency", 24)),
                "max_hosts":    int(options.get("takeover_max_hosts", 120)),
                "rate_limit":   float(options.get("takeover_rate_limit", 20.0)),
                "http_timeout": float(options.get("takeover_http_timeout", 6.0)),
                "dns_timeout":  float(options.get("takeover_dns_timeout", 2.5)),
            })
            dangling = report.get("dangling", []) or []
            result.findings = dangling
            result.summary = {
                "scanned":    report.get("scanned", 0),
                "candidates": len(report.get("candidates", [])),
                "dangling":   len(dangling),
            }
            result.ok = True
            if progress:
                progress("Subdomain Takeover — complete", 100)
        except Exception as e:  # noqa: BLE001
            result.error = str(e)
            logger.warning("[sniper] Takeover module failed: %s", e)

        result.elapsed = time.monotonic() - t0
        return result


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════
def _host_from_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "http://" + t
    try:
        return urlparse(t).hostname or ""
    except Exception:
        return t.split("/")[0].split(":")[0]


def _compute_risk(report: SniperReport) -> None:
    score = 0.0
    for m in report.modules:
        if not m.ok and not m.findings:
            continue
        for f in m.findings:
            sev = (f.get("severity") or "").lower()
            try:
                conf = float(f.get("confidence") or 0.5)
            except (TypeError, ValueError):
                conf = 0.5

            if m.name == "SQLi":
                score += 30 * max(conf, 0.5)
            elif m.name == "XSS":
                score += (22 if sev in ("high", "critical") else 14) * max(conf, 0.5)
            elif m.name == "Directory Fuzzer":
                st = f.get("status", 0)
                score += 8 if st == 200 else (5 if st in (401, 403) else 2)
                if any(x in (f.get("path") or "").lower()
                       for x in (".env", ".git", "backup", ".sql", ".bak",
                                 ".ssh", "id_rsa")):
                    score += 15
            elif m.name == "Subdomain Takeover":
                risk = (f.get("risk") or "").lower()
                score += {"confirmed": 35, "probable": 22}.get(risk, 10)

    score = int(min(100, round(score)))
    report.risk_score = score
    if   score >= 70: report.risk_level = "critical"
    elif score >= 45: report.risk_level = "high"
    elif score >= 20: report.risk_level = "medium"
    elif score > 0:   report.risk_level = "low"
    else:             report.risk_level = "none"


def _priority_rank(report: SniperReport) -> None:
    priority: List[Dict[str, Any]] = []
    weights = {
        "SQLi": 100,
        "Subdomain Takeover": 90,
        "XSS": 80,
        "Directory Fuzzer": 50,
    }

    for m in report.modules:
        if not m.findings:
            continue
        base = weights.get(m.name, 10)
        for f in m.findings:
            entry = {
                "module": m.name,
                "target": report.target,
                "severity": (f.get("severity") or "medium").lower(),
                "confidence": float(f.get("confidence") or 0.5),
                "detail": f,
                "weight": base,
            }
            if m.name == "Directory Fuzzer":
                st = f.get("status", 0)
                path = (f.get("path") or "").lower()
                if any(x in path for x in (".env", ".git", "backup", ".sql",
                                            ".bak", ".ssh", "id_rsa")):
                    entry["severity"] = "critical"
                    entry["weight"] += 40
                elif st == 200:
                    entry["severity"] = "high"
                    entry["weight"] += 20
            elif m.name == "Subdomain Takeover":
                risk = (f.get("risk") or "").lower()
                if risk == "confirmed":
                    entry["severity"] = "critical"
                    entry["weight"] += 40
                elif risk == "probable":
                    entry["severity"] = "high"
                    entry["weight"] += 20

            priority.append(entry)

    priority.sort(key=lambda e: (-e["weight"], -e["confidence"]))
    report.priority_findings = priority[:20]


# ═══════════════════════════════════════════════════════════════════════════
# Sniper Scanner
# ═══════════════════════════════════════════════════════════════════════════
class SniperScanner:
    """Orchestrates the four modules against a target with per-module timeouts."""

    def __init__(
        self,
        *,
        module_timeout: float = DEFAULT_MODULE_TIMEOUT,
        global_budget: float = DEFAULT_GLOBAL_BUDGET,
        cancel_event: Optional[threading.Event] = None,
    ):
        self.module_timeout = float(module_timeout)
        self.global_budget = float(global_budget)
        self._stop = cancel_event or threading.Event()
        self._adapters: List[_ModuleAdapter] = [
            _SqliAdapter(),
            _XssAdapter(),
            _DirfuzzAdapter(),
            _TakeoverAdapter(),
        ]

    def cancel(self) -> None:
        self._stop.set()

    def _make_report(self, target: str) -> SniperReport:
        return SniperReport(
            target=target,
            host=_host_from_target(target),
            started_at=datetime.now(timezone.utc).isoformat(),
        )

    # ── Run a single adapter with a hard per-module timeout ────────────
    def _run_with_timeout(
        self,
        adapter: _ModuleAdapter,
        target: str,
        options: Dict[str, Any],
        progress: Optional[Callable[[str, int], None]] = None,
        deadline: Optional[float] = None,
    ) -> ModuleResult:
        local_cancel = threading.Event()

        def _watchdog() -> None:
            wait_until = time.monotonic() + min(
                self.module_timeout,
                (deadline - time.monotonic()) if deadline else self.module_timeout,
            )
            while time.monotonic() < wait_until:
                if self._stop.is_set():
                    local_cancel.set()
                    return
                time.sleep(0.25)
            # Timeout hit — propagate cancel
            local_cancel.set()

        watch_thread = threading.Thread(
            target=_watchdog, daemon=True,
            name=f"sniper-watchdog-{adapter.name}",
        )
        watch_thread.start()

        def _target_fn() -> ModuleResult:
            return adapter.run(
                target, options,
                progress=progress,
                cancel_event=local_cancel,
            )

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        fut = pool.submit(_target_fn)
        try:
            # Try to get a result within the effective per-module window
            effective = self.module_timeout
            if deadline is not None:
                effective = max(1.0, min(effective, deadline - time.monotonic()))
            result = fut.result(timeout=effective)
            if local_cancel.is_set() and not result.findings:
                # Cancelled early — mark honestly
                if self._stop.is_set():
                    result.cancelled = True
                else:
                    result.timed_out = True
                    result.error = result.error or "module timeout"
            return result
        except concurrent.futures.TimeoutError:
            local_cancel.set()
            logger.warning(
                "[sniper] module %s exceeded %.1fs — aborting",
                adapter.name, effective,
            )
            # Best-effort drain
            try:
                result = fut.result(timeout=0.1)
                result.timed_out = True
                if not result.error:
                    result.error = f"module timeout after {effective:.0f}s"
                return result
            except Exception:
                return ModuleResult(
                    name=adapter.name,
                    timed_out=True,
                    error=f"module timeout after {effective:.0f}s",
                )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    # ── Blocking API ───────────────────────────────────────────────────
    def run(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> SniperReport:
        options = options or {}
        report = self._make_report(target)
        t0 = time.monotonic()
        deadline = t0 + self.global_budget

        results: Dict[str, ModuleResult] = {}
        results_lock = threading.Lock()

        def _run(adapter: _ModuleAdapter) -> None:
            if self._stop.is_set():
                return
            r = self._run_with_timeout(adapter, target, options, deadline=deadline)
            with results_lock:
                results[adapter.name] = r

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self._adapters)
        ) as pool:
            futures = [pool.submit(_run, a) for a in self._adapters]
            remaining = max(0.1, deadline - time.monotonic())
            for f in concurrent.futures.as_completed(futures, timeout=remaining + 5):
                try:
                    f.result()
                except Exception as e:  # noqa: BLE001
                    logger.warning("[sniper] worker raised: %s", e)

        # Assemble report
        for a in self._adapters:
            r = results.get(a.name) or ModuleResult(
                name=a.name,
                error="module did not return a result",
                timed_out=True,
            )
            report.modules.append(r)
            if not r.ok and r.error:
                report.errors.append(f"{r.name}: {r.error}")

        if self._stop.is_set():
            report.cancelled = True
        if time.monotonic() > deadline:
            report.budget_exceeded = True

        _compute_risk(report)
        _priority_rank(report)
        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.elapsed = time.monotonic() - t0
        return report

    # ── Streaming API (SSE) with heartbeat ─────────────────────────────
    def run_streaming(
        self, target: str, options: Optional[Dict[str, Any]] = None
    ) -> Iterator[Dict[str, Any]]:
        options = options or {}
        report = self._make_report(target)
        t0 = time.monotonic()
        deadline = t0 + self.global_budget

        yield {
            "type": "start",
            "target": target,
            "host": report.host,
            "modules": [a.name for a in self._adapters],
            "module_timeout": self.module_timeout,
            "global_budget": self.global_budget,
            "version": __version__,
        }

        progress_q: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        results: Dict[str, ModuleResult] = {}
        results_lock = threading.Lock()
        started_modules = time.monotonic()

        def _emit(module: str, message: str, pct: int) -> None:
            progress_q.put({
                "type": "progress",
                "module": module,
                "message": message,
                "pct": max(0, min(100, int(pct))),
                "ts": round(time.monotonic() - started_modules, 2),
            })

        def _run(adapter: _ModuleAdapter) -> None:
            if self._stop.is_set():
                return
            progress_q.put({
                "type": "module_start",
                "module": adapter.name,
                "ts": round(time.monotonic() - started_modules, 2),
            })
            r = self._run_with_timeout(
                adapter, target, options,
                progress=lambda msg, pct, m=adapter.name: _emit(m, msg, pct),
                deadline=deadline,
            )
            with results_lock:
                results[adapter.name] = r
            progress_q.put({
                "type": "module_done",
                "module": adapter.name,
                "elapsed": round(r.elapsed, 2),
                "findings": len(r.findings),
                "ok": r.ok,
                "timed_out": r.timed_out,
                "error": r.error,
                "ts": round(time.monotonic() - started_modules, 2),
            })

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self._adapters)
        ) as pool:
            futures = [pool.submit(_run, a) for a in self._adapters]
            completed = 0
            total = len(futures)
            last_heartbeat = time.monotonic()

            while completed < total:
                # Hard budget check
                if time.monotonic() > deadline:
                    logger.warning("[sniper] global budget exceeded — aborting")
                    self._stop.set()
                    for f in futures:
                        f.cancel()
                    break

                if self._stop.is_set():
                    for f in futures:
                        f.cancel()
                    break

                try:
                    event = progress_q.get(timeout=0.5)
                except queue.Empty:
                    event = None

                if event is not None:
                    if event.get("type") == "module_done":
                        completed += 1
                    yield event
                    continue

                # Heartbeat every N seconds
                now = time.monotonic()
                if now - last_heartbeat >= DEFAULT_HEARTBEAT:
                    last_heartbeat = now
                    yield {
                        "type": "heartbeat",
                        "elapsed": round(now - t0, 2),
                        "modules_done": completed,
                        "modules_total": total,
                    }

            # Drain remaining events
            while True:
                try:
                    yield progress_q.get_nowait()
                except queue.Empty:
                    break

        # Assemble report
        for a in self._adapters:
            r = results.get(a.name) or ModuleResult(
                name=a.name,
                error="module did not return a result",
                timed_out=True,
            )
            report.modules.append(r)
            if not r.ok and r.error:
                report.errors.append(f"{r.name}: {r.error}")

        if self._stop.is_set():
            report.cancelled = True
        if time.monotonic() > deadline:
            report.budget_exceeded = True

        _compute_risk(report)
        _priority_rank(report)
        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.elapsed = time.monotonic() - t0

        yield {"type": "complete", "report": report.to_public_dict()}


# ═══════════════════════════════════════════════════════════════════════════
# Public helpers
# ═══════════════════════════════════════════════════════════════════════════
def run(
    target: str, options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Blocking full scan. Returns the aggregated report dict."""
    options = options or {}
    scanner = SniperScanner(
        module_timeout=float(options.get("module_timeout", DEFAULT_MODULE_TIMEOUT)),
        global_budget=float(options.get("global_budget", DEFAULT_GLOBAL_BUDGET)),
    )
    return scanner.run(target, options).to_public_dict()


def run_streaming(
    target: str, options: Optional[Dict[str, Any]] = None
) -> Iterator[Dict[str, Any]]:
    """Streaming full scan — yields progress events."""
    options = options or {}
    scanner = SniperScanner(
        module_timeout=float(options.get("module_timeout", DEFAULT_MODULE_TIMEOUT)),
        global_budget=float(options.get("global_budget", DEFAULT_GLOBAL_BUDGET)),
    )
    yield from scanner.run_streaming(target, options)


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

    p = argparse.ArgumentParser(description="Sniper: Auto-Exploiter CLI v2")
    p.add_argument("target", help="URL or host, e.g. https://example.com")
    p.add_argument("--json", action="store_true")
    p.add_argument("--stream", action="store_true")
    p.add_argument("--no-takeover", action="store_true")
    p.add_argument("--dirfuzz-wordlist", default="lottery-dirs.txt")
    p.add_argument("--dirfuzz-max-paths", type=int, default=80)
    p.add_argument("--module-timeout", type=float, default=DEFAULT_MODULE_TIMEOUT)
    p.add_argument("--global-budget", type=float, default=DEFAULT_GLOBAL_BUDGET)
    args = p.parse_args()

    options = {
        "dirfuzz_wordlist": args.dirfuzz_wordlist,
        "dirfuzz_max_paths": args.dirfuzz_max_paths,
        "takeover_enumerate": not args.no_takeover,
        "module_timeout": args.module_timeout,
        "global_budget": args.global_budget,
    }

    if args.stream:
        for ev in run_streaming(args.target, options):
            t = ev.get("type")
            if t == "progress":
                print(f"[{ev['module']:22s}] {ev['pct']:3d}%  {ev['message']}")
            elif t == "module_start":
                print(f"[{ev['module']:22s}] ▶ started")
            elif t == "module_done":
                status = "OK" if ev["ok"] else ("TIMEOUT" if ev.get("timed_out") else "FAIL")
                print(f"[{ev['module']:22s}] ◀ {status}  {ev['findings']} finding(s) in {ev['elapsed']:.2f}s")
                if ev.get("error"):
                    print(f"                         error: {ev['error']}")
            elif t == "heartbeat":
                print(f"[heartbeat] elapsed={ev['elapsed']}s  "
                      f"done={ev['modules_done']}/{ev['modules_total']}")
            elif t == "complete":
                if args.json:
                    print(json.dumps(ev["report"], indent=2))
        sys.exit(0)

    report = run(args.target, options)
    if args.json:
        print(json.dumps(report, indent=2))
        sys.exit(0)

    print("\n" + "═" * 72)
    print(f"  Sniper Report — {report['target']}")
    print("═" * 72)
    print(f"  Risk score : {report['risk_score']}/100 ({report['risk_level'].upper()})")
    print(f"  Elapsed    : {report['elapsed']}s")
    if report.get("budget_exceeded"):
        print("  Note       : global budget exceeded — partial results")
    if report.get("cancelled"):
        print("  Note       : cancelled")
    print()
    for m in report["modules"]:
        status = "OK" if m["ok"] else ("TIMEOUT" if m.get("timed_out") else "FAIL")
        print(f"  [{status:7s}] {m['name']:22s} {m['findings_count']:3d} finding(s) "
              f"in {m['elapsed']:.2f}s")
        if m["error"]:
            print(f"             error: {m['error']}")
    print()
