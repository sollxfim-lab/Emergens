#!/usr/bin/env python3
"""
modules/sniper.py — v2.1.0
═══════════════════════════════════════════════════════════════════════════
Sniper: Auto-Exploiter — full-stack recon orchestrator.

Changelog v2.1.0
    • Integrates xss_exploiter v2, subdomain_takeover v2, dirfuzz v2
    • Per-module timeout + global time budget (both configurable)
    • Cancel Event propagated into every adapter and sub-module
    • SSE heartbeat every 10s so proxies don't kill the stream
    • Progress callbacks wired end-to-end (dirfuzz / xss / takeover)
    • Cross-module correlation: CNAME dangling + takeover provider merge
    • Priority ranking with weighted scoring + dedup by (module, key)
    • Explicit `timed_out` / `cancelled` flags on every ModuleResult
    • Local wordlist loader — no `from app import _load_wordlist`
    • Reduced defaults to stay under 90s on typical targets
    • Structured progress events compatible with exploit.js SSE reader

Public API (backward compatible)
    ─ run(target, options)                          → dict report
    ─ run_streaming(target, options, cancel_event)  → Iterator[dict]
    ─ SniperScanner                                 → class interface
    ─ MODULE_TIMEOUTS / DEFAULT_*                   → tunables

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
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("oxysintx.sniper")

__version__ = "2.1.0"


# ═══════════════════════════════════════════════════════════════════════════
# Tunables
# ═══════════════════════════════════════════════════════════════════════════
DEFAULT_MODULE_TIMEOUT = 90.0        # per-module hard limit
DEFAULT_GLOBAL_BUDGET  = 150.0       # whole-run hard limit
DEFAULT_HEARTBEAT      = 10.0        # SSE heartbeat interval
PROGRESS_QUEUE_MAX     = 500         # back-pressure on SSE queue

MODULE_TIMEOUTS: Dict[str, float] = {
    "SQLi":               120.0,
    "XSS":                75.0,
    "Directory Fuzzer":   75.0,
    "Subdomain Takeover": 90.0,
}

# Risk weights per module (used by _compute_risk)
_MODULE_WEIGHTS: Dict[str, int] = {
    "SQLi":               100,
    "Subdomain Takeover": 90,
    "XSS":                80,
    "Directory Fuzzer":   50,
}


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
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

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
            "started_at": self.started_at,
            "finished_at": self.finished_at,
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
    correlations: List[Dict[str, Any]] = field(default_factory=list)
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
            "correlations": self.correlations,
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
# Utilities
# ═══════════════════════════════════════════════════════════════════════════
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _base_url_from_target(target: str) -> str:
    """Return a scheme-qualified base URL without trailing slash."""
    t = (target or "").strip()
    if not t:
        return ""
    if not t.startswith(("http://", "https://")):
        t = "http://" + t
    return t.rstrip("/")


def _severity_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        (sev or "").lower(), 5
    )


# ═══════════════════════════════════════════════════════════════════════════
# Module adapters
# ═══════════════════════════════════════════════════════════════════════════
class _ModuleAdapter:
    """Base class for a Sniper module adapter."""

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

    @staticmethod
    def _is_cancelled(ev: Optional[threading.Event]) -> bool:
        return ev is not None and ev.is_set()


# ── SQLi ────────────────────────────────────────────────────────────────
class _SqliAdapter(_ModuleAdapter):
    name = "SQLi"
    default_timeout = MODULE_TIMEOUTS["SQLi"]

    def run(self, target, options, progress=None, cancel_event=None):
        t0 = time.monotonic()
        result = ModuleResult(name=self.name, started_at=_now_iso())
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
        result.finished_at = _now_iso()
        return result


# ── XSS (uses xss_exploiter v2) ────────────────────────────────────────
class _XssAdapter(_ModuleAdapter):
    name = "XSS"
    default_timeout = MODULE_TIMEOUTS["XSS"]

    def run(self, target, options, progress=None, cancel_event=None):
        t0 = time.monotonic()
        result = ModuleResult(name=self.name, started_at=_now_iso())
        if progress:
            progress("XSS — running", 10)

        try:
            from modules import xss_exploiter  # type: ignore

            xss_opts: Dict[str, Any] = {
                "max_payloads": int(options.get("xss_max_payloads", 20)),
                "max_params":   int(options.get("xss_max_params", 8)),
                "concurrency":  int(options.get("xss_concurrency", 8)),
                "rate_limit":   float(options.get("xss_rate_limit", 25.0)),
                "timeout":      float(options.get("xss_timeout", 8.0)),
                "waf_bypass":   bool(options.get("xss_waf_bypass", False)),
                "cancel_event": cancel_event,
                "max_duration": float(options.get("xss_max_duration", 60.0)),
            }

            if progress:
                def _xss_progress(done: int, total: int, label: str) -> None:
                    pct = int((done / total) * 80) + 10 if total else 10
                    progress(f"XSS — {done}/{total}", pct)
                xss_opts["progress_cb"] = _xss_progress

            report = xss_exploiter.run(target, xss_opts)
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
            # Older xss_exploiter that doesn't accept cancel_event / progress_cb
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
        result.finished_at = _now_iso()
        return result


# ── Directory Fuzzer (uses dirfuzz v2) ─────────────────────────────────
class _DirfuzzAdapter(_ModuleAdapter):
    name = "Directory Fuzzer"
    default_timeout = MODULE_TIMEOUTS["Directory Fuzzer"]

    def run(self, target, options, progress=None, cancel_event=None):
        t0 = time.monotonic()
        result = ModuleResult(name=self.name, started_at=_now_iso())
        if progress:
            progress("Directory Fuzzer — starting", 10)

        try:
            from modules import dirfuzz as dirfuzz_module  # type: ignore

            base = _base_url_from_target(target)

            df_opts: Dict[str, Any] = {
                "wordlist_name":  options.get("dirfuzz_wordlist", "lottery-dirs.txt"),
                "max_paths":      int(options.get("dirfuzz_max_paths", 80)),
                "concurrency":    int(options.get("dirfuzz_concurrency", 24)),
                "rate_limit":     float(options.get("dirfuzz_rate_limit", 40.0)),
                "timeout":        float(options.get("dirfuzz_timeout", 4.0)),
                "max_duration":   float(options.get("dirfuzz_max_duration", 60.0)),
                "follow_redirects": bool(options.get("dirfuzz_follow_redirects", False)),
                "cancel_event":   cancel_event,
            }

            if progress:
                def _df_progress(done: int, total: int, label: str) -> None:
                    pct = int((done / total) * 85) + 10 if total else 10
                    progress(f"{done}/{total}", pct)
                df_opts["progress_cb"] = _df_progress

            report = dirfuzz_module.run(base, df_opts)
            hits = report.get("hits", [])

            # Normalise to the sniper findings format — keep only the
            # fields that matter for correlation & scoring
            result.findings = [
                {
                    "path":     h.get("path"),
                    "url":      h.get("url"),
                    "status":   h.get("status"),
                    "size":     h.get("size"),
                    "severity": h.get("severity", "info"),
                    "category": h.get("category", "other"),
                    "secrets":  h.get("secrets", []),
                    "redirect_to": h.get("redirect_to"),
                }
                for h in hits
            ]
            result.summary = {
                "tried":    report.get("tried", 0),
                "hits":     len(result.findings),
                "critical": report.get("critical_count", 0),
                "soft_404": report.get("soft_404", False),
            }
            result.ok = True
            if progress:
                progress("Directory Fuzzer — complete", 100)
        except Exception as e:  # noqa: BLE001
            result.error = str(e)
            logger.warning("[sniper] Directory Fuzzer failed: %s", e)

        result.elapsed = time.monotonic() - t0
        result.finished_at = _now_iso()
        return result


# ── Subdomain Takeover (uses subdomain_takeover v2) ────────────────────
class _TakeoverAdapter(_ModuleAdapter):
    name = "Subdomain Takeover"
    default_timeout = MODULE_TIMEOUTS["Subdomain Takeover"]

    def run(self, target, options, progress=None, cancel_event=None):
        t0 = time.monotonic()
        result = ModuleResult(name=self.name, started_at=_now_iso())
        if progress:
            progress("Subdomain Takeover — starting", 10)

        try:
            from modules import subdomain_takeover  # type: ignore

            host = _host_from_target(target)
            tk_opts: Dict[str, Any] = {
                "enumerate":     bool(options.get("takeover_enumerate", True)),
                "use_crtsh":     bool(options.get("takeover_crtsh", True)),
                "use_wordlist":  bool(options.get("takeover_wordlist", True)),
                "concurrency":   int(options.get("takeover_concurrency", 24)),
                "max_hosts":     int(options.get("takeover_max_hosts", 120)),
                "rate_limit":    float(options.get("takeover_rate_limit", 25.0)),
                "http_timeout":  float(options.get("takeover_http_timeout", 5.0)),
                "dns_timeout":   float(options.get("takeover_dns_timeout", 2.5)),
                "max_duration":  float(options.get("takeover_max_duration", 75.0)),
                "cancel_event":  cancel_event,
            }

            if progress:
                def _tk_progress(done: int, total: int, label: str) -> None:
                    pct = int((done / total) * 85) + 10 if total else 10
                    progress(f"{done}/{total}", pct)
                tk_opts["progress_cb"] = _tk_progress

            report = subdomain_takeover.run(host, tk_opts)
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
        result.finished_at = _now_iso()
        return result


# ═══════════════════════════════════════════════════════════════════════════
# Risk scoring
# ═══════════════════════════════════════════════════════════════════════════
def _compute_risk(report: SniperReport) -> None:
    score = 0.0
    for m in report.modules:
        if not m.findings:
            continue
        for f in m.findings:
            sev = (f.get("severity") or "").lower()
            try:
                conf = float(f.get("confidence") or 0.5)
            except (TypeError, ValueError):
                conf = 0.5
            conf = max(0.0, min(1.0, conf))

            if m.name == "SQLi":
                score += 30 * max(conf, 0.5)

            elif m.name == "XSS":
                base = 22 if sev in ("high", "critical") else 14
                score += base * max(conf, 0.5)

            elif m.name == "Directory Fuzzer":
                st = f.get("status", 0)
                if st == 200:
                    score += 8
                elif st in (401, 403):
                    score += 5
                else:
                    score += 2
                path_l = (f.get("path") or "").lower()
                if any(x in path_l for x in (".env", ".git", "backup", ".sql",
                                              ".bak", ".ssh", "id_rsa", "config")):
                    score += 15
                if f.get("secrets"):
                    score += 25  # leaked credentials are always serious

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


# ═══════════════════════════════════════════════════════════════════════════
# Priority ranking + dedup
# ═══════════════════════════════════════════════════════════════════════════
def _finding_key(module: str, f: Dict[str, Any]) -> str:
    """Stable dedup key per finding."""
    if module == "Directory Fuzzer":
        return f"dir:{f.get('path')}"
    if module == "XSS":
        return f"xss:{f.get('parameter')}:{f.get('context')}"
    if module == "Subdomain Takeover":
        return f"tk:{f.get('host')}:{f.get('provider')}"
    if module == "SQLi":
        return f"sqli:{f.get('parameter')}:{f.get('technique')}"
    return f"{module}:{hash(str(f))}"


def _priority_rank(report: SniperReport) -> None:
    priority: List[Dict[str, Any]] = []
    seen: set = set()

    for m in report.modules:
        if not m.findings:
            continue
        base_weight = _MODULE_WEIGHTS.get(m.name, 10)

        for f in m.findings:
            key = _finding_key(m.name, f)
            if key in seen:
                continue
            seen.add(key)

            entry: Dict[str, Any] = {
                "module": m.name,
                "target": report.target,
                "severity": (f.get("severity") or "medium").lower(),
                "confidence": float(f.get("confidence") or 0.5),
                "detail": f,
                "weight": base_weight,
            }

            if m.name == "Directory Fuzzer":
                st = f.get("status", 0)
                path_l = (f.get("path") or "").lower()
                if f.get("secrets"):
                    entry["severity"] = "critical"
                    entry["weight"] += 50
                elif any(x in path_l for x in (".env", ".git", "backup", ".sql",
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

            elif m.name == "XSS":
                if entry["severity"] in ("high", "critical"):
                    entry["weight"] += 15

            priority.append(entry)

    priority.sort(key=lambda e: (-e["weight"], -e["confidence"],
                                  _severity_order(e["severity"])))
    report.priority_findings = priority[:25]


# ═══════════════════════════════════════════════════════════════════════════
# Cross-module correlation
# ═══════════════════════════════════════════════════════════════════════════
def _correlate_findings(report: SniperReport) -> None:
    """
    Detect chains like:
      • Dirfuzz found a 200 exposing a takeover-provider CNAME
      • XSS on the same endpoint as SQLi
      • Dirfuzz found a config file referenced by a takeover host
    """
    corr: List[Dict[str, Any]] = []

    modules_by_name = {m.name: m for m in report.modules}

    # 1. Same parameter vulnerable to both XSS and SQLi
    xss = modules_by_name.get("XSS")
    sqli = modules_by_name.get("SQLi")
    if xss and sqli:
        xss_params = {
            (f.get("parameter") or "").lower()
            for f in xss.findings if f.get("parameter")
        }
        sqli_params = {
            (f.get("parameter") or "").lower()
            for f in sqli.findings if f.get("parameter")
        }
        overlap = xss_params & sqli_params
        if overlap:
            corr.append({
                "type": "same_parameter_multi_vuln",
                "severity": "critical",
                "message": f"Parameter(s) vulnerable to both XSS and SQLi: "
                           f"{', '.join(sorted(overlap))}",
                "evidence": sorted(overlap),
            })

    # 2. Takeover candidates + dirfuzz hits mentioning the same host
    tk = modules_by_name.get("Subdomain Takeover")
    df = modules_by_name.get("Directory Fuzzer")
    if tk and df:
        tk_hosts = {
            (f.get("host") or "").lower()
            for f in tk.findings if f.get("host")
        }
        for hit in df.findings:
            url_l = (hit.get("url") or "").lower()
            for h in tk_hosts:
                if h and h in url_l:
                    corr.append({
                        "type": "takeover_host_reachable",
                        "severity": "high",
                        "message": f"Dangling takeover host '{h}' is reachable "
                                   f"via fuzz path '{hit.get('path')}'",
                        "evidence": {"host": h, "path": hit.get("path")},
                    })
                    break

    # 3. Dirfuzz secrets leaked on the same host as takeover
    if df and tk:
        tk_providers = {
            (f.get("provider") or "").lower()
            for f in tk.findings if f.get("provider")
        }
        for hit in df.findings:
            if hit.get("secrets") and tk_providers:
                corr.append({
                    "type": "secret_exposed_on_takeover_target",
                    "severity": "critical",
                    "message": f"Leaked secret at '{hit.get('path')}' on a host "
                               f"with dangling CNAME",
                    "evidence": {
                        "path": hit.get("path"),
                        "secrets": [s.get("type") for s in hit.get("secrets", [])],
                    },
                })
                break  # one is enough — avoid spam

    # Deduplicate by type + message
    uniq: Dict[str, Dict[str, Any]] = {}
    for c in corr:
        key = f"{c['type']}:{c['message']}"
        uniq.setdefault(key, c)

    report.correlations = list(uniq.values())


# ═══════════════════════════════════════════════════════════════════════════
# Sniper Scanner
# ═══════════════════════════════════════════════════════════════════════════
class SniperScanner:
    """Orchestrates the four modules with per-module + global timeouts."""

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
            started_at=_now_iso(),
        )

    # ── Effective per-module timeout ───────────────────────────────────
    def _effective_timeout(self, adapter: _ModuleAdapter,
                           deadline: Optional[float]) -> float:
        per_module = MODULE_TIMEOUTS.get(adapter.name, self.module_timeout)
        per_module = min(per_module, self.module_timeout)
        if deadline is None:
            return per_module
        remaining = deadline - time.monotonic()
        return max(1.0, min(per_module, remaining))

    # ── Run one adapter with watchdog ──────────────────────────────────
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
            wait_until = time.monotonic() + self._effective_timeout(adapter, deadline)
            while time.monotonic() < wait_until:
                if self._stop.is_set():
                    local_cancel.set()
                    return
                time.sleep(0.2)
            local_cancel.set()   # timeout → propagate cancel

        watch = threading.Thread(target=_watchdog, daemon=True,
                                  name=f"sniper-watch-{adapter.name}")
        watch.start()

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = pool.submit(
            adapter.run, target, options, progress, local_cancel
        )

        effective = self._effective_timeout(adapter, deadline)
        try:
            result = future.result(timeout=effective + 1.0)
            if local_cancel.is_set() and not result.findings:
                if self._stop.is_set():
                    result.cancelled = True
                else:
                    result.timed_out = True
                    result.error = result.error or "module timeout"
            return result
        except concurrent.futures.TimeoutError:
            local_cancel.set()
            logger.warning("[sniper] %s exceeded %.1fs — aborting",
                            adapter.name, effective)
            # Give it a short grace period to unwind gracefully
            try:
                result = future.result(timeout=0.5)
                result.timed_out = True
                if not result.error:
                    result.error = f"module timeout after {effective:.0f}s"
                return result
            except Exception:
                return ModuleResult(
                    name=adapter.name,
                    timed_out=True,
                    elapsed=effective,
                    error=f"module timeout after {effective:.0f}s",
                    started_at=_now_iso(),
                    finished_at=_now_iso(),
                )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    # ── Blocking API ───────────────────────────────────────────────────
    def run(self, target: str,
            options: Optional[Dict[str, Any]] = None) -> SniperReport:
        options = options or {}
        report = self._make_report(target)
        t0 = time.monotonic()
        deadline = t0 + self.global_budget

        results: Dict[str, ModuleResult] = {}
        results_lock = threading.Lock()

        def _run(adapter: _ModuleAdapter) -> None:
            if self._stop.is_set():
                with results_lock:
                    results[adapter.name] = ModuleResult(
                        name=adapter.name, cancelled=True,
                        error="cancelled before start",
                        started_at=_now_iso(), finished_at=_now_iso(),
                    )
                return
            r = self._run_with_timeout(adapter, target, options, deadline=deadline)
            with results_lock:
                results[adapter.name] = r

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self._adapters)
        ) as pool:
            futures = [pool.submit(_run, a) for a in self._adapters]
            for fut in concurrent.futures.as_completed(
                futures, timeout=max(1.0, deadline - time.monotonic()) + 5.0
            ):
                try:
                    fut.result()
                except Exception as e:  # noqa: BLE001
                    logger.warning("[sniper] worker raised: %s", e)

        # Assemble
        for a in self._adapters:
            r = results.get(a.name) or ModuleResult(
                name=a.name,
                error="module did not return a result",
                timed_out=True,
                started_at=_now_iso(),
                finished_at=_now_iso(),
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
        _correlate_findings(report)
        report.finished_at = _now_iso()
        report.elapsed = time.monotonic() - t0
        return report

    # ── Streaming API (SSE) ────────────────────────────────────────────
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

        progress_q: "queue.Queue[Dict[str, Any]]" = queue.Queue(
            maxsize=PROGRESS_QUEUE_MAX
        )
        results: Dict[str, ModuleResult] = {}
        results_lock = threading.Lock()

        def _emit(module: str, message: str, pct: int) -> None:
            ev = {
                "type": "progress",
                "module": module,
                "message": message,
                "pct": max(0, min(100, int(pct))),
                "ts": round(time.monotonic() - t0, 2),
            }
            try:
                progress_q.put_nowait(ev)
            except queue.Full:
                # Drop oldest progress event under back-pressure
                try:
                    progress_q.get_nowait()
                    progress_q.put_nowait(ev)
                except Exception:
                    pass

        def _run(adapter: _ModuleAdapter) -> None:
            try:
                progress_q.put_nowait({
                    "type": "module_start",
                    "module": adapter.name,
                    "ts": round(time.monotonic() - t0, 2),
                })
            except queue.Full:
                pass

            if self._stop.is_set():
                with results_lock:
                    results[adapter.name] = ModuleResult(
                        name=adapter.name, cancelled=True,
                        error="cancelled before start",
                        started_at=_now_iso(), finished_at=_now_iso(),
                    )
                try:
                    progress_q.put_nowait({
                        "type": "module_done",
                        "module": adapter.name,
                        "elapsed": 0.0,
                        "findings": 0,
                        "ok": False,
                        "timed_out": False,
                        "cancelled": True,
                        "error": "cancelled before start",
                        "ts": round(time.monotonic() - t0, 2),
                    })
                except queue.Full:
                    pass
                return

            r = self._run_with_timeout(
                adapter, target, options,
                progress=lambda msg, pct, m=adapter.name: _emit(m, msg, pct),
                deadline=deadline,
            )
            with results_lock:
                results[adapter.name] = r
            try:
                progress_q.put_nowait({
                    "type": "module_done",
                    "module": adapter.name,
                    "elapsed": round(r.elapsed, 2),
                    "findings": len(r.findings),
                    "ok": r.ok,
                    "timed_out": r.timed_out,
                    "cancelled": r.cancelled,
                    "error": r.error,
                    "ts": round(time.monotonic() - t0, 2),
                })
            except queue.Full:
                pass

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self._adapters)
        ) as pool:
            futures = [pool.submit(_run, a) for a in self._adapters]
            completed = 0
            total = len(futures)
            last_heartbeat = time.monotonic()

            while completed < total:
                # Global budget check
                if time.monotonic() > deadline:
                    logger.warning("[sniper] global budget exceeded — aborting")
                    self._stop.set()
                    for f in futures:
                        f.cancel()
                    break

                # External cancel check
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

                # Heartbeat every DEFAULT_HEARTBEAT seconds
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
                started_at=_now_iso(), finished_at=_now_iso(),
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
        _correlate_findings(report)
        report.finished_at = _now_iso()
        report.elapsed = time.monotonic() - t0

        yield {"type": "complete", "report": report.to_public_dict()}


# ═══════════════════════════════════════════════════════════════════════════
# Public helpers
# ═══════════════════════════════════════════════════════════════════════════
def run(target: str,
        options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Blocking full scan. Returns the aggregated report dict."""
    options = options or {}
    scanner = SniperScanner(
        module_timeout=float(options.get("module_timeout", DEFAULT_MODULE_TIMEOUT)),
        global_budget=float(options.get("global_budget", DEFAULT_GLOBAL_BUDGET)),
        cancel_event=options.get("cancel_event"),
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
        cancel_event=options.get("cancel_event"),
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

    p = argparse.ArgumentParser(description="Sniper: Auto-Exploiter v2.1.0")
    p.add_argument("target", help="URL or host, e.g. https://example.com")
    p.add_argument("--json", action="store_true", help="raw JSON output")
    p.add_argument("--stream", action="store_true", help="stream progress events")
    p.add_argument("--no-takeover", action="store_true",
                   help="skip subdomain takeover module")
    p.add_argument("--no-sqli", action="store_true", help="skip SQLi module")
    p.add_argument("--no-xss", action="store_true", help="skip XSS module")
    p.add_argument("--no-dirfuzz", action="store_true", help="skip dirfuzz module")
    p.add_argument("--dirfuzz-wordlist", default="lottery-dirs.txt")
    p.add_argument("--dirfuzz-max-paths", type=int, default=80)
    p.add_argument("--xss-max-payloads", type=int, default=20)
    p.add_argument("--takeover-max-hosts", type=int, default=120)
    p.add_argument("--module-timeout", type=float, default=DEFAULT_MODULE_TIMEOUT)
    p.add_argument("--global-budget", type=float, default=DEFAULT_GLOBAL_BUDGET)
    args = p.parse_args()

    options = {
        "dirfuzz_wordlist":    args.dirfuzz_wordlist,
        "dirfuzz_max_paths":   args.dirfuzz_max_paths,
        "xss_max_payloads":    args.xss_max_payloads,
        "takeover_enumerate":  not args.no_takeover,
        "takeover_max_hosts":  args.takeover_max_hosts,
        "module_timeout":      args.module_timeout,
        "global_budget":       args.global_budget,
    }

    if args.stream:
        for ev in run_streaming(args.target, options):
            t = ev.get("type")
            if t == "start":
                print(f"[start] {ev['target']} — {len(ev['modules'])} modules")
            elif t == "module_start":
                print(f"[{ev['module']:22s}] ▶ start")
            elif t == "progress":
                print(f"[{ev['module']:22s}] {ev['pct']:3d}%  {ev['message']}")
            elif t == "module_done":
                status = "OK" if ev["ok"] else ("TIMEOUT" if ev.get("timed_out")
                                                else ("CANCELLED" if ev.get("cancelled") else "FAIL"))
                print(f"[{ev['module']:22s}] ◀ {status}  "
                      f"{ev['findings']} finding(s) in {ev['elapsed']:.2f}s")
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

    # ── Human report ───────────────────────────────────────────────────
    print()
    print("═" * 72)
    print(f"  Sniper Report — {report['target']}")
    print("═" * 72)
    print(f"  Risk score : {report['risk_score']}/100 ({report['risk_level'].upper()})")
    print(f"  Elapsed    : {report['elapsed']}s")
    if report.get("budget_exceeded"):
        print("  Note       : global budget exceeded — partial results")
    if report.get("cancelled"):
        print("  Note       : cancelled")
    print()

    print("  MODULE RESULTS")
    print("  " + "─" * 68)
    for m in report["modules"]:
        status = "OK" if m["ok"] else (
            "TIMEOUT" if m.get("timed_out") else (
                "CANCEL" if m.get("cancelled") else "FAIL"
            )
        )
        print(f"  [{status:7s}] {m['name']:22s} {m['findings_count']:3d} finding(s) "
              f"in {m['elapsed']:.2f}s")
        if m["error"]:
            print(f"             error: {m['error']}")
    print()

    if report.get("correlations"):
        print("  CORRELATIONS")
        print("  " + "─" * 68)
        for c in report["correlations"]:
            print(f"  [{c['severity'].upper():8s}] {c['message']}")
        print()

    if report["priority_findings"]:
        print("  TOP PRIORITY FINDINGS")
        print("  " + "─" * 68)
        for i, f in enumerate(report["priority_findings"][:10], 1):
            detail = f.get("detail") or {}
            key = (detail.get("parameter") or detail.get("path")
                   or detail.get("host") or "")
            print(f"  {i:2d}. [{f['severity'].upper():8s}] {f['module']:22s} {key}")
        print()
