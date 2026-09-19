#!/usr/bin/env python3
"""
modules/sniper.py
──────────────────────────────────────────────────────────────────────────
Sniper: Auto-Exploiter — full-stack recon orchestrator.

Runs four modules in a single pass:
    1. SQLi Exploiter      (modules.analytic_manager)
    2. XSS Exploiter       (modules.xss_exploiter)
    3. Directory Fuzzer    (inline wordlist probing)
    4. Subdomain Takeover  (modules.subdomain_takeover)

Features
    • Per-module timeouts and isolated failure handling
    • Optional progressive event streaming (SSE)
    • Risk aggregation and priority ranking
    • Unified report with one actionable score per target
    • Concurrency control — modules run in parallel by default
    • Cancellation support

Public API
    ─ run(target, options)              → aggregated report dict
    ─ run_streaming(target, options)    → generator of progress events
    ─ SniperScanner                     → class-based interface

Author: Yanxzyx
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("oxysintx.sniper")


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class ModuleResult:
    name: str
    ok: bool = False
    elapsed: float = 0.0
    error: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
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
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "priority_findings": self.priority_findings,
            "modules": [m.to_public_dict() for m in self.modules],
            "errors": self.errors[:10],
            "counts": {
                "sqli": _module_findings(self, "SQLi"),
                "xss": _module_findings(self, "XSS"),
                "dirfuzz": _module_findings(self, "Directory Fuzzer"),
                "takeover": _module_findings(self, "Subdomain Takeover"),
            },
        }


def _module_findings(report: SniperReport, name: str) -> int:
    for m in report.modules:
        if m.name == name:
            return len(m.findings)
    return 0


# ═══════════════════════════════════════════════════════════════════════════
# Module adapters — wrap existing modules behind a uniform interface
# ═══════════════════════════════════════════════════════════════════════════
class _ModuleAdapter:
    """Base class for a Sniper module adapter."""

    name: str = "Module"

    def run(self, target: str, options: Dict[str, Any],
            progress: Optional[Callable[[str, int], None]] = None
            ) -> ModuleResult:
        raise NotImplementedError


# ── SQLi ────────────────────────────────────────────────────────────────
class _SqliAdapter(_ModuleAdapter):
    name = "SQLi"

    def run(self, target, options, progress=None):
        t0 = time.monotonic()
        result = ModuleResult(name=self.name)

        if progress: progress("SQLi — running", 10)
        try:
            from modules import analytic_manager
            if not hasattr(analytic_manager, "AnalyticDataManager"):
                raise ImportError("AnalyticDataManager not available")
            engine = analytic_manager.AnalyticDataManager()
            report = engine.run_sql_injection_scan(target, "GET", None)
            payload = report.get("results", report) if isinstance(report, dict) else report
            findings = payload.get("findings", []) if isinstance(payload, dict) else []
            result.findings = findings
            result.summary = {
                "vulnerable": bool(payload.get("vulnerable")) if isinstance(payload, dict) else False,
                "requests_sent": payload.get("requests_sent", 0) if isinstance(payload, dict) else 0,
                "duration": payload.get("duration", 0) if isinstance(payload, dict) else 0,
                "database_hint": payload.get("database_hint") if isinstance(payload, dict) else None,
            }
            result.ok = True
            if progress: progress("SQLi — complete", 100)
        except Exception as e:  # noqa: BLE001
            result.error = str(e)
            logger.warning(f"[sniper] SQLi module failed: {e}")

        result.elapsed = time.monotonic() - t0
        return result


# ── XSS ─────────────────────────────────────────────────────────────────
class _XssAdapter(_ModuleAdapter):
    name = "XSS"

    def run(self, target, options, progress=None):
        t0 = time.monotonic()
        result = ModuleResult(name=self.name)

        if progress: progress("XSS — running", 10)
        try:
            from modules import xss_exploiter
            report = xss_exploiter.run(target, {
                "max_payloads": options.get("xss_max_payloads", 60),
                "max_params":   options.get("xss_max_params", 15),
                "concurrency":  options.get("xss_concurrency", 8),
                "rate_limit":   options.get("xss_rate_limit", 12.0),
                "waf_bypass":   options.get("xss_waf_bypass", True),
            })
            result.findings = report.get("findings", [])
            result.summary = {
                "vulnerable":       report.get("vulnerable", False),
                "waf_detected":     report.get("waf_detected"),
                "payloads_tested":  report.get("payloads_tested", 0),
                "parameters_tested": report.get("parameters_tested", []),
                "requests_sent":    report.get("requests_sent", 0),
            }
            result.ok = True
            if progress: progress("XSS — complete", 100)
        except Exception as e:  # noqa: BLE001
            result.error = str(e)
            logger.warning(f"[sniper] XSS module failed: {e}")

        result.elapsed = time.monotonic() - t0
        return result


# ── Directory Fuzzer ────────────────────────────────────────────────────
class _DirfuzzAdapter(_ModuleAdapter):
    name = "Directory Fuzzer"

    def run(self, target, options, progress=None):
        t0 = time.monotonic()
        result = ModuleResult(name=self.name)

        if progress: progress("Directory Fuzzer — starting", 10)
        try:
            from concurrent.futures import ThreadPoolExecutor
            import requests as _rq

            base = target.rstrip("/")
            if not base.startswith(("http://", "https://")):
                base = "http://" + base

            # Prefer a named wordlist if the sniper config requests one
            wordlist_name = options.get("dirfuzz_wordlist") or "lottery-dirs.txt"
            wordlist: List[str] = []

            # Try to load from wordlist/ (only if app-level helpers are available)
            try:
                from app import _load_wordlist  # type: ignore
                loaded, err = _load_wordlist(
                    wordlist_name,
                    max_lines=options.get("dirfuzz_max_paths", 100),
                )
                if not err and loaded:
                    wordlist = loaded
            except Exception:
                pass

            # Fallback to bundled subset if app-level loader is unavailable
            if not wordlist:
                wordlist = [
                    ".env", ".git/", ".svn/", "admin/", "administrator/",
                    "backup/", "backups/", "wp-admin/", "wp-login.php",
                    "phpmyadmin/", "pma/", "adminer.php", "config.php",
                    "config.json", "wp-config.php", "xmlrpc.php",
                    "server-status", "server-info", "phpinfo.php",
                    "info.php", "test.php", "api/", "api/v1/", "graphql",
                    "robots.txt", "sitemap.xml", ".well-known/",
                    "uploads/", "files/", "static/", "assets/",
                ][:options.get("dirfuzz_max_paths", 100)]

            headers = {"User-Agent": "Emergens-Sniper/1.0"}
            timeout = options.get("dirfuzz_timeout", 5)
            hits: List[Dict[str, Any]] = []

            def _probe(path: str):
                url = f"{base}/{path.lstrip('/')}"
                try:
                    r = _rq.get(url, headers=headers, timeout=timeout,
                                allow_redirects=False, stream=True)
                    status = r.status_code
                    size = r.headers.get("Content-Length") or 0
                    r.close()
                    if status == 404:
                        return None
                    return {"path": "/" + path.lstrip("/"), "status": status, "size": size}
                except Exception:
                    return None

            with ThreadPoolExecutor(max_workers=16) as pool:
                for i, hit in enumerate(pool.map(_probe, wordlist)):
                    if hit:
                        hits.append(hit)
                    if progress and i % 10 == 0:
                        pct = int((i + 1) / len(wordlist) * 90) + 10
                        progress(f"Directory Fuzzer — {i+1}/{len(wordlist)}", pct)

            # Rank — sensitive config files first
            def _rank(h):
                p = h["path"].lower()
                if any(x in p for x in (".env", ".git", "backup", "dump", ".sql", ".bak", "config")):
                    return 0
                if h["status"] in (401, 403):
                    return 1
                if h["status"] == 200:
                    return 2
                return 3
            hits.sort(key=_rank)

            result.findings = hits
            result.summary = {
                "tried":  len(wordlist),
                "hits":   len(hits),
                "source": wordlist_name if wordlist else "bundled",
                "critical": len([h for h in hits
                                 if any(x in h["path"].lower()
                                        for x in (".env", ".git", "backup", "dump", ".sql", ".bak"))]),
            }
            result.ok = True
            if progress: progress("Directory Fuzzer — complete", 100)
        except Exception as e:  # noqa: BLE001
            result.error = str(e)
            logger.warning(f"[sniper] Directory Fuzzer failed: {e}")

        result.elapsed = time.monotonic() - t0
        return result


# ── Subdomain Takeover ──────────────────────────────────────────────────
class _TakeoverAdapter(_ModuleAdapter):
    name = "Subdomain Takeover"

    def run(self, target, options, progress=None):
        t0 = time.monotonic()
        result = ModuleResult(name=self.name)

        if progress: progress("Subdomain Takeover — starting", 10)
        try:
            from modules import subdomain_takeover
            host = _host_from_target(target)
            report = subdomain_takeover.run(host, {
                "enumerate":    options.get("takeover_enumerate", True),
                "use_crtsh":    options.get("takeover_crtsh", True),
                "use_wordlist": options.get("takeover_wordlist", True),
                "concurrency":  options.get("takeover_concurrency", 20),
                "max_hosts":    options.get("takeover_max_hosts", 300),
                "rate_limit":   options.get("takeover_rate_limit", 15.0),
            })

            dangling = report.get("dangling", []) or []
            result.findings = dangling
            result.summary = {
                "scanned":    report.get("scanned", 0),
                "candidates": len(report.get("candidates", [])),
                "dangling":   len(dangling),
            }
            result.ok = True
            if progress: progress("Subdomain Takeover — complete", 100)
        except Exception as e:  # noqa: BLE001
            result.error = str(e)
            logger.warning(f"[sniper] Takeover module failed: {e}")

        result.elapsed = time.monotonic() - t0
        return result


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════
def _host_from_target(target: str) -> str:
    """Extract the hostname from a URL or a bare host."""
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
    """Compute a 0–100 risk score and a level label."""
    score = 0
    for m in report.modules:
        if not m.ok:
            continue
        for f in m.findings:
            sev = (f.get("severity") or "").lower()
            conf = float(f.get("confidence") or 0.5)
            if m.name == "SQLi":
                base = 30
                score += base * max(conf, 0.5)
            elif m.name == "XSS":
                base = 22 if sev in ("high", "critical") else 14
                score += base * max(conf, 0.5)
            elif m.name == "Directory Fuzzer":
                # Direct hits: only count 200 or 401/403
                st = f.get("status", 0)
                if st == 200:
                    score += 8
                elif st in (401, 403):
                    score += 5
                else:
                    score += 2
                # Config/backup exposure bonus
                if any(x in (f.get("path") or "").lower()
                       for x in (".env", ".git", "backup", ".sql", ".bak")):
                    score += 15
            elif m.name == "Subdomain Takeover":
                risk = (f.get("risk") or "").lower()
                if risk == "confirmed":
                    score += 35
                elif risk == "probable":
                    score += 22
                else:
                    score += 10

    score = int(min(100, round(score)))
    report.risk_score = score
    if score >= 70:
        report.risk_level = "critical"
    elif score >= 45:
        report.risk_level = "high"
    elif score >= 20:
        report.risk_level = "medium"
    elif score > 0:
        report.risk_level = "low"
    else:
        report.risk_level = "none"


def _priority_rank(report: SniperReport) -> None:
    """Build a flattened, priority-ranked list of the top findings."""
    priority: List[Dict[str, Any]] = []

    weights = {
        "SQLi": 100,
        "Subdomain Takeover": 90,
        "XSS": 80,
        "Directory Fuzzer": 50,
    }

    for m in report.modules:
        if not m.ok:
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
            # Module-specific boosts
            if m.name == "Directory Fuzzer":
                st = f.get("status", 0)
                path = (f.get("path") or "").lower()
                if any(x in path for x in (".env", ".git", "backup", ".sql", ".bak")):
                    entry["severity"] = "critical"
                    entry["weight"] += 40
                elif st == 200:
                    entry["severity"] = "high"
                    entry["weight"] += 20
                else:
                    entry["severity"] = "medium"
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
    report.priority_findings = priority[:20]  # top 20


# ═══════════════════════════════════════════════════════════════════════════
# Sniper Scanner
# ═══════════════════════════════════════════════════════════════════════════
class SniperScanner:
    """Orchestrates the four modules against a target."""

    def __init__(self):
        self._adapters: List[_ModuleAdapter] = [
            _SqliAdapter(),
            _XssAdapter(),
            _DirfuzzAdapter(),
            _TakeoverAdapter(),
        ]
        self._stop = threading.Event()

    def cancel(self) -> None:
        self._stop.set()

    def _make_report(self, target: str) -> SniperReport:
        return SniperReport(
            target=target,
            host=_host_from_target(target),
            started_at=datetime.now(timezone.utc).isoformat(),
        )

    # ── Streaming API (generator) ──────────────────────────────────────
    def run_streaming(self, target: str, options: Optional[Dict[str, Any]] = None
                      ) -> Iterator[Dict[str, Any]]:
        """Yield progress events as modules complete."""
        options = options or {}
        report = self._make_report(target)
        t0 = time.monotonic()

        yield {"type": "start", "target": target, "host": report.host,
               "modules": [a.name for a in self._adapters]}

        # Progressive progress queue
        import queue
        progress_q: "queue.Queue[Dict[str, Any]]" = queue.Queue()

        def _emit(module: str, message: str, pct: int) -> None:
            progress_q.put({
                "type": "progress",
                "module": module,
                "message": message,
                "pct": max(0, min(100, int(pct))),
            })

        results: Dict[str, ModuleResult] = {}
        results_lock = threading.Lock()

        def _run(adapter: _ModuleAdapter):
            if self._stop.is_set():
                return
            r = adapter.run(target, options,
                            progress=lambda msg, pct, m=adapter.name: _emit(m, msg, pct))
            with results_lock:
                results[adapter.name] = r
            progress_q.put({"type": "module_done", "module": adapter.name,
                            "elapsed": r.elapsed, "findings": len(r.findings),
                            "ok": r.ok, "error": r.error})

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self._adapters)) as pool:
            futures = [pool.submit(_run, a) for a in self._adapters]

            # Drain progress while futures run
            completed = 0
            total = len(futures)
            while completed < total:
                if self._stop.is_set():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    event = progress_q.get(timeout=0.5)
                except queue.Empty:
                    continue
                if event.get("type") == "module_done":
                    completed += 1
                yield event

            # Drain remaining events
            while True:
                try:
                    yield progress_q.get_nowait()
                except queue.Empty:
                    break

        # Assemble the final report
        report.modules = [
            results.get(a.name, ModuleResult(name=a.name, error="not_run"))
            for a in self._adapters
        ]
        for m in report.modules:
            if not m.ok and m.error:
                report.errors.append(f"{m.name}: {m.error}")

        _compute_risk(report)
        _priority_rank(report)

        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.elapsed = time.monotonic() - t0

        yield {"type": "complete", "report": report.to_public_dict()}

    # ── Blocking API ───────────────────────────────────────────────────
    def run(self, target: str, options: Optional[Dict[str, Any]] = None
            ) -> SniperReport:
        options = options or {}
        report = self._make_report(target)
        t0 = time.monotonic()

        results: Dict[str, ModuleResult] = {}
        results_lock = threading.Lock()

        def _run(adapter: _ModuleAdapter):
            if self._stop.is_set():
                return
            r = adapter.run(target, options)
            with results_lock:
                results[adapter.name] = r

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self._adapters)) as pool:
            futures = [pool.submit(_run, a) for a in self._adapters]
            for f in concurrent.futures.as_completed(futures):
                try:
                    f.result()
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"[sniper] worker raised: {e}")

        report.modules = [
            results.get(a.name, ModuleResult(name=a.name, error="not_run"))
            for a in self._adapters
        ]
        for m in report.modules:
            if not m.ok and m.error:
                report.errors.append(f"{m.name}: {m.error}")

        _compute_risk(report)
        _priority_rank(report)

        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.elapsed = time.monotonic() - t0
        return report


# ═══════════════════════════════════════════════════════════════════════════
# Public helpers
# ═══════════════════════════════════════════════════════════════════════════
def run(target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Blocking full scan. Returns the aggregated report dict."""
    scanner = SniperScanner()
    return scanner.run(target, options).to_public_dict()


def run_streaming(target: str, options: Optional[Dict[str, Any]] = None
                  ) -> Iterator[Dict[str, Any]]:
    """Streaming full scan — yields progress events."""
    scanner = SniperScanner()
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

    parser = argparse.ArgumentParser(description="Sniper: Auto-Exploiter CLI")
    parser.add_argument("target", help="URL or host, e.g. https://example.com")
    parser.add_argument("--json", action="store_true", help="raw JSON output")
    parser.add_argument("--stream", action="store_true", help="stream progress events")
    parser.add_argument("--no-takeover", action="store_true",
                        help="skip subdomain takeover module")
    parser.add_argument("--dirfuzz-wordlist", default="lottery-dirs.txt")
    parser.add_argument("--dirfuzz-max-paths", type=int, default=100)

    args = parser.parse_args()

    options = {
        "dirfuzz_wordlist": args.dirfuzz_wordlist,
        "dirfuzz_max_paths": args.dirfuzz_max_paths,
        "takeover_enumerate": not args.no_takeover,
    }

    if args.stream:
        for ev in run_streaming(args.target, options):
            if ev["type"] == "progress":
                print(f"[{ev['module']:20s}] {ev['pct']:3d}%  {ev['message']}")
            elif ev["type"] == "module_done":
                status = "OK" if ev["ok"] else "FAIL"
                print(f"[{ev['module']:20s}] {status}  {ev['findings']} finding(s) in {ev['elapsed']:.2f}s")
                if ev.get("error"):
                    print(f"                       error: {ev['error']}")
            elif ev["type"] == "complete":
                if args.json:
                    print(json.dumps(ev["report"], indent=2))
        sys.exit(0)

    report = run(args.target, options)

    if args.json:
        print(json.dumps(report, indent=2))
        sys.exit(0)

    # Human report
    print()
    print("═" * 72)
    print(f"  Sniper Report — {report['target']}")
    print("═" * 72)
    print(f"  Risk score : {report['risk_score']}/100 ({report['risk_level'].upper()})")
    print(f"  Elapsed    : {report['elapsed']}s")
    print()

    print("  MODULE RESULTS")
    print("  " + "─" * 68)
    for m in report["modules"]:
        status = "OK" if m["ok"] else "FAIL"
        print(f"  [{status:4s}] {m['name']:22s} {m['findings_count']:3d} finding(s) "
              f"in {m['elapsed']:.2f}s")
        if m["error"]:
            print(f"         error: {m['error']}")
    print()

    if report["priority_findings"]:
        print("  TOP PRIORITY FINDINGS")
        print("  " + "─" * 68)
        for i, f in enumerate(report["priority_findings"][:10], 1):
            print(f"  {i:2d}. [{f['severity'].upper():8s}] {f['module']}")
            detail = f.get("detail") or {}
            key = (detail.get("parameter") or detail.get("path")
                   or detail.get("host") or "")
            if key:
                print(f"      → {key}")
        print()
