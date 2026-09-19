#!/usr/bin/env python3
"""
Analytic Manager — v2.0.0
Combines exploit repository, brute force, SQLi, and XSS behind a single
facade. All sub-modules are optional — missing ones degrade gracefully
instead of crashing the whole manager.

Location: modules/analytic_manager.py
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("oxysintx.analytic_manager")
__version__ = "2.0.0"


# ═══════════════════════════════════════════════════════════════════════════
# Optional sub-module imports — each wrapped so a single missing module
# doesn't take down the whole manager.
# ═══════════════════════════════════════════════════════════════════════════
try:
    from modules.exploit_repository import ExploitRepository  # type: ignore
    _repo_available = True
except ImportError:
    ExploitRepository = None  # type: ignore
    _repo_available = False

try:
    from modules.brute_force import BruteForceAttack  # type: ignore
    _bf_available = True
except ImportError:
    BruteForceAttack = None  # type: ignore
    _bf_available = False

# SQLi — prefer native engine, fall back to legacy module
_sqli_mode = "none"
try:
    from modules import sqli_engine as _sqli_native  # type: ignore
    _sqli_mode = "native"
except ImportError:
    _sqli_native = None  # type: ignore
    try:
        from modules.sql_injection import run_sql_injection  # type: ignore
        _sqli_mode = "legacy"
    except ImportError:
        run_sql_injection = None  # type: ignore

# XSS — prefer xss_exploiter v2, fall back to legacy module
_xss_mode = "none"
try:
    from modules import xss_exploiter as _xss_native  # type: ignore
    _xss_mode = "native"
except ImportError:
    _xss_native = None  # type: ignore
    try:
        from modules.xss import run_xss  # type: ignore
        _xss_mode = "legacy"
    except ImportError:
        run_xss = None  # type: ignore


class AnalyticDataManager:
    def __init__(self):
        self._lock = threading.Lock()

        self.repository = ExploitRepository() if _repo_available else None
        self.brute_force = BruteForceAttack() if _bf_available else None

        if not _repo_available:
            logger.info("[analytic] exploit_repository not available — disabled")
        if not _bf_available:
            logger.info("[analytic] brute_force not available — disabled")
        logger.info("[analytic] SQLi mode=%s · XSS mode=%s", _sqli_mode, _xss_mode)

    # ── Statistics ──────────────────────────────────────────────────────
    def get_statistics(self) -> Dict[str, Any]:
        if not self.repository:
            return {
                "total_exploits": 0,
                "by_category": {},
                "by_service": {},
                "risk_levels": {"critical": 0, "high": 0,
                                "medium": 0, "low": 0},
                "repo_available": False,
                "sqli_mode": _sqli_mode,
                "xss_mode": _xss_mode,
            }

        all_exploits = self.repository.get_all()
        return {
            "total_exploits": len(all_exploits),
            "by_category": {
                cat.value: len(self.repository.get_by_category(cat))
                for cat in getattr(self.repository, "_by_category", {})
            },
            "by_service": {
                svc: len(self.repository.get_by_service(svc))
                for svc in getattr(self.repository, "_by_service", {})
            },
            "risk_levels": {
                "critical": len([e for e in all_exploits
                                 if getattr(e, "risk_level", "") == "critical"]),
                "high":     len([e for e in all_exploits
                                 if getattr(e, "risk_level", "") == "high"]),
                "medium":   len([e for e in all_exploits
                                 if getattr(e, "risk_level", "") == "medium"]),
                "low":      len([e for e in all_exploits
                                 if getattr(e, "risk_level", "") == "low"]),
            },
            "repo_available": True,
            "sqli_mode": _sqli_mode,
            "xss_mode": _xss_mode,
        }

    # ── Exploit listing ─────────────────────────────────────────────────
    def list_exploits(self, category=None, service=None) -> List[Dict]:
        if not self.repository:
            return []
        if category:
            exploits = self.repository.get_by_category(category) \
                if isinstance(category, str) else []
        elif service:
            exploits = self.repository.get_by_service(service)
        else:
            exploits = self.repository.get_all()
        return [e.to_dict() for e in exploits]

    def search_exploits(self, query) -> List[Dict]:
        if not self.repository:
            return []
        return [e.to_dict() for e in self.repository.search(query)]

    # ── Brute force ─────────────────────────────────────────────────────
    def run_brute_force(self, target, protocols=None,
                        username_file="data1.txt",
                        password_file="data1.txt") -> Dict[str, Any]:
        if not self.brute_force:
            return {
                "error": "brute_force module not installed",
                "available": False,
            }
        return self.brute_force.run_full_attack(
            target, protocols, username_file, password_file
        )

    def stop_brute_force(self) -> Dict[str, Any]:
        if not self.brute_force:
            return {"error": "brute_force module not installed",
                    "available": False}
        self.brute_force.stop()
        return {"success": True}

    # ── SQLi — accepts optional cancel_event + progress_cb ──────────────
    def run_sql_injection_scan(self, url, method="GET", params=None,
                                cancel_event=None, progress_cb=None,
                                **kwargs) -> Dict[str, Any]:
        if _sqli_mode == "native":
            opts = {
                "method": method,
                "params": params,
                "cancel_event": cancel_event,
                "progress_cb": progress_cb,
            }
            opts.update({k: v for k, v in kwargs.items()
                         if k in ("techniques", "max_params", "concurrency",
                                  "rate_limit", "timeout", "max_duration")})
            return _sqli_native.run(url, opts)

        if _sqli_mode == "legacy":
            try:
                return run_sql_injection(url, method, params)
            except Exception as e:
                logger.warning("[analytic] legacy SQLi failed: %s", e)
                return {"error": str(e), "findings": [],
                        "vulnerable": False}

        return {
            "error": "no SQLi engine available",
            "vulnerable": False,
            "findings": [],
            "url": url,
        }

    # ── XSS — accepts optional cancel_event + progress_cb ───────────────
    def run_xss_scan(self, url, method="GET", params=None,
                      cancel_event=None, progress_cb=None,
                      **kwargs) -> Dict[str, Any]:
        if _xss_mode == "native":
            opts = {
                "method": method,
                "params": params,
                "cancel_event": cancel_event,
                "progress_cb": progress_cb,
            }
            opts.update({k: v for k, v in kwargs.items()
                         if k in ("max_payloads", "max_params",
                                  "concurrency", "rate_limit",
                                  "timeout", "waf_bypass")})
            result = _xss_native.run(url, opts)
            return {"results": result}

        if _xss_mode == "legacy":
            try:
                return run_xss(url, method, params)
            except Exception as e:
                logger.warning("[analytic] legacy XSS failed: %s", e)
                return {"error": str(e), "results": {}}

        return {
            "error": "no XSS engine available",
            "results": {},
            "url": url,
        }

    # ── Export ──────────────────────────────────────────────────────────
    def export_data(self, output_file="analytic_data_export.json") -> Dict[str, Any]:
        data = {
            "timestamp": time.time(),
            "version": __version__,
            "statistics": self.get_statistics(),
            "exploits": ([e.to_dict()
                          for e in self.repository.get_all()]
                          if self.repository else []),
            "brute_force_results": (
                self.brute_force.results if self.brute_force else {}
            ),
        }
        try:
            with open(output_file, "w") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            logger.warning("[analytic] export failed: %s", e)
        return data


__all__ = ["AnalyticDataManager"]
