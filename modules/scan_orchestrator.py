"""
Oxysintx — Scan Orchestrator (v3.5.0)

Background job manager for the Oxysintx Flask stack.

================================================================================
INTEGRATION WITH app.py
================================================================================
Public API consumed by app.py:
    • `ScanOrchestrator()`                          — instantiate
    • `ScanOrchestrator.list_tools()` → dict        — Security Testing carousel
    • `ScanOrchestrator.get_tool_info(name)`        — per-tool metadata
    • `ScanOrchestrator.start_scan(target, mode, tools, history_store)`
    • `ScanOrchestrator.get_progress(job_id)`       — poll from /api/scan/<id>/status
    • `ScanOrchestrator.cancel_scan(job_id)`        — cancel running job
    • `TOOL_MAP` (module-level dict)                — direct tool dispatch
    • `call_tool(name, target, mode, **kw)`         — one-shot sync call

Alias modules (scan_ssl.py, scan_headers.py, etc.) are intentionally
skipped via `IS_SCAN_TOOL = False`. The canonical implementations
(ssl_check.py, headers_check.py, ...) remain in the registry.

================================================================================
CALLING CONVENTIONS
================================================================================
Two conventions exist in the modules/ tree:

    1. mode-string style:  run(target: str, mode: str, **kwargs) -> dict
       Used by: xss, sql_map, sql_injection, port_scan, dns_lookup, ...

    2. options-dict style: run(target: str, options: dict) -> dict
       Used by: xss_exploiter, sqli_engine, dirfuzz, sniper

`_call_tool()` dispatches to the correct convention automatically.

================================================================================
MODULE DISCOVERY
================================================================================
Auto-discovery walks `modules/` at import time and registers every
single-file module that:
    • is not in _EXCLUDED_MODULES
    • does not start with "_"
    • exposes a callable `run`
    • does not declare `IS_SCAN_TOOL = False`
    • does not set `TOOL_KIND` to a non-scan kind

Author: Yanxzyx
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

import modules as modules_pkg

# =============================================================================
# Metadata
# =============================================================================
__version__ = "3.5.0"
__author__  = "Yanxzyx"

# =============================================================================
# Configuration
# =============================================================================
MAX_CONCURRENT_SCANS      = 3
SCAN_TIMEOUT_SECONDS      = 600
JOB_CLEANUP_AFTER_SECONDS = 3600

# Basic mode: fast passive recon — the tools the dashboard shows by default
DEFAULT_BASIC_TOOLS: List[str] = [
    "whois_lookup",
    "dns_lookup",
    "ssl_check",
    "headers_check",
    "ip_info",
    "connectivity_check",
    "email_security",
    "subdomain_enum",
    "tech_fingerprint",
    "port_scan",
]

DEFAULT_EXPERT_TOOLS: Optional[List[str]] = None  # auto-filled

logger = logging.getLogger("oxysintx.scan_orchestrator")


# =============================================================================
# Exclusion list
# =============================================================================
_EXCLUDED_MODULES: Set[str] = {
    # ── Orchestrator / infra ─────────────────────────────────────────
    "scan_orchestrator",
    "source_viewer",
    "_common",

    # ── Bots & integrations ──────────────────────────────────────────
    "telegram",
    "whatsapp",
    "quick_menu",

    # ── Helper / workspace sub-modules ───────────────────────────────
    "testing",
    "adios",
    "c2",
    "start",       # MHDDoS engine subprocess

    # ── Exploit Suite only — kept out of Security Testing carousel ───
    "dirfuzz",
    "sqli_engine",
    "sql_injection",
    "xss_exploiter",
    "sniper",

    # ── OSINT — dedicated /api/osint/* endpoints ─────────────────────
    "osint",
    "osint_search",
    "osint_tools",
    "github_scraper",
    "username_search",
    "leak_search",
    "leakdata",
    "search_user",
    "search_user_run",
    "youtube_stalk",
    "twitter_stalk",
    "instagram_stalk",

    # ── Attack tools — never scanners ────────────────────────────────
    "brute_force",
    "subdomain_takeover",
    "exploit_repository",

    # ── Analytic store / history ─────────────────────────────────────
    "analytic_manager",
    "history_store",
}

# `TOOL_KIND` values that disqualify a module as a scanner
_NON_SCAN_KINDS: Set[str] = {
    "exploit", "exploitation", "attack", "payload",
    "wordlist", "helper", "utility",
    "osint", "intel", "stalk", "scraper", "search", "lookup_user",
}

# Modules that use the options-dict calling convention: run(target, options)
_OPTIONS_STYLE_MODULES: Set[str] = {
    "sqli_engine",
    "dirfuzz",
    "sniper",
}

# Per-mode default options for options-style modules
_OPTIONS_STYLE_MODE_DEFAULTS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "sqli_engine": {
        "basic":  {"techniques": ["error", "boolean"], "max_params": 8},
        "expert": {"techniques": ["error", "boolean", "time", "union"],
                    "max_params": 15},
    },
    "dirfuzz": {
        "basic":  {"max_paths": 100, "concurrency": 16},
        "expert": {"max_paths": 400, "concurrency": 32},
    },
    "sniper": {
        "basic":  {"module_timeout": 60.0,  "global_budget": 90.0},
        "expert": {"module_timeout": 120.0, "global_budget": 240.0},
    },
}


# =============================================================================
# Helpers
# =============================================================================
def _extract_version(mod: Any) -> str:
    """Best-effort version string for a module."""
    for attr in ("__version__", "VERSION"):
        v = getattr(mod, attr, None)
        if isinstance(v, str) and v.strip():
            return v.strip()
    info = getattr(mod, "TOOL_INFO", None)
    if isinstance(info, dict):
        v = info.get("version")
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


# =============================================================================
# Tool discovery
# =============================================================================
def discover_tools() -> Dict[str, Any]:
    """
    Walk the ``modules`` package and return ``{name: module}`` for every
    module that qualifies as a scan tool.
    """
    tools: Dict[str, Any] = {}

    for _, name, is_pkg in pkgutil.iter_modules(modules_pkg.__path__):
        if name.startswith("_") or name in _EXCLUDED_MODULES:
            continue
        if is_pkg:
            continue

        try:
            mod = importlib.import_module(f"modules.{name}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to import modules.%s: %s", name, exc,
                            exc_info=True)
            continue

        if not callable(getattr(mod, "run", None)):
            logger.debug("modules.%s skipped — no callable run()", name)
            continue

        if getattr(mod, "IS_SCAN_TOOL", True) is False:
            logger.info("modules.%s skipped — IS_SCAN_TOOL=False", name)
            continue

        kind = str(getattr(mod, "TOOL_KIND", "") or "").strip().lower()
        if kind in _NON_SCAN_KINDS:
            logger.info("modules.%s skipped — TOOL_KIND=%s", name, kind)
            continue

        tools[name] = mod
        logger.debug("Registered scan tool: modules.%s (kind=%s)",
                     name, kind or "unspecified")

    return tools


# Initial discovery
TOOL_MAP: Dict[str, Any] = discover_tools()
DEFAULT_EXPERT_TOOLS = sorted(TOOL_MAP.keys())
logger.info("Discovered %d scan tool(s): %s",
            len(TOOL_MAP), sorted(TOOL_MAP))


def _parse_tools(requested: List[str]) -> List[str]:
    """Filter ``requested`` to known tools. Falls back to the basic set."""
    valid = [t for t in requested if t in TOOL_MAP]
    if not valid:
        logger.warning("No valid tools requested; falling back to basic set")
        valid = [t for t in DEFAULT_BASIC_TOOLS if t in TOOL_MAP]
    return valid


# =============================================================================
# Universal tool invoker
# =============================================================================
def _call_tool(
    module_name: str,
    module: Any,
    target: str,
    mode: str,
    tool_options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Invoke a module's ``run()`` respecting its calling convention.
    """
    tool_options = tool_options or {}
    run_fn: Callable = module.run

    if module_name in _OPTIONS_STYLE_MODULES:
        opts: Dict[str, Any] = {}
        defaults = _OPTIONS_STYLE_MODE_DEFAULTS.get(module_name, {}).get(mode, {})
        opts.update(defaults)
        opts.update(tool_options)
        opts.setdefault("mode", mode)
        return run_fn(target, opts)

    # Default: mode-string convention
    return run_fn(target, mode, **tool_options)


# =============================================================================
# ScanJob
# =============================================================================
@dataclass
class ScanJob:
    """Mutable state for a single background scan job."""
    job_id:        str
    target:        str
    mode:          str
    tools:         List[str]
    entry_id:      int
    cancel_event:  threading.Event

    tool_options:  Dict[str, Any] = field(default_factory=dict)
    status:        str = "pending"
    percent:       int = 0
    current_tool:  Optional[str] = None
    results:       Dict[str, Any] = field(default_factory=dict)
    error:         Optional[str] = None
    created_at:    float = field(default_factory=time.time)
    finished_at:   Optional[float] = None
    _thread:       Optional[threading.Thread] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-safe snapshot of this job."""
        return {
            "job_id":       self.job_id,
            "target":       self.target,
            "mode":         self.mode,
            "tools":        list(self.tools),
            "status":       self.status,
            "percent":      self.percent,
            "current_tool": self.current_tool,
            "results":      self.results,
            "error":        self.error,
            "created_at":   self.created_at,
            "finished_at":  self.finished_at,
            "elapsed":      round(
                (self.finished_at or time.time()) - self.created_at, 2
            ),
        }


# =============================================================================
# ScanOrchestrator
# =============================================================================
class ScanOrchestrator:
    """
    Thread-safe manager for background scan jobs.
    Uses a bounded semaphore to cap concurrent work, propagates
    cancellation via ``threading.Event``, enforces a global per-job
    timeout, and writes each job's outcome into the history store.
    """

    def __init__(
        self,
        max_concurrent: int = MAX_CONCURRENT_SCANS,
        timeout:        int = SCAN_TIMEOUT_SECONDS,
        cleanup_after:  int = JOB_CLEANUP_AFTER_SECONDS,
    ):
        self._jobs:          Dict[str, ScanJob] = {}
        self._lock:          threading.Lock = threading.Lock()
        self._semaphore:     threading.BoundedSemaphore = \
            threading.BoundedSemaphore(max(1, int(max_concurrent)))
        self._timeout:       int = int(timeout)
        self._cleanup_after: int = int(cleanup_after)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def list_tools(self) -> Dict[str, Dict[str, Any]]:
        """Return ``{tool_name: TOOL_INFO}`` for every discovered scanner."""
        out: Dict[str, Dict[str, Any]] = {}
        for name, mod in TOOL_MAP.items():
            info = getattr(mod, "TOOL_INFO", None)
            if isinstance(info, dict):
                out[name] = dict(info)
            else:
                out[name] = {
                    "name": name,
                    "description": "",
                    "version": _extract_version(mod),
                }
        return out

    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Return ``TOOL_INFO`` for a single tool, or ``None`` if unknown."""
        mod = TOOL_MAP.get(tool_name)
        if mod is None:
            return None
        info = getattr(mod, "TOOL_INFO", None)
        if isinstance(info, dict):
            return dict(info)
        return {
            "name": tool_name,
            "description": "",
            "version": _extract_version(mod),
        }

    def is_tool(self, tool_name: str) -> bool:
        """Return True if ``tool_name`` is a registered scan tool."""
        return tool_name in TOOL_MAP

    # ------------------------------------------------------------------
    # Direct synchronous invocation
    # ------------------------------------------------------------------
    def run_tool_sync(
        self,
        tool_name: str,
        target: str,
        mode: str = "basic",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Run a single tool synchronously and return its result.
        """
        if tool_name not in TOOL_MAP:
            raise ValueError(f"Unknown tool: {tool_name}")

        module = TOOL_MAP[tool_name]
        try:
            return _call_tool(tool_name, module, target, mode, kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.error("Direct tool %s failed: %s",
                         tool_name, exc, exc_info=True)
            return {
                "tool":   tool_name,
                "target": target,
                "data":   {},
                "error":  str(exc),
            }

    # ------------------------------------------------------------------
    # Background job lifecycle
    # ------------------------------------------------------------------
    def start_scan(
        self,
        target: str,
        mode: str,
        tools: List[str],
        history_store,
        tool_options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Launch a background scan and return its ``job_id``.
        """
        # Resolve effective tool list
        if not tools:
            tools = (
                list(DEFAULT_EXPERT_TOOLS or [])
                if mode == "expert"
                else list(DEFAULT_BASIC_TOOLS)
            )
        tools = _parse_tools(tools)
        if not tools:
            raise RuntimeError("No usable scan tools available for this mode")

        # Create the history entry
        try:
            entry_id = history_store.add_entry(
                target, mode, tools, status="running"
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to create history entry: %s", exc)
            entry_id = -1

        job_id       = str(uuid.uuid4())
        cancel_event = threading.Event()
        job = ScanJob(
            job_id=job_id,
            target=target,
            mode=mode,
            tools=tools,
            entry_id=entry_id,
            cancel_event=cancel_event,
            tool_options=tool_options or {},
        )

        with self._lock:
            self._jobs[job_id] = job

        self._semaphore.acquire()
        thread = threading.Thread(
            target=self._execute,
            args=(job, history_store),
            daemon=True,
            name=f"scan-{job_id[:8]}",
        )
        job._thread = thread
        thread.start()

        logger.info("Scan started: job=%s target=%s mode=%s tools=%s",
                    job_id, target, mode, tools)
        return job_id

    def get_progress(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Return current state of a job, or ``None`` if unknown."""
        with self._lock:
            job = self._jobs.get(job_id)
        return job.to_dict() if job else None

    def cancel_scan(self, job_id: str) -> bool:
        """Signal a running job to stop. Returns True if found and running."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.status in ("pending", "running"):
                job.cancel_event.set()
                logger.info("Cancel signal sent to job %s", job_id)
                return True
        return False

    def cancel_all(self) -> None:
        """Signal every active job to stop (graceful shutdown)."""
        with self._lock:
            for job in self._jobs.values():
                if job.status in ("pending", "running"):
                    job.cancel_event.set()
        logger.info("Cancel signal sent to all active jobs")

    def list_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent ``limit`` jobs, newest first."""
        with self._lock:
            jobs = sorted(self._jobs.values(),
                          key=lambda j: j.created_at, reverse=True)
        return [j.to_dict() for j in jobs[: max(1, int(limit))]]

    # ------------------------------------------------------------------
    # Internal execution
    # ------------------------------------------------------------------
    def _execute(self, job: ScanJob, history_store) -> None:
        """Runs the tool loop inside the job's dedicated thread."""
        start_time = time.time()
        total_tools = max(1, len(job.tools))

        try:
            job.status = "running"
            job.results = {}

            for idx, tool_name in enumerate(job.tools):
                # Cancellation check
                if job.cancel_event.is_set():
                    job.status = "cancelled"
                    job.error  = "Cancelled by user"
                    break

                # Global timeout check
                if time.time() - start_time > self._timeout:
                    job.status = "timeout"
                    job.error  = f"Scan exceeded {self._timeout}s limit"
                    break

                # Progress bookkeeping
                job.current_tool = tool_name
                job.percent      = int((idx / total_tools) * 100)

                # Run the tool
                tool_module = TOOL_MAP.get(tool_name)
                if tool_module is None:
                    job.results[tool_name] = {
                        "tool":   tool_name,
                        "target": job.target,
                        "data":   {},
                        "error":  "Tool disappeared from registry",
                    }
                    continue

                try:
                    result = _call_tool(
                        tool_name,
                        tool_module,
                        job.target,
                        job.mode,
                        job.tool_options,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Tool %s raised on target %s: %s",
                        tool_name, job.target, exc, exc_info=True,
                    )
                    result = {
                        "tool":   tool_name,
                        "target": job.target,
                        "data":   {},
                        "error":  str(exc),
                    }

                job.results[tool_name] = result

            # Clean completion
            if job.status == "running":
                job.status       = "completed"
                job.percent      = 100
                job.current_tool = None

        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error in job %s", job.job_id)
            job.status = "error"
            job.error  = f"Unexpected error: {exc}"

        finally:
            try:
                self._semaphore.release()
            except Exception:
                pass

            job.finished_at = time.time()

            if job.entry_id and job.entry_id != -1:
                try:
                    history_store.update_entry(
                        job.entry_id,
                        status=job.status,
                        result=job.results if job.status == "completed" else None,
                        error=job.error,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Failed to update history for job %s: %s",
                        job.job_id, exc,
                    )

            self._cleanup_old_jobs()

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------
    def _cleanup_old_jobs(self) -> None:
        """Drop finished jobs older than the retention window."""
        now = time.time()
        with self._lock:
            stale = [
                jid
                for jid, job in self._jobs.items()
                if job.finished_at and (now - job.finished_at) > self._cleanup_after
            ]
            for jid in stale:
                del self._jobs[jid]
                logger.debug("Job %s removed from memory (cleanup)", jid)

    def reload_tools(self) -> None:
        """Re-run module discovery and rebuild the tool registry."""
        global TOOL_MAP, DEFAULT_EXPERT_TOOLS
        TOOL_MAP = discover_tools()
        DEFAULT_EXPERT_TOOLS = sorted(TOOL_MAP.keys())
        logger.info("Tools reloaded — %d scanner(s) available: %s",
                    len(TOOL_MAP), DEFAULT_EXPERT_TOOLS)


# =============================================================================
# Public helpers
# =============================================================================
def get_registry_snapshot() -> Dict[str, Any]:
    """Lightweight summary of the current registry."""
    return {
        "version":          __version__,
        "tool_count":       len(TOOL_MAP),
        "tools":            sorted(TOOL_MAP.keys()),
        "basic_tools":      [t for t in DEFAULT_BASIC_TOOLS if t in TOOL_MAP],
        "expert_tools":     list(DEFAULT_EXPERT_TOOLS or []),
        "excluded":         sorted(_EXCLUDED_MODULES),
        "non_scan_kinds":   sorted(_NON_SCAN_KINDS),
        "options_style":    sorted(_OPTIONS_STYLE_MODULES),
    }


def call_tool(
    tool_name: str,
    target: str,
    mode: str = "basic",
    **kwargs: Any,
) -> Dict[str, Any]:
    """Module-level convenience wrapper around the universal invoker."""
    module = TOOL_MAP.get(tool_name)
    if module is None:
        raise ValueError(f"Unknown tool: {tool_name}")
    return _call_tool(tool_name, module, target, mode, kwargs)