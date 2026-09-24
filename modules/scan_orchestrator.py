"""
Oxysintx — Scan Orchestrator (v3.1.0)

Background job manager for running security scanning tools.

================================================================================
WHAT APPEARS IN "SECURITY TESTING"
================================================================================
The dashboard's Security Testing carousel is populated from `/api/tools`,
which is built from ``ScanOrchestrator.list_tools()`` → ``TOOL_MAP``.

By design, the following modules **are visible** in Security Testing:
    • sql_map         → "SQLMap (SQL Injection)"
    • xss_exploiter   → "XSS Exploiter"
    • every other module in modules/ that exposes run() and is not excluded
      (whois_lookup, dns_lookup, ssl_check, headers_check, ip_info,
      connectivity_check, email_security, subdomain_enum, tech_fingerprint,
      port_scan, etc.)

By design, the following modules are **excluded from Security Testing** and
are available ONLY from the Exploit Suite panel:
    • dirfuzz         → Directory / File Fuzzer
    • sqli_engine     → SQLi Engine (advanced, 4 techniques)
    • sql_injection   → Lightweight SQLi scanner
    • xss             → Lightweight XSS scanner
    • sniper          → Auto-Exploiter orchestrator

The following modules are **never** treated as tools:
    • scan_orchestrator, source_viewer, _common
    • telegram, whatsapp, quick_menu
    • testing, adios, c2, start (MHDDoS engine)
    • brute_force, subdomain_takeover, exploit_repository
    • analytic_manager, history_store

================================================================================
CALLING CONVENTIONS
================================================================================
Two conventions exist in the modules/ tree:

    1. mode-string style:
           run(target: str, mode: str, **kwargs) -> dict
       Used by: sql_map, xss, sql_injection, port_scan, dns_lookup, ...

    2. options-dict style:
           run(target: str, options: dict) -> dict
       Used by: xss_exploiter, sqli_engine, dirfuzz, sniper

The orchestrator's ``_call_tool()`` helper inspects the module name and
dispatches to the correct convention. If a module is not listed in
``_OPTIONS_STYLE_MODULES`` it is assumed to be mode-string style.

To add a new scanner: drop a file in modules/ with the mode-string run() and
optionally a TOOL_INFO dict. It is auto-discovered on the next restart.

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
__version__ = "3.1.0"
__author__ = "Yanxzyx"

# =============================================================================
# Configuration
# =============================================================================
MAX_CONCURRENT_SCANS      = 3
SCAN_TIMEOUT_SECONDS      = 600
JOB_CLEANUP_AFTER_SECONDS = 3600
TOOL_INIT_TIMEOUT_SECONDS = 120

# Basic mode: fast passive recon
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

# Expert mode: auto-filled with every discovered tool
DEFAULT_EXPERT_TOOLS: Optional[List[str]] = None

logger = logging.getLogger("oxysintx.scan_orchestrator")


# =============================================================================
# Exclusion list
# =============================================================================
_EXCLUDED_MODULES: Set[str] = {
    # ── Orchestrator / infra ─────────────────────────────────────────────
    "scan_orchestrator",
    "source_viewer",
    "_common",

    # ── Bots & integrations ──────────────────────────────────────────────
    "telegram",
    "whatsapp",
    "quick_menu",

    # ── Code workspace / helper sub-modules ──────────────────────────────
    "testing",
    "adios",
    "c2",

    # ── Engine subprocess (MHDDoS) ───────────────────────────────────────
    "start",

    # ── Exploit Suite ONLY (kept out of Security Testing carousel) ───────
    "dirfuzz",
    "sqli_engine",
    "sql_injection",
    "xss",
    "sniper",

    # ── Attack / exploit tools — never scanners ──────────────────────────
    "brute_force",
    "subdomain_takeover",
    "exploit_repository",

    # ── Analytic store / history ─────────────────────────────────────────
    "analytic_manager",
    "history_store",
}

# Module's declared TOOL_KIND — any of these means "not a scanner"
_NON_SCAN_KINDS: Set[str] = {
    "exploit",
    "exploitation",
    "attack",
    "payload",
    "wordlist",
    "helper",
    "utility",
}

# Modules that use the options-dict calling convention: run(target, options)
_OPTIONS_STYLE_MODULES: Set[str] = {
    "xss_exploiter",
    "sqli_engine",
    "dirfuzz",
    "sniper",
}

# Per-mode defaults applied when an options-style module is invoked.
# The keys are module names; values map {mode: {default_options}}.
_OPTIONS_STYLE_MODE_DEFAULTS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "xss_exploiter": {
        "basic":  {"max_payloads": 20, "max_params": 8,  "concurrency": 6,  "waf_bypass": False},
        "expert": {"max_payloads": 60, "max_params": 15, "concurrency": 12, "waf_bypass": True},
    },
    "sqli_engine": {
        "basic":  {"techniques": ["error", "boolean"], "max_params": 8},
        "expert": {"techniques": ["error", "boolean", "time", "union"], "max_params": 15},
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
# Tool discovery
# =============================================================================
def discover_tools() -> Dict[str, Any]:
    """
    Walk the ``modules`` package and return ``{name: module}`` for every
    module that qualifies as a scan tool.

    A module qualifies if all of these hold:
        • its name is not in ``_EXCLUDED_MODULES``
        • its name does not start with ``_``
        • it is a single-file module (not a nested package)
        • it exposes a callable ``run``
        • it does not set ``IS_SCAN_TOOL = False``
        • its ``TOOL_KIND`` (if present) is not in ``_NON_SCAN_KINDS``
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
            logger.warning("Failed to import modules.%s: %s", name, exc, exc_info=True)
            continue

        run_fn = getattr(mod, "run", None)
        if not callable(run_fn):
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
logger.info("Discovered %d scan tool(s): %s", len(TOOL_MAP), sorted(TOOL_MAP))


def _parse_tools(requested: List[str]) -> List[str]:
    """Filter ``requested`` to known tools. Falls back to the basic set."""
    valid = [t for t in requested if t in TOOL_MAP]
    if not valid:
        logger.warning("No valid tools requested; falling back to basic set")
        valid = [t for t in DEFAULT_BASIC_TOOLS if t in TOOL_MAP]
    return valid


# =============================================================================
# Universal tool invoker — handles both calling conventions
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

    • Options-style modules (``run(target, options)``):
        Build an options dict from the module's per-mode defaults, merged
        with any caller overrides, then call ``run(target, options)``.

    • Mode-string modules (``run(target, mode, **kwargs)``):
        Call directly with positional ``mode`` and unpacked kwargs.
    """
    tool_options = tool_options or {}
    run_fn: Callable = module.run

    if module_name in _OPTIONS_STYLE_MODULES:
        opts: Dict[str, Any] = {}
        defaults = _OPTIONS_STYLE_MODE_DEFAULTS.get(module_name, {}).get(mode, {})
        opts.update(defaults)
        opts.update(tool_options)
        # Preserve the mode as a hint for modules that accept it
        opts.setdefault("mode", mode)
        return run_fn(target, opts)

    # Default: mode-string convention
    return run_fn(target, mode, **tool_options)


# =============================================================================
# ScanJob — per-scan state container
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

    Uses a bounded semaphore to cap concurrent work, propagates cancellation
    via ``threading.Event``, enforces a global per-job timeout, and writes
    each job's outcome into the history store.
    """

    def __init__(
        self,
        max_concurrent: int = MAX_CONCURRENT_SCANS,
        timeout:        int = SCAN_TIMEOUT_SECONDS,
        cleanup_after:  int = JOB_CLEANUP_AFTER_SECONDS,
    ):
        self._jobs:          Dict[str, ScanJob] = {}
        self._lock:          threading.Lock = threading.Lock()
        self._semaphore:     threading.BoundedSemaphore = threading.BoundedSemaphore(
            max(1, int(max_concurrent))
        )
        self._timeout:       int = int(timeout)
        self._cleanup_after: int = int(cleanup_after)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def list_tools(self) -> Dict[str, Dict[str, Any]]:
        """Return ``{tool_name: TOOL_INFO}`` for every discovered scanner."""
        return {
            name: dict(getattr(mod, "TOOL_INFO",
                                {"name": name, "description": ""}))
            for name, mod in TOOL_MAP.items()
        }

    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Return ``TOOL_INFO`` for a single tool, or ``None`` if unknown."""
        mod = TOOL_MAP.get(tool_name)
        if mod is None:
            return None
        return dict(getattr(mod, "TOOL_INFO",
                            {"name": tool_name, "description": ""}))

    def is_tool(self, tool_name: str) -> bool:
        """Return True if ``tool_name`` is a registered scan tool."""
        return tool_name in TOOL_MAP

    # ------------------------------------------------------------------
    # Direct (synchronous) invocation — respects calling conventions
    # ------------------------------------------------------------------
    def run_tool_sync(
        self,
        tool_name: str,
        target: str,
        mode: str = "basic",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Run a single tool and return its result. Handles both mode-string
        and options-dict conventions.
        """
        if tool_name not in TOOL_MAP:
            raise ValueError(f"Unknown tool: {tool_name}")

        module = TOOL_MAP[tool_name]
        try:
            return _call_tool(tool_name, module, target, mode, kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.error("Direct tool %s failed: %s", tool_name, exc, exc_info=True)
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

        Parameters
        ----------
        target : str
            Domain, hostname, or IP address to scan.
        mode : str
            ``"basic"`` or ``"expert"``.
        tools : list[str]
            Requested tool names. Empty → default set for ``mode``.
        history_store : HistoryStore
            Store used to persist the scan entry and results.
        tool_options : dict, optional
            Extra kwargs forwarded to every tool's ``run()``.
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

        # Create the history entry (status=running)
        try:
            entry_id = history_store.add_entry(target, mode, tools, status="running")
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

        # Acquire concurrency slot before spawning the thread
        self._semaphore.acquire()
        thread = threading.Thread(
            target=self._execute,
            args=(job, history_store),
            daemon=True,
            name=f"scan-{job_id[:8]}",
        )
        job._thread = thread
        thread.start()

        logger.info(
            "Scan started: job=%s target=%s mode=%s tools=%s",
            job_id, target, mode, tools,
        )
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
        """Signal every active job to stop (used during graceful shutdown)."""
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
                # ── Cancellation check ────────────────────────────────
                if job.cancel_event.is_set():
                    job.status = "cancelled"
                    job.error  = "Cancelled by user"
                    break

                # ── Global timeout check ──────────────────────────────
                if time.time() - start_time > self._timeout:
                    job.status = "timeout"
                    job.error  = f"Scan exceeded {self._timeout}s limit"
                    break

                # ── Progress bookkeeping ──────────────────────────────
                job.current_tool = tool_name
                job.percent      = int((idx / total_tools) * 100)

                # ── Run the tool (respects calling convention) ────────
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

            # ── Mark finished cleanly if no terminal flag was set ─────
            if job.status == "running":
                job.status       = "completed"
                job.percent      = 100
                job.current_tool = None

        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error in job %s", job.job_id)
            job.status = "error"
            job.error  = f"Unexpected error: {exc}"

        finally:
            # Always release the concurrency slot
            try:
                self._semaphore.release()
            except Exception:
                pass

            job.finished_at = time.time()

            # Persist outcome to history
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

            # Best-effort memory cleanup of old jobs
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
    """
    Return a lightweight summary of the current registry. Useful for
    diagnostics and the ``/api/modules/status`` endpoint.
    """
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
    """
    Module-level convenience wrapper around the universal invoker.
    Handy for external callers (e.g. app.py) that want the same dispatch
    logic without instantiating an orchestrator.
    """
    module = TOOL_MAP.get(tool_name)
    if module is None:
        raise ValueError(f"Unknown tool: {tool_name}")
    return _call_tool(tool_name, module, target, mode, kwargs)
