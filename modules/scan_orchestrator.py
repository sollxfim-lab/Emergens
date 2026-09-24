"""
Oxysintx — Scan Orchestrator (v3.0.0)

Background job manager for running passive security scanning tools.

================================================================================
OVERVIEW
================================================================================
This module auto-discovers *scan* tools from the ``modules`` package and runs
them safely in the background with concurrency, cancellation, timeouts, and
history integration.

A module is treated as a **scan tool** if all of the following are true:
    1. It lives inside the ``modules`` package
    2. Its name does not start with ``_``
    3. Its name is not in ``_EXCLUDED_MODULES``
    4. It exposes a callable ``run(target, mode, **kwargs)``
    5. It does **not** declare ``IS_SCAN_TOOL = False``
    6. Its ``TOOL_KIND`` (if present) is not in ``_NON_SCAN_KINDS``

================================================================================
DELIBERATELY EXCLUDED — NOT SCAN TOOLS
================================================================================
The following modules are **never** registered as scanners, even though some of
them expose a ``run()`` function, because they are:

    • Exploitation / attack tools  → sql_injection, xss_exploiter, brute_force,
                                      subdomain_takeover, c2, exploit_repository
    • Infrastructure               → scan_orchestrator, source_viewer, _common
    • Bots / integrations          → telegram, whatsapp, quick_menu
    • Code test workspace          → testing, adios
    • Engine subprocess            → start (MHDDoS)
    • The lightweight XSS scanner  → xss   (superseded by xss_exploiter)
    • The lightweight SQLi scanner → sql_map / sqli_engine are used through
                                      their dedicated routes in app.py, not
                                      through the orchestrator.

To add a new *scanner*, drop a file in ``modules/`` exposing ``run()`` + optional
``TOOL_INFO``. The orchestrator picks it up on the next restart (or on a call to
``ScanOrchestrator.reload_tools()``).

================================================================================
Adding a new scanner — example
================================================================================
    # modules/my_scanner.py
    TOOL_INFO = {
        "name": "My Scanner",
        "version": "1.0.0",
        "description": "Passive recon for X, Y, Z",
        "category": "Recon",
        "author": "You",
    }
    TOOL_KIND = "scanner"          # or "recon" / "lookup"  — never "exploit"

    def run(target: str, mode: str, **kwargs) -> dict:
        return {"tool": "my_scanner", "target": target, "data": {...}, "error": None}

================================================================================
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
# Configuration
# =============================================================================
__version__ = "3.0.0"
__author__ = "Yanxzyx"

MAX_CONCURRENT_SCANS        = 3            # simultaneous jobs
SCAN_TIMEOUT_SECONDS        = 600          # global per-job timeout (10 min)
JOB_CLEANUP_AFTER_SECONDS   = 3600         # keep finished jobs in RAM for 1 h
TOOL_INIT_TIMEOUT_SECONDS   = 120          # per-tool soft timeout (informational)

# Default scanner set for "basic" mode (fast passive checks)
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

# "expert" mode auto-fills with every discovered tool at runtime
DEFAULT_EXPERT_TOOLS: Optional[List[str]] = None

logger = logging.getLogger("oxysintx.scan_orchestrator")


# =============================================================================
# Tool discovery
# =============================================================================
# Modules that must NEVER be treated as scan tools.
# Grouped for readability — this list is the single source of truth for
# exclusions, and is enforced on every (re)discovery.
_EXCLUDED_MODULES: Set[str] = {
    # ── Orchestrator / infra ─────────────────────────────────────────────
    "scan_orchestrator",
    "source_viewer",
    "_common",

    # ── Bots & integrations ──────────────────────────────────────────────
    "telegram",
    "whatsapp",
    "quick_menu",

    # ── Code workspace / helper sub‑modules ──────────────────────────────
    "testing",
    "adios",
    "c2",

    # ── Engine subprocess (MHDDoS) ───────────────────────────────────────
    "start",

    # ── Exploitation / attack modules (NOT scanners) ─────────────────────
    #    These have their own dedicated API routes in app.py.
    "sql_injection",
    "sql_map",
    "sqli_engine",
    "xss",
    "xss_exploiter",
    "brute_force",
    "subdomain_takeover",
    "exploit_repository",

    # ── Analytic store / aggregation layer ───────────────────────────────
    "analytic_manager",
    "history_store",
}

# A module's declared TOOL_KIND is respected — these values mean "not a scanner"
_NON_SCAN_KINDS: Set[str] = {
    "exploit",
    "exploitation",
    "attack",
    "payload",
    "wordlist",
    "helper",
    "utility",
}


def discover_tools() -> Dict[str, Any]:
    """
    Walk the ``modules`` package and return ``{name: module}`` for every
    module that qualifies as a scan tool.

    A module qualifies if all of these hold:
        • its name is not in ``_EXCLUDED_MODULES``
        • its name does not start with ``_``
        • it exposes a callable ``run``
        • it does not set ``IS_SCAN_TOOL = False``
        • its ``TOOL_KIND`` is not in ``_NON_SCAN_KINDS``
    """
    tools: Dict[str, Any] = {}

    for _, name, is_pkg in pkgutil.iter_modules(modules_pkg.__path__):
        # Skip private sub-packages and anything explicitly excluded
        if name.startswith("_") or name in _EXCLUDED_MODULES:
            continue

        # Skip nested packages — tools are single-file modules
        if is_pkg:
            continue

        try:
            mod = importlib.import_module(f"modules.{name}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to import modules.%s: %s", name, exc, exc_info=True)
            continue

        # Must expose run()
        run_fn = getattr(mod, "run", None)
        if not callable(run_fn):
            logger.debug("modules.%s skipped — no callable run()", name)
            continue

        # Explicit opt-out
        if getattr(mod, "IS_SCAN_TOOL", True) is False:
            logger.info("modules.%s skipped — IS_SCAN_TOOL=False", name)
            continue

        # Respect declared kind
        kind = str(getattr(mod, "TOOL_KIND", "") or "").strip().lower()
        if kind in _NON_SCAN_KINDS:
            logger.info("modules.%s skipped — TOOL_KIND=%s", name, kind)
            continue

        tools[name] = mod
        logger.debug("Registered scan tool: modules.%s (kind=%s)",
                     name, kind or "unspecified")

    return tools


# Initial discovery at import time
TOOL_MAP: Dict[str, Any] = discover_tools()
DEFAULT_EXPERT_TOOLS = sorted(TOOL_MAP.keys())
logger.info("Discovered %d scan tool(s): %s", len(TOOL_MAP), sorted(TOOL_MAP))


def _parse_tools(requested: List[str]) -> List[str]:
    """
    Filter ``requested`` to only those names that are known scan tools.
    Falls back to the basic set if nothing matches.
    """
    valid = [t for t in requested if t in TOOL_MAP]
    if not valid:
        logger.warning("No valid tools requested; falling back to basic set")
        valid = [t for t in DEFAULT_BASIC_TOOLS if t in TOOL_MAP]
    return valid


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
    status:        str = "pending"          # pending|running|completed|cancelled|timeout|error
    percent:       int = 0
    current_tool:  Optional[str] = None
    results:       Dict[str, Any] = field(default_factory=dict)
    error:         Optional[str] = None
    created_at:    float = field(default_factory=time.time)
    finished_at:   Optional[float] = None
    _thread:       Optional[threading.Thread] = None

    # ── Public view ──────────────────────────────────────────────────────
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

    The orchestrator uses a bounded semaphore to cap concurrent work,
    propagates cancellation via ``threading.Event``, enforces a global
    per-job timeout, and writes every job's outcome into the history store.
    """

    def __init__(
        self,
        max_concurrent: int = MAX_CONCURRENT_SCANS,
        timeout:        int = SCAN_TIMEOUT_SECONDS,
        cleanup_after:  int = JOB_CLEANUP_AFTER_SECONDS,
    ):
        self._jobs:        Dict[str, ScanJob] = {}
        self._lock:        threading.Lock     = threading.Lock()
        self._semaphore:   threading.BoundedSemaphore = threading.BoundedSemaphore(
            max(1, int(max_concurrent))
        )
        self._timeout:     int = int(timeout)
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
    # Direct (synchronous) invocation — bypasses the job queue
    # ------------------------------------------------------------------
    def run_tool_sync(
        self,
        tool_name: str,
        target: str,
        mode: str = "basic",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Run a single tool and return its result. Useful for one-shot API
        calls (e.g. ``POST /api/scan/<tool_name>``).
        """
        if tool_name not in TOOL_MAP:
            raise ValueError(f"Unknown tool: {tool_name}")

        module = TOOL_MAP[tool_name]
        try:
            return module.run(target, mode, **kwargs)
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
            Requested tool names. Empty list → default set for ``mode``.
        history_store : HistoryStore
            Store used to persist the scan entry and results.
        tool_options : dict, optional
            Extra ``kwargs`` forwarded to every tool's ``run()`` call.
        """
        # Resolve the effective tool list
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
        """Return the current state of a job, or ``None`` if unknown."""
        with self._lock:
            job = self._jobs.get(job_id)
        return job.to_dict() if job else None

    def cancel_scan(self, job_id: str) -> bool:
        """
        Signal a running job to stop. Returns True if the job was found
        and is still in a cancellable state.
        """
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

                # ── Run the tool ──────────────────────────────────────
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
                    result = tool_module.run(
                        job.target,
                        job.mode,
                        **job.tool_options,
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
        """Drop finished jobs that are older than the retention window."""
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
        """
        Re-run module discovery and rebuild the tool registry. Useful when
        new scanner modules are added while the server is running.
        """
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
    Return a lightweight summary of the current registry. Handy for
    diagnostics and the /api/modules/status endpoint.
    """
    return {
        "version":        __version__,
        "tool_count":     len(TOOL_MAP),
        "tools":          sorted(TOOL_MAP.keys()),
        "basic_tools":    [t for t in DEFAULT_BASIC_TOOLS if t in TOOL_MAP],
        "expert_tools":   list(DEFAULT_EXPERT_TOOLS or []),
        "excluded":       sorted(_EXCLUDED_MODULES),
        "non_scan_kinds": sorted(_NON_SCAN_KINDS),
    }
