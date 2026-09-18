"""
Oxysintx – Scan Orchestrator (v2.1.0)

Background job manager for running security scanning tools.

Changes in v2.1.0
-----------------
- Tools now receive ``cancel_event=threading.Event`` so long-running tools
  (e.g. brute_force) can abort mid-execution instead of only between tools.
- ``tool_options`` is filtered per-tool: if a tool's ``run()`` does not accept
  a kwarg the orchestrator drops it and retries, instead of failing the job.
- Per-tool timing captured in results (``_meta.elapsed_ms``).
- Progress callbacks: ``ScanOrchestrator.on_progress(cb)``.
- ``update_entry`` failures no longer abort job finalisation.
- Global timeout now checked **before** and **after** each tool, plus during
  submission so a hung tool cannot block the whole scan past ``SCAN_TIMEOUT``.
- History entry is always finalised, even on unexpected exceptions.

Adding a new tool
-----------------
Create ``modules/<name>.py`` exposing:

    def run(target: str, mode: str, **kwargs) -> dict
    TOOL_INFO = {"name": "My Tool", "version": "1.0.0", ...}

Optional kwarg (recommended):

    def run(target, mode, *, cancel_event=None, **kwargs): ...
        if cancel_event and cancel_event.is_set():
            return {"tool": __name__, "target": target, "data": {}, "error": "cancelled"}

The orchestrator auto-registers any module that defines a callable ``run``.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

import modules as modules_pkg

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MAX_CONCURRENT_SCANS = 3
SCAN_TIMEOUT_SECONDS = 600
JOB_CLEANUP_AFTER_SECONDS = 3600

DEFAULT_BASIC_TOOLS: List[str] = [
    "whois_lookup", "dns_lookup", "ssl_check", "headers_check",
    "ip_info", "connectivity_check", "email_security", "subdomain_enum",
    "tech_fingerprint", "port_scan",
]

# Filled at import time with every discovered tool name.
DEFAULT_EXPERT_TOOLS: Optional[List[str]] = None

logger = logging.getLogger("oxysintx.scan_orchestrator")

# ---------------------------------------------------------------------------
# Modules that are NOT scan tools
# ---------------------------------------------------------------------------
# These modules live in `modules/` but are either infrastructure, integrations,
# or high-noise tools that must be launched explicitly. The orchestrator will
# never auto-register them in TOOL_MAP, so they don't appear in /api/tools.
#
# NOTE: `brute_force` is intentionally kept here. It is a package (not a single
# module) and is invoked from /api/exploit/bruteforce via AnalyticDataManager.
# To expose it as a scan tool, remove it from this set — the package exposes
# the run()/TOOL_INFO contract required by the orchestrator.
_EXCLUDED_MODULES: Set[str] = {
    # Core / infrastructure
    "scan_orchestrator",
    "source_viewer",
    "_common",
    # Bots & integrations
    "telegram",
    "whatsapp",
    # C2 / cod
    "testing",
    "adios",
    "c2",
    "start",
    # Analytic / legacy modules
    "analytic_manager",
    "brute_force",
    "sql_injection",
    "exploit_repository",
}

# Tools whose run() is known to hang; skip the global timeout check for them
# because they manage their own deadline. Currently none.
_LONG_RUNNING_TOOLS: Set[str] = set()

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def _accepts_kwarg(func: Callable, name: str) -> bool:
    """Return True if ``func`` declares ``name`` or a **kwargs catch-all."""
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        # C-extension or builtin without a signature: be permissive.
        return True

    for param in sig.parameters.values():
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            return True
        if param.name == name:
            return True
    return False


def discover_tools() -> Dict[str, Any]:
    """Return ``{module_name: module_object}`` for every valid scan tool."""
    tools: Dict[str, Any] = {}
    for _, name, _ in pkgutil.iter_modules(modules_pkg.__path__):
        if name in _EXCLUDED_MODULES or name.startswith("_"):
            continue
        try:
            mod = importlib.import_module(f"modules.{name}")
        except Exception as exc:  # noqa: BLE001 - discovery must not crash
            logger.warning("Failed to import module %s: %s", name, exc, exc_info=True)
            continue

        run_fn = getattr(mod, "run", None)
        if not callable(run_fn):
            logger.debug("Module %s skipped – no callable run()", name)
            continue

        tools[name] = mod
        logger.debug("Registered scan tool: %s", name)

    return tools


TOOL_MAP: Dict[str, Any] = discover_tools()
logger.info("Discovered %d scan tools: %s", len(TOOL_MAP), sorted(TOOL_MAP))

if DEFAULT_EXPERT_TOOLS is None:
    DEFAULT_EXPERT_TOOLS = sorted(TOOL_MAP.keys())


def _parse_tools(requested: Iterable[str]) -> List[str]:
    """Keep only known tools. Fall back to basic set if none match."""
    valid = [t for t in requested if t in TOOL_MAP]
    if not valid:
        logger.warning("No valid tools requested; falling back to basic set")
        valid = [t for t in DEFAULT_BASIC_TOOLS if t in TOOL_MAP]
    return valid


# ---------------------------------------------------------------------------
# ScanJob
# ---------------------------------------------------------------------------
@dataclass
class ScanJob:
    job_id: str
    target: str
    mode: str
    tools: List[str]
    entry_id: int
    cancel_event: threading.Event
    tool_options: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    percent: int = 0
    current_tool: Optional[str] = None
    results: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    _thread: Optional[threading.Thread] = None

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "target": self.target,
            "mode": self.mode,
            "tools": self.tools,
            "status": self.status,
            "percent": self.percent,
            "current_tool": self.current_tool,
            "results": self.results,
            "error": self.error,
        }


ProgressCallback = Callable[[ScanJob], None]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
class ScanOrchestrator:
    def __init__(
        self,
        max_concurrent: int = MAX_CONCURRENT_SCANS,
        timeout: int = SCAN_TIMEOUT_SECONDS,
        cleanup_after: int = JOB_CLEANUP_AFTER_SECONDS,
    ) -> None:
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._timeout = timeout
        self._cleanup_after = cleanup_after
        self._progress_callbacks: List[ProgressCallback] = []

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def list_tools(self) -> Dict[str, dict]:
        return {
            name: getattr(mod, "TOOL_INFO", {"name": name, "description": ""})
            for name, mod in TOOL_MAP.items()
        }

    def get_tool_info(self, tool_name: str) -> Optional[dict]:
        mod = TOOL_MAP.get(tool_name)
        if mod is None:
            return None
        return getattr(mod, "TOOL_INFO", {"name": tool_name, "description": ""})

    def on_progress(self, callback: ProgressCallback) -> None:
        """Register a callback invoked after every tool completes."""
        with self._lock:
            self._progress_callbacks.append(callback)

    # ------------------------------------------------------------------
    # Direct invocation (no job bookkeeping)
    # ------------------------------------------------------------------
    def run_tool_sync(
        self,
        tool_name: str,
        target: str,
        mode: str = "basic",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Run a single tool synchronously and return its raw result."""
        if tool_name not in TOOL_MAP:
            raise ValueError(f"Unknown tool: {tool_name}")

        module = TOOL_MAP[tool_name]
        try:
            return module.run(target, mode, **kwargs)
        except Exception as exc:  # noqa: BLE001 - direct call is best-effort
            logger.error("Direct tool %s failed: %s", tool_name, exc, exc_info=True)
            return {
                "tool": tool_name,
                "target": target,
                "data": {},
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # Job lifecycle
    # ------------------------------------------------------------------
    def start_scan(
        self,
        target: str,
        mode: str,
        tools: List[str],
        history_store: Any,
        tool_options: Optional[Dict[str, Any]] = None,
    ) -> str:
        if not tools:
            tools = DEFAULT_EXPERT_TOOLS if mode == "expert" else DEFAULT_BASIC_TOOLS
        tools = _parse_tools(tools)

        entry_id = history_store.add_entry(target, mode, tools, status="running")

        job_id = str(uuid.uuid4())
        cancel_event = threading.Event()
        job = ScanJob(
            job_id=job_id,
            target=target,
            mode=mode,
            tools=tools,
            entry_id=entry_id,
            cancel_event=cancel_event,
            tool_options=dict(tool_options or {}),
        )

        with self._lock:
            self._jobs[job_id] = job

        # Acquire a slot *before* spawning so the worker thread never blocks
        # inside start_scan; keeps the HTTP handler fast.
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

    def get_progress(self, job_id: str) -> Optional[dict]:
        with self._lock:
            job = self._jobs.get(job_id)
        return job.to_dict() if job else None

    def cancel_scan(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
        if job and job.status in ("pending", "running"):
            job.cancel_event.set()
            logger.info("Cancel signal sent to job %s", job_id)
            return True
        return False

    def cancel_all(self) -> None:
        with self._lock:
            active = [j for j in self._jobs.values() if j.status in ("pending", "running")]
        for job in active:
            job.cancel_event.set()
            logger.info("Cancel signal sent to job %s (shutdown)", job.job_id)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    def _execute(self, job: ScanJob, history_store: Any) -> None:
        start_time = time.time()
        final_status = "error"
        final_error: Optional[str] = job.error

        try:
            job.status = "running"
            total = max(1, len(job.tools))
            job.results = {}

            for idx, tool_name in enumerate(job.tools):
                # --- cancellation ---
                if job.cancel_event.is_set():
                    final_status = "cancelled"
                    final_error = "Cancelled by user"
                    break

                # --- global timeout (pre-check) ---
                if time.time() - start_time > self._timeout:
                    final_status = "timeout"
                    final_error = f"Scan exceeded {self._timeout}s limit"
                    break

                job.current_tool = tool_name
                job.percent = int((idx / total) * 100)

                # --- run the tool ---
                tool_started = time.perf_counter()
                result = self._invoke_tool(job, tool_name)
                elapsed_ms = (time.perf_counter() - tool_started) * 1000.0

                if isinstance(result, dict):
                    result.setdefault("_meta", {})["elapsed_ms"] = round(elapsed_ms, 1)
                job.results[tool_name] = result

                # --- global timeout (post-check) ---
                if time.time() - start_time > self._timeout:
                    final_status = "timeout"
                    final_error = f"Scan exceeded {self._timeout}s limit"
                    break

                # --- notify progress listeners ---
                self._emit_progress(job)

            else:
                # Loop completed without break
                final_status = "completed"

            # Ensure percent reflects the true terminal state
            if final_status == "completed":
                job.percent = 100
                job.current_tool = None
            else:
                job.percent = min(job.percent, 99)

        except Exception as exc:  # noqa: BLE001 - never let the worker die silently
            logger.exception("Unexpected error in job %s", job.job_id)
            final_status = "error"
            final_error = f"Unexpected error: {exc}"

        finally:
            job.status = final_status
            job.error = final_error
            job.finished_at = time.time()

            # Release the concurrency slot first so other scans can start even
            # if the history update below fails.
            try:
                self._semaphore.release()
            except ValueError:
                # BoundedSemaphore raises if we somehow release twice; ignore.
                pass

            # Persist to history — best effort, must not raise.
            try:
                history_store.update_entry(
                    job.entry_id,
                    status=job.status,
                    result=job.results if job.status == "completed" else None,
                    error=job.error,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Failed to update history for job %s: %s", job.job_id, exc
                )

            self._emit_progress(job)
            self._cleanup_old_jobs()

    # ------------------------------------------------------------------
    # Tool invocation
    # ------------------------------------------------------------------
    def _invoke_tool(self, job: ScanJob, tool_name: str) -> Dict[str, Any]:
        """Call ``run()`` with options, gracefully dropping unsupported kwargs."""
        module = TOOL_MAP[tool_name]
        run_fn = module.run

        kwargs = self._build_tool_kwargs(job, run_fn)

        try:
            return run_fn(job.target, job.mode, **kwargs)
        except TypeError as exc:
            # Most likely an unexpected keyword argument. Retry without the
            # optional orchestrator-injected ones before giving up.
            logger.warning(
                "Tool %s rejected kwargs (%s); retrying with minimal args",
                tool_name, exc,
            )
            try:
                return run_fn(job.target, job.mode)
            except Exception as inner:  # noqa: BLE001
                logger.error("Tool %s failed: %s", tool_name, inner, exc_info=True)
                return self._error_result(tool_name, job.target, inner)
        except Exception as exc:  # noqa: BLE001
            logger.error("Tool %s failed: %s", tool_name, exc, exc_info=True)
            return self._error_result(tool_name, job.target, exc)

    def _build_tool_kwargs(self, job: ScanJob, run_fn: Callable) -> Dict[str, Any]:
        """Return the subset of options that ``run_fn`` actually accepts."""
        # Start from the caller-supplied options.
        candidates: Dict[str, Any] = dict(job.tool_options)

        # Inject orchestrator-level context only if the tool opts in.
        if _accepts_kwarg(run_fn, "cancel_event"):
            candidates["cancel_event"] = job.cancel_event
        if _accepts_kwarg(run_fn, "mode"):
            # run()'s second positional is already mode; only pass if the
            # caller's signature names it explicitly and we're overriding.
            pass

        # Filter by the tool's actual signature.
        accepted: Dict[str, Any] = {}
        for key, value in candidates.items():
            if _accepts_kwarg(run_fn, key):
                accepted[key] = value
            else:
                logger.debug(
                    "Dropping unsupported kwarg %r for tool %s",
                    key, getattr(run_fn, "__module__", "?"),
                )
        return accepted

    @staticmethod
    def _error_result(tool_name: str, target: str, exc: BaseException) -> Dict[str, Any]:
        return {
            "tool": tool_name,
            "target": target,
            "data": {},
            "error": f"{type(exc).__name__}: {exc}",
        }

    # ------------------------------------------------------------------
    # Progress
    # ------------------------------------------------------------------
    def _emit_progress(self, job: ScanJob) -> None:
        with self._lock:
            callbacks = tuple(self._progress_callbacks)
        if not callbacks:
            return
        for cb in callbacks:
            try:
                cb(job)
            except Exception:  # noqa: BLE001
                logger.exception("Progress callback raised")

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------
    def _cleanup_old_jobs(self) -> None:
        now = time.time()
        with self._lock:
            stale = [
                jid for jid, j in self._jobs.items()
                if j.finished_at and (now - j.finished_at > self._cleanup_after)
            ]
            for jid in stale:
                del self._jobs[jid]
                logger.debug("Job %s removed from memory (cleanup)", jid)

    def reload_tools(self) -> None:
        """Re-scan the modules package. Call after adding a new tool file."""
        global TOOL_MAP, DEFAULT_EXPERT_TOOLS
        TOOL_MAP = discover_tools()
        DEFAULT_EXPERT_TOOLS = sorted(TOOL_MAP.keys())
        logger.info("Tools reloaded. %d tools available.", len(TOOL_MAP))
