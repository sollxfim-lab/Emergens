"""
Oxysintx – Scan Orchestrator (v2.0.0)

Background job manager for running security scanning tools.

Key features:
- Automatic module discovery: any .py file in the `modules` package that
  exposes a `run(target, mode, **kwargs)` function is automatically registered.
- Two scan modes: basic (subset of tools) and expert (all discovered tools).
- Concurrent execution with a semaphore to limit CPU / I/O pressure.
- Background threading with live progress reporting.
- Cancellation via `threading.Event` – tools can check `cancel_event` periodically.
- Global timeout – scans that exceed the limit are automatically stopped.
- Memory cleanup of old jobs after a configurable retention period.
- History integration: each scan is linked to a history entry.
- Non‑scan modules (telegram.py, adios.py, testing.py, etc.) are excluded from
  tool discovery.

Adding a new tool
-----------------
Create a Python file in `modules/` that defines:

    def run(target: str, mode: str, **kwargs) -> dict
    TOOL_INFO = {"name": "My Tool", "version": "1.0.0", ...}

The orchestrator will automatically pick it up on the next restart.
"""

import uuid
import threading
import importlib
import pkgutil
import time
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field

import modules as modules_pkg

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MAX_CONCURRENT_SCANS = 3           # max simultaneous scans
SCAN_TIMEOUT_SECONDS = 600         # global timeout (10 minutes)
JOB_CLEANUP_AFTER_SECONDS = 3600   # remove finished jobs from memory after 1 hour

# Default tool sets per mode (used when no explicit list is provided)
DEFAULT_BASIC_TOOLS = [
    "whois_lookup", "dns_lookup", "ssl_check", "headers_check",
    "ip_info", "connectivity_check", "email_security", "subdomain_enum",
    "tech_fingerprint", "port_scan"
]
DEFAULT_EXPERT_TOOLS = None  # filled with all discovered tools at runtime

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("oxysintx.scan_orchestrator")

# ---------------------------------------------------------------------------
# Automatic module discovery
# ---------------------------------------------------------------------------
# Modules in the `modules` package that are NOT scan tools.
# The orchestrator skips these during discovery so they do not appear in the
# tool list and are never called via run().
_EXCLUDED_MODULES: Set[str] = {
    # Core / infrastructure
    "scan_orchestrator",
    "source_viewer",
    "_common",
    # Bots & integrations
    "telegram",
    "whatsapp",
    # Code testing & DDoS
    "testing",
    "adios",
    "c2",
    # Analytic modules
    "analytic_manager",
    "brute_force",
    "sql_injection",
    "xss",
    "exploit_repository",
}

# ---------------------------------------------------------------------------
# Tool discovery function
# ---------------------------------------------------------------------------
def discover_tools() -> Dict[str, Any]:
    """
    Scan the `modules` package and return a dict of module name -> module object
    for all modules that expose a callable `run()` function and are not excluded.

    Returns
    -------
    dict
        Keys are module names, values are the imported module objects.
    """
    tools = {}
    for _, name, _ in pkgutil.iter_modules(modules_pkg.__path__):
        # Skip explicitly excluded modules and private modules
        if name in _EXCLUDED_MODULES or name.startswith("_"):
            continue

        try:
            mod = importlib.import_module(f"modules.{name}")
            if hasattr(mod, "run") and callable(mod.run):
                tools[name] = mod
            else:
                logger.debug("Module %s skipped – no run() function", name)
        except Exception as exc:
            logger.warning("Failed to load module %s: %s", name, exc, exc_info=True)

    return tools

# Initial discovery
TOOL_MAP = discover_tools()
logger.info("Discovered %d scan tools: %s", len(TOOL_MAP), list(TOOL_MAP.keys()))

# If DEFAULT_EXPERT_TOOLS is None, use all discovered tools
if DEFAULT_EXPERT_TOOLS is None:
    DEFAULT_EXPERT_TOOLS = sorted(TOOL_MAP.keys())

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def _parse_tools(tools: List[str]) -> List[str]:
    """
    Filter the requested tool list to only known tools.
    If none match, fall back to the basic set.
    """
    valid = [t for t in tools if t in TOOL_MAP]
    if not valid:
        logger.warning("No valid tools requested; falling back to basic set")
        valid = [t for t in DEFAULT_BASIC_TOOLS if t in TOOL_MAP]
    return valid

# ---------------------------------------------------------------------------
# ScanJob – represents a single scan execution
# ---------------------------------------------------------------------------
@dataclass
class ScanJob:
    """Holds all state for a scan job."""
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

# ---------------------------------------------------------------------------
# ScanOrchestrator – the core manager
# ---------------------------------------------------------------------------
class ScanOrchestrator:
    def __init__(self, max_concurrent: int = MAX_CONCURRENT_SCANS,
                 timeout: int = SCAN_TIMEOUT_SECONDS,
                 cleanup_after: int = JOB_CLEANUP_AFTER_SECONDS):
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._timeout = timeout
        self._cleanup_after = cleanup_after

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def list_tools(self) -> Dict[str, dict]:
        """
        Return metadata for all discovered tools.
        """
        return {
            name: getattr(mod, "TOOL_INFO", {"name": name, "description": ""})
            for name, mod in TOOL_MAP.items()
        }

    def get_tool_info(self, tool_name: str) -> Optional[dict]:
        """
        Return metadata for a specific tool.
        """
        mod = TOOL_MAP.get(tool_name)
        if mod:
            return getattr(mod, "TOOL_INFO", {"name": tool_name, "description": ""})
        return None

    def run_tool_sync(self, tool_name: str, target: str, mode: str = "basic",
                      **kwargs) -> Dict[str, Any]:
        """
        Run a single tool synchronously and return its result.
        Useful for direct API calls without creating a full scan job.
        """
        if tool_name not in TOOL_MAP:
            raise ValueError(f"Unknown tool: {tool_name}")
        module = TOOL_MAP[tool_name]
        try:
            return module.run(target, mode, **kwargs)
        except Exception as exc:
            logger.error("Direct tool %s failed: %s", tool_name, exc, exc_info=True)
            return {
                "tool": tool_name,
                "target": target,
                "data": {},
                "error": str(exc),
            }

    def start_scan(self, target: str, mode: str, tools: List[str],
                   history_store, tool_options: Optional[Dict[str, Any]] = None) -> str:
        """
        Launch a new scan.

        Args:
            target: domain or IP.
            mode: 'basic' or 'expert'.
            tools: list of tool names (empty => default set for mode).
            history_store: HistoryStore instance.
            tool_options: optional dict of extra parameters forwarded to every
                          tool's run() call (e.g. timeout, max_workers, folder_path).
        Returns:
            job_id (UUID string) for polling.
        """
        # Determine the actual tool list
        if not tools:
            tools = DEFAULT_EXPERT_TOOLS if mode == "expert" else DEFAULT_BASIC_TOOLS
        tools = _parse_tools(tools)

        # Create a history entry (status = running)
        entry_id = history_store.add_entry(target, mode, tools, status="running")

        # Register the job
        job_id = str(uuid.uuid4())
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

        # Acquire concurrency permit, then start background thread
        self._semaphore.acquire()
        thread = threading.Thread(
            target=self._execute, args=(job, history_store),
            daemon=True, name=f"scan-{job_id[:8]}"
        )
        job._thread = thread
        thread.start()
        logger.info(
            "Scan started: job=%s target=%s mode=%s tools=%s",
            job_id, target, mode, tools
        )
        return job_id

    def get_progress(self, job_id: str) -> Optional[dict]:
        """Return the current state of a job, or None if unknown."""
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return None
        return job.to_dict()

    def cancel_scan(self, job_id: str) -> bool:
        """Signal a running scan to stop. Returns True if the job was found and running."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.status in ("pending", "running"):
                job.cancel_event.set()
                logger.info("Cancel signal sent to job %s", job_id)
                return True
        return False

    def cancel_all(self) -> None:
        """Cancel every active scan (used during graceful shutdown)."""
        with self._lock:
            for job in self._jobs.values():
                if job.status in ("pending", "running"):
                    job.cancel_event.set()
                    logger.info("Cancel signal sent to job %s (shutdown)", job.job_id)

    # ------------------------------------------------------------------
    # Internal execution
    # ------------------------------------------------------------------
    def _execute(self, job: ScanJob, history_store) -> None:
        """Main worker method – runs inside a dedicated thread."""
        start_time = time.time()
        try:
            job.status = "running"
            total_tools = len(job.tools)
            job.results = {}

            for idx, tool_name in enumerate(job.tools):
                # Check user cancellation
                if job.cancel_event.is_set():
                    job.status = "cancelled"
                    job.error = "Cancelled by user"
                    break

                # Check global timeout
                if time.time() - start_time > self._timeout:
                    job.status = "timeout"
                    job.error = f"Scan exceeded {self._timeout}s limit"
                    break

                # Update progress
                job.current_tool = tool_name
                job.percent = int((idx / total_tools) * 100)

                # Run the tool
                tool_module = TOOL_MAP[tool_name]
                try:
                    result = tool_module.run(
                        job.target,
                        job.mode,
                        **job.tool_options
                    )
                except Exception as exc:
                    logger.error("Error in tool %s: %s", tool_name, exc, exc_info=True)
                    result = {
                        "tool": tool_name,
                        "target": job.target,
                        "data": {},
                        "error": str(exc),
                    }
                job.results[tool_name] = result

            # If we finished the loop without a terminal state, mark as completed
            if job.status == "running":
                job.status = "completed"
                job.percent = 100
                job.current_tool = None

        except Exception as exc:
            logger.exception("Unexpected error in job %s", job.job_id)
            job.status = "error"
            job.error = f"Unexpected error: {exc}"
        finally:
            # Release semaphore
            self._semaphore.release()
            job.finished_at = time.time()

            # Update history entry
            try:
                history_store.update_entry(
                    job.entry_id,
                    status=job.status,
                    result=job.results if job.status == "completed" else None,
                    error=job.error,
                )
            except Exception as exc:
                logger.error("Failed to update history for job %s: %s", job.job_id, exc)

            # Schedule memory cleanup for old jobs
            self._cleanup_old_jobs()

    def _cleanup_old_jobs(self) -> None:
        """Remove finished jobs that have been kept longer than the retention period."""
        now = time.time()
        with self._lock:
            stale_ids = [
                jid for jid, job in self._jobs.items()
                if job.finished_at and (now - job.finished_at > self._cleanup_after)
            ]
            for jid in stale_ids:
                del self._jobs[jid]
                logger.debug("Job %s removed from memory (cleanup)", jid)

    def reload_tools(self) -> None:
        """
        Re-discover tools. Useful if new modules are added dynamically.
        """
        global TOOL_MAP, DEFAULT_EXPERT_TOOLS
        TOOL_MAP = discover_tools()
        DEFAULT_EXPERT_TOOLS = sorted(TOOL_MAP.keys())
        logger.info("Tools reloaded. %d tools available.", len(TOOL_MAP))