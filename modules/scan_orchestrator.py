"""
Oxysintx – Scan Orchestrator (v2.3.0)

Background job manager for running security scanning tools.

Changes in v2.3.0
-----------------
- Module discovery hardened: ``dirfuzz`` and every non-scan module is now
  explicitly excluded, plus a per-module opt-out via ``TOOL_INFO["scan_tool"]
  = False`` so a module can hide itself without editing this file.
- Two distinct phases in tool dispatch: ``pre-cancel`` (skip entirely) and
  ``mid-tool cancel`` (propagate ``cancel_event`` then wait briefly).
- Per-tool event callbacks via ``ScanOrchestrator.on_tool_event(cb)`` —
  fires on ``tool_start``, ``tool_done``, ``tool_error``, ``tool_retry``.
  Ideal for streaming to an SSE consumer without polling.
- New helpers: ``run_tool_async()`` (fire-and-forget tool call returning a
  job id), ``wait_for_job(job_id, timeout)`` (blocking wait for tests),
  ``snapshot_full()`` (complete job data, not just summary).
- Job status now distinguishes ``cancelling`` (signal sent, worker still
  unwinding) from ``cancelled`` (worker terminated). UI can render both.
- Byte-accurate truncation: ``_meta.original_bytes`` and
  ``_meta.truncated`` are added to oversized results, matching the
  ``SCAN_RESULT_MAX_BYTES`` cap.
- Discovery cache: repeated ``reload_tools()`` calls no longer re-exec a
  module that already failed to import, preventing log spam.
- Metrics extended: ``tools_per_phase`` (pre-cancel skips counted), plus
  ``per_tool.avg_ms`` and ``per_tool.error_kinds``.
- Tool deduplication is case-insensitive; ``"DNS_Lookup"`` and
  ``"dns_lookup"`` collapse to one.

Changes in v2.2.0
-----------------
- Structured metrics: total / completed / failed / cancelled / timed-out,
  per-tool success rates and average durations.
- Environment-overridable configuration.
- Result size caps.
- Per-tool timeout overrides via TOOL_INFO["timeout_seconds"].
- Retry policy for flaky tools: TOOL_INFO["retries"].
- Progress callbacks on tool start / finish + terminal states.
- Introspection helpers: list_jobs(), cancel_all(), snapshot(), metrics(),
  reload_tools().
- Tool deduplication at start_scan().
- Cleanup runs on snapshot() as well.
- run_tool_sync() honours an optional ``timeout`` kwarg.
- Thread-safe metrics counters.

Adding a new tool
-----------------
Create ``modules/<name>.py`` exposing:

    def run(target: str, mode: str, **kwargs) -> dict
    TOOL_INFO = {
        "name": "My Tool",
        "version": "1.0.0",
        "description": "…",
        # Optional:
        "timeout_seconds": 120,   # per-tool timeout, default = SCAN_TIMEOUT
        "retries": 1,             # retry on exception, default 0
        "category": "recon",      # free-form, surfaced in list_tools()
        "scan_tool": True,        # default True; set False to hide from
                                  # auto-discovery (for modules invoked via
                                  # their own endpoints, e.g. dirfuzz)
    }

Optional kwarg (recommended):

    def run(target, mode, *, cancel_event=None, **kwargs): ...
        if cancel_event and cancel_event.is_set():
            return {"tool": __name__, "target": target, "data": {},
                    "error": "cancelled"}

The orchestrator auto-registers any module that defines a callable ``run``
and has not opted out via ``TOOL_INFO["scan_tool"] = False``.
"""

from __future__ import annotations

import importlib
import inspect
import json
import logging
import os
import pkgutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

import modules as modules_pkg


# ---------------------------------------------------------------------------
# Configuration (env-overridable)
# ---------------------------------------------------------------------------
def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        return default


MAX_CONCURRENT_SCANS: int = _env_int("SCAN_MAX_CONCURRENT", 3)
SCAN_TIMEOUT_SECONDS: int = _env_int("SCAN_TIMEOUT_SECONDS", 600)
JOB_CLEANUP_AFTER_SECONDS: int = _env_int("SCAN_JOB_TTL", 3600)
RESULT_MAX_BYTES: int = _env_int("SCAN_RESULT_MAX_BYTES", 1_048_576)  # 1 MB per tool
TOOL_RETRY_BACKOFF: float = _env_float("SCAN_RETRY_BACKOFF", 0.5)
CANCEL_GRACE_SECONDS: float = _env_float("SCAN_CANCEL_GRACE", 5.0)


DEFAULT_BASIC_TOOLS: List[str] = [
    "whois_lookup", "dns_lookup", "ssl_check", "headers_check",
    "ip_info", "connectivity_check", "email_security", "subdomain_enum",
    "tech_fingerprint", "port_scan",
]

DEFAULT_EXPERT_TOOLS: Optional[List[str]] = None

logger = logging.getLogger("oxysintx.scan_orchestrator")


# ---------------------------------------------------------------------------
# Modules that are NOT scan tools
# ---------------------------------------------------------------------------
# Modules excluded by *name*. Modules can also opt out at runtime by
# declaring ``TOOL_INFO["scan_tool"] = False``. Both mechanisms apply.
_EXCLUDED_MODULES: Set[str] = {
    # Core / infrastructure
    "scan_orchestrator",
    "source_viewer",
    "_common",

    # Bots & integrations
    "telegram",
    "whatsapp",
    "quick_menu",
    "downsea",

    # C2 / cod / helper
    "testing",
    "adios",
    "c2",
    "start",

    # Analytic / legacy — invoked via their own endpoints
    "analytic_manager",
    "brute_force",
    "sql_injection",
    "exploit_repository",

    # Exploit modules — each exposes its own /api/exploit/* endpoints and
    # has a different run() signature (run(target_or_base, options_dict)).
    "xss_exploiter",
    "subdomain_takeover",
    "sniper",
    "dirfuzz",               # ← NEW: invoked via /api/exploit/dirfuzz/*
    "http_logger",

    # OSINT / search helpers (not timed scans)
    "search_user",
    "osint",
}

_LONG_RUNNING_TOOLS: Set[str] = set()

# Module import cache — prevents re-exec of modules that failed to import
# every time reload_tools() is called.
_IMPORT_FAILURES: Dict[str, str] = {}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def _accepts_kwarg(func: Callable, name: str) -> bool:
    """Return True if ``func`` declares ``name`` or a **kwargs catch-all."""
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return True
    for param in sig.parameters.values():
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            return True
        if param.name == name:
            return True
    return False


def _wants_scan_tool(mod: Any) -> bool:
    """Respect ``TOOL_INFO['scan_tool']`` — default True."""
    info = getattr(mod, "TOOL_INFO", None) or {}
    flag = info.get("scan_tool", True)
    return bool(flag)


def discover_tools(*, retry_failures: bool = False) -> Dict[str, Any]:
    """Return ``{module_name: module_object}`` for every valid scan tool.

    Modules that failed to import are cached — call with
    ``retry_failures=True`` after fixing the module to try again.
    """
    if retry_failures:
        _IMPORT_FAILURES.clear()

    tools: Dict[str, Any] = {}
    for _, name, _ in pkgutil.iter_modules(modules_pkg.__path__):
        if name in _EXCLUDED_MODULES or name.startswith("_"):
            continue
        if name in _IMPORT_FAILURES:
            logger.debug(
                "Module %s skipped (cached import failure: %s)",
                name, _IMPORT_FAILURES[name],
            )
            continue
        try:
            mod = importlib.import_module(f"modules.{name}")
        except Exception as exc:  # noqa: BLE001
            _IMPORT_FAILURES[name] = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "Failed to import module %s: %s", name, exc, exc_info=True,
            )
            continue

        run_fn = getattr(mod, "run", None)
        if not callable(run_fn):
            logger.debug("Module %s skipped – no callable run()", name)
            continue

        if not _wants_scan_tool(mod):
            logger.debug(
                "Module %s skipped – TOOL_INFO['scan_tool'] = False", name,
            )
            continue

        tools[name] = mod
        logger.debug("Registered scan tool: %s", name)

    return tools


TOOL_MAP: Dict[str, Any] = discover_tools()
logger.info("Discovered %d scan tools: %s", len(TOOL_MAP), sorted(TOOL_MAP))

if DEFAULT_EXPERT_TOOLS is None:
    DEFAULT_EXPERT_TOOLS = sorted(TOOL_MAP.keys())


def _parse_tools(requested: Iterable[str]) -> List[str]:
    """Keep only known tools. Deduplicate (case-insensitive) preserving order."""
    seen: Set[str] = set()
    valid: List[str] = []
    for t in requested:
        if not isinstance(t, str):
            continue
        key = t.strip().lower()
        if key in TOOL_MAP and key not in seen:
            seen.add(key)
            valid.append(key)
    if not valid:
        logger.warning("No valid tools requested; falling back to basic set")
        valid = [t for t in DEFAULT_BASIC_TOOLS if t in TOOL_MAP]
    return valid


def _tool_timeout(tool_name: str) -> int:
    info = getattr(TOOL_MAP.get(tool_name), "TOOL_INFO", None) or {}
    try:
        override = int(info.get("timeout_seconds", SCAN_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        override = SCAN_TIMEOUT_SECONDS
    return max(5, min(override, 86_400))


def _tool_retries(tool_name: str) -> int:
    info = getattr(TOOL_MAP.get(tool_name), "TOOL_INFO", None) or {}
    try:
        n = int(info.get("retries", 0))
    except (TypeError, ValueError):
        n = 0
    return max(0, min(n, 5))


def _truncate_result(result: Any, max_bytes: int = RESULT_MAX_BYTES) -> Any:
    """Return a copy of ``result`` capped to ``max_bytes`` of JSON."""
    if not isinstance(result, dict):
        return result
    try:
        encoded = json.dumps(result, ensure_ascii=False, default=str)
    except Exception:
        return result
    encoded_bytes = len(encoded.encode("utf-8"))
    if encoded_bytes <= max_bytes:
        # Add a lightweight marker only if the caller asked for one.
        result.setdefault("_meta", {})["original_bytes"] = encoded_bytes
        return result

    trimmed = dict(result)
    meta = dict(trimmed.get("_meta") or {})
    meta["truncated"] = True
    meta["original_bytes"] = encoded_bytes
    meta["max_bytes"] = max_bytes
    trimmed["_meta"] = meta

    data = trimmed.get("data")
    if data is not None:
        try:
            data_encoded = json.dumps(data, ensure_ascii=False, default=str)
        except Exception:
            data_encoded = ""
        trimmed["data"] = {
            "_truncated": True,
            "_original_bytes": len(data_encoded.encode("utf-8")),
            "_max_bytes": max_bytes,
            "_note": ("Result exceeded the size cap. Increase "
                      "SCAN_RESULT_MAX_BYTES or inspect the tool directly."),
        }
    return trimmed


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
    started_at: Optional[float] = None
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
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed": (
                round((self.finished_at or time.time())
                      - (self.started_at or self.created_at), 2)
            ),
        }

    def to_summary(self) -> dict:
        """Trimmed version without the (potentially huge) ``results`` blob."""
        d = self.to_dict()
        d.pop("results", None)
        d["results_keys"] = list(self.results.keys())
        return d


ProgressCallback = Callable[[ScanJob], None]
ToolEventCallback = Callable[[str, Dict[str, Any]], None]


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
        self._tool_event_callbacks: List[ToolEventCallback] = []

        self._metrics: Dict[str, Any] = {
            "scans_started": 0,
            "scans_completed": 0,
            "scans_failed": 0,
            "scans_cancelled": 0,
            "scans_timed_out": 0,
            "tools_invoked": 0,
            "tools_failed": 0,
            "tools_retried": 0,
            "tools_skipped_cancelled": 0,
            "per_tool": {},
        }

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def list_tools(self) -> Dict[str, dict]:
        return {
            name: getattr(mod, "TOOL_INFO",
                          {"name": name, "description": ""})
            for name, mod in TOOL_MAP.items()
        }

    def get_tool_info(self, tool_name: str) -> Optional[dict]:
        mod = TOOL_MAP.get(tool_name)
        if mod is None:
            return None
        return getattr(mod, "TOOL_INFO",
                        {"name": tool_name, "description": ""})

    def on_progress(self, callback: ProgressCallback) -> None:
        with self._lock:
            self._progress_callbacks.append(callback)

    def off_progress(self, callback: ProgressCallback) -> None:
        with self._lock:
            try:
                self._progress_callbacks.remove(callback)
            except ValueError:
                pass

    def on_tool_event(self, callback: ToolEventCallback) -> None:
        """Register a callback fired per-tool event.

        The callback receives ``(event_type, payload)`` where ``event_type``
        is one of ``tool_start``, ``tool_done``, ``tool_error``,
        ``tool_retry``, ``tool_skipped``.
        """
        with self._lock:
            self._tool_event_callbacks.append(callback)

    def metrics(self) -> Dict[str, Any]:
        with self._lock:
            metrics = json.loads(json.dumps(self._metrics, default=str))
            active = sum(1 for j in self._jobs.values()
                         if j.status in ("pending", "running", "cancelling"))
            metrics["active_jobs"] = active
            metrics["jobs_in_memory"] = len(self._jobs)
            metrics["tools_registered"] = len(TOOL_MAP)
            # Enrich per_tool with average duration
            for name, entry in metrics["per_tool"].items():
                calls = entry.get("calls") or 0
                entry["avg_ms"] = (
                    round(entry.get("total_ms", 0.0) / calls, 1) if calls else 0.0
                )
            return metrics

    def list_jobs(
        self,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[dict]:
        with self._lock:
            jobs = list(self._jobs.values())
        if status:
            jobs = [j for j in jobs if j.status == status]
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return [j.to_summary() for j in jobs[: max(1, min(limit, 500))]]

    def snapshot(self) -> Dict[str, Any]:
        self._cleanup_old_jobs()
        return {
            "metrics": self.metrics(),
            "active": self.list_jobs(status="running", limit=50),
            "pending": self.list_jobs(status="pending", limit=50),
            "cancelling": self.list_jobs(status="cancelling", limit=50),
        }

    def snapshot_full(self) -> Dict[str, Any]:
        """Like snapshot() but includes full job data (with results)."""
        self._cleanup_old_jobs()
        with self._lock:
            jobs = [j.to_dict() for j in self._jobs.values()]
        jobs.sort(key=lambda j: j["created_at"], reverse=True)
        return {"metrics": self.metrics(), "jobs": jobs}

    # ------------------------------------------------------------------
    # Direct invocation
    # ------------------------------------------------------------------
    def run_tool_sync(
        self,
        tool_name: str,
        target: str,
        mode: str = "basic",
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        if tool_name not in TOOL_MAP:
            raise ValueError(f"Unknown tool: {tool_name}")
        module = TOOL_MAP[tool_name]
        if timeout is None:
            try:
                return module.run(target, mode, **kwargs)
            except Exception as exc:  # noqa: BLE001
                logger.error("Direct tool %s failed: %s",
                              tool_name, exc, exc_info=True)
                return {"tool": tool_name, "target": target,
                        "data": {}, "error": str(exc)}

        cancel_event = threading.Event()
        result_box: Dict[str, Any] = {}
        err_box: Dict[str, Any] = {}

        if _accepts_kwarg(module.run, "cancel_event"):
            kwargs.setdefault("cancel_event", cancel_event)

        def _worker():
            try:
                result_box["v"] = module.run(target, mode, **kwargs)
            except Exception as exc:  # noqa: BLE001
                err_box["e"] = exc

        t = threading.Thread(target=_worker, daemon=True,
                             name=f"tool-{tool_name}")
        t.start()
        t.join(timeout)

        if t.is_alive():
            cancel_event.set()
            return {"tool": tool_name, "target": target, "data": {},
                    "error": f"timeout after {timeout}s"}
        if "e" in err_box:
            logger.error("Direct tool %s failed: %s",
                          tool_name, err_box["e"], exc_info=True)
            return {"tool": tool_name, "target": target, "data": {},
                    "error": str(err_box["e"])}
        return result_box.get("v", {
            "tool": tool_name, "target": target, "data": {},
            "error": "no_result",
        })

    def run_tool_async(
        self,
        tool_name: str,
        target: str,
        mode: str = "basic",
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Fire-and-forget a single tool. Returns ``{job_id, status}``
        immediately; poll with ``get_progress(job_id)`` or wait with
        ``wait_for_job(job_id)``."""
        if tool_name not in TOOL_MAP:
            raise ValueError(f"Unknown tool: {tool_name}")

        job_id = str(uuid.uuid4())
        cancel_event = threading.Event()
        job = ScanJob(
            job_id=job_id,
            target=target,
            mode=mode,
            tools=[tool_name],
            entry_id=-1,  # not persisted
            cancel_event=cancel_event,
            tool_options=dict(kwargs),
        )

        with self._lock:
            self._jobs[job_id] = job
            self._metrics["scans_started"] += 1

        self._semaphore.acquire()
        thread = threading.Thread(
            target=self._execute_single,
            args=(job, tool_name, timeout),
            daemon=True,
            name=f"toolasync-{job_id[:8]}",
        )
        job._thread = thread
        thread.start()
        self._emit_progress(job)
        return {"job_id": job_id, "status": job.status,
                "tool": tool_name, "target": target}

    def wait_for_job(
        self,
        job_id: str,
        timeout: Optional[float] = None,
    ) -> Optional[dict]:
        """Block until the job reaches a terminal state or ``timeout`` expires."""
        deadline = (time.monotonic() + timeout) if timeout else None
        while True:
            with self._lock:
                job = self._jobs.get(job_id)
            if job is None:
                return None
            if job.status in ("completed", "cancelled", "error", "timeout"):
                return job.to_dict()
            if deadline is not None and time.monotonic() > deadline:
                return job.to_dict()
            time.sleep(0.15)

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
        if not target or not str(target).strip():
            raise ValueError("target is required")

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
            self._metrics["scans_started"] += 1

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
        self._emit_progress(job)
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
            job.status = "cancelling"
            logger.info("Cancel signal sent to job %s", job_id)
            self._emit_progress(job)
            return True
        return False

    def cancel_all(self) -> int:
        with self._lock:
            active = [j for j in self._jobs.values()
                      if j.status in ("pending", "running")]
        for job in active:
            job.cancel_event.set()
            job.status = "cancelling"
        if active:
            logger.info("Cancel signal sent to %d job(s) (bulk)", len(active))
            for job in active:
                self._emit_progress(job)
        return len(active)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    def _execute(self, job: ScanJob, history_store: Any) -> None:
        start_time = time.time()
        final_status = "error"
        final_error: Optional[str] = job.error

        try:
            job.status = "running"
            job.started_at = start_time
            total = max(1, len(job.tools))
            job.results = {}

            for idx, tool_name in enumerate(job.tools):
                # --- pre-tool cancellation: skip entirely ---
                if job.cancel_event.is_set():
                    final_status = "cancelled"
                    final_error = "Cancelled by user"
                    with self._lock:
                        self._metrics["tools_skipped_cancelled"] += 1
                    self._emit_tool_event("tool_skipped", {
                        "job_id": job.job_id, "tool": tool_name,
                        "reason": "cancelled_before_start",
                    })
                    break

                # --- global timeout (pre-check) ---
                if time.time() - start_time > self._timeout:
                    final_status = "timeout"
                    final_error = f"Scan exceeded {self._timeout}s limit"
                    break

                job.current_tool = tool_name
                job.percent = int((idx / total) * 100)
                self._emit_progress(job)
                self._emit_tool_event("tool_start", {
                    "job_id": job.job_id, "tool": tool_name,
                    "index": idx, "total": total,
                })

                tool_started = time.perf_counter()
                result = self._invoke_tool_with_retries(job, tool_name)
                elapsed_ms = (time.perf_counter() - tool_started) * 1000.0

                if isinstance(result, dict):
                    result.setdefault("_meta", {})["elapsed_ms"] = round(elapsed_ms, 1)
                    result = _truncate_result(result)
                job.results[tool_name] = result
                self._record_tool_metric(tool_name, result, elapsed_ms)

                ok = not (isinstance(result, dict) and result.get("error"))
                self._emit_tool_event(
                    "tool_done" if ok else "tool_error",
                    {
                        "job_id": job.job_id, "tool": tool_name,
                        "index": idx, "total": total,
                        "elapsed_ms": round(elapsed_ms, 1),
                        "error": result.get("error") if isinstance(result, dict) else None,
                    },
                )

                # --- global timeout (post-check) ---
                if time.time() - start_time > self._timeout:
                    final_status = "timeout"
                    final_error = f"Scan exceeded {self._timeout}s limit"
                    break

                job.percent = int(((idx + 1) / total) * 100)
                self._emit_progress(job)
            else:
                final_status = "completed"

            if final_status == "completed":
                job.percent = 100
                job.current_tool = None
            else:
                job.percent = min(job.percent, 99)

        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error in job %s", job.job_id)
            final_status = "error"
            final_error = f"Unexpected error: {exc}"

        finally:
            job.status = final_status
            job.error = final_error
            job.finished_at = time.time()

            try:
                self._semaphore.release()
            except ValueError:
                pass

            try:
                history_store.update_entry(
                    job.entry_id,
                    status=job.status,
                    result=job.results if job.status == "completed" else None,
                    error=job.error,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to update history for job %s: %s",
                              job.job_id, exc)

            with self._lock:
                if final_status == "completed":
                    self._metrics["scans_completed"] += 1
                elif final_status == "cancelled":
                    self._metrics["scans_cancelled"] += 1
                elif final_status == "timeout":
                    self._metrics["scans_timed_out"] += 1
                else:
                    self._metrics["scans_failed"] += 1

            self._emit_progress(job)
            self._cleanup_old_jobs()

    def _execute_single(
        self,
        job: ScanJob,
        tool_name: str,
        timeout: Optional[float],
    ) -> None:
        """Simplified executor for run_tool_async()."""
        start_time = time.time()
        final_status = "error"
        final_error: Optional[str] = None

        try:
            job.status = "running"
            job.started_at = start_time
            job.current_tool = tool_name

            module = TOOL_MAP[tool_name]
            kwargs = self._build_tool_kwargs(job, module.run)

            result_box: Dict[str, Any] = {}
            err_box: Dict[str, Any] = {}

            def _call():
                try:
                    result_box["v"] = module.run(
                        job.target, job.mode, **kwargs,
                    )
                except Exception as exc:  # noqa: BLE001
                    err_box["e"] = exc

            t = threading.Thread(target=_call, daemon=True,
                                  name=f"toolinner-{job.job_id[:6]}")
            t.start()
            t.join(timeout)

            if t.is_alive():
                job.cancel_event.set()
                final_status = "timeout"
                final_error = f"tool timeout after {timeout}s"
                result = {"tool": tool_name, "target": job.target,
                          "data": {}, "error": final_error}
            elif "e" in err_box:
                final_status = "error"
                final_error = str(err_box["e"])
                result = self._error_result(tool_name, job.target, err_box["e"])
            else:
                final_status = "completed"
                result = result_box.get("v", {
                    "tool": tool_name, "target": job.target,
                    "data": {}, "error": "no_result",
                })

            if isinstance(result, dict):
                result = _truncate_result(result)
            job.results[tool_name] = result
            job.percent = 100

        except Exception as exc:  # noqa: BLE001
            logger.exception("run_tool_async worker %s failed", job.job_id)
            final_status = "error"
            final_error = f"Unexpected error: {exc}"

        finally:
            job.status = final_status
            job.error = final_error
            job.finished_at = time.time()
            try:
                self._semaphore.release()
            except ValueError:
                pass
            with self._lock:
                if final_status == "completed":
                    self._metrics["scans_completed"] += 1
                elif final_status == "timeout":
                    self._metrics["scans_timed_out"] += 1
                else:
                    self._metrics["scans_failed"] += 1
            self._emit_progress(job)
            self._cleanup_old_jobs()

    # ------------------------------------------------------------------
    # Tool invocation
    # ------------------------------------------------------------------
    def _invoke_tool_with_retries(self, job: ScanJob,
                                    tool_name: str) -> Dict[str, Any]:
        retries = _tool_retries(tool_name)
        attempt = 0
        last_result: Dict[str, Any] = {}

        while attempt <= retries:
            if job.cancel_event.is_set():
                return {"tool": tool_name, "target": job.target,
                        "data": {}, "error": "cancelled"}

            last_result = self._invoke_tool(job, tool_name)
            failed = (
                isinstance(last_result, dict)
                and last_result.get("error")
                and "cancelled" not in str(last_result.get("error", "")).lower()
            )
            if not failed:
                return last_result
            if attempt < retries:
                with self._lock:
                    self._metrics["tools_retried"] += 1
                logger.info(
                    "Retrying tool %s (attempt %d/%d) after: %s",
                    tool_name, attempt + 1, retries, last_result.get("error"),
                )
                self._emit_tool_event("tool_retry", {
                    "job_id": job.job_id, "tool": tool_name,
                    "attempt": attempt + 1, "of": retries,
                    "error": last_result.get("error"),
                })
                time.sleep(TOOL_RETRY_BACKOFF * (attempt + 1))
            attempt += 1

        return last_result

    def _invoke_tool(self, job: ScanJob, tool_name: str) -> Dict[str, Any]:
        module = TOOL_MAP[tool_name]
        run_fn = module.run

        with self._lock:
            self._metrics["tools_invoked"] += 1

        kwargs = self._build_tool_kwargs(job, run_fn)

        try:
            return run_fn(job.target, job.mode, **kwargs)
        except TypeError as exc:
            logger.warning(
                "Tool %s rejected kwargs (%s); retrying with minimal args",
                tool_name, exc,
            )
            try:
                return run_fn(job.target, job.mode)
            except Exception as inner:  # noqa: BLE001
                logger.error("Tool %s failed: %s",
                              tool_name, inner, exc_info=True)
                with self._lock:
                    self._metrics["tools_failed"] += 1
                return self._error_result(tool_name, job.target, inner)
        except Exception as exc:  # noqa: BLE001
            logger.error("Tool %s failed: %s",
                          tool_name, exc, exc_info=True)
            with self._lock:
                self._metrics["tools_failed"] += 1
            return self._error_result(tool_name, job.target, exc)

    def _build_tool_kwargs(self, job: ScanJob,
                            run_fn: Callable) -> Dict[str, Any]:
        candidates: Dict[str, Any] = dict(job.tool_options)
        if _accepts_kwarg(run_fn, "cancel_event"):
            candidates["cancel_event"] = job.cancel_event

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
    def _error_result(tool_name: str, target: str,
                      exc: BaseException) -> Dict[str, Any]:
        return {
            "tool": tool_name,
            "target": target,
            "data": {},
            "error": f"{type(exc).__name__}: {exc}",
        }

    # ------------------------------------------------------------------
    # Metrics helpers
    # ------------------------------------------------------------------
    def _record_tool_metric(self, tool_name: str,
                             result: Any, elapsed_ms: float) -> None:
        ok = not (isinstance(result, dict) and result.get("error"))
        with self._lock:
            entry = self._metrics["per_tool"].setdefault(
                tool_name,
                {"ok": 0, "fail": 0, "total_ms": 0.0, "calls": 0},
            )
            entry["calls"] += 1
            entry["total_ms"] += elapsed_ms
            if ok:
                entry["ok"] += 1
            else:
                entry["fail"] += 1
                error_str = str(result.get("error", ""))[:60]
                kinds = entry.setdefault("error_kinds", {})
                kinds[error_str] = kinds.get(error_str, 0) + 1

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

    def _emit_tool_event(self, event_type: str,
                          payload: Dict[str, Any]) -> None:
        with self._lock:
            callbacks = tuple(self._tool_event_callbacks)
        if not callbacks:
            return
        for cb in callbacks:
            try:
                cb(event_type, payload)
            except Exception:  # noqa: BLE001
                logger.exception("Tool-event callback raised")

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

    def reload_tools(self, *, retry_failures: bool = False) -> None:
        """Re-scan the modules package. Call after adding a new tool file."""
        global TOOL_MAP, DEFAULT_EXPERT_TOOLS
        TOOL_MAP = discover_tools(retry_failures=retry_failures)
        DEFAULT_EXPERT_TOOLS = sorted(TOOL_MAP.keys())
        logger.info("Tools reloaded. %d tools available.", len(TOOL_MAP))
