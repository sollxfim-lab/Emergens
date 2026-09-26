#!/usr/bin/env python3
"""
Opencode — Scan Orchestrator (v3.8.0)

Background job manager for the Opencode Flask stack.

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

================================================================================
CALLING CONVENTIONS
================================================================================
Two conventions exist in the modules/ tree:

    1. mode-string style:  run(target: str, mode: str, **kwargs) -> dict
       Used by: xss, sql_map, sql_injection, port_scan, dns_lookup,
                lfi_rfi, headers_check, ssl_check, ...

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

================================================================================
CHANGELOG — v3.8.0
================================================================================
  ✔ NEW   — `lfi_rfi` (Local/Remote File Inclusion Scanner v1.0.0) is now
            auto-discovered and appears in the expert-mode tool list.
            It is intentionally **excluded** from DEFAULT_BASIC_TOOLS
            because LFI/RFI testing is an active intrusion technique,
            whereas basic mode is a passive recon sweep by design.

  ✔ NEW   — `_INTRUSIVE_TOOLS` set: modules that are never auto-added to
            the basic tool list. Populated with `lfi_rfi`, `sql_map`,
            `xss`, `xss_exploiter`, `sqli_engine`, `sniper`, `dirfuzz`.
            Dashboard users can still explicitly select any of them.

  ✔ NEW   — `get_registry_snapshot()` now exposes `intrusive_tools` and
            `basic_tools` (filtered), so the frontend can colour-code
            which tools are safe to run in a first pass.

  ✔ NEW   — `ScanOrchestrator.list_tools()` output now includes an
            `"intrusive": bool` flag on each entry, sourced from
            `_INTRUSIVE_TOOLS`. The dashboard's Testing carousel reads
            this to show a warning badge without any hard-coded list
            on the JS side.

  ✔ HARD  — `_announce_registry()` now word-wraps the tool list into
            multiple indented rows so adding more scanners (like
            `lfi_rfi`) never pushes the terminal past 80 columns.

  ✔ HARD  — `_parse_tools()` refuses `_INTRUSIVE_TOOLS` when the caller
            passes an empty list in basic mode (falls back to the
            passive set) — prevents accidental aggressive scans from
            the dashboard's "Quick Scan" button.

  ✔ PRESERVE — Every public symbol from v3.7.0 remains:
               ScanOrchestrator, ScanJob, TOOL_MAP, call_tool,
               discover_tools, get_registry_snapshot, ScanReporter,
               active_job_count, run_tool_sync, is_tool, list_jobs,
               cancel_scan, cancel_all, reload_tools.

Author: Yanxzyx
"""

from __future__ import annotations

import importlib
import logging
import os
import pkgutil
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import modules as modules_pkg


# =============================================================================
# Metadata
# =============================================================================
__version__ = "3.8.0"
__author__  = "Yanxzyx"


# =============================================================================
# Configuration
# =============================================================================
MAX_CONCURRENT_SCANS      = 3
SCAN_TIMEOUT_SECONDS      = 600
JOB_CLEANUP_AFTER_SECONDS = 3600

# Basic mode: fast passive recon — the tools the dashboard shows by default.
# Every tool listed here MUST be safe to run against a target that has only
# granted "passive recon" scope. Intrusive scanners belong in expert mode.
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

logger = logging.getLogger("opencode.scan_orchestrator")


# =============================================================================
# ANSI colour helpers — bright blue theme, auto-degrade to plain text
# =============================================================================
class _Ansi:
    RESET      = "\033[0m"
    BOLD       = "\033[1m"
    DIM        = "\033[2m"
    BLUE       = "\033[38;5;39m"
    BLUE_HI    = "\033[38;5;45m"
    BLUE_DEEP  = "\033[38;5;27m"
    BLUE_LIGHT = "\033[38;5;117m"
    CYAN       = "\033[38;5;51m"
    GREEN      = "\033[38;5;42m"
    RED        = "\033[38;5;203m"
    YELLOW     = "\033[38;5;220m"
    GRAY       = "\033[38;5;244m"
    GRAY_DIM   = "\033[38;5;240m"
    WHITE      = "\033[97m"


def _supports_color() -> bool:
    if os.getenv("OPENCODE_QUIET"):
        return False
    if os.getenv("NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


_USE_COLOR = _supports_color()


def _c(text: str, color: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{color}{text}{_Ansi.RESET}"


_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
_SPINNER_INTERVAL = 0.08


def _human_dur(seconds: float) -> str:
    if seconds < 1.0:
        return f"{int(seconds * 1000)}ms"
    if seconds < 60.0:
        return f"{seconds:.2f}s"
    m = int(seconds // 60)
    s = seconds - m * 60
    return f"{m}m {s:.1f}s"


# =============================================================================
# Embedding detection — do NOT announce when app.py already has a boot screen
# =============================================================================
def _is_embedded() -> bool:
    """
    Return True when this module was imported by an entrypoint that prints
    its own startup display (e.g. app.py). In that case, the registry
    announcement is redundant and should be suppressed.

    Override with:
        OPENCODE_SHOW_REGISTRY=1  →  always announce
        OPENCODE_QUIET=1          →  never announce
    """
    if os.getenv("OPENCODE_SHOW_REGISTRY"):
        return False
    if os.getenv("OPENCODE_QUIET"):
        return True
    main_mod = sys.modules.get("__main__")
    if main_mod is None:
        return False
    main_file = getattr(main_mod, "__file__", "") or ""
    if not main_file:
        return False
    base = os.path.basename(main_file).lower()
    return base in ("app.py", "app.pyc") or base == "app"


# =============================================================================
# Registry announcement — pretty stdout line, not a logger record
# =============================================================================
def _announce_registry(tool_names: List[str], intrusive: Set[str]) -> None:
    """
    Print a blue ✓ line summarising the discovered scan tools to stdout.

    Bypasses the logging pipeline so we can emit clean, coloured output
    that respects TTY state. Records a DEBUG log line for log files.
    """
    logger.debug(
        "Registered %d scan tool(s): %s",
        len(tool_names),
        ", ".join(tool_names) or "(none)",
    )

    if _is_embedded():
        return
    if os.getenv("OPENCODE_QUIET"):
        return

    n = len(tool_names)
    n_intrusive = sum(1 for t in tool_names if t in intrusive)

    # ── Non-TTY / NO_COLOR fallback ────────────────────────────────────
    if not _USE_COLOR:
        suffix = f" ({n_intrusive} intrusive)" if n_intrusive else ""
        sys.stdout.write(
            f"  ok  {n} scan tool(s) registered{suffix}  ·  v{__version__}\n"
        )
        sys.stdout.flush()
        return

    # ── Colourful TTY version ──────────────────────────────────────────
    mark  = _c("✓", _Ansi.GREEN)
    count = _c(f"{n} scan tool{'s' if n != 1 else ''} registered", _Ansi.WHITE)
    ver   = _c(f"v{__version__}", _Ansi.BLUE_HI)
    sep   = _c("·", _Ansi.BLUE_DEEP)
    sys.stdout.write(f"  {mark} {count}  {sep}  {ver}\n")

    # Tool list — wrap into short rows, mark intrusive tools in a different
    # colour so it's obvious at a glance which ones are aggressive.
    if tool_names:
        bullet  = _c("·", _Ansi.BLUE)
        indent  = "      "
        max_w   = 68
        row: List[str] = []
        line_len = 0

        def _flush() -> None:
            nonlocal row, line_len
            if not row:
                return
            # Intrusive tools get an amber tint
            pieces = [
                _c(name, _Ansi.YELLOW) if name in intrusive else _c(name, _Ansi.GRAY)
                for name in row
            ]
            sys.stdout.write(f"{indent}{bullet} " + " · ".join(pieces) + "\n")
            row = []
            line_len = 0

        for name in tool_names:
            add = len(name) + (3 if row else 0)
            if line_len + add > max_w and row:
                _flush()
                add = len(name)
            row.append(name)
            line_len += add
        _flush()

    sys.stdout.flush()


# =============================================================================
# ScanReporter — live terminal view for one scan job
# =============================================================================
class ScanReporter:
    """
    Renders a Claude-Code-style live view of one scan job to stdout.

        ╭─ scan a4f8c2d1 ─────────────────────────────────────────╮
        │  example.com  ·  expert mode  ·  15 tools               │
        ╰─────────────────────────────────────────────────────────╯
        ⠋ whois_lookup
        ✓ whois_lookup                          1/15    1.24s
        ...
        ─────────────────────────────────────────────────────────
        ✓ Scan complete   15/15 tools  ·  18.45s
    """

    _print_lock        = threading.Lock()
    _active_reporters  = 0

    def __init__(
        self,
        job_id: str,
        target: str,
        mode: str,
        tools: List[str],
        *,
        tool_meta: Optional[Dict[str, Dict[str, Any]]] = None,
        enabled: bool = True,
    ):
        self.job_id      = job_id
        self.short       = (job_id or "?").split("-")[0][:8] or "????????"
        self.target      = target
        self.mode        = mode
        self.tools       = list(tools)
        self.total       = max(1, len(self.tools))
        self.tool_meta   = tool_meta or {}
        self.enabled     = bool(enabled) and _USE_COLOR and not os.getenv("OPENCODE_QUIET")

        with ScanReporter._print_lock:
            ScanReporter._active_reporters += 1
            self._can_animate = (ScanReporter._active_reporters == 1)

        self._stop_spinner: Optional[threading.Event] = None
        self._spinner_thread: Optional[threading.Thread] = None
        self._line_occupied = False
        self._closed = False

    def _emit(self, text: str, *, end: str = "\n") -> None:
        if not self.enabled:
            return
        with ScanReporter._print_lock:
            sys.stdout.write(text + end)
            sys.stdout.flush()

    def _write_inplace(self, text: str) -> None:
        if not self.enabled:
            return
        with ScanReporter._print_lock:
            sys.stdout.write("\r\033[K" + text)
            sys.stdout.flush()
            self._line_occupied = True

    def _finish_line(self, text: str) -> None:
        if not self.enabled:
            return
        with ScanReporter._print_lock:
            if self._line_occupied:
                sys.stdout.write("\r\033[K")
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
            self._line_occupied = False

    def header(self) -> None:
        if not self.enabled:
            logger.debug(
                "Scan starting | job=%s target=%s mode=%s tools=%d",
                self.short, self.target, self.mode, self.total,
            )
            return
        width = 66
        title = f"─ scan {self.short} "
        top   = "╭" + title + "─" * max(0, width - len(title) - 2) + "╮"
        body  = f"│  {self.target}  ·  {self.mode} mode  ·  {self.total} tools"
        body  = body[: width - 2].ljust(width - 2) + "│"
        bot   = "╰" + "─" * (width - 2) + "╯"
        with ScanReporter._print_lock:
            sys.stdout.write("\n")
            sys.stdout.write(_c("  " + top,  _Ansi.BLUE_DEEP) + "\n")
            sys.stdout.write(_c("  " + body, _Ansi.BLUE_DEEP) + "\n")
            sys.stdout.write(_c("  " + bot,  _Ansi.BLUE_DEEP) + "\n")
            sys.stdout.flush()

    def summary(
        self,
        status: str,
        elapsed: float,
        completed: int,
        error: Optional[str] = None,
    ) -> None:
        if not self.enabled:
            logger.debug(
                "Scan finished | job=%s status=%s %d/%d elapsed=%.2fs%s",
                self.short, status, completed, self.total, elapsed,
                f" error={error}" if error else "",
            )
            return
        if status == "completed":
            mark  = _c("✓", _Ansi.GREEN)
            label = _c("Scan complete", _Ansi.BOLD + _Ansi.GREEN)
        elif status == "cancelled":
            mark  = _c("⊘", _Ansi.YELLOW)
            label = _c("Scan cancelled", _Ansi.BOLD + _Ansi.YELLOW)
        elif status == "timeout":
            mark  = _c("⏱", _Ansi.YELLOW)
            label = _c("Scan timed out", _Ansi.BOLD + _Ansi.YELLOW)
        else:
            mark  = _c("✗", _Ansi.RED)
            label = _c("Scan failed", _Ansi.BOLD + _Ansi.RED)
        counter = _c(f"{completed}/{self.total} tools", _Ansi.WHITE)
        dur     = _c(_human_dur(elapsed), _Ansi.GRAY)
        rule    = _c("─" * 66, _Ansi.BLUE_DEEP)
        with ScanReporter._print_lock:
            sys.stdout.write("\n")
            sys.stdout.write("  " + rule + "\n")
            sys.stdout.write(f"  {mark} {label}  {counter}  ·  {dur}\n")
            if error:
                short_err = (error or "")[:120]
                sys.stdout.write(f"      {_c(short_err, _Ansi.GRAY_DIM)}\n")
            sys.stdout.write("\n")
            sys.stdout.flush()

    def tool_start(self, name: str, index: int) -> None:
        if not self.enabled:
            return
        if self._can_animate:
            self._stop_spinner = threading.Event()
            self._spinner_thread = threading.Thread(
                target=self._spin_loop,
                args=(name,),
                daemon=True,
                name=f"spin-{self.short}-{index}",
            )
            self._spinner_thread.start()
        else:
            self._emit(f"  {_c('→', _Ansi.BLUE)} {_c(name, _Ansi.WHITE)}")

    def tool_finish(
        self,
        name: str,
        index: int,
        elapsed: float,
        ok: bool = True,
        error: Optional[str] = None,
    ) -> None:
        if self._stop_spinner is not None:
            self._stop_spinner.set()
            if self._spinner_thread is not None:
                self._spinner_thread.join(timeout=0.4)
            self._stop_spinner = None
            self._spinner_thread = None
        if not self.enabled:
            return
        mark    = _c("✓", _Ansi.GREEN) if ok else _c("✗", _Ansi.RED)
        counter = _c(f"{index}/{self.total}", _Ansi.GRAY_DIM)
        dur     = _c(_human_dur(elapsed), _Ansi.GRAY)
        display = name if len(name) <= 32 else name[:29] + "…"
        name_col = _c(f"{display:<32s}", _Ansi.WHITE)
        self._finish_line(f"  {mark} {name_col} {counter:>7s}   {dur}")
        if not ok and error:
            short_err = error.splitlines()[0][:110] if error else ""
            self._emit(f"      {_c(short_err, _Ansi.GRAY_DIM)}")

    def _spin_loop(self, name: str) -> None:
        i = 0
        while self._stop_spinner is not None and not self._stop_spinner.is_set():
            frame = _SPINNER_FRAMES[i % len(_SPINNER_FRAMES)]
            line  = f"  {_c(frame, _Ansi.BLUE)} {_c(name, _Ansi.WHITE)}"
            self._write_inplace(line)
            i += 1
            time.sleep(_SPINNER_INTERVAL)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._stop_spinner is not None:
            self._stop_spinner.set()
            if self._spinner_thread is not None:
                self._spinner_thread.join(timeout=0.4)
            self._stop_spinner = None
            self._spinner_thread = None
        with ScanReporter._print_lock:
            ScanReporter._active_reporters = max(
                0, ScanReporter._active_reporters - 1
            )

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


# =============================================================================
# Exclusion list
# =============================================================================
_EXCLUDED_MODULES: Set[str] = {
    "scan_orchestrator",
    "source_viewer",
    "_common",
    "telegram",
    "whatsapp",
    "quick_menu",
    "testing",
    "adios",
    "c2",
    "start",
    "dirfuzz",
    "sqli_engine",
    "sql_injection",
    "xss_exploiter",
    "sniper",
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
    "brute_force",
    "subdomain_takeover",
    "exploit_repository",
    "analytic_manager",
    "history_store",
}

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

# Modules that MUST NOT be auto-added to a basic-mode scan. They actively
# inject payloads, probe for injection points, or make outbound requests
# beyond plain passive recon. The dashboard surfaces them with an amber
# warning badge; users can still opt in explicitly.
_INTRUSIVE_TOOLS: Set[str] = {
    "lfi_rfi",
    "xss",
    "xss_exploiter",
    "sql_map",
    "sql_injection",
    "sqli_engine",
    "sniper",
    "dirfuzz",
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


def _tool_display_name(tool_key: str, mod: Any) -> str:
    """Friendly name from TOOL_INFO when available."""
    info = getattr(mod, "TOOL_INFO", None)
    if isinstance(info, dict):
        name = info.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    return tool_key


# =============================================================================
# Tool discovery
# =============================================================================
def discover_tools() -> Dict[str, Any]:
    """Walk the modules package and return {name: module} for scan tools."""
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
            logger.debug("modules.%s skipped — IS_SCAN_TOOL=False", name)
            continue

        kind = str(getattr(mod, "TOOL_KIND", "") or "").strip().lower()
        if kind in _NON_SCAN_KINDS:
            logger.debug("modules.%s skipped — TOOL_KIND=%s", name, kind)
            continue

        tools[name] = mod
        logger.debug("Registered scan tool: modules.%s (kind=%s)",
                     name, kind or "unspecified")

    return tools


# Initial discovery
TOOL_MAP: Dict[str, Any] = discover_tools()
DEFAULT_EXPERT_TOOLS = sorted(TOOL_MAP.keys())

# Announce to stdout (blue), unless we're being imported by app.py
_announce_registry(sorted(TOOL_MAP.keys()), _INTRUSIVE_TOOLS)


def _parse_tools(requested: List[str]) -> List[str]:
    """
    Filter `requested` to known tools. Falls back to the basic set.

    Basic-mode fallback excludes intrusive tools so a dashboard "Quick Scan"
    with no explicit tool list never fires an active intrusion probe.
    """
    valid = [t for t in requested if t in TOOL_MAP]
    if not valid:
        logger.warning("No valid tools requested; falling back to basic set")
        # Explicitly filter out intrusive tools on the safe-fallback path
        valid = [t for t in DEFAULT_BASIC_TOOLS
                 if t in TOOL_MAP and t not in _INTRUSIVE_TOOLS]
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
    """Invoke a module's run() respecting its calling convention."""
    tool_options = tool_options or {}
    run_fn: Callable = module.run

    if module_name in _OPTIONS_STYLE_MODULES:
        opts: Dict[str, Any] = {}
        defaults = _OPTIONS_STYLE_MODE_DEFAULTS.get(module_name, {}).get(mode, {})
        opts.update(defaults)
        opts.update(tool_options)
        opts.setdefault("mode", mode)
        return run_fn(target, opts)

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
    tool_timings:  Dict[str, float] = field(default_factory=dict)
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
            "tool_timings": dict(self.tool_timings),
        }


# =============================================================================
# ScanOrchestrator
# =============================================================================
class ScanOrchestrator:
    """
    Thread-safe manager for background scan jobs.

    Uses a bounded semaphore to cap concurrent work, propagates
    cancellation via threading.Event, enforces a global per-job timeout,
    streams a live terminal progress view, and writes each job's outcome
    into the history store.
    """

    def __init__(
        self,
        max_concurrent: int = MAX_CONCURRENT_SCANS,
        timeout:        int = SCAN_TIMEOUT_SECONDS,
        cleanup_after:  int = JOB_CLEANUP_AFTER_SECONDS,
        verbose:        bool = True,
    ):
        self._jobs:          Dict[str, ScanJob] = {}
        self._lock:          threading.Lock = threading.Lock()
        self._semaphore:     threading.BoundedSemaphore = \
            threading.BoundedSemaphore(max(1, int(max_concurrent)))
        self._timeout:       int = int(timeout)
        self._cleanup_after: int = int(cleanup_after)
        self._verbose:       bool = bool(verbose)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def list_tools(self) -> Dict[str, Dict[str, Any]]:
        """
        Return ``{tool_name: TOOL_INFO}`` for every discovered scanner.

        Each entry is extended with two orchestrator-supplied fields:
            "intrusive": bool   — True if the tool fires active probes
            "available": bool   — always True once registered
        """
        out: Dict[str, Dict[str, Any]] = {}
        for name, mod in TOOL_MAP.items():
            info = getattr(mod, "TOOL_INFO", None)
            if isinstance(info, dict):
                entry = dict(info)
            else:
                entry = {
                    "name": name,
                    "description": "",
                    "version": _extract_version(mod),
                }
            entry["intrusive"] = name in _INTRUSIVE_TOOLS
            entry["available"] = True
            out[name] = entry
        return out

    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Return ``TOOL_INFO`` for a single tool, or ``None`` if unknown."""
        mod = TOOL_MAP.get(tool_name)
        if mod is None:
            return None
        info = getattr(mod, "TOOL_INFO", None)
        if isinstance(info, dict):
            entry = dict(info)
        else:
            entry = {
                "name": tool_name,
                "description": "",
                "version": _extract_version(mod),
            }
        entry["intrusive"] = tool_name in _INTRUSIVE_TOOLS
        entry["available"] = True
        return entry

    def is_tool(self, tool_name: str) -> bool:
        return tool_name in TOOL_MAP

    def is_intrusive(self, tool_name: str) -> bool:
        return tool_name in _INTRUSIVE_TOOLS

    def active_job_count(self) -> int:
        with self._lock:
            return sum(
                1 for j in self._jobs.values()
                if j.status in ("pending", "running")
            )

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
        if not tools:
            if mode == "expert":
                # Expert mode: every discovered tool, including intrusive
                tools = list(DEFAULT_EXPERT_TOOLS or [])
            else:
                # Basic mode: passive set only
                tools = [t for t in DEFAULT_BASIC_TOOLS if t in TOOL_MAP]
        tools = _parse_tools(tools)
        if not tools:
            raise RuntimeError("No usable scan tools available for this mode")

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

        logger.info(
            "Scan queued | job=%s target=%s mode=%s tools=%d",
            job_id[:8], target, mode, len(tools),
        )
        return job_id

    def get_progress(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
        return job.to_dict() if job else None

    def cancel_scan(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.status in ("pending", "running"):
                job.cancel_event.set()
                logger.info("Cancel signal sent to job %s", job_id[:8])
                return True
        return False

    def cancel_all(self) -> None:
        with self._lock:
            for job in self._jobs.values():
                if job.status in ("pending", "running"):
                    job.cancel_event.set()
        logger.info("Cancel signal sent to all active jobs")

    def list_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            jobs = sorted(self._jobs.values(),
                          key=lambda j: j.created_at, reverse=True)
        return [j.to_dict() for j in jobs[: max(1, int(limit))]]

    # ------------------------------------------------------------------
    # Internal execution
    # ------------------------------------------------------------------
    def _execute(self, job: ScanJob, history_store) -> None:
        start_time  = time.time()
        total_tools = max(1, len(job.tools))
        completed   = 0

        tool_meta = {
            name: (getattr(mod, "TOOL_INFO", None) or {})
            for name, mod in TOOL_MAP.items()
        }

        reporter = ScanReporter(
            job.job_id, job.target, job.mode, job.tools,
            tool_meta=tool_meta,
            enabled=self._verbose,
        )
        reporter.header()

        try:
            job.status  = "running"
            job.results = {}

            for idx, tool_name in enumerate(job.tools):
                if job.cancel_event.is_set():
                    job.status = "cancelled"
                    job.error  = "Cancelled by user"
                    break

                if time.time() - start_time > self._timeout:
                    job.status = "timeout"
                    job.error  = f"Scan exceeded {self._timeout}s limit"
                    break

                job.current_tool = tool_name
                job.percent      = int((idx / total_tools) * 100)

                reporter.tool_start(tool_name, idx + 1)
                t0 = time.time()

                tool_module = TOOL_MAP.get(tool_name)
                if tool_module is None:
                    job.results[tool_name] = {
                        "tool":   tool_name,
                        "target": job.target,
                        "data":   {},
                        "error":  "Tool disappeared from registry",
                    }
                    reporter.tool_finish(
                        tool_name, idx + 1, time.time() - t0,
                        ok=False, error="Tool disappeared from registry",
                    )
                    continue

                try:
                    result = _call_tool(
                        tool_name,
                        tool_module,
                        job.target,
                        job.mode,
                        job.tool_options,
                    )
                    ok = True
                    err_msg: Optional[str] = None
                    if isinstance(result, dict) and result.get("error"):
                        err_msg = str(result["error"])
                        ok = False
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
                    ok = False
                    err_msg = str(exc)

                elapsed = time.time() - t0
                job.results[tool_name] = result
                job.tool_timings[tool_name] = round(elapsed, 3)
                reporter.tool_finish(
                    tool_name, idx + 1, elapsed,
                    ok=ok, error=err_msg,
                )
                completed += 1

            if job.status == "running":
                job.status       = "completed"
                job.percent      = 100
                job.current_tool = None

        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error in job %s", job.job_id[:8])
            job.status = "error"
            job.error  = f"Unexpected error: {exc}"

        finally:
            elapsed = time.time() - start_time
            try:
                reporter.summary(
                    status=job.status,
                    elapsed=elapsed,
                    completed=completed,
                    error=job.error,
                )
            finally:
                reporter.close()

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
                        job.job_id[:8], exc,
                    )

            logger.info(
                "Scan finished | job=%s status=%s %d/%d elapsed=%.2fs",
                job.job_id[:8], job.status, completed, total_tools, elapsed,
            )

            self._cleanup_old_jobs()

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------
    def _cleanup_old_jobs(self) -> None:
        now = time.time()
        with self._lock:
            stale = [
                jid
                for jid, job in self._jobs.items()
                if job.finished_at and (now - job.finished_at) > self._cleanup_after
            ]
            for jid in stale:
                del self._jobs[jid]
                logger.debug("Job %s removed from memory (cleanup)", jid[:8])

    def reload_tools(self) -> None:
        """Re-run module discovery and rebuild the tool registry."""
        global TOOL_MAP, DEFAULT_EXPERT_TOOLS
        TOOL_MAP = discover_tools()
        DEFAULT_EXPERT_TOOLS = sorted(TOOL_MAP.keys())
        logger.info("Tools reloaded — %d scanner(s) available", len(TOOL_MAP))
        _announce_registry(DEFAULT_EXPERT_TOOLS, _INTRUSIVE_TOOLS)


# =============================================================================
# Public helpers
# =============================================================================
def get_registry_snapshot() -> Dict[str, Any]:
    """Lightweight summary of the current registry."""
    all_tools = sorted(TOOL_MAP.keys())
    intrusive = sorted(t for t in all_tools if t in _INTRUSIVE_TOOLS)
    return {
        "version":          __version__,
        "tool_count":       len(TOOL_MAP),
        "tools":            all_tools,
        "basic_tools":      [t for t in DEFAULT_BASIC_TOOLS if t in TOOL_MAP],
        "expert_tools":     list(DEFAULT_EXPERT_TOOLS or []),
        "intrusive_tools":  intrusive,
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