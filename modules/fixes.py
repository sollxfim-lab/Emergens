#!/usr/bin/env python3
"""
fixes.py — Runtime patch for modules/port_scan.py (v4.0.0 → v4.0.1)
====================================================================

PURPOSE
-------
Fixes the "basic mode reports 65535 ports" bug WITHOUT modifying
port_scan.py itself. Uses monkey-patching to override the broken
functions at import time.

THE BUG
-------
porttxt/*.txt files were allowed to contain huge ranges like '1-65535'.
The old loader only checked against MAX_TOTAL_PORTS (65535) — the
global expert-mode cap — so a single bad file could balloon the basic
scan from 1000 to 65535 ports, and the CLI would honestly report
"Range: 1-65535" which looked like a bug.

THE FIX
-------
1. HARD CAP basic mode at 1000 ports (MAX_BASIC_PORTS).
2. Reject any range token that would blow past the cap (with warning).
3. Reject/truncate port files that exceed a size/line budget.
4. Emit a clear warning when the cap is hit.
5. Report an honest port_range summary (contiguous vs sparse).

----------------------------------------------------------------------------
CHANGELOG — v1.1.0  (Opencode integration)
----------------------------------------------------------------------------
  ✔ RENAME  — Logger namespace `oxysintx.port_scan.fixes` →
              `opencode.port_scan.fixes` (matches the app-wide rebrand).
  ✔ NEW     — Blue Claude-Code-style terminal output for the patch
              application step: a small spinner while patches apply,
              then a single blue ✓ line with the change count and the
              version bump (v4.0.0 → v4.0.1).
  ✔ NEW     — `--diagnose` now renders a coloured table (files, size,
              lines, issues) instead of a raw JSON dump. Add `--json`
              for the machine-readable output the CI scripts expect.
  ✔ NEW     — CLI scan output uses the same blue box header + summary
              border as `ScanReporter` in scan_orchestrator.py, so
              both tools look like they belong to the same product.
  ✔ NEW     — Full respect for `NO_COLOR`, `FORCE_COLOR` and
              `OPENCODE_QUIET` env vars — identical semantics to
              app.py and scan_orchestrator.py.
  ✔ NEW     — `check()` includes `logger_namespace` and
              `colour_enabled` for support diagnostics.
  ✔ HARD    — `apply()` is fully silent when `OPENCODE_QUIET=1` is set,
              so importing fixes.py from a headless service never
              pollutes the log.
  ✔ PRESERVE — Every public symbol from v1.0.0 remains: `apply()`,
              `check()`, `diagnose_ports()`, `run_patched`,
              `load_basic_ports_patched`, `_parse_port_file_patched`,
              and all tunable constants.

USAGE
-----
    # Option A — import before port_scan (auto-patches on import)
    import modules.fixes            # ← applies patches
    from modules import port_scan   # ← now patched
    result = port_scan.run("192.168.1.1", "basic")

    # Option B — run this file as CLI (proxies to port_scan)
    python -m modules.fixes 192.168.1.1 --mode basic

    # Option C — one-liner from shell
    python -c "import modules.fixes, modules.port_scan as p; p.run('x','basic')"

    # Option D — verify patches are active
    python -m modules.fixes --check

    # Option E — inspect the porttxt/ folder for problematic files
    python -m modules.fixes --diagnose

    # Option F — same as D/E but machine-readable
    python -m modules.fixes --check --json

Author : Yanxzyx
Version: 1.1.0
"""

from __future__ import annotations

import argparse
import json as _json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ═══════════════════════════════════════════════════════════════════════════
# ANSI COLOUR — bright blue theme, identical to app.py / scan_orchestrator.py
# ═══════════════════════════════════════════════════════════════════════════
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
    """Detect whether stdout can render ANSI colours."""
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
    """Wrap `text` in an ANSI colour, or return it unchanged when colour is off."""
    if not _USE_COLOR:
        return text
    return f"{color}{text}{_Ansi.RESET}"


_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING — opencode namespace, isolated handler
# ═══════════════════════════════════════════════════════════════════════════
logger = logging.getLogger("opencode.port_scan.fixes")
logger.propagate = False
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# ═══════════════════════════════════════════════════════════════════════════
# TUNABLES  (override port_scan's defaults at runtime)
# ═══════════════════════════════════════════════════════════════════════════
MAX_BASIC_PORTS     = 1000              # basic mode HARD cap
MAX_BASIC_FILE_SIZE = 64 * 1024         # 64 KB per file — basic mode only
MAX_BASIC_LINES     = 500               # max lines parsed per file
WARN_THRESHOLD      = 0.9               # warn at 90% of cap

_PATCH_LOCK = threading.Lock()
_PATCHED    = False
_PATCH_LOG: List[str] = []


# ═══════════════════════════════════════════════════════════════════════════
# IMPORT GUARD
# ═══════════════════════════════════════════════════════════════════════════
try:
    from modules import port_scan as _ps
    _PS_AVAILABLE = True
except ImportError as _e:
    _ps = None
    _PS_AVAILABLE = False
    _PS_IMPORT_ERR = str(_e)


# ═══════════════════════════════════════════════════════════════════════════
# TERMINAL EMITTERS — blue theme, TTY-safe, OPENCODE_QUIET-aware
# ═══════════════════════════════════════════════════════════════════════════
def _emit_apply_success(changes: int, version_from: str, version_to: str) -> None:
    """Print the one-shot blue ✓ line after patches are applied."""
    if os.getenv("OPENCODE_QUIET"):
        return
    if not _USE_COLOR:
        sys.stdout.write(
            f"  ok  port_scan patched  ({changes} change"
            f"{'s' if changes != 1 else ''})  "
            f"v{version_from} -> v{version_to}\n"
        )
        sys.stdout.flush()
        return

    mark  = _c("✓", _Ansi.GREEN)
    label = _c(f"Patched port_scan", _Ansi.WHITE)
    cnt   = _c(f"{changes} change{'s' if changes != 1 else ''}", _Ansi.GRAY)
    arrow = _c("→", _Ansi.BLUE_HI)
    bump  = (
        f"{_c('v' + version_from, _Ansi.GRAY_DIM)} "
        f"{arrow} "
        f"{_c('v' + version_to, _Ansi.BLUE_HI)}"
    )
    sys.stdout.write(f"  {mark} {label}  ·  {cnt}  ·  {bump}\n")
    sys.stdout.flush()


def _emit_apply_failure(reason: str) -> None:
    """Print the blue ✗ line when patching fails."""
    if os.getenv("OPENCODE_QUIET"):
        return
    if not _USE_COLOR:
        sys.stdout.write(f"  !!  port_scan patch failed  ({reason})\n")
        sys.stdout.flush()
        return

    mark  = _c("✗", _Ansi.RED)
    label = _c("Patch failed", _Ansi.BOLD + _Ansi.RED)
    detail = _c(reason[:110], _Ansi.GRAY_DIM)
    sys.stdout.write(f"  {mark} {label}  {detail}\n")
    sys.stdout.flush()


def _run_with_spinner(label: str, fn):
    """
    Run `fn()` while showing a small blue spinner. Auto-degrades to a
    silent call in non-TTY / quiet mode. Returns fn's return value.
    """
    if not _USE_COLOR or os.getenv("OPENCODE_QUIET"):
        return fn()

    box: Dict[str, Any] = {"ok": False, "val": None, "err": None}

    def _worker():
        try:
            box["val"] = fn()
            box["ok"] = True
        except BaseException as exc:  # noqa: BLE001
            box["err"] = exc

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    i = 0
    while t.is_alive():
        frame = _SPINNER_FRAMES[i % len(_SPINNER_FRAMES)]
        sys.stdout.write(f"\r\033[K  {_c(frame, _Ansi.BLUE)} {_c(label, _Ansi.GRAY)}")
        sys.stdout.flush()
        i += 1
        time.sleep(0.06)
    t.join(timeout=0.5)
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()

    if box["ok"]:
        return box["val"]
    raise box["err"]  # type: ignore[misc]


# ═══════════════════════════════════════════════════════════════════════════
# PATCHED:  _parse_port_file
# ═══════════════════════════════════════════════════════════════════════════
def _parse_port_file_patched(
    fpath: Path,
    ports: Set[int],
    cap: List[bool],
    max_ports: int = 65535,
    max_lines: Optional[int] = None,
) -> int:
    """
    v4.0.1 — hardened port-file parser.

    Improvements over the original:
      • `max_ports` — per-call cap (basic mode passes 1000)
      • `max_lines` — abort after N lines
      • Ranges that exceed `max_ports` are skipped with a warning
      • Ranges larger than the available budget are truncated
    """
    count = 0
    lines_seen = 0

    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                lines_seen += 1
                if max_lines is not None and lines_seen > max_lines:
                    logger.warning(
                        "[fixes] %s exceeded %d lines — truncated",
                        fpath.name, max_lines,
                    )
                    break

                if len(ports) >= max_ports:
                    cap[0] = True
                    return count

                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                for token in line.replace(",", " ").split():
                    token = token.strip()
                    if not token:
                        continue

                    # Range notation
                    if "-" in token and not token.startswith("-"):
                        try:
                            s, e = token.split("-", 1)
                            si, ei = int(s.strip()), int(e.strip())
                            if si > ei:
                                si, ei = ei, si

                            if not (1 <= si <= 65535 and 1 <= ei <= 65535):
                                continue

                            range_size = ei - si + 1
                            # ▼ v4.0.1 — reject oversized ranges
                            if range_size > max_ports:
                                logger.warning(
                                    "[fixes] %s contains range %d-%d (%d ports) "
                                    "exceeding cap %d — skipped",
                                    fpath.name, si, ei, range_size, max_ports,
                                )
                                continue

                            avail = max_ports - len(ports)
                            if avail <= 0:
                                cap[0] = True
                                return count

                            rp = list(range(si, ei + 1))
                            if len(rp) > avail:
                                rp = rp[:avail]
                                cap[0] = True

                            ports.update(rp)
                            count += len(rp)
                            if cap[0]:
                                return count
                        except ValueError:
                            continue
                    else:
                        try:
                            p = int(token)
                            if 1 <= p <= 65535:
                                if len(ports) >= max_ports:
                                    cap[0] = True
                                    return count
                                ports.add(p)
                                count += 1
                        except ValueError:
                            continue
    except OSError as e:
        logger.debug("[fixes] cannot read %s: %s", fpath, e)

    return count


# ═══════════════════════════════════════════════════════════════════════════
# PATCHED:  load_basic_ports
# ═══════════════════════════════════════════════════════════════════════════
def load_basic_ports_patched(
    folder_path: Optional[str] = None
) -> Tuple[List[int], Dict[str, Any]]:
    """
    v4.0.1 — BASIC MODE loader with hard cap at 1000 ports.

    Reads port2.txt .. port1000.txt from the porttxt folder.
    Falls back to built-in 1-1000 if none are usable.
    """
    BASIC_FILE_START = getattr(_ps, "BASIC_FILE_START", 2)
    BASIC_FILE_END   = getattr(_ps, "BASIC_FILE_END", 1000)
    MIN_PORT         = getattr(_ps, "MIN_PORT", 1)
    MAX_PORT         = getattr(_ps, "MAX_PORT", 65535)
    BASIC_PORTS      = getattr(_ps, "BASIC_PORTS", list(range(1, 1001)))
    resolve          = _ps._resolve_porttxt_path

    base = resolve(folder_path)
    ports: Set[int] = set()
    files_read: List[str] = []
    file_contributions: List[Dict[str, Any]] = []
    errors: List[str] = []
    skipped: List[Dict[str, str]] = []
    cap = [False]

    if base.is_dir():
        for idx in range(BASIC_FILE_START, BASIC_FILE_END + 1):
            if len(ports) >= MAX_BASIC_PORTS:
                break

            fpath = base / f"port{idx}.txt"
            if not fpath.is_file():
                continue

            try:
                size = fpath.stat().st_size
            except OSError:
                continue

            if size == 0:
                skipped.append({"file": fpath.name, "reason": "empty file"})
                continue
            if size > MAX_BASIC_FILE_SIZE:
                skipped.append({
                    "file": fpath.name,
                    "reason": f"size {size} B exceeds {MAX_BASIC_FILE_SIZE} B",
                })
                continue

            added = _parse_port_file_patched(
                fpath, ports, cap,
                max_ports=MAX_BASIC_PORTS,
                max_lines=MAX_BASIC_LINES,
            )
            if added > 0:
                files_read.append(fpath.name)
                file_contributions.append({
                    "file":        fpath.name,
                    "added":       added,
                    "total_after": len(ports),
                })

    if ports:
        total = len(ports)
        pmin, pmax = min(ports), max(ports)

        if total >= int(MAX_BASIC_PORTS * WARN_THRESHOLD):
            logger.warning(
                "[fixes] basic mode: %d/%d ports loaded — near cap",
                total, MAX_BASIC_PORTS,
            )
        logger.info(
            "[fixes] basic mode: %d unique ports from %d file(s) "
            "(min=%d max=%d%s)",
            total, len(files_read), pmin, pmax,
            ", CAPPED" if cap[0] else "",
        )

        return sorted(ports), {
            "directory":          str(base),
            "files_read":         len(files_read),
            "file_names":         files_read,
            "file_contributions": file_contributions,
            "skipped_files":      skipped,
            "total_ports_loaded": total,
            "min_port":           pmin,
            "max_port":           pmax,
            "capped":             cap[0],
            "source":             "wordlist",
            "errors":             errors,
            "patched":            True,
            "patch_version":      "4.0.1",
        }

    # Fallback
    logger.info(
        "[fixes] no usable basic port files in %s — fallback to 1-1000 "
        "(%d file(s) skipped)",
        base, len(skipped),
    )
    return BASIC_PORTS.copy(), {
        "directory":          str(base),
        "files_read":         0,
        "file_names":         [],
        "file_contributions": [],
        "skipped_files":      skipped,
        "total_ports_loaded": len(BASIC_PORTS),
        "min_port":           1,
        "max_port":           1000,
        "capped":             False,
        "source":             "builtin_fallback",
        "errors":             errors,
        "patched":            True,
        "patch_version":      "4.0.1",
    }


# ═══════════════════════════════════════════════════════════════════════════
# PATCHED:  run
# ═══════════════════════════════════════════════════════════════════════════
def run_patched(target: str, mode: str = "basic", **kwargs) -> dict:
    """
    v4.0.1 — wrapper around port_scan.run() that:
      • uses patched load_basic_ports for basic mode
      • adds an honest port_range summary + contiguous flag
      • emits a warning when basic mode was capped at 1000
    """
    result = _ps._original_run(target, mode=mode, **kwargs)
    if not isinstance(result, dict):
        return result

    data = result.get("data") or {}

    if mode == "basic" and data.get("mode") == "basic":
        lm = data.get("load_metadata") or {}
        pmin = lm.get("min_port")
        pmax = lm.get("max_port")
        total = lm.get("total_ports_loaded") or data.get("ports_checked")

        if pmin is not None and pmax is not None:
            contiguous = (pmax - pmin + 1) == total
            data["port_range"] = [pmin, pmax]
            data["port_range_contiguous"] = contiguous
        else:
            data["port_range"] = [0, 0]
            data["port_range_contiguous"] = False

        if lm.get("capped"):
            data["warning"] = (
                "Basic mode was capped at 1000 ports. One of your porttxt/*.txt "
                "files likely contains a large range. Verify porttxt contents "
                "or reduce port file sizes."
            )
            logger.warning("[fixes] %s", data["warning"])

        data["_patched"] = True
        data["_patch_version"] = "4.0.1"

    result["data"] = data
    return result


# ═══════════════════════════════════════════════════════════════════════════
# APPLY
# ═══════════════════════════════════════════════════════════════════════════
def apply(force: bool = False) -> bool:
    """
    Apply all patches to the port_scan module. Idempotent — safe to call
    multiple times. Returns True if patches are active.
    """
    global _PATCHED, _PATCH_LOG

    if not _PS_AVAILABLE:
        logger.error(
            "[fixes] cannot apply — port_scan module not importable: %s",
            _PS_IMPORT_ERR,
        )
        _emit_apply_failure(f"port_scan not importable: {_PS_IMPORT_ERR}")
        return False

    with _PATCH_LOCK:
        if _PATCHED and not force:
            return True

        # Capture the pre-patch version for the nice version bump line.
        version_from = "?"
        try:
            version_from = str(getattr(_ps, "TOOL_INFO", {}).get("version", "?"))
        except Exception:
            pass

        def _do_patch() -> int:
            """Returns the number of individual changes applied."""
            changes = 0

            if not hasattr(_ps, "_original_run"):
                _ps._original_run = _ps.run
                changes += 1

            _ps.MAX_BASIC_PORTS     = MAX_BASIC_PORTS
            _ps.MAX_BASIC_FILE_SIZE = MAX_BASIC_FILE_SIZE
            _ps.MAX_BASIC_LINES     = MAX_BASIC_LINES
            _PATCH_LOG.append(f"constants: MAX_BASIC_PORTS={MAX_BASIC_PORTS}")
            changes += 1

            _ps._parse_port_file = _parse_port_file_patched
            changes += 1
            _PATCH_LOG.append("functions: _parse_port_file")

            _ps.load_basic_ports = load_basic_ports_patched
            changes += 1
            _PATCH_LOG.append("functions: load_basic_ports")

            _ps.run = run_patched
            changes += 1
            _PATCH_LOG.append("functions: run")

            try:
                _ps.TOOL_INFO["version"] = "4.0.1"
                desc = _ps.TOOL_INFO.get("description", "")
                if "[patched by fixes.py]" not in desc:
                    _ps.TOOL_INFO["description"] = desc + " [patched by fixes.py]"
                _PATCH_LOG.append("TOOL_INFO: version → 4.0.1")
                changes += 1
            except Exception:
                pass

            return changes

        try:
            # Run the patch inside a small blue spinner when stdout is a TTY.
            changes = _run_with_spinner(
                "Applying port_scan patches…",
                _do_patch,
            )

            _PATCHED = True
            _emit_apply_success(changes, version_from, "4.0.1")
            logger.info(
                "[fixes] port_scan patched successfully (%d changes)",
                changes,
            )
            return True

        except Exception as e:
            logger.error("[fixes] patch failed: %s", e, exc_info=True)
            _emit_apply_failure(str(e))
            return False


# ═══════════════════════════════════════════════════════════════════════════
# AUTO-APPLY ON IMPORT
# ═══════════════════════════════════════════════════════════════════════════
if _PS_AVAILABLE:
    apply()
else:
    logger.warning(
        "[fixes] port_scan module not found — nothing to patch. "
        "Error: %s", _PS_IMPORT_ERR,
    )


# ═══════════════════════════════════════════════════════════════════════════
# DIAGNOSTICS
# ═══════════════════════════════════════════════════════════════════════════
def check() -> Dict[str, Any]:
    """Return a status report on the patch state."""
    out: Dict[str, Any] = {
        "port_scan_available": _PS_AVAILABLE,
        "patched":             _PATCHED,
        "patch_log":           list(_PATCH_LOG),
        "max_basic_ports":     MAX_BASIC_PORTS,
        "max_basic_file_size": MAX_BASIC_FILE_SIZE,
        "max_basic_lines":     MAX_BASIC_LINES,
        "logger_namespace":    logger.name,
        "colour_enabled":      _USE_COLOR,
        "quiet_mode":          bool(os.getenv("OPENCODE_QUIET")),
    }
    if _PS_AVAILABLE:
        out["port_scan_version"] = getattr(_ps, "TOOL_INFO", {}).get("version", "?")
        out["loader_is_patched"] = (
            getattr(_ps, "load_basic_ports", None) is load_basic_ports_patched
        )
        out["parse_is_patched"] = (
            getattr(_ps, "_parse_port_file", None) is _parse_port_file_patched
        )
        out["run_is_patched"] = (
            getattr(_ps, "run", None) is run_patched
        )
    return out


def diagnose_ports(folder_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Inspect the porttxt/ folder and report which files are problematic.
    Useful for the operator to identify the bad file without guesswork.
    """
    if not _PS_AVAILABLE:
        return {"error": "port_scan module not available"}

    base = _ps._resolve_porttxt_path(folder_path)
    report: Dict[str, Any] = {
        "directory": str(base),
        "exists":    base.is_dir(),
        "files":     [],
        "warnings":  [],
    }

    if not base.is_dir():
        report["warnings"].append(f"Directory does not exist: {base}")
        return report

    for idx in range(2, 1001):
        fpath = base / f"port{idx}.txt"
        if not fpath.is_file():
            continue
        try:
            size = fpath.stat().st_size
        except OSError:
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue

        issues: List[str] = []
        if size > MAX_BASIC_FILE_SIZE:
            issues.append(f"file too large ({size} B > {MAX_BASIC_FILE_SIZE} B)")
        if len(lines) > MAX_BASIC_LINES:
            issues.append(f"too many lines ({len(lines)} > {MAX_BASIC_LINES})")

        port_count = 0
        has_big_range = False
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for tok in line.replace(",", " ").split():
                if "-" in tok and not tok.startswith("-"):
                    try:
                        s, e = tok.split("-", 1)
                        si, ei = int(s.strip()), int(e.strip())
                        if abs(ei - si) > 500:
                            has_big_range = True
                    except ValueError:
                        pass
                else:
                    try:
                        int(tok)
                        port_count += 1
                    except ValueError:
                        pass

        if has_big_range:
            issues.append("contains a very large range (e.g. 1-65535)")
            report["warnings"].append(
                f"{fpath.name} contains a huge range — will be skipped in "
                f"basic mode"
            )

        report["files"].append({
            "name":             fpath.name,
            "size_bytes":       size,
            "lines":            len(lines),
            "individual_ports": port_count,
            "issues":           issues,
            "will_be_skipped":  bool(issues),
        })

    return report


# ═══════════════════════════════════════════════════════════════════════════
# PRETTY PRINTERS — blue-theme output for CLI
# ═══════════════════════════════════════════════════════════════════════════
def _hr(width: int = 66) -> str:
    return _c("─" * width, _Ansi.BLUE_DEEP)


def _box_top(title: str, width: int = 66) -> str:
    t = f"─ {title} "
    return _c("╭" + t + "─" * max(0, width - len(t) - 2) + "╮", _Ansi.BLUE_DEEP)


def _box_mid(text: str, width: int = 66) -> str:
    body = ("  " + text)[: width - 2].ljust(width - 2)
    return _c("│" + body + "│", _Ansi.BLUE_DEEP)


def _box_bot(width: int = 66) -> str:
    return _c("╰" + "─" * (width - 2) + "╯", _Ansi.BLUE_DEEP)


def _print_check_human(state: Dict[str, Any]) -> None:
    """Human-friendly patch-status output (default for --check)."""
    width = 66
    ok = state.get("patched") and state.get("port_scan_available")

    print()
    print(_box_top("port_scan patch status", width))
    print(_box_mid(f"port_scan module   : "
                    f"{'available' if state.get('port_scan_available') else 'missing'}", width))
    print(_box_mid(f"patched            : "
                    f"{'yes' if state.get('patched') else 'no'}", width))
    print(_box_mid(f"loader  patched    : "
                    f"{state.get('loader_is_patched', False)}", width))
    print(_box_mid(f"parser  patched    : "
                    f"{state.get('parse_is_patched', False)}", width))
    print(_box_mid(f"run()   patched    : "
                    f"{state.get('run_is_patched', False)}", width))
    if state.get("port_scan_version"):
        print(_box_mid(f"port_scan version  : "
                        f"{state['port_scan_version']}", width))
    print(_box_mid(f"logger namespace   : "
                    f"{state.get('logger_namespace', '?')}", width))
    print(_box_mid(f"colour enabled     : "
                    f"{state.get('colour_enabled', False)}", width))
    print(_box_mid(f"quiet mode         : "
                    f"{state.get('quiet_mode', False)}", width))
    print(_box_mid(f"max basic ports    : "
                    f"{state.get('max_basic_ports', '?')}", width))
    print(_box_bot(width))

    if _USE_COLOR:
        mark = _c("✓", _Ansi.GREEN) if ok else _c("✗", _Ansi.RED)
        label = (
            _c("All patches active", _Ansi.BOLD + _Ansi.GREEN)
            if ok else
            _c("Patches NOT active", _Ansi.BOLD + _Ansi.RED)
        )
        print(f"  {mark} {label}\n")
    else:
        print(f"  {'OK' if ok else 'FAIL'}: "
              f"{'all patches active' if ok else 'patches NOT active'}\n")


def _print_diagnose_human(report: Dict[str, Any]) -> None:
    """Human-friendly diagnose output (default for --diagnose)."""
    if report.get("error"):
        print(f"  {_c('✗', _Ansi.RED)} {report['error']}")
        return

    width = 66
    print()
    print(_box_top("porttxt/ diagnostics", width))
    print(_box_mid(f"directory : {report.get('directory', '?')}", width))
    print(_box_mid(f"exists    : {report.get('exists', False)}", width))
    print(_box_mid(f"files     : {len(report.get('files', []))}", width))
    print(_box_bot(width))

    files = report.get("files", [])
    if not files:
        print(f"  {_c('(no port files found)', _Ansi.GRAY_DIM)}\n")
        return

    # Header row
    if _USE_COLOR:
        hdr = (
            f"  {_c('STATUS', _Ansi.GRAY_DIM):<10}"
            f" {_c('FILE', _Ansi.GRAY_DIM):<20}"
            f" {_c('SIZE', _Ansi.GRAY_DIM):>8}"
            f" {_c('LINES', _Ansi.GRAY_DIM):>7}"
            f" {_c('PORTS', _Ansi.GRAY_DIM):>7}"
            f"  {_c('NOTES', _Ansi.GRAY_DIM)}"
        )
    else:
        hdr = "  STATUS     FILE                    SIZE   LINES   PORTS  NOTES"
    print(hdr)
    print("  " + _c("─" * 64, _Ansi.BLUE_DEEP))

    for f in files:
        skipped = f.get("will_be_skipped")
        status = (
            _c("⚠ SKIP", _Ansi.YELLOW) if skipped
            else _c("✓ OK", _Ansi.GREEN)
        )
        name = f["name"] if len(f["name"]) <= 18 else f["name"][:15] + "…"
        notes = "; ".join(f.get("issues") or [])[:40]
        print(
            f"  {status:<10}"
            f" {name:<20}"
            f" {f['size_bytes']:>8}"
            f" {f['lines']:>7}"
            f" {f['individual_ports']:>7}"
            f"  {_c(notes, _Ansi.GRAY_DIM)}"
        )

    warnings = report.get("warnings", [])
    if warnings:
        print()
        for w in warnings:
            print(f"  {_c('⚠', _Ansi.YELLOW)} {_c(w, _Ansi.GRAY_DIM)}")
    print()


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Runtime patch + CLI proxy for modules/port_scan.py",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", nargs="?",
                        help="Passed through to port_scan.run()")
    parser.add_argument("--mode", choices=["basic", "expert"], default="basic")
    parser.add_argument("--check", action="store_true",
                        help="Show patch status and exit")
    parser.add_argument("--diagnose", action="store_true",
                        help="Inspect porttxt/ folder for problematic files")
    parser.add_argument("--folder", default=None,
                        help="Override porttxt folder path")
    parser.add_argument("--timeout", type=float, default=0.4)
    parser.add_argument("--workers", type=int, default=400)
    parser.add_argument("--banner", action="store_true")
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--rdns", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--json", action="store_true",
                        help="Emit raw JSON for --check / --diagnose / scan")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.check:
        state = check()
        if args.json:
            print(_json.dumps(state, indent=2))
        else:
            _print_check_human(state)
        return 0

    if args.diagnose:
        report = diagnose_ports(args.folder)
        if args.json:
            print(_json.dumps(report, indent=2))
        else:
            _print_diagnose_human(report)
        return 0

    if not args.target:
        parser.error("target required (or use --check / --diagnose)")

    if not _PS_AVAILABLE:
        logger.error("port_scan module not importable — cannot scan")
        return 1

    result = run_patched(
        args.target, mode=args.mode,
        timeout=args.timeout, max_workers=args.workers,
        folder_path=args.folder,
        banner=args.banner, tls=args.tls, rdns=args.rdns,
        verbose=args.verbose,
    )

    if args.json:
        print(_json.dumps(result, indent=2, default=str))
        return 0 if not result.get("error") else 1

    if result.get("error"):
        print(f"  {_c('✗', _Ansi.RED)} {result['error']}")
        return 1

    d = result.get("data", {})
    width = 66

    # ── Header ────────────────────────────────────────────────────────
    print()
    print(_box_top(f"port scan  ·  {result.get('target', '?')}", width))
    print(_box_mid(f"resolved    : {d.get('resolved_ip', 'unknown')}", width))
    print(_box_mid(f"mode        : {d.get('mode')}", width))
    print(_box_mid(f"source      : {d.get('source')}", width))

    if d.get("port_range"):
        pmin, pmax = d["port_range"]
        if d.get("port_range_contiguous"):
            range_str = f"{pmin}-{pmax} (contiguous)"
        else:
            range_str = (
                f"{pmin}..{pmax} "
                f"({d.get('ports_checked', 0)} unique, sparse)"
            )
        print(_box_mid(f"range       : {range_str}", width))

    print(_box_mid(f"checked     : {d.get('ports_checked', 0)} ports", width))

    open_count = d.get("open_count", 0)
    open_colored = (
        _c(str(open_count), _Ansi.GREEN if open_count else _Ansi.GRAY)
        if _USE_COLOR else str(open_count)
    )
    print(_box_mid(f"open        : {open_colored}", width))
    print(_box_mid(f"time        : {d.get('scan_time', 0):.2f}s", width))
    print(_box_mid(f"threads     : {d.get('threads_used', 0)}", width))
    print(_box_bot(width))

    # ── Warnings ──────────────────────────────────────────────────────
    if d.get("warning"):
        print(f"  {_c('⚠', _Ansi.YELLOW)} {_c(d['warning'], _Ansi.YELLOW)}")

    # ── Wordlist loading summary ──────────────────────────────────────
    lm = d.get("load_metadata") or {}
    if lm:
        files_read = lm.get("files_read", 0)
        skipped_n = len(lm.get("skipped_files", []))
        print(f"  {_c('wordlist', _Ansi.GRAY_DIM)}: "
              f"{files_read} file(s) read, {skipped_n} skipped")
        if lm.get("capped"):
            print(f"  {_c('⚠ capped at 1000 ports', _Ansi.YELLOW)}")
        for fc in lm.get("file_contributions", [])[:5]:
            print(f"      {_c('·', _Ansi.BLUE)} "
                  f"{fc['file']:15s} → {fc['added']:4d} ports")
        if len(lm.get("file_contributions", [])) > 5:
            more = len(lm["file_contributions"]) - 5
            print(f"      {_c(f'· ... {more} more file(s)', _Ansi.GRAY_DIM)}")
        for sk in lm.get("skipped_files", [])[:3]:
            print(f"      {_c('⚠', _Ansi.YELLOW)} "
                  f"skipped {sk['file']}: "
                  f"{_c(sk['reason'], _Ansi.GRAY_DIM)}")

    # ── Open-port table ───────────────────────────────────────────────
    print("  " + _hr(64))
    ports = d.get("open_ports_details", [])
    if ports:
        for p in ports:
            banner = f"  {_c(p['banner'][:40], _Ansi.GRAY_DIM)}" if p.get("banner") else ""
            port_str = _c(f"{p['port']:>5d}", _Ansi.GREEN) if _USE_COLOR else f"{p['port']:>5d}"
            svc_str  = _c(f"{p['service']:<14s}", _Ansi.WHITE) if _USE_COLOR else f"{p['service']:<14s}"
            print(f"  {port_str}/tcp  {svc_str}  "
                  f"{p['response_time']:.3f}s{banner}")
    else:
        print(f"  {_c('no open ports found.', _Ansi.GRAY_DIM)}")
    print("  " + _hr(64))
    print()

    return 0


if __name__ == "__main__":
    sys.exit(_main())