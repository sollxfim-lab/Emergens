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

Author : Yanxzyx
Version: 1.0.0
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ═══════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════
logger = logging.getLogger("oxysintx.port_scan.fixes")
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
    # Constants copied from port_scan module (or fallbacks)
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
    # Force basic mode to use the patched loader (monkey-patched on _ps)
    # by re-invoking the original run() — the loader swap already happened
    # at apply() time, so we just call through.
    result = _ps._original_run(target, mode=mode, **kwargs)
    if not isinstance(result, dict):
        return result

    data = result.get("data") or {}

    # ▼ v4.0.1 — honest port_range reporting
    if mode == "basic" and data.get("mode") == "basic":
        ports_list = data.get("open_ports_details") or []
        # We need the actual scanned list — reload metadata from loader
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

        # Warning when capped
        if lm.get("capped"):
            data["warning"] = (
                "Basic mode was capped at 1000 ports. One of your porttxt/*.txt "
                "files likely contains a large range. Verify porttxt contents "
                "or reduce port file sizes."
            )
            logger.warning("[fixes] %s", data["warning"])

        # Attach patch marker
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
        return False

    with _PATCH_LOCK:
        if _PATCHED and not force:
            return True

        try:
            # Preserve original run() for our wrapper
            if not hasattr(_ps, "_original_run"):
                _ps._original_run = _ps.run

            # Inject new constants
            _ps.MAX_BASIC_PORTS     = MAX_BASIC_PORTS
            _ps.MAX_BASIC_FILE_SIZE = MAX_BASIC_FILE_SIZE
            _ps.MAX_BASIC_LINES     = MAX_BASIC_LINES
            _PATCH_LOG.append(f"constants: MAX_BASIC_PORTS={MAX_BASIC_PORTS}")

            # Swap functions
            _ps._parse_port_file   = _parse_port_file_patched
            _ps.load_basic_ports   = load_basic_ports_patched
            _ps.run                = run_patched
            _PATCH_LOG.append("functions: _parse_port_file, load_basic_ports, run")

            # Bump visible version
            try:
                _ps.TOOL_INFO["version"] = "4.0.1"
                _ps.TOOL_INFO["description"] += " [patched by fixes.py]"
                _PATCH_LOG.append("TOOL_INFO: version → 4.0.1")
            except Exception:
                pass

            _PATCHED = True
            logger.info(
                "[fixes] port_scan patched successfully (%d changes)",
                len(_PATCH_LOG),
            )
            return True

        except Exception as e:
            logger.error("[fixes] patch failed: %s", e, exc_info=True)
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

        # Detect suspicious content
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
            "name":          fpath.name,
            "size_bytes":    size,
            "lines":         len(lines),
            "individual_ports": port_count,
            "issues":        issues,
            "will_be_skipped": bool(issues),
        })

    return report


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
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.check:
        import json
        print(json.dumps(check(), indent=2))
        return 0

    if args.diagnose:
        import json
        print(json.dumps(diagnose_ports(args.folder), indent=2))
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

    if result.get("error"):
        print(f"ERROR: {result['error']}")
        return 1

    d = result.get("data", {})
    print("=" * 60)
    print(f"  Port Scan v{result.get('version', '?')}  (patched)")
    print("=" * 60)
    print(f"  Target      : {result['target']}")
    print(f"  Resolved    : {d.get('resolved_ip', 'unknown')}")
    print(f"  Mode        : {d.get('mode')}")
    print(f"  Source      : {d.get('source')}")

    if d.get("port_range"):
        pmin, pmax = d["port_range"]
        if d.get("port_range_contiguous"):
            print(f"  Range       : {pmin}-{pmax} (contiguous)")
        else:
            print(f"  Range       : {pmin}..{pmax} "
                  f"({d.get('ports_checked', 0)} unique ports, sparse)")

    print(f"  Checked     : {d.get('ports_checked', 0)} ports")
    print(f"  Open        : {d.get('open_count', 0)} found")
    print(f"  Time        : {d.get('scan_time', 0):.2f}s")
    print(f"  Threads     : {d.get('threads_used', 0)}")

    if d.get("warning"):
        print(f"  ⚠ WARNING   : {d['warning']}")

    lm = d.get("load_metadata") or {}
    if lm:
        print(f"  Files       : {lm.get('files_read', 0)} read, "
              f"{len(lm.get('skipped_files', []))} skipped")
        if lm.get("capped"):
            print("  ⚠ Capped    : YES (1000-port limit)")
        for fc in lm.get("file_contributions", [])[:5]:
            print(f"    · {fc['file']:15s} → {fc['added']:4d} ports")
        if len(lm.get("file_contributions", [])) > 5:
            print(f"    · ... ({len(lm['file_contributions']) - 5} more files)")
        for sk in lm.get("skipped_files", [])[:3]:
            print(f"    ⚠ skipped {sk['file']}: {sk['reason']}")

    print("-" * 60)
    for p in d.get("open_ports_details", []):
        banner = f"  | {p['banner'][:40]}" if p.get("banner") else ""
        print(f"  {p['port']:5d}/tcp  {p['service']:14s}  "
              f"{p['response_time']:.3f}s{banner}")
    if not d.get("open_ports_details"):
        print("  No open ports found.")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(_main())