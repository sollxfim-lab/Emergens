#!/usr/bin/env python3
"""
Oxysintx – Code Testing & Backup Module (v2.3.0)

Provides secure Python code execution, project file listing, hierarchical
folder mapping, and automatic backup functionality **strictly within
/home/container/oxysintx/**.

Integrates with the Oxysintx Flask application (app.py) and the CodeTest
web interface (templates/code_test.html).

Update v2.3.0:
    - Added `map_project_tree()` to generate a full nested directory map
      (folders + files) for any allowed subdirectory.
    - Added `get_project_tree()` as an alias for mapping.
    - Improved file listing with tree metadata (parent, depth, extension).
    - Added `TOOL_INFO` and `run()` for ScanOrchestrator integration.
    - Maintains full backup, code execution, and workspace info features.

Author: Yanxzyx
"""

import os
import sys
import io
import traceback
import json
import shutil
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# Constants – ALL OPERATIONS RESTRICTED TO THIS DIRECTORY
# ---------------------------------------------------------------------------
ALLOWED_ROOT: str = "/home/container/oxysintx"

# Backup directory (inside ALLOWED_ROOT)
BACKUP_DIR: str = os.path.join(ALLOWED_ROOT, "backup")

# Error log file
ERROR_LOG_FILE: str = os.path.join(BACKUP_DIR, "error.log")

# Maximum allowed output/error size (characters) to prevent resource exhaustion
MAX_OUTPUT_SIZE: int = 500_000

# Tool metadata for ScanOrchestrator
TOOL_INFO = {
    "name": "File & Code Viewer",
    "description": "List project files, map folder hierarchy, or retrieve code from within allowed root.",
    "version": "2.3.0",
    "author": "Yanxzyx",
}

# ---------------------------------------------------------------------------
# Directory & Logging Setup
# ---------------------------------------------------------------------------
def _ensure_directories() -> None:
    """Create the backup directory and error log file if they do not exist."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    if not os.path.exists(ERROR_LOG_FILE):
        with open(ERROR_LOG_FILE, "w", encoding="utf-8") as f:
            f.write(f"# Error log created at {datetime.now(timezone.utc).isoformat()}\n")

_ensure_directories()

# Configure a dedicated logger for testing operations
logger = logging.getLogger("oxysintx.testing")
logger.setLevel(logging.DEBUG)

# File handler – writes warnings and errors to error.log
fh = logging.FileHandler(ERROR_LOG_FILE, encoding="utf-8")
fh.setLevel(logging.WARNING)
formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
fh.setFormatter(formatter)
logger.addHandler(fh)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _safe_serialize(obj: Any) -> Any:
    """Convert non‑JSON‑serializable objects to strings for safe output."""
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return str(obj)


def _is_within_allowed(path: str) -> bool:
    """
    Resolve a relative path against ALLOWED_ROOT and verify it does not escape
    the allowed directory. Prevents directory traversal attacks.
    """
    abs_path = os.path.abspath(os.path.join(ALLOWED_ROOT, path))
    return os.path.commonpath([abs_path, ALLOWED_ROOT]) == ALLOWED_ROOT


def _resolve_scan_dir(root_path: Optional[str] = None) -> str:
    """
    Resolve a scan directory safely within ALLOWED_ROOT.

    Returns:
        Absolute path to scan.

    Raises:
        ValueError if path escapes allowed root or does not exist.
    """
    if root_path is None or root_path == "":
        scan_dir = ALLOWED_ROOT
    else:
        scan_dir = os.path.abspath(os.path.join(ALLOWED_ROOT, root_path))

    if os.path.commonpath([scan_dir, ALLOWED_ROOT]) != ALLOWED_ROOT:
        raise ValueError(f"Access denied: {root_path}")
    if not os.path.isdir(scan_dir):
        raise ValueError(f"Directory not found: {scan_dir}")
    return scan_dir


# ---------------------------------------------------------------------------
# Code Execution (Sandboxed)
# ---------------------------------------------------------------------------
def run_tests(code: str, test_cases: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Execute Python source code in a restricted namespace and capture stdout/stderr.

    Parameters
    ----------
    code : str
        The Python code to execute.
    test_cases : list of dict, optional
        Reserved for future structured testing; currently unused.

    Returns
    -------
    dict
        A dictionary containing:
        - passed (bool)       : True if the code ran without exceptions.
        - output (str)        : Captured stdout.
        - errors (str)        : Captured stderr and traceback (if any).
        - execution_time_ms (int) : Approximate execution duration.
        - backup_info (dict)  : Paths of the snapshot backups.
        - timestamp (str)     : ISO‑8601 UTC timestamp of the run.
    """
    if test_cases is None:
        test_cases = []

    start_time = datetime.now(timezone.utc)
    result: Dict[str, Any] = {
        "passed": False,
        "output": "",
        "errors": "",
        "execution_time_ms": 0,
        "backup_info": {},
        "timestamp": start_time.isoformat(),
    }

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()

    try:
        # Compile first to catch syntax errors early
        compiled = compile(code, "<code_test>", "exec")

        # Restricted builtins – extend carefully in production
        safe_globals = {
            "__builtins__": {
                "print": print,
                "len": len,
                "range": range,
                "int": int,
                "float": float,
                "str": str,
                "bool": bool,
                "list": list,
                "dict": dict,
                "tuple": tuple,
                "set": set,
                "isinstance": isinstance,
                "Exception": Exception,
                "ValueError": ValueError,
                "TypeError": TypeError,
                "KeyError": KeyError,
            },
            "__name__": "__main__",
        }
        safe_locals: Dict[str, Any] = {}

        exec(compiled, safe_globals, safe_locals)
        result["passed"] = True

    except Exception:
        result["passed"] = False
        exc_type, exc_value, exc_tb = sys.exc_info()
        tb_lines = traceback.format_exception(exc_type, exc_value, exc_tb)
        result["errors"] = "".join(tb_lines)
        logger.error("Code execution failed:\n%s", result["errors"])

    finally:
        result["output"] = sys.stdout.getvalue()[:MAX_OUTPUT_SIZE]
        stderr_text = sys.stderr.getvalue()
        if stderr_text:
            result["errors"] = (result["errors"] + "\n[stderr]\n" + stderr_text)[:MAX_OUTPUT_SIZE]
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    end_time = datetime.now(timezone.utc)
    result["execution_time_ms"] = int((end_time - start_time).total_seconds() * 1000)

    # Always create a snapshot backup for audit purposes
    try:
        backup_info = _backup_code_snapshot(code, result)
        result["backup_info"] = backup_info
    except Exception as backup_err:
        logger.warning("Backup snapshot failed: %s", backup_err)

    return _safe_serialize(result)


def _backup_code_snapshot(code: str, result: Dict[str, Any]) -> Dict[str, str]:
    """Save the executed code and a summary of the result to the backup folder."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    code_filename = f"code_snapshot_{timestamp}.py"
    result_filename = f"result_{timestamp}.json"

    code_path = os.path.join(BACKUP_DIR, code_filename)
    result_path = os.path.join(BACKUP_DIR, result_filename)

    with open(code_path, "w", encoding="utf-8") as f:
        f.write(code)

    summary = {
        "passed": result.get("passed"),
        "execution_time_ms": result.get("execution_time_ms"),
        "timestamp": result.get("timestamp"),
        "errors": (result.get("errors") or "")[:2000],
    }
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.info("Snapshot saved: %s, %s", code_path, result_path)
    return {
        "code_backup": os.path.relpath(code_path, ALLOWED_ROOT),
        "result_backup": os.path.relpath(result_path, ALLOWED_ROOT),
    }


# ---------------------------------------------------------------------------
# Real‑Filesystem Listing (restricted to ALLOWED_ROOT)
# ---------------------------------------------------------------------------
def list_project_files(
    root_path: Optional[str] = None,
    extensions: Optional[Tuple[str, ...]] = None,
) -> List[Dict[str, Any]]:
    """
    Recursively list all files and directories inside ALLOWED_ROOT (or a subdirectory).

    Parameters
    ----------
    root_path : str, optional
        Subdirectory relative to ALLOWED_ROOT. If None, the entire allowed root is scanned.
    extensions : tuple of str, optional
        Filter by file extension(s), e.g. ('.py', '.json'). Directories are not filtered.

    Returns
    -------
    list of dict
        Each item has:
        - name (str)         : File or folder name.
        - path (str)         : Relative path from ALLOWED_ROOT.
        - type (str)         : 'file' or 'directory'.
        - size (int)         : File size in bytes (0 for directories).
        - modified (str)     : ISO‑8601 UTC timestamp of last modification.
        - parent (str)       : Relative path of parent directory.
        - depth (int)        : Directory depth from ALLOWED_ROOT.
        - extension (str)    : File extension (lowercase) or empty for directories.
    """
    try:
        scan_dir = _resolve_scan_dir(root_path)
    except ValueError as e:
        logger.error("Invalid scan path: %s", e)
        return []

    file_list = []
    for dirpath, dirnames, filenames in os.walk(scan_dir):
        # Exclude hidden / system directories and __pycache__
        dirnames[:] = [
            d for d in dirnames if not d.startswith(".") and d != "__pycache__"
        ]

        # Add directories
        for d in dirnames:
            full_path = os.path.join(dirpath, d)
            rel_path = os.path.relpath(full_path, ALLOWED_ROOT)
            rel_parent = os.path.relpath(os.path.dirname(full_path), ALLOWED_ROOT)
            depth = rel_path.count(os.sep) + (1 if rel_path != "." else 0)
            file_list.append(
                {
                    "name": d,
                    "path": rel_path,
                    "type": "directory",
                    "size": 0,
                    "modified": datetime.fromtimestamp(
                        os.path.getmtime(full_path), tz=timezone.utc
                    ).isoformat(),
                    "parent": rel_parent if rel_parent != "." else "",
                    "depth": depth,
                    "extension": "",
                }
            )

        # Add files (skip hidden files)
        for f in filenames:
            if f.startswith("."):
                continue
            if extensions and not f.endswith(extensions):
                continue
            full_path = os.path.join(dirpath, f)
            rel_path = os.path.relpath(full_path, ALLOWED_ROOT)
            rel_parent = os.path.relpath(os.path.dirname(full_path), ALLOWED_ROOT)
            depth = rel_path.count(os.sep)
            try:
                stat = os.stat(full_path)
                file_list.append(
                    {
                        "name": f,
                        "path": rel_path,
                        "type": "file",
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                        "parent": rel_parent if rel_parent != "." else "",
                        "depth": depth,
                        "extension": os.path.splitext(f)[1].lower(),
                    }
                )
            except OSError as e:
                logger.warning("Cannot stat %s: %s", full_path, e)

    # Sort: directories first, then alphabetically by name
    file_list.sort(key=lambda x: (x["type"] != "directory", x["name"].lower()))
    return file_list


# ---------------------------------------------------------------------------
# Hierarchical Project Mapping (NEW in v2.3.0)
# ---------------------------------------------------------------------------
def map_project_tree(root_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate a full nested folder/file map for the allowed root or a subdirectory.

    Parameters
    ----------
    root_path : str, optional
        Subdirectory relative to ALLOWED_ROOT. If None, maps entire ALLOWED_ROOT.

    Returns
    -------
    dict
        A tree structure:
        {
            "name": ...,
            "path": ...,
            "type": "directory",
            "children": [
                { "name": ..., "path": ..., "type": "file", "size": ..., "extension": ... },
                { "name": ..., "path": ..., "type": "directory", "children": [...] }
            ],
            "total_files": int,
            "total_dirs": int
        }
    """
    try:
        scan_dir = _resolve_scan_dir(root_path)
    except ValueError as e:
        logger.error("Invalid mapping path: %s", e)
        return {
            "name": "",
            "path": "",
            "type": "directory",
            "children": [],
            "total_files": 0,
            "total_dirs": 0,
            "error": str(e),
        }

    def build_node(abs_path: str, rel_path: str) -> Dict[str, Any]:
        node = {
            "name": os.path.basename(abs_path),
            "path": rel_path,
            "type": "directory",
            "children": [],
            "total_files": 0,
            "total_dirs": 0,
        }
        try:
            entries = sorted(os.listdir(abs_path), key=str.lower)
        except OSError as e:
            logger.warning("Cannot list %s: %s", abs_path, e)
            return node

        for entry in entries:
            if entry.startswith(".") or entry == "__pycache__":
                continue
            entry_abs = os.path.join(abs_path, entry)
            entry_rel = os.path.relpath(entry_abs, ALLOWED_ROOT)
            if os.path.isdir(entry_abs):
                child = build_node(entry_abs, entry_rel)
                node["children"].append(child)
                node["total_dirs"] += 1 + child.get("total_dirs", 0)
                node["total_files"] += child.get("total_files", 0)
            else:
                try:
                    stat = os.stat(entry_abs)
                    node["children"].append({
                        "name": entry,
                        "path": entry_rel,
                        "type": "file",
                        "size": stat.st_size,
                        "extension": os.path.splitext(entry)[1].lower(),
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                    })
                    node["total_files"] += 1
                except OSError as e:
                    logger.warning("Cannot stat %s: %s", entry_abs, e)

        # Sort children: directories first, then files
        node["children"].sort(key=lambda x: (x["type"] != "directory", x["name"].lower()))
        return node

    if scan_dir == ALLOWED_ROOT:
        rel_root = ""
    else:
        rel_root = os.path.relpath(scan_dir, ALLOWED_ROOT)
    tree = build_node(scan_dir, rel_root)
    tree["allowed_root"] = ALLOWED_ROOT
    tree["generated_at"] = datetime.now(timezone.utc).isoformat()
    return tree


def get_project_tree(root_path: Optional[str] = None) -> Dict[str, Any]:
    """Alias for map_project_tree()."""
    return map_project_tree(root_path)


# ---------------------------------------------------------------------------
# File Read/Write Operations
# ---------------------------------------------------------------------------
def read_file(file_path: str) -> Dict[str, Any]:
    """
    Read the contents of a file inside ALLOWED_ROOT.

    Returns
    -------
    dict with 'success' (bool), 'content' (str), 'error' (str).
    """
    if not _is_within_allowed(file_path):
        msg = f"Access denied: {file_path}"
        logger.warning(msg)
        return {"success": False, "error": msg, "content": ""}

    abs_path = os.path.join(ALLOWED_ROOT, file_path)
    if not os.path.isfile(abs_path):
        msg = f"File not found: {abs_path}"
        logger.warning(msg)
        return {"success": False, "error": msg, "content": ""}

    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            content = f.read()
        return {"success": True, "content": content}
    except Exception as e:
        logger.exception("Failed to read %s", abs_path)
        return {"success": False, "error": str(e), "content": ""}


def write_file(file_path: str, content: str) -> Dict[str, Any]:
    """
    Create or overwrite a file inside ALLOWED_ROOT.
    Directories in the path are created automatically if missing.

    Returns
    -------
    dict with 'success' (bool) and 'error' (str).
    """
    if not _is_within_allowed(file_path):
        msg = f"Access denied: {file_path}"
        logger.warning(msg)
        return {"success": False, "error": msg}

    abs_path = os.path.join(ALLOWED_ROOT, file_path)
    try:
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("File written: %s", abs_path)
        return {"success": True}
    except Exception as e:
        logger.exception("Failed to write %s", abs_path)
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# ScanOrchestrator integration
# ---------------------------------------------------------------------------
def run(target: str = "", mode: str = "basic", **kwargs) -> Dict[str, Any]:
    """
    Entry point for ScanOrchestrator.

    Args:
        target: File path to read (if provided). If empty, returns project file list.
        mode: 'basic' or 'expert' (not used)
        **kwargs: Additional options (ignored)

    Returns:
        dict containing file list or file content.
    """
    if target:
        # Retrieve code of a specific file
        return read_file(target)
    else:
        # Return full project file listing (flat)
        files = list_project_files()
        return {
            "tool": "file_code_viewer",
            "target": "",
            "data": {"files": files},
        }


# ---------------------------------------------------------------------------
# Backup Operations (real files, within ALLOWED_ROOT only)
# ---------------------------------------------------------------------------
def backup_file(file_path: str) -> Dict[str, Any]:
    """
    Create a timestamped backup of a single file.

    Parameters
    ----------
    file_path : str
        Relative path to the file inside ALLOWED_ROOT.

    Returns
    -------
    dict
        - success (bool)
        - backup_path (str)   : Relative path of the backup file (from ALLOWED_ROOT).
        - error (str)         : Error message if failed.
    """
    if not _is_within_allowed(file_path):
        logger.error("Backup denied for path outside allowed root: %s", file_path)
        return {"success": False, "error": "Access denied. File is outside /home/container/oxysintx/."}

    abs_path = os.path.abspath(os.path.join(ALLOWED_ROOT, file_path))
    if not os.path.isfile(abs_path):
        msg = f"File not found: {abs_path}"
        logger.error(msg)
        return {"success": False, "error": msg}

    base = os.path.basename(abs_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_name = f"{os.path.splitext(base)[0]}_{timestamp}{os.path.splitext(base)[1]}"
    backup_path = os.path.join(BACKUP_DIR, backup_name)

    try:
        shutil.copy2(abs_path, backup_path)  # copy2 preserves metadata
        rel_backup = os.path.relpath(backup_path, ALLOWED_ROOT)
        logger.info("File backed up: %s -> %s", abs_path, rel_backup)
        return {"success": True, "backup_path": rel_backup}
    except Exception as e:
        msg = f"Backup failed for {abs_path}: {str(e)}"
        logger.exception(msg)
        return {"success": False, "error": msg}


def backup_all_source_files() -> Dict[str, Any]:
    """
    Backup all Python (.py) and JSON (.json) files inside ALLOWED_ROOT,
    excluding the backup directory itself.

    Returns
    -------
    dict
        - success (bool)
        - total_backed_up (int)
        - backup_list (list of str) : Relative paths of successful backups.
        - errors (list of str)      : Error messages for failed files.
    """
    files = list_project_files(extensions=(".py", ".json"))
    backed_up = []
    errors = []
    for f in files:
        if f["type"] != "file":
            continue
        # Skip files inside the backup directory itself
        if f["path"].startswith("backup"):
            continue
        res = backup_file(f["path"])
        if res["success"]:
            backed_up.append(res["backup_path"])
        else:
            errors.append(res["error"])

    total = len(backed_up)
    logger.info("Full backup completed: %d files backed up, %d errors", total, len(errors))
    return {
        "success": total > 0,
        "total_backed_up": total,
        "backup_list": backed_up,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Backup Housekeeping
# ---------------------------------------------------------------------------
def cleanup_old_backups(max_age_days: int = 30) -> int:
    """
    Delete backup files older than `max_age_days` from the backup directory.

    Parameters
    ----------
    max_age_days : int, optional
        Age threshold in days (default 30).

    Returns
    -------
    int
        Number of files deleted.
    """
    if not os.path.isdir(BACKUP_DIR):
        return 0

    cutoff_time = datetime.now().timestamp() - (max_age_days * 86400)
    deleted = 0
    for fname in os.listdir(BACKUP_DIR):
        fpath = os.path.join(BACKUP_DIR, fname)
        if os.path.isfile(fpath):
            try:
                if os.path.getmtime(fpath) < cutoff_time:
                    os.remove(fpath)
                    deleted += 1
                    logger.info("Old backup deleted: %s", fname)
            except OSError as e:
                logger.warning("Could not delete %s: %s", fname, e)
    return deleted


# ---------------------------------------------------------------------------
# Workspace Info (restricted to ALLOWED_ROOT)
# ---------------------------------------------------------------------------
def get_workspace_info() -> Dict[str, Any]:
    """
    Gather metadata about the workspace and backup directory.

    Returns
    -------
    dict
        - allowed_root (str)
        - backup_dir (str)
        - backup_dir_exists (bool)
        - error_log_size (int)
        - error_log_last_lines (list of str)
        - project_file_count (int)
        - project_dir_count (int)
        - last_error (str or None)
        - backup_total_size_bytes (int)
        - total_size_bytes (int)
    """
    info = {
        "allowed_root": ALLOWED_ROOT,
        "backup_dir": BACKUP_DIR,
        "backup_dir_exists": os.path.isdir(BACKUP_DIR),
        "error_log_size": 0,
        "error_log_last_lines": [],
        "project_file_count": 0,
        "project_dir_count": 0,
        "last_error": None,
        "backup_total_size_bytes": 0,
        "total_size_bytes": 0,
    }

    # Error log information
    if os.path.isfile(ERROR_LOG_FILE):
        info["error_log_size"] = os.path.getsize(ERROR_LOG_FILE)
        try:
            with open(ERROR_LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
                info["error_log_last_lines"] = [line.rstrip() for line in lines[-10:]]
                if lines:
                    info["last_error"] = lines[-1].strip()
        except Exception as e:
            logger.warning("Failed to read error log: %s", e)

    # Count files and directories inside ALLOWED_ROOT
    all_entries = list_project_files()
    info["project_file_count"] = sum(1 for f in all_entries if f["type"] == "file")
    info["project_dir_count"] = sum(1 for f in all_entries if f["type"] == "directory")

    # Total size of allowed root (excluding backup if needed, but we include)
    total_size = 0
    for dirpath, _, filenames in os.walk(ALLOWED_ROOT):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total_size += os.path.getsize(fp)
            except OSError:
                pass
    info["total_size_bytes"] = total_size

    # Backup directory size
    backup_size = 0
    if os.path.isdir(BACKUP_DIR):
        for dirpath, _, filenames in os.walk(BACKUP_DIR):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    backup_size += os.path.getsize(fp)
                except OSError:
                    pass
    info["backup_total_size_bytes"] = backup_size

    return info


# ---------------------------------------------------------------------------
# Self‑test (executed when script is run directly)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== Oxysintx Testing Module v2.3 (Restricted to /home/container/oxysintx/) ===\n")
    print(f"ALLOWED_ROOT : {ALLOWED_ROOT}")
    print(f"BACKUP_DIR   : {BACKUP_DIR}")

    # Sample code execution
    sample_code = """
print("Hello, CodeTest!")
x = 5 + 3
print(f"Result: {x}")
"""
    print("\n--- Running sample code ---")
    res = run_tests(sample_code)
    print(json.dumps(res, indent=2, default=str))

    # List first few project files
    print("\n--- Project File Listing (first 10) ---")
    files = list_project_files()
    for f in files[:10]:
        emoji = "D" if f["type"] == "directory" else "F"
        print(f"[{emoji}] {f['path']} ({f['size']} bytes, depth={f['depth']})")

    # Display hierarchical tree (first 3 levels for brevity)
    print("\n--- Hierarchical Project Tree (truncated to depth 2) ---")
    tree = map_project_tree()
    def print_tree(node, indent=0, max_depth=2):
        if indent > max_depth:
            return
        prefix = "  " * indent
        if node["type"] == "directory":
            print(f"{prefix}📁 {node['name']} (files={node['total_files']}, dirs={node['total_dirs']})")
            for child in node["children"]:
                print_tree(child, indent + 1, max_depth)
        else:
            print(f"{prefix}📄 {node['name']} ({node['size']} bytes)")
    print_tree(tree)

    # Backup the first .py file found (if any)
    py_files = [f for f in files if f["type"] == "file" and f["path"].endswith(".py")]
    if py_files:
        print("\n--- Backup first .py file ---")
        bres = backup_file(py_files[0]["path"])
        print(bres)

    # Workspace info
    print("\n--- Workspace Info ---")
    info = get_workspace_info()
    print(json.dumps(info, indent=2, default=str))