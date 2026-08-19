# modules/scan_school.py
"""
Oxysintx School Search Tool v1.0.0

Searches Malaysian school records from a local JSON database.
Place the dataset at:  listschool/school.json

The module is automatically discovered by the ScanOrchestrator
and can be used via:
    - Dashboard "Sekolah Search" panel
    - Direct API call: POST /api/scan/school_search
    - Telegram bot /scan command (if integrated)

Public interface:
    run(target, mode='basic', **kwargs) -> dict
    TOOL_INFO dict

Author: Yanxzyx
"""

import os
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("oxysintx.scan_school")

# ---------------------------------------------------------------------------
# Path to the JSON data file (relative to project root)
# ---------------------------------------------------------------------------
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_PATH = os.path.join(_PROJECT_ROOT, "listschool", "school.json")

# ---------------------------------------------------------------------------
# Tool metadata – displayed in the dashboard and API docs
# ---------------------------------------------------------------------------
TOOL_INFO = {
    "name": "School Search",
    "description": "Search Malaysian school information by name or school code.",
    "version": "1.0.0",
    "category": "Data",
    "author": "Yanxzyx",
}

# ---------------------------------------------------------------------------
# Cached data (loaded once on first use)
# ---------------------------------------------------------------------------
_school_cache: Optional[List[Dict[str, Any]]] = None
_cache_lock = __import__("threading").Lock()  # lightweight import for lock


def _load_schools() -> List[Dict[str, Any]]:
    """Load the school database from JSON, caching it in memory."""
    global _school_cache
    if _school_cache is not None:
        return _school_cache

    with _cache_lock:
        if _school_cache is not None:  # double-check inside lock
            return _school_cache

        if not os.path.exists(_DATA_PATH):
            logger.warning("School data file not found: %s", _DATA_PATH)
            _school_cache = []
            return _school_cache

        try:
            with open(_DATA_PATH, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, list):
                logger.error("Invalid school.json structure – expected a list")
                _school_cache = []
            else:
                _school_cache = data
            logger.info("Loaded %d school records from %s", len(_school_cache), _DATA_PATH)
        except (json.JSONDecodeError, IOError) as exc:
            logger.error("Failed to parse school.json: %s", exc)
            _school_cache = []

    return _school_cache


# ---------------------------------------------------------------------------
# Main entry point – called by the orchestrator
# ---------------------------------------------------------------------------
def run(target: str, mode: str = "basic", **kwargs) -> Dict[str, Any]:
    """
    Search schools by name or school code.

    Args:
        target:   search query (partial name or full school code)
        mode:     not used (kept for interface compatibility)
        **kwargs: additional options (ignored)

    Returns:
        {
            "tool": "school_search",
            "target": "<query>",
            "data": {
                "results": [ ... matched school objects ... ],
                "count": <number of matches>,
                "total_records": <total schools in database>
            }
        }
    """
    query = target.strip().lower() if target else ""
    if not query:
        return {
            "tool": "school_search",
            "target": target,
            "data": {"error": "no_query", "results": [], "count": 0, "total_records": 0},
        }

    schools = _load_schools()
    matches = []

    for school in schools:
        name = school.get("name", "").lower()
        code = school.get("schoolcode", "").lower()
        if query in name or query == code:
            matches.append(school)

    # Sort results by name for consistency
    matches.sort(key=lambda s: s.get("name", ""))

    return {
        "tool": "school_search",
        "target": target,
        "data": {
            "results": matches,
            "count": len(matches),
            "total_records": len(schools),
        },
    }


# ---------------------------------------------------------------------------
# Standalone usage (for testing)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    q = sys.argv[1] if len(sys.argv) > 1 else "kebangsaan"
    result = run(q)
    print(json.dumps(result, indent=2, ensure_ascii=False))