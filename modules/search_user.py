# modules/search_user.py
"""
Oxysintx Leak Data Search Tool v1.0.0

Searches leaked personal records stored as JSON files in the
`userdata/` directory. Each file should be a JSON object with at
least a `nama_penuh` field.

The module is automatically discovered by the ScanOrchestrator
and can be used via:
    - Dashboard "Leak Data" panel (via /api/leakdata/search)
    - Direct API call: POST /api/scan/search_user
    - Telegram bot /scan command

Public interface:
    run(target, mode='basic', **kwargs) -> dict
    TOOL_INFO dict

Author: Yanxzyx
"""

import os
import json
import glob
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("oxysintx.search_user")

# ---------------------------------------------------------------------------
# Path to the userdata directory (relative to project root)
# ---------------------------------------------------------------------------
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_USERDATA_DIR = os.path.join(_PROJECT_ROOT, "userdata")

# ---------------------------------------------------------------------------
# Tool metadata – displayed in the dashboard and API docs
# ---------------------------------------------------------------------------
TOOL_INFO = {
    "name": "Leak Data Search",
    "description": "Search leaked personal records by name from userdata folder.",
    "version": "1.0.0",
    "category": "Data",
    "author": "Yanxzyx",
}

# ---------------------------------------------------------------------------
# Helper: load all JSON files from userdata/
# ---------------------------------------------------------------------------
def _load_all_records() -> List[Dict[str, Any]]:
    """Load all valid JSON records from the userdata directory."""
    if not os.path.isdir(_USERDATA_DIR):
        logger.warning("Userdata directory not found: %s", _USERDATA_DIR)
        return []

    records = []
    # Find all .json files (case-insensitive)
    json_files = (
        glob.glob(os.path.join(_USERDATA_DIR, "*.json")) +
        glob.glob(os.path.join(_USERDATA_DIR, "*.JSON"))
    )

    for filepath in json_files:
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            # Accept both a single dict or a list of dicts
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        records.append(item)
            elif isinstance(data, dict):
                records.append(data)
        except (json.JSONDecodeError, IOError) as exc:
            logger.warning("Skipping corrupt file %s: %s", filepath, exc)
        except Exception as exc:
            logger.error("Unexpected error reading %s: %s", filepath, exc)

    logger.info("Loaded %d records from %d files in %s",
                len(records), len(json_files), _USERDATA_DIR)
    return records


# ---------------------------------------------------------------------------
# Main entry point – called by the orchestrator
# ---------------------------------------------------------------------------
def run(target: str, mode: str = "basic", **kwargs) -> Dict[str, Any]:
    """
    Search leaked personal data by name.

    Args:
        target:   search query (matched case-insensitively against
                  nama_penuh field)
        mode:     not used (kept for interface compatibility)
        **kwargs: additional options (ignored)

    Returns:
        {
            "tool": "search_user",
            "target": "<query>",
            "data": {
                "results": [ ... matched record objects ... ],
                "count": <number of matches>
            }
        }
    """
    query = target.strip().lower() if target else ""
    if not query:
        return {
            "tool": "search_user",
            "target": target,
            "data": {"error": "no_query", "results": [], "count": 0},
        }

    all_records = _load_all_records()
    matches = []

    for rec in all_records:
        # Search primarily by full name, but also check other name-like fields
        name = rec.get("nama_penuh", "").lower()
        # Additional fields could be searched if desired, for now just name
        if query in name:
            matches.append(rec)

    # Sort results by name for consistency
    matches.sort(key=lambda r: r.get("nama_penuh", ""))

    return {
        "tool": "search_user",
        "target": target,
        "data": {
            "results": matches,
            "count": len(matches),
        },
    }


# ---------------------------------------------------------------------------
# Standalone usage (for testing)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    q = sys.argv[1] if len(sys.argv) > 1 else "ali"
    result = run(q)
    print(json.dumps(result, indent=2, ensure_ascii=False))