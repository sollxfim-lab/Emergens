# modules/search_user.py
"""
Oxysintx Leak Data Search Tool v2.0.0

Searches leaked personal records stored as JSON files in the
`userdata/` directory.

Supports two JSON layouts:
  1. School structure:
     {
       "school": {...},
       "classes": [
         {
           "className": "1A",
           "teacher": "...",
           "students": [
             {"no": 1, "name": "...", "ic": "..."}
           ]
         }
       ]
     }
  2. Legacy flat records:
     [{"nama_penuh": "...", "ic": "..."}] or single dict.

Search target is matched case-insensitively against:
  - full name (nama_penuh / name)
  - IC number
  - class name
  - student number

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
    "description": "Search leaked personal records by name, IC, class, or student number from userdata folder.",
    "version": "2.0.0",
    "category": "Data",
    "author": "Yanxzyx",
}

# ---------------------------------------------------------------------------
# Helper: flatten school/classes structure into individual student records
# ---------------------------------------------------------------------------
def _flatten_school_record(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten a school record with classes into individual student records."""
    records = []
    school = data.get("school", {})
    school_name = school.get("name", "")
    school_alias = school.get("alias", "")
    address = school.get("address", "")
    year = school.get("year", "")

    for cls in data.get("classes", []):
        class_name = cls.get("className", "")
        teacher = cls.get("teacher", "")
        for student in cls.get("students", []):
            records.append({
                "nama_penuh": student.get("name", ""),
                "ic": student.get("ic", ""),
                "no": student.get("no", ""),
                "class_name": class_name,
                "teacher": teacher,
                "school_name": school_name,
                "school_alias": school_alias,
                "address": address,
                "year": year,
            })
    return records


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

            # Case 1: School structure with classes/students
            if isinstance(data, dict) and "classes" in data:
                records.extend(_flatten_school_record(data))
                continue

            # Case 2: List of records
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        # If item is a school-style dict, flatten it
                        if "classes" in item:
                            records.extend(_flatten_school_record(item))
                        else:
                            records.append(item)
                continue

            # Case 3: Single flat record
            if isinstance(data, dict):
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
    Search leaked personal data by name, IC, class, or student number.

    Args:
        target:   search query (matched case-insensitively)
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
        # Build a list of searchable string fields
        searchable_fields = [
            str(rec.get("nama_penuh", "")).lower(),
            str(rec.get("ic", "")).lower(),
            str(rec.get("no", "")).lower(),
            str(rec.get("class_name", "")).lower(),
            str(rec.get("school_name", "")).lower(),
        ]

        # Match if query appears in any searchable field
        if any(query in field for field in searchable_fields if field):
            matches.append(rec)

    # Sort results by name, then by student number
    matches.sort(key=lambda r: (
        str(r.get("nama_penuh", "")),
        str(r.get("no", "")).zfill(4)
    ))

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
