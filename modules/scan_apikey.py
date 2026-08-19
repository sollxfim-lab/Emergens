#!/usr/bin/env python3
"""
Oxysintx - API Key Scanner Module (v1.0.0)

Scans files or URLs for exposed API keys, tokens, and secrets.
Uses a curated set of regex patterns to detect common API key formats.
Integrates with the Oxysintx ScanOrchestrator.

Author: Yanxzyx
"""

import os
import re
import logging
import requests
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("oxysintx.scan_apikey")

# ---------------------------------------------------------------------------
# Patterns – inspired by open‑source projects like TruffleHog & GitLeaks
# ---------------------------------------------------------------------------
# Each pattern is a tuple: (name, regex, confidence)
# confidence: high = almost certainly a real key, medium = possible, low = weak heuristic
API_KEY_PATTERNS: List[Dict[str, Any]] = [
    # Generic / common
    {"name": "Generic API Key",              "regex": r"(?i)(?:api[_-]?key|apikey|api)['\"]?\s*(?:=|:)\s*['\"]([a-zA-Z0-9_\-]{20,64})['\"]", "confidence": "medium"},
    {"name": "Bearer Token",                 "regex": r"['\"]?(?:bearer|token|auth)['\"]?\s*(?:=|:)\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]", "confidence": "low"},

    # Cloud providers
    {"name": "AWS Access Key ID",            "regex": r"AKIA[0-9A-Z]{16}", "confidence": "high"},
    {"name": "AWS Secret Key",               "regex": r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*(?:=|:)\s*['\"]([0-9a-zA-Z/+]{40})['\"]", "confidence": "high"},
    {"name": "Google API Key",               "regex": r"AIza[0-9A-Za-z\-_]{35}", "confidence": "high"},
    {"name": "Google OAuth Client ID",       "regex": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "confidence": "high"},
    {"name": "Azure Connection String",      "regex": r"(?i)connection[_-]?string['\"]?\s*(?:=|:)\s*['\"](DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net)['\"]", "confidence": "high"},

    # GitHub, GitLab, Bitbucket
    {"name": "GitHub Personal Access Token", "regex": r"ghp_[0-9a-zA-Z]{36}", "confidence": "high"},
    {"name": "GitHub OAuth Access Token",    "regex": r"gho_[0-9a-zA-Z]{36}", "confidence": "high"},
    {"name": "GitLab Personal Access Token", "regex": r"glpat-[0-9a-zA-Z\-_]{20}", "confidence": "high"},
    {"name": "Bitbucket App Password",       "regex": r"(?i)bitbucket[_-]?app[_-]?password['\"]?\s*(?:=|:)\s*['\"]([a-zA-Z0-9]{16,24})['\"]", "confidence": "medium"},

    # Stripe, PayPal, etc.
    {"name": "Stripe API Key",               "regex": r"(?:sk|rk)_live_[0-9a-zA-Z]{24}", "confidence": "high"},
    {"name": "Stripe Test Key",              "regex": r"(?:sk|rk)_test_[0-9a-zA-Z]{24}", "confidence": "high"},
    {"name": "PayPal Braintree Access Token","regex": r"access_token\$production\$[0-9a-f]{16}\$[0-9a-f]{32}", "confidence": "high"},

    # Social / others
    {"name": "Facebook Access Token",        "regex": r"EAACEdEose0cBA[0-9A-Za-z]+", "confidence": "high"},
    {"name": "Twitter API Key",              "regex": r"(?i)twitter[_-]?api[_-]?key['\"]?\s*(?:=|:)\s*['\"]([a-zA-Z0-9]{25,50})['\"]", "confidence": "medium"},
    {"name": "Twilio API Key",               "regex": r"SK[0-9a-fA-F]{32}", "confidence": "high"},
    {"name": "Slack Webhook URL",            "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "confidence": "high"},
    {"name": "Private SSH Key",              "regex": r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----", "confidence": "high"},

    # Cryptocurrency
    {"name": "Bitcoin Private Key (WIF)",    "regex": r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}", "confidence": "medium"},
    {"name": "Ethereum Private Key",         "regex": r"0x[a-fA-F0-9]{64}", "confidence": "low"},
]

# ---------------------------------------------------------------------------
# Helper: fetch content from a URL
# ---------------------------------------------------------------------------
def _fetch_url(url: str, timeout: int = 10) -> Optional[str]:
    """Download text content from a URL, returning None on failure."""
    try:
        headers = {
            "User-Agent": "Oxysintx-APIKeyScanner/1.0"
        }
        resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        # Only process text-based responses
        content_type = resp.headers.get("Content-Type", "")
        if "text" in content_type or "javascript" in content_type or "json" in content_type:
            return resp.text
        else:
            logger.warning("Skipping non-text content at %s (Content-Type: %s)", url, content_type)
            return None
    except Exception as e:
        logger.error("Failed to fetch %s: %s", url, e)
        return None

# ---------------------------------------------------------------------------
# Core scanning function
# ---------------------------------------------------------------------------
def _scan_content(content: str, source: str, mode: str = "basic") -> List[Dict[str, Any]]:
    """
    Scan text content for API key patterns.
    Returns a list of matches with source, pattern name, matched string, confidence, and line.
    """
    findings = []
    lines = content.splitlines(keepends=True)

    for pattern_info in API_KEY_PATTERNS:
        # Expert mode uses all patterns; basic mode uses only high/medium confidence
        if mode == "basic" and pattern_info["confidence"] not in ("high", "medium"):
            continue

        regex = re.compile(pattern_info["regex"])
        for line_no, line in enumerate(lines, start=1):
            for match in regex.finditer(line):
                # The full matched string (could be the whole line or a group)
                # Use group(0) if no capture group; but many patterns have a capture group for the key itself
                # We'll present the whole match and, if a capture group exists, the captured value as well.
                matched_text = match.group(0).strip()
                # Extract the first capture group if present (the actual key)
                key_value = ""
                if match.lastindex and match.lastindex >= 1:
                    key_value = match.group(1).strip()

                findings.append({
                    "source": source,
                    "line": line_no,
                    "pattern_name": pattern_info["name"],
                    "confidence": pattern_info["confidence"],
                    "match": matched_text,
                    "extracted_key": key_value if key_value else matched_text,
                })

    return findings

# ---------------------------------------------------------------------------
# Public API: run(target, mode)
# ---------------------------------------------------------------------------
def run(target: str, mode: str = "basic") -> Dict[str, Any]:
    """
    Scan a target (local file path or remote URL) for API keys.

    Args:
        target: File path or HTTP(S) URL.
        mode: "basic" (high+medium confidence) or "expert" (all patterns).

    Returns:
        dict with keys:
            - findings (list of dict)
            - stats (dict with total, by_confidence, by_pattern)
            - scanned (str) – the target that was scanned
    """
    result = {
        "findings": [],
        "stats": {},
        "scanned": target,
    }

    if not target:
        return {"error": "No target provided"}

    content = None
    source_label = target

    # Determine if target is a URL or file
    if target.startswith(("http://", "https://")):
        content = _fetch_url(target)
        if content is None:
            return {"error": f"Could not fetch URL: {target}"}
    else:
        # Local file path
        if not os.path.isfile(target):
            return {"error": f"File not found: {target}"}
        try:
            with open(target, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            return {"error": f"Failed to read file: {e}"}

    # Perform scan
    findings = _scan_content(content, source_label, mode)
    result["findings"] = findings

    # Build statistics
    total = len(findings)
    by_confidence = {"high": 0, "medium": 0, "low": 0}
    by_pattern = {}
    for f in findings:
        conf = f["confidence"]
        if conf in by_confidence:
            by_confidence[conf] += 1
        else:
            by_confidence[conf] = 1
        pname = f["pattern_name"]
        by_pattern[pname] = by_pattern.get(pname, 0) + 1

    result["stats"] = {
        "total": total,
        "by_confidence": by_confidence,
        "by_pattern": by_pattern,
    }

    logger.info("API key scan on '%s' completed: %d findings", target, total)
    return result

# ---------------------------------------------------------------------------
# Self‑test (when run directly)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    # Sample test with a dummy string containing a fake key
    test_content = """
    api_key = "AKIA1234567890ABCDEF"
    github_token = ghp_1234567890abcdef1234567890abcdef12345678
    """
    # Save to a temporary file
    test_file = "/tmp/test_apikey.txt"
    with open(test_file, "w") as f:
        f.write(test_content)
    print("=== Testing scan_apikey.py ===")
    result = run(test_file, mode="basic")
    print(json.dumps(result, indent=2))
    os.remove(test_file)