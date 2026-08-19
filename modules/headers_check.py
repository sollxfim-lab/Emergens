"""
HTTP security header analysis – comprehensive & production‑ready.

Evaluates the same headers checked by securityheaders.com, plus modern
fetch‑metadata and cross‑origin isolation headers.  Expert mode adds raw
response headers, cookie flags, and CSP parser output.
"""

import requests
from urllib.parse import urlparse

from modules._common import default_headers

TOOL_INFO = {
    "name": "HTTP Security Headers",
    "description": (
        "Checks for HSTS, CSP, X‑Frame‑Options, and 9 other security "
        "headers.  Missing headers are graded by severity and an overall "
        "score is computed.  Expert mode adds raw headers, cookie flags "
        "and CSP directive breakdown."
    ),
}

# ---------------------------------------------------------------------------
#  Header definitions – extended beyond the original set.
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    # --- standard OWASP set ---
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections (HSTS)",
        "severity": "critical",
        "weight": 5,
    },
    "Content-Security-Policy": {
        "description": "Restricts resource loading – strong anti‑XSS",
        "severity": "critical",
        "weight": 5,
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking",
        "severity": "hard",
        "weight": 3,
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME‑type sniffing",
        "severity": "normal",
        "weight": 2,
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent cross‑origin",
        "severity": "normal",
        "weight": 2,
    },
    "Permissions-Policy": {
        "description": "Controls browser features (camera, mic, etc.)",
        "severity": "normal",
        "weight": 2,
    },
    # --- modern additions ---
    "Cross-Origin-Resource-Policy": {
        "description": "Prevents cross‑origin resource inclusion",
        "severity": "hard",
        "weight": 3,
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Enables cross‑origin isolation for powerful APIs",
        "severity": "normal",
        "weight": 1,
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing contexts to prevent cross‑origin attacks",
        "severity": "hard",
        "weight": 2,
    },
    # --- fetch metadata (partial – full check requires browser, we flag presence) ---
    "Sec-Fetch-Site": {
        "description": "Fetch metadata – site context of the request",
        "severity": "normal",
        "weight": 1,
    },
    "Sec-Fetch-Mode": {
        "description": "Fetch metadata – request mode",
        "severity": "normal",
        "weight": 1,
    },
    "Sec-Fetch-Dest": {
        "description": "Fetch metadata – request destination",
        "severity": "normal",
        "weight": 1,
    },
}

_SEVERITY_RANK = {"critical": 4, "hard": 3, "normal": 2, "low": 1}


# ---------------------------------------------------------------------------
#  Cookie flag helper
# ---------------------------------------------------------------------------
def _analyse_cookies(resp: requests.Response) -> list:
    """Return a list of dicts describing each Set‑Cookie header."""
    cookies = []
    raw = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw, "headers") else []
    for item in raw:
        parts = item.split(";")
        name_val = parts[0].strip()
        flags = {p.strip().lower() for p in parts[1:]}
        cookies.append(
            {
                "name_value": name_val,
                "secure": "secure" in flags,
                "httponly": "httponly" in flags,
                "samesite": next((f.split("=")[1].strip() for f in flags if f.startswith("samesite=")), None),
            }
        )
    return cookies


# ---------------------------------------------------------------------------
#  CSP parser (lightweight)
# ---------------------------------------------------------------------------
def _parse_csp(csp_value: str) -> dict:
    """Break a CSP header into directive -> list of sources."""
    directives = {}
    for token in csp_value.split(";"):
        token = token.strip()
        if not token:
            continue
        parts = token.split()
        directives[parts[0].lower()] = parts[1:] if len(parts) > 1 else []
    return directives


# ---------------------------------------------------------------------------
#  Main entry point
# ---------------------------------------------------------------------------

def run(target: str, mode: str = "basic") -> dict:
    """
    Audit the HTTP security headers of `target`.

    Args:
        target: URL or hostname (https:// is prepended if missing).
        mode:   'basic' – summary + missing headers.
                'expert' – raw headers, cookie flags, CSP analysis.

    Returns:
        Dict with keys 'tool', 'target', 'data', 'error'.
    """
    if not target.startswith("http"):
        urls = [f"https://{target}", f"http://{target}"]
    else:
        urls = [target]

    resp = None
    last_error = None

    # Try HTTPS first, then HTTP
    for url in urls:
        try:
            resp = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                headers=default_headers(),
                verify=True,  # Don't ignore cert errors for security headers audit
            )
            if resp.status_code < 500:  # any 2xx/3xx/4xx is fine
                break
        except requests.exceptions.SSLError:
            last_error = "SSL certificate verification failed"
            continue
        except requests.exceptions.ConnectionError:
            last_error = "Connection refused or network unreachable"
            continue
        except requests.exceptions.Timeout:
            last_error = "Request timed out"
            continue
        except Exception as e:
            last_error = str(e)
            continue

    if resp is None:
        return {
            "tool": "headers_check",
            "target": target,
            "data": {},
            "error": last_error or "Could not connect to target",
        }

    # ------------------------------------------------------------------
    # Analyse headers
    # ------------------------------------------------------------------
    present_headers: dict = {}
    missing_headers: list = []
    total_weight = sum(h["weight"] for h in SECURITY_HEADERS.values())
    score_weight = 0

    for header, meta in SECURITY_HEADERS.items():
        if header in resp.headers:
            present_headers[header] = resp.headers[header]
            score_weight += meta["weight"]
        else:
            missing_headers.append(
                {
                    "header": header,
                    "description": meta["description"],
                    "severity": meta["severity"],
                }
            )

    # Highest missing severity
    highest_severity = "none"
    if missing_headers:
        highest_severity = max(
            (m["severity"] for m in missing_headers),
            key=lambda s: _SEVERITY_RANK.get(s, 0),
        )

    # Overall score
    score_percent = round((score_weight / total_weight) * 100) if total_weight else 0

    # Build result data
    data = {
        "url": resp.url,
        "status_code": resp.status_code,
        "server": resp.headers.get("Server", "unknown"),
        "present_headers": present_headers,
        "missing_headers": missing_headers,
        "score_percent": score_percent,
        "highest_severity": highest_severity,
    }

    # Cookie flags are always useful
    data["cookies"] = _analyse_cookies(resp)

    # ------------------------------------------------------------------
    # Expert mode additions
    # ------------------------------------------------------------------
    if mode == "expert":
        data["all_response_headers"] = dict(resp.headers)
        # Parse CSP if present
        csp_raw = resp.headers.get("Content-Security-Policy")
        if csp_raw:
            data["csp_analysis"] = _parse_csp(csp_raw)
        # Include redirect history
        data["redirect_count"] = len(resp.history)
        data["final_url"] = resp.url
        # Parse Permissions-Policy
        pp_raw = resp.headers.get("Permissions-Policy")
        if pp_raw:
            data["permissions_policy_directives"] = pp_raw

    return {
        "tool": "headers_check",
        "target": target,
        "data": data,
        "error": None,
    }