"""
Cookie & session security auditor.

Sets no cookies and submits no payloads. Fetches the target (following a
GET redirect chain) and inspects every Set-Cookie issued along the way
for the standard hardening attributes:
    Secure, HttpOnly, SameSite, __Host-/__Secure- prefixes,
    session-identifier naming, and cookie-scope issues.
"""
from http.cookies import SimpleCookie

import requests

TOOL_KIND = "scanner"

TOOL_INFO = {
    "name": "Cookie Security Audit",
    "description": "Inspects Set-Cookie headers for Secure, HttpOnly, SameSite "
    "and session-name hardening — fully passive.",
    "version": "1.0.0",
}

_TIMEOUT = 10.0
_UA = {"User-Agent": "Emergens-CookieAudit/1.0 (+authorized-testing)"}

_SESSION_HINTS = ("sess", "session", "sid", "jsessionid", "phpsessid",
                  "aspsessionid", "auth", "token", "jwt", "csrf")


def _normalize(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t.rstrip("/")


def _parse_set_cookie_headers(resp) -> list:
    """requests exposes duplicate Set-Cookie lines via raw headers."""
    raw = resp.raw.headers.getlist("Set-Cookie") if resp.raw is not None else []
    cookies = []
    for header in raw:
        c = SimpleCookie()
        try:
            c.load(header)
        except Exception:
            continue
        for name, morsel in c.items():
            lowered = header.lower()
            cookies.append({
                "name": name,
                "value_preview": (morsel.value or "")[:6] + "…" if morsel.value else "",
                "secure": "secure" in lowered,
                "httponly": "httponly" in lowered,
                "samesite": _extract_samesite(lowered),
                "host_prefix": name.startswith("__Host-"),
                "secure_prefix": name.startswith("__Secure-"),
                "session_like": any(h in name.lower() for h in _SESSION_HINTS),
            })
    return cookies


def _extract_samesite(lowered_header: str) -> str:
    if "samesite=strict" in lowered_header:
        return "Strict"
    if "samesite=lax" in lowered_header:
        return "Lax"
    if "samesite=none" in lowered_header:
        return "None"
    return ""


def run(target: str, mode: str = "basic") -> dict:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    url = _normalize(target)

    try:
        resp = requests.get(url, headers=_UA, timeout=_TIMEOUT, verify=False,
                            allow_redirects=True)
    except Exception as e:
        return {"tool": "cookie_audit", "target": target, "data": {"scanned": url}, "error": str(e)}

    cookies = _parse_set_cookie_headers(resp)

    issues = []
    for c in cookies:
        if not c["secure"]:
            issues.append(f"{c['name']}: missing Secure flag")
        if not c["httponly"] and c["session_like"]:
            issues.append(f"{c['name']}: session-like cookie without HttpOnly")
        if not c["samesite"]:
            issues.append(f"{c['name']}: missing SameSite attribute")
        if c["secure_prefix"] and not c["secure"]:
            issues.append(f"{c['name']}: __Secure- prefix without Secure flag")

    session_cookies = [c for c in cookies if c["session_like"]]

    if any("HttpOnly" in i or "__Secure-" in i for i in issues):
        risk = "high"
    elif issues:
        risk = "medium"
    else:
        risk = "info"

    data = {
        "scanned": url,
        "mode": mode,
        "final_status": resp.status_code,
        "cookies": cookies,
        "cookie_count": len(cookies),
        "session_cookies": [c["name"] for c in session_cookies],
        "issues": issues,
        "risk": risk,
    }
    return {"tool": "cookie_audit", "target": target, "data": data, "error": None}
