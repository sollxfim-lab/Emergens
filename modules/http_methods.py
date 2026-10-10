"""
HTTP methods & verb tampering auditor.

Sends OPTIONS (and, in expert mode, tests dangerous verbs individually)
to determine which HTTP methods the server accepts and whether
dangerous ones (TRACE, TRACK, PUT, DELETE, PATCH) are exposed.
"""
import requests

TOOL_KIND = "scanner"

TOOL_INFO = {
    "name": "HTTP Methods Audit",
    "description": "Enumerates allowed HTTP methods via OPTIONS and flags "
    "dangerous verbs (TRACE / TRACK / PUT / DELETE) when exposed.",
    "version": "1.0.0",
}

_DANGEROUS = {"TRACE", "TRACK", "PUT", "DELETE", "PATCH", "CONNECT"}
_SAFE = {"GET", "HEAD", "POST", "OPTIONS"}
_TIMEOUT = 8.0
_UA = {"User-Agent": "Emergens-HTTPMethods/1.0 (+authorized-testing)"}


def _normalize(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t.rstrip("/")


def run(target: str, mode: str = "basic") -> dict:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    url = _normalize(target)
    data: dict = {"scanned": url, "mode": mode}

    try:
        resp = requests.options(url, headers=_UA, timeout=_TIMEOUT, verify=False, allow_redirects=True)
    except Exception as e:
        return {"tool": "http_methods", "target": target, "data": data, "error": str(e)}

    allow = (resp.headers.get("Allow") or resp.headers.get("Public") or "").strip()
    allowed = {m.strip().upper() for m in allow.split(",") if m.strip()}

    # Fallback heuristic: when Allow is absent, infer from OPTIONS status.
    if not allowed:
        if resp.status_code == 405:
            allowed = {"GET", "HEAD", "POST"}
        else:
            allowed = {"GET", "HEAD", "POST", "OPTIONS"}
            if resp.status_code in (200, 204):
                allowed.add("OPTIONS")

    dangerous_exposed = sorted(allowed & _DANGEROUS)
    unusual = sorted(allowed - _SAFE - _DANGEROUS)

    verb_results = []
    if mode == "expert" and dangerous_exposed:
        for verb in dangerous_exposed:
            try:
                r = requests.request(verb, url, headers=_UA, timeout=_TIMEOUT, verify=False)
                verb_results.append({
                    "verb": verb,
                    "status_code": r.status_code,
                    "accepted": r.status_code not in (405, 501),
                    "server_header": r.headers.get("Server"),
                })
            except Exception as e:
                verb_results.append({"verb": verb, "error": str(e)})

    if any(v.get("accepted") for v in verb_results):
        risk = "high"
    elif dangerous_exposed:
        risk = "medium"
    elif unusual:
        risk = "low"
    else:
        risk = "info"

    data.update({
        "allow_header": allow or None,
        "allowed_methods": sorted(allowed),
        "dangerous_exposed": dangerous_exposed,
        "unusual_methods": unusual,
        "verb_results": verb_results,
        "risk": risk,
    })
    return {"tool": "http_methods", "target": target, "data": data, "error": None}
