"""
CORS misconfiguration scanner.

Passive analysis of the target's Cross-Origin Resource Sharing
configuration. Sends Origin probe headers and reads back
Access-Control-Allow-* headers — no exploit payloads involved.

Checks for the classic misconfigurations:
  • Origin reflected verbatim with credentials allowed
  • Wildcard origin (*) combined with credentials
  • Null origin allowed
  • Overly permissive subdomain matching
"""
import requests

TOOL_KIND = "scanner"

TOOL_INFO = {
    "name": "CORS Misconfiguration",
    "description": "Audits Access-Control-Allow-Origin behaviour for reflected, "
    "wildcard-with-credentials and null-origin misconfigurations.",
    "version": "1.0.0",
}

_PROBE_ORIGINS = [
    "https://emergens-probe.example",
    "null",
    "https://emergens-probe.target.example",
]

_UA = {"User-Agent": "Emergens-CORS-Scanner/1.0 (+authorized-testing)"}
_TIMEOUT = 8.0


def _normalize(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t.rstrip("/")


def _probe(url: str, origin: str) -> dict:
    headers = dict(_UA)
    headers["Origin"] = origin
    try:
        resp = requests.get(url, headers=headers, timeout=_TIMEOUT, verify=False)
    except Exception as e:
        return {"origin": origin, "error": str(e)}

    acao = (resp.headers.get("Access-Control-Allow-Origin") or "").strip()
    acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").strip().lower()
    acam = (resp.headers.get("Access-Control-Allow-Methods") or "").strip()
    acah = (resp.headers.get("Access-Control-Allow-Headers") or "").strip()

    reflected = acao == origin and origin != "null"
    wildcard = acao == "*"
    null_allowed = acao == "null"
    creds = acac == "true"

    issues = []
    if reflected and creds:
        issues.append("origin-reflected-with-credentials (critical)")
    if reflected and not creds:
        issues.append("origin-reflected (medium)")
    if wildcard and creds:
        issues.append("wildcard-with-credentials (invalid/high)")
    if null_allowed:
        issues.append("null-origin-allowed (medium)")
    if wildcard:
        issues.append("wildcard-origin (low)")

    return {
        "origin": origin,
        "status_code": resp.status_code,
        "acao": acao,
        "allow_credentials": acac or None,
        "allow_methods": acam or None,
        "allow_headers": acah or None,
        "reflected": reflected,
        "issues": issues,
    }


def run(target: str, mode: str = "basic") -> dict:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    url = _normalize(target)

    probes = [_PROBE_ORIGINS[0]] if mode == "basic" else list(_PROBE_ORIGINS)
    results = []
    for origin in probes:
        r = _probe(url, origin)
        if "error" not in r:
            results.append(r)

    all_issues = [i for r in results for i in r.get("issues", [])]
    if any("critical" in i for i in all_issues):
        risk = "high"
    elif all_issues:
        risk = "medium"
    else:
        risk = "info"

    data = {
        "scanned": url,
        "mode": mode,
        "probes": results,
        "issues": all_issues,
        "risk": risk,
        "misconfigured": bool(all_issues),
    }
    return {"tool": "cors_check", "target": target, "data": data, "error": None}
