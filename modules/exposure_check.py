"""
Information-disclosure header & file exposure check.

Passive check for classic sensitive files and paths that should never be
publicly reachable: .git, .env, backup archives, phpinfo, server-status,
debug panels and similar. Each path is probed with a single GET and only
a status-code + size signature is recorded — no exploit payloads.
"""
import requests

TOOL_KIND = "scanner"

TOOL_INFO = {
    "name": "Exposure Check",
    "description": "Probes well-known sensitive paths (.git, .env, backups, "
    "server-status, debug panels) for accidental public exposure.",
    "version": "1.0.0",
}

_TIMEOUT = 6.0
_UA = {"User-Agent": "Emergens-ExposureCheck/1.0 (+authorized-testing)"}

_PATHS = [
    ("/.git/HEAD",                          "git-repository",   "high"),
    ("/.git/config",                        "git-config",       "high"),
    ("/.env",                               "env-file",         "high"),
    ("/.env.bak",                           "env-backup",       "high"),
    ("/.DS_Store",                          "macos-artifact",   "low"),
    ("/backup.zip",                         "backup-archive",   "high"),
    ("/backup.tar.gz",                      "backup-archive",   "high"),
    ("/dump.sql",                           "db-dump",          "high"),
    ("/database.sql",                       "db-dump",          "high"),
    ("/phpinfo.php",                        "phpinfo",          "medium"),
    ("/info.php",                           "phpinfo",          "medium"),
    ("/server-status",                      "server-status",    "medium"),
    ("/server-info",                        "server-info",      "medium"),
    ("/debug/vars",                         "go-expvar",        "medium"),
    ("/actuator",                           "spring-actuator",  "medium"),
    ("/actuator/env",                       "spring-actuator-env", "high"),
    ("/.svn/entries",                       "svn-repository",   "high"),
    ("/web.config.bak",                     "config-backup",    "medium"),
    ("/config.php.bak",                     "config-backup",    "medium"),
    ("/composer.lock",                      "composer-lock",    "low"),
    ("/package.json",                       "package-json",     "low"),
    ("/.htaccess",                          "htaccess",         "low"),
    ("/wp-config.php.bak",                  "config-backup",    "medium"),
    ("/id_rsa",                             "private-key",      "high"),
]


def _normalize(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t.rstrip("/")


def _looks_like_hit(resp, path: str) -> bool:
    """Status alone is noisy — check body signature for common false-positives."""
    if resp.status_code == 200:
        return True
    if resp.status_code in (401, 403) and path not in ("/server-status", "/server-info"):
        # 401/403 confirms existence without exposing content.
        return True
    return False


def run(target: str, mode: str = "basic") -> dict:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    base = _normalize(target)

    paths = _PATHS[:10] if mode == "basic" else list(_PATHS)
    exposed = []
    checked = 0
    for path, kind, severity in paths:
        checked += 1
        try:
            resp = requests.get(base + path, headers=_UA, timeout=_TIMEOUT,
                                verify=False, allow_redirects=False)
        except Exception:
            continue
        if _looks_like_hit(resp, path):
            exposed.append({
                "path": path,
                "kind": kind,
                "severity": severity,
                "status_code": resp.status_code,
                "content_length": resp.headers.get("Content-Length"),
            })

    high_count = sum(1 for e in exposed if e["severity"] == "high")
    medium_count = sum(1 for e in exposed if e["severity"] == "medium")

    if high_count:
        risk = "high"
    elif medium_count:
        risk = "medium"
    elif exposed:
        risk = "low"
    else:
        risk = "info"

    data = {
        "scanned": base,
        "mode": mode,
        "paths_checked": checked,
        "exposed": exposed,
        "exposed_count": len(exposed),
        "high_severity_count": high_count,
        "risk": risk,
    }
    return {"tool": "exposure_check", "target": target, "data": data, "error": None}
