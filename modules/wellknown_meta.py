"""
Security TXT & well-known metadata discovery.

Reads the standardized /.well-known/security.txt (RFC 9116) plus other
informative well-known files that are passive, public data:
  • security.txt      — responsible-disclosure contacts
  • robots.txt        — crawl directives (often reveals hidden paths)
  • humans.txt        — team credits
  • ai.txt            — AI-crawler policy
  • .well-known/assetlinks.json / apple-app-site-association — mobile app links
"""
import re

import requests

TOOL_KIND = "scanner"

TOOL_INFO = {
    "name": "Security TXT & Metadata",
    "description": "Reads RFC 9116 security.txt, robots.txt and other public "
    "well-known files for disclosure contacts and crawl hints.",
    "version": "1.0.0",
}

_TIMEOUT = 8.0
_UA = {"User-Agent": "Emergens-Metadata/1.0 (+authorized-testing)"}

_FILES: list = [
    ("security_txt", ["/.well-known/security.txt", "/security.txt"]),
    ("robots_txt", ["/robots.txt"]),
    ("humans_txt", ["/humans.txt"]),
    ("ai_txt", ["/ai.txt"]),
    ("assetlinks", ["/.well-known/assetlinks.json"]),
    ("apple_app_site", ["/.well-known/apple-app-site-association"]),
]

_TXT_FIELD_RE = re.compile(r"^([A-Za-z\-]+)\s*:\s*(.+)$", re.M)


def _normalize(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t.rstrip("/")


def _fetch(url: str):
    try:
        resp = requests.get(url, headers=_UA, timeout=_TIMEOUT, verify=False)
        if resp.status_code == 200 and resp.text and len(resp.text) < 200_000:
            return resp.text
    except Exception:
        pass
    return None


def _parse_security_txt(text: str) -> dict:
    fields = {}
    for m in _TXT_FIELD_RE.finditer(text):
        key = m.group(1).lower()
        fields.setdefault(key, []).append(m.group(2).strip())
    return fields


def _parse_robots(text: str) -> dict:
    disallowed = re.findall(r"(?im)^\s*Disallow\s*:\s*(\S+)", text)
    allowed = re.findall(r"(?im)^\s*Allow\s*:\s*(\S+)", text)
    sitemaps = re.findall(r"(?im)^\s*Sitemap\s*:\s*(\S+)", text)
    agents = re.findall(r"(?im)^\s*User-agent\s*:\s*(\S+)", text)
    return {
        "disallow_paths": disallowed[:60],
        "allow_paths": allowed[:30],
        "sitemaps": sitemaps[:10],
        "user_agents": sorted(set(agents))[:15],
        "disallow_count": len(disallowed),
    }


def run(target: str, mode: str = "basic") -> dict:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    base = _normalize(target)
    data: dict = {"scanned": base, "mode": mode, "files": {}}

    for name, paths in _FILES:
        if name in ("humans_txt", "ai_txt") and mode != "expert":
            continue
        for p in paths:
            text = _fetch(base + p)
            if text is None:
                continue
            entry = {"path": p, "size": len(text)}
            if name == "security_txt":
                entry["fields"] = _parse_security_txt(text)
                entry["contacts"] = entry["fields"].get("contact", [])
                entry["encryption"] = entry["fields"].get("encryption", [])
            elif name == "robots_txt":
                entry.update(_parse_robots(text))
            else:
                entry["excerpt"] = text[:1200]
            data["files"][name] = entry
            break  # first working path wins

    sec = data["files"].get("security_txt", {})
    data["has_security_txt"] = bool(sec)
    data["disclosure_contacts"] = sec.get("contacts", [])

    robots = data["files"].get("robots_txt")
    data["robots_interesting_paths"] = (
        [p for p in (robots or {}).get("disallow_paths", [])
         if any(k in p.lower() for k in ("admin", "private", "internal", "secret", "backup", "test", "dev", "api"))]
        if robots else []
    )

    data["risk"] = "info" if not data["robots_interesting_paths"] else "low"
    return {"tool": "wellknown_meta", "target": target, "data": data, "error": None}
