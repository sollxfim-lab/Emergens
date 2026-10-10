"""
Exposed JavaScript files & client-side secrets.

Fetches the target homepage, discovers referenced .js assets, and scans
each file with high-signal regular expressions for accidentally-shipped
secrets: API keys, tokens, private endpoints, source-map references and
debug flags. Read-only — no payloads are submitted anywhere.
"""
import re
from urllib.parse import urljoin, urlparse

import requests

TOOL_KIND = "scanner"

TOOL_INFO = {
    "name": "JS Secrets & Exposure",
    "description": "Discovers JavaScript assets and scans them for leaked API "
    "keys, tokens, source maps and internal endpoints.",
    "version": "1.0.0",
}

_TIMEOUT = 10.0
_UA = {"User-Agent": "Emergens-JSExposure/1.0 (+authorized-testing)"}
_MAX_FILES = 12          # basic mode cap
_MAX_FILES_EXPERT = 30   # expert mode cap
_MAX_BYTES = 512 * 1024  # per-file scan limit

_JS_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)

# (label, regex, severity)
_PATTERNS = [
    ("AWS Access Key",      re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    ("Google API Key",      re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "high"),
    ("Firebase API Key",    re.compile(r"AAAA[A-Za-z0-9_%:\-]{20,}"), "medium"),
    ("Stripe Key (live)",   re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "high"),
    ("Stripe Key (test)",   re.compile(r"pk_test_[0-9a-zA-Z]{24,}"), "low"),
    ("Slack Token",         re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"), "high"),
    ("Telegram Bot Token",  re.compile(r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}"), "high"),
    ("JWT",                 re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), "medium"),
    ("Private Key Block",   re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "high"),
    ("Generic Secret Var",  re.compile(r"""(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)["']?\s*[:=]\s*["'][^"'\s]{8,}["']""", re.I), "low"),
    ("Source Map Ref",      re.compile(r"//[#@]\s*sourceMappingURL=\S+\.map"), "medium"),
    ("Sentry DSN",          re.compile(r"https://[0-9a-f]{32}@[0-9a-z\-]+\.sentry\.io/[0-9]+", re.I), "medium"),
    ("Internal Endpoint",   re.compile(r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?[^\s\"']*"), "medium"),
    ("Debug Flag",          re.compile(r"\b(?:debug|DEBUG)\s*[:=]\s*true\b"), "low"),
]


def _normalize(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t.rstrip("/")


def _discover_js(html: str, base: str) -> list:
    urls = []
    for src in _JS_RE.findall(html):
        full = urljoin(base, src)
        if urlparse(full).netloc:
            urls.append(full)
    # de-duplicate preserving order
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _scan_file(url: str) -> dict:
    entry: dict = {"url": url, "findings": [], "error": None}
    try:
        resp = requests.get(url, headers=_UA, timeout=_TIMEOUT, verify=False,
                            stream=True)
        content = resp.raw.read(_MAX_BYTES, decode_content=True)
        text = content.decode("utf-8", errors="replace")
    except Exception as e:
        entry["error"] = str(e)
        return entry

    for label, rx, severity in _PATTERNS:
        for m in rx.finditer(text):
            value = m.group(0)
            # Redact the middle of any potential secret in the report.
            redacted = (value[:10] + "…" + value[-4:]) if len(value) > 18 else value
            entry["findings"].append({
                "pattern": label,
                "severity": severity,
                "match": redacted,
                "position": m.start(),
            })
    return entry


def run(target: str, mode: str = "basic") -> dict:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    base = _normalize(target)

    try:
        home = requests.get(base, headers=_UA, timeout=_TIMEOUT, verify=False)
        home.raise_for_status()
    except Exception as e:
        return {"tool": "js_exposure", "target": target, "data": {"scanned": base}, "error": str(e)}

    js_urls = _discover_js(home.text or "", base)
    cap = _MAX_FILES_EXPERT if mode == "expert" else _MAX_FILES
    js_urls = js_urls[:cap]

    files = [_scan_file(u) for u in js_urls]
    findings = [f for file in files for f in file["findings"]]
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    if severity_counts["high"]:
        risk = "high"
    elif severity_counts["medium"]:
        risk = "medium"
    elif severity_counts["low"]:
        risk = "low"
    else:
        risk = "info"

    data = {
        "scanned": base,
        "mode": mode,
        "js_files_found": len(js_urls),
        "js_files_scanned": len(files),
        "files": files,
        "findings": findings,
        "severity_counts": severity_counts,
        "risk": risk,
    }
    return {"tool": "js_exposure", "target": target, "data": data, "error": None}
