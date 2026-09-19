#!/usr/bin/env python3
"""
modules/dirfuzz.py — v2.0.0 (safe import build)
Directory & File Fuzzer with soft-404 detection, token-bucket rate limiting,
cancellable workers, SSE streaming, and secret scanning.

Author: Yanxzyx
"""
from __future__ import annotations

# ── Standard library ────────────────────────────────────────────────────
import concurrent.futures
import hashlib
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

# ── Third-party ─────────────────────────────────────────────────────────
import requests
import urllib3
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("oxysintx.dirfuzz")
__version__ = "2.0.0"

# ── Paths ───────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORDLIST_DIR = _PROJECT_ROOT / "wordlist"

# ── Tunables ────────────────────────────────────────────────────────────
DEFAULT_WORDLIST     = "lottery-dirs.txt"
DEFAULT_MAX_PATHS    = 300
DEFAULT_CONCURRENCY  = 24
DEFAULT_RATE_LIMIT   = 40.0
DEFAULT_TIMEOUT      = 4.0
DEFAULT_MAX_DURATION = 90.0
MAX_RESPONSE_BYTES   = 32768

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# ── Minimal bundled wordlist (safety net) ──────────────────────────────
_BUNDLED_WORDLIST: List[str] = [
    ".env", ".env.local", ".git/config", ".git/HEAD", ".svn/entries",
    ".htaccess", ".htpasswd", ".ssh/id_rsa", ".aws/credentials",
    "config.php", "config.json", "config.yml", "config.xml",
    "wp-config.php", "settings.py", "settings.php", "database.yml",
    "credentials.json", "secrets.json", "private.key",
    "backup.sql", "backup.zip", "backup.tar.gz", "backups/",
    "dump.sql", "database.sql", "db.sql",
    "admin/", "administrator/", "admin.php", "wp-admin/",
    "wp-login.php", "wp-json/", "xmlrpc.php",
    "phpmyadmin/", "pma/", "adminer.php",
    "api/", "api/v1/", "api/v2/", "graphql", "swagger.json",
    "openapi.json", "actuator/", "actuator/env", "metrics", "health",
    "robots.txt", "sitemap.xml", "security.txt", "server-status",
    "phpinfo.php", "info.php", "test.php",
    "CHANGELOG.md", "README.md", "package.json", "composer.json",
    "Dockerfile", "docker-compose.yml", ".DS_Store",
    "uploads/", "files/", "media/", "static/", "assets/",
    ".git/", ".svn/", ".hg/", ".bzr/",
    "logs/", "error.log", "access.log", "debug.log",
    "install/", "setup/", "upgrade/", "backup/", "old/", "tmp/",
]

_INTERESTING_STATUSES = {200, 201, 202, 204, 301, 302, 307, 308,
                         401, 403, 405, 500, 501, 502, 503}

_SENSITIVE_PATTERNS: List[Tuple[str, str, str]] = [
    (r"\.env(\b|$|\.)",            "config",      "critical"),
    (r"\.git(/|$|\.)",             "vcs",         "critical"),
    (r"\.svn(/|$)",                "vcs",         "high"),
    (r"\.ssh(/|$|_)",              "credentials", "critical"),
    (r"\.aws(/|$)",                "credentials", "critical"),
    (r"id_rsa",                    "credentials", "critical"),
    (r"private\.key|\.pem$|\.pfx$", "credentials", "critical"),
    (r"backup",                    "backup",      "high"),
    (r"\.bak(\b|$)",               "backup",      "high"),
    (r"dump|\.sql(\b|$)",          "database",    "critical"),
    (r"\.zip$|\.tar(\.gz)?$|\.tgz$", "archive",   "high"),
    (r"admin|administrator",       "admin",       "high"),
    (r"phpmyadmin|adminer|pma(/|$)", "admin",     "critical"),
    (r"\.htpasswd|\.htaccess",     "config",      "high"),
    (r"config(\.|$|/)",            "config",      "high"),
    (r"credentials",               "credentials", "critical"),
    (r"secret",                    "credentials", "high"),
    (r"docker-compose|Dockerfile", "config",      "medium"),
    (r"\.DS_Store",                "info",        "low"),
]

_BODY_SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    (r"AKIA[0-9A-Z]{16}",                      "AWS Access Key",  "critical"),
    (r"ASIA[0-9A-Z]{16}",                      "AWS Temp Key",    "critical"),
    (r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
                                                "Private Key",     "critical"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
                                                "JWT Token",       "high"),
    (r"ghp_[A-Za-z0-9]{36}",                    "GitHub PAT",      "critical"),
    (r"xox[abprs]-[A-Za-z0-9-]{10,}",           "Slack Token",     "critical"),
    (r"sk_live_[A-Za-z0-9]{20,}",               "Stripe Live Key", "critical"),
    (r"AIza[0-9A-Za-z_\-]{35}",                 "Google API Key",  "high"),
    (r"mongodb(\+srv)?://[^\s\"'<>]+",          "MongoDB URI",     "critical"),
    (r"postgres(ql)?://[^\s\"'<>]+",            "PostgreSQL URI",  "critical"),
    (r"mysql://[^\s\"'<>]+",                    "MySQL URI",       "critical"),
    (r"redis://[^\s\"'<>]+",                    "Redis URI",       "high"),
    (r"password\s*[:=]\s*['\"][^'\"]{6,}['\"]", "Hardcoded Password", "high"),
    (r"api[_-]?key\s*[:=]\s*['\"][^'\"]{12,}['\"]", "Hardcoded API Key", "high"),
]


# ═══════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════
@dataclass
class Hit:
    path: str
    url: str
    status: int
    size: int = 0
    content_type: str = ""
    redirect_to: Optional[str] = None
    category: str = "other"
    severity: str = "info"
    secrets: List[Dict[str, str]] = field(default_factory=list)
    response_preview: str = ""
    elapsed_ms: float = 0.0

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "url": self.url,
            "status": self.status,
            "size": self.size,
            "content_type": self.content_type,
            "redirect_to": self.redirect_to,
            "category": self.category,
            "severity": self.severity,
            "secrets": self.secrets,
            "response_preview": self.response_preview[:400],
            "elapsed_ms": round(self.elapsed_ms, 1),
        }


@dataclass
class ScanReport:
    base: str
    started_at: str
    finished_at: str = ""
    elapsed: float = 0.0
    tried: int = 0
    hits: List[Hit] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    baseline_status: Optional[int] = None
    baseline_size: Optional[int] = None
    soft_404: bool = False
    requests_sent: int = 0
    cancelled: bool = False
    budget_exceeded: bool = False

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "base": self.base,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed": round(self.elapsed, 2),
            "tried": self.tried,
            "requests_sent": self.requests_sent,
            "baseline_status": self.baseline_status,
            "baseline_size": self.baseline_size,
            "soft_404": self.soft_404,
            "cancelled": self.cancelled,
            "budget_exceeded": self.budget_exceeded,
            "hits_count": len(self.hits),
            "critical_count": sum(1 for h in self.hits
                                   if h.severity == "critical"),
            "hits": [h.to_public_dict() for h in self.hits],
            "errors": self.errors[:10],
            "version": __version__,
        }


# ═══════════════════════════════════════════════════════════════════════
# Token bucket
# ═══════════════════════════════════════════════════════════════════════
class _TokenBucket:
    def __init__(self, rate: float, burst: int = 8):
        self.rate = max(0.1, float(rate))
        self.burst = max(1, int(burst))
        self._tokens = float(self.burst)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 20.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.burst,
                                    self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                wait = (1.0 - self._tokens) / self.rate
            time.sleep(min(wait, 0.15))
        return False


# ═══════════════════════════════════════════════════════════════════════
# Wordlist helpers
# ═══════════════════════════════════════════════════════════════════════
def _filter_wordlist_line(line: str) -> Optional[str]:
    s = line.strip()
    if not s or s.startswith(("#", "//", ";")):
        return None
    if len(s) > 512:
        return None
    if s.lower().startswith(("http://", "https://", "ftp://")):
        return None
    return s.lstrip("/")


def ensure_wordlist_dir() -> None:
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)


def load_wordlist(name: str = DEFAULT_WORDLIST,
                  max_lines: int = DEFAULT_MAX_PATHS) -> List[str]:
    """Load a wordlist from disk or fall back to bundled entries."""
    ensure_wordlist_dir()
    base = Path(name).name
    if not base.endswith(".txt"):
        base += ".txt"
    target = (WORDLIST_DIR / base).resolve()
    try:
        target.relative_to(WORDLIST_DIR.resolve())
    except ValueError:
        return list(_BUNDLED_WORDLIST[:max_lines])

    if target.exists() and target.stat().st_size > 0:
        try:
            out: List[str] = []
            with target.open("r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    s = _filter_wordlist_line(raw)
                    if s:
                        out.append(s)
                    if max_lines and len(out) >= max_lines:
                        break
            if out:
                return out
        except OSError:
            pass
    return list(_BUNDLED_WORDLIST[:max_lines] if max_lines else _BUNDLED_WORDLIST)


def list_wordlists() -> List[Dict[str, Any]]:
    ensure_wordlist_dir()
    out: List[Dict[str, Any]] = []
    for path in sorted(WORDLIST_DIR.glob("*.txt")):
        try:
            count = 0
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if _filter_wordlist_line(line):
                        count += 1
            out.append({
                "name": path.name,
                "size": path.stat().st_size,
                "count": count,
                "source": "local",
                "category": "custom",
            })
        except OSError:
            continue
    return out


# ═══════════════════════════════════════════════════════════════════════
# Classification helpers
# ═══════════════════════════════════════════════════════════════════════
def _classify_path(path: str) -> Tuple[str, str]:
    p = path.lower()
    for pattern, cat, sev in _SENSITIVE_PATTERNS:
        if re.search(pattern, p):
            return cat, sev
    if p.endswith("/"):
        return "directory", "info"
    if any(p.endswith(ext) for ext in (".html", ".htm", ".txt", ".md")):
        return "content", "info"
    return "other", "info"


def _scan_body_secrets(body: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen = set()
    haystack = body[:16384]
    for pattern, label, severity in _BODY_SECRET_PATTERNS:
        if label in seen:
            continue
        m = re.search(pattern, haystack)
        if m:
            v = m.group(0)
            redacted = v if len(v) <= 24 else v[:10] + "…" + v[-8:]
            out.append({"type": label, "severity": severity,
                        "value_preview": redacted})
            seen.add(label)
    return out


def _upgrade_severity(base: str, secrets: List[Dict[str, str]]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    best = base
    for s in secrets:
        if order.get(s.get("severity", "info"), 0) > order.get(best, 0):
            best = s["severity"]
    return best


# ═══════════════════════════════════════════════════════════════════════
# HTTP session
# ═══════════════════════════════════════════════════════════════════════
def _build_session() -> requests.Session:
    s = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=64, pool_maxsize=128,
        max_retries=Retry(total=1, backoff_factor=0.3,
                          status_forcelist=(502, 503, 504),
                          allowed_methods=frozenset(["GET", "HEAD"]),
                          raise_on_status=False),
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "User-Agent": _USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
    })
    return s


def _read_capped(r: requests.Response, cap: int = MAX_RESPONSE_BYTES) -> str:
    buf = b""
    try:
        for chunk in r.iter_content(chunk_size=4096):
            buf += chunk
            if len(buf) >= cap:
                break
    except Exception:
        pass
    finally:
        try:
            r.close()
        except Exception:
            pass
    try:
        return buf.decode("utf-8", errors="replace")
    except Exception:
        return buf.decode("latin-1", errors="replace")


# ═══════════════════════════════════════════════════════════════════════
# Scanner
# ═══════════════════════════════════════════════════════════════════════
class DirFuzzer:
    def __init__(self, *, concurrency: int = DEFAULT_CONCURRENCY,
                 timeout: float = DEFAULT_TIMEOUT,
                 rate_limit: float = DEFAULT_RATE_LIMIT,
                 max_duration: float = DEFAULT_MAX_DURATION,
                 cancel_event: Optional[threading.Event] = None,
                 progress_cb: Optional[Callable[[int, int, str], None]] = None):
        self.concurrency = max(1, min(int(concurrency), 64))
        self.timeout = float(timeout)
        self.bucket = _TokenBucket(rate=rate_limit, burst=12)
        self.max_duration = float(max_duration)
        self._stop = cancel_event or threading.Event()
        self._progress_cb = progress_cb
        self._session = _build_session()
        self._req_lock = threading.Lock()
        self._req_count = 0
        self._done = 0
        self._total = 0
        self._started_mono = 0.0
        self._baseline_status: Optional[int] = None
        self._baseline_size: Optional[int] = None
        self._baseline_hash: Optional[str] = None

    def _budget_exceeded(self) -> bool:
        return (time.monotonic() - self._started_mono) > self.max_duration

    def _emit(self, label: str) -> None:
        if not self._progress_cb:
            return
        try:
            self._progress_cb(self._done, self._total, label)
        except Exception:
            pass

    def _fetch(self, url: str) -> Optional[requests.Response]:
        if self._stop.is_set() or self._budget_exceeded():
            return None
        if not self.bucket.acquire(timeout=15.0):
            return None
        try:
            r = self._session.get(url, timeout=self.timeout,
                                   allow_redirects=False, verify=False,
                                   stream=True)
            with self._req_lock:
                self._req_count += 1
            return r
        except requests.exceptions.RequestException:
            return None

    def establish_baseline(self, base: str) -> None:
        r = self._fetch(f"{base}/.em-{uuid.uuid4().hex[:12]}/")
        if r is None:
            return
        try:
            body = _read_capped(r, cap=8192)
            self._baseline_status = r.status_code
            self._baseline_size = int(r.headers.get("Content-Length") or len(body))
            self._baseline_hash = hashlib.md5(
                body.encode("utf-8", "ignore")).hexdigest()
        except Exception:
            pass

    def _looks_like_baseline(self, r: requests.Response, body: str) -> bool:
        if self._baseline_status is None:
            return False
        if r.status_code != self._baseline_status:
            return False
        size = int(r.headers.get("Content-Length") or len(body))
        if self._baseline_size is not None and abs(size - self._baseline_size) > 32:
            return False
        if self._baseline_hash is not None:
            h = hashlib.md5(body.encode("utf-8", "ignore")).hexdigest()
            if h == self._baseline_hash:
                return True
        return False

    def probe(self, base: str, path: str) -> Optional[Hit]:
        if self._stop.is_set() or self._budget_exceeded():
            return None
        url = f"{base}/{path.lstrip('/')}"
        t0 = time.monotonic()
        r = self._fetch(url)
        if r is None:
            return None
        elapsed = (time.monotonic() - t0) * 1000
        try:
            status = r.status_code
            if status == 404 or status not in _INTERESTING_STATUSES:
                return None
            body = _read_capped(r)
            if self._looks_like_baseline(r, body):
                return None
            redirect_to = r.headers.get("Location") if status in (301, 302, 307, 308) else None
            category, severity = _classify_path(path)
            secrets = _scan_body_secrets(body)
            if secrets:
                severity = _upgrade_severity(severity, secrets)
            if status == 200 and category in ("config", "credentials", "vcs", "database"):
                severity = "critical" if severity == "info" else severity
            return Hit(
                path="/" + path.lstrip("/"), url=url, status=status,
                size=int(r.headers.get("Content-Length") or len(body)),
                content_type=(r.headers.get("Content-Type") or "").split(";")[0].strip(),
                redirect_to=redirect_to, category=category,
                severity=severity, secrets=secrets,
                response_preview=body[:400], elapsed_ms=elapsed,
            )
        finally:
            try:
                r.close()
            except Exception:
                pass

    def scan(self, base: str, paths: List[str]) -> ScanReport:
        base = base.rstrip("/")
        started = datetime.now(timezone.utc)
        self._started_mono = time.monotonic()
        report = ScanReport(base=base, started_at=started.isoformat())

        self.establish_baseline(base)
        report.baseline_status = self._baseline_status
        report.baseline_size = self._baseline_size
        report.soft_404 = bool(self._baseline_status == 200
                                and self._baseline_hash is not None)

        self._total = len(paths)
        self._done = 0
        hits: List[Hit] = []
        lock = threading.Lock()

        def worker(path: str) -> None:
            try:
                hit = self.probe(base, path)
            except Exception as e:
                logger.debug("[dirfuzz] probe(%s) failed: %s", path, e)
                hit = None
            with lock:
                self._done += 1
                if hit is not None:
                    hits.append(hit)
                if self._done % 10 == 0 or self._done == self._total:
                    self._emit(path)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.concurrency
        ) as pool:
            futures = [pool.submit(worker, p) for p in paths]
            for fut in concurrent.futures.as_completed(futures):
                if self._stop.is_set() or self._budget_exceeded():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    fut.result()
                except Exception:
                    continue

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        hits.sort(key=lambda h: (sev_order.get(h.severity, 5), h.path))

        report.hits = hits
        report.tried = len(paths)
        report.requests_sent = self._req_count
        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.elapsed = time.monotonic() - self._started_mono
        report.cancelled = self._stop.is_set()
        report.budget_exceeded = self._budget_exceeded()
        return report


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════
def _normalise_base(base: str) -> str:
    base = (base or "").strip()
    if not base:
        raise ValueError("base URL is required")
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    return base.rstrip("/")


def _normalise_options(options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    options = options or {}

    def _i(key, default, lo, hi):
        try: return max(lo, min(hi, int(options.get(key, default))))
        except (TypeError, ValueError): return default

    def _f(key, default, lo, hi):
        try: return max(lo, min(hi, float(options.get(key, default))))
        except (TypeError, ValueError): return default

    def _b(key, default):
        v = options.get(key, default)
        return bool(v) if v is not None else default

    return {
        "wordlist_name":  options.get("wordlist_name") or DEFAULT_WORDLIST,
        "wordlist":       options.get("wordlist") or None,
        "max_paths":      _i("max_paths", DEFAULT_MAX_PATHS, 10, 2000),
        "concurrency":    _i("concurrency", DEFAULT_CONCURRENCY, 1, 64),
        "rate_limit":     _f("rate_limit", DEFAULT_RATE_LIMIT, 1.0, 200.0),
        "timeout":        _f("timeout", DEFAULT_TIMEOUT, 1.0, 15.0),
        "max_duration":   _f("max_duration", DEFAULT_MAX_DURATION, 10.0, 300.0),
        "follow_redirects": _b("follow_redirects", False),
        "cancel_event":   options.get("cancel_event"),
        "progress_cb":    options.get("progress_cb"),
    }


def _resolve_paths(o: Dict[str, Any]) -> List[str]:
    inline = o.get("wordlist")
    if isinstance(inline, list) and inline:
        cleaned: List[str] = []
        for p in inline[:o["max_paths"]]:
            s = _filter_wordlist_line(str(p))
            if s:
                cleaned.append(s)
        if cleaned:
            return cleaned
    return load_wordlist(o["wordlist_name"], max_lines=o["max_paths"])


def run(base: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    o = _normalise_options(options)
    base = _normalise_base(base)
    paths = _resolve_paths(o)
    if not paths:
        return {"base": base, "error": "no paths to test", "hits": [],
                "tried": 0, "version": __version__}
    fuzzer = DirFuzzer(
        concurrency=o["concurrency"], timeout=o["timeout"],
        rate_limit=o["rate_limit"], max_duration=o["max_duration"],
        cancel_event=o["cancel_event"], progress_cb=o["progress_cb"],
    )
    return fuzzer.scan(base, paths).to_public_dict()


def scan_single(base: str, path: str,
                options: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    o = _normalise_options(options)
    base = _normalise_base(base)
    fuzzer = DirFuzzer(concurrency=1, timeout=o["timeout"],
                        rate_limit=o["rate_limit"],
                        max_duration=o["max_duration"],
                        cancel_event=o["cancel_event"])
    fuzzer.establish_baseline(base)
    hit = fuzzer.probe(base, path)
    return hit.to_public_dict() if hit else None


def run_streaming(base: str, options: Optional[Dict[str, Any]] = None,
                  cancel_event: Optional[threading.Event] = None
                  ) -> Iterator[Dict[str, Any]]:
    o = _normalise_options(options)
    if cancel_event is not None:
        o["cancel_event"] = cancel_event
    events: List[Dict[str, Any]] = []
    events_lock = threading.Lock()
    done = threading.Event()

    def _progress(done_count: int, total: int, label: str) -> None:
        pct = int((done_count / total) * 100) if total else 0
        with events_lock:
            events.append({"type": "progress", "done": done_count,
                           "total": total, "percent": pct, "label": label})

    o["progress_cb"] = _progress
    result_holder: Dict[str, Any] = {}

    def _worker() -> None:
        try:
            result_holder["result"] = run(base, o)
        except Exception as e:
            result_holder["error"] = str(e)
        finally:
            done.set()

    threading.Thread(target=_worker, daemon=True).start()

    yield {"type": "start", "base": base,
           "options": {"max_paths": o["max_paths"],
                       "concurrency": o["concurrency"],
                       "rate_limit": o["rate_limit"]}}

    while not done.is_set():
        with events_lock:
            pending, events[:] = list(events), []
        for ev in pending:
            yield ev
        done.wait(timeout=0.4)

    with events_lock:
        for ev in events:
            yield ev

    if "error" in result_holder:
        yield {"type": "error", "message": result_holder["error"]}
    else:
        yield {"type": "result", "data": result_holder.get("result", {})}


# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse, json, sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    p = argparse.ArgumentParser(description="Directory Fuzzer v2.0.0")
    p.add_argument("base")
    p.add_argument("--wordlist", default=DEFAULT_WORDLIST)
    p.add_argument("--max-paths", type=int, default=DEFAULT_MAX_PATHS)
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT)
    p.add_argument("--json", action="store_true")
    p.add_argument("--list-wordlists", action="store_true")
    args = p.parse_args()

    if args.list_wordlists:
        print(json.dumps(list_wordlists(), indent=2))
        sys.exit(0)

    report = run(args.base, {"wordlist_name": args.wordlist,
                              "max_paths": args.max_paths,
                              "concurrency": args.concurrency,
                              "rate_limit": args.rate_limit})
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"\nScanned {report['tried']} path(s), {report['hits_count']} hit(s), "
              f"{report['critical_count']} critical in {report['elapsed']}s\n")
        for h in report["hits"][:30]:
            print(f"  [{h['severity'].upper():8s}] [{h['status']:3d}] {h['path']}")
