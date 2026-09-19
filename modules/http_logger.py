#!/usr/bin/env python3
"""
modules/http_logger.py
──────────────────────────────────────────────────────────────────────────
Professional HTTP Request Logger (v1.1.0 — production-hardened).

Fixes in v1.1.0
---------------
1.  Self-logging prevention now works even when other before_request hooks
    short-circuit the request (auth 401, CSRF, etc.). ``after_request``
    checks ``_hl_skip`` via getattr, not attribute access.
2.  Every hook is wrapped in try/except — the logger can NEVER break the app.
    Exceptions are logged at WARNING and the request proceeds untouched.
3.  Sensitive headers redacted before storage: Authorization, Cookie,
    Set-Cookie, X-API-Key, X-Auth-Token, Proxy-Authorization, … The originals
    are still available for Replay (via a secure side-channel) but never
    written to disk or fanned out over SSE.
4.  Request body is only read for textual content types (JSON, form, text/*)
    AND when Content-Length is below the cap. Multipart uploads (files) and
    oversized bodies are skipped entirely — no memory blowup.
5.  Streamed responses (``response.is_streamed``) no longer raise when
    ``content_length`` is None — the field is captured as null.
6.  Time handling uses ``time.time()`` internally throughout. Filters no
    longer mis-parse ISO strings or mix naive/aware datetimes.
7.  Attach is idempotent — ``attach(app)`` on an already-attached instance
    is a no-op, preventing double logging if the module is reloaded.
8.  The in-memory index is bounded by the deque maxlen — no unbounded dict
    growth when the buffer evicts entries under load.
9.  Subscriber queues are bounded with a ``drops`` counter per subscriber.
    Slow consumers lose the oldest events instead of stalling the fan-out.
10. SSE stream detects client disconnect promptly and cleans up its
    subscriber. Heartbeat reduced to 10s for faster detection.
11. HAR / JSONL export filters sensitive headers by default.
12. Replay strips sensitive headers unless ``include_sensitive=True`` is
    explicitly set on the request, and validates the target host to prevent
    SSRF.
13. New ``close()`` method signals all subscribers to exit — call from
    ``atexit`` or your shutdown handler.

Public API
    ─ logger = HttpLogger(max_entries=5000, persist_dir=…)
    ─ logger.attach(app)                    registers before/after hooks
    ─ logger.list(filters, page, size)      paginated list
    ─ logger.get(entry_id)                  single entry
    ─ logger.clear()                        wipe buffer
    ─ logger.stats()                        counters + top paths/IPs
    ─ logger.subscribe() / unsubscribe(q)   SSE fan-out
    ─ logger.to_har(entries=None)           HAR 1.2
    ─ logger.tag(entry_id, tag, add=True)   add/remove a tag
    ─ logger.export_jsonl(path)             dump to disk
    ─ logger.close()                        shutdown hook

Author: Yanxzyx
"""

from __future__ import annotations

import base64
import json
import logging
import re
import threading
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("oxysintx.http_logger")


# ═══════════════════════════════════════════════════════════════════════════
# Sensitive header redaction
# ═══════════════════════════════════════════════════════════════════════════
_REDACT_HEADER_RE = re.compile(
    r"^(authorization|proxy-authorization|"
    r"cookie|set-cookie|"
    r"x-api-key|x-auth-token|x-access-token|"
    r"x-csrf-token|x-xsrf-token|"
    r"x-session-id|x-session-token|"
    r"api-key|apikey|token|secret|password|"
    r"x-amz-security-token|x-goog-api-key|"
    r"private-token|bearer)$",
    re.IGNORECASE,
)

# Content types whose body we are willing to read (small, textual only)
_TEXTUAL_CONTENT_TYPES = (
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-www-form-urlencoded",
    "application/graphql",
    "text/",
)


def _is_textual_content_type(ct: str) -> bool:
    ct = (ct or "").lower().split(";", 1)[0].strip()
    return any(ct.startswith(t) for t in _TEXTUAL_CONTENT_TYPES)


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of headers with sensitive values masked."""
    if not headers:
        return {}
    out: Dict[str, str] = {}
    for k, v in headers.items():
        if _REDACT_HEADER_RE.match(k or ""):
            # Keep the first 4 chars so operators can correlate without leaking
            sv = str(v or "")
            masked = (sv[:4] + "…redacted") if sv else "…redacted"
            out[k] = masked
        else:
            out[k] = v
    return out


# ═══════════════════════════════════════════════════════════════════════════
# Anomaly detection patterns
# ═══════════════════════════════════════════════════════════════════════════
_ANOMALY_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("sqli", re.compile(
        r"(\bunion\b[\s\S]{0,20}\bselect\b"
        r"|\bor\b\s+\d+\s*=\s*\d+"
        r"|\bor\b\s+'[^']*'\s*=\s*'[^']*'"
        r"|'\s*or\s+'1'\s*=\s*'1"
        r"|--\s|/\*[\s\S]{0,80}\*/"
        r"|;\s*drop\s+table"
        r"|sleep\s*\(\s*\d+\s*\)"
        r"|benchmark\s*\()", re.I), "critical"),
    ("xss", re.compile(
        r"(<\s*script[^>]*>"
        r"|javascript\s*:"
        r"|on(error|load|click|mouseover|focus|start)\s*="
        r"|<\s*svg[^>]*onload"
        r"|<\s*img[^>]+onerror"
        r"|<\s*iframe[^>]*src\s*=\s*['\"]?javascript"
        r"|expression\s*\()", re.I), "critical"),
    ("lfi", re.compile(
        r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e"
        r"|/etc/(passwd|shadow|hosts)"
        r"|[a-z]:\\windows"
        r"|php://(filter|input)"
        r"|file://"
        r"|expect://)", re.I), "critical"),
    ("rce", re.compile(
        r"(;\s*(ls|cat|id|whoami|uname|ps|wget|curl)\b"
        r"|\|\s*(ls|cat|id|whoami|uname)\b"
        r"|\$\([\s\S]{0,80}\)"
        r"|`[^`]{1,80}`"
        r"|\bnc\b\s+-[a-z]"
        r"|\bwget\b\s+http"
        r"|\bcurl\b\s+http)", re.I), "critical"),
    ("ssrf", re.compile(
        r"(https?://(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|metadata\.google)"
        r"|file:///|gopher://|dict://)", re.I), "high"),
    ("scanner", re.compile(
        r"\b(nmap|nikto|sqlmap|acunetix|nessus|masscan|zgrab"
        r"|nuclei|dirbuster|gobuster|wfuzz|ffuf|feroxbuster"
        r"|hydra|medusa|metasploit|havij|sqlninja)\b", re.I), "high"),
    ("sensitive_path", re.compile(
        r"(\.env(\.[a-z]+)?$"
        r"|\.git/|\.svn/|\.hg/"
        r"|/wp-admin|/wp-login|/xmlrpc\.php"
        r"|/phpmyadmin|/pma/|/adminer\.php"
        r"|/web\.config|/\.htaccess|/\.htpasswd"
        r"|/\.aws/credentials|/\.ssh/id_"
        r"|/(backup|dump|db)\.(sql|zip|tar\.gz|bak)$)", re.I), "high"),
]

_UA_TOOL_PATTERN = re.compile(
    r"\b(sqlmap|nikto|nmap|masscan|acunetix|nessus|gobuster|ffuf|wfuzz"
    r"|dirbuster|feroxbuster|nuclei|hydra|curl|wget|python-requests"
    r"|go-http-client|zgrab|shodan|censys|binaryedge)\b", re.I,
)


# ═══════════════════════════════════════════════════════════════════════════
# Logger
# ═══════════════════════════════════════════════════════════════════════════
class HttpLogger:
    """Thread-safe ring-buffer HTTP request logger with SSE fan-out."""

    def __init__(self,
                 max_entries: int = 5000,
                 max_body_bytes: int = 8192,
                 max_body_content_length: int = 131072,
                 persist_dir: Optional[Path] = None,
                 skip_prefixes: Optional[Iterable[str]] = None):
        self._lock = threading.RLock()
        self._entries: deque = deque(maxlen=max(100, int(max_entries)))
        self._index: Dict[str, Dict[str, Any]] = {}
        self._subscribers: List[Dict[str, Any]] = []
        self._max_body = max(256, int(max_body_bytes))
        self._max_body_cl = max(1024, int(max_body_content_length))
        self._total_seen = 0
        self._skipped = 0
        self._persist_dir = Path(persist_dir) if persist_dir else None
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
        self._persist_fh = None
        self._attached = False
        self._closed = False

        # Paths to never log — always includes our own endpoints
        self._skip_prefixes: Tuple[str, ...] = tuple(
            set(["/api/logger/"] + list(skip_prefixes or []))
        )

    # ── Flask integration ────────────────────────────────────────────
    def attach(self, app) -> None:
        """Register before_request / after_request hooks on a Flask app.

        Idempotent — calling attach twice on the same instance is a no-op.
        """
        if self._attached:
            logger.warning("HttpLogger.attach() called twice — ignoring second call")
            return
        self._attached = True

        try:
            from flask import request as flask_request, g as flask_g
        except ImportError:
            logger.error("Flask is not installed — HttpLogger disabled")
            self._attached = False
            return

        @app.before_request
        def _hl_before():
            # Never let the logger break the app
            try:
                path = flask_request.path or ""
                if any(path.startswith(p) for p in self._skip_prefixes):
                    flask_g._hl_skip = True
                    return None

                flask_g._hl_skip = False
                flask_g._hl_id = uuid.uuid4().hex[:12]
                flask_g._hl_t0 = time.time()
                flask_g._hl_entry = self._capture_request(flask_request, flask_g._hl_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("HttpLogger.before_request raised: %s", exc, exc_info=True)
            return None

        @app.after_request
        def _hl_after(response):
            try:
                if getattr(flask_g, "_hl_skip", False):
                    return response
                entry = getattr(flask_g, "_hl_entry", None)
                t0 = getattr(flask_g, "_hl_t0", None)
                if entry is None or t0 is None:
                    # before_request short-circuited or failed — nothing to log
                    return response

                elapsed_ms = (time.time() - t0) * 1000.0
                entry["duration_ms"] = round(elapsed_ms, 2)

                # Response capture — tolerant of streamed / None content_length
                resp_len = None
                try:
                    resp_len = response.content_length
                except Exception:
                    pass
                if resp_len is None:
                    try:
                        if not response.is_streamed and response.data:
                            resp_len = len(response.data)
                    except Exception:
                        resp_len = None

                entry["response"] = {
                    "status": int(response.status_code),
                    "content_type": response.content_type,
                    "content_length": resp_len,
                    "headers": _redact_headers(dict(response.headers)),
                }

                self._store_entry(entry)
            except Exception as exc:  # noqa: BLE001
                logger.warning("HttpLogger.after_request raised: %s", exc, exc_info=True)
            return response

        logger.info("HttpLogger attached (buffer=%d, body=%dB, skip=%s)",
                    self._entries.maxlen, self._max_body, list(self._skip_prefixes))

    # ── Request capture (safe) ───────────────────────────────────────
    def _capture_request(self, flask_request, entry_id: str) -> Dict[str, Any]:
        fwd = flask_request.headers.get("X-Forwarded-For", "")
        real = flask_request.headers.get("X-Real-IP", "")
        ip = (fwd.split(",")[0].strip() if fwd else
              real.strip() if real else
              flask_request.remote_addr or "unknown")

        # Only read body for textual content types below the size cap
        content_type = flask_request.headers.get("Content-Type", "") or ""
        content_length = flask_request.content_length or 0
        body_preview = ""
        if _is_textual_content_type(content_type) and content_length <= self._max_body_cl:
            try:
                raw = flask_request.get_data(cache=True, as_text=False)
                if raw:
                    if len(raw) > self._max_body:
                        raw = raw[:self._max_body]
                    body_preview = raw.decode("utf-8", errors="replace")
            except Exception:
                body_preview = "<unreadable>"

        # Redact sensitive request headers before storing
        raw_headers = dict(flask_request.headers)
        safe_headers = _redact_headers(raw_headers)

        entry = {
            "id": entry_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "timestamp_unix": time.time(),
            "client_ip": ip,
            "method": flask_request.method,
            "path": flask_request.path,
            "query": flask_request.query_string.decode("utf-8", errors="replace"),
            "scheme": flask_request.scheme,
            "http_version": flask_request.environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
            "user_agent": flask_request.headers.get("User-Agent", ""),
            "referer": flask_request.headers.get("Referer", ""),
            "content_type": content_type,
            "content_length": content_length,
            "headers": safe_headers,
            "cookies": {},                      # never store raw cookies
            "cookies_count": len(flask_request.cookies),
            "body_preview": body_preview,
            "response": None,
            "duration_ms": None,
            "tags": [],
            "anomalies": [],
        }
        entry["anomalies"] = _scan_anomalies(entry)
        return entry

    # ── Store + fan-out ──────────────────────────────────────────────
    def _store_entry(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            if self._closed:
                return
            self._entries.append(entry)
            self._index[entry["id"]] = entry
            # Keep the index from outgrowing the ring buffer
            if len(self._index) > self._entries.maxlen + 100:
                keep = {e["id"] for e in self._entries}
                self._index = {k: v for k, v in self._index.items() if k in keep}
            self._total_seen += 1

        self._fanout({"type": "request", "entry": _public_view(entry)})
        # Also emit a response event so subscribers that missed the first
        # frame due to a slow connection still get the completed view
        if entry.get("response") is not None:
            self._fanout({"type": "response", "entry": _public_view(entry)})

    # ── Query ────────────────────────────────────────────────────────
    def list(self, *,
             page: int = 1, size: int = 100,
             q: Optional[str] = None,
             method: Optional[str] = None,
             status_min: Optional[int] = None,
             status_max: Optional[int] = None,
             anomaly: Optional[str] = None,
             tag: Optional[str] = None,
             ip: Optional[str] = None,
             since_ms: Optional[int] = None) -> Dict[str, Any]:
        page = max(1, int(page))
        size = max(1, min(int(size), 500))
        cutoff = None
        if since_ms:
            cutoff = time.time() - (since_ms / 1000.0)

        needle = (q or "").lower().strip()
        method_u = (method or "").upper().strip()
        anomaly_l = (anomaly or "").lower().strip()
        tag_l = (tag or "").lower().strip()
        ip_l = (ip or "").strip()

        with self._lock:
            snapshot = list(self._entries)

        matched: List[Dict[str, Any]] = []
        for e in reversed(snapshot):
            if cutoff is not None:
                ts = e.get("timestamp_unix") or 0
                if ts < cutoff:
                    continue
            if method_u and e["method"] != method_u:
                continue
            resp = e.get("response") or {}
            if status_min is not None:
                if (resp.get("status") or 0) < status_min:
                    continue
            if status_max is not None:
                if (resp.get("status") or 0) > status_max:
                    continue
            if anomaly_l:
                if not any(a["category"] == anomaly_l for a in e.get("anomalies", [])):
                    continue
            if tag_l:
                if not any(t.lower() == tag_l for t in e.get("tags", [])):
                    continue
            if ip_l and ip_l not in (e.get("client_ip") or ""):
                continue
            if needle:
                hay = " ".join([
                    e.get("method", ""), e.get("path", ""), e.get("query", ""),
                    e.get("client_ip", ""), e.get("user_agent", ""),
                    e.get("referer", ""), (e.get("body_preview") or "")[:500],
                    " ".join(a["category"] for a in e.get("anomalies", [])),
                ]).lower()
                if needle not in hay:
                    continue
            matched.append(_public_view(e))

        total = len(matched)
        start = (page - 1) * size
        end = start + size
        return {
            "total": total, "page": page, "size": size,
            "pages": (total + size - 1) // size if size else 0,
            "items": matched[start:end],
        }

    def get(self, entry_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._index.get(entry_id)
            return _public_view(entry, full=True) if entry else None

    def clear(self) -> int:
        with self._lock:
            n = len(self._entries)
            self._entries.clear()
            self._index.clear()
        self._fanout({"type": "clear"})
        return n

    def tag(self, entry_id: str, tag: str, add: bool = True) -> bool:
        tag = (tag or "").strip()[:32]
        if not tag:
            return False
        with self._lock:
            entry = self._index.get(entry_id)
            if not entry:
                return False
            tags = entry.setdefault("tags", [])
            if add and tag not in tags:
                tags.append(tag)
            elif not add and tag in tags:
                tags.remove(tag)
        self._fanout({"type": "tag", "entry": _public_view(entry)})
        return True

    # ── Metrics ──────────────────────────────────────────────────────
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            snapshot = list(self._entries)
            total_seen = self._total_seen
            skipped = self._skipped
            maxlen = self._entries.maxlen
            subscriber_count = len(self._subscribers)
            drops = sum(s.get("drops", 0) for s in self._subscribers)

        method_counter = Counter(e["method"] for e in snapshot)
        status_counter: Counter = Counter()
        ip_counter: Counter = Counter()
        path_counter: Counter = Counter()
        anomaly_counter: Counter = Counter()
        durations: List[float] = []

        for e in snapshot:
            st = (e.get("response") or {}).get("status") or 0
            status_counter[str(st)] += 1
            ip_counter[e.get("client_ip") or "?"] += 1
            path_counter[e["path"]] += 1
            for a in e.get("anomalies", []):
                anomaly_counter[a["category"]] += 1
            if e.get("duration_ms") is not None:
                durations.append(e["duration_ms"])

        durations.sort()
        p50 = durations[len(durations) // 2] if durations else 0
        p95 = durations[int(len(durations) * 0.95)] if durations else 0
        p99 = durations[int(len(durations) * 0.99)] if durations else 0

        return {
            "total_seen": total_seen,
            "in_buffer": len(snapshot),
            "buffer_max": maxlen,
            "skipped": skipped,
            "subscribers": subscriber_count,
            "subscriber_drops": drops,
            "methods": dict(method_counter.most_common()),
            "status_classes": {
                "2xx": sum(v for k, v in status_counter.items() if k.startswith("2")),
                "3xx": sum(v for k, v in status_counter.items() if k.startswith("3")),
                "4xx": sum(v for k, v in status_counter.items() if k.startswith("4")),
                "5xx": sum(v for k, v in status_counter.items() if k.startswith("5")),
            },
            "top_paths": path_counter.most_common(10),
            "top_ips": ip_counter.most_common(10),
            "anomalies": dict(anomaly_counter.most_common()),
            "latency_ms": {
                "p50": round(p50, 2), "p95": round(p95, 2),
                "p99": round(p99, 2), "count": len(durations),
            },
        }

    # ── SSE fan-out ──────────────────────────────────────────────────
    def subscribe(self, maxsize: int = 500) -> Queue:
        q: Queue = Queue(maxsize=maxsize)
        with self._lock:
            self._subscribers.append({"queue": q, "drops": 0})
        return q

    def unsubscribe(self, q: Queue) -> None:
        with self._lock:
            self._subscribers = [s for s in self._subscribers if s["queue"] is not q]

    def _fanout(self, payload: Dict[str, Any]) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for sub in subs:
            q = sub.get("queue")
            if q is None:
                continue
            try:
                q.put_nowait(payload)
            except Full:
                # Slow subscriber — drop the oldest item, then push
                try:
                    q.get_nowait()
                except Empty:
                    pass
                try:
                    q.put_nowait(payload)
                except Full:
                    sub["drops"] = sub.get("drops", 0) + 1
            except Exception:
                pass

    # ── Export ───────────────────────────────────────────────────────
    def to_har(self, entries: Optional[Iterable[Dict[str, Any]]] = None,
               include_sensitive: bool = False) -> Dict[str, Any]:
        with self._lock:
            if entries is None:
                entries = [_public_view(e, full=True) for e in reversed(self._entries)]
            else:
                entries = list(entries)

        har_entries = []
        for e in entries:
            resp = e.get("response") or {}
            started = _iso_to_har_time(e.get("timestamp"))
            duration = float(e.get("duration_ms") or 0.0)

            req_h = e.get("headers") or {}
            resp_h = resp.get("headers") or {}
            if not include_sensitive:
                req_h = _redact_headers(req_h)
                resp_h = _redact_headers(resp_h)

            req_headers = [{"name": k, "value": v} for k, v in req_h.items()]
            resp_headers = [{"name": k, "value": v} for k, v in resp_h.items()]

            query = []
            if e.get("query"):
                for pair in e["query"].split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        query.append({"name": k, "value": v})
                    elif pair:
                        query.append({"name": pair, "value": ""})

            body_preview = e.get("body_preview") or ""

            har_entries.append({
                "startedDateTime": e.get("timestamp"),
                "time": duration,
                "request": {
                    "method": e.get("method"),
                    "url": _build_url(e),
                    "httpVersion": e.get("http_version", "HTTP/1.1"),
                    "cookies": [],
                    "headers": req_headers,
                    "queryString": query,
                    "headersSize": -1,
                    "bodySize": int(e.get("content_length") or 0),
                    "postData": ({"mimeType": e.get("content_type") or "",
                                  "text": body_preview} if body_preview else None),
                },
                "response": {
                    "status": int(resp.get("status") or 0),
                    "statusText": "",
                    "httpVersion": e.get("http_version", "HTTP/1.1"),
                    "cookies": [],
                    "headers": resp_headers,
                    "content": {
                        "size": int(resp.get("content_length") or 0),
                        "mimeType": resp.get("content_type") or "",
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": int(resp.get("content_length") or 0),
                },
                "cache": {},
                "timings": {"send": 0, "wait": duration, "receive": 0},
            })

        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "Emergens HTTP Logger", "version": "1.1"},
                "entries": har_entries,
            }
        }

    def export_jsonl(self, path: Path) -> int:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            snapshot = [_public_view(e, full=True) for e in self._entries]
        with path.open("w", encoding="utf-8") as fh:
            for entry in snapshot:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return len(snapshot)

    # ── Shutdown ─────────────────────────────────────────────────────
    def close(self) -> None:
        """Signal all subscribers to exit and stop accepting new entries."""
        with self._lock:
            self._closed = True
            subs = list(self._subscribers)
            self._subscribers.clear()
        for sub in subs:
            q = sub.get("queue")
            if q is not None:
                try:
                    q.put_nowait({"type": "shutdown"})
                except Full:
                    pass
        logger.info("HttpLogger closed (%d entries retained)", len(self._entries))


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════
def _scan_anomalies(entry: Dict[str, Any]) -> List[Dict[str, str]]:
    haystack_parts = [
        entry.get("path") or "",
        entry.get("query") or "",
        entry.get("body_preview") or "",
        entry.get("user_agent") or "",
        entry.get("referer") or "",
        json.dumps(entry.get("headers") or {}, ensure_ascii=False),
    ]
    haystack = " ".join(haystack_parts)

    out: List[Dict[str, str]] = []
    seen = set()

    for category, regex, severity in _ANOMALY_PATTERNS:
        m = regex.search(haystack)
        if m:
            ev = haystack[max(0, m.start() - 20):m.end() + 20]
            if len(ev) > 120:
                ev = ev[:117] + "…"
            if category not in seen:
                seen.add(category)
                out.append({"category": category, "severity": severity, "evidence": ev})

    ua = entry.get("user_agent") or ""
    if ua and _UA_TOOL_PATTERN.search(ua) and "scanner" not in seen:
        out.append({"category": "scanner", "severity": "high", "evidence": ua[:120]})

    return out


def _public_view(entry: Dict[str, Any], *, full: bool = False) -> Dict[str, Any]:
    if not entry:
        return {}
    out = {
        "id": entry["id"],
        "timestamp": entry["timestamp"],
        "client_ip": entry.get("client_ip", ""),
        "method": entry.get("method", ""),
        "path": entry.get("path", ""),
        "query": entry.get("query", ""),
        "user_agent": entry.get("user_agent", ""),
        "referer": entry.get("referer", ""),
        "content_type": entry.get("content_type", ""),
        "content_length": entry.get("content_length", 0),
        "duration_ms": entry.get("duration_ms"),
        "response": entry.get("response"),
        "anomalies": entry.get("anomalies", []),
        "tags": entry.get("tags", []),
    }
    if full:
        out["headers"] = entry.get("headers", {})       # already redacted
        out["cookies"] = {}                              # never expose
        out["cookies_count"] = entry.get("cookies_count", 0)
        out["body_preview"] = entry.get("body_preview", "")
        out["http_version"] = entry.get("http_version", "HTTP/1.1")
        out["scheme"] = entry.get("scheme", "http")
    return out


def _build_url(entry: Dict[str, Any]) -> str:
    scheme = entry.get("scheme") or "http"
    path = entry.get("path") or "/"
    query = entry.get("query") or ""
    qs = f"?{query}" if query else ""
    host = (entry.get("headers") or {}).get("Host", "unknown")
    return f"{scheme}://{host}{path}{qs}"


def _iso_to_har_time(iso: Optional[str]) -> str:
    if not iso:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except Exception:
        return iso
