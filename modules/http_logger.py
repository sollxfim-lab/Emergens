#!/usr/bin/env python3
"""
modules/http_logger.py — v2.0.0
═══════════════════════════════════════════════════════════════════════════
Global HTTP request capture with anomaly detection, tagging, HAR export,
disk persistence, and real-time SSE broadcasting.

Features
    • Ring buffer (default 5000 entries) — constant memory usage
    • Optional disk persistence (JSONL, auto-rotated at 32 MB / 10k lines)
    • Thread-safe — usable from Flask's threaded WSGI runner
    • Broadly compatible with app.py v4.3.0
    • Anomaly scanner: SQLi, XSS, path traversal, command injection,
      scanner user-agents, sensitive paths, auth attempts, oversized payloads
    • Tag system: attach/remove labels on any entry
    • SSE subscribers: N consumers via per-subscriber Queue
    • HAR 1.2 export ready for DevTools / Charles / Postman import
    • Full-text search across path, query, headers, body, IP, tags
    • Rich filtering: method, status range, anomaly class, tag, IP, since_ms
    • Aggregated statistics: total, by method, by status, anomalies, top paths
    • Auto-skips /api/logger/* to prevent self-loop

Public API (used by app.py)
    HttpLogger(max_entries=5000, max_body_bytes=8192, persist_dir=None)
        .attach(app)                          → None
        .list(page=1, size=100, q=None, ...)  → dict
        .get(entry_id)                        → dict | None
        .clear()                              → int
        .tag(entry_id, tag, add=True)         → bool
        .stats()                              → dict
        .to_har(items)                        → dict
        .subscribe()                          → queue.Queue
        .unsubscribe(queue)                   → None

Author: Yanxzyx
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import queue
import re
import threading
import time
import uuid
from collections import OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("oxysintx.http_logger")

__version__ = "2.0.0"


# ═══════════════════════════════════════════════════════════════════════════
# Anomaly signatures
# ═══════════════════════════════════════════════════════════════════════════
_ANOMALY_PATTERNS: List[Tuple[str, str, str, str]] = [
    # (label, severity, category, regex)

    # ── SQLi ──────────────────────────────────────────────────────────
    ("sqli_union",      "critical", "sqli",
     r"(?i)\bunion\b[\s/\+%]*\bselect\b"),
    ("sqli_or_true",    "high",     "sqli",
     r"(?i)(?:'|\"|%27|%22)\s*(?:or|and)\s*(?:\d|'|\")[^\n]{0,20}="),
    ("sqli_comment",    "medium",   "sqli",
     r"(?i)(?:--|#|/\*|\*/|;--)(?:\s|$)"),
    ("sqli_sleep",      "critical", "sqli",
     r"(?i)\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\("),
    ("sqli_information", "high",    "sqli",
     r"(?i)\binformation_schema\b"),

    # ── XSS ───────────────────────────────────────────────────────────
    ("xss_script_tag",   "critical", "xss",
     r"(?i)<\s*script\b[^>]*>"),
    ("xss_event_handler", "high",    "xss",
     r"(?i)\bon(?:error|load|click|mouseover|focus|toggle|start)\s*="),
    ("xss_javascript_uri", "high",   "xss",
     r"(?i)javascript\s*:"),
    ("xss_svg_onload",   "high",     "xss",
     r"(?i)<\s*svg[^>]*onload"),

    # ── Path traversal ────────────────────────────────────────────────
    ("path_traversal",   "high",     "traversal",
     r"(?:\.\./|\.\.\\|%2e%2e(?:%2f|/|\\)){2,}"),
    ("path_traversal_enc", "medium", "traversal",
     r"(?i)%2e%2e(?:%252f|%2f|/)"),

    # ── Command injection ─────────────────────────────────────────────
    ("cmd_injection",    "critical", "rce",
     r"(?:;|\||&&|\|\|)\s*(?:cat|ls|id|whoami|uname|curl|wget|nc)\b"),

    # ── Sensitive paths / config exposure ─────────────────────────────
    ("sensitive_path",   "high",     "sensitive",
     r"(?i)/(?:\.env|\.git/|\.svn/|\.htpasswd|wp-config\.php|"
     r"id_rsa|\.ssh/|\.aws/|credentials\.json|config\.php\.bak)"),

    # ── Scanner / recon tooling user-agents ───────────────────────────
    ("scanner_ua",       "medium",   "scanner",
     r"(?i)User-Agent:\s*(?:sqlmap|nmap|nikto|masscan|dirb|gobuster|"
     r"wfuzz|ffuf|burpsuite|acunetix|nessus|openvas|w3af|zgrab)"),
    ("curl_ua",          "low",      "scanner",
     r"(?i)User-Agent:\s*curl/"),

    # ── Auth probes ───────────────────────────────────────────────────
    ("auth_attempt",     "medium",   "auth",
     r"(?i)/(?:wp-login\.php|wp-admin|phpmyadmin|adminer|admin\.php|"
     r"administrator|xmlrpc\.php)"),
    ("basic_auth_probe", "medium",   "auth",
     r"(?i)Authorization:\s*Basic\s"),

    # ── Payload-size & protocol anomalies ─────────────────────────────
    ("oversized_body",   "medium",   "payload",
     r"(?i)Content-Length:\s*(?:[1-9]\d{6,})"),  # >= 1 MB
]

_COMPILED_ANOMALIES = [
    (label, sev, cat, re.compile(pattern))
    for (label, sev, cat, pattern) in _ANOMALY_PATTERNS
]

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ═══════════════════════════════════════════════════════════════════════════
# HttpLogger
# ═══════════════════════════════════════════════════════════════════════════
class HttpLogger:
    """Thread-safe HTTP request logger with disk persistence + SSE fanout."""

    def __init__(
        self,
        max_entries: int = 5000,
        max_body_bytes: int = 8192,
        persist_dir: Optional[Path] = None,
    ):
        self.max_entries = max(100, int(max_entries))
        self.max_body_bytes = max(512, int(max_body_bytes))
        self.persist_dir = Path(persist_dir) if persist_dir else None

        self._lock = threading.RLock()
        self._entries: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._subscribers: List["queue.Queue[Dict[str, Any]]"] = []

        # Persistence handles
        self._persist_path: Optional[Path] = None
        self._persist_fh = None
        self._persist_line_count = 0
        self._persist_bytes = 0
        self._persist_rotate_at_bytes = 32 * 1024 * 1024   # 32 MB
        self._persist_rotate_at_lines = 10000

        # Counters for stats
        self._by_method: Dict[str, int] = {}
        self._by_status: Dict[str, int] = {}
        self._by_anomaly: Dict[str, int] = {}
        self._by_ip: Dict[str, int] = {}
        self._by_path: Dict[str, int] = {}
        self._total_seen = 0
        self._total_dropped = 0

        if self.persist_dir is not None:
            self._init_persistence()

    # ═══════════════════════════════════════════════════════════════════
    # Persistence
    # ═══════════════════════════════════════════════════════════════════
    def _init_persistence(self) -> None:
        try:
            self.persist_dir.mkdir(parents=True, exist_ok=True)
            self._persist_path = self.persist_dir / "requests.jsonl"
            self._persist_fh = open(self._persist_path, "a",
                                     encoding="utf-8", buffering=1)
            try:
                self._persist_bytes = self._persist_path.stat().st_size
            except OSError:
                self._persist_bytes = 0
            logger.info("[http_logger] persisting to %s", self._persist_path)
        except OSError as exc:
            logger.warning("[http_logger] persistence disabled: %s", exc)
            self._persist_fh = None
            self._persist_path = None

    def _maybe_rotate(self) -> None:
        if not self._persist_path or not self._persist_fh:
            return
        if (self._persist_bytes < self._persist_rotate_at_bytes
                and self._persist_line_count < self._persist_rotate_at_lines):
            return
        try:
            self._persist_fh.close()
        except Exception:
            pass
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        rotated = self.persist_dir / f"requests-{stamp}.jsonl"
        try:
            self._persist_path.rename(rotated)
            logger.info("[http_logger] rotated to %s", rotated.name)
        except OSError as exc:
            logger.warning("[http_logger] rotate failed: %s", exc)
        try:
            self._persist_fh = open(self._persist_path, "a",
                                     encoding="utf-8", buffering=1)
        except OSError:
            self._persist_fh = None
        self._persist_line_count = 0
        self._persist_bytes = 0

    def _persist(self, entry: Dict[str, Any]) -> None:
        if not self._persist_fh:
            return
        try:
            line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
            self._persist_fh.write(line)
            self._persist_line_count += 1
            self._persist_bytes += len(line.encode("utf-8"))
            self._maybe_rotate()
        except Exception as exc:
            logger.debug("[http_logger] persist failed: %s", exc)

    # ═══════════════════════════════════════════════════════════════════
    # Subscribers (SSE)
    # ═══════════════════════════════════════════════════════════════════
    def subscribe(self) -> "queue.Queue[Dict[str, Any]]":
        q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=1000)
        with self._lock:
            self._subscribers.append(q)
        logger.debug("[http_logger] subscriber added (total=%d)",
                     len(self._subscribers))
        return q

    def unsubscribe(self, q: "queue.Queue[Dict[str, Any]]") -> None:
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass
        logger.debug("[http_logger] subscriber removed (total=%d)",
                     len(self._subscribers))

    def _broadcast(self, entry: Dict[str, Any]) -> None:
        # Trim large fields so SSE payloads stay small
        slim = {
            "type": "request",
            "id": entry.get("id"),
            "method": entry.get("method"),
            "path": entry.get("path"),
            "query": entry.get("query"),
            "status": entry.get("status"),
            "ip": entry.get("ip"),
            "scheme": entry.get("scheme"),
            "host": entry.get("host"),
            "timestamp": entry.get("timestamp"),
            "anomalies": entry.get("anomalies", []),
            "tags": entry.get("tags", []),
            "elapsed_ms": entry.get("elapsed_ms"),
        }
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(slim)
            except queue.Full:
                # Drop oldest to make room — subscriber is too slow
                try:
                    q.get_nowait()
                    q.put_nowait(slim)
                except Exception:
                    pass

    # ═══════════════════════════════════════════════════════════════════
    # Anomaly scanning
    # ═══════════════════════════════════════════════════════════════════
    def _scan_anomalies(
        self,
        method: str,
        path: str,
        query: str,
        headers: Dict[str, str],
        body: str,
        status: int,
    ) -> List[Dict[str, str]]:
        # Build a combined "haystack" once
        header_blob = " ".join(f"{k}: {v}" for k, v in headers.items())
        haystack = f"{method} {path}?{query}\n{header_blob}\n{body}"

        findings: List[Dict[str, str]] = []
        seen_labels = set()
        for label, sev, cat, rx in _COMPILED_ANOMALIES:
            if label in seen_labels:
                continue
            m = rx.search(haystack)
            if not m:
                continue
            matched = m.group(0)
            if len(matched) > 80:
                matched = matched[:77] + "..."
            findings.append({
                "label": label,
                "severity": sev,
                "category": cat,
                "matched": matched,
            })
            seen_labels.add(label)

        # Extra: status-based anomaly (5xx from client-generated traffic)
        if 500 <= status < 600:
            findings.append({
                "label": "server_error_5xx",
                "severity": "medium",
                "category": "status",
                "matched": f"HTTP {status}",
            })

        # Sort by severity
        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 9))
        return findings

    # ═══════════════════════════════════════════════════════════════════
    # Entry builder
    # ═══════════════════════════════════════════════════════════════════
    def _build_entry(self, request, response, elapsed_ms: float) -> Dict[str, Any]:
        # ── Client info ───────────────────────────────────────────────
        fwd = request.headers.get("X-Forwarded-For", "")
        ip = fwd.split(",")[0].strip() if fwd else (
            request.headers.get("X-Real-IP") or request.remote_addr or "unknown"
        )

        # ── URL components ────────────────────────────────────────────
        scheme = request.scheme or "http"
        host = request.host or ""
        path = request.path or "/"
        query = request.query_string.decode("utf-8", "replace") if \
            request.query_string else ""

        # ── Body (capped) ─────────────────────────────────────────────
        body_text = ""
        try:
            raw = request.get_data(cache=False, as_text=False) or b""
            if len(raw) > self.max_body_bytes:
                body_text = raw[:self.max_body_bytes].decode("utf-8", "replace") + "…"
            else:
                body_text = raw.decode("utf-8", "replace")
        except Exception:
            body_text = ""

        # ── Response body (capped) ────────────────────────────────────
        resp_body = ""
        try:
            if response is not None and response.direct_passthrough is False:
                raw = response.get_data() or b""
                if len(raw) > self.max_body_bytes:
                    resp_body = raw[:self.max_body_bytes].decode("utf-8", "replace") + "…"
                else:
                    resp_body = raw.decode("utf-8", "replace")
        except Exception:
            resp_body = ""

        # ── Headers (dict, capped to 40 entries) ──────────────────────
        req_headers = {}
        for i, (k, v) in enumerate(request.headers.items()):
            if i >= 40:
                break
            req_headers[k] = v[:500]

        resp_headers = {}
        if response is not None:
            for i, (k, v) in enumerate(response.headers.items()):
                if i >= 40:
                    break
                resp_headers[k] = v[:500]

        # ── Status ────────────────────────────────────────────────────
        status = getattr(response, "status_code", 0) if response else 0

        # ── Anomalies ─────────────────────────────────────────────────
        anomalies = self._scan_anomalies(
            request.method or "GET", path, query,
            req_headers, body_text, status,
        )

        # ── Timestamps ────────────────────────────────────────────────
        now = time.time()

        return {
            "id": uuid.uuid4().hex[:16],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "timestamp_ms": int(now * 1000),
            "elapsed_ms": round(elapsed_ms, 1),

            "method": (request.method or "GET").upper(),
            "scheme": scheme,
            "host": host,
            "path": path,
            "query": query,
            "url": f"{scheme}://{host}{path}" + (f"?{query}" if query else ""),

            "status": status,
            "content_type": (response.headers.get("Content-Type")
                              if response else "") or "",

            "ip": ip,
            "user_agent": request.headers.get("User-Agent", "")[:300],
            "referer": request.headers.get("Referer", "")[:300],

            "headers": req_headers,
            "response_headers": resp_headers,

            "body_preview": body_text[:self.max_body_bytes],
            "response_preview": resp_body[:self.max_body_bytes],

            "content_length": request.content_length or 0,
            "response_length": getattr(response, "content_length", None)
                                if response else 0,

            "anomalies": anomalies,
            "tags": [],
        }

    # ═══════════════════════════════════════════════════════════════════
    # Record
    # ═══════════════════════════════════════════════════════════════════
    def _record(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            self._entries[entry["id"]] = entry
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
                self._total_dropped += 1

            # Aggregates
            self._total_seen += 1
            self._by_method[entry["method"]] = \
                self._by_method.get(entry["method"], 0) + 1
            status_band = f"{entry['status'] // 100}xx" if entry["status"] else "0xx"
            self._by_status[status_band] = self._by_status.get(status_band, 0) + 1
            self._by_ip[entry["ip"]] = self._by_ip.get(entry["ip"], 0) + 1
            self._by_path[entry["path"]] = \
                self._by_path.get(entry["path"], 0) + 1
            for a in entry["anomalies"]:
                key = a["category"]
                self._by_anomaly[key] = self._by_anomaly.get(key, 0) + 1

        self._persist(entry)
        self._broadcast(entry)

    # ═══════════════════════════════════════════════════════════════════
    # Flask integration
    # ═══════════════════════════════════════════════════════════════════
    def attach(self, app) -> None:
        """Register before/after request hooks on a Flask app."""

        # Paths to skip to prevent feedback loops
        skip_prefixes = (
            "/api/logger/",
            "/static/",
            "/favicon.ico",
        )

        def _before():
            try:
                from flask import g, request
                # Skip logger's own endpoints
                p = request.path or ""
                if any(p.startswith(pre) for pre in skip_prefixes):
                    g._http_logger_skip = True
                    return
                g._http_logger_started = time.monotonic()
            except Exception:
                pass

        def _after(response):
            try:
                from flask import g, request
                if getattr(g, "_http_logger_skip", False):
                    return response
                started = getattr(g, "_http_logger_started", None)
                elapsed_ms = 0.0 if started is None else \
                    (time.monotonic() - started) * 1000
                entry = self._build_entry(request, response, elapsed_ms)
                self._record(entry)
            except Exception as exc:
                logger.debug("[http_logger] hook error: %s", exc)
            return response

        app.before_request(_before)
        app.after_request(_after)
        logger.info("[http_logger] attached to Flask app (buffer=%d)",
                     self.max_entries)

    # ═══════════════════════════════════════════════════════════════════
    # Query API
    # ═══════════════════════════════════════════════════════════════════
    def list(
        self,
        page: int = 1,
        size: int = 100,
        q: Optional[str] = None,
        method: Optional[str] = None,
        status_min: Optional[int] = None,
        status_max: Optional[int] = None,
        anomaly: Optional[str] = None,
        tag: Optional[str] = None,
        ip: Optional[str] = None,
        since_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Filtered + paginated query. Returns ``{items, total, page, size}``."""
        page = max(1, int(page))
        size = max(1, min(int(size), 1000))

        with self._lock:
            entries = list(self._entries.values())

        # ── Filters ───────────────────────────────────────────────────
        filtered: List[Dict[str, Any]] = []
        ql = (q or "").lower().strip()
        method_u = (method or "").upper().strip()
        anomaly_l = (anomaly or "").lower().strip()
        tag_l = (tag or "").lower().strip()
        ip_l = (ip or "").lower().strip()

        for e in entries:
            if method_u and e.get("method", "").upper() != method_u:
                continue
            if status_min is not None and (e.get("status") or 0) < status_min:
                continue
            if status_max is not None and (e.get("status") or 0) > status_max:
                continue
            if since_ms is not None and (e.get("timestamp_ms") or 0) < since_ms:
                continue
            if ip_l and ip_l not in (e.get("ip", "").lower()):
                continue
            if anomaly_l:
                hits = [a["category"].lower() for a in e.get("anomalies", [])]
                hits += [a["label"].lower() for a in e.get("anomalies", [])]
                if anomaly_l not in hits:
                    continue
            if tag_l:
                if tag_l not in [t.lower() for t in e.get("tags", [])]:
                    continue
            if ql:
                hay = " ".join([
                    e.get("path", ""),
                    e.get("query", ""),
                    e.get("url", ""),
                    e.get("ip", ""),
                    e.get("user_agent", ""),
                    e.get("referer", ""),
                    json.dumps(e.get("headers", {}), ensure_ascii=False),
                    e.get("body_preview", ""),
                    " ".join(e.get("tags", [])),
                    " ".join(a["label"] for a in e.get("anomalies", [])),
                ]).lower()
                if ql not in hay:
                    continue
            filtered.append(e)

        # Newest first
        filtered.sort(key=lambda x: x.get("timestamp_ms", 0), reverse=True)

        total = len(filtered)
        start = (page - 1) * size
        end = start + size
        page_items = filtered[start:end]

        # Strip bulky fields for list view
        light: List[Dict[str, Any]] = []
        for e in page_items:
            light.append({
                "id": e["id"],
                "timestamp": e["timestamp"],
                "timestamp_ms": e["timestamp_ms"],
                "elapsed_ms": e.get("elapsed_ms"),
                "method": e.get("method"),
                "scheme": e.get("scheme"),
                "host": e.get("host"),
                "path": e.get("path"),
                "query": e.get("query"),
                "url": e.get("url"),
                "status": e.get("status"),
                "ip": e.get("ip"),
                "user_agent": e.get("user_agent"),
                "anomalies": e.get("anomalies", []),
                "tags": e.get("tags", []),
                "content_length": e.get("content_length"),
                "response_length": e.get("response_length"),
                "body_preview": e.get("body_preview", "")[:200],
            })

        return {
            "items": light,
            "total": total,
            "page": page,
            "size": size,
            "pages": max(1, (total + size - 1) // size),
        }

    def get(self, entry_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._entries.get(entry_id)

    def clear(self) -> int:
        with self._lock:
            n = len(self._entries)
            self._entries.clear()
            self._by_method.clear()
            self._by_status.clear()
            self._by_anomaly.clear()
            self._by_ip.clear()
            self._by_path.clear()
        return n

    def tag(self, entry_id: str, tag: str, add: bool = True) -> bool:
        tag = (tag or "").strip()
        if not tag:
            return False
        with self._lock:
            e = self._entries.get(entry_id)
            if not e:
                return False
            tags = e.setdefault("tags", [])
            if add:
                if tag not in tags:
                    tags.append(tag)
            else:
                if tag in tags:
                    tags.remove(tag)
        return True

    # ═══════════════════════════════════════════════════════════════════
    # Stats
    # ═══════════════════════════════════════════════════════════════════
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._total_seen
            buffer_size = len(self._entries)
            dropped = self._total_dropped
            by_method = dict(self._by_method)
            by_status = dict(self._by_status)
            by_anomaly = dict(self._by_anomaly)

            top_ips = sorted(self._by_ip.items(),
                              key=lambda kv: kv[1], reverse=True)[:10]
            top_paths = sorted(self._by_path.items(),
                                key=lambda kv: kv[1], reverse=True)[:10]

            # Compute anomaly severity totals from live entries
            sev_counts: Dict[str, int] = {}
            recent_errors = 0
            now_ms = int(time.time() * 1000)
            for e in self._entries.values():
                for a in e.get("anomalies", []):
                    sev = a.get("severity", "info")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                if now_ms - e.get("timestamp_ms", 0) < 60_000:
                    if 500 <= (e.get("status") or 0) < 600:
                        recent_errors += 1

            # Most recent entry timestamp
            last_ms = max((e.get("timestamp_ms", 0)
                           for e in self._entries.values()), default=0)

        return {
            "total_seen": total,
            "buffer_size": buffer_size,
            "buffer_capacity": self.max_entries,
            "total_dropped": dropped,
            "subscribers": len(self._subscribers),
            "by_method": by_method,
            "by_status": by_status,
            "by_anomaly_category": by_anomaly,
            "by_anomaly_severity": sev_counts,
            "top_ips": [{"ip": k, "count": v} for k, v in top_ips],
            "top_paths": [{"path": k, "count": v} for k, v in top_paths],
            "recent_5xx_last_minute": recent_errors,
            "last_entry_ms": last_ms,
            "version": __version__,
        }

    # ═══════════════════════════════════════════════════════════════════
    # HAR export
    # ═══════════════════════════════════════════════════════════════════
    def to_har(self, items: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        """Convert entries to HAR 1.2 format (importable into DevTools)."""
        entries: List[Dict[str, Any]] = []
        for e in items:
            # Full entry (not the slimmed list version)
            with self._lock:
                full = self._entries.get(e.get("id"))
            src = full or e

            req_headers = [
                {"name": k, "value": str(v)}
                for k, v in (src.get("headers") or {}).items()
            ]
            resp_headers = [
                {"name": k, "value": str(v)}
                for k, v in (src.get("response_headers") or {}).items()
            ]

            # Parse ISO timestamp
            started = src.get("timestamp") or ""
            try:
                t = datetime.fromisoformat(started.replace("Z", "+00:00"))
            except Exception:
                t = datetime.now(timezone.utc)

            elapsed_ms = float(src.get("elapsed_ms") or 0)

            entries.append({
                "startedDateTime": t.isoformat(),
                "time": elapsed_ms,
                "request": {
                    "method": src.get("method", "GET"),
                    "url": src.get("url") or "",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": req_headers,
                    "queryString": self._parse_qs(src.get("query", "")),
                    "postData": {
                        "mimeType": src.get("content_type") or "application/octet-stream",
                        "text": src.get("body_preview", ""),
                    } if src.get("body_preview") else None,
                    "headersSize": -1,
                    "bodySize": int(src.get("content_length") or 0),
                },
                "response": {
                    "status": int(src.get("status") or 0),
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": resp_headers,
                    "content": {
                        "size": int(src.get("response_length") or 0),
                        "mimeType": src.get("content_type") or "application/octet-stream",
                        "text": src.get("response_preview", ""),
                    },
                    "redirectURL": (src.get("response_headers") or {}).get("Location", ""),
                    "headersSize": -1,
                    "bodySize": int(src.get("response_length") or 0),
                },
                "cache": {},
                "timings": {
                    "send": 0,
                    "wait": elapsed_ms,
                    "receive": 0,
                },
                "serverIPAddress": src.get("ip", ""),
                "comment": (f"anomalies: "
                            + ",".join(a["label"]
                                       for a in src.get("anomalies", []))
                            if src.get("anomalies") else ""),
                "_custom": {
                    "id": src.get("id"),
                    "tags": src.get("tags", []),
                    "anomalies": src.get("anomalies", []),
                },
            })

        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "Emergens HTTP Logger",
                    "version": __version__,
                },
                "pages": [],
                "entries": entries,
            }
        }

    @staticmethod
    def _parse_qs(query: str) -> List[Dict[str, str]]:
        if not query:
            return []
        out: List[Dict[str, str]] = []
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
            else:
                k, v = pair, ""
            out.append({"name": k, "value": v})
        return out

    # ═══════════════════════════════════════════════════════════════════
    # Lifecycle
    # ═══════════════════════════════════════════════════════════════════
    def close(self) -> None:
        """Flush and close the persistence handle."""
        with self._lock:
            try:
                if self._persist_fh:
                    self._persist_fh.flush()
                    self._persist_fh.close()
            except Exception:
                pass
            self._persist_fh = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════
# Self-test
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    print(f"http_logger v{__version__}")
    print(f"  anomaly rules  : {len(_COMPILED_ANOMALIES)}")
    print(f"  categories     : "
          f"{sorted(set(a[2] for a in _ANOMALY_PATTERNS))}")

    lg = HttpLogger(max_entries=100, max_body_bytes=4096)
    print(f"  instantiated   : {lg}")
    print(f"  stats (empty)  : {json.dumps(lg.stats(), indent=2)}")
    print()
    print("OK — module loads cleanly.")
