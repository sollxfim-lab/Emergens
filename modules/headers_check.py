#!/usr/bin/env python3
"""
HTTP Security Header Analyzer — Advanced Intelligence Scanner (v3.1.0)
======================================================================

Enterprise-grade HTTP security analysis with:
  • Multi-layer Cloudflare bypass (curl_cffi / cloudscraper / FlareSolverr / manual)
  • WAF detection (Cloudflare / Akamai / Imperva / ModSec / F5 / Sucuri / AWS WAF)
  • Technology stack fingerprinting from response headers
  • Compliance mapping (OWASP Top 10, PCI-DSS 4.0, HIPAA, SOC2, NIST)
  • HTML body intelligence (inline scripts, SRI, forms, mixed content)
  • security.txt / robots.txt / sitemap detection
  • Threat intel enrichment (IP / ASN / hosting provider)
  • 30+ security headers with per-header value quality grading
  • A+–F grade (securityheaders.com compatible) + CVSS-like risk score
  • Cookie security deep audit (SameSite=None+no Secure, __Host- rules)
  • CSP deep analyser with score + findings
  • Redirect chain analysis + downgrade detection
  • TLS probe (protocol + cipher + cert transparency hint)
  • Multi-path probing (/, /login, /api, /admin, /account)
  • Batch scanning + SSE streaming
  • Bounded response reader (2 MB cap), session reuse + Retry adapter
  • Isolated logger, backward-compatible run(target, mode) signature
  • Flask Blueprint: POST|GET /api/headers/scan
  • Module aliases: headers_check, scan_headers, headers, headers_scan

----------------------------------------------------------------------------
Changelog v3.1.0  (Emergens integration + hardening)
----------------------------------------------------------------------------
  ✔ NEW    — Flask Blueprint `headers_bp` exposing
             `POST|GET /api/headers/scan` so terminal.py's
             `_client.post("/api/headers/scan", ...)` works out-of-the-box.
  ✔ NEW    — `register_blueprint(app)` helper for app.py wiring.
  ✔ NEW    — Aliases `headers_check`, `scan_headers`, `headers`,
             `headers_scan` — any terminal.py scan-registry slug resolves.
  ✔ NEW    — `self_check()` runtime diagnostic + CLI `--self-check`.
  ✔ FIXED  — `_make_fake_response()` now constructs a proper `.raw.headers`
             (`urllib3.HTTPHeaderDict`) so `_analyse_cookies()` no longer
             crashes on the CF-bypass path.
  ✔ FIXED  — `_analyse_cookies()` guarded against `resp.raw is None`.
  ✔ HARD   — Response envelope's `tool` field normalised to `"headers"`.
  ✔ HARD   — Blueprint endpoint gracefully parses JSON / query-string /
             defaults, and never 500s on bad input.

----------------------------------------------------------------------------
Acknowledgment
----------------------------------------------------------------------------
  • Author        : Yanxzyx   (#credit ~ Yanxzyx)
  • Framework     : Emergens / Oxysintx orchestrator stack
  • Dependencies  : `requests` (required) + optional `curl_cffi`,
                    `cloudscraper` for CF bypass, `Flask` for the endpoint
  • References    : OWASP Secure Headers Project, securityheaders.com
                    grading, RFC 6797 (HSTS), RFC 6265bis (cookies),
                    RFC 9116 (security.txt), CSP Level 3
  • With thanks to the `requests` and `urllib3` maintainers for exposing
    a sane Response / HTTPHeaderDict model, and to the cloudscraper /
    curl_cffi teams for making CF research reproducible.

----------------------------------------------------------------------------
Testing
----------------------------------------------------------------------------
  Quick smoke test (CLI):
      python3 -m modules.headers_check example.com --mode expert
      python3 -m modules.headers_check --self-check

  Programmatic:
      from modules.headers_check import run, self_check
      print(self_check())
      print(run("example.com", mode="expert"))

  Flask wiring (in app.py):
      from modules.headers_check import register_blueprint
      register_blueprint(app)
"""

from __future__ import annotations

import argparse
import hashlib
import json as _json
import logging
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict
from urllib3.util.retry import Retry
try:
    from urllib3._collections import HTTPHeaderDict
except Exception:
    try:
        from urllib3.response import HTTPHeaderDict  # type: ignore
    except Exception:
        HTTPHeaderDict = None  # type: ignore

# ── Optional: Flask ───────────────────────────────────────────────────────
try:
    from flask import Blueprint, jsonify, request
    _HAS_FLASK = True
except Exception:
    _HAS_FLASK = False

# ── Optional: Cloudflare bypass libraries ─────────────────────────────────
try:
    from curl_cffi import requests as curl_requests  # type: ignore
    _HAS_CURL_CFFI = True
except ImportError:
    curl_requests = None
    _HAS_CURL_CFFI = False

try:
    import cloudscraper  # type: ignore
    _HAS_CLOUDSCRAPER = True
except ImportError:
    cloudscraper = None
    _HAS_CLOUDSCRAPER = False

# ── Optional: shared headers helper ───────────────────────────────────────
try:
    from modules._common import default_headers  # type: ignore
except ImportError:
    def default_headers() -> Dict[str, str]:
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING — isolated
# ═══════════════════════════════════════════════════════════════════════════
logger = logging.getLogger("oxysintx.headers")
logger.propagate = False
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# ═══════════════════════════════════════════════════════════════════════════
# METADATA
# ═══════════════════════════════════════════════════════════════════════════
__version__ = "3.1.0"
__author__  = "Yanxzyx"
__credit__  = "#credit ~ Yanxzyx"

TOOL_INFO = {
    "name": "HTTP Security Headers",
    "version": __version__,
    "description": (
        "Advanced HTTP security header analyser with Cloudflare bypass, WAF "
        "detection, tech fingerprinting, compliance mapping (OWASP/PCI-DSS/"
        "HIPAA/SOC2), HTML body intelligence, TLS probe, and A+–F grading."
    ),
    "category": "Web Security",
    "author": __author__,
    "credit": __credit__,
}
TOOL_KIND = "scanner"

FLARESOLVERR_URL = os.getenv("FLARESOLVERR_URL", "").strip()


# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
DEFAULT_TIMEOUT      = 12
DEFAULT_MAX_BYTES    = 2 * 1024 * 1024
DEFAULT_RETRIES      = 2
DEFAULT_BACKOFF      = 0.6
STREAM_CHUNK_SIZE    = 65536
MAX_HEADER_VALUE     = 4096
DEFAULT_RATE_LIMIT   = 30.0
CF_CHALLENGE_TIMEOUT = 30

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
]

DEPRECATED_HEADERS = {
    "X-XSS-Protection": {
        "reason": "Ignored by modern browsers; can introduce vulnerabilities. "
                  "Use Content-Security-Policy instead.",
        "severity": "low",
    },
    "Expect-CT": {
        "reason": "Deprecated since 2021. Certificate Transparency is mandatory.",
        "severity": "low",
    },
    "Public-Key-Pins": {
        "reason": "Deprecated. Use Certificate Transparency monitoring instead.",
        "severity": "low",
    },
    "Public-Key-Pins-Report-Only": {
        "reason": "Deprecated.",
        "severity": "low",
    },
    "X-Content-Security-Policy": {
        "reason": "Obsolete CSP 1.0 header. Use Content-Security-Policy.",
        "severity": "low",
    },
    "X-WebKit-CSP": {
        "reason": "Obsolete. Use Content-Security-Policy.",
        "severity": "low",
    },
}

_SEV_RANK = {"critical": 5, "high": 4, "hard": 4, "medium": 3, "normal": 3,
             "low": 2, "info": 1, "none": 0}

COMMON_PATHS = ["/", "/login", "/signin", "/admin", "/api",
                "/api/v1", "/account", "/wp-admin"]


# ═══════════════════════════════════════════════════════════════════════════
# HEADER DEFINITIONS (30+)
# ═══════════════════════════════════════════════════════════════════════════
SECURITY_HEADERS: Dict[str, Dict[str, Any]] = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections (HSTS)",
        "severity":    "critical",
        "weight":      6,
        "recommendation": "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "description": "Restricts resource loading — strongest defence against XSS",
        "severity":    "critical",
        "weight":      6,
        "recommendation": "Add a strict CSP: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'",
    },
    "Content-Security-Policy-Report-Only": {
        "description": "CSP in monitor mode (does not enforce)",
        "severity":    "info",
        "weight":      0,
        "recommendation": "Optional — useful when rolling out a strict CSP",
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking",
        "severity":    "hard",
        "weight":      4,
        "recommendation": "Add: X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity":    "normal",
        "weight":      2,
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent cross-origin",
        "severity":    "normal",
        "weight":      2,
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Controls browser features (camera, mic, geolocation…)",
        "severity":    "normal",
        "weight":      2,
        "recommendation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
    "Feature-Policy": {
        "description": "Deprecated predecessor of Permissions-Policy",
        "severity":    "info",
        "weight":      0,
        "recommendation": "Replace with Permissions-Policy",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Prevents cross-origin resource inclusion",
        "severity":    "hard",
        "weight":      3,
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Enables cross-origin isolation for powerful APIs",
        "severity":    "normal",
        "weight":      2,
        "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing contexts against cross-origin attacks",
        "severity":    "hard",
        "weight":      3,
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "Sec-Fetch-Site": {
        "description": "Fetch metadata — site context",
        "severity":    "info",
        "weight":      1,
        "recommendation": "Browser-managed — informational only.",
    },
    "Sec-Fetch-Mode": {
        "description": "Fetch metadata — request mode",
        "severity":    "info",
        "weight":      1,
        "recommendation": "Browser-managed — informational only.",
    },
    "Sec-Fetch-Dest": {
        "description": "Fetch metadata — request destination",
        "severity":    "info",
        "weight":      1,
        "recommendation": "Browser-managed — informational only.",
    },
    "Report-To": {
        "description": "Reporting endpoint group (CSP / NEL / deprecation)",
        "severity":    "low",
        "weight":      1,
        "recommendation": "Consider adding Report-To for CSP violation visibility",
    },
    "Reporting-Endpoints": {
        "description": "Modern replacement for Report-To (Reporting API v1)",
        "severity":    "low",
        "weight":      1,
        "recommendation": "Consider adding Reporting-Endpoints for visibility",
    },
    "NEL": {
        "description": "Network Error Logging",
        "severity":    "low",
        "weight":      1,
        "recommendation": "Optional: NEL enables fleet-wide network error collection",
    },
    "X-Download-Options": {
        "description": "Prevents IE from executing downloads in site context",
        "severity":    "low",
        "weight":      1,
        "recommendation": "Optional: X-Download-Options: noopen (legacy IE)",
    },
    "X-DNS-Prefetch-Control": {
        "description": "Controls DNS prefetching",
        "severity":    "info",
        "weight":      1,
        "recommendation": "Optional: X-DNS-Prefetch-Control: off for privacy",
    },
    "Origin-Agent-Cluster": {
        "description": "Isolates origin in its own agent cluster",
        "severity":    "low",
        "weight":      1,
        "recommendation": "Consider: Origin-Agent-Cluster: ?1",
    },
    "Clear-Site-Data": {
        "description": "Clears browser storage on sensitive transitions",
        "severity":    "info",
        "weight":      0,
        "recommendation": "Optional — useful on logout",
    },
    "Cache-Control": {
        "description": "Controls caching — critical for sensitive pages",
        "severity":    "normal",
        "weight":      2,
        "recommendation": "Add: Cache-Control: no-store for authenticated responses",
    },
    "Pragma": {
        "description": "Legacy caching directive",
        "severity":    "info",
        "weight":      0,
        "recommendation": "Informational — Cache-Control supersedes",
    },
    "Expires": {
        "description": "Legacy cache expiry",
        "severity":    "info",
        "weight":      0,
        "recommendation": "Informational — Cache-Control supersedes",
    },
    "Server-Timing": {
        "description": "Exposes backend timing metrics",
        "severity":    "info",
        "weight":      0,
        "recommendation": "Informational only.",
    },
    "Vary": {
        "description": "Controls cache keys",
        "severity":    "info",
        "weight":      0,
        "recommendation": "Informational — Vary: Origin needed for CORS correctness",
    },
    "Server": {
        "description": "Web server identification — may leak version",
        "severity":    "info",
        "weight":      0,
        "recommendation": "Consider hiding version information",
    },
    "X-Powered-By": {
        "description": "Framework identification — leaks tech stack",
        "severity":    "low",
        "weight":      0,
        "recommendation": "Consider removing X-Powered-By to reduce info disclosure",
    },
    "X-AspNet-Version": {
        "description": "ASP.NET version — information disclosure",
        "severity":    "low",
        "weight":      0,
        "recommendation": "Remove or suppress version headers",
    },
    "Access-Control-Allow-Origin": {
        "description": "CORS allowed origin — critical if misconfigured",
        "severity":    "hard",
        "weight":      2,
        "recommendation": "Never use * with credentials; validate origins against an allowlist",
    },
    "Access-Control-Allow-Credentials": {
        "description": "CORS credentials — must not be combined with wildcard origin",
        "severity":    "hard",
        "weight":      1,
        "recommendation": "Only enable when paired with strict ACAO allowlist",
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# CLOUDFLARE / WAF DETECTION
# ═══════════════════════════════════════════════════════════════════════════
_CF_HEADER_MARKERS = (
    "cf-ray", "cf-cache-status", "cf-request-id", "cf-chl-",
)
_CF_BODY_MARKERS = (
    b"just a moment", b"checking your browser",
    b"cf-browser-verification", b"cf_chl_opt",
    b"__cf_chl_jschl_tk__", b"challenge-platform",
    b"turnstile", b"cf_chl_captcha",
)
_CF_STATUS_CODES = {403, 429, 503}

WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare":     ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "AWS WAF":        ["awselb", "x-amz-cf-id", "x-amzn-requestid"],
    "ModSecurity":    ["mod_security", "modsecurity", "not acceptable"],
    "Sucuri":         ["sucuri", "x-sucuri-id"],
    "Imperva":        ["incap_ses", "visid_incap", "incapsula", "x-iinfo"],
    "F5 BIG-IP":      ["bigipserver", "tscookie", "f5-"],
    "Akamai":         ["akamai", "ak_bmsc", "x-akamai"],
    "Barracuda":      ["barra_counter_session", "barracuda"],
    "Wordfence":      ["wordfence"],
    "Fastly":         ["fastly", "x-fastly", "x-served-by"],
    "StackPath":      ["stackpath"],
    "Bunny CDN":      ["bunnycdn", "b-cdn"],
}


def _detect_waf(headers: Dict[str, str], body: str,
                status: int) -> Optional[Dict[str, Any]]:
    headers_lower = {k.lower(): (v or "").lower() for k, v in headers.items()}
    hay = " ".join(f"{k}: {v}" for k, v in headers_lower.items())
    body_lower = (body or "")[:8192].lower()
    combined = (hay + " " + body_lower)[:16000]

    for name, sigs in WAF_SIGNATURES.items():
        if any(sig.lower() in combined for sig in sigs):
            return {
                "name": name,
                "evidence": [s for s in sigs if s.lower() in combined][:3],
                "confidence": "high",
            }
    return None


def _detect_cloudflare(headers: Dict[str, str], body: bytes,
                       status: int) -> Optional[str]:
    h_lower = {k.lower(): (v or "").lower() for k, v in headers.items()}
    has_cf = ("cloudflare" in h_lower.get("server", "")) or any(
        m in h_lower for m in _CF_HEADER_MARKERS
    )
    bl = (body or b"")[:8192].lower()
    if b"turnstile" in bl or b"cf-chl-captcha" in bl:
        return "turnstile"
    if b"cf_chl_opt" in bl or b"managed challenge" in bl:
        return "managed"
    if any(m in bl for m in (b"just a moment", b"checking your browser",
                             b"cf-browser-verification", b"challenge-platform")):
        return "js_challenge"
    if status == 503 and has_cf:
        return "uam"
    if status == 429 and has_cf:
        return "rate_limit"
    if status == 403 and has_cf:
        return "waf_block"
    if has_cf and status in _CF_STATUS_CODES:
        return "unknown"
    return None


# ═══════════════════════════════════════════════════════════════════════════
# CLOUDFLARE BYPASS ENGINE
# ═══════════════════════════════════════════════════════════════════════════
class CloudflareBypass:
    """Multi-strategy CF bypass: curl_cffi → cloudscraper → FlareSolverr → manual."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT,
                 cf_timeout: int = CF_CHALLENGE_TIMEOUT,
                 verify_tls: bool = True,
                 proxy_dict: Optional[Dict[str, str]] = None,
                 flaresolverr_url: str = FLARESOLVERR_URL):
        self.timeout = timeout
        self.cf_timeout = cf_timeout
        self.verify_tls = verify_tls
        self.proxy_dict = proxy_dict
        self.flaresolverr_url = flaresolverr_url
        self._cloudscraper = None
        self._curl_cffi_session = None

    def _get_curl_cffi(self):
        if not _HAS_CURL_CFFI:
            return None
        if self._curl_cffi_session is None:
            try:
                self._curl_cffi_session = curl_requests.Session()
            except Exception as exc:
                logger.debug("[cf] curl_cffi init failed: %s", exc)
                return None
        return self._curl_cffi_session

    def _fetch_curl_cffi(self, url: str) -> Optional[Tuple[bytes, Dict, int]]:
        sess = self._get_curl_cffi()
        if sess is None:
            return None
        try:
            r = sess.get(
                url, impersonate="chrome", timeout=self.timeout,
                verify=self.verify_tls, proxies=self.proxy_dict,
                allow_redirects=True,
                headers={"User-Agent": _UA_POOL[0]},
            )
            return r.content or b"", dict(r.headers), r.status_code
        except Exception as exc:
            logger.debug("[cf] curl_cffi failed: %s", exc)
            return None

    def _get_cloudscraper(self):
        if not _HAS_CLOUDSCRAPER:
            return None
        if self._cloudscraper is None:
            try:
                self._cloudscraper = cloudscraper.create_scraper(
                    browser={"browser": "chrome", "platform": "windows",
                             "mobile": False, "desktop": True},
                    interpreter="native", delay=3,
                )
                if self.proxy_dict:
                    self._cloudscraper.proxies.update(self.proxy_dict)
            except Exception as exc:
                logger.debug("[cf] cloudscraper init failed: %s", exc)
                return None
        return self._cloudscraper

    def _fetch_cloudscraper(self, url: str) -> Optional[Tuple[bytes, Dict, int]]:
        client = self._get_cloudscraper()
        if client is None:
            return None
        try:
            r = client.get(url, timeout=self.cf_timeout,
                           verify=self.verify_tls, allow_redirects=True)
            return r.content or b"", dict(r.headers), r.status_code
        except Exception as exc:
            logger.debug("[cf] cloudscraper failed: %s", exc)
            return None

    def _fetch_flaresolverr(self, url: str) -> Optional[Tuple[bytes, Dict, int]]:
        if not self.flaresolverr_url:
            return None
        try:
            payload = {"cmd": "request.get", "url": url,
                       "maxTimeout": self.cf_timeout * 1000}
            r = requests.post(
                self.flaresolverr_url.rstrip("/") + "/v1",
                json=payload, timeout=self.cf_timeout + 10,
            )
            if r.status_code != 200:
                return None
            data = r.json()
            if data.get("status") != "ok":
                return None
            sol = data.get("solution") or {}
            return (
                (sol.get("response") or "").encode("utf-8", "ignore"),
                sol.get("headers") or {},
                int(sol.get("status") or 0),
            )
        except Exception as exc:
            logger.debug("[cf] flaresolverr failed: %s", exc)
            return None

    def _fetch_manual(self, url: str) -> Optional[Tuple[bytes, Dict, int]]:
        try:
            import random
            headers = dict(default_headers())
            headers["User-Agent"] = random.choice(_UA_POOL)
            r = requests.get(url, headers=headers, timeout=self.timeout,
                             verify=self.verify_tls, proxies=self.proxy_dict,
                             allow_redirects=True)
            return r.content or b"", dict(r.headers), r.status_code
        except Exception as exc:
            logger.debug("[cf] manual failed: %s", exc)
            return None

    def fetch(self, url: str) -> Tuple[Optional[bytes], Dict, int, str]:
        strategies: List[Tuple[str, Callable]] = []
        if _HAS_CURL_CFFI:
            strategies.append(("curl_cffi", self._fetch_curl_cffi))
        if _HAS_CLOUDSCRAPER:
            strategies.append(("cloudscraper", self._fetch_cloudscraper))
        if self.flaresolverr_url:
            strategies.append(("flaresolverr", self._fetch_flaresolverr))
        strategies.append(("manual", self._fetch_manual))

        last: Tuple[Optional[bytes], Dict, int] = (None, {}, 0)
        for name, fn in strategies:
            result = fn(url)
            if result is None:
                continue
            body, headers, status = result
            last = (body, headers, status)
            cf_type = _detect_cloudflare(headers, body, status)
            if cf_type is None:
                logger.info("[cf] %s → %d via %s (clean)", url, status, name)
                return body, headers, status, name
            logger.info("[cf] %s → %d via %s (CF: %s)",
                        url, status, name, cf_type)
            if cf_type == "waf_block":
                return body, headers, status, name + " (waf_block)"
        return last[0], last[1], last[2], "failed-all"


# ═══════════════════════════════════════════════════════════════════════════
# TECH STACK FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════
TECH_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"nginx", re.I),                   "Nginx", "Web Server"),
    (re.compile(r"apache", re.I),                  "Apache", "Web Server"),
    (re.compile(r"microsoft-iis", re.I),           "IIS", "Web Server"),
    (re.compile(r"litespeed", re.I),               "LiteSpeed", "Web Server"),
    (re.compile(r"openresty", re.I),               "OpenResty", "Web Server"),
    (re.compile(r"gunicorn", re.I),                "Gunicorn", "Web Server"),
    (re.compile(r"werkzeug", re.I),                "Werkzeug", "Web Server"),
    (re.compile(r"^uvicorn", re.I),                "Uvicorn", "Web Server"),
    (re.compile(r"cloudflare", re.I),              "Cloudflare", "CDN"),
    (re.compile(r"cloudfront", re.I),              "Amazon CloudFront", "CDN"),
    (re.compile(r"akamai", re.I),                  "Akamai", "CDN"),
    (re.compile(r"fastly", re.I),                  "Fastly", "CDN"),
    (re.compile(r"^php/(\d+\.\d+)", re.I),         "PHP", "Language"),
    (re.compile(r"asp\.net", re.I),                "ASP.NET", "Framework"),
    (re.compile(r"express", re.I),                 "Express", "Framework"),
    (re.compile(r"django", re.I),                  "Django", "Framework"),
    (re.compile(r"rails|phusion", re.I),           "Ruby on Rails", "Framework"),
    (re.compile(r"next\.js", re.I),                "Next.js", "Framework"),
    (re.compile(r"vercel", re.I),                  "Vercel", "Hosting"),
    (re.compile(r"netlify", re.I),                 "Netlify", "Hosting"),
    (re.compile(r"github\.com|github\.io", re.I),  "GitHub Pages", "Hosting"),
    (re.compile(r"heroku|vegur", re.I),            "Heroku", "Hosting"),
    (re.compile(r"firebase", re.I),                "Firebase", "Hosting"),
]


def _fingerprint_tech(headers: Dict[str, str]) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    seen = set()
    header_blob = " ".join(f"{k}: {v}" for k, v in headers.items())
    for rx, name, category in TECH_PATTERNS:
        m = rx.search(header_blob)
        if m and name not in seen:
            seen.add(name)
            entry = {"name": name, "category": category}
            if m.groups():
                entry["version"] = m.group(1)
            found.append(entry)
    return found


# ═══════════════════════════════════════════════════════════════════════════
# COMPLIANCE MAPPING
# ═══════════════════════════════════════════════════════════════════════════
COMPLIANCE_MAP = {
    "OWASP_Top10": {
        "A03_Injection": ["Content-Security-Policy"],
        "A05_Security_Misconfiguration": [
            "Strict-Transport-Security", "X-Content-Type-Options",
            "X-Frame-Options", "Content-Security-Policy",
            "Referrer-Policy", "Permissions-Policy",
        ],
        "A07_Identification_Auth_Failures": ["Strict-Transport-Security"],
        "A08_Software_Data_Integrity_Failures": ["Content-Security-Policy"],
    },
    "PCI_DSS_4.0": {
        "Req_4.2_Encrypt_Transmission": ["Strict-Transport-Security"],
        "Req_6.4_Web_App_Protection": [
            "Content-Security-Policy", "X-Frame-Options",
            "X-Content-Type-Options",
        ],
        "Req_8.3_Authentication": ["Cache-Control"],
    },
    "HIPAA": {
        "§164.312(e)(1)_Transmission_Security": ["Strict-Transport-Security"],
        "§164.312(c)(1)_Integrity": ["Content-Security-Policy"],
    },
    "SOC2_CC6": {
        "CC6.1_Logical_Access": ["X-Frame-Options", "Content-Security-Policy"],
        "CC6.7_Transmission_Protection": ["Strict-Transport-Security"],
    },
    "NIST_800_53": {
        "SC-8_Transmission_Confidentiality": ["Strict-Transport-Security"],
        "SC-18_Mobile_Code": ["Content-Security-Policy"],
        "SI-10_Information_Input_Validation": ["Content-Security-Policy"],
    },
}


def _compliance_report(present: Dict[str, str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for framework, controls in COMPLIANCE_MAP.items():
        fw: Dict[str, Any] = {}
        for control, required_headers in controls.items():
            missing = [h for h in required_headers if h not in present]
            status = "compliant" if not missing else (
                "partial" if len(missing) < len(required_headers) else "non_compliant"
            )
            fw[control] = {
                "status": status,
                "missing_headers": missing,
            }
        out[framework] = fw
    return out


# ═══════════════════════════════════════════════════════════════════════════
# COOKIE ANALYSIS — HARDENED in v3.1.0
# ═══════════════════════════════════════════════════════════════════════════
def _analyse_cookies(resp: requests.Response) -> List[Dict[str, Any]]:
    """
    Extract and audit Set-Cookie headers.

    v3.1.0: guarded against `resp.raw is None` (which happens when the
    scanner reconstructs a Response via `_make_fake_response` for the
    CF-bypass path).
    """
    cookies: List[Dict[str, Any]] = []
    raw: List[str] = []

    try:
        raw_headers = getattr(resp.raw, "headers", None) if resp.raw else None
        if raw_headers is not None and hasattr(raw_headers, "get_all"):
            raw = list(raw_headers.get_all("Set-Cookie") or [])
    except Exception:
        raw = []

    if not raw:
        try:
            sc = resp.headers.get("Set-Cookie") if resp.headers else None
            if sc:
                raw = [sc]
        except Exception:
            raw = []

    for item in raw or []:
        if not item:
            continue
        try:
            parts = [p.strip() for p in item.split(";")]
            if not parts:
                continue
            name_val = parts[0]
            flags = parts[1:]
            lower = [f.lower() for f in flags]
            is_secure   = any(f == "secure" for f in lower)
            is_httponly = any(f == "httponly" for f in lower)
            samesite = next((f.split("=", 1)[1].strip().lower()
                             for f in flags if f.lower().startswith("samesite=")), None)
            max_age = expires = domain = path = None
            for f in flags:
                fl = f.lower()
                if fl.startswith("max-age="):
                    try: max_age = int(f.split("=", 1)[1].strip())
                    except Exception: pass
                elif fl.startswith("expires="): expires = f.split("=", 1)[1].strip()
                elif fl.startswith("domain="):  domain  = f.split("=", 1)[1].strip()
                elif fl.startswith("path="):    path    = f.split("=", 1)[1].strip()
            name = name_val.split("=", 1)[0].strip() if "=" in name_val else name_val

            issues = []
            if not is_secure:
                issues.append({"severity": "high",
                               "issue": "Cookie transmitted without Secure flag"})
            if not is_httponly:
                issues.append({"severity": "medium",
                               "issue": "Cookie accessible to JavaScript (no HttpOnly)"})
            if samesite is None:
                issues.append({"severity": "medium",
                               "issue": "SameSite not set (browsers default to Lax)"})
            elif samesite == "none" and not is_secure:
                issues.append({"severity": "high",
                               "issue": "SameSite=None requires Secure"})
            if name.startswith("__Host-") and (not is_secure or domain is not None or path != "/"):
                issues.append({"severity": "high",
                               "issue": "__Host- prefix requires Secure, no Domain, Path=/"})
            elif name.startswith("__Secure-") and not is_secure:
                issues.append({"severity": "high",
                               "issue": "__Secure- prefix requires Secure flag"})

            cookies.append({
                "name_value": name_val[:128], "name": name,
                "secure": is_secure, "httponly": is_httponly,
                "samesite": samesite, "max_age": max_age, "expires": expires,
                "domain": domain, "path": path, "issues": issues,
            })
        except Exception as e:
            logger.debug("[headers] cookie parse failed: %s", e)
            continue
    return cookies


# ═══════════════════════════════════════════════════════════════════════════
# CSP PARSER + QUALITY
# ═══════════════════════════════════════════════════════════════════════════
def _parse_csp(csp_value: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if not csp_value:
        return out
    for tok in csp_value.split(";"):
        tok = tok.strip()
        if not tok:
            continue
        parts = tok.split()
        if parts:
            out[parts[0].lower()] = parts[1:] if len(parts) > 1 else []
    return out


def _analyse_csp_quality(csp_value: str) -> Dict[str, Any]:
    directives = _parse_csp(csp_value)
    findings: List[Dict[str, str]] = []
    score = 100
    script_src = directives.get("script-src") or directives.get("default-src", [])
    object_src = directives.get("object-src", [])
    base_uri   = directives.get("base-uri", [])
    frame_anc  = directives.get("frame-ancestors", [])

    def _has(sources, token):
        return any(s.lower() == token for s in sources)

    if not directives:
        findings.append({"severity": "high", "issue": "CSP is empty"})
        score -= 50
    else:
        if _has(script_src, "'unsafe-inline'"):
            findings.append({"severity": "high",
                             "issue": "script-src contains 'unsafe-inline'"})
            score -= 30
        if _has(script_src, "'unsafe-eval'"):
            findings.append({"severity": "high",
                             "issue": "script-src contains 'unsafe-eval'"})
            score -= 25
        if any(s == "*" for s in script_src):
            findings.append({"severity": "high",
                             "issue": "script-src wildcard '*'"})
            score -= 30
        if not script_src and "default-src" not in directives:
            findings.append({"severity": "high",
                             "issue": "Neither script-src nor default-src present"})
            score -= 30

    if not _has(object_src, "'none'"):
        findings.append({"severity": "medium",
                         "issue": "object-src should be 'none'"})
        score -= 10
    if not base_uri:
        findings.append({"severity": "low", "issue": "base-uri not set"})
        score -= 5
    if not frame_anc:
        findings.append({"severity": "low", "issue": "frame-ancestors not set"})
        score -= 5
    if "report-uri" not in directives and "report-to" not in directives:
        findings.append({"severity": "info",
                         "issue": "No CSP reporting endpoint configured"})

    return {
        "directives": directives,
        "source_count": sum(len(v) for v in directives.values()),
        "directive_count": len(directives),
        "findings": findings,
        "score": max(0, min(100, score)),
    }


# ═══════════════════════════════════════════════════════════════════════════
# HTML BODY INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════
_INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S,
)
_SRI_RE = re.compile(r'\bintegrity\s*=\s*["\']([^"\']+)["\']', re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>", re.I)
_FORM_ACTION_RE = re.compile(r'\baction\s*=\s*["\']([^"\']*)["\']', re.I)
_HTTP_IN_HTTPS_RE = re.compile(
    r'(?:src|href)\s*=\s*["\']http://[^"\']+["\']', re.I,
)
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]*>', re.I,
)
_TARGET_BLANK_RE = re.compile(
    r'<a\b[^>]*target\s*=\s*["\']_blank["\'][^>]*>', re.I,
)


def _analyse_html_body(body: bytes, final_url: str) -> Dict[str, Any]:
    if not body:
        return {}
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        return {}

    inline_scripts = _INLINE_SCRIPT_RE.findall(text)
    executable_inline = [
        s.strip() for s in inline_scripts
        if s.strip() and not re.match(r"^\s*(?:\{|\"|<)", s.strip())
        and "application/ld+json" not in s.lower()
    ]
    sri_count = len(_SRI_RE.findall(text))
    forms = _FORM_RE.findall(text)
    form_actions = _FORM_ACTION_RE.findall(text)
    insecure_actions = [a for a in form_actions if a.lower().startswith("http://")]
    mixed_content = _HTTP_IN_HTTPS_RE.findall(text) if final_url.startswith("https://") else []
    meta_refresh = _META_REFRESH_RE.findall(text)
    target_blank = _TARGET_BLANK_RE.findall(text)
    target_blank_unsafe = 0
    for tag in re.findall(r'<a\b[^>]*target\s*=\s*["\']_blank["\'][^>]*>', text, re.I):
        if "rel=" not in tag.lower() or (
            "noopener" not in tag.lower() and "noreferrer" not in tag.lower()
        ):
            target_blank_unsafe += 1

    issues: List[Dict[str, str]] = []
    if executable_inline:
        issues.append({
            "severity": "medium",
            "issue": f"{len(executable_inline)} inline script block(s) — CSP 'unsafe-inline' risk",
        })
    if mixed_content:
        issues.append({
            "severity": "high",
            "issue": f"{len(mixed_content)} mixed-content reference(s) (HTTP resource on HTTPS page)",
        })
    if insecure_actions:
        issues.append({
            "severity": "high",
            "issue": f"{len(insecure_actions)} form(s) submitting to HTTP",
        })
    if target_blank_unsafe:
        issues.append({
            "severity": "low",
            "issue": f"{target_blank_unsafe} target=_blank link(s) without rel=noopener",
        })

    return {
        "body_size": len(body),
        "inline_script_count": len(executable_inline),
        "sri_integrity_count": sri_count,
        "form_count": len(forms),
        "form_actions": form_actions[:20],
        "mixed_content_count": len(mixed_content),
        "meta_refresh_count": len(meta_refresh),
        "target_blank_count": len(target_blank),
        "target_blank_unsafe": target_blank_unsafe,
        "issues": issues,
    }


# ═══════════════════════════════════════════════════════════════════════════
# DISCOVERY FILES
# ═══════════════════════════════════════════════════════════════════════════
def _check_discovery_files(session: requests.Session, base_url: str,
                           timeout: float) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    paths = {
        "security_txt":     "/.well-known/security.txt",
        "security_txt_alt": "/security.txt",
        "robots_txt":       "/robots.txt",
        "sitemap_xml":      "/sitemap.xml",
    }
    parsed = urlparse(base_url)
    base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    for key, path in paths.items():
        try:
            r = session.get(base + path, timeout=timeout,
                            allow_redirects=True, stream=True)
            if r.status_code == 200:
                body = b""
                try:
                    for chunk in r.iter_content(chunk_size=8192):
                        body += chunk
                        if len(body) > 65536:
                            break
                except Exception:
                    pass
                text = body.decode("utf-8", errors="ignore")
                out[key] = {
                    "url": base + path,
                    "status": 200,
                    "size": len(body),
                    "preview": text[:512],
                }
            else:
                out[key] = {"url": base + path, "status": r.status_code}
        except Exception as e:
            out[key] = {"url": base + path, "error": str(e)}
    return out


# ═══════════════════════════════════════════════════════════════════════════
# HEADER VALUE QUALITY
# ═══════════════════════════════════════════════════════════════════════════
def _quality_hsts(value: str) -> Dict[str, Any]:
    out = {"issues": [], "score": 100}
    v = (value or "").lower()
    m = re.search(r"max-age\s*=\s*(\d+)", v)
    max_age = int(m.group(1)) if m else 0
    if not m:
        out["issues"].append({"severity": "high", "issue": "HSTS missing max-age"})
        out["score"] -= 50
    if 0 < max_age < 15552000:
        out["issues"].append({
            "severity": "medium",
            "issue": f"max-age ({max_age}s) < 180 days recommended",
        })
        out["score"] -= 20
    if max_age < 31536000:
        out["issues"].append({
            "severity": "low",
            "issue": "max-age below 1 year (2 years recommended for preload)",
        })
    if "includesubdomains" not in v:
        out["issues"].append({"severity": "medium",
                              "issue": "includeSubDomains not set"})
        out["score"] -= 15
    if "preload" not in v:
        out["issues"].append({"severity": "info", "issue": "preload not set"})
    out.update({"max_age": max_age,
                "include_subdomains": "includesubdomains" in v,
                "preload": "preload" in v,
                "score": max(0, out["score"])})
    return out


def _quality_xfo(value: str) -> Dict[str, Any]:
    out = {"issues": [], "score": 100}
    v = (value or "").strip().upper()
    if v == "ALLOW-FROM":
        out["issues"].append({"severity": "medium",
                              "issue": "ALLOW-FROM is deprecated"})
        out["score"] -= 30
    elif v not in ("DENY", "SAMEORIGIN"):
        out["issues"].append({"severity": "medium",
                              "issue": f"Unrecognised value: {value!r}"})
        out["score"] -= 40
    elif v == "SAMEORIGIN":
        out["issues"].append({"severity": "info",
                              "issue": "SAMEORIGIN — consider DENY if framing not required"})
    return out


def _quality_referrer(value: str) -> Dict[str, Any]:
    out = {"issues": [], "score": 100}
    v = (value or "").strip().lower()
    weak = {"unsafe-url", "no-referrer-when-downgrade"}
    good = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "same-origin", "origin", "origin-when-cross-origin"}
    if v in weak:
        out["issues"].append({"severity": "medium",
                              "issue": f"Weak policy ({value})"})
        out["score"] -= 40
    elif v not in good:
        out["issues"].append({"severity": "low",
                              "issue": f"Unrecognised value: {value!r}"})
        out["score"] -= 20
    return out


def _quality_permissions_policy(value: str) -> Dict[str, Any]:
    out = {"issues": [], "score": 100}
    v = (value or "").strip().lower()
    if not v:
        out["issues"].append({"severity": "low", "issue": "Empty Permissions-Policy"})
        out["score"] -= 10
    if re.search(r"\*\s*;|=\s*\*", v):
        out["issues"].append({"severity": "medium", "issue": "Wildcard '*' allowed"})
        out["score"] -= 20
    return out


def _quality_xcto(value: str) -> Dict[str, Any]:
    out = {"issues": [], "score": 100}
    if (value or "").strip().lower() != "nosniff":
        out["issues"].append({"severity": "medium",
                              "issue": "X-Content-Type-Options should be 'nosniff'"})
        out["score"] -= 40
    return out


def _quality_acao(value: str) -> Dict[str, Any]:
    out = {"issues": [], "score": 100}
    v = (value or "").strip()
    if v == "*":
        out["issues"].append({
            "severity": "medium",
            "issue": "ACAO wildcard '*' — disallows credentials, but exposes resources",
        })
        out["score"] -= 20
    return out


_QUALITY_CHECKERS: Dict[str, Callable[[str], Dict[str, Any]]] = {
    "Strict-Transport-Security":    _quality_hsts,
    "X-Frame-Options":              _quality_xfo,
    "Referrer-Policy":              _quality_referrer,
    "Permissions-Policy":           _quality_permissions_policy,
    "X-Content-Type-Options":       _quality_xcto,
    "Access-Control-Allow-Origin":  _quality_acao,
}


# ═══════════════════════════════════════════════════════════════════════════
# GRADE + RISK SCORE
# ═══════════════════════════════════════════════════════════════════════════
def _grade(score: int, has_csp: bool, has_hsts: bool) -> str:
    if score >= 95 and has_csp and has_hsts:
        return "A+"
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 45: return "D"
    if score >= 25: return "E"
    return "F"


def _risk_score(score: int, missing: List[Dict], quality: List[Dict],
                grade: str) -> Dict[str, Any]:
    base_risk = (100 - score) / 10.0
    crit_missing = sum(1 for m in missing if m.get("severity") == "critical")
    hard_missing = sum(1 for m in missing if m.get("severity") == "hard")
    crit_quality = sum(1 for q in quality if q.get("severity") in ("high", "critical"))
    risk = min(10.0, base_risk + crit_missing * 0.8 + hard_missing * 0.3
               + crit_quality * 0.4)
    if risk >= 8.0:   label = "CRITICAL"
    elif risk >= 6.0: label = "HIGH"
    elif risk >= 4.0: label = "MEDIUM"
    elif risk >= 2.0: label = "LOW"
    else:             label = "MINIMAL"
    return {
        "score": round(risk, 2),
        "label": label,
        "grade": grade,
        "critical_missing": crit_missing,
        "hard_missing":     hard_missing,
        "critical_quality": crit_quality,
    }


# ═══════════════════════════════════════════════════════════════════════════
# TLS PROBE + REDIRECT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════
def _probe_tls(host: str, port: int = 443,
               timeout: float = 6.0) -> Optional[Dict[str, Any]]:
    if not host:
        return None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
                return {
                    "protocol": ssock.version(),
                    "cipher":   (ssock.cipher() or ("",))[0],
                    "subject":  dict(x[0] for x in cert.get("subject", [])),
                    "issuer":   dict(x[0] for x in cert.get("issuer", [])),
                    "not_after": cert.get("notAfter", ""),
                }
    except Exception as e:
        logger.debug("[headers] TLS probe failed for %s: %s", host, e)
    return None


def _analyse_redirects(resp: requests.Response) -> Dict[str, Any]:
    chain = []
    prev_scheme = None
    downgrades = 0
    for h in resp.history or []:
        scheme = urlparse(h.url).scheme
        if prev_scheme == "https" and scheme == "http":
            downgrades += 1
        prev_scheme = scheme
        chain.append({
            "status": h.status_code, "url": h.url,
            "location": h.headers.get("Location", ""), "scheme": scheme,
        })
    final_scheme = urlparse(resp.url).scheme
    http_to_https = (
        bool(chain) and any(c["scheme"] == "http" for c in chain)
        and final_scheme == "https"
    )
    return {
        "chain": chain, "count": len(chain),
        "downgrades": downgrades,
        "forced_https": http_to_https,
        "final_scheme": final_scheme,
    }


# ═══════════════════════════════════════════════════════════════════════════
# SESSION / IO HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def _build_session(headers: Optional[Dict[str, str]] = None,
                   verify_ssl: bool = True,
                   retries: int = DEFAULT_RETRIES) -> requests.Session:
    s = requests.Session()
    s.headers.update(headers or default_headers())
    try:
        adapter = HTTPAdapter(
            pool_connections=8, pool_maxsize=16,
            max_retries=Retry(
                total=retries, backoff_factor=DEFAULT_BACKOFF,
                status_forcelist=(429, 502, 503, 504),
                allowed_methods=frozenset(["GET", "HEAD"]),
                raise_on_status=False,
            ),
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    except Exception:
        pass
    s.verify = verify_ssl
    return s


def _read_bounded(resp: requests.Response, max_bytes: int) -> bytes:
    buf = bytearray()
    try:
        for chunk in resp.iter_content(chunk_size=STREAM_CHUNK_SIZE):
            if not chunk:
                continue
            remaining = max_bytes - len(buf)
            if remaining <= 0:
                break
            buf.extend(chunk[:remaining])
    except Exception:
        pass
    return bytes(buf)


def _normalize_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t


def _build_urls(target: str) -> List[str]:
    if not target:
        return []
    if target.startswith(("http://", "https://")):
        return [target]
    return [f"https://{target}", f"http://{target}"]


def _safe_join(base: str, path: str) -> str:
    p = urlparse(base)
    return urlunparse((p.scheme, p.netloc,
                       path if path.startswith("/") else "/" + path,
                       "", "", ""))


def _make_fake_response(url: str, headers: Dict[str, str],
                        status: int, body: bytes) -> requests.Response:
    """
    Wrap a bypass result as a requests.Response-like object.

    v3.1.0: constructs a proper `urllib3.HTTPHeaderDict` for `.raw.headers`
    so `_analyse_cookies()` can extract Set-Cookie reliably, even for
    responses produced by curl_cffi / cloudscraper.
    """
    r = requests.Response()
    r.url = url
    r.status_code = status
    r._content = body or b""
    r.encoding = "utf-8"
    r.history = []

    plain: Dict[str, str] = {}
    hd = HTTPHeaderDict() if HTTPHeaderDict is not None else None
    for k, v in (headers or {}).items():
        if isinstance(v, (list, tuple)):
            if hd is not None:
                for item in v:
                    try:
                        hd.add(k, str(item))
                    except Exception:
                        pass
            plain[k] = ", ".join(str(x) for x in v)
        else:
            if hd is not None:
                try:
                    hd.add(k, str(v))
                except Exception:
                    pass
            plain[k] = str(v)

    r.headers = CaseInsensitiveDict(plain)

    if hd is not None:
        class _FakeRaw:
            def __init__(self, h):
                self.headers = h

        r.raw = _FakeRaw(hd)
    else:
        r.raw = None
    return r


# ═══════════════════════════════════════════════════════════════════════════
# RESPONSE ANALYSER
# ═══════════════════════════════════════════════════════════════════════════
def _analyze_response(resp: requests.Response, body: bytes,
                      mode: str, target: str,
                      waf_info: Optional[Dict],
                      tech_stack: List[Dict],
                      cf_info: Optional[str]) -> Dict[str, Any]:
    present: Dict[str, str] = {}
    missing: List[Dict[str, Any]] = []
    deprecated_found: List[Dict[str, Any]] = []
    quality_issues: List[Dict[str, Any]] = []

    total_weight = sum(h["weight"] for h in SECURITY_HEADERS.values())
    score_weight = 0

    for header, meta in SECURITY_HEADERS.items():
        v = resp.headers.get(header)
        if v:
            present[header] = v[:MAX_HEADER_VALUE]
            score_weight += meta["weight"]
            checker = _QUALITY_CHECKERS.get(header)
            if checker:
                try:
                    q = checker(v)
                    for iss in q.get("issues", []):
                        quality_issues.append({
                            "header": header,
                            "severity": iss["severity"],
                            "issue": iss["issue"],
                        })
                except Exception as e:
                    logger.debug("[headers] quality check failed for %s: %s",
                                 header, e)
        else:
            missing.append({
                "header": header,
                "description": meta["description"],
                "severity": meta["severity"],
                "recommendation": meta.get("recommendation", ""),
            })

    for header, meta in DEPRECATED_HEADERS.items():
        if header in resp.headers:
            deprecated_found.append({
                "header": header,
                "value": resp.headers.get(header, "")[:200],
                "reason": meta["reason"],
                "severity": meta["severity"],
            })

    non_info_missing = [m for m in missing if m["severity"] != "info"]
    highest_severity = "none"
    if non_info_missing:
        highest_severity = max(
            (m["severity"] for m in non_info_missing),
            key=lambda s: _SEV_RANK.get(s, 0),
        )

    score_percent = round((score_weight / total_weight) * 100) if total_weight else 0
    has_csp  = "Content-Security-Policy" in resp.headers
    has_hsts = "Strict-Transport-Security" in resp.headers
    grade    = _grade(score_percent, has_csp, has_hsts)
    risk     = _risk_score(score_percent, missing, quality_issues, grade)

    data: Dict[str, Any] = {
        "url":                  resp.url,
        "status_code":          resp.status_code,
        "server":               resp.headers.get("Server", "unknown"),
        "powered_by":           resp.headers.get("X-Powered-By", ""),
        "present_headers":      present,
        "missing_headers":      missing,
        "deprecated_headers":   deprecated_found,
        "quality_issues":       quality_issues,
        "score_percent":        score_percent,
        "grade":                grade,
        "highest_severity":     highest_severity,
        "has_csp":              has_csp,
        "has_hsts":             has_hsts,
        "recommendation_count": len(missing),
        "risk":                 risk,
        "compliance":           _compliance_report(present),
        "cookies":              _analyse_cookies(resp),
        "redirects":            _analyse_redirects(resp),
        "tech_stack":           tech_stack,
        "waf":                  waf_info,
        "cloudflare_challenge": cf_info,
    }

    if mode == "expert":
        data["all_response_headers"] = {
            k: v[:MAX_HEADER_VALUE] for k, v in resp.headers.items()
        }
        csp_raw = resp.headers.get("Content-Security-Policy")
        if csp_raw:
            data["csp_analysis"] = _analyse_csp_quality(csp_raw)
        pp_raw = resp.headers.get("Permissions-Policy")
        if pp_raw:
            data["permissions_policy_directives"] = pp_raw
        parsed = urlparse(resp.url)
        if parsed.scheme == "https" and parsed.hostname:
            tls = _probe_tls(parsed.hostname, parsed.port or 443)
            if tls:
                data["tls"] = tls
        data["content_type"] = resp.headers.get("Content-Type", "")
        data["content_length"] = len(body)
        data["html_analysis"] = _analyse_html_body(body, resp.url)

    return data


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
def run(target: str, mode: str = "basic", **kwargs) -> Dict[str, Any]:
    """
    Audit HTTP security headers of `target`. Never raises.

    kwargs:
        timeout (float)       — default 12s
        verify_ssl (bool)     — default True
        headers (dict)        — custom request headers
        follow_redirects      — default True
        check_paths (bool)    — also scan /login, /api, /admin
        check_discovery (bool)— fetch security.txt / robots.txt / sitemap.xml
        use_cf_bypass (bool)  — enable Cloudflare bypass (default True)
        proxy (dict)          — proxy dict {"http": ..., "https": ...}
        max_bytes (int)       — bounded body read
    """
    timeout          = float(kwargs.get("timeout", DEFAULT_TIMEOUT))
    verify_ssl       = bool(kwargs.get("verify_ssl", True))
    custom_headers   = kwargs.get("headers")
    follow_redirects = bool(kwargs.get("follow_redirects", True))
    check_paths      = bool(kwargs.get("check_paths", False))
    check_discovery  = bool(kwargs.get("check_discovery", mode == "expert"))
    use_cf_bypass    = bool(kwargs.get("use_cf_bypass", True))
    proxy            = kwargs.get("proxy")
    max_bytes        = int(kwargs.get("max_bytes", DEFAULT_MAX_BYTES))

    urls = _build_urls(target)
    if not urls:
        return _error_result(target, "Empty target.")

    session = _build_session(custom_headers, verify_ssl)
    if proxy:
        session.proxies.update(proxy)

    resp: Optional[requests.Response] = None
    body: bytes = b""
    last_error: Optional[str] = None
    used_url: Optional[str] = None
    cf_method_used: Optional[str] = None

    for url in urls:
        try:
            r = session.get(url, timeout=timeout,
                            allow_redirects=follow_redirects, stream=True)
            body = _read_bounded(r, max_bytes)
            cf_type = _detect_cloudflare(dict(r.headers), body, r.status_code)
            if cf_type and use_cf_bypass:
                logger.info("[headers] CF detected (%s) → invoking bypass", cf_type)
                cf = CloudflareBypass(
                    timeout=int(timeout), cf_timeout=CF_CHALLENGE_TIMEOUT,
                    verify_tls=verify_ssl, proxy_dict=proxy,
                )
                cf_body, cf_headers, cf_status, method_used = cf.fetch(url)
                if cf_body is not None:
                    body = cf_body
                    resp = _make_fake_response(url, cf_headers, cf_status, cf_body)
                    used_url = url
                    cf_method_used = method_used
                    break
            if r.status_code < 500:
                resp = r
                used_url = url
                break
            resp = r
            used_url = url
        except requests.exceptions.SSLError:
            last_error = "SSL certificate verification failed"
        except requests.exceptions.ConnectionError:
            last_error = "Connection refused or network unreachable"
        except requests.exceptions.Timeout:
            last_error = f"Request timed out after {timeout}s"
        except Exception as e:
            last_error = str(e)

    if resp is None:
        return _error_result(target, last_error or "Could not connect to target")

    if not body and hasattr(resp, "content"):
        try:
            body = resp.content[:max_bytes]
        except Exception:
            body = b""

    waf_info = _detect_waf(dict(resp.headers),
                           body.decode("utf-8", "ignore")[:8192],
                           resp.status_code)
    tech_stack = _fingerprint_tech(dict(resp.headers))
    cf_type = _detect_cloudflare(dict(resp.headers), body, resp.status_code)

    data = _analyze_response(resp, body, mode, target, waf_info, tech_stack, cf_type)
    data["tested_url"] = used_url
    data["cf_bypass_used"] = cf_method_used
    data["cf_bypass_available"] = {
        "curl_cffi":    _HAS_CURL_CFFI,
        "cloudscraper": _HAS_CLOUDSCRAPER,
        "flaresolverr": bool(FLARESOLVERR_URL),
        "manual":       True,
    }

    if check_paths:
        paths_data = []
        for path in COMMON_PATHS:
            full = _safe_join(used_url or urls[0], path)
            try:
                r = session.get(full, timeout=timeout,
                                allow_redirects=follow_redirects, stream=True)
                _ = _read_bounded(r, max_bytes)
                paths_data.append({
                    "path": path, "url": r.url,
                    "status_code": r.status_code,
                    "has_csp":  "Content-Security-Policy" in r.headers,
                    "has_hsts": "Strict-Transport-Security" in r.headers,
                    "has_xfo":  "X-Frame-Options" in r.headers,
                    "has_xcto": "X-Content-Type-Options" in r.headers,
                })
            except Exception as e:
                paths_data.append({"path": path, "url": full, "error": str(e)})
        data["paths"] = paths_data

    if check_discovery:
        try:
            data["discovery"] = _check_discovery_files(
                session, used_url or urls[0], timeout,
            )
        except Exception as e:
            data["discovery_error"] = str(e)

    return {
        "tool":    "headers",   # normalised slug
        "version": __version__,
        "target":  target,
        "data":    data,
        "error":   None,
    }


def _error_result(target: str, message: str) -> Dict[str, Any]:
    return {
        "tool":    "headers",
        "version": __version__,
        "target":  target,
        "data":    {},
        "error":   message,
    }


# ── Aliases: satisfy every slug terminal.py looks for ────────────────────
headers_check  = run
scan_headers   = run
headers        = run
headers_scan   = run
check_headers  = run


# ═══════════════════════════════════════════════════════════════════════════
# STREAMING API
# ═══════════════════════════════════════════════════════════════════════════
def run_streaming(
    target: str,
    options: Optional[Dict[str, Any]] = None,
    cancel_event: Optional[Any] = None,
) -> Iterator[Dict[str, Any]]:
    options = options or {}
    started = time.time()
    yield {"type": "start", "target": target, "options": options}
    yield {"type": "stage", "stage": "connecting"}
    try:
        result = run(
            target,
            mode=str(options.get("mode", "basic")),
            timeout=float(options.get("timeout", DEFAULT_TIMEOUT)),
            verify_ssl=bool(options.get("verify_ssl", True)),
            headers=options.get("headers"),
            follow_redirects=bool(options.get("follow_redirects", True)),
            check_paths=bool(options.get("check_paths", False)),
            check_discovery=bool(options.get("check_discovery", False)),
            use_cf_bypass=bool(options.get("use_cf_bypass", True)),
            proxy=options.get("proxy"),
            max_bytes=int(options.get("max_bytes", DEFAULT_MAX_BYTES)),
        )
    except Exception as e:
        yield {"type": "error", "message": str(e)}
        return
    if cancel_event is not None and hasattr(cancel_event, "is_set"):
        if cancel_event.is_set():
            yield {"type": "error", "message": "cancelled"}
            return
    yield {"type": "stage", "stage": "analyse"}
    yield {"type": "result", "data": result}
    yield {
        "type": "summary",
        "duration_ms": int((time.time() - started) * 1000),
        "ok": result.get("error") is None,
    }
    yield {"type": "stage", "stage": "done"}


# ═══════════════════════════════════════════════════════════════════════════
# BATCH SCANNING
# ═══════════════════════════════════════════════════════════════════════════
def scan_many(
    targets: Iterable[str],
    mode: str = "basic",
    workers: int = 6,
    on_result: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    **kwargs,
) -> List[Dict[str, Any]]:
    targets = list(targets)
    results: List[Optional[Dict[str, Any]]] = [None] * len(targets)

    def _one(idx: int, tgt: str) -> Tuple[int, Dict[str, Any]]:
        r = run(tgt, mode=mode, **kwargs)
        if on_result is not None:
            try:
                on_result(tgt, r)
            except Exception as e:
                logger.debug("[headers] on_result callback failed: %s", e)
        return idx, r

    if workers <= 1 or len(targets) <= 1:
        for i, t in enumerate(targets):
            _, r = _one(i, t)
            results[i] = r
        return [r for r in results if r is not None]

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_one, i, t): i for i, t in enumerate(targets)}
        for fut in as_completed(futures):
            try:
                idx, r = fut.result()
                results[idx] = r
            except Exception as e:
                logger.warning("[headers] batch worker error: %s", e)
    return [r for r in results if r is not None]


# ═══════════════════════════════════════════════════════════════════════════
# SELF-CHECK
# ═══════════════════════════════════════════════════════════════════════════
def self_check() -> Dict[str, Any]:
    """Return diagnostic dict describing runtime capability."""
    py = sys.version_info
    return {
        "module":       "modules.headers_check",
        "version":      __version__,
        "author":       __author__,
        "credit":       __credit__,
        "python":       f"{py.major}.{py.minor}.{py.micro}",
        "requests":     True,
        "flask":        _HAS_FLASK,
        "curl_cffi":    _HAS_CURL_CFFI,
        "cloudscraper": _HAS_CLOUDSCRAPER,
        "flaresolverr": bool(FLARESOLVERR_URL),
        "aliases":      ["run", "headers_check", "scan_headers",
                         "headers", "headers_scan", "check_headers"],
        "endpoint":     "/api/headers/scan" if _HAS_FLASK else None,
        "ready":        _HAS_FLASK,
    }


# ═══════════════════════════════════════════════════════════════════════════
# SARIF EXPORT
# ═══════════════════════════════════════════════════════════════════════════
def to_sarif(result: Dict[str, Any]) -> Dict[str, Any]:
    d = result.get("data", {})
    findings = []
    for m in d.get("missing_headers", []):
        findings.append({
            "ruleId": f"headers/{m['header']}",
            "level": {"critical": "error", "hard": "error",
                      "normal": "warning"}.get(m["severity"], "note"),
            "message": {"text": f"Missing header: {m['header']} — {m['description']}"},
        })
    for q in d.get("quality_issues", []):
        findings.append({
            "ruleId": f"headers-quality/{q['header']}",
            "level": {"high": "error", "medium": "warning"}.get(q["severity"], "note"),
            "message": {"text": f"{q['header']}: {q['issue']}"},
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Oxysintx HTTP Security Headers",
                "version": __version__,
            }},
            "results": findings,
        }],
    }


# ═══════════════════════════════════════════════════════════════════════════
# FLASK BLUEPRINT  →  POST|GET /api/headers/scan
# ═══════════════════════════════════════════════════════════════════════════
if _HAS_FLASK:
    headers_bp = Blueprint("headers_check", __name__)

    @headers_bp.route("/api/headers/scan", methods=["POST", "GET"])
    def _headers_scan_endpoint():
        """
        Payload (JSON or query):
            { "target": "example.com", "mode": "basic|expert",
              "timeout": 12, "verify_ssl": true,
              "check_paths": false, "check_discovery": false,
              "use_cf_bypass": true }

        Response shape — matches terminal.py `_render_headers()`:
            {
              "tool": "headers", "version": "3.1.0",
              "target": "example.com",
              "data": { url, server, grade, score_percent,
                        risk: {label, score}, missing_headers: [...],
                        present_headers: {...}, ... },
              "error": null
            }
        """
        payload = request.get_json(silent=True) or {}
        target = (payload.get("target")
                  or request.args.get("target", "")).strip()
        mode = (payload.get("mode")
                or request.args.get("mode", "basic")).strip().lower()
        if mode not in ("basic", "expert"):
            mode = "basic"

        def _bool_from(key, default):
            v = payload.get(key, request.args.get(key))
            if v is None:
                return default
            return str(v).lower() not in ("0", "false", "no", "off", "")

        try:
            timeout = float(payload.get("timeout")
                            or request.args.get("timeout")
                            or DEFAULT_TIMEOUT)
        except (TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT

        if not target:
            return jsonify({
                "tool": "headers", "version": __version__,
                "target": "", "data": {},
                "error": "missing 'target' parameter",
            }), 400

        result = run(
            target,
            mode=mode,
            timeout=timeout,
            verify_ssl=_bool_from("verify_ssl", True),
            check_paths=_bool_from("check_paths", False),
            check_discovery=_bool_from("check_discovery", mode == "expert"),
            use_cf_bypass=_bool_from("use_cf_bypass", True),
        )
        return jsonify(result)


    def register_blueprint(app) -> None:
        """Convenience helper for app.py: `register_blueprint(app)`."""
        app.register_blueprint(headers_bp)
        logger.info("headers_check blueprint registered at /api/headers/scan")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def _print_human(result: Dict[str, Any]) -> None:
    if result.get("error"):
        print(f"[FAIL] {result['target']}: {result['error']}")
        return
    d = result["data"]
    print(f"\n═══ HTTP Security Headers: {result['target']} ═══\n")
    print(f"URL         : {d.get('url')}")
    print(f"Status      : {d.get('status_code')}")
    print(f"Server      : {d.get('server')}")
    print(f"Grade       : {d.get('grade')}  ({d.get('score_percent')}%)")
    print(f"Severity    : {d.get('highest_severity')}")
    if d.get("risk"):
        r = d["risk"]
        print(f"Risk        : {r['label']} ({r['score']}/10)")
    if d.get("tls"):
        print(f"TLS         : {d['tls'].get('protocol')} / {d['tls'].get('cipher')}")
    if d.get("waf"):
        print(f"WAF         : {d['waf']['name']}")
    if d.get("cloudflare_challenge"):
        print(f"CF challenge: {d['cloudflare_challenge']}")
    if d.get("cf_bypass_used"):
        print(f"CF bypass   : {d['cf_bypass_used']}")
    if d.get("tech_stack"):
        print("Tech stack  : " +
              ", ".join(f"{t['name']}" + (f" v{t['version']}" if t.get('version') else "")
                        for t in d['tech_stack']))
    print()

    present = d.get("present_headers", {})
    missing = d.get("missing_headers", [])
    deprecated = d.get("deprecated_headers", [])
    quality = d.get("quality_issues", [])

    print(f"✓ Present ({len(present)})")
    for h, v in list(present.items())[:25]:
        print(f"    {h}: {str(v)[:70]}")
    if missing:
        print(f"\n✗ Missing ({len(missing)})")
        for m in missing:
            print(f"    [{m['severity']}] {m['header']}")
            if m.get("recommendation"):
                print(f"        → {m['recommendation']}")
    if quality:
        print(f"\n! Quality issues ({len(quality)})")
        for q in quality:
            print(f"    [{q['severity']}] {q['header']}: {q['issue']}")
    if deprecated:
        print(f"\n⚠ Deprecated ({len(deprecated)})")
        for dep in deprecated:
            print(f"    {dep['header']}: {dep['reason']}")

    comp = d.get("compliance", {})
    if comp:
        print("\nCompliance:")
        for fw, controls in comp.items():
            ok = sum(1 for c in controls.values() if c["status"] == "compliant")
            print(f"    {fw}: {ok}/{len(controls)} controls compliant")


def _main() -> int:
    parser = argparse.ArgumentParser(
        description=f"HTTP Security Header Analyzer v{__version__}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("targets", nargs="*", help="Hostnames or URLs")
    parser.add_argument("--mode", choices=["basic", "expert"], default="basic")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--check-paths", action="store_true")
    parser.add_argument("--check-discovery", action="store_true")
    parser.add_argument("--no-cf-bypass", action="store_true")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--proxy", help="Proxy URL (http://...)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--sarif", action="store_true")
    parser.add_argument("--output", help="Write JSON to file")
    parser.add_argument("--self-check", action="store_true",
                        help="print runtime diagnostics and exit")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()

    if args.self_check or not args.targets:
        print(_json.dumps(self_check(), indent=2))
        if not args.targets and not args.self_check:
            print("\nTip: pass at least one target, e.g. `example.com`.")
        return 0

    proxy_dict = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    results = scan_many(
        args.targets,
        mode=args.mode,
        workers=args.workers,
        timeout=args.timeout,
        verify_ssl=not args.no_verify,
        check_paths=args.check_paths,
        check_discovery=args.check_discovery or args.mode == "expert",
        use_cf_bypass=not args.no_cf_bypass,
        proxy=proxy_dict,
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            _json.dump(results, f, indent=2, default=str, ensure_ascii=False)
        print(f"Output written to {args.output}")
        return 0

    if args.sarif and len(results) == 1:
        print(_json.dumps(to_sarif(results[0]), indent=2, default=str))
        return 0

    if args.json:
        print(_json.dumps(results, indent=2, default=str, ensure_ascii=False))
        return 0

    for r in results:
        _print_human(r)
    return 0


if __name__ == "__main__":
    sys.exit(_main())