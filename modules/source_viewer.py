#!/usr/bin/env python3
"""
source_viewer.py — Robust Source Code & Asset Extractor for Oxysintx

Capabilities:
    - Fetch a URL (HTTP/HTTPS) with redirect following and size limiting
    - Detect and decode content using the declared charset or fallback
    - Return raw HTML source (default) or structured extraction of:
        * Script tags (src attributes)
        * Link tags (stylesheet hrefs)
        * Image tags (src attributes)
        * Anchor tags (href attributes)
        * Iframe tags (src attributes)
        * Firebase configuration snippets (apiKey patterns)
    - Configurable User‑Agent, timeout, and maximum payload size
    - Retry logic with exponential backoff on transient errors
    - Proxy support via standard environment variables (HTTP_PROXY / HTTPS_PROXY)

Interfaces (used by app.py):
    run(url, extract=False) -> dict
        Returns {"source": html_string} or {"error": message}
        When extract=True, also returns "extracted" key with parsed lists.

Author: EAST CODEX
Version: 2.0.0
"""

import re
import logging
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 12                # seconds (connect + read)
MAX_CONTENT_LENGTH = 6 * 1024 * 1024  # 6 MB hard cap
CHUNK_SIZE = 16384                  # 16 KiB download chunks
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
RETRY_TOTAL = 3                     # total retries (including first attempt)
RETRY_BACKOFF_FACTOR = 0.5          # sleep = backoff_factor * (2 ** (retry - 1))
RETRY_STATUS_FORCELIST = [429, 500, 502, 503, 504]

# ---------------------------------------------------------------------------
# Session factory with retry & connection pooling
# ---------------------------------------------------------------------------
def _create_session() -> requests.Session:
    """
    Build a requests.Session with a Retry adapter.
    The session reuses TCP connections (HTTP keep-alive) for speed.
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=RETRY_TOTAL,
        backoff_factor=RETRY_BACKOFF_FACTOR,
        status_forcelist=RETRY_STATUS_FORCELIST,
        allowed_methods=["GET", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

# ---------------------------------------------------------------------------
# Helpers for safe content reading
# ---------------------------------------------------------------------------
def _read_response_safely(response: requests.Response) -> Tuple[bytes, int]:
    """
    Read response body in chunks, respecting MAX_CONTENT_LENGTH.
    Returns (raw_bytes, total_size).
    """
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
        if chunk:
            total += len(chunk)
            if total > MAX_CONTENT_LENGTH:
                logger.warning(
                    "Response exceeded size limit (%d bytes) – truncating",
                    MAX_CONTENT_LENGTH,
                )
                # Keep the first MAX_CONTENT_LENGTH bytes
                remaining = MAX_CONTENT_LENGTH - (total - len(chunk))
                chunks.append(chunk[:remaining])
                total = MAX_CONTENT_LENGTH
                break
            chunks.append(chunk)
    return b"".join(chunks), total

def _decode_content(raw: bytes, encoding: Optional[str]) -> str:
    """
    Decode raw bytes using the given encoding, falling back to UTF-8 with replacement.
    """
    if not encoding:
        encoding = "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except (UnicodeDecodeError, LookupError):
        logger.debug("Encoding '%s' failed, falling back to UTF-8", encoding)
        return raw.decode("utf-8", errors="replace")

# ---------------------------------------------------------------------------
# HTML resource extraction (server‑side parsing)
# ---------------------------------------------------------------------------
_FIREBASE_PATTERNS = [
    re.compile(r"firebase\.initializeApp\s*\(\s*\{[^}]+apiKey\s*:\s*\"[^\"]+\"", re.IGNORECASE),
    re.compile(r'apiKey\s*:\s*\"AIza[^"]*\"', re.IGNORECASE),
    re.compile(r"config\s*=\s*\{[^}]*apiKey", re.IGNORECASE),
]

def _extract_resources(html: str) -> Dict[str, Any]:
    """
    Parse the HTML string and extract:
        - scripts : list of src values from <script src="...">
        - styles  : list of href values from <link rel="stylesheet" href="...">
        - images  : list of src values from <img src="...">
        - links   : list of href values from <a href="...">
        - iframes : list of src values from <iframe src="...">
        - firebase: list of matching Firebase config snippets (strings)
    """
    scripts = re.findall(r'<script\s[^>]*src\s*=\s*["\'](.*?)["\']', html, re.IGNORECASE)
    # Stylesheets: <link ... rel="stylesheet" ... href="..."> (order may vary)
    styles = re.findall(
        r'<link\s(?:[^>]*\s)?href\s*=\s*["\'](.*?)["\'](?:[^>]*\s)?rel\s*=\s*["\']stylesheet["\']', html,
        re.IGNORECASE,
    )
    # Alternate pattern for rel after href
    styles += re.findall(
        r'<link\s(?:[^>]*\s)?rel\s*=\s*["\']stylesheet["\'](?:[^>]*\s)?href\s*=\s*["\'](.*?)["\']', html,
        re.IGNORECASE,
    )
    styles = list(set(styles))
    images = re.findall(r'<img\s[^>]*src\s*=\s*["\'](.*?)["\']', html, re.IGNORECASE)
    links = re.findall(r'<a\s[^>]*href\s*=\s*["\'](.*?)["\']', html, re.IGNORECASE)
    iframes = re.findall(r'<iframe\s[^>]*src\s*=\s*["\'](.*?)["\']', html, re.IGNORECASE)

    firebase_matches = []
    for pat in _FIREBASE_PATTERNS:
        firebase_matches.extend(pat.findall(html))

    return {
        "scripts": scripts,
        "styles": styles,
        "images": images,
        "links": links,
        "iframes": iframes,
        "firebase": firebase_matches,
    }

# ---------------------------------------------------------------------------
# Main API function
# ---------------------------------------------------------------------------
def run(url: str, extract: bool = False) -> Dict[str, Any]:
    """
    Fetch the source code of a publicly accessible URL.

    Args:
        url:     Target URL (must start with http:// or https://).
        extract: If True, also parse the HTML and return extracted resources.

    Returns:
        On success: {"source": <html string>, [extracted: {...}]}
        On failure: {"error": "<message>"}
    """
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"error": "invalid_url_scheme"}

    logger.info("Fetching source for %s (extract=%s)", url, extract)

    session = _create_session()
    try:
        response = session.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            stream=True,
        )
        response.raise_for_status()

        # Read content
        raw_bytes, total_size = _read_response_safely(response)
        content_type = response.headers.get("Content-Type", "")
        encoding = response.encoding

        # Only decode text/* content types as HTML
        if "text/" in content_type or "application/xhtml+xml" in content_type or "application/xml" in content_type:
            html = _decode_content(raw_bytes, encoding)
        else:
            # Non‑HTML response – return the raw text representation
            html = _decode_content(raw_bytes, "utf-8")
            logger.info("Non-HTML content-type '%s', returned as plain text", content_type)

        result: Dict[str, Any] = {
            "source": html,
            "content_type": content_type,
            "encoding": encoding or "utf-8",
            "size_bytes": total_size,
        }

        if extract and ("text/html" in content_type or "application/xhtml" in content_type):
            result["extracted"] = _extract_resources(html)

        logger.info("Successfully fetched %s (%d bytes)", url, len(html))
        return result

    except requests.exceptions.Timeout:
        logger.error("Timeout fetching %s", url)
        return {"error": "request_timed_out"}
    except requests.exceptions.ConnectionError:
        logger.error("Connection error for %s", url)
        return {"error": "connection_failed"}
    except requests.exceptions.HTTPError as e:
        logger.error("HTTP %d fetching %s", e.response.status_code, url)
        return {"error": f"http_error_{e.response.status_code}"}
    except requests.exceptions.RequestException as e:
        logger.error("Request error for %s: %s", url, e)
        return {"error": "request_failed", "detail": str(e)}
    except Exception as e:
        logger.error("Unexpected error for %s: %s", url, e, exc_info=True)
        return {"error": "unexpected_error", "detail": str(e)}
    finally:
        session.close()

# Legacy alias
fetch_source = run