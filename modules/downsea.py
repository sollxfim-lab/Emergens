# modules/downsea.py
"""
downsea.py — TikTok & Pinterest Downloader Backend
Flask Blueprint: local proxy untuk API TikTok/Pinterest.
Dipakai oleh data_main.html agar tidak CORS / langsung ke API pihak ketiga.

Author: Yanxzyx
"""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Blueprint, jsonify, request

logger = logging.getLogger("oxysintx.downsea")

downsea_bp = Blueprint("downsea", __name__)

# Base URL upstream
BASE_URL = os.getenv("DOWNSEA_BASE_URL", "https://api.siputzx.my.id")

TIKTOK_API = f"{BASE_URL}/api/d/tiktok/v2"
PINTEREST_API = f"{BASE_URL}/api/s/pinterest"

TIMEOUT = 20
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
}

# ---------------------------------------------------------------------------
# Simple in-memory TTL cache
# ---------------------------------------------------------------------------
_CACHE_TTL = 300  # 5 menit
_cache: Dict[str, Tuple[float, Any]] = {}


def _cache_get(key: str) -> Optional[Any]:
    hit = _cache.get(key)
    if not hit:
        return None
    ts, value = hit
    if time.time() - ts > _CACHE_TTL:
        _cache.pop(key, None)
        return None
    return value


def _cache_set(key: str, value: Any) -> None:
    _cache[key] = (time.time(), value)


# ---------------------------------------------------------------------------
# Upstream fetch
# ---------------------------------------------------------------------------
def _fetch_json(api_url: str, params: dict) -> Tuple[Optional[Any], Optional[Tuple[str, int]]]:
    try:
        resp = requests.get(
            api_url,
            params=params,
            headers=REQUEST_HEADERS,
            timeout=TIMEOUT,
        )

        if resp.status_code == 429:
            return None, ("upstream_rate_limited", 429)

        resp.raise_for_status()
        data = resp.json()
        return data, None

    except requests.Timeout:
        logger.warning("Upstream timeout: %s params=%s", api_url, params)
        return None, ("upstream_timeout", 504)

    except requests.RequestException as exc:
        logger.warning("Upstream request failed: %s", exc)
        return None, ("upstream_error", 502)

    except ValueError:
        logger.warning("Invalid JSON from upstream: %s", api_url)
        return None, ("invalid_upstream_response", 502)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_TIKTOK_URL_RE = re.compile(
    r"^https?://(?:www\.)?(?:vt\.tiktok\.com|tiktok\.com|vm\.tiktok\.com)/\S+",
    re.IGNORECASE,
)


def _is_valid_tiktok_url(url: str) -> bool:
    return bool(_TIKTOK_URL_RE.match(url))


def _normalize_pinterest(data: Any) -> list:
    """Ambil list pin dari berbagai struktur response API Pinterest."""
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("data", "result", "results", "pins"):
            if key in data and isinstance(data[key], list):
                return data[key]

        nested = data.get("data")
        if isinstance(nested, dict):
            for key in ("results", "pins"):
                if key in nested and isinstance(nested[key], list):
                    return nested[key]

    return []


def _extract_tiktok_metadata(data: dict) -> dict:
    """Normalisasi respons TikTok agar frontend konsisten."""
    d = data.get("data", {}) if isinstance(data, dict) else {}

    return {
        "item_id": d.get("itemId") or "",
        "original": d.get("original") or "",
        "aweme_link": d.get("aweme_link") or "",
        "music_link": d.get("music_link") or "",
        "watermark_link": d.get("watermark_link") or "",
        "no_watermark_link": d.get("no_watermark_link") or "",
        "no_watermark_link_hd": d.get("no_watermark_link_hd") or "",
        "cover_link": d.get("cover_link") or d.get("origin_cover") or "",
        "author_cover_link": d.get("author_cover_link") or "",
        "text": d.get("text") or "",
        "create_time": d.get("create_time") or "0",
        "duration": d.get("duration") or 0,
        "author_unique_id": d.get("author_unique_id") or "",
        "author_nickname": d.get("author_nickname") or "",
        "author_id": d.get("author_id") or "",
        "comment_count": d.get("comment_count") or "0",
        "play_count": d.get("play_count") or "0",
        "share_count": d.get("share_count") or "0",
        "like_count": d.get("like_count") or "0",
        "slides": d.get("slides") or "",
        "type": d.get("type") or 1,
        "signed": d.get("signed") or 0,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@downsea_bp.route("/api/downloader/tiktok", methods=["GET"])
def tiktok_downloader():
    url = request.args.get("url", "").strip()

    if not url:
        return jsonify({"error": "url_required"}), 400

    if not _is_valid_tiktok_url(url):
        return jsonify({"error": "invalid_tiktok_url"}), 400

    cache_key = f"tiktok:{url}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    data, err = _fetch_json(TIKTOK_API, {"url": url})
    if err:
        msg, code = err
        return jsonify({"error": msg}), code

    # Deteksi jika upstream mengembalikan status false meski HTTP 200
    if isinstance(data, dict) and data.get("status") is False:
        logger.warning("Upstream TikTok error: %s", data)
        return jsonify({
            "error": data.get("error") or "upstream_error",
            "code": data.get("code") or 500,
        }), 400

    normalized = {"data": _extract_tiktok_metadata(data)}
    _cache_set(cache_key, normalized)
    logger.info("TikTok download success for %s", url)
    return jsonify(normalized)


@downsea_bp.route("/api/downloader/pinterest", methods=["GET"])
def pinterest_downloader():
    # Terima parameter q atau query dari frontend
    query = (request.args.get("q") or request.args.get("query") or "").strip()

    if not query:
        return jsonify({"error": "query_required"}), 400

    if len(query) > 120:
        return jsonify({"error": "query_too_long"}), 400

    cache_key = f"pinterest:{query.lower()}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)

    # Upstream Pinterest meminta parameter `query`
    data, err = _fetch_json(PINTEREST_API, {"query": query})
    if err:
        msg, code = err
        return jsonify({"error": msg}), code

    # Deteksi error dari upstream meski HTTP 200
    if isinstance(data, dict) and data.get("status") is False:
        logger.warning("Upstream Pinterest error: %s", data)
        return jsonify({
            "error": data.get("error") or "upstream_error",
            "code": data.get("code") or 500,
        }), 400

    pins = _normalize_pinterest(data)
    result = {"data": pins}
    _cache_set(cache_key, result)
    logger.info("Pinterest search success for %r (%d pins)", query, len(pins))
    return jsonify(result)


@downsea_bp.route("/api/downloader/health", methods=["GET"])
def downloader_health():
    return jsonify({
        "status": "ok",
        "service": "downsea",
        "version": "1.0.0",
        "upstream": BASE_URL,
    })