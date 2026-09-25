#!/usr/bin/env python3
"""
Tech Fingerprinting — Passive detection of CMS, frameworks, servers,
languages, analytics, CDNs, and security products from public response
data (headers, HTML markers, cookies, meta tags, script sources, DNS
CNAME chains, and favicon hashes).

Canonical module — self-contained, zero cross-module dependencies.

Detection sources (in order of reliability):
    1. Response headers          (Server, X-Powered-By, Set-Cookie, ...)
    2. DNS CNAME chain           (cloudflare.net → Cloudflare, etc.)
    3. HTML meta generator       (<meta name="generator" content="...">)
    4. Script/link src patterns  (<script src="/wp-content/...">)
    5. Cookie names & flags      (wordpress_logged_in, PHPSESSID, ...)
    6. Inline HTML markers       (class names, IDs, comment banners)
    7. Multi-path probing        (/robots.txt, /sitemap.xml, /humans.txt)
    8. Favicon SHA-256 match     (against a small built-in database)

Features
    • 200+ signatures across 20 categories
    • DNS-level CDN / hosting detection via CNAME chain
    • Multi-path probing so origin tech isn't masked by front CDN
    • Confidence levels: high / medium / low
    • Version extraction where the marker exposes one
    • Category grouping + confidence-ordered output
    • Multi-source evidence trail per detection
    • Redirect-aware — merges cookies from the full redirect chain
    • Streaming body reader — never holds more than MAX_BODY_CHARS in RAM
    • Tolerant of TLS errors, timeouts, and slow hosts
    • Isolated logger — no duplicate output with Flask/root
    • Drop-in compatible — same `run()` signature as before
    • Flask Blueprint exposing POST|GET /api/techfp/scan
    • SSE streaming generator + batch scan_many()
    • Self-check runtime diagnostic + CLI --self-check

----------------------------------------------------------------------------
Changelog v3.1.0  (Emergens integration + hardening)
----------------------------------------------------------------------------
  ✔ NEW    — Flask Blueprint `techfp_bp` exposing
             `POST|GET /api/techfp/scan` so terminal.py's
             `_client.post("/api/techfp/scan", ...)` works.
  ✔ NEW    — `register_blueprint(app)` helper for app.py wiring.
  ✔ NEW    — Aliases `tech_fingerprint`, `scan_tech_fingerprint`, `techfp`,
             `fingerprint`, `tech_fp` — any terminal.py scan-registry
             slug resolves the callable.
  ✔ NEW    — `self_check()` runtime diagnostic + CLI `--self-check`.
  ✔ FIXED  — `_extract_cookie_names()` scoped to the response + redirect
             chain, not the entire session (false positives eliminated).
  ✔ FIXED  — Extra-paths probe uses `resp.url or url` guard consistently.
  ✔ HARD   — Envelope tool name normalised to `"tech_fingerprint"`, with
             guaranteed `detections` (list) and `final_url` (str).

----------------------------------------------------------------------------
Acknowledgment
----------------------------------------------------------------------------
  • Author        : Yanxzyx   (#credit ~ Yanxzyx)
  • Framework     : Emergens / Oxysintx orchestrator stack
  • Dependencies  : `requests` (required) + optional
                    `dnspython` (CNAME chain detection), `Flask` (endpoint)
  • Data sources  : Wappalyzer-style signature corpus, builtwith
                    community signatures, public favicon hash databases
  • References    : Wappalyzer OSS signature taxonomy, HTTP Archive
                    technology detection guidelines
  • With thanks to the Wappalyzer project for the category taxonomy,
    the `requests` / `urllib3` maintainers for a sane HTTP model, and
    the dnspython team for reliable CNAME resolution.

----------------------------------------------------------------------------
Testing
----------------------------------------------------------------------------
  Quick smoke test (CLI):
      python3 -m modules.tech_fingerprint example.com
      python3 -m modules.tech_fingerprint --self-check

  Programmatic:
      from modules.tech_fingerprint import run, self_check
      print(self_check())
      print(run("example.com", mode="expert"))

  Flask wiring (in app.py):
      from modules.tech_fingerprint import register_blueprint
      register_blueprint(app)
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# ── Optional: Flask ──────────────────────────────────────────────────────
try:
    from flask import Blueprint, jsonify, request
    _HAS_FLASK = True
except Exception:
    _HAS_FLASK = False

# ── Optional: dnspython for CNAME chain detection ────────────────────────
try:
    import dns.resolver as _dns_resolver  # type: ignore
    _HAS_DNS = True
except ImportError:
    _dns_resolver = None
    _HAS_DNS = False


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING — isolated
# ═══════════════════════════════════════════════════════════════════════════
logger = logging.getLogger("oxysintx.tech_fingerprint")
logger.propagate = False
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_handler)
logger.setLevel(logging.INFO)

urllib3.disable_warnings(InsecureRequestWarning)


# ═══════════════════════════════════════════════════════════════════════════
# OPTIONAL: shared headers helper
# ═══════════════════════════════════════════════════════════════════════════
try:
    from modules._common import default_headers  # type: ignore
except Exception:
    def default_headers() -> Dict[str, str]:
        return {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
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
# METADATA
# ═══════════════════════════════════════════════════════════════════════════
__version__ = "3.1.0"
__author__  = "Yanxzyx"
__credit__  = "#credit ~ Yanxzyx"

TOOL_INFO = {
    "name": "Tech Fingerprint",
    "description": (
        "Passive detection of CMS, frameworks, servers, languages, "
        "analytics, CDNs, and security products from response headers, "
        "DNS CNAME chains, HTML markers, cookies, meta tags, favicon "
        "hashes, and multi-path probing."
    ),
    "version": __version__,
    "author": __author__,
    "credit": __credit__,
    "category": "Recon",
}
TOOL_KIND = "scanner"

DEFAULT_TIMEOUT      = 8
MAX_BODY_CHARS       = 300_000
MAX_FAVICON_BYTES    = 512_000
MAX_REDIRECTS        = 5
FAVICON_TIMEOUT      = 5
STREAM_CHUNK_SIZE    = 65_536

EXTRA_PATHS = ("/robots.txt", "/sitemap.xml", "/humans.txt")
EXTRA_PATH_MAX_CHARS = 30_000


# ═══════════════════════════════════════════════════════════════════════════
# SIGNATURE DATABASE
# ═══════════════════════════════════════════════════════════════════════════
SIGNATURES: List[Dict[str, Any]] = [
    # ─── CMS ─────────────────────────────────────────────────────────────
    {"name": "WordPress", "category": "CMS", "confidence": "high",
     "html": [r"wp-content/", r"wp-includes/", r"/wp-json/"],
     "meta_generator": [r"WordPress\s*([\d.]+)?"],
     "cookies": [r"^wordpress_", r"^wp-settings-"],
     "version_regex": r"WordPress\s*([\d.]+)"},
    {"name": "Joomla", "category": "CMS", "confidence": "high",
     "html": [r"/media/jui/", r"/components/com_", r"/templates/"],
     "meta_generator": [r"Joomla!?\s*([\d.]+)?"],
     "version_regex": r"Joomla!?\s*([\d.]+)"},
    {"name": "Drupal", "category": "CMS", "confidence": "high",
     "html": [r"Drupal\.settings", r"/sites/default/files", r"drupal-"],
     "meta_generator": [r"Drupal\s*([\d.]+)?"],
     "headers": {"x-generator": r"^Drupal"},
     "version_regex": r"Drupal\s*([\d.]+)"},
    {"name": "Magento", "category": "E-commerce", "confidence": "high",
     "html": [r"Magento_", r"/mage/", r"var/mage/"],
     "cookies": [r"^frontend=", r"^adminhtml="],
     "headers": {"x-magento-cache-debug": r".", "x-magento-vary": r"."}},
    {"name": "Ghost", "category": "CMS", "confidence": "high",
     "meta_generator": [r"Ghost\s*([\d.]+)?"],
     "html": [r"ghost-url", r'content="Ghost']},
    {"name": "Sitecore", "category": "CMS", "confidence": "high",
     "cookies": [r"^SC_ANALYTICS_", r"^shell#lang"],
     "html": [r"/sitecore/", r"Sitecore\.Web"]},
    {"name": "TYPO3", "category": "CMS", "confidence": "high",
     "meta_generator": [r"TYPO3"],
     "html": [r"/typo3conf/", r"/typo3temp/"]},
    {"name": "Contao", "category": "CMS", "confidence": "high",
     "html": [r"/assets/contao/", r"Contao"]},
    {"name": "Craft CMS", "category": "CMS", "confidence": "medium",
     "cookies": [r"^CraftSessionId$"],
     "html": [r"/craftcms/", r"craft\.cms"]},
    {"name": "October CMS", "category": "CMS", "confidence": "medium",
     "html": [r"/modules/system/assets/", r"octobercms"]},
    {"name": "HubSpot CMS", "category": "CMS", "confidence": "medium",
     "html": [r"hs-scripts\.com", r"hs-analytics\.net", r"hsforms\.net"],
     "cookies": [r"^hs_"]},
    {"name": "Squarespace", "category": "Website Builder", "confidence": "high",
     "html": [r"static1\.squarespace\.com", r"squarespace\.com/universal/"]},
    {"name": "Wix", "category": "Website Builder", "confidence": "high",
     "html": [r"static\.parastorage\.com", r"wixstatic\.com"],
     "headers": {"x-wix-request-id": r"."}},
    {"name": "Webflow", "category": "Website Builder", "confidence": "medium",
     "html": [r"assets\.website-files\.com", r"webflow\.js"]},
    {"name": "Hugo", "category": "Static Site Generator", "confidence": "medium",
     "meta_generator": [r"Hugo\s*([\d.]+)?"],
     "html": [r"/_hugo"]},
    {"name": "Jekyll", "category": "Static Site Generator", "confidence": "medium",
     "meta_generator": [r"Jekyll\s*v?([\d.]+)?"]},
    {"name": "Gatsby", "category": "Static Site Generator", "confidence": "medium",
     "html": [r"gatsby-", r"___gatsby"]},
    {"name": "Next.js", "category": "Framework", "confidence": "high",
     "html": [r"__NEXT_DATA__", r"/_next/static/"],
     "headers": {"x-powered-by": r"^Next\.js"}},
    {"name": "Nuxt.js", "category": "Framework", "confidence": "high",
     "html": [r"__NUXT__", r"/_nuxt/"]},
    {"name": "Docusaurus", "category": "Static Site Generator", "confidence": "medium",
     "meta_generator": [r"Docusaurus"],
     "html": [r"docusaurus"]},
    {"name": "Astro", "category": "Static Site Generator", "confidence": "medium",
     "meta_generator": [r"Astro\s*v?([\d.]+)?"],
     "html": [r"astro-island"]},

    # ─── E-COMMERCE ──────────────────────────────────────────────────────
    {"name": "Shopify", "category": "E-commerce", "confidence": "high",
     "html": [r"cdn\.shopify\.com", r"Shopify\.theme", r"/cdn/shop/"],
     "headers": {"x-shopid": r".", "x-shardid": r".", "x-sorting-hat-podid": r"."}},
    {"name": "WooCommerce", "category": "E-commerce", "confidence": "high",
     "html": [r"woocommerce", r"wc-ajax", r"/wp-content/plugins/woocommerce"]},
    {"name": "BigCommerce", "category": "E-commerce", "confidence": "high",
     "html": [r"cdn\d*\.bigcommerce\.com", r"/stencil/"]},
    {"name": "PrestaShop", "category": "E-commerce", "confidence": "high",
     "meta_generator": [r"PrestaShop"],
     "html": [r"/modules/ps_", r"prestashop"],
     "cookies": [r"^PrestaShop-"]},
    {"name": "OpenCart", "category": "E-commerce", "confidence": "medium",
     "html": [r"catalog/view/theme/", r"index\.php\?route="]},
    {"name": "Salesforce Commerce Cloud", "category": "E-commerce", "confidence": "medium",
     "html": [r"demandware\.static", r"/on/demandware\.store/"]},
    {"name": "Adobe Commerce", "category": "E-commerce", "confidence": "medium",
     "html": [r"magento", r"/static/version\d+/frontend/"]},
    {"name": "Ecwid", "category": "E-commerce", "confidence": "medium",
     "html": [r"app\.ecwid\.com", r"ecwid\.com/scripts"]},
    {"name": "Snipcart", "category": "E-commerce", "confidence": "medium",
     "html": [r"cdn\.snipcart\.com"]},

    # ─── JS FRAMEWORKS / LIBRARIES ───────────────────────────────────────
    {"name": "React", "category": "JS Framework", "confidence": "medium",
     "html": [r"data-reactroot", r"react-root", r"__REACT_DEVTOOLS"],
     "script_src": [r"/react(?:[.-]|/).*\.js"]},
    {"name": "Vue.js", "category": "JS Framework", "confidence": "medium",
     "html": [r"data-v-[0-9a-f]{6,}", r"__vue__", r"vue\.config"],
     "script_src": [r"/vue(?:@|\.min|\.runtime|-)"],
     "version_regex": r"Vue\.js\s*v?([\d.]+)"},
    {"name": "Angular", "category": "JS Framework", "confidence": "high",
     "html": [r'ng-version="([\d.]+)', r"ng-app=", r"_ngcontent"],
     "script_src": [r"/angular(?:[.-]|/)"],
     "version_regex": r'ng-version="([\d.]+)"'},
    {"name": "Svelte", "category": "JS Framework", "confidence": "medium",
     "html": [r"svelte-[0-9a-z]{6}", r"__svelte"]},
    {"name": "Alpine.js", "category": "JS Framework", "confidence": "medium",
     "html": [r'x-data="', r'x-init="'],
     "script_src": [r"alpine(?:\.min)?\.js"]},
    {"name": "Ember.js", "category": "JS Framework", "confidence": "medium",
     "html": [r"ember-view", r'data-ember-action']},
    {"name": "Backbone.js", "category": "JS Library", "confidence": "medium",
     "script_src": [r"/backbone(?:[.-]|/)"]},
    {"name": "jQuery", "category": "JS Library", "confidence": "high",
     "script_src": [r"/jquery[.-]?([\d.]+)?(?:\.min)?\.js", r"jquery/[\d.]+/jquery"],
     "version_regex": r"jquery[.-]?([\d.]+)(?:\.min)?\.js"},
    {"name": "jQuery Migrate", "category": "JS Library", "confidence": "medium",
     "script_src": [r"jquery-migrate"]},
    {"name": "jQuery UI", "category": "JS Library", "confidence": "medium",
     "script_src": [r"jquery-ui"]},
    {"name": "Bootstrap", "category": "CSS Framework", "confidence": "high",
     "script_src": [r"/bootstrap[.-]?([\d.]+)?(?:\.min)?\.(?:js|css)"],
     "html": [r"bootstrap\.min\.(?:js|css)"],
     "version_regex": r"bootstrap[.-]?([\d.]+)"},
    {"name": "Tailwind CSS", "category": "CSS Framework", "confidence": "low",
     "html": [r"tailwindcss", r"tw-[a-z]+-"]},
    {"name": "Foundation", "category": "CSS Framework", "confidence": "medium",
     "script_src": [r"foundation(?:\.min)?\.(?:js|css)"]},
    {"name": "Bulma", "category": "CSS Framework", "confidence": "medium",
     "script_src": [r"bulma(?:\.min)?\.css"]},
    {"name": "Materialize", "category": "CSS Framework", "confidence": "medium",
     "script_src": [r"materialize(?:\.min)?\.(?:js|css)"]},
    {"name": "Font Awesome", "category": "Font/Icon", "confidence": "medium",
     "script_src": [r"kit\.fontawesome\.com", r"use\.fontawesome\.com", r"font-?awesome"],
     "html": [r"fa-[a-z]+ fa-"]},
    {"name": "Lodash", "category": "JS Library", "confidence": "medium",
     "script_src": [r"/lodash(?:[.-]|/)"]},
    {"name": "Underscore.js", "category": "JS Library", "confidence": "medium",
     "script_src": [r"/underscore(?:[.-]|/)"]},
    {"name": "Moment.js", "category": "JS Library", "confidence": "medium",
     "script_src": [r"/moment(?:[.-]|/)"]},
    {"name": "Day.js", "category": "JS Library", "confidence": "medium",
     "script_src": [r"dayjs(?:\.min)?\.js"]},
    {"name": "D3.js", "category": "JS Library", "confidence": "medium",
     "script_src": [r"/d3(?:[.-]|/)"]},
    {"name": "Three.js", "category": "JS Library", "confidence": "medium",
     "script_src": [r"/three(?:[.-]|/)"],
     "html": [r"THREE\."]},
    {"name": "Chart.js", "category": "JS Library", "confidence": "medium",
     "script_src": [r"chart(?:\.min)?\.js"]},
    {"name": "Swiper", "category": "JS Library", "confidence": "medium",
     "script_src": [r"swiper(?:\.min)?\.(?:js|css)"]},
    {"name": "GSAP", "category": "JS Library", "confidence": "medium",
     "script_src": [r"gsap(?:\.min)?\.js", r"/gsap/"]},
    {"name": "Popper.js", "category": "JS Library", "confidence": "medium",
     "script_src": [r"popper(?:\.min)?\.js"]},
    {"name": "Axios", "category": "JS Library", "confidence": "medium",
     "script_src": [r"axios(?:\.min)?\.js"]},

    # ─── WEB SERVERS / HOSTING ───────────────────────────────────────────
    {"name": "Nginx", "category": "Web Server", "confidence": "high",
     "headers": {"server": r"\bnginx(?:/([\d.]+))?"},
     "version_regex": r"nginx/([\d.]+)"},
    {"name": "Apache HTTP Server", "category": "Web Server", "confidence": "high",
     "headers": {"server": r"\bApache(?:/([\d.]+))?"},
     "version_regex": r"Apache/([\d.]+)"},
    {"name": "Apache Tomcat", "category": "Web Server", "confidence": "high",
     "headers": {"server": r"Apache-Coyote|Tomcat"},
     "html": [r"Apache Tomcat"]},
    {"name": "Microsoft IIS", "category": "Web Server", "confidence": "high",
     "headers": {"server": r"Microsoft-IIS(?:/([\d.]+))?"},
     "version_regex": r"Microsoft-IIS/([\d.]+)"},
    {"name": "LiteSpeed", "category": "Web Server", "confidence": "high",
     "headers": {"server": r"LiteSpeed"}},
    {"name": "Caddy", "category": "Web Server", "confidence": "high",
     "headers": {"server": r"Caddy"}},
    {"name": "OpenResty", "category": "Web Server", "confidence": "high",
     "headers": {"server": r"openresty(?:/([\d.]+))?"},
     "version_regex": r"openresty/([\d.]+)"},
    {"name": "Gunicorn", "category": "Web Server", "confidence": "high",
     "headers": {"server": r"gunicorn(?:/([\d.]+))?"},
     "version_regex": r"gunicorn/([\d.]+)"},
    {"name": "Werkzeug", "category": "Web Server", "confidence": "high",
     "headers": {"server": r"Werkzeug(?:/([\d.]+))?"},
     "version_regex": r"Werkzeug/([\d.]+)"},
    {"name": "Uvicorn", "category": "Web Server", "confidence": "medium",
     "headers": {"server": r"uvicorn"}},
    {"name": "Kestrel", "category": "Web Server", "confidence": "medium",
     "headers": {"server": r"Kestrel"}},
    {"name": "Cowboy", "category": "Web Server", "confidence": "medium",
     "headers": {"server": r"Cowboy"}},

    # ─── HOSTING PLATFORMS ───────────────────────────────────────────────
    {"name": "Vercel", "category": "Hosting", "confidence": "high",
     "headers": {"server": r"Vercel", "x-vercel-id": r"."}},
    {"name": "Netlify", "category": "Hosting", "confidence": "high",
     "headers": {"server": r"Netlify", "x-nf-request-id": r"."}},
    {"name": "GitHub Pages", "category": "Hosting", "confidence": "high",
     "headers": {"server": r"GitHub\.com", "x-github-request-id": r"."}},
    {"name": "Heroku", "category": "Hosting", "confidence": "medium",
     "headers": {"via": r"vegur", "x-heroku-request-id": r"."}},
    {"name": "Firebase Hosting", "category": "Hosting", "confidence": "high",
     "headers": {"server": r"Firebase", "x-served-by": r"^(?:cache|hosting)"}},
    {"name": "Render", "category": "Hosting", "confidence": "medium",
     "headers": {"server": r"Render"}},
    {"name": "Fly.io", "category": "Hosting", "confidence": "medium",
     "headers": {"server": r"Fly", "fly-request-id": r"."}},
    {"name": "Railway", "category": "Hosting", "confidence": "medium",
     "headers": {"x-railway-": r"."}},
    {"name": "Amazon S3", "category": "Storage/CDN", "confidence": "high",
     "headers": {"server": r"AmazonS3", "x-amz-request-id": r"."}},
    {"name": "Google Cloud Storage", "category": "Storage/CDN", "confidence": "medium",
     "headers": {"server": r"UploadServer", "x-goog-generation": r"."}},
    {"name": "Azure Blob Storage", "category": "Storage/CDN", "confidence": "medium",
     "headers": {"x-ms-request-id": r".", "x-ms-version": r"."}},

    # ─── LANGUAGES / FRAMEWORKS ──────────────────────────────────────────
    {"name": "PHP", "category": "Language", "confidence": "high",
     "headers": {"x-powered-by": r"PHP/([\d.]+)"},
     "cookies": [r"^PHPSESSID$"],
     "version_regex": r"PHP/([\d.]+)"},
    {"name": "ASP.NET", "category": "Framework", "confidence": "high",
     "headers": {"x-aspnet-version": r"([\d.]+)", "x-powered-by": r"ASP\.NET"},
     "cookies": [r"^ASP\.NET_SessionId$"]},
    {"name": "ASP.NET MVC", "category": "Framework", "confidence": "medium",
     "headers": {"x-aspnetmvc-version": r"([\d.]+)"}},
    {"name": "Express", "category": "Framework", "confidence": "high",
     "headers": {"x-powered-by": r"Express"}},
    {"name": "Django", "category": "Framework", "confidence": "medium",
     "cookies": [r"^csrftoken$", r"^django"],
     "html": [r"csrfmiddlewaretoken"]},
    {"name": "Flask", "category": "Framework", "confidence": "medium",
     "cookies": [r"^session$"],
     "headers": {"server": r"Werkzeug"}},
    {"name": "FastAPI", "category": "Framework", "confidence": "low",
     "headers": {"server": r"uvicorn"}},
    {"name": "Ruby on Rails", "category": "Framework", "confidence": "medium",
     "cookies": [r"^_rails", r"^_session_id$"],
     "headers": {"x-powered-by": r"Phusion Passenger"}},
    {"name": "Spring Boot", "category": "Framework", "confidence": "medium",
     "cookies": [r"^JSESSIONID$"],
     "headers": {"x-application-context": r"."}},
    {"name": "Laravel", "category": "Framework", "confidence": "medium",
     "cookies": [r"^laravel_session$", r"^XSRF-TOKEN$"]},
    {"name": "Symfony", "category": "Framework", "confidence": "medium",
     "cookies": [r"^symfony$"],
     "headers": {"x-debug-token": r"."}},
    {"name": "CodeIgniter", "category": "Framework", "confidence": "medium",
     "cookies": [r"^ci_session$"]},
    {"name": "CakePHP", "category": "Framework", "confidence": "medium",
     "cookies": [r"^CAKEPHP$", r"^cakephp$"]},
    {"name": "Yii", "category": "Framework", "confidence": "medium",
     "cookies": [r"^YII_CSRF_TOKEN$"]},
    {"name": "Golang", "category": "Language", "confidence": "medium",
     "headers": {"server": r"^Go-http-client"}},
    {"name": "Node.js", "category": "Language", "confidence": "medium",
     "headers": {"x-powered-by": r"^Express|^Node\.js"}},

    # ─── CDN / EDGE ──────────────────────────────────────────────────────
    {"name": "Cloudflare", "category": "CDN/Security", "confidence": "high",
     "headers": {"cf-ray": r".", "cf-cache-status": r".", "server": r"^cloudflare$"},
     "cookies": [r"^__cfduid$", r"^__cf_bm$", r"^cf_clearance$"]},
    {"name": "Akamai", "category": "CDN", "confidence": "high",
     "headers": {"x-akamai-transformed": r".", "server": r"AkamaiGHost"},
     "cookies": [r"^ak_bmsc$", r"^bm_sz$"]},
    {"name": "Fastly", "category": "CDN", "confidence": "high",
     "headers": {"x-served-by": r"cache-", "x-fastly-request-id": r"."}},
    {"name": "Amazon CloudFront", "category": "CDN", "confidence": "high",
     "headers": {"x-amz-cf-id": r".", "via": r"CloudFront"}},
    {"name": "Google Cloud CDN", "category": "CDN", "confidence": "medium",
     "headers": {"via": r"google", "x-goog-": r"."}},
    {"name": "Bunny CDN", "category": "CDN", "confidence": "medium",
     "headers": {"server": r"BunnyCDN"}},
    {"name": "StackPath", "category": "CDN", "confidence": "medium",
     "headers": {"server": r"StackPath"}},
    {"name": "KeyCDN", "category": "CDN", "confidence": "medium",
     "headers": {"server": r"keycdn"}},
    {"name": "Sucuri CloudProxy", "category": "WAF/CDN", "confidence": "high",
     "headers": {"x-sucuri-id": r".", "server": r"Sucuri"}},
    {"name": "Incapsula/Imperva", "category": "WAF/CDN", "confidence": "high",
     "headers": {"x-iinfo": r".", "x-cdn": r"Incapsula"},
     "cookies": [r"^incap_ses_", r"^visid_incap_"]},
    {"name": "Azure Front Door", "category": "CDN", "confidence": "medium",
     "headers": {"x-azure-ref": r".", "x-fd-healthprobe": r"."}},
    {"name": "jsDelivr", "category": "CDN", "confidence": "medium",
     "script_src": [r"cdn\.jsdelivr\.net"]},
    {"name": "unpkg", "category": "CDN", "confidence": "medium",
     "script_src": [r"unpkg\.com"]},
    {"name": "cdnjs", "category": "CDN", "confidence": "medium",
     "script_src": [r"cdnjs\.cloudflare\.com"]},

    # ─── WAF / ANTI-BOT ──────────────────────────────────────────────────
    {"name": "AWS WAF", "category": "WAF", "confidence": "medium",
     "cookies": [r"^aws-waf-token$"]},
    {"name": "ModSecurity", "category": "WAF", "confidence": "medium",
     "headers": {"server": r"ModSecurity|NOYB"}},
    {"name": "Wordfence", "category": "WAF", "confidence": "medium",
     "html": [r"wordfence"],
     "cookies": [r"^wfvt_"]},
    {"name": "Barracuda WAF", "category": "WAF", "confidence": "low",
     "cookies": [r"^barra_counter_session$"]},
    {"name": "F5 BIG-IP ASM", "category": "WAF", "confidence": "low",
     "cookies": [r"^TS[0-9a-f]{8}$", r"^BIGipServer"]},
    {"name": "reCAPTCHA", "category": "Anti-bot", "confidence": "medium",
     "html": [r"google\.com/recaptcha", r"g-recaptcha"]},
    {"name": "hCaptcha", "category": "Anti-bot", "confidence": "medium",
     "html": [r"hcaptcha\.com", r"h-captcha"]},
    {"name": "Cloudflare Turnstile", "category": "Anti-bot", "confidence": "medium",
     "html": [r"challenges\.cloudflare\.com/turnstile"]},

    # ─── ANALYTICS / TRACKING ────────────────────────────────────────────
    {"name": "Google Analytics (Universal)", "category": "Analytics", "confidence": "high",
     "script_src": [r"google-analytics\.com/analytics\.js"],
     "html": [r"ga\('create'"]},
    {"name": "Google Analytics 4", "category": "Analytics", "confidence": "high",
     "script_src": [r"googletagmanager\.com/gtag/js"],
     "html": [r"gtag\('config'"]},
    {"name": "Google Tag Manager", "category": "Tag Manager", "confidence": "high",
     "script_src": [r"googletagmanager\.com/gtm\.js"],
     "html": [r"GTM-[A-Z0-9]+"]},
    {"name": "Facebook Pixel", "category": "Analytics", "confidence": "high",
     "script_src": [r"connect\.facebook\.net/.*/fbevents\.js"],
     "html": [r"fbq\('init'"]},
    {"name": "Hotjar", "category": "Analytics", "confidence": "high",
     "script_src": [r"static\.hotjar\.com"]},
    {"name": "Segment", "category": "Analytics", "confidence": "medium",
     "script_src": [r"cdn\.segment\.com"]},
    {"name": "Mixpanel", "category": "Analytics", "confidence": "medium",
     "script_src": [r"cdn\.mxpnl\.com", r"mixpanel"]},
    {"name": "Matomo/Piwik", "category": "Analytics", "confidence": "medium",
     "script_src": [r"matomo\.js", r"piwik\.js"],
     "html": [r"_paq\.push"]},
    {"name": "Plausible", "category": "Analytics", "confidence": "medium",
     "script_src": [r"plausible\.io/js/"]},
    {"name": "Umami", "category": "Analytics", "confidence": "medium",
     "script_src": [r"/umami\.js", r"umami\.is"]},
    {"name": "Microsoft Clarity", "category": "Analytics", "confidence": "medium",
     "script_src": [r"clarity\.ms"]},
    {"name": "Yandex Metrica", "category": "Analytics", "confidence": "medium",
     "script_src": [r"mc\.yandex\.ru"]},
    {"name": "Baidu Tongji", "category": "Analytics", "confidence": "medium",
     "script_src": [r"hm\.baidu\.com"]},
    {"name": "TikTok Pixel", "category": "Analytics", "confidence": "medium",
     "script_src": [r"analytics\.tiktok\.com"]},
    {"name": "LinkedIn Insight", "category": "Analytics", "confidence": "medium",
     "script_src": [r"snap\.licdn\.com"]},
    {"name": "Twitter/X Pixel", "category": "Analytics", "confidence": "medium",
     "script_src": [r"static\.ads-twitter\.com"]},
    {"name": "Pinterest Tag", "category": "Analytics", "confidence": "medium",
     "script_src": [r"ct\.pinterest\.com"]},
    {"name": "New Relic", "category": "APM", "confidence": "medium",
     "script_src": [r"js-agent\.newrelic\.com", r"nr-data\.net"]},
    {"name": "Datadog RUM", "category": "APM", "confidence": "medium",
     "script_src": [r"datadoghq-browser-agent\.com"]},
    {"name": "Sentry", "category": "Error Monitoring", "confidence": "medium",
     "script_src": [r"browser\.sentry-cdn\.com"]},
    {"name": "Bugsnag", "category": "Error Monitoring", "confidence": "medium",
     "script_src": [r"d2wy8f7a9ursnm\.cloudfront\.net"]},
    {"name": "Rollbar", "category": "Error Monitoring", "confidence": "medium",
     "script_src": [r"cdn\.rollbar\.com"]},

    # ─── MARKETING / SUPPORT / CRM ───────────────────────────────────────
    {"name": "HubSpot", "category": "Marketing", "confidence": "medium",
     "script_src": [r"js\.hs-scripts\.com", r"js\.hubspot\.com"]},
    {"name": "Intercom", "category": "Support", "confidence": "medium",
     "script_src": [r"widget\.intercom\.io", r"js\.intercomcdn\.com"]},
    {"name": "Zendesk", "category": "Support", "confidence": "medium",
     "script_src": [r"static\.zdassets\.com"]},
    {"name": "Crisp", "category": "Support", "confidence": "medium",
     "script_src": [r"client\.crisp\.chat"]},
    {"name": "Tawk.to", "category": "Support", "confidence": "medium",
     "script_src": [r"embed\.tawk\.to"]},
    {"name": "Drift", "category": "Support", "confidence": "medium",
     "script_src": [r"js\.driftt\.com"]},
    {"name": "Freshchat", "category": "Support", "confidence": "medium",
     "script_src": [r"wchat\.freshchat\.com"]},
    {"name": "LiveChat", "category": "Support", "confidence": "medium",
     "script_src": [r"cdn\.livechatinc\.com"]},
    {"name": "Mailchimp", "category": "Marketing", "confidence": "medium",
     "script_src": [r"chimpstatic\.com", r"mailchimp\.com"]},
    {"name": "Klaviyo", "category": "Marketing", "confidence": "medium",
     "script_src": [r"static\.klaviyo\.com"]},

    # ─── PAYMENTS ────────────────────────────────────────────────────────
    {"name": "Stripe", "category": "Payments", "confidence": "medium",
     "script_src": [r"js\.stripe\.com"],
     "html": [r"""Stripe\(['"]pk_"""]},
    {"name": "PayPal", "category": "Payments", "confidence": "medium",
     "script_src": [r"paypal\.com/sdk/js", r"paypalobjects\.com"]},
    {"name": "Razorpay", "category": "Payments", "confidence": "medium",
     "script_src": [r"checkout\.razorpay\.com"]},
    {"name": "Square", "category": "Payments", "confidence": "medium",
     "script_src": [r"js\.squareup\.com"]},
    {"name": "Braintree", "category": "Payments", "confidence": "medium",
     "script_src": [r"js\.braintreegateway\.com"]},
    {"name": "Adyen", "category": "Payments", "confidence": "medium",
     "script_src": [r"checkoutshopper-(?:live|test)\.adyen\.com"]},
    {"name": "Klarna", "category": "Payments", "confidence": "medium",
     "script_src": [r"x\.klarnacdn\.net"]},
    {"name": "Paddle", "category": "Payments", "confidence": "medium",
     "script_src": [r"cdn\.paddle\.com"]},

    # ─── MISC / UTILITY ──────────────────────────────────────────────────
    {"name": "Google Fonts", "category": "Font/Icon", "confidence": "medium",
     "script_src": [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"]},
    {"name": "Typekit/Adobe Fonts", "category": "Font/Icon", "confidence": "medium",
     "script_src": [r"use\.typekit\.net", r"use\.typekit\.com"]},
    {"name": "Optimizely", "category": "A/B Testing", "confidence": "medium",
     "script_src": [r"cdn\.optimizely\.com"]},
    {"name": "Disqus", "category": "Comments", "confidence": "medium",
     "script_src": [r"disqus\.com/embed\.js", r"disquscdn\.com"]},
    {"name": "Algolia", "category": "Search", "confidence": "medium",
     "script_src": [r"algolia\.net"]},
    {"name": "Google Maps", "category": "Maps", "confidence": "medium",
     "script_src": [r"maps\.googleapis\.com/maps/api/js"]},
    {"name": "Mapbox", "category": "Maps", "confidence": "medium",
     "script_src": [r"api\.mapbox\.com"]},
    {"name": "YouTube Embed", "category": "Media", "confidence": "low",
     "html": [r"youtube\.com/embed/", r"youtube-nocookie\.com"]},
    {"name": "Vimeo Embed", "category": "Media", "confidence": "low",
     "html": [r"player\.vimeo\.com"]},
    {"name": "reCAPTCHA Enterprise", "category": "Anti-bot", "confidence": "medium",
     "script_src": [r"recaptcha/enterprise\.js"]},
]


def _compile_signatures() -> None:
    for sig in SIGNATURES:
        for key in ("html", "meta_generator", "script_src", "cookies"):
            if key in sig:
                sig[f"_{key}_re"] = [re.compile(p, re.IGNORECASE) for p in sig[key]]
        if "headers" in sig:
            sig["_headers_re"] = {
                h.lower(): re.compile(p, re.IGNORECASE)
                for h, p in sig["headers"].items()
            }
        if "version_regex" in sig:
            try:
                sig["_version_re"] = re.compile(sig["version_regex"], re.IGNORECASE)
            except re.error:
                sig["_version_re"] = None


_compile_signatures()


# ═══════════════════════════════════════════════════════════════════════════
# FAVICON HASH DATABASE (SHA-256 of well-known /favicon.ico)
# ═══════════════════════════════════════════════════════════════════════════
FAVICON_HASHES: Dict[str, Tuple[str, str]] = {
    # Populate with verified SHA-256 hex digests from live sites or a
    # public DB (favihash, Shodan favicon DB). Known placeholder:
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        ("Empty favicon (S3-style)", "Storage/CDN"),
}


# ═══════════════════════════════════════════════════════════════════════════
# DNS CNAME PATTERNS
# ═══════════════════════════════════════════════════════════════════════════
DNS_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"cloudflare\.net$", re.I),          "Cloudflare", "CDN/Security"),
    (re.compile(r"cloudfront\.net$", re.I),          "Amazon CloudFront", "CDN"),
    (re.compile(r"fastly\.net$|fastlylb\.net$", re.I), "Fastly", "CDN"),
    (re.compile(r"edgekey\.net$|edgesuite\.net$|akamaiedge\.net$|akamai\.net$", re.I),
        "Akamai", "CDN"),
    (re.compile(r"netlify\.app$|netlify\.com$", re.I), "Netlify", "Hosting"),
    (re.compile(r"vercel-dns\.com$|vercel\.app$", re.I), "Vercel", "Hosting"),
    (re.compile(r"github\.io$", re.I),                "GitHub Pages", "Hosting"),
    (re.compile(r"herokudns\.com$|herokuapp\.com$", re.I), "Heroku", "Hosting"),
    (re.compile(r"myshopify\.com$|shopify\.com$", re.I), "Shopify", "E-commerce"),
    (re.compile(r"wpengine\.com$", re.I),             "WP Engine", "Hosting"),
    (re.compile(r"pantheonsite\.io$", re.I),          "Pantheon", "Hosting"),
    (re.compile(r"wixsite\.com$|wix\.com$", re.I),    "Wix", "Website Builder"),
    (re.compile(r"squarespace\.com$", re.I),          "Squarespace", "Website Builder"),
    (re.compile(r"webflow\.io$", re.I),               "Webflow", "Website Builder"),
    (re.compile(r"s3\.amazonaws\.com$|s3-.*\.amazonaws\.com$", re.I),
        "Amazon S3", "Storage/CDN"),
    (re.compile(r"azureedge\.net$", re.I),            "Azure CDN", "CDN"),
    (re.compile(r"azurewebsites\.net$", re.I),        "Azure App Service", "Hosting"),
    (re.compile(r"trafficmanager\.net$", re.I),       "Azure Traffic Manager", "CDN"),
    (re.compile(r"b-cdn\.net$", re.I),                "Bunny CDN", "CDN"),
    (re.compile(r"stackpathdns\.com$", re.I),         "StackPath", "CDN"),
    (re.compile(r"incapdns\.net$", re.I),             "Imperva Incapsula", "WAF/CDN"),
    (re.compile(r"sucuri\.net$", re.I),               "Sucuri", "WAF/CDN"),
    (re.compile(r"firebaseapp\.com$", re.I),          "Firebase Hosting", "Hosting"),
    (re.compile(r"ghs\.googlehosted\.com$|googleusercontent\.com$", re.I),
        "Google Hosted", "Hosting"),
    (re.compile(r"readthedocs\.io$", re.I),           "Read the Docs", "Hosting"),
    (re.compile(r"surge\.sh$", re.I),                 "Surge.sh", "Hosting"),
    (re.compile(r"fly\.dev$", re.I),                  "Fly.io", "Hosting"),
    (re.compile(r"render\.com$", re.I),               "Render", "Hosting"),
]


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class Detection:
    name: str
    category: str
    confidence: str
    version: Optional[str] = None
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "confidence": self.confidence,
            "version": self.version,
            "evidence": self.evidence,
        }


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def _normalize_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t


def _extract_hostname(target: str) -> str:
    try:
        return urlparse(_normalize_target(target)).hostname or ""
    except Exception:
        return ""


def _dns_cname_chain(host: str, max_depth: int = 5) -> List[str]:
    """Return CNAME chain for `host`. Empty list if dnspython unavailable."""
    if not _HAS_DNS or not host:
        return []
    chain: List[str] = []
    current = host
    seen = set()
    for _ in range(max_depth):
        if current in seen:
            break
        seen.add(current)
        try:
            answers = _dns_resolver.resolve(current, "CNAME", lifetime=4)
            for rdata in answers:
                target = str(rdata.target).rstrip(".")
                if target and target not in chain:
                    chain.append(target)
                    current = target
                    break
            else:
                break
        except Exception:
            break
    return chain


def _extract_cookie_names(
    resp: requests.Response,
    session: Optional[requests.Session] = None,
) -> List[str]:
    """
    Extract cookie names.

    v3.1.0: scoped to response cookies plus redirect-chain cookies only.
    Previously iterated `session.cookies` which could include stale
    cookies from prior requests in a reused session, producing false
    positives.
    """
    seen = set()
    names: List[str] = []

    def _add(name: str) -> None:
        if name and name not in seen:
            seen.add(name)
            names.append(name)

    # Cookies set in the current response
    try:
        for c in resp.cookies:
            _add(c.name)
    except Exception:
        pass

    # Cookies set along the redirect chain
    try:
        for h in (resp.history or []):
            for c in h.cookies:
                _add(c.name)
    except Exception:
        pass

    # Only fall back to session cookies if the response yielded nothing
    if not names and session is not None:
        try:
            for c in session.cookies:
                _add(c.name)
        except Exception:
            pass

    return names


def _extract_script_srcs(html: str) -> List[str]:
    urls: List[str] = []
    for pat in (
        r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']',
        r'<link[^>]+href\s*=\s*["\']([^"\']+)["\']',
    ):
        for m in re.finditer(pat, html, re.IGNORECASE):
            urls.append(m.group(1))
    return urls


def _extract_meta_generator(html: str) -> List[str]:
    results: List[str] = []
    for m in re.finditer(
        r'<meta\s+[^>]*name\s*=\s*["\']generator["\'][^>]*content\s*=\s*["\']([^"\']+)["\']',
        html, re.IGNORECASE,
    ):
        results.append(m.group(1))
    for m in re.finditer(
        r'<meta\s+[^>]*content\s*=\s*["\']([^"\']+)["\'][^>]*name\s*=\s*["\']generator["\']',
        html, re.IGNORECASE,
    ):
        results.append(m.group(1))
    return results


def _read_response_body(
    resp: requests.Response, max_bytes: int, chunk_size: int = STREAM_CHUNK_SIZE,
) -> bytes:
    buf = bytearray()
    try:
        for chunk in resp.iter_content(chunk_size=chunk_size):
            if not chunk:
                continue
            remaining = max_bytes - len(buf)
            if remaining <= 0:
                break
            buf.extend(chunk[:remaining])
    except requests.exceptions.RequestException as e:
        logger.debug("Body read interrupted: %s", e)
    return bytes(buf)


def _fetch_favicon_hash(
    session: requests.Session, base_url: str, timeout: int,
) -> Optional[str]:
    try:
        parsed = urlparse(base_url)
        favicon_url = urlunparse(
            parsed._replace(path="/favicon.ico", params="", query="", fragment="")
        )
        r = session.get(
            favicon_url, timeout=timeout, verify=False,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "image/*,*/*;q=0.5"},
            stream=True,
        )
        if not r.ok:
            return None
        content = _read_response_body(r, MAX_FAVICON_BYTES, chunk_size=8192)
        if not content or len(content) >= MAX_FAVICON_BYTES:
            return None
        return hashlib.sha256(content).hexdigest()
    except Exception as e:
        logger.debug("Favicon fetch failed for %s: %s", base_url, e)
    return None


def _probe_extra_paths(
    session: requests.Session, base_url: str, timeout: int,
) -> Dict[str, str]:
    """Fetch /robots.txt, /sitemap.xml, /humans.txt. Returns {path: text}."""
    out: Dict[str, str] = {}
    try:
        parsed = urlparse(base_url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    except Exception:
        return out
    for path in EXTRA_PATHS:
        try:
            r = session.get(
                base + path, timeout=timeout, verify=False,
                headers=default_headers(), allow_redirects=True, stream=True,
            )
            if not r.ok:
                continue
            body = _read_response_body(r, EXTRA_PATH_MAX_CHARS, chunk_size=8192)
            if not body:
                continue
            encoding = r.encoding or "utf-8"
            try:
                text = body.decode(encoding, errors="ignore")
            except (LookupError, UnicodeDecodeError):
                text = body.decode("utf-8", errors="ignore")
            out[path] = text
        except Exception as e:
            logger.debug("Extra path %s failed: %s", path, e)
    return out


# ═══════════════════════════════════════════════════════════════════════════
# DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════
def _detect_from_headers(resp: requests.Response) -> List[Detection]:
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    detections: List[Detection] = []
    for sig in SIGNATURES:
        compiled = sig.get("_headers_re")
        if not compiled:
            continue
        for hname, hre in compiled.items():
            hval = headers_lower.get(hname)
            if hval and hre.search(hval):
                version = None
                vre = sig.get("_version_re")
                if vre:
                    m = vre.search(hval)
                    if m and m.groups():
                        version = m.group(1)
                detections.append(Detection(
                    name=sig["name"], category=sig["category"],
                    confidence=sig["confidence"], version=version,
                    evidence=[f"header: {hname}: {hval[:120]}"],
                ))
                break
    return detections


def _detect_from_cookies(cookie_names: List[str]) -> List[Detection]:
    detections: List[Detection] = []
    for sig in SIGNATURES:
        compiled = sig.get("_cookies_re")
        if not compiled:
            continue
        for name in cookie_names:
            for cre in compiled:
                if cre.search(name):
                    detections.append(Detection(
                        name=sig["name"], category=sig["category"],
                        confidence=sig["confidence"],
                        evidence=[f"cookie: {name}"],
                    ))
                    break
            else:
                continue
            break
    return detections


def _detect_from_html(
    html: str, meta_generators: List[str], script_srcs: List[str],
) -> List[Detection]:
    detections: List[Detection] = []
    script_blob = " ".join(script_srcs)
    for sig in SIGNATURES:
        matched = False
        evidence: List[str] = []

        for mre in sig.get("_meta_generator_re", []):
            for mgen in meta_generators:
                if mre.search(mgen):
                    evidence.append(f"meta generator: {mgen}")
                    matched = True
                    break
            if matched:
                break

        if not matched:
            for sre in sig.get("_script_src_re", []):
                m = sre.search(script_blob)
                if m:
                    evidence.append(f"script src: {m.group(0)[:120]}")
                    matched = True
                    break

        if not matched:
            for hre in sig.get("_html_re", []):
                m = hre.search(html)
                if m:
                    evidence.append(f"html: {m.group(0)[:120]}")
                    matched = True
                    break

        if matched:
            version = None
            vre = sig.get("_version_re")
            if vre:
                for source in (" ".join(meta_generators), script_blob, html):
                    m = vre.search(source)
                    if m and m.groups():
                        version = m.group(1)
                        break
            detections.append(Detection(
                name=sig["name"], category=sig["category"],
                confidence=sig["confidence"], version=version,
                evidence=evidence,
            ))
    return detections


def _detect_from_dns(host: str) -> List[Detection]:
    chain = _dns_cname_chain(host)
    detections: List[Detection] = []
    for cname in chain:
        for pat, name, category in DNS_PATTERNS:
            if pat.search(cname):
                detections.append(Detection(
                    name=name, category=category, confidence="high",
                    evidence=[f"DNS CNAME: {cname}"],
                ))
                break
    return detections


def _detect_from_extra_paths(extra: Dict[str, str]) -> List[Detection]:
    detections: List[Detection] = []
    if not extra:
        return detections
    for path, text in extra.items():
        lower = text.lower()
        if path == "/robots.txt":
            if "wp-admin" in lower or "wp-content" in lower:
                detections.append(Detection(
                    name="WordPress", category="CMS", confidence="high",
                    evidence=[f"{path}: wp-admin / wp-content disallow"],
                ))
            if "sitemap" in lower and "shopify" in lower:
                detections.append(Detection(
                    name="Shopify", category="E-commerce", confidence="medium",
                    evidence=[f"{path}: shopify sitemap"],
                ))
            if "disallow: /admin" in lower and "magento" in lower:
                detections.append(Detection(
                    name="Magento", category="E-commerce", confidence="medium",
                    evidence=[f"{path}: magento admin disallow"],
                ))
        if path == "/sitemap.xml":
            if "wp-sitemap" in lower:
                detections.append(Detection(
                    name="WordPress", category="CMS", confidence="medium",
                    evidence=[f"{path}: wp-sitemap namespace"],
                ))
            if "shopify" in lower:
                detections.append(Detection(
                    name="Shopify", category="E-commerce", confidence="medium",
                    evidence=[f"{path}: shopify sitemap"],
                ))
    return detections


def _detect_from_favicon(favicon_hash: Optional[str]) -> List[Detection]:
    if not favicon_hash:
        return []
    entry = FAVICON_HASHES.get(favicon_hash)
    if not entry:
        return []
    name, category = entry
    return [Detection(
        name=name, category=category, confidence="high",
        evidence=[f"favicon SHA-256: {favicon_hash[:16]}…"],
    )]


def _merge_detections(dets: List[Detection]) -> List[Detection]:
    merged: Dict[str, Detection] = {}
    conf_rank = {"high": 3, "medium": 2, "low": 1}
    for d in dets:
        if d.name in merged:
            existing = merged[d.name]
            for ev in d.evidence:
                if ev not in existing.evidence:
                    existing.evidence.append(ev)
            if not existing.version and d.version:
                existing.version = d.version
            if conf_rank.get(d.confidence, 0) > conf_rank.get(existing.confidence, 0):
                existing.confidence = d.confidence
        else:
            merged[d.name] = Detection(
                name=d.name, category=d.category,
                confidence=d.confidence, version=d.version,
                evidence=list(d.evidence),
            )
    return list(merged.values())


def _build_summary(detections: List[Detection]) -> Dict[str, List[str]]:
    by_cat: Dict[str, List[str]] = {}
    for d in detections:
        by_cat.setdefault(d.category, []).append(d.name)
    for names in by_cat.values():
        names.sort()
    return dict(sorted(by_cat.items()))


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
def run(target: str, mode: str = "basic", **kwargs) -> Dict[str, Any]:
    """
    Fingerprint `target`. Never raises — errors returned in result['error'].

    kwargs:
        timeout (int)         — default 8
        check_favicon (bool)  — default True
        probe_extra (bool)    — default True (robots.txt / sitemap.xml / humans.txt)
        max_redirects (int)   — default 5
        verbose (bool)        — default False
    """
    timeout       = int(kwargs.get("timeout", DEFAULT_TIMEOUT))
    check_favicon = bool(kwargs.get("check_favicon", True))
    max_redirects = int(kwargs.get("max_redirects", MAX_REDIRECTS))
    probe_extra   = bool(kwargs.get("probe_extra", True))
    verbose       = bool(kwargs.get("verbose", False))

    if verbose:
        logger.setLevel(logging.DEBUG)

    url = _normalize_target(target)
    if not url:
        return _error_result(target, "Empty target — provide a domain or URL.")

    host = _extract_hostname(target)

    session = requests.Session()
    session.max_redirects = max_redirects
    try:
        try:
            resp = session.get(
                url, timeout=timeout,
                headers=default_headers(),
                allow_redirects=True, verify=False, stream=True,
            )
        except requests.exceptions.SSLError as e:
            return _error_result(target, f"SSL error: {e}")
        except requests.exceptions.TooManyRedirects as e:
            return _error_result(target, f"Too many redirects: {e}")
        except requests.exceptions.Timeout:
            return _error_result(target, f"Request timed out after {timeout}s")
        except requests.exceptions.ConnectionError as e:
            return _error_result(target, f"Connection error: {e}")
        except requests.exceptions.RequestException as e:
            return _error_result(target, f"Request failed: {e}")
        except Exception as e:
            logger.exception("Unexpected error scanning %s", target)
            return _error_result(target, str(e))

        body_bytes = _read_response_body(resp, MAX_BODY_CHARS)
        encoding = resp.encoding or "utf-8"
        try:
            html = body_bytes.decode(encoding, errors="ignore")
        except (LookupError, UnicodeDecodeError):
            html = body_bytes.decode("utf-8", errors="ignore")

        cookie_names    = _extract_cookie_names(resp, session)
        meta_generators = _extract_meta_generator(html)
        script_srcs     = _extract_script_srcs(html)

        header_dets = _detect_from_headers(resp)
        cookie_dets = _detect_from_cookies(cookie_names)
        html_dets   = _detect_from_html(html, meta_generators, script_srcs)
        dns_dets    = _detect_from_dns(host)

        # v3.1.0: consistent `resp.url or url` guard
        final_base = resp.url or url

        extra_paths: Dict[str, str] = {}
        if probe_extra:
            extra_paths = _probe_extra_paths(session, final_base, timeout)
        extra_dets = _detect_from_extra_paths(extra_paths)

        favicon_hash = None
        favicon_dets: List[Detection] = []
        if check_favicon:
            favicon_hash = _fetch_favicon_hash(session, final_base, FAVICON_TIMEOUT)
            favicon_dets = _detect_from_favicon(favicon_hash)

        all_dets = _merge_detections(
            header_dets + cookie_dets + html_dets +
            dns_dets + extra_dets + favicon_dets
        )

        conf_rank = {"high": 3, "medium": 2, "low": 1}
        detections_json = [
            d.to_dict() for d in sorted(
                all_dets,
                key=lambda d: (-conf_rank.get(d.confidence, 0), d.category, d.name),
            )
        ]

        data: Dict[str, Any] = {
            "detected": [d.name for d in all_dets],
            "detections": detections_json,
            "summary_by_category": _build_summary(all_dets),
            "count_by_confidence": {
                "high":   sum(1 for d in all_dets if d.confidence == "high"),
                "medium": sum(1 for d in all_dets if d.confidence == "medium"),
                "low":    sum(1 for d in all_dets if d.confidence == "low"),
            },
            "server_header": resp.headers.get("Server"),
            "powered_by": resp.headers.get("X-Powered-By"),
            "final_url": resp.url,
            "status_code": resp.status_code,
            "content_type": resp.headers.get("Content-Type"),
            "headers": dict(resp.headers),
            "meta_generators": meta_generators,
            "cookie_names": cookie_names,
            "script_src_count": len(script_srcs),
            "body_bytes_read": len(body_bytes),
            "dns_cname_chain": _dns_chain(host),
            "extra_paths_probed": list(extra_paths.keys()),
        }
        if favicon_hash:
            data["favicon_sha256"] = favicon_hash

        return {
            "tool": "tech_fingerprint",
            "version": __version__,
            "target": target,
            "data": data,
            "error": None,
        }

    finally:
        session.close()


def _dns_chain(host: str) -> List[str]:
    """Memoised CNAME chain for the response payload (avoids dup DNS query)."""
    return _dns_cname_chain(host)


def _error_result(target: str, message: str) -> Dict[str, Any]:
    return {
        "tool": "tech_fingerprint",
        "version": __version__,
        "target": target,
        "data": {},
        "error": message,
    }


# ── Aliases: satisfy every slug terminal.py looks for ────────────────────
tech_fingerprint      = run
scan_tech_fingerprint = run
techfp                = run
fingerprint           = run
tech_fp               = run
techfingerprint       = run


# ═══════════════════════════════════════════════════════════════════════════
# STREAMING API
# ═══════════════════════════════════════════════════════════════════════════
def run_streaming(
    target: str,
    options: Optional[Dict[str, Any]] = None,
    cancel_event: Optional[Any] = None,
) -> Iterator[Dict[str, Any]]:
    """SSE-friendly generator mirroring the Emergens app SSE envelope."""
    import time as _time
    options = options or {}
    started = _time.time()

    yield {"type": "start", "target": target, "options": options}
    yield {"type": "stage", "stage": "connecting"}

    if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
        yield {"type": "error", "message": "cancelled before start"}
        return

    try:
        result = run(
            target,
            mode=str(options.get("mode", "basic")),
            timeout=int(options.get("timeout", DEFAULT_TIMEOUT)),
            check_favicon=bool(options.get("check_favicon", True)),
            probe_extra=bool(options.get("probe_extra", True)),
            max_redirects=int(options.get("max_redirects", MAX_REDIRECTS)),
        )
    except Exception as e:
        yield {"type": "error", "message": str(e)}
        return

    if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
        yield {"type": "error", "message": "cancelled after fetch"}
        return

    yield {"type": "stage", "stage": "analyse"}
    yield {"type": "result", "data": result}
    yield {
        "type": "summary",
        "duration_ms": int((_time.time() - started) * 1000),
        "ok": result.get("error") is None,
    }
    yield {"type": "stage", "stage": "done"}


# ═══════════════════════════════════════════════════════════════════════════
# BATCH SCANNING
# ═══════════════════════════════════════════════════════════════════════════
def scan_many(
    targets,
    mode: str = "basic",
    workers: int = 6,
    on_result=None,
    **kwargs,
) -> List[Dict[str, Any]]:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    targets = list(targets)
    results: List[Optional[Dict[str, Any]]] = [None] * len(targets)

    def _one(idx: int, tgt: str):
        r = run(tgt, mode=mode, **kwargs)
        if on_result is not None:
            try:
                on_result(tgt, r)
            except Exception as e:
                logger.debug("on_result callback failed: %s", e)
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
                logger.warning("Batch worker error: %s", e)

    return [r for r in results if r is not None]


# ═══════════════════════════════════════════════════════════════════════════
# SELF-CHECK
# ═══════════════════════════════════════════════════════════════════════════
def self_check() -> Dict[str, Any]:
    """Return diagnostic dict describing runtime capability."""
    import sys as _sys
    py = _sys.version_info
    return {
        "module":       "modules.tech_fingerprint",
        "version":      __version__,
        "author":       __author__,
        "credit":       __credit__,
        "python":       f"{py.major}.{py.minor}.{py.micro}",
        "requests":     True,
        "flask":        _HAS_FLASK,
        "dnspython":    _HAS_DNS,
        "aliases":      ["run", "tech_fingerprint", "scan_tech_fingerprint",
                         "techfp", "fingerprint", "tech_fp", "techfingerprint"],
        "endpoint":     "/api/techfp/scan" if _HAS_FLASK else None,
        "signatures":   len(SIGNATURES),
        "dns_patterns": len(DNS_PATTERNS),
        "favicon_db":   len(FAVICON_HASHES),
        "ready":        _HAS_FLASK,
    }


# ═══════════════════════════════════════════════════════════════════════════
# FLASK BLUEPRINT  →  POST|GET /api/techfp/scan
# ═══════════════════════════════════════════════════════════════════════════
if _HAS_FLASK:
    techfp_bp = Blueprint("tech_fingerprint", __name__)

    @techfp_bp.route("/api/techfp/scan", methods=["POST", "GET"])
    def _techfp_scan_endpoint():
        """
        Payload (JSON or query):
            { "target": "example.com", "mode": "basic|expert",
              "timeout": 8, "check_favicon": true,
              "probe_extra": true, "max_redirects": 5 }

        Response shape — matches terminal.py `_render_techfp()`.
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

        def _int_from(key, default):
            v = payload.get(key, request.args.get(key))
            if v is None:
                return default
            try:
                return int(v)
            except (TypeError, ValueError):
                return default

        if not target:
            return jsonify({
                "tool": "tech_fingerprint", "version": __version__,
                "target": "", "data": {},
                "error": "missing 'target' parameter",
            }), 400

        result = run(
            target,
            mode=mode,
            timeout=_int_from("timeout", DEFAULT_TIMEOUT),
            check_favicon=_bool_from("check_favicon", True),
            probe_extra=_bool_from("probe_extra", True),
            max_redirects=_int_from("max_redirects", MAX_REDIRECTS),
        )
        return jsonify(result)


    def register_blueprint(app) -> None:
        """Convenience helper for app.py: `register_blueprint(app)`."""
        app.register_blueprint(techfp_bp)
        logger.info("tech_fingerprint blueprint registered at /api/techfp/scan")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def _main() -> int:
    import argparse
    import json as _json
    import sys

    parser = argparse.ArgumentParser(
        description=TOOL_INFO["description"],
        epilog=f"Version {TOOL_INFO['version']} — {TOOL_INFO['author']}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("targets", nargs="*",
                        help="Domain(s) or URL(s) to fingerprint")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--no-favicon", action="store_true",
                        help="Skip favicon hash check")
    parser.add_argument("--no-extra", action="store_true",
                        help="Skip /robots.txt /sitemap.xml /humans.txt probing")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--json", action="store_true", help="Raw JSON output")
    parser.add_argument("-o", "--output", help="Save JSON result to file")
    parser.add_argument("--self-check", action="store_true",
                        help="Print runtime diagnostics and exit")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()

    if args.self_check or not args.targets:
        print(_json.dumps(self_check(), indent=2))
        if not args.targets and not args.self_check:
            print("\nTip: pass at least one target, e.g. `example.com`.")
        return 0

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    results = scan_many(
        args.targets,
        workers=args.workers,
        timeout=args.timeout,
        check_favicon=not args.no_favicon,
        probe_extra=not args.no_extra,
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            _json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        print(f"Saved to {args.output}")
        return 0

    if args.json:
        print(_json.dumps(results, indent=2, ensure_ascii=False, default=str))
        return 0

    for result in results:
        if result.get("error"):
            print(f"\n[FAIL] {result['target']}: {result['error']}")
            continue
        data = result["data"]
        print(f"\n═══ Tech Fingerprint: {result['target']} ═══\n")
        print(f"Final URL:  {data.get('final_url')}")
        print(f"Status:     {data.get('status_code')}")
        print(f"Server:     {data.get('server_header') or '-'}")
        print(f"Powered-By: {data.get('powered_by') or '-'}")
        if data.get("dns_cname_chain"):
            print(f"CNAME:      {' → '.join(data['dns_cname_chain'])}")
        print()
        if not data.get("detections"):
            print("No technologies detected.")
            continue
        print(f"Detected ({len(data['detections'])}):")
        for d in data["detections"]:
            ver = f" v{d['version']}" if d.get("version") else ""
            print(f"  [{d['confidence']:<6}] {d['name']}{ver}  ({d['category']})")
            for ev in d["evidence"][:3]:
                print(f"           · {ev}")

    return 0


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(_main())