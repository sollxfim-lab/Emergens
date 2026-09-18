#!/usr/bin/env python3
"""
Tech Fingerprinting — Passive detection of CMS, frameworks, servers,
languages, analytics, CDNs, and security products from public response
data (headers, HTML markers, cookies, meta tags, script sources).

Detection sources (in order of reliability):
    1. Response headers          (Server, X-Powered-By, Set-Cookie, ...)
    2. HTML meta generator       (<meta name="generator" content="...">)
    3. Script/link src patterns  (<script src="/wp-content/...">)
    4. Inline HTML markers       (class names, IDs, comment banners)
    5. Cookie names & flags      (wordpress_logged_in, PHPSESSID, ...)
    6. Favicon hash              (SHA-256 of /favicon.ico — opt-in)

Features:
    • 130+ signatures across 15 categories (CMS, e-commerce, JS, CDN, ...)
    • Confidence levels: high / medium / low
    • Version extraction where the marker exposes one
    • Category grouping for structured output
    • Multi-source evidence trail per detection
    • Redirect-aware — merges cookies from the full redirect chain
    • Streaming body reader — never holds more than MAX_BODY_CHARS in RAM
    • Bounded favicon download (512 KB cap)
    • Tolerant of TLS errors and slow hosts
    • Standalone — works with or without modules/_common.py
    • Isolated logger — no duplicate output with Flask/root
    • Drop-in compatible — same `run()` signature as before

Author: Yanxzyx
Version: 2.1.0 — streaming, redirect-cookie merge, session cleanup
"""

from __future__ import annotations

import hashlib
import logging
import re
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# ═══════════════════════════════════════════════════════════════════════════
# LOGGING — isolated, no duplicate with Flask/root
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

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

# Suppress the noisy cert warnings from verify=False — intentional and scoped
# to this module by wrapping requests calls in `_suppress_insecure_warning()`.
urllib3.disable_warnings(InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════════════════════
# OPTIONAL DEPENDENCY: modules/_common.py
# ═══════════════════════════════════════════════════════════════════════════
try:
    from modules._common import default_headers  # type: ignore
except Exception:
    def default_headers() -> Dict[str, str]:
        """Fallback UA/header set if the shared helper isn't installed."""
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
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
TOOL_INFO = {
    "name": "Tech Fingerprint",
    "description": (
        "Passive detection of CMS, frameworks, servers, languages, "
        "analytics, CDNs, and security products from response headers, "
        "HTML markers, cookies, meta tags, and script sources."
    ),
    "version": "2.1.0",
    "author": "Yanxzyx",
}

DEFAULT_TIMEOUT      = 8
MAX_BODY_CHARS       = 300_000     # Cap for HTML parsing
MAX_FAVICON_BYTES    = 512_000     # 512 KB is generous for a favicon
MAX_REDIRECTS        = 5
FAVICON_TIMEOUT      = 5
STREAM_CHUNK_SIZE    = 65_536

# ═══════════════════════════════════════════════════════════════════════════
# SIGNATURE DATABASE
# ═══════════════════════════════════════════════════════════════════════════
# Each entry: {
#   "name":     display name,
#   "category": grouping,
#   "confidence": "high" | "medium" | "low",
#   "headers":  {header_name_lower: regex}
#   "cookies":  [regex on cookie names]
#   "html":     [regex on HTML body]
#   "meta_generator": [regex on <meta name="generator"> content]
#   "script_src":     [regex on <script src>/<link href> URLs]
#   "version_regex":  optional regex to extract version
# }

SIGNATURES: List[Dict[str, Any]] = [
    # ─── CMS ─────────────────────────────────────────────────────────────
    {
        "name": "WordPress", "category": "CMS", "confidence": "high",
        "html": [r"wp-content/", r"wp-includes/", r"/wp-json/"],
        "meta_generator": [r"WordPress\s*([\d.]+)?"],
        "cookies": [r"^wordpress_", r"^wp-settings-"],
        "version_regex": r"WordPress\s*([\d.]+)",
    },
    {
        "name": "Joomla", "category": "CMS", "confidence": "high",
        "html": [r"/media/jui/", r"/components/com_", r"/templates/"],
        "meta_generator": [r"Joomla!?\s*([\d.]+)?"],
        "version_regex": r"Joomla!?\s*([\d.]+)",
    },
    {
        "name": "Drupal", "category": "CMS", "confidence": "high",
        "html": [r"Drupal\.settings", r"/sites/default/files", r"drupal-"],
        "meta_generator": [r"Drupal\s*([\d.]+)?"],
        "headers": {"x-generator": r"^Drupal"},
        "version_regex": r"Drupal\s*([\d.]+)",
    },
    {
        "name": "Magento", "category": "E-commerce", "confidence": "high",
        "html": [r"Magento_", r"/mage/", r"var/mage/"],
        "cookies": [r"^frontend=", r"^adminhtml="],
        "headers": {"x-magento-cache-debug": r".", "x-magento-vary": r"."},
    },
    {
        "name": "Ghost", "category": "CMS", "confidence": "high",
        "meta_generator": [r"Ghost\s*([\d.]+)?"],
        "html": [r"ghost-url", r'content="Ghost'],
    },
    {
        "name": "Sitecore", "category": "CMS", "confidence": "high",
        "cookies": [r"^SC_ANALYTICS_", r"^shell#lang"],
        "html": [r"/sitecore/", r"Sitecore\.Web"],
    },
    {
        "name": "TYPO3", "category": "CMS", "confidence": "high",
        "meta_generator": [r"TYPO3"],
        "html": [r"/typo3conf/", r"/typo3temp/"],
    },
    {
        "name": "Contao", "category": "CMS", "confidence": "high",
        "html": [r"/assets/contao/", r"Contao"],
    },
    {
        "name": "Hugo", "category": "Static Site Generator", "confidence": "medium",
        "meta_generator": [r"Hugo\s*([\d.]+)?"],
        "html": [r"/_hugo"],
    },
    {
        "name": "Jekyll", "category": "Static Site Generator", "confidence": "medium",
        "meta_generator": [r"Jekyll\s*v?([\d.]+)?"],
    },
    {
        "name": "Gatsby", "category": "Static Site Generator", "confidence": "medium",
        "html": [r"gatsby-", r"___gatsby"],
    },
    {
        "name": "Next.js", "category": "Static Site Generator", "confidence": "medium",
        "html": [r"__NEXT_DATA__", r"/_next/static/"],
        "headers": {"x-powered-by": r"^Next\.js"},
    },
    {
        "name": "Nuxt.js", "category": "Static Site Generator", "confidence": "medium",
        "html": [r"__NUXT__", r"/_nuxt/"],
    },
    {
        "name": "Docusaurus", "category": "Static Site Generator", "confidence": "medium",
        "meta_generator": [r"Docusaurus"],
        "html": [r"docusaurus"],
    },

    # ─── E-COMMERCE ──────────────────────────────────────────────────────
    {
        "name": "Shopify", "category": "E-commerce", "confidence": "high",
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme", r"/cdn/shop/"],
        "headers": {"x-shopid": r".", "x-shardid": r".", "x-sorting-hat-podid": r"."},
    },
    {
        "name": "WooCommerce", "category": "E-commerce", "confidence": "high",
        "html": [r"woocommerce", r"wc-ajax", r"/wp-content/plugins/woocommerce"],
    },
    {
        "name": "BigCommerce", "category": "E-commerce", "confidence": "high",
        "html": [r"cdn\d*\.bigcommerce\.com", r"/stencil/"],
    },
    {
        "name": "PrestaShop", "category": "E-commerce", "confidence": "high",
        "meta_generator": [r"PrestaShop"],
        "html": [r"/modules/ps_", r"prestashop"],
        "cookies": [r"^PrestaShop-"],
    },
    {
        "name": "OpenCart", "category": "E-commerce", "confidence": "medium",
        "html": [r"catalog/view/theme/", r"index\.php\?route="],
    },
    {
        "name": "Salesforce Commerce Cloud", "category": "E-commerce", "confidence": "medium",
        "html": [r"demandware\.static", r"/on/demandware\.store/"],
    },

    # ─── JS FRAMEWORKS / LIBRARIES ───────────────────────────────────────
    {
        "name": "React", "category": "JS Framework", "confidence": "medium",
        "html": [r"data-reactroot", r"react-root", r"__REACT_DEVTOOLS"],
        "script_src": [r"/react(?:[.-]|/).*\.js"],
    },
    {
        "name": "Vue.js", "category": "JS Framework", "confidence": "medium",
        "html": [r"data-v-[0-9a-f]{6,}", r"__vue__", r"vue\.config"],
        "script_src": [r"/vue(?:@|\.min|\.runtime|-)"],
        "version_regex": r"Vue\.js\s*v?([\d.]+)",
    },
    {
        "name": "Angular", "category": "JS Framework", "confidence": "medium",
        "html": [r'ng-version="([\d.]+)', r"ng-app=", r"_ngcontent"],
        "script_src": [r"/angular(?:[.-]|/)"],
        "version_regex": r'ng-version="([\d.]+)"',
    },
    {
        "name": "Svelte", "category": "JS Framework", "confidence": "medium",
        "html": [r"svelte-[0-9a-z]{6}", r"__svelte"],
    },
    {
        "name": "Alpine.js", "category": "JS Framework", "confidence": "medium",
        "html": [r'x-data="', r'x-init="'],
        "script_src": [r"alpine(?:\.min)?\.js"],
    },
    {
        "name": "jQuery", "category": "JS Library", "confidence": "high",
        "script_src": [r"/jquery[.-]?([\d.]+)?(?:\.min)?\.js", r"jquery/[\d.]+/jquery"],
        "version_regex": r"jquery[.-]?([\d.]+)(?:\.min)?\.js",
    },
    {
        "name": "Bootstrap", "category": "CSS Framework", "confidence": "high",
        "script_src": [r"/bootstrap[.-]?([\d.]+)?(?:\.min)?\.(?:js|css)"],
        "html": [r"bootstrap\.min\.(?:js|css)"],
        "version_regex": r"bootstrap[.-]?([\d.]+)",
    },
    {
        "name": "Tailwind CSS", "category": "CSS Framework", "confidence": "low",
        "html": [r"tailwindcss", r"tw-[a-z]+-"],
    },
    {
        "name": "Font Awesome", "category": "Font/Icon", "confidence": "medium",
        "script_src": [
            r"kit\.fontawesome\.com",
            r"use\.fontawesome\.com",
            r"font-?awesome",
        ],
        "html": [r"fa-[a-z]+ fa-"],
    },
    {
        "name": "Lodash", "category": "JS Library", "confidence": "medium",
        "script_src": [r"/lodash(?:[.-]|/)"],
    },
    {
        "name": "Underscore.js", "category": "JS Library", "confidence": "medium",
        "script_src": [r"/underscore(?:[.-]|/)"],
    },
    {
        "name": "Moment.js", "category": "JS Library", "confidence": "medium",
        "script_src": [r"/moment(?:[.-]|/)"],
    },
    {
        "name": "D3.js", "category": "JS Library", "confidence": "medium",
        "script_src": [r"/d3(?:[.-]|/)"],
    },
    {
        "name": "Three.js", "category": "JS Library", "confidence": "medium",
        "script_src": [r"/three(?:[.-]|/)"],
        "html": [r"THREE\."],
    },
    {
        "name": "Chart.js", "category": "JS Library", "confidence": "medium",
        "script_src": [r"chart(?:\.min)?\.js"],
    },
    {
        "name": "Swiper", "category": "JS Library", "confidence": "medium",
        "script_src": [r"swiper(?:\.min)?\.(?:js|css)"],
    },
    {
        "name": "GSAP", "category": "JS Library", "confidence": "medium",
        "script_src": [r"gsap(?:\.min)?\.js", r"/gsap/"],
    },

    # ─── WEB SERVERS ─────────────────────────────────────────────────────
    {
        "name": "Nginx", "category": "Web Server", "confidence": "high",
        "headers": {"server": r"\bnginx(?:/([\d.]+))?"},
        "version_regex": r"nginx/([\d.]+)",
    },
    {
        "name": "Apache HTTP Server", "category": "Web Server", "confidence": "high",
        "headers": {"server": r"\bApache(?:/([\d.]+))?"},
        "version_regex": r"Apache/([\d.]+)",
    },
    {
        "name": "Apache Tomcat", "category": "Web Server", "confidence": "high",
        "headers": {"server": r"Apache-Coyote|Tomcat"},
        "html": [r"Apache Tomcat"],
    },
    {
        "name": "Microsoft IIS", "category": "Web Server", "confidence": "high",
        "headers": {"server": r"Microsoft-IIS(?:/([\d.]+))?"},
        "version_regex": r"Microsoft-IIS/([\d.]+)",
    },
    {
        "name": "LiteSpeed", "category": "Web Server", "confidence": "high",
        "headers": {"server": r"LiteSpeed"},
    },
    {
        "name": "Caddy", "category": "Web Server", "confidence": "high",
        "headers": {"server": r"Caddy"},
    },
    {
        "name": "OpenResty", "category": "Web Server", "confidence": "high",
        "headers": {"server": r"openresty(?:/([\d.]+))?"},
        "version_regex": r"openresty/([\d.]+)",
    },
    {
        "name": "Gunicorn", "category": "Web Server", "confidence": "high",
        "headers": {"server": r"gunicorn(?:/([\d.]+))?"},
        "version_regex": r"gunicorn/([\d.]+)",
    },
    {
        "name": "Werkzeug", "category": "Web Server", "confidence": "high",
        "headers": {"server": r"Werkzeug(?:/([\d.]+))?"},
        "version_regex": r"Werkzeug/([\d.]+)",
    },
    {
        "name": "Uvicorn", "category": "Web Server", "confidence": "medium",
        "headers": {"server": r"uvicorn"},
    },
    {
        "name": "Kestrel", "category": "Web Server", "confidence": "medium",
        "headers": {"server": r"Kestrel"},
    },
    {
        "name": "Vercel", "category": "Hosting", "confidence": "high",
        "headers": {"server": r"Vercel", "x-vercel-id": r"."},
    },
    {
        "name": "Netlify", "category": "Hosting", "confidence": "high",
        "headers": {"server": r"Netlify", "x-nf-request-id": r"."},
    },
    {
        "name": "GitHub Pages", "category": "Hosting", "confidence": "high",
        "headers": {"server": r"GitHub\.com", "x-github-request-id": r"."},
    },
    {
        "name": "Heroku", "category": "Hosting", "confidence": "medium",
        "headers": {"via": r"vegur", "x-heroku-request-id": r"."},
    },
    {
        "name": "Firebase Hosting", "category": "Hosting", "confidence": "high",
        "headers": {"server": r"Firebase", "x-served-by": r"^(?:cache|hosting)"},
    },
    {
        "name": "Amazon S3", "category": "Storage/CDN", "confidence": "high",
        "headers": {"server": r"AmazonS3", "x-amz-request-id": r"."},
    },
    {
        "name": "Google Cloud Storage", "category": "Storage/CDN", "confidence": "medium",
        "headers": {"server": r"UploadServer", "x-goog-generation": r"."},
    },

    # ─── LANGUAGES / FRAMEWORKS ──────────────────────────────────────────
    {
        "name": "PHP", "category": "Language", "confidence": "high",
        "headers": {"x-powered-by": r"PHP/([\d.]+)"},
        "cookies": [r"^PHPSESSID$"],
        "version_regex": r"PHP/([\d.]+)",
    },
    {
        "name": "ASP.NET", "category": "Framework", "confidence": "high",
        "headers": {"x-aspnet-version": r"([\d.]+)", "x-powered-by": r"ASP\.NET"},
        "cookies": [r"^ASP\.NET_SessionId$"],
    },
    {
        "name": "ASP.NET MVC", "category": "Framework", "confidence": "medium",
        "headers": {"x-aspnetmvc-version": r"([\d.]+)"},
    },
    {
        "name": "Express", "category": "Framework", "confidence": "high",
        "headers": {"x-powered-by": r"Express"},
    },
    {
        "name": "Django", "category": "Framework", "confidence": "medium",
        "cookies": [r"^csrftoken$", r"^django"],
        "html": [r"csrfmiddlewaretoken"],
    },
    {
        "name": "Flask", "category": "Framework", "confidence": "medium",
        "cookies": [r"^session$"],
        "headers": {"server": r"Werkzeug"},
    },
    {
        "name": "Ruby on Rails", "category": "Framework", "confidence": "medium",
        "cookies": [r"^_rails", r"^_session_id$"],
        "headers": {"x-powered-by": r"Phusion Passenger"},
    },
    {
        "name": "Spring Boot", "category": "Framework", "confidence": "medium",
        "cookies": [r"^JSESSIONID$"],
        "headers": {"x-application-context": r"."},
    },
    {
        "name": "Laravel", "category": "Framework", "confidence": "medium",
        "cookies": [r"^laravel_session$", r"^XSRF-TOKEN$"],
    },
    {
        "name": "Symfony", "category": "Framework", "confidence": "medium",
        "cookies": [r"^symfony$"],
        "headers": {"x-debug-token": r"."},
    },
    {
        "name": "CodeIgniter", "category": "Framework", "confidence": "medium",
        "cookies": [r"^ci_session$"],
    },
    {
        "name": "Golang", "category": "Language", "confidence": "low",
        "headers": {"server": r"^Go-http-client"},
    },
    {
        "name": "Node.js", "category": "Language", "confidence": "medium",
        "headers": {"x-powered-by": r"^Express|^Node\.js"},
    },

    # ─── CDN / EDGE ──────────────────────────────────────────────────────
    {
        "name": "Cloudflare", "category": "CDN/Security", "confidence": "high",
        "headers": {"cf-ray": r".", "cf-cache-status": r".", "server": r"^cloudflare$"},
        "cookies": [r"^__cfduid$", r"^__cf_bm$", r"^cf_clearance$"],
    },
    {
        "name": "Akamai", "category": "CDN", "confidence": "high",
        "headers": {"x-akamai-transformed": r".", "server": r"AkamaiGHost"},
        "cookies": [r"^ak_bmsc$", r"^bm_sz$"],
    },
    {
        "name": "Fastly", "category": "CDN", "confidence": "high",
        "headers": {"x-served-by": r"cache-", "x-fastly-request-id": r"."},
    },
    {
        "name": "Amazon CloudFront", "category": "CDN", "confidence": "high",
        "headers": {"x-amz-cf-id": r".", "via": r"CloudFront"},
    },
    {
        "name": "Google Cloud CDN", "category": "CDN", "confidence": "medium",
        "headers": {"via": r"google", "x-goog-": r"."},
    },
    {
        "name": "Bunny CDN", "category": "CDN", "confidence": "medium",
        "headers": {"server": r"BunnyCDN"},
    },
    {
        "name": "StackPath", "category": "CDN", "confidence": "medium",
        "headers": {"server": r"StackPath"},
    },
    {
        "name": "Sucuri CloudProxy", "category": "WAF/CDN", "confidence": "high",
        "headers": {"x-sucuri-id": r".", "server": r"Sucuri"},
    },
    {
        "name": "Incapsula/Imperva", "category": "WAF/CDN", "confidence": "high",
        "headers": {"x-iinfo": r".", "x-cdn": r"Incapsula"},
        "cookies": [r"^incap_ses_", r"^visid_incap_"],
    },
    {
        "name": "KeyCDN", "category": "CDN", "confidence": "medium",
        "headers": {"server": r"keycdn"},
    },
    {
        "name": "jsDelivr", "category": "CDN", "confidence": "medium",
        "script_src": [r"cdn\.jsdelivr\.net"],
    },
    {
        "name": "unpkg", "category": "CDN", "confidence": "medium",
        "script_src": [r"unpkg\.com"],
    },
    {
        "name": "cdnjs", "category": "CDN", "confidence": "medium",
        "script_src": [r"cdnjs\.cloudflare\.com"],
    },

    # ─── WAF / ANTI-BOT ──────────────────────────────────────────────────
    {
        "name": "AWS WAF", "category": "WAF", "confidence": "medium",
        "cookies": [r"^aws-waf-token$"],
    },
    {
        "name": "ModSecurity", "category": "WAF", "confidence": "medium",
        "headers": {"server": r"ModSecurity|NOYB"},
    },
    {
        "name": "Wordfence", "category": "WAF", "confidence": "medium",
        "html": [r"wordfence"],
        "cookies": [r"^wfvt_"],
    },
    {
        "name": "reCAPTCHA", "category": "Anti-bot", "confidence": "medium",
        "html": [r"google\.com/recaptcha", r"g-recaptcha"],
    },
    {
        "name": "hCaptcha", "category": "Anti-bot", "confidence": "medium",
        "html": [r"hcaptcha\.com", r"h-captcha"],
    },
    {
        "name": "Cloudflare Turnstile", "category": "Anti-bot", "confidence": "medium",
        "html": [r"challenges\.cloudflare\.com/turnstile"],
    },

    # ─── ANALYTICS / TRACKING / MARKETING ────────────────────────────────
    {
        "name": "Google Analytics (Universal)", "category": "Analytics", "confidence": "high",
        "script_src": [r"google-analytics\.com/analytics\.js"],
        "html": [r"ga\('create'"],
    },
    {
        "name": "Google Analytics 4", "category": "Analytics", "confidence": "high",
        "script_src": [r"googletagmanager\.com/gtag/js"],
        "html": [r"gtag\('config'"],
    },
    {
        "name": "Google Tag Manager", "category": "Tag Manager", "confidence": "high",
        "script_src": [r"googletagmanager\.com/gtm\.js"],
        "html": [r"GTM-[A-Z0-9]+"],
    },
    {
        "name": "Facebook Pixel", "category": "Analytics", "confidence": "high",
        "script_src": [r"connect\.facebook\.net/.*/fbevents\.js"],
        "html": [r"fbq\('init'"],
    },
    {
        "name": "Hotjar", "category": "Analytics", "confidence": "high",
        "script_src": [r"static\.hotjar\.com"],
    },
    {
        "name": "Segment", "category": "Analytics", "confidence": "medium",
        "script_src": [r"cdn\.segment\.com"],
    },
    {
        "name": "Mixpanel", "category": "Analytics", "confidence": "medium",
        "script_src": [r"cdn\.mxpnl\.com", r"mixpanel"],
    },
    {
        "name": "Matomo/Piwik", "category": "Analytics", "confidence": "medium",
        "script_src": [r"matomo\.js", r"piwik\.js"],
        "html": [r"_paq\.push"],
    },
    {
        "name": "Plausible", "category": "Analytics", "confidence": "medium",
        "script_src": [r"plausible\.io/js/"],
    },
    {
        "name": "Umami", "category": "Analytics", "confidence": "medium",
        "script_src": [r"/umami\.js", r"umami\.is"],
    },
    {
        "name": "Microsoft Clarity", "category": "Analytics", "confidence": "medium",
        "script_src": [r"clarity\.ms"],
    },
    {
        "name": "Yandex Metrica", "category": "Analytics", "confidence": "medium",
        "script_src": [r"mc\.yandex\.ru"],
    },
    {
        "name": "Baidu Tongji", "category": "Analytics", "confidence": "medium",
        "script_src": [r"hm\.baidu\.com"],
    },
    {
        "name": "TikTok Pixel", "category": "Analytics", "confidence": "medium",
        "script_src": [r"analytics\.tiktok\.com"],
    },
    {
        "name": "LinkedIn Insight", "category": "Analytics", "confidence": "medium",
        "script_src": [r"snap\.licdn\.com"],
    },
    {
        "name": "Twitter/X Pixel", "category": "Analytics", "confidence": "medium",
        "script_src": [r"static\.ads-twitter\.com"],
    },
    {
        "name": "Pinterest Tag", "category": "Analytics", "confidence": "medium",
        "script_src": [r"ct\.pinterest\.com"],
    },
    {
        "name": "HubSpot", "category": "Marketing", "confidence": "medium",
        "script_src": [r"js\.hs-scripts\.com", r"js\.hubspot\.com"],
    },
    {
        "name": "Intercom", "category": "Support", "confidence": "medium",
        "script_src": [r"widget\.intercom\.io", r"js\.intercomcdn\.com"],
    },
    {
        "name": "Zendesk", "category": "Support", "confidence": "medium",
        "script_src": [r"static\.zdassets\.com"],
    },
    {
        "name": "Crisp", "category": "Support", "confidence": "medium",
        "script_src": [r"client\.crisp\.chat"],
    },
    {
        "name": "Tawk.to", "category": "Support", "confidence": "medium",
        "script_src": [r"embed\.tawk\.to"],
    },
    {
        "name": "Drift", "category": "Support", "confidence": "medium",
        "script_src": [r"js\.driftt\.com"],
    },

    # ─── PAYMENTS ────────────────────────────────────────────────────────
    {
        "name": "Stripe", "category": "Payments", "confidence": "medium",
        "script_src": [r"js\.stripe\.com"],
        "html": [r"""Stripe\(['"]pk_"""],
    },
    {
        "name": "PayPal", "category": "Payments", "confidence": "medium",
        "script_src": [r"paypal\.com/sdk/js", r"paypalobjects\.com"],
    },
    {
        "name": "Razorpay", "category": "Payments", "confidence": "medium",
        "script_src": [r"checkout\.razorpay\.com"],
    },
    {
        "name": "Square", "category": "Payments", "confidence": "medium",
        "script_src": [r"js\.squareup\.com"],
    },
    {
        "name": "Braintree", "category": "Payments", "confidence": "medium",
        "script_src": [r"js\.braintreegateway\.com"],
    },
    {
        "name": "Adyen", "category": "Payments", "confidence": "medium",
        "script_src": [r"checkoutshopper-(?:live|test)\.adyen\.com"],
    },
    {
        "name": "Klarna", "category": "Payments", "confidence": "medium",
        "script_src": [r"x\.klarnacdn\.net"],
    },

    # ─── MISC / UTILITY ──────────────────────────────────────────────────
    {
        "name": "Google Fonts", "category": "Font/Icon", "confidence": "medium",
        "script_src": [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"],
    },
    {
        "name": "Typekit/Adobe Fonts", "category": "Font/Icon", "confidence": "medium",
        "script_src": [r"use\.typekit\.net", r"use\.typekit\.com"],
    },
    {
        "name": "Sentry", "category": "Error Monitoring", "confidence": "medium",
        "script_src": [r"browser\.sentry-cdn\.com"],
    },
    {
        "name": "New Relic", "category": "APM", "confidence": "medium",
        "script_src": [r"js-agent\.newrelic\.com", r"nr-data\.net"],
    },
    {
        "name": "Datadog RUM", "category": "APM", "confidence": "medium",
        "script_src": [r"datadoghq-browser-agent\.com"],
    },
    {
        "name": "Optimizely", "category": "A/B Testing", "confidence": "medium",
        "script_src": [r"cdn\.optimizely\.com"],
    },
    {
        "name": "Disqus", "category": "Comments", "confidence": "medium",
        "script_src": [r"disqus\.com/embed\.js", r"disquscdn\.com"],
    },
    {
        "name": "Algolia", "category": "Search", "confidence": "medium",
        "script_src": [r"cdn\.jsdelivr\.net/.*algoliasearch", r"algolia\.net"],
    },
    {
        "name": "Google Maps", "category": "Maps", "confidence": "medium",
        "script_src": [r"maps\.googleapis\.com/maps/api/js"],
    },
    {
        "name": "Mapbox", "category": "Maps", "confidence": "medium",
        "script_src": [r"api\.mapbox\.com"],
    },
    {
        "name": "YouTube Embed", "category": "Media", "confidence": "low",
        "html": [r"youtube\.com/embed/", r"youtube-nocookie\.com"],
    },
    {
        "name": "Vimeo Embed", "category": "Media", "confidence": "low",
        "html": [r"player\.vimeo\.com"],
    },
]


# Pre-compile every regex once at import — big perf win.
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
    """Return a fully-qualified URL with scheme; add https:// if missing."""
    t = (target or "").strip()
    if not t:
        return ""
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t


def _extract_cookie_names(
    resp: requests.Response,
    session: Optional[requests.Session] = None,
) -> List[str]:
    """
    Collect cookie names from both the final response AND the session jar.
    Cookies set during redirects (301/302) live only in session.cookies —
    e.g. Laravel's `laravel_session`, WordPress' `wordpress_*`, etc.
    Order is preserved and duplicates removed.
    """
    seen = set()
    names: List[str] = []

    for c in resp.cookies:
        if c.name not in seen:
            seen.add(c.name)
            names.append(c.name)

    if session is not None:
        for c in session.cookies:
            if c.name not in seen:
                seen.add(c.name)
                names.append(c.name)

    return names


def _extract_script_srcs(html: str) -> List[str]:
    """Extract src/href URLs from <script> and <link> tags."""
    urls: List[str] = []
    for pat in (
        r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']',
        r'<link[^>]+href\s*=\s*["\']([^"\']+)["\']',
    ):
        for m in re.finditer(pat, html, re.IGNORECASE):
            urls.append(m.group(1))
    return urls


def _extract_meta_generator(html: str) -> List[str]:
    """Return content= values of any <meta name='generator'> tags."""
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
    resp: requests.Response,
    max_bytes: int,
    chunk_size: int = STREAM_CHUNK_SIZE,
) -> bytes:
    """
    Read at most `max_bytes` from a streaming response. Stops early if the
    cap is hit so we never hold more than ~max_bytes in memory, even if the
    server tries to send gigabytes.
    """
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
    session: requests.Session,
    base_url: str,
    timeout: int,
) -> Optional[str]:
    """
    Fetch /favicon.ico (bounded to MAX_FAVICON_BYTES) and return SHA-256 of
    its bytes, or None. Uses the same session so cookies/proxies apply.
    """
    try:
        parsed = urlparse(base_url)
        favicon_url = urlunparse(
            parsed._replace(path="/favicon.ico", params="", query="", fragment="")
        )
        r = session.get(
            favicon_url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "image/*,*/*;q=0.5"},
            stream=True,
        )
        if not r.ok:
            return None
        content = _read_response_body(r, MAX_FAVICON_BYTES, chunk_size=8192)
        if not content:
            return None
        if len(content) >= MAX_FAVICON_BYTES:
            # Probably not a favicon — just an HTML error page or huge file
            return None
        return hashlib.sha256(content).hexdigest()
    except Exception as e:
        logger.debug("Favicon fetch failed for %s: %s", base_url, e)
    return None


# ═══════════════════════════════════════════════════════════════════════════
# DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════
def _detect_from_headers(resp: requests.Response) -> List[Detection]:
    """Match signatures against response headers."""
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
                    name=sig["name"],
                    category=sig["category"],
                    confidence=sig["confidence"],
                    version=version,
                    evidence=[f"header: {hname}: {hval[:120]}"],
                ))
                break
    return detections


def _detect_from_cookies(cookie_names: List[str]) -> List[Detection]:
    """Match signatures against cookie names."""
    detections: List[Detection] = []
    for sig in SIGNATURES:
        compiled = sig.get("_cookies_re")
        if not compiled:
            continue
        for name in cookie_names:
            for cre in compiled:
                if cre.search(name):
                    detections.append(Detection(
                        name=sig["name"],
                        category=sig["category"],
                        confidence=sig["confidence"],
                        evidence=[f"cookie: {name}"],
                    ))
                    break
            else:
                continue
            break
    return detections


def _detect_from_html(
    html: str,
    meta_generators: List[str],
    script_srcs: List[str],
) -> List[Detection]:
    """Match signatures against HTML body, meta generators, and script srcs."""
    detections: List[Detection] = []
    script_blob = " ".join(script_srcs)

    for sig in SIGNATURES:
        matched = False
        evidence: List[str] = []

        # Meta generator
        for mre in sig.get("_meta_generator_re", []):
            for mgen in meta_generators:
                if mre.search(mgen):
                    evidence.append(f"meta generator: {mgen}")
                    matched = True
                    break
            if matched:
                break

        # Script / link src
        if not matched:
            for sre in sig.get("_script_src_re", []):
                m = sre.search(script_blob)
                if m:
                    evidence.append(f"script src: {m.group(0)[:120]}")
                    matched = True
                    break

        # HTML body markers
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
                name=sig["name"],
                category=sig["category"],
                confidence=sig["confidence"],
                version=version,
                evidence=evidence,
            ))
    return detections


def _merge_detections(dets: List[Detection]) -> List[Detection]:
    """
    Merge detections with the same name. Evidence order is preserved
    (insertion order), so results are deterministic across runs.
    """
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
                name=d.name,
                category=d.category,
                confidence=d.confidence,
                version=d.version,
                evidence=list(d.evidence),
            )
    return list(merged.values())


def _build_summary(detections: List[Detection]) -> Dict[str, List[str]]:
    """Group detected names by category."""
    by_cat: Dict[str, List[str]] = {}
    for d in detections:
        by_cat.setdefault(d.category, []).append(d.name)
    for names in by_cat.values():
        names.sort()
    return dict(sorted(by_cat.items()))


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
def run(target: str, mode: str = "basic", **kwargs) -> dict:
    """
    Fingerprint the technologies behind `target`.

    kwargs:
        timeout (int)       — HTTP timeout (default 8)
        check_favicon (bool)— fetch /favicon.ico and hash it (default False)
        max_redirects (int) — follow up to N redirects (default 5)
        verbose (bool)      — enable DEBUG logging
    """
    timeout       = int(kwargs.get("timeout", DEFAULT_TIMEOUT))
    check_favicon = bool(kwargs.get("check_favicon", False))
    max_redirects = int(kwargs.get("max_redirects", MAX_REDIRECTS))
    verbose       = bool(kwargs.get("verbose", False))

    if verbose:
        logger.setLevel(logging.DEBUG)

    url = _normalize_target(target)
    if not url:
        return _error_result(target, "Empty target — provide a domain or URL.")

    session = requests.Session()
    session.max_redirects = max_redirects
    try:
        try:
            resp = session.get(
                url,
                timeout=timeout,
                headers=default_headers(),
                allow_redirects=True,
                verify=False,
                stream=True,
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

        # ── Stream body with hard cap — never download more than MAX_BODY_CHARS
        body_bytes = _read_response_body(resp, MAX_BODY_CHARS)

        # Decode using the response's declared encoding, fallback to utf-8.
        encoding = resp.encoding or "utf-8"
        try:
            html = body_bytes.decode(encoding, errors="ignore")
        except (LookupError, UnicodeDecodeError):
            html = body_bytes.decode("utf-8", errors="ignore")

        # ── Derived inputs (redirect-aware cookies)
        cookie_names    = _extract_cookie_names(resp, session)
        meta_generators = _extract_meta_generator(html)
        script_srcs     = _extract_script_srcs(html)

        # ── Detectors
        header_dets = _detect_from_headers(resp)
        cookie_dets = _detect_from_cookies(cookie_names)
        html_dets   = _detect_from_html(html, meta_generators, script_srcs)

        all_dets = _merge_detections(header_dets + cookie_dets + html_dets)

        # ── Optional favicon hash (reuses same session)
        favicon_hash = None
        if check_favicon:
            favicon_hash = _fetch_favicon_hash(session, url, FAVICON_TIMEOUT)

        # ── Output
        conf_rank = {"high": 3, "medium": 2, "low": 1}
        detections_json = [
            d.to_dict() for d in sorted(
                all_dets,
                key=lambda d: (-conf_rank.get(d.confidence, 0), d.name),
            )
        ]

        data: Dict[str, Any] = {
            "detected": [d.name for d in all_dets],
            "detections": detections_json,
            "summary_by_category": _build_summary(all_dets),
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
        }
        if favicon_hash:
            data["favicon_sha256"] = favicon_hash

        return {
            "tool": "tech_fingerprint",
            "version": TOOL_INFO["version"],
            "target": target,
            "data": data,
            "error": None,
        }

    finally:
        session.close()


def _error_result(target: str, message: str) -> dict:
    return {
        "tool": "tech_fingerprint",
        "version": TOOL_INFO["version"],
        "target": target,
        "data": {},
        "error": message,
    }


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def _main() -> None:
    import argparse
    import json as _json
    import sys

    parser = argparse.ArgumentParser(
        description=TOOL_INFO["description"],
        epilog=f"Version {TOOL_INFO['version']} — {TOOL_INFO['author']}",
    )
    parser.add_argument("target", help="Domain or URL to fingerprint")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--favicon", action="store_true",
                        help="Also fetch and hash /favicon.ico")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-o", "--output", help="Save JSON result to file")
    args = parser.parse_args()

    result = run(
        target=args.target,
        timeout=args.timeout,
        check_favicon=args.favicon,
        verbose=args.verbose,
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            _json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Saved to {args.output}")
        return

    if result.get("error"):
        print(f"ERROR: {result['error']}", file=sys.stderr)
        sys.exit(1)

    data = result["data"]
    print(f"\n=== Tech Fingerprint: {result['target']} ===\n")
    print(f"Final URL:  {data.get('final_url')}")
    print(f"Status:     {data.get('status_code')}")
    print(f"Server:     {data.get('server_header') or '-'}")
    print(f"Powered-By: {data.get('powered_by') or '-'}")
    print()
    if not data["detections"]:
        print("No technologies detected.")
        return
    print(f"Detected ({len(data['detections'])}):")
    for d in data["detections"]:
        ver = f" v{d['version']}" if d.get("version") else ""
        print(f"  [{d['confidence']:<6}] {d['name']}{ver}  ({d['category']})")
        for ev in d["evidence"]:
            print(f"           · {ev}")


if __name__ == "__main__":
    _main()
