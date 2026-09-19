#!/usr/bin/env python3
"""
modules/subdomain_takeover.py
──────────────────────────────────────────────────────────────────────────
Professional Subdomain Takeover detection engine.

Features
    • CNAME chain resolution (up to 10 hops)
    • 45+ provider fingerprints (AWS, Azure, GCP, Heroku, GitHub, etc.)
    • HTTP/HTTPS probe to confirm dangling services
    • Certificate Transparency enumeration via crt.sh
    • Bundled wordlist fallback for common subdomain prefixes
    • ThreadPoolExecutor with configurable concurrency
    • Rate limiting per host
    • Per-provider response-header and body-signature matching
    • Structured JSON output compatible with exploit.js

Public API
    ─ run(domain, options)         → {"candidates": [...], "dangling": [...]}
    ─ scan_single(host)            → per-host report
    ─ enumerate_subdomains(domain) → list of discovered hosts
    ─ PROVIDERS                    → provider fingerprint table

Author: Yanxzyx
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
import urllib3

try:
    import dns.resolver
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False


# Suppress the noisy InsecureRequestWarning when we probe misconfigured TLS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


logger = logging.getLogger("oxysintx.subdomain_takeover")


# ═══════════════════════════════════════════════════════════════════════════
# PROVIDER FINGERPRINTS
# ═══════════════════════════════════════════════════════════════════════════
# Each entry declares:
#   cnames   — substrings that must match the CNAME target
#   body     — substrings that must appear in the HTTP response body
#   headers  — header → substring that must match the header value
#   status   — HTTP status code that indicates a dangling service
#   severity — informational risk classification
#
# Matching logic (in `_fingerprint_match`):
#   If the CNAME matches → `cnames` hit is worth 1 point.
#   If the HTTP body matches → `body` hit is worth 2 points.
#   If the headers match → `headers` hit is worth 2 points.
#   Total ≥ 3 → "confirmed", ≥ 2 → "probable", ≥ 1 → "possible"
# ═══════════════════════════════════════════════════════════════════════════

PROVIDERS: List[Dict[str, Any]] = [
    # ─── AWS ─────────────────────────────────────────────────────────────
    {
        "name": "AWS S3",
        "cnames": ["s3.amazonaws.com", "s3-website", "s3-external-1.amazonaws.com"],
        "body": ["<Code>NoSuchBucket</Code>", "The specified bucket does not exist"],
        "headers": {"Server": "AmazonS3"},
        "severity": "critical",
        "documentation": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html",
    },
    {
        "name": "AWS CloudFront",
        "cnames": ["cloudfront.net"],
        "body": ["Bad request", "ERROR: The request could not be satisfied"],
        "headers": {"X-Cache": "Error from cloudfront"},
        "severity": "critical",
        "documentation": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/",
    },
    {
        "name": "AWS Elastic Beanstalk",
        "cnames": ["elasticbeanstalk.com"],
        "body": [],
        "headers": {},
        "severity": "high",
        "documentation": "https://docs.aws.amazon.com/elasticbeanstalk/",
    },
    {
        "name": "AWS Load Balancer",
        "cnames": ["elb.amazonaws.com", "elb.us-", "elb.eu-", "elb.ap-"],
        "body": [],
        "headers": {},
        "severity": "medium",
        "documentation": "https://docs.aws.amazon.com/elasticloadbalancing/",
    },

    # ─── Microsoft Azure ─────────────────────────────────────────────────
    {
        "name": "Azure App Service",
        "cnames": ["azurewebsites.net", "cloudapp.azure.com", "cloudapp.net"],
        "body": [
            "Error 404 - Web app not found",
            "The resource you are looking for has been removed",
        ],
        "headers": {},
        "severity": "critical",
        "documentation": "https://learn.microsoft.com/azure/app-service/",
    },
    {
        "name": "Azure Traffic Manager",
        "cnames": ["trafficmanager.net"],
        "body": [],
        "headers": {},
        "severity": "high",
        "documentation": "https://learn.microsoft.com/azure/traffic-manager/",
    },
    {
        "name": "Azure CDN",
        "cnames": ["azureedge.net", "afd.azureedge.net"],
        "body": ["The requested content does not exist"],
        "headers": {},
        "severity": "critical",
        "documentation": "https://learn.microsoft.com/azure/cdn/",
    },
    {
        "name": "Azure Blob Storage",
        "cnames": ["blob.core.windows.net"],
        "body": ["BlobNotFound", "The specified container does not exist"],
        "headers": {},
        "severity": "critical",
        "documentation": "https://learn.microsoft.com/azure/storage/blobs/",
    },

    # ─── Google Cloud ────────────────────────────────────────────────────
    {
        "name": "Google Cloud Storage",
        "cnames": ["storage.googleapis.com", "commondatastorage.googleapis.com"],
        "body": ["NoSuchBucket", "The specified bucket does not exist"],
        "headers": {},
        "severity": "critical",
        "documentation": "https://cloud.google.com/storage/",
    },
    {
        "name": "Google App Engine",
        "cnames": ["appspot.com"],
        "body": ["Error 404", "The requested URL was not found on this server"],
        "headers": {},
        "severity": "high",
        "documentation": "https://cloud.google.com/appengine/",
    },
    {
        "name": "Firebase Hosting",
        "cnames": ["firebaseapp.com", "web.app"],
        "body": ["Site Not Found", "404 - Page Not Found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://firebase.google.com/docs/hosting",
    },

    # ─── Other cloud providers ───────────────────────────────────────────
    {
        "name": "Heroku",
        "cnames": ["herokuapp.com", "herokudns.com", "herokussl.com"],
        "body": ["No such app", "There is no app configured at this host"],
        "headers": {},
        "severity": "critical",
        "documentation": "https://devcenter.heroku.com/articles/custom-domains",
    },
    {
        "name": "Netlify",
        "cnames": ["netlify.app", "netlify.com"],
        "body": ["Not Found - Request ID", "Looks like you've followed a broken link"],
        "headers": {},
        "severity": "high",
        "documentation": "https://docs.netlify.com/domains-https/",
    },
    {
        "name": "Vercel",
        "cnames": ["vercel.app", "now.sh", "vercel-dns.com"],
        "body": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        "headers": {},
        "severity": "high",
        "documentation": "https://vercel.com/docs/concepts/projects/domains",
    },
    {
        "name": "GitHub Pages",
        "cnames": ["github.io", "github.map.fastly.net"],
        "body": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "headers": {},
        "severity": "critical",
        "documentation": "https://docs.github.com/pages",
    },
    {
        "name": "GitLab Pages",
        "cnames": ["gitlab.io"],
        "body": ["The page you're looking for could not be found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://docs.gitlab.com/ee/user/project/pages/",
    },
    {
        "name": "Bitbucket Cloud",
        "cnames": ["bitbucket.io"],
        "body": ["Repository not found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://support.atlassian.com/bitbucket-cloud/",
    },
    {
        "name": "Surge.sh",
        "cnames": ["surge.sh"],
        "body": ["project not found", "404 Not Found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://surge.sh/help/",
    },
    {
        "name": "Render",
        "cnames": ["onrender.com"],
        "body": ["Not Found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://render.com/docs/custom-domains",
    },
    {
        "name": "Fly.io",
        "cnames": ["fly.dev", "fly.io"],
        "body": ["404 Not Found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://fly.io/docs/",
    },
    {
        "name": "Railway",
        "cnames": ["railway.app"],
        "body": ["Application not found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://docs.railway.app/",
    },
    {
        "name": "Kinsta",
        "cnames": ["kinsta.cloud"],
        "body": ["No Site For Domain"],
        "headers": {},
        "severity": "high",
        "documentation": "https://kinsta.com/docs/",
    },
    {
        "name": "DigitalOcean Spaces",
        "cnames": ["digitaloceanspaces.com"],
        "body": ["NoSuchBucket", "The specified bucket does not exist"],
        "headers": {},
        "severity": "critical",
        "documentation": "https://docs.digitalocean.com/products/spaces/",
    },
    {
        "name": "DigitalOcean App Platform",
        "cnames": ["ondigitalocean.app"],
        "body": ["404 Not Found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://docs.digitalocean.com/products/app-platform/",
    },
    {
        "name": "Cloudflare Pages",
        "cnames": ["pages.dev"],
        "body": ["Not Found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://developers.cloudflare.com/pages/",
    },
    {
        "name": "Cloudflare Workers",
        "cnames": ["workers.dev"],
        "body": ["There is nothing here yet", "404 Not Found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://developers.cloudflare.com/workers/",
    },

    # ─── SaaS platforms ──────────────────────────────────────────────────
    {
        "name": "Shopify",
        "cnames": ["myshopify.com", "shopify.com"],
        "body": ["Sorry, this shop is currently unavailable"],
        "headers": {},
        "severity": "critical",
        "documentation": "https://help.shopify.com/domains",
    },
    {
        "name": "BigCommerce",
        "cnames": ["mybigcommerce.com", "bigcommerce.com"],
        "body": ["Store Not Found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://support.bigcommerce.com/",
    },
    {
        "name": "Squarespace",
        "cnames": ["squarespace.com"],
        "body": ["No Such Account", "You're using an unsupported browser"],
        "headers": {},
        "severity": "high",
        "documentation": "https://support.squarespace.com/",
    },
    {
        "name": "Wix",
        "cnames": ["wixsite.com", "wix.com"],
        "body": ["Looks like this site was made on Wix", "Page not found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://support.wix.com/",
    },
    {
        "name": "WordPress.com",
        "cnames": ["wordpress.com", "wpcomstaging.com"],
        "body": ["Do you want to register"],
        "headers": {},
        "severity": "high",
        "documentation": "https://wordpress.com/support/domains/",
    },
    {
        "name": "Tumblr",
        "cnames": ["tumblr.com"],
        "body": ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
        "headers": {},
        "severity": "high",
        "documentation": "https://tumblr.com/docs/en/custom_domains",
    },
    {
        "name": "Zendesk",
        "cnames": ["zendesk.com"],
        "body": ["Help Center Closed", "No help center found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://support.zendesk.com/hc/en-us/articles/4408846122906",
    },
    {
        "name": "Desk.com",
        "cnames": ["desk.com"],
        "body": ["Sorry, this page is unavailable"],
        "headers": {},
        "severity": "medium",
        "documentation": "https://desk.com/",
    },
    {
        "name": "ReadTheDocs",
        "cnames": ["readthedocs.io", "readthedocs.org"],
        "body": ["404 - Not Found", "This page does not exist yet"],
        "headers": {},
        "severity": "high",
        "documentation": "https://docs.readthedocs.io/",
    },
    {
        "name": "Statuspage.io",
        "cnames": ["statuspage.io"],
        "body": ["This status page does not exist"],
        "headers": {},
        "severity": "medium",
        "documentation": "https://statuspage.io/",
    },
    {
        "name": "Fastly",
        "cnames": ["fastly.net", "fastlylb.net"],
        "body": ["Fastly error: unknown domain"],
        "headers": {"X-Served-By": "cache-"},
        "severity": "high",
        "documentation": "https://docs.fastly.com/",
    },
    {
        "name": "Pantheon",
        "cnames": ["pantheonsite.io"],
        "body": ["The gods are wise", "404 - The page you are looking for"],
        "headers": {},
        "severity": "high",
        "documentation": "https://pantheon.io/docs/domains/",
    },
    {
        "name": "Cargo Collective",
        "cnames": ["cargocollective.com"],
        "body": ["404 Not Found"],
        "headers": {},
        "severity": "medium",
        "documentation": "https://cargocollective.com/",
    },
    {
        "name": "Helpjuice",
        "cnames": ["helpjuice.com"],
        "body": ["We could not find what you're looking for"],
        "headers": {},
        "severity": "medium",
        "documentation": "https://helpjuice.com/",
    },
    {
        "name": "Helpscout",
        "cnames": ["helpscoutdocs.com"],
        "body": ["No settings were found for this company"],
        "headers": {},
        "severity": "medium",
        "documentation": "https://helpscout.com/",
    },
    {
        "name": "Tilda",
        "cnames": ["tilda.ws"],
        "body": ["Please renew your subscription"],
        "headers": {},
        "severity": "medium",
        "documentation": "https://tilda.cc/",
    },
    {
        "name": "Smartling",
        "cnames": ["smartling.com"],
        "body": ["Domain is not configured"],
        "headers": {},
        "severity": "medium",
        "documentation": "https://smartling.com/",
    },
    {
        "name": "Strikingly",
        "cnames": ["strikingly.com", "s.strikinglydns.com"],
        "body": ["page not found"],
        "headers": {},
        "severity": "medium",
        "documentation": "https://strikingly.com/",
    },
    {
        "name": "Unbounce",
        "cnames": ["unbouncepages.com"],
        "body": ["The requested URL was not found on this server"],
        "headers": {},
        "severity": "medium",
        "documentation": "https://unbounce.com/",
    },
    {
        "name": "UserVoice",
        "cnames": ["uservoice.com"],
        "body": ["This UserVoice subdomain is currently available"],
        "headers": {},
        "severity": "medium",
        "documentation": "https://uservoice.com/",
    },
    {
        "name": "Tave",
        "cnames": ["tave.com"],
        "body": ["404 Not Found"],
        "headers": {},
        "severity": "low",
        "documentation": "https://tave.com/",
    },
    {
        "name": "Agile CRM",
        "cnames": ["agilecrm.com"],
        "body": ["Sorry, this page is no longer available"],
        "headers": {},
        "severity": "low",
        "documentation": "https://agilecrm.com/",
    },
    {
        "name": "Anima",
        "cnames": ["animaapp.io"],
        "body": ["The page you're looking for doesn't exist"],
        "headers": {},
        "severity": "low",
        "documentation": "https://animaapp.com/",
    },
    {
        "name": "Ngrok",
        "cnames": ["ngrok.io", "ngrok-free.app"],
        "body": ["Tunnel not found", "endpoint not found"],
        "headers": {},
        "severity": "high",
        "documentation": "https://ngrok.com/docs/",
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# COMMON SUBDOMAIN WORDLIST (fallback enumeration)
# ═══════════════════════════════════════════════════════════════════════════
COMMON_SUBDOMAINS: List[str] = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
    "web", "media", "email", "images", "img", "www1", "intranet", "portal",
    "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3",
    "dns", "search", "staging", "server", "mx1", "chat", "wap", "my", "svn",
    "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2",
    "lyncdiscover", "info", "apps", "download", "remote", "db", "forums",
    "store", "relay", "files", "newsletter", "app", "live", "owa", "en",
    "start", "sms", "office", "exchange", "ipv4", "help", "blogs", "helpdesk",
    "web1", "home", "library", "ftp2", "ntp", "monitor", "login", "service",
    "correo", "www4", "moodle", "webconf", "radio", "oa", "erp", "account",
    "partners", "upload", "git", "gitlab", "jenkins", "docker", "k8s",
    "kubernetes", "prometheus", "grafana", "kibana", "elastic", "solr",
    "staging1", "stage", "qa", "uat", "internal", "external", "partner",
    "careers", "jobs", "about", "contact", "newsite", "assets", "v2", "v3",
]


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class CnameChain:
    """Result of walking the CNAME chain for a host."""
    chain: List[str] = field(default_factory=list)
    final_target: Optional[str] = None
    failed_at: Optional[str] = None     # hostname where resolution broke
    error: Optional[str] = None

    @property
    def is_dangling(self) -> bool:
        """A chain that ends in NXDOMAIN is a dangling-CNAME candidate."""
        return bool(self.failed_at and not self.error)


@dataclass
class HttpProbe:
    """HTTP/HTTPS probe result for a host."""
    url: Optional[str] = None
    status: Optional[int] = None
    server: Optional[str] = None
    body_snippet: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    elapsed_ms: float = 0.0

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "server": self.server,
            "body_snippet": self.body_snippet[:300],
            "headers": {k: v for k, v in list(self.headers.items())[:20]},
            "error": self.error,
            "elapsed_ms": round(self.elapsed_ms, 1),
        }


@dataclass
class TakeoverFinding:
    """A single subdomain takeover finding."""
    host: str
    provider: Optional[str] = None
    risk: str = "unknown"               # confirmed | probable | possible
    severity: str = "unknown"           # critical | high | medium | low
    cname_chain: List[str] = field(default_factory=list)
    final_cname: Optional[str] = None
    http: Optional[HttpProbe] = None
    matched_body: Optional[str] = None
    matched_headers: Dict[str, str] = field(default_factory=dict)
    matched_cname_pattern: Optional[str] = None
    documentation: Optional[str] = None
    reason: str = ""

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "provider": self.provider,
            "risk": self.risk,
            "severity": self.severity,
            "cname_chain": self.cname_chain,
            "final_cname": self.final_cname,
            "documentation": self.documentation,
            "reason": self.reason,
            "matched": {
                "cname": self.matched_cname_pattern,
                "body": self.matched_body,
                "headers": self.matched_headers,
            },
            "http": self.http.to_public_dict() if self.http else None,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Rate limiter
# ═══════════════════════════════════════════════════════════════════════════
class RateLimiter:
    """Simple per-key token-bucket rate limiter."""

    def __init__(self, rate_per_second: float = 10.0):
        self._rate = max(0.1, float(rate_per_second))
        self._interval = 1.0 / self._rate
        self._lock = threading.Lock()
        self._next_allowed: Dict[str, float] = {}

    def wait(self, key: str = "default") -> None:
        with self._lock:
            now = time.monotonic()
            nxt = self._next_allowed.get(key, 0.0)
            if now < nxt:
                sleep_for = nxt - now
            else:
                sleep_for = 0.0
            self._next_allowed[key] = max(now, nxt) + self._interval
        if sleep_for > 0:
            time.sleep(sleep_for)


# ═══════════════════════════════════════════════════════════════════════════
# DNS resolution
# ═══════════════════════════════════════════════════════════════════════════
class DnsResolver:
    """CNAME chain resolver with caching and safe defaults."""

    def __init__(self, timeout: float = 3.0, max_hops: int = 10):
        self.timeout = timeout
        self.max_hops = max_hops
        self._cache: Dict[str, CnameChain] = {}
        self._lock = threading.Lock()

    def resolve_chain(self, host: str) -> CnameChain:
        with self._lock:
            cached = self._cache.get(host)
        if cached is not None:
            return cached
        result = self._walk(host)
        with self._lock:
            self._cache[host] = result
        return result

    def _walk(self, host: str) -> CnameChain:
        chain = [host]
        current = host
        seen: Set[str] = set()
        for _ in range(self.max_hops):
            if current in seen:
                return CnameChain(chain=chain, final_target=current,
                                  error="cname_loop")
            seen.add(current)
            try:
                target = self._lookup_cname(current)
            except _NxDomain:
                # NXDOMAIN on the *original* host means it simply doesn't exist.
                # NXDOMAIN on a CNAME *target* means the CNAME dangles.
                if len(chain) == 1:
                    return CnameChain(chain=chain, error="nxdomain")
                return CnameChain(chain=chain, final_target=chain[-2],
                                  failed_at=current)
            except _NoAnswer:
                # No CNAME at this hop — resolution stopped cleanly
                return CnameChain(chain=chain, final_target=current)
            except Exception as e:  # noqa: BLE001
                return CnameChain(chain=chain, final_target=current, error=str(e))

            if not target:
                return CnameChain(chain=chain, final_target=current)

            chain.append(target)
            current = target

        return CnameChain(chain=chain, final_target=current, error="max_hops")

    def _lookup_cname(self, host: str) -> Optional[str]:
        if not _DNS_AVAILABLE:
            return self._lookup_cname_socket(host)
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            answers = resolver.resolve(host, "CNAME", raise_on_no_answer=False)
            if answers.rrset is None:
                raise _NoAnswer()
            return str(answers[0].target).rstrip(".").lower()
        except dns.resolver.NXDOMAIN:
            raise _NxDomain()
        except dns.resolver.NoAnswer:
            raise _NoAnswer()
        except dns.resolver.NoNameservers:
            # Fall back to a socket lookup so a broken resolver doesn't kill us
            return self._lookup_cname_socket(host)
        except Exception:
            return self._lookup_cname_socket(host)

    @staticmethod
    def _lookup_cname_socket(host: str) -> Optional[str]:
        """Best-effort CNAME via gethostbyname_ex (returns the canonical name)."""
        try:
            _, aliases, _ = socket.gethostbyname_ex(host)
            if aliases:
                return aliases[0].rstrip(".").lower()
        except socket.gaierror:
            raise _NxDomain()
        return None


class _NxDomain(Exception):
    """Raised when a lookup hits NXDOMAIN."""


class _NoAnswer(Exception):
    """Raised when a lookup returns an empty answer section."""


# ═══════════════════════════════════════════════════════════════════════════
# HTTP probe
# ═══════════════════════════════════════════════════════════════════════════
def _probe_http(host: str, timeout: float = 8.0,
                rate_limiter: Optional[RateLimiter] = None) -> HttpProbe:
    """Probe a host over HTTPS (fallback HTTP), following no redirects."""
    if rate_limiter:
        rate_limiter.wait(host)

    headers = {
        "User-Agent": "Emergens-Takeover-Scanner/1.0 (+https://emergens.id)",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }

    last_error = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        start = time.monotonic()
        try:
            r = requests.get(
                url, timeout=timeout, headers=headers,
                allow_redirects=False, verify=False, stream=True,
            )
            body_bytes = b""
            for chunk in r.iter_content(chunk_size=4096):
                body_bytes += chunk
                if len(body_bytes) >= 16384:
                    break
            r.close()
            elapsed = (time.monotonic() - start) * 1000

            try:
                body_text = body_bytes.decode("utf-8", errors="replace")
            except Exception:
                body_text = body_bytes.decode("latin-1", errors="replace")

            return HttpProbe(
                url=url,
                status=r.status_code,
                server=r.headers.get("Server"),
                body_snippet=body_text[:1000],
                headers={k: v for k, v in r.headers.items()},
                elapsed_ms=elapsed,
            )
        except requests.exceptions.SSLError as e:
            last_error = f"ssl: {e}"
            continue
        except requests.exceptions.ConnectionError as e:
            last_error = f"conn: {e}"
            continue
        except requests.exceptions.Timeout:
            last_error = "timeout"
            continue
        except Exception as e:  # noqa: BLE001
            last_error = str(e)
            continue

    return HttpProbe(error=last_error or "no_response")


# ═══════════════════════════════════════════════════════════════════════════
# Fingerprinting engine
# ═══════════════════════════════════════════════════════════════════════════
def _fingerprint_match(cname: Optional[str],
                       http: Optional[HttpProbe]) -> List[TakeoverFinding]:
    """Return provider matches sorted by confidence."""
    cname = (cname or "").lower()
    body_lower = (http.body_snippet or "").lower() if http else ""
    headers_lower = {k.lower(): (v or "").lower()
                     for k, v in (http.headers or {}).items()} if http else {}

    findings: List[TakeoverFinding] = []

    for provider in PROVIDERS:
        score = 0
        matched_cname: Optional[str] = None
        matched_body: Optional[str] = None
        matched_headers: Dict[str, str] = {}

        # ── CNAME pattern match (weight 1) ──
        for pattern in provider.get("cnames", []):
            if pattern.lower() in cname:
                score += 1
                matched_cname = pattern
                break

        # ── HTTP body match (weight 2) ──
        for needle in provider.get("body", []):
            if needle.lower() in body_lower:
                score += 2
                matched_body = needle
                break

        # ── Header match (weight 2) ──
        for hk, hv in (provider.get("headers") or {}).items():
            hk_l = hk.lower()
            hv_l = (hv or "").lower()
            if hk_l in headers_lower and hv_l in headers_lower[hk_l]:
                score += 2
                matched_headers[hk] = headers_lower[hk_l]
                break

        if score == 0:
            continue

        if score >= 3:
            risk = "confirmed"
        elif score >= 2:
            risk = "probable"
        else:
            risk = "possible"

        # Build a human-readable reason string
        reason_parts = []
        if matched_cname:
            reason_parts.append(f"CNAME matches '{matched_cname}'")
        if matched_body:
            reason_parts.append(f"body signature '{matched_body}'")
        if matched_headers:
            for hk, hv in matched_headers.items():
                reason_parts.append(f"header {hk}: {hv}")

        findings.append(TakeoverFinding(
            host="",  # filled by caller
            provider=provider["name"],
            risk=risk,
            severity=provider.get("severity", "medium"),
            matched_cname_pattern=matched_cname,
            matched_body=matched_body,
            matched_headers=matched_headers,
            documentation=provider.get("documentation"),
            reason="; ".join(reason_parts) or "fingerprint match",
        ))

    # Sort by severity, then confidence
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    conf_order = {"confirmed": 0, "probable": 1, "possible": 2}
    findings.sort(key=lambda f: (conf_order[f.risk], order.get(f.severity, 9)))
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Subdomain enumeration
# ═══════════════════════════════════════════════════════════════════════════
def enumerate_subdomains(domain: str,
                         use_crtsh: bool = True,
                         use_wordlist: bool = True,
                         timeout: float = 20.0) -> Set[str]:
    """Return a set of candidate subdomains for the given domain.

    Sources:
      • crt.sh (Certificate Transparency) via HTTPS
      • A bundled ~150-entry common-prefix wordlist
      • The apex domain itself
    """
    domain = domain.strip().lower().rstrip(".")
    out: Set[str] = {domain}
    root = _registrable_domain(domain)

    # ── crt.sh ──
    if use_crtsh:
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            r = requests.get(url, timeout=timeout,
                             headers={"User-Agent": "Emergens-Takeover/1.0"})
            if r.status_code == 200 and r.text.strip().startswith("["):
                data = json.loads(r.text)
                for entry in data:
                    for name in (entry.get("name_value") or "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith("." + root) or name == root:
                            out.add(name)
            else:
                logger.warning(f"crt.sh returned HTTP {r.status_code} for {domain}")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"crt.sh enumeration failed for {domain}: {e}")

    # ── wordlist ──
    if use_wordlist:
        for prefix in COMMON_SUBDOMAINS:
            out.add(f"{prefix}.{domain}")

    return out


def _registrable_domain(host: str) -> str:
    """Best-effort extraction of the registrable domain."""
    if _TLDEXTRACT_AVAILABLE:
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    # Fallback — last two labels
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


# ═══════════════════════════════════════════════════════════════════════════
# Scanner
# ═══════════════════════════════════════════════════════════════════════════
class SubdomainTakeoverScanner:
    """High-level scanner that orchestrates the full pipeline."""

    def __init__(self,
                 concurrency: int = 20,
                 dns_timeout: float = 3.0,
                 http_timeout: float = 8.0,
                 rate_limit: float = 15.0):
        self.concurrency = max(1, min(int(concurrency), 100))
        self.dns = DnsResolver(timeout=dns_timeout)
        self.http_timeout = http_timeout
        self.rate_limiter = RateLimiter(rate_per_second=rate_limit)
        self._stop = threading.Event()

    def cancel(self) -> None:
        self._stop.set()

    # ── Single-host scan ────────────────────────────────────────────────
    def scan_single(self, host: str) -> Optional[TakeoverFinding]:
        """Return a TakeoverFinding if `host` looks vulnerable, else None."""
        if self._stop.is_set():
            return None

        chain = self.dns.resolve_chain(host)

        # Skip hosts that outright don't exist (NXDOMAIN on the original host)
        if chain.error == "nxdomain":
            return None

        # Skip hosts that resolve to a real A record without a dangling CNAME
        if not chain.chain or len(chain.chain) < 2:
            # No CNAME at all → no takeover possible via CNAME
            return None

        # The host has a CNAME — probe it over HTTP
        http = _probe_http(host, timeout=self.http_timeout,
                           rate_limiter=self.rate_limiter)

        cname_target = chain.final_target or chain.chain[-1]
        findings = _fingerprint_match(cname_target, http)

        if not findings:
            return None

        top = findings[0]
        top.host = host
        top.cname_chain = list(chain.chain)
        top.final_cname = cname_target
        top.http = http

        # Boost confidence if the CNAME chain actually broke
        if chain.is_dangling:
            if top.risk == "possible":
                top.risk = "probable"
            elif top.risk == "probable":
                top.risk = "confirmed"
            top.reason = (top.reason + "; CNAME target did not resolve").strip("; ")

        return top

    # ── Bulk scan ───────────────────────────────────────────────────────
    def scan_many(self, hosts: Iterable[str]) -> List[TakeoverFinding]:
        hosts = list(dict.fromkeys(h.strip().lower() for h in hosts if h))
        findings: List[TakeoverFinding] = []
        lock = threading.Lock()

        def worker(h: str):
            if self._stop.is_set():
                return
            try:
                result = self.scan_single(h)
            except Exception as e:  # noqa: BLE001
                logger.warning(f"scan_single({h}) failed: {e}")
                result = None
            if result:
                with lock:
                    findings.append(result)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.concurrency
        ) as executor:
            futures = [executor.submit(worker, h) for h in hosts]
            for future in concurrent.futures.as_completed(futures):
                if self._stop.is_set():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    future.result()
                except Exception:
                    continue

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# Public API — called by exploit.js via /api/exploit/takeover
# ═══════════════════════════════════════════════════════════════════════════
def run(domain: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Run a full subdomain takeover scan.

    Args:
        domain:  apex domain or subdomain (e.g. "example.com")
        options: {
            "enumerate":     bool  — run crt.sh + wordlist enumeration (default True)
            "use_crtsh":     bool  — use crt.sh (default True)
            "use_wordlist":  bool  — use the bundled wordlist (default True)
            "concurrency":   int   — parallel workers (default 20)
            "max_hosts":     int   — hard cap on hosts to scan (default 500)
            "http_timeout":  float — HTTP probe timeout (default 8s)
            "dns_timeout":   float — DNS timeout (default 3s)
            "rate_limit":    float — probes per second (default 15)
        }

    Returns:
        {
            "domain":     str,
            "scanned":    int,
            "started_at": ISO-8601 UTC,
            "finished_at":ISO-8601 UTC,
            "elapsed":    float (seconds),
            "candidates": [{host, cname_chain, final_cname}, ...],
            "dangling":   [ TakeoverFinding dicts ],
        }
    """
    options = options or {}

    enumerate_hosts  = bool(options.get("enumerate", True))
    use_crtsh        = bool(options.get("use_crtsh", True))
    use_wordlist     = bool(options.get("use_wordlist", True))
    concurrency      = int(options.get("concurrency", 20))
    max_hosts        = int(options.get("max_hosts", 500))
    http_timeout     = float(options.get("http_timeout", 8.0))
    dns_timeout      = float(options.get("dns_timeout", 3.0))
    rate_limit       = float(options.get("rate_limit", 15.0))

    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        raise ValueError("domain is required")

    started_at = datetime.now(timezone.utc)
    t0 = time.monotonic()

    # ── Enumerate ──────────────────────────────────────────────────────
    if enumerate_hosts:
        hosts = enumerate_subdomains(domain,
                                     use_crtsh=use_crtsh,
                                     use_wordlist=use_wordlist)
    else:
        hosts = {domain}

    hosts = sorted(hosts)[:max_hosts]
    logger.info(f"Subdomain takeover scan: {domain} — {len(hosts)} host(s)")

    # ── Scan ───────────────────────────────────────────────────────────
    scanner = SubdomainTakeoverScanner(
        concurrency=concurrency,
        dns_timeout=dns_timeout,
        http_timeout=http_timeout,
        rate_limit=rate_limit,
    )
    findings = scanner.scan_many(hosts)

    # ── Build the full candidate list (all hosts with a CNAME) ─────────
    candidates: List[Dict[str, Any]] = []
    for h in hosts:
        chain = scanner.dns.resolve_chain(h)
        if len(chain.chain) >= 2:
            candidates.append({
                "host": h,
                "cname_chain": chain.chain,
                "final_cname": chain.final_target,
                "dangling": chain.is_dangling,
            })

    finished_at = datetime.now(timezone.utc)
    elapsed = time.monotonic() - t0

    return {
        "domain":      domain,
        "scanned":     len(hosts),
        "started_at":  started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "elapsed":     round(elapsed, 2),
        "candidates":  candidates,
        "dangling":    [f.to_public_dict() for f in findings],
    }


# ═══════════════════════════════════════════════════════════════════════════
# CLI (for standalone testing)
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Subdomain Takeover Scanner — standalone CLI",
    )
    parser.add_argument("domain", help="apex domain, e.g. example.com")
    parser.add_argument("--no-enum", action="store_true",
                        help="skip subdomain enumeration, scan only the apex")
    parser.add_argument("--no-crtsh", action="store_true",
                        help="skip crt.sh enumeration")
    parser.add_argument("--no-wordlist", action="store_true",
                        help="skip the bundled wordlist")
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--max-hosts", type=int, default=500)
    parser.add_argument("--rate-limit", type=float, default=15.0)
    parser.add_argument("--json", action="store_true",
                        help="output raw JSON instead of the human report")

    args = parser.parse_args()

    try:
        report = run(args.domain, {
            "enumerate":    not args.no_enum,
            "use_crtsh":    not args.no_crtsh,
            "use_wordlist": not args.no_wordlist,
            "concurrency":  args.concurrency,
            "max_hosts":    args.max_hosts,
            "rate_limit":   args.rate_limit,
        })
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(report, indent=2))
        sys.exit(0)

    # ── Human-readable report ─────────────────────────────────────────
    print()
    print("═" * 72)
    print(f"  Subdomain Takeover Report — {report['domain']}")
    print("═" * 72)
    print(f"  Scanned     : {report['scanned']} host(s)")
    print(f"  Candidates  : {len(report['candidates'])} with CNAME")
    print(f"  Dangling    : {len(report['dangling'])}")
    print(f"  Elapsed     : {report['elapsed']}s")
    print()

    if report["dangling"]:
        print("  VULNERABLE HOSTS")
        print("  " + "─" * 68)
        for d in report["dangling"]:
            sev = d["severity"].upper()
            risk = d["risk"].upper()
            print(f"  [{sev:8s}] [{risk:10s}] {d['host']}")
            print(f"              Provider : {d['provider']}")
            print(f"              CNAME    : {' → '.join(d['cname_chain'])}")
            if d["matched"].get("body"):
                print(f"              Body sig : {d['matched']['body'][:60]}")
            if d["matched"].get("headers"):
                for hk, hv in d["matched"]["headers"].items():
                    print(f"              Header   : {hk}: {hv[:60]}")
            if d.get("documentation"):
                print(f"              Docs     : {d['documentation']}")
            print()
    else:
        print("  No takeover vulnerabilities detected.")
        print()

    if report["candidates"]:
        print("  ALL CANDIDATES")
        print("  " + "─" * 68)
        for c in report["candidates"][:30]:
            marker = "  ⚠ " if c["dangling"] else "    "
            print(f"{marker}{c['host']:45s} → {c['final_cname']}")
        if len(report["candidates"]) > 30:
            print(f"    … and {len(report['candidates']) - 30} more")
    print()
