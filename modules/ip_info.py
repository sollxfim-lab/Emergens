#!/usr/bin/env python3
"""
Oxysintx — IP & ASN Intelligence Module (v5.0.0)

Enterprise IP intelligence scanner with dual-mode operation:

  ┌── OFFLINE / LOCAL INTELLIGENCE (no external API needed) ──────────┐
  │ • IP classification (private/public/loopback/multicast/reserved)  │
  │ • IPv4 / IPv6 analysis with scope + type                          │
  │ • Reverse DNS (PTR) + forward confirmation                        │
  │ • Team Cymru ASN lookup (IPv4 + IPv6 via DNS TXT)                 │
  │ • WHOIS via raw TCP port 43 (no HTTP API)                         │
  │ • RDAP via official ARIN/RIPE/APNIC registry (no key)             │
  │ • DNSBL / RBL blacklist checks (Spamhaus, Barracuda, SORBS…)      │
  │ • TCP reachability probe (open/closed/filtered)                   │
  │ • TLS certificate fetch (subject / issuer / expiry / SANs)        │
  │ • CDN detection (Cloudflare / Akamai / CloudFront / Fastly)       │
  │ • TOR exit node detection                                         │
  │ • Known VPN / datacenter / hosting range detection                │
  └───────────────────────────────────────────────────────────────────┘

  ┌── API PROVIDERS (with Cloudflare bypass) ────────────────────────┐
  │ • ipwho.is        • ip-api.com      • ipapi.co                    │
  │ • ipinfo.io       • ipapi.is        • freeipapi.com               │
  │ • All through multi-layer CF bypass: curl_cffi / cloudscraper /   │
  │   FlareSolverr / manual — with rate limit + retry + fallback      │
  └───────────────────────────────────────────────────────────────────┘

Extra features
  • Cloudflare bypass + WAF detection
  • Rich security flags: is_proxy / is_hosting / is_tor / is_vpn / is_abuse
  • Confidence-based result merging (provider weights)
  • TTL cache + token-bucket rate limiting
  • Multi-provider parallel queries with graceful degradation
  • Batch scanning, SSE streaming, SARIF export
  • Full CLI with offline mode (`--offline`)
  • Isolated logger — never duplicates Flask handlers
  • Backward-compatible run(target, mode) orchestrator signature

Author: Yanxzyx
Version: 5.0.0
"""

from __future__ import annotations

import argparse
import ipaddress
import json as _json
import logging
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ── Optional: Cloudflare bypass libs ──────────────────────────────────────
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

# ── Optional: dnspython for TXT-based ASN lookups ─────────────────────────
try:
    import dns.resolver as _dns_resolver  # type: ignore
    _HAS_DNS = True
except ImportError:
    _dns_resolver = None
    _HAS_DNS = False

FLARESOLVERR_URL = os.getenv("FLARESOLVERR_URL", "").strip()


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════
logger = logging.getLogger("oxysintx.ip_info")
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
# METADATA
# ═══════════════════════════════════════════════════════════════════════════
__version__ = "5.0.0"
__author__  = "Yanxzyx"

TOOL_INFO = {
    "name": "IP & ASN Info",
    "version": __version__,
    "description": (
        "Enterprise IP & ASN intelligence scanner with dual-mode: offline "
        "local analysis (Team Cymru ASN, RDAP, WHOIS, DNSBL, TCP probe, TLS "
        "cert, Tor/VPN/CDN detection) + API providers (ipwho.is, ip-api.com, "
        "ipapi.co, ipinfo.io, ipapi.is, freeipapi.com) with Cloudflare bypass."
    ),
    "category": "Network",
    "author": __author__,
}
TOOL_KIND = "scanner"


# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
DEFAULT_TIMEOUT      = 10.0
DEFAULT_CACHE_TTL    = 3600
DEFAULT_RATE_LIMIT   = 20.0
DEFAULT_WORKERS      = 6
DNSBL_TIMEOUT        = 5.0
RDAP_TIMEOUT         = 12.0
WHOIS_TIMEOUT        = 8.0
TCP_PROBE_TIMEOUT    = 4.0
TLS_TIMEOUT          = 5.0
TOR_LIST_TIMEOUT     = 12.0
TOR_LIST_TTL         = 3600
TOR_LIST_URL         = "https://check.torproject.org/torbulkexitlist"

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

# DNS-based blacklist zones (queried as <reversed-ip>.<zone>)
DNSBL_ZONES = {
    "zen.spamhaus.org":         "Spamhaus ZEN",
    "b.barracudacentral.org":   "Barracuda",
    "dnsbl.sorbs.net":          "SORBS",
    "bl.spamcop.net":           "SpamCop",
    "dnsbl-1.uceprotect.net":   "UCEPROTECT L1",
    "dnsbl-2.uceprotect.net":   "UCEPROTECT L2",
    "psbl.surriel.com":         "PSBL",
    "cbl.abuseat.org":          "CBL (Abuseat)",
    "spam.dnsbl.sorbs.net":     "SORBS Spam",
    "ubl.unsubscore.com":       "Lashback UBL",
}

# Known datacenter / hosting ASNs (informational hint)
HOSTING_ASNS = {
    "AS13335", "AS14061", "AS16509", "AS14618", "AS15169", "AS396982",
    "AS8075", "AS20940", "AS19527", "AS54113", "AS24940", "AS20473",
    "AS63949", "AS9009", "AS12876", "AS16276", "AS51167", "AS197540",
}

# CDN ASN → name (for ASN-based CDN detection)
CDN_ASNS = {
    "AS13335": "Cloudflare",
    "AS20940": "Akamai",
    "AS16625": "Akamai",
    "AS16509": "Amazon (CloudFront/AWS)",
    "AS14618": "Amazon (CloudFront/AWS)",
    "AS54113": "Fastly",
    "AS19527": "Google Cloud CDN",
    "AS396982": "Google Cloud",
    "AS15169": "Google",
    "AS12222": "Akamai",
    "AS35995": "Voxility",
    "AS14061": "DigitalOcean",
    "AS24940": "Hetzner",
    "AS63949": "Linode",
    "AS20473": "Vultr",
}

# Scoring weights per provider for merge priority
PROVIDER_WEIGHTS = {
    "ipinfo.io":    1.00,
    "ipapi.is":     0.95,
    "ipwho.is":     0.90,
    "ipapi.co":     0.85,
    "ip-api.com":   0.80,
    "freeipapi.com": 0.70,
    "team-cymru":   0.95,
    "rdap":         0.90,
    "whois":        0.80,
    "local":        1.00,
}


# ═══════════════════════════════════════════════════════════════════════════
# TTL CACHE
# ═══════════════════════════════════════════════════════════════════════════
class TTLCache:
    def __init__(self, ttl_seconds: int = DEFAULT_CACHE_TTL):
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self.ttl = ttl_seconds
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            ts, val = entry
            if time.time() - ts < self.ttl:
                return val
            self._cache.pop(key, None)
        return None

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._cache[key] = (time.time(), value)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# ═══════════════════════════════════════════════════════════════════════════
# TOKEN BUCKET
# ═══════════════════════════════════════════════════════════════════════════
class _TokenBucket:
    def __init__(self, rate: float, burst: int = 4):
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
            time.sleep(min(wait, 0.2))
        return False


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class IPInfoResult:
    ip: str

    # ── Geo
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    postal: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    utc_offset: Optional[str] = None

    # ── Network
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    asn_country: Optional[str] = None
    asn_registry: Optional[str] = None
    asn_route: Optional[str] = None
    asn_description: Optional[str] = None
    bgp_prefix: Optional[str] = None
    domain: Optional[str] = None
    reverse_dns: Optional[str] = None
    type: Optional[str] = None

    # ── IP classification (local)
    ip_version: Optional[int] = None
    is_private: Optional[bool] = None
    is_loopback: Optional[bool] = None
    is_multicast: Optional[bool] = None
    is_reserved: Optional[bool] = None
    is_link_local: Optional[bool] = None
    is_global: Optional[bool] = None
    ip_scope: Optional[str] = None

    # ── Security flags
    is_proxy: Optional[bool] = None
    is_hosting: Optional[bool] = None
    is_mobile: Optional[bool] = None
    is_tor: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_abuse: Optional[bool] = None

    # ── Provider / source
    provider: Optional[str] = None
    providers_used: List[str] = field(default_factory=list)
    confidence: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ═══════════════════════════════════════════════════════════════════════════
# LOCAL INTELLIGENCE — no external API needed
# ═══════════════════════════════════════════════════════════════════════════
def _classify_ip(ip: str) -> Dict[str, Any]:
    """Classify an IP address locally using the stdlib ipaddress module."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    if isinstance(addr, ipaddress.IPv4Address):
        version = 4
        reverse_ptr = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    else:
        version = 6
        # Nibble-reversed ip6.arpa form
        hex_expanded = addr.exploded.replace(":", "")
        reverse_ptr = ".".join(reversed(hex_expanded)) + ".ip6.arpa"
    return {
        "ip_version": version,
        "is_private": addr.is_private,
        "is_loopback": addr.is_loopback,
        "is_multicast": addr.is_multicast,
        "is_reserved": addr.is_reserved,
        "is_link_local": addr.is_link_local,
        "is_global": addr.is_global,
        "ip_scope": "global" if addr.is_global else (
            "private" if addr.is_private else
            "loopback" if addr.is_loopback else
            "link-local" if addr.is_link_local else
            "reserved"
        ),
        "reverse_ptr": reverse_ptr,
    }


def _reverse_dns(ip: str, timeout: float = 5.0) -> Optional[str]:
    """PTR lookup (uses system resolver)."""
    try:
        # socket.gethostbyaddr is blocking; wrap in a thread timeout guard
        result: List[Optional[str]] = [None]

        def _worker():
            try:
                result[0] = socket.gethostbyaddr(ip)[0]
            except Exception:
                result[0] = None

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(timeout=timeout)
        return result[0]
    except Exception:
        return None


def _forward_confirm(hostname: str, expected_ip: str,
                     timeout: float = 5.0) -> bool:
    """Confirm hostname resolves back to the same IP (forward-confirmed rDNS)."""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        return any(info[4][0] == expected_ip for info in infos)
    except Exception:
        return False


def _team_cymru_asn(ip: str) -> Dict[str, Any]:
    """
    Team Cymru ASN lookup via DNS TXT — no HTTP API, works for IPv4 + IPv6.
    Returns {asn, asn_name, asn_country, asn_registry, asn_route, asn_description}.
    """
    out: Dict[str, Any] = {}
    if not _HAS_DNS:
        logger.debug("[ip] dnspython not installed — skipping Team Cymru")
        return out

    try:
        if ":" in ip:
            try:
                addr = ipaddress.IPv6Address(ip)
                hex_str = addr.exploded.replace(":", "")
                query = ".".join(reversed(hex_str)) + ".origin6.asn.cymru.com"
            except Exception:
                return out
        else:
            query = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"

        try:
            ans = _dns_resolver.resolve(query, "TXT", lifetime=5)
        except Exception as e:
            logger.debug("[ip] Team Cymru TXT resolve failed: %s", e)
            return out

        for rdata in ans:
            txt = str(rdata).strip('"').strip("'")
            parts = [p.strip() for p in txt.split("|")]
            if not parts or not parts[0]:
                continue
            asn_raw = parts[0]
            if asn_raw.lower() in ("na", "none", ""):
                continue
            out["asn"] = asn_raw if asn_raw.upper().startswith("AS") else f"AS{asn_raw}"
            if len(parts) >= 2 and parts[1]: out["bgp_prefix"] = parts[1]
            if len(parts) >= 3 and parts[2]: out["asn_route"]    = parts[2]
            if len(parts) >= 4 and parts[3]: out["asn_country"]  = parts[3]
            if len(parts) >= 5 and parts[4]: out["asn_registry"] = parts[4]
            if len(parts) >= 7 and parts[6]: out["asn_name"]     = parts[6]
            break

        asn_num = (out.get("asn") or "").replace("AS", "").strip()
        if asn_num:
            try:
                desc_ans = _dns_resolver.resolve(
                    f"AS{asn_num}.asn.cymru.com", "TXT", lifetime=5,
                )
                for rdata in desc_ans:
                    desc_txt = str(rdata).strip('"').strip("'")
                    desc_parts = [p.strip() for p in desc_txt.split("|")]
                    if len(desc_parts) >= 5 and desc_parts[4]:
                        out["asn_description"] = desc_parts[4]
                    break
            except Exception:
                pass

    except Exception as e:
        logger.debug("[ip] Team Cymru lookup failed for %s: %s", ip, e)
    return out


def _rdap_lookup(ip: str, timeout: float = RDAP_TIMEOUT) -> Dict[str, Any]:
    """
    Query RDAP (official registry protocol) via rdap.org bootstrap.
    No API key required — returns raw registry data.
    """
    out: Dict[str, Any] = {}
    try:
        # rdap.org is the official IANA bootstrap
        r = requests.get(
            f"https://rdap.org/ip/{ip}",
            timeout=timeout,
            headers={"User-Agent": _UA_POOL[0], "Accept": "application/rdap+json"},
            allow_redirects=True,
        )
        if r.status_code != 200:
            return out
        data = r.json()
        out["rdap_handle"] = data.get("handle")
        out["rdap_name"]   = data.get("name")
        out["rdap_type"]   = data.get("type")
        out["rdap_country"] = data.get("country")
        # Organization / description
        for ent in (data.get("entities") or [])[:3]:
            roles = ent.get("roles") or []
            vcard = ent.get("vcardArray") or []
            name = None
            try:
                for item in (vcard[1] if len(vcard) > 1 else []):
                    if item[0] == "fn" and len(item) > 3:
                        name = item[3]
                        break
            except Exception:
                pass
            if name:
                for role in roles or ["entity"]:
                    out.setdefault("rdap_entities", []).append({
                        "role": role, "name": name,
                    })
        # Events (registration, last changed)
        for ev in (data.get("events") or [])[:4]:
            action = ev.get("eventAction")
            date   = ev.get("eventDate")
            if action and date:
                out.setdefault("rdap_events", []).append({
                    "action": action, "date": date,
                })
        # Remarks
        for rem in (data.get("remarks") or [])[:2]:
            desc = rem.get("description") or []
            if desc:
                out.setdefault("rdap_remarks", []).extend(desc[:3])
    except Exception as e:
        logger.debug("[ip] RDAP lookup failed for %s: %s", ip, e)
    return out


# ── WHOIS raw port 43 (no HTTP API) ───────────────────────────────────────
_WHOIS_SERVERS = {
    "arin":   "whois.arin.net",
    "ripe":   "whois.ripe.net",
    "apnic":  "whois.apnic.net",
    "lacnic": "whois.lacnic.net",
    "afrinic": "whois.afrinic.net",
}


def _whois_raw(ip: str, timeout: float = WHOIS_TIMEOUT) -> Dict[str, Any]:
    """
    Query WHOIS on TCP port 43 directly. Tries IANA referral first,
    then falls back to well-known RIR servers.
    """
    out: Dict[str, Any] = {}

    def _query(server: str, query: str) -> Optional[str]:
        try:
            with socket.create_connection((server, 43), timeout=timeout) as s:
                s.sendall((query + "\r\n").encode("utf-8"))
                chunks = []
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                    if sum(len(c) for c in chunks) > 65536:
                        break
                return b"".join(chunks).decode("utf-8", errors="ignore")
        except Exception as e:
            logger.debug("[ip] whois %s failed: %s", server, e)
            return None

    text = _query("whois.iana.org", ip)
    server = None
    if text:
        m = re.search(r"^refer:\s+(\S+)", text, re.M | re.I)
        if m:
            server = m.group(1).strip()

    if not server:
        # Try each RIR until one responds with "NetRange" or "inetnum"
        for name, srv in _WHOIS_SERVERS.items():
            text = _query(srv, ip)
            if text and re.search(r"(NetRange|inetnum|inet6num|CIDR)", text, re.I):
                server = srv
                break

    if text:
        out["whois_server"] = server
        # Extract a few useful fields (informational)
        for field_name, pattern in (
            ("whois_netname",    r"^\s*NetName:\s*(.+)$"),
            ("whois_orgname",    r"^\s*OrgName:\s*(.+)$"),
            ("whois_country",    r"^\s*Country:\s*(.+)$"),
            ("whois_cidr",       r"^\s*CIDR:\s*(.+)$"),
            ("whois_netrange",   r"^\s*NetRange:\s*(.+)$"),
            ("whois_descr",      r"^\s*descr:\s*(.+)$"),
            ("whois_org",        r"^\s*org:\s*(.+)$"),
        ):
            m = re.search(pattern, text, re.M | re.I)
            if m:
                out[field_name] = m.group(1).strip()[:200]
        out["whois_raw_length"] = len(text)
    return out


# ── DNSBL / RBL blacklist checks ──────────────────────────────────────────
def _dnsbl_check(ip: str, zones: Optional[Dict[str, str]] = None,
                 timeout: float = DNSBL_TIMEOUT) -> Dict[str, Any]:
    """Check IPv4 IP against public DNSBL zones. IPv6 skipped (not supported widely)."""
    out: Dict[str, Any] = {"listed": False, "results": []}
    if ":" in ip:
        out["skipped"] = "IPv6 not supported by most public DNSBLs"
        return out

    zones = zones or DNSBL_ZONES
    reversed_ip = ".".join(reversed(ip.split(".")))
    for zone, name in zones.items():
        fqdn = f"{reversed_ip}.{zone}"
        try:
            ans = socket.gethostbyname_ex(fqdn)
            if ans and ans[2]:
                # 127.0.0.x response indicates listing; x = reason code
                for addr in ans[2]:
                    if addr.startswith("127."):
                        out["listed"] = True
                        out["results"].append({
                            "zone": zone, "name": name,
                            "response": addr,
                            "reason": ans[0] if ans[0] != fqdn else "",
                        })
                        break
        except socket.gaierror:
            continue
        except Exception:
            continue
    return out


# ── TCP reachability probe ────────────────────────────────────────────────
def _tcp_probe(ip: str, ports: Tuple[int, ...] = (80, 443, 22, 21),
               timeout: float = TCP_PROBE_TIMEOUT) -> Dict[str, Any]:
    """Probe common TCP ports to check reachability. Returns per-port status."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    results: List[Dict[str, Any]] = []
    for port in ports:
        t0 = time.time()
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.close()
            results.append({
                "port": port, "status": "open",
                "latency_ms": int((time.time() - t0) * 1000),
            })
        except socket.timeout:
            results.append({"port": port, "status": "filtered"})
        except (ConnectionRefusedError, ConnectionResetError, OSError):
            results.append({"port": port, "status": "closed"})
        except Exception as e:
            results.append({"port": port, "status": "error", "error": str(e)})
    return {"probes": results,
            "any_open": any(p["status"] == "open" for p in results)}


# ── TLS certificate fetch ─────────────────────────────────────────────────
def _tls_cert(ip: str, port: int = 443,
              timeout: float = TLS_TIMEOUT) -> Optional[Dict[str, Any]]:
    """Fetch TLS certificate from the target (SNI disabled for raw IP)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=None) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "subject":  subject,
                    "issuer":   issuer,
                    "not_before": cert.get("notBefore", ""),
                    "not_after":  cert.get("notAfter", ""),
                    "san": cert.get("subjectAltName", [])[:20],
                    "protocol": ssock.version(),
                    "cipher":   (ssock.cipher() or ("",))[0],
                }
    except Exception as e:
        logger.debug("[ip] TLS cert fetch failed for %s: %s", ip, e)
    return None


# ── TOR exit node list (cached) ───────────────────────────────────────────
_tor_cache: Dict[str, Any] = {"list": None, "ts": 0.0}
_tor_lock = threading.Lock()


def _load_tor_exits(force: bool = False) -> set:
    with _tor_lock:
        now = time.time()
        if (not force and _tor_cache["list"] is not None
                and now - _tor_cache["ts"] < TOR_LIST_TTL):
            return _tor_cache["list"]
        exits = set()
        try:
            r = requests.get(TOR_LIST_URL, timeout=TOR_LIST_TIMEOUT,
                             headers={"User-Agent": _UA_POOL[0]})
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        exits.add(line)
        except Exception as e:
            logger.debug("[ip] Tor exit list fetch failed: %s", e)
        if not exits and _tor_cache["list"]:
            return _tor_cache["list"]
        _tor_cache["list"] = exits
        _tor_cache["ts"] = now
        return exits


def _is_tor_exit(ip: str) -> Optional[bool]:
    exits = _load_tor_exits()
    if not exits:
        return None
    return ip in exits


# ── CDN / hosting detection ───────────────────────────────────────────────
def _detect_cdn(asn: Optional[str], org: Optional[str]) -> Optional[str]:
    if asn and asn.upper() in CDN_ASNS:
        return CDN_ASNS[asn.upper()]
    org_lower = (org or "").lower()
    for name in ("cloudflare", "akamai", "cloudfront", "fastly", "google cloud",
                 "azure", "amazon", "digitalocean", "hetzner", "linode",
                 "ovh", "vultr", "rackspace"):
        if name in org_lower:
            return name.title()
    return None


def _is_hosting(asn: Optional[str]) -> Optional[bool]:
    if not asn:
        return None
    return asn.upper() in HOSTING_ASNS


# ═══════════════════════════════════════════════════════════════════════════
# CLOUDFLARE BYPASS ENGINE
# ═══════════════════════════════════════════════════════════════════════════
_CF_MARKERS = (
    "cf-ray", "cf-cache-status", "cf-request-id", "cf-chl-",
)
_CF_BODY_MARKERS = (
    b"just a moment", b"checking your browser",
    b"cf-browser-verification", b"cf_chl_opt",
    b"__cf_chl_jschl_tk__", b"challenge-platform",
)


def _detect_cloudflare(headers: Dict[str, str], body: bytes,
                       status: int) -> Optional[str]:
    h_lower = {k.lower(): (v or "").lower() for k, v in headers.items()}
    has_cf = ("cloudflare" in h_lower.get("server", "")) or any(
        m in h_lower for m in _CF_MARKERS
    )
    bl = (body or b"")[:8192].lower()
    if any(m in bl for m in _CF_BODY_MARKERS):
        return "js_challenge"
    if status in (403, 429, 503) and has_cf:
        return "challenge"
    return None


class CloudflareBypass:
    """Multi-strategy CF bypass: curl_cffi → cloudscraper → FlareSolverr → manual."""

    def __init__(self, timeout: float = 10.0,
                 cf_timeout: int = 30, verify_tls: bool = True,
                 proxy_dict: Optional[Dict[str, str]] = None,
                 flaresolverr_url: str = FLARESOLVERR_URL):
        self.timeout = timeout
        self.cf_timeout = cf_timeout
        self.verify_tls = verify_tls
        self.proxy_dict = proxy_dict
        self.flaresolverr_url = flaresolverr_url
        self._cloudscraper = None
        self._curl_cffi = None

    def _curl_cffi(self):
        if not _HAS_CURL_CFFI:
            return None
        if self._curl_cffi is None:
            try:
                self._curl_cffi = curl_requests.Session()
            except Exception as exc:
                logger.debug("[ip/cf] curl_cffi init failed: %s", exc)
                return None
        return self._curl_cffi

    def _fetch_curl_cffi(self, url: str) -> Optional[Tuple[bytes, Dict, int]]:
        s = self._curl_cffi()
        if s is None:
            return None
        try:
            r = s.get(url, impersonate="chrome", timeout=self.timeout,
                      verify=self.verify_tls, proxies=self.proxy_dict,
                      allow_redirects=True,
                      headers={"User-Agent": _UA_POOL[0]})
            return r.content or b"", dict(r.headers), r.status_code
        except Exception as exc:
            logger.debug("[ip/cf] curl_cffi failed: %s", exc)
            return None

    def _cloudscraper(self):
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
                logger.debug("[ip/cf] cloudscraper init failed: %s", exc)
                return None
        return self._cloudscraper

    def _fetch_cloudscraper(self, url: str) -> Optional[Tuple[bytes, Dict, int]]:
        c = self._cloudscraper()
        if c is None:
            return None
        try:
            r = c.get(url, timeout=self.cf_timeout, verify=self.verify_tls,
                      allow_redirects=True)
            return r.content or b"", dict(r.headers), r.status_code
        except Exception as exc:
            logger.debug("[ip/cf] cloudscraper failed: %s", exc)
            return None

    def _fetch_flaresolverr(self, url: str) -> Optional[Tuple[bytes, Dict, int]]:
        if not self.flaresolverr_url:
            return None
        try:
            payload = {"cmd": "request.get", "url": url,
                       "maxTimeout": self.cf_timeout * 1000}
            r = requests.post(self.flaresolverr_url.rstrip("/") + "/v1",
                              json=payload, timeout=self.cf_timeout + 10)
            if r.status_code != 200:
                return None
            data = r.json()
            if data.get("status") != "ok":
                return None
            sol = data.get("solution") or {}
            return ((sol.get("response") or "").encode("utf-8", "ignore"),
                    sol.get("headers") or {},
                    int(sol.get("status") or 0))
        except Exception as exc:
            logger.debug("[ip/cf] flaresolverr failed: %s", exc)
            return None

    def _fetch_manual(self, url: str) -> Optional[Tuple[bytes, Dict, int]]:
        try:
            import random
            r = requests.get(url, timeout=self.timeout, verify=self.verify_tls,
                             proxies=self.proxy_dict, allow_redirects=True,
                             headers={"User-Agent": random.choice(_UA_POOL)})
            return r.content or b"", dict(r.headers), r.status_code
        except Exception as exc:
            logger.debug("[ip/cf] manual failed: %s", exc)
            return None

    def get_json(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch JSON via bypass chain. Returns parsed dict or None."""
        strategies: List[Tuple[str, Callable]] = []
        if _HAS_CURL_CFFI:
            strategies.append(("curl_cffi", self._fetch_curl_cffi))
        if _HAS_CLOUDSCRAPER:
            strategies.append(("cloudscraper", self._fetch_cloudscraper))
        if self.flaresolverr_url:
            strategies.append(("flaresolverr", self._fetch_flaresolverr))
        strategies.append(("manual", self._fetch_manual))

        for name, fn in strategies:
            result = fn(url)
            if result is None:
                continue
            body, headers, status = result
            if status >= 400:
                continue
            cf_type = _detect_cloudflare(headers, body, status)
            if cf_type:
                logger.debug("[ip/cf] %s CF %s via %s", url, cf_type, name)
                continue
            try:
                return _json.loads(body)
            except Exception:
                continue
        return None


# ═══════════════════════════════════════════════════════════════════════════
# GEO PROVIDERS
# ═══════════════════════════════════════════════════════════════════════════
class GeoProvider:
    name = "base"
    supports_ipv6 = False
    weight = 0.5

    def lookup(self, ip: str, cf: Optional[CloudflareBypass],
               session: Optional[requests.Session]) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


class IPWhoIsProvider(GeoProvider):
    name = "ipwho.is"
    supports_ipv6 = True
    weight = PROVIDER_WEIGHTS["ipwho.is"]

    def lookup(self, ip, cf, session):
        try:
            r = (session or requests).get(f"https://ipwho.is/{ip}", timeout=8,
                                          headers={"User-Agent": _UA_POOL[0]})
            data = r.json()
            if not data.get("success", False):
                return None
            tz = data.get("timezone") or {}
            conn = data.get("connection") or {}
            return {
                "ip": ip,
                "country": data.get("country"),
                "country_code": data.get("country_code"),
                "region": data.get("region"),
                "city": data.get("city"),
                "postal": data.get("postal"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "timezone": tz.get("id") if isinstance(tz, dict) else tz,
                "utc_offset": tz.get("utc_offset") if isinstance(tz, dict) else None,
                "isp": conn.get("isp"),
                "org": conn.get("org"),
                "asn": conn.get("asn"),
                "asn_name": conn.get("asn_name"),
                "domain": conn.get("domain"),
                "type": data.get("type"),
                "provider": self.name,
                "_provider_weight": self.weight,
            }
        except Exception as e:
            logger.debug("[ip] ipwho.is failed: %s", e)
            return None


class IPApiProvider(GeoProvider):
    name = "ip-api.com"
    supports_ipv6 = False
    weight = PROVIDER_WEIGHTS["ip-api.com"]

    def lookup(self, ip, cf, session):
        for scheme in ("https", "http"):
            try:
                r = requests.get(
                    f"{scheme}://ip-api.com/json/{ip}",
                    params={"fields": "status,message,country,countryCode,"
                                      "region,regionName,city,zip,lat,lon,"
                                      "timezone,isp,org,as,asname,reverse,"
                                      "mobile,proxy,hosting,query"},
                    timeout=6,
                    headers={"User-Agent": _UA_POOL[0]},
                )
                data = r.json()
                if data.get("status") == "success":
                    return {
                        "ip": ip,
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "postal": data.get("zip"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "timezone": data.get("timezone"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("as"),
                        "asn_name": data.get("asname"),
                        "domain": data.get("reverse"),
                        "is_proxy": data.get("proxy"),
                        "is_hosting": data.get("hosting"),
                        "is_mobile": data.get("mobile"),
                        "provider": self.name,
                        "_provider_weight": self.weight,
                    }
                break
            except Exception:
                continue
        return None


class IPApiCoProvider(GeoProvider):
    name = "ipapi.co"
    supports_ipv6 = True
    weight = PROVIDER_WEIGHTS["ipapi.co"]

    def lookup(self, ip, cf, session):
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8,
                             headers={"User-Agent": _UA_POOL[0]})
            data = r.json()
            if data.get("error"):
                return None
            return {
                "ip": ip,
                "country": data.get("country_name"),
                "country_code": data.get("country_code"),
                "region": data.get("region"),
                "city": data.get("city"),
                "postal": data.get("postal"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "timezone": data.get("timezone"),
                "utc_offset": data.get("utc_offset"),
                "isp": data.get("org"),
                "org": data.get("org"),
                "asn": data.get("asn"),
                "domain": data.get("hostname"),
                "type": data.get("org_type"),
                "provider": self.name,
                "_provider_weight": self.weight,
            }
        except Exception:
            return None


class IPInfoIOProvider(GeoProvider):
    name = "ipinfo.io"
    supports_ipv6 = True
    weight = PROVIDER_WEIGHTS["ipinfo.io"]

    def __init__(self, token: Optional[str] = None):
        self.token = token

    def lookup(self, ip, cf, session):
        headers = {"User-Agent": _UA_POOL[0]}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers,
                             timeout=8)
            data = r.json()
            if "ip" not in data:
                return None
            asn = asn_name = None
            org = data.get("org", "")
            if org.startswith("AS"):
                parts = org.split(" ", 1)
                asn = parts[0]
                asn_name = parts[1] if len(parts) > 1 else None
            lat = lon = None
            if data.get("loc"):
                try:
                    lat, lon = map(float, data["loc"].split(","))
                except Exception:
                    pass
            return {
                "ip": ip,
                "country": data.get("country"),
                "country_code": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "postal": data.get("postal"),
                "latitude": lat,
                "longitude": lon,
                "timezone": data.get("timezone"),
                "isp": org,
                "org": org,
                "asn": asn,
                "asn_name": asn_name,
                "domain": data.get("hostname"),
                "is_hosting": bool(data.get("hosting")),
                "provider": self.name,
                "_provider_weight": self.weight,
            }
        except Exception:
            return None


class IPApiIsProvider(GeoProvider):
    """ipapi.is — free tier, no key required for basic lookups."""
    name = "ipapi.is"
    supports_ipv6 = True
    weight = PROVIDER_WEIGHTS["ipapi.is"]

    def lookup(self, ip, cf, session):
        try:
            url = f"https://api.ipapi.is/?q={ip}"
            data = None
            if cf is not None:
                data = cf.get_json(url)
            if data is None:
                r = requests.get(url, timeout=8,
                                 headers={"User-Agent": _UA_POOL[0]})
                data = r.json()
            if not data or "ip" not in data:
                return None
            loc = data.get("location") or {}
            asn = data.get("asn") or {}
            company = data.get("company") or {}
            return {
                "ip": ip,
                "country": loc.get("country"),
                "country_code": loc.get("country_code"),
                "region": loc.get("state"),
                "city": loc.get("city"),
                "postal": loc.get("zip"),
                "latitude": loc.get("latitude"),
                "longitude": loc.get("longitude"),
                "timezone": loc.get("timezone"),
                "isp": asn.get("org"),
                "org": company.get("name") or asn.get("org"),
                "asn": f"AS{asn.get('asn')}" if asn.get("asn") else None,
                "asn_name": asn.get("org"),
                "asn_route": asn.get("route"),
                "asn_country": asn.get("country"),
                "asn_registry": asn.get("registry"),
                "type": data.get("type"),
                "is_proxy": data.get("is_proxy"),
                "is_hosting": data.get("is_datacenter"),
                "is_mobile": data.get("is_mobile"),
                "is_abuse": data.get("is_abuser"),
                "provider": self.name,
                "_provider_weight": self.weight,
            }
        except Exception:
            return None


class FreeIPAPIProvider(GeoProvider):
    """freeipapi.com — free, no key, IPv4+IPv6."""
    name = "freeipapi.com"
    supports_ipv6 = True
    weight = PROVIDER_WEIGHTS["freeipapi.com"]

    def lookup(self, ip, cf, session):
        try:
            r = requests.get(f"https://freeipapi.com/api/json/{ip}",
                             timeout=8,
                             headers={"User-Agent": _UA_POOL[0]})
            data = r.json()
            if not data or "ipAddress" not in data:
                return None
            return {
                "ip": ip,
                "country": data.get("countryName"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("cityName"),
                "postal": data.get("zipCode"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "timezone": data.get("timeZones", [None])[0] if isinstance(
                    data.get("timeZones"), list) else data.get("timeZone"),
                "provider": self.name,
                "_provider_weight": self.weight,
            }
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════════
# MAIN LOOKUP CLASS
# ═══════════════════════════════════════════════════════════════════════════
class IPInfoLookup:
    """
    Enterprise IP & ASN intelligence scanner.

    Args:
        providers:        list of GeoProvider instances
        include_ipinfo:   add ipinfo.io as fallback
        ipinfo_token:     optional ipinfo.io token
        cache_ttl:        TTL cache in seconds
        timeout:          HTTP timeout
        include_rdns:     perform reverse DNS
        include_asn:      perform Team Cymru ASN lookup
        include_local:    perform local analysis (RDAP, WHOIS, DNSBL, TCP, TLS)
        include_threat:   check TOR exit nodes + CDN / hosting flags
        use_cf_bypass:    use Cloudflare bypass engine
        offline:          skip all external API providers
    """

    def __init__(
        self,
        providers: Optional[List[GeoProvider]] = None,
        include_ipinfo: bool = True,
        ipinfo_token: Optional[str] = None,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        timeout: float = DEFAULT_TIMEOUT,
        include_rdns: bool = True,
        include_asn: bool = True,
        include_local: bool = True,
        include_threat: bool = True,
        use_cf_bypass: bool = True,
        offline: bool = False,
        rate_limit: float = DEFAULT_RATE_LIMIT,
    ):
        self.providers: List[GeoProvider] = providers or [
            IPInfoIOProvider(token=ipinfo_token) if include_ipinfo else None,
            IPApiIsProvider(),
            IPWhoIsProvider(),
            IPApiCoProvider(),
            IPApiProvider(),
            FreeIPAPIProvider(),
        ]
        self.providers = [p for p in self.providers if p is not None]

        self.cache = TTLCache(ttl_seconds=cache_ttl)
        self.timeout = timeout
        self.include_rdns = include_rdns
        self.include_asn = include_asn
        self.include_local = include_local
        self.include_threat = include_threat
        self.use_cf_bypass = use_cf_bypass
        self.offline = offline
        self._bucket = _TokenBucket(rate_limit, burst=4)

        self._cf = CloudflareBypass(timeout=timeout, verify_tls=True) \
            if (use_cf_bypass and not offline) else None

        self._session = requests.Session()
        try:
            adapter = HTTPAdapter(
                pool_connections=16, pool_maxsize=32,
                max_retries=Retry(total=2, backoff_factor=0.5,
                                  status_forcelist=(429, 502, 503, 504),
                                  allowed_methods=frozenset(["GET"]),
                                  raise_on_status=False),
            )
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)
        except Exception:
            pass

    # ── helpers ────────────────────────────────────────────────────────
    def _resolve_host(self, target: str) -> Optional[str]:
        try:
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    infos = socket.getaddrinfo(target, None, family)
                    if infos:
                        return infos[0][4][0]
                except socket.gaierror:
                    continue
        except Exception as e:
            logger.debug("[ip] resolve failed: %s", e)
        return None

    @staticmethod
    def _is_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _merge_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge provider results using weight-based priority per field."""
        merged: Dict[str, Any] = {}
        field_weight: Dict[str, float] = {}
        providers_used: List[str] = []
        for result in results:
            if not result:
                continue
            weight = float(result.get("_provider_weight", 0.5))
            name = result.get("provider", "unknown")
            if name not in providers_used:
                providers_used.append(name)
            for key, value in result.items():
                if key.startswith("_") or value is None:
                    continue
                prev_w = field_weight.get(key, -1.0)
                if weight > prev_w:
                    merged[key] = value
                    field_weight[key] = weight
        if providers_used:
            merged["providers_used"] = providers_used
            merged["confidence"] = round(
                min(1.0, sum(PROVIDER_WEIGHTS.get(p, 0.5)
                             for p in providers_used) / max(1, len(providers_used))), 2
            )
        return merged

    # ── local intelligence ────────────────────────────────────────────
    def _local_intel(self, ip: str) -> Dict[str, Any]:
        local: Dict[str, Any] = {}
        local.update(_classify_ip(ip) or {})
        if self.include_rdns:
            rdns = _reverse_dns(ip, timeout=5.0)
            if rdns:
                local["reverse_dns"] = rdns
                local["forward_confirmed"] = _forward_confirm(rdns, ip)
        return local

    def _deep_intel(self, ip: str, asn: Optional[str]) -> Dict[str, Any]:
        """RDAP + WHOIS + DNSBL + TCP + TLS (only in local/deep mode)."""
        deep: Dict[str, Any] = {}

        # RDAP
        try:
            rdap = _rdap_lookup(ip, timeout=RDAP_TIMEOUT)
            if rdap:
                deep["rdap"] = rdap
        except Exception:
            pass

        # WHOIS
        try:
            whois_data = _whois_raw(ip, timeout=WHOIS_TIMEOUT)
            if whois_data:
                deep["whois"] = whois_data
        except Exception:
            pass

        # DNSBL
        if self.include_threat:
            try:
                dnsbl = _dnsbl_check(ip, timeout=DNSBL_TIMEOUT)
                if dnsbl.get("results") or dnsbl.get("skipped"):
                    deep["dnsbl"] = dnsbl
                if dnsbl.get("listed"):
                    deep["is_abuse"] = True
            except Exception:
                pass

        # TCP probe (common ports)
        if self.include_local:
            try:
                tcp = _tcp_probe(ip, ports=(80, 443, 22, 21),
                                 timeout=TCP_PROBE_TIMEOUT)
                deep["tcp"] = tcp
            except Exception:
                pass

            # TLS cert (only if 443 open)
            if deep.get("tcp", {}).get("any_open"):
                tls = _tls_cert(ip, port=443, timeout=TLS_TIMEOUT)
                if tls:
                    deep["tls"] = tls

        return deep

    def _threat_flags(self, ip: str, asn: Optional[str],
                      org: Optional[str]) -> Dict[str, Any]:
        flags: Dict[str, Any] = {}
        if self.include_threat:
            # Tor exit
            try:
                tor = _is_tor_exit(ip)
                if tor is not None:
                    flags["is_tor"] = tor
            except Exception:
                pass
            # CDN
            cdn = _detect_cdn(asn, org)
            if cdn:
                flags["cdn"] = cdn
            # Hosting
            hosting = _is_hosting(asn)
            if hosting is not None:
                flags["is_hosting"] = hosting
        return flags

    # ── lookup pipeline ───────────────────────────────────────────────
    def lookup(self, target: str) -> Tuple[Dict[str, Any], Optional[str]]:
        # 1. Resolve to IP
        ip = target if self._is_ip(target) else self._resolve_host(target)
        if not ip:
            return {}, f"Cannot resolve host: {target}"

        # 2. Cache
        cached = self.cache.get(ip)
        if cached:
            logger.info("[ip] cache hit for %s", ip)
            return cached, None

        # 3. Local classification (always)
        merged = self._local_intel(ip)
        merged["ip"] = ip

        # 4. Team Cymru ASN (offline-capable — DNS TXT only)
        if self.include_asn:
            try:
                asn_info = _team_cymru_asn(ip)
                for k, v in (asn_info or {}).items():
                    merged.setdefault(k, v)
            except Exception as e:
                logger.debug("[ip] Team Cymru failed: %s", e)

        # 5. API providers (skip in offline mode)
        provider_results: List[Dict[str, Any]] = []
        if not self.offline and self.providers:
            def _query(p: GeoProvider):
                self._bucket.acquire()
                try:
                    return p.lookup(ip, self._cf, self._session)
                except Exception as e:
                    logger.debug("[ip] provider %s failed: %s", p.name, e)
                    return None

            workers = min(len(self.providers), DEFAULT_WORKERS)
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = [ex.submit(_query, p) for p in self.providers]
                for fut in as_completed(futures):
                    try:
                        r = fut.result()
                        if r:
                            provider_results.append(r)
                    except Exception:
                        pass

            provider_merged = self._merge_results(provider_results)
            for k, v in provider_merged.items():
                if k in ("providers_used", "confidence"):
                    merged[k] = v
                else:
                    merged.setdefault(k, v)

        # 6. Deep intelligence (RDAP / WHOIS / DNSBL / TCP / TLS)
        if self.include_local:
            try:
                deep = self._deep_intel(ip, merged.get("asn"))
                for k, v in (deep or {}).items():
                    if k not in merged:
                        merged[k] = v
            except Exception as e:
                logger.debug("[ip] deep intel failed: %s", e)

        # 7. Threat flags (Tor / CDN / hosting)
        flags = self._threat_flags(ip, merged.get("asn"), merged.get("org"))
        for k, v in flags.items():
            if v is not None:
                merged.setdefault(k, v)

        # 8. Provider field for top-line reporting
        if provider_results:
            top = max(provider_results,
                      key=lambda r: r.get("_provider_weight", 0.0))
            merged["provider"] = top.get("provider")

        # 9. Strip internal keys
        clean = {k: v for k, v in merged.items() if not k.startswith("_")}

        # 10. Cache + return
        self.cache.set(ip, clean)
        return clean, None

    # ── orchestrator-compatible entry point ───────────────────────────
    def run(self, target: str, mode: str = "basic") -> Dict[str, Any]:
        start = time.time()
        data, error = self.lookup(target)
        elapsed = time.time() - start

        meta = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 3),
            "mode": mode,
            "offline": self.offline,
            "providers_tried": [p.name for p in self.providers],
            "cf_bypass": {
                "enabled": self._cf is not None,
                "curl_cffi": _HAS_CURL_CFFI,
                "cloudscraper": _HAS_CLOUDSCRAPER,
                "flaresolverr": bool(FLARESOLVERR_URL),
            },
            "resolved_ip": data.get("ip") if data else None,
        }

        return {
            "tool": "ip_info",
            "version": __version__,
            "target": target,
            "data": data,
            "error": error,
            "metadata": meta,
        }


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT (orchestrator compatible)
# ═══════════════════════════════════════════════════════════════════════════
def run(target: str, mode: str = "basic", **kwargs) -> Dict[str, Any]:
    """
    Scan an IP or hostname.

    kwargs:
        cache_ttl (int)      — cache TTL in seconds
        include_rdns (bool)
        include_asn (bool)
        include_local (bool) — RDAP / WHOIS / DNSBL / TCP / TLS
        include_threat (bool)— Tor / CDN / hosting flags
        use_cf_bypass (bool) — enable Cloudflare bypass
        offline (bool)       — skip external APIs
        ipinfo_token (str)
        timeout (float)
        rate_limit (float)
    """
    scanner = IPInfoLookup(
        cache_ttl=int(kwargs.get("cache_ttl", DEFAULT_CACHE_TTL)),
        timeout=float(kwargs.get("timeout", DEFAULT_TIMEOUT)),
        include_rdns=bool(kwargs.get("include_rdns", True)),
        include_asn=bool(kwargs.get("include_asn", True)),
        include_local=bool(kwargs.get("include_local", mode == "expert")),
        include_threat=bool(kwargs.get("include_threat", True)),
        use_cf_bypass=bool(kwargs.get("use_cf_bypass", True)),
        offline=bool(kwargs.get("offline", False)),
        ipinfo_token=kwargs.get("ipinfo_token"),
        rate_limit=float(kwargs.get("rate_limit", DEFAULT_RATE_LIMIT)),
    )
    return scanner.run(target, mode)


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
    yield {"type": "stage", "stage": "resolving"}
    try:
        result = run(
            target,
            mode=str(options.get("mode", "basic")),
            cache_ttl=int(options.get("cache_ttl", DEFAULT_CACHE_TTL)),
            timeout=float(options.get("timeout", DEFAULT_TIMEOUT)),
            include_local=bool(options.get("include_local", True)),
            include_threat=bool(options.get("include_threat", True)),
            use_cf_bypass=bool(options.get("use_cf_bypass", True)),
            offline=bool(options.get("offline", False)),
            ipinfo_token=options.get("ipinfo_token"),
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
    workers: int = DEFAULT_WORKERS,
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
            except Exception:
                pass
        return idx, r

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = {ex.submit(_one, i, t): i for i, t in enumerate(targets)}
        for fut in as_completed(futures):
            try:
                idx, r = fut.result()
                results[idx] = r
            except Exception as e:
                logger.warning("[ip] batch worker error: %s", e)
    return [r for r in results if r is not None]


# ═══════════════════════════════════════════════════════════════════════════
# SARIF EXPORT
# ═══════════════════════════════════════════════════════════════════════════
def to_sarif(result: Dict[str, Any]) -> Dict[str, Any]:
    d = result.get("data", {}) or {}
    findings = []
    if d.get("is_tor"):
        findings.append({
            "ruleId": "ip/tor-exit",
            "level": "warning",
            "message": {"text": "IP is a known TOR exit node"},
        })
    if d.get("is_abuse"):
        findings.append({
            "ruleId": "ip/abuse-listed",
            "level": "error",
            "message": {"text": "IP is listed in a DNSBL blacklist"},
        })
    if d.get("dnsbl", {}).get("listed"):
        findings.append({
            "ruleId": "ip/dnsbl",
            "level": "error",
            "message": {"text": "IP appears on one or more DNSBL zones"},
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Oxysintx IP & ASN Info",
                "version": __version__,
            }},
            "results": findings,
        }],
    }


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def _colored(text: str, color: str = "") -> str:
    colors = {
        "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
        "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
        "white": "\033[97m", "dim": "\033[2m", "reset": "\033[0m",
    }
    if not color or not os.isatty(1):
        return text
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def _print_human(result: Dict[str, Any]) -> None:
    if result.get("error"):
        print(_colored(f"\n[FAIL] {result['target']}: {result['error']}", "red"))
        return

    d = result["data"]
    meta = result.get("metadata", {})

    print(_colored(f"\n═══ IP & ASN Intelligence: {result['target']} ═══\n", "cyan"))

    # ── Network core ────────────────────────────────────────────────
    print(_colored("Network", "yellow"))
    print(f"  IP           : {d.get('ip')}")
    if d.get("reverse_dns"):
        fc = " (forward-confirmed)" if d.get("forward_confirmed") else ""
        print(f"  Reverse DNS  : {d['reverse_dns']}{fc}")
    if d.get("ip_version") is not None:
        v = f"IPv{d['ip_version']}  ({d.get('ip_scope', 'unknown')})"
        print(f"  Version      : {v}")
    if d.get("asn"):
        print(f"  ASN          : {d['asn']}")
    if d.get("asn_name"):
        print(f"  ASN Name     : {d['asn_name']}")
    if d.get("asn_route"):
        print(f"  Route        : {d['asn_route']}")
    if d.get("asn_country"):
        print(f"  ASN Country  : {d['asn_country']}")
    if d.get("bgp_prefix"):
        print(f"  BGP Prefix   : {d['bgp_prefix']}")
    if d.get("asn_registry"):
        print(f"  Registry     : {d['asn_registry']}")
    if d.get("provider"):
        print(f"  Data Source  : {d['provider']}")
    if d.get("confidence"):
        print(f"  Confidence   : {d['confidence']}")

    # ── Geo ─────────────────────────────────────────────────────────
    if d.get("country") or d.get("city"):
        print(_colored("\nGeolocation", "yellow"))
        loc = ", ".join(filter(None, [d.get("city"), d.get("region"),
                                       d.get("postal"), d.get("country")]))
        if loc:
            print(f"  Location     : {loc}")
        if d.get("latitude") is not None and d.get("longitude") is not None:
            print(f"  Coordinates  : {d['latitude']}, {d['longitude']}")
        if d.get("timezone"):
            print(f"  Timezone     : {d['timezone']}")

    # ── ISP / Org ───────────────────────────────────────────────────
    if d.get("isp") or d.get("org"):
        print(_colored("\nISP / Organisation", "yellow"))
        if d.get("isp"): print(f"  ISP          : {d['isp']}")
        if d.get("org"): print(f"  Organisation : {d['org']}")
        if d.get("domain"): print(f"  Domain       : {d['domain']}")
        if d.get("type"):   print(f"  Type         : {d['type']}")

    # ── Security flags ──────────────────────────────────────────────
    sec_keys = ["is_proxy", "is_hosting", "is_mobile", "is_tor", "is_vpn",
                "is_abuse", "cdn"]
    sec_present = {k: d.get(k) for k in sec_keys if d.get(k) is not None}
    if sec_present:
        print(_colored("\nSecurity Flags", "yellow"))
        for k, v in sec_present.items():
            label = k.replace("is_", "").replace("_", " ").title()
            color = "red" if v in (True, "true") else "green"
            print(f"  {label:<13}: " + _colored(str(v), color))

    # ── DNSBL ───────────────────────────────────────────────────────
    if d.get("dnsbl"):
        bl = d["dnsbl"]
        print(_colored("\nDNSBL / RBL", "yellow"))
        if bl.get("skipped"):
            print(f"  {bl['skipped']}")
        elif bl.get("listed"):
            print(_colored(f"  ⚠ LISTED on {len(bl['results'])} zone(s):", "red"))
            for r in bl["results"]:
                print(f"    - {r['zone']} ({r['name']})")
        else:
            print(_colored("  ✓ Not listed on any checked zone", "green"))

    # ── RDAP / WHOIS ────────────────────────────────────────────────
    if d.get("rdap"):
        rdap = d["rdap"]
        print(_colored("\nRDAP", "yellow"))
        for k, label in (("rdap_handle", "Handle"), ("rdap_name", "Name"),
                         ("rdap_type", "Type"), ("rdap_country", "Country")):
            if rdap.get(k):
                print(f"  {label:<13}: {rdap[k]}")
        for ev in rdap.get("rdap_events", []):
            print(f"  {ev['action']:<13}: {ev['date']}")

    if d.get("whois"):
        w = d["whois"]
        print(_colored("\nWHOIS", "yellow"))
        for k, label in (("whois_server", "Server"),
                         ("whois_netname", "Netname"),
                         ("whois_orgname", "Org"),
                         ("whois_org", "Org Handle"),
                         ("whois_country", "Country"),
                         ("whois_cidr", "CIDR"),
                         ("whois_netrange", "NetRange"),
                         ("whois_descr", "Descr")):
            if w.get(k):
                print(f"  {label:<13}: {w[k]}")

    # ── TCP / TLS ───────────────────────────────────────────────────
    if d.get("tcp"):
        print(_colored("\nTCP Reachability", "yellow"))
        for p in d["tcp"].get("probes", []):
            status_color = {"open": "green", "closed": "red",
                            "filtered": "yellow"}.get(p["status"], "dim")
            lat = f" ({p['latency_ms']}ms)" if "latency_ms" in p else ""
            print(f"  Port {p['port']:<5} : " +
                  _colored(p["status"].upper() + lat, status_color))

    if d.get("tls"):
        tls = d["tls"]
        print(_colored("\nTLS Certificate", "yellow"))
        subj = tls.get("subject", {}).get("commonName", "-")
        iss = tls.get("issuer", {}).get("organizationName", "-")
        print(f"  Subject      : {subj}")
        print(f"  Issuer       : {iss}")
        if tls.get("protocol"):
            print(f"  Protocol     : {tls['protocol']}")
        if tls.get("not_after"):
            print(f"  Expires      : {tls['not_after']}")

    # ── Metadata ────────────────────────────────────────────────────
    print(_colored("\nMetadata", "yellow"))
    for k in ("timestamp", "elapsed_seconds", "mode", "offline",
              "resolved_ip", "providers_tried"):
        if k in meta:
            v = meta[k]
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            print(f"  {k:<15}: {v}")


def _main() -> int:
    parser = argparse.ArgumentParser(
        description=f"Oxysintx IP & ASN Intelligence v{__version__}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("targets", nargs="+",
                        help="IP addresses or hostnames (one or more)")
    parser.add_argument("--mode", choices=["basic", "expert"], default="basic")
    parser.add_argument("--offline", action="store_true",
                        help="Skip all external HTTP APIs — use local "
                             "intelligence only (Team Cymru, RDAP, WHOIS, DNSBL)")
    parser.add_argument("--no-local", action="store_true",
                        help="Skip local deep intel (RDAP/WHOIS/DNSBL/TCP/TLS)")
    parser.add_argument("--no-threat", action="store_true",
                        help="Skip Tor / CDN / hosting flag detection")
    parser.add_argument("--no-rdns", action="store_true",
                        help="Disable reverse DNS")
    parser.add_argument("--no-asn", action="store_true",
                        help="Disable Team Cymru ASN lookup")
    parser.add_argument("--no-cf-bypass", action="store_true",
                        help="Disable Cloudflare bypass")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--cache-ttl", type=int, default=DEFAULT_CACHE_TTL)
    parser.add_argument("--ipinfo-token", help="Optional ipinfo.io token")
    parser.add_argument("--json", action="store_true", help="Raw JSON output")
    parser.add_argument("--sarif", action="store_true",
                        help="SARIF output (single target only)")
    parser.add_argument("--output", help="Write JSON to file")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    results = scan_many(
        args.targets,
        mode=args.mode,
        workers=args.workers,
        cache_ttl=args.cache_ttl,
        timeout=args.timeout,
        include_rdns=not args.no_rdns,
        include_asn=not args.no_asn,
        include_local=not args.no_local and args.mode == "expert" or not args.no_local,
        include_threat=not args.no_threat,
        use_cf_bypass=not args.no_cf_bypass,
        offline=args.offline,
        ipinfo_token=args.ipinfo_token,
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