#!/usr/bin/env python3
"""
SSL/TLS Certificate Inspector — comprehensive & production-ready (v3.1.0)
=========================================================================

Reads exactly what any browser padlock shows, plus deeper fields in expert
mode. Drop-in compatible with the Emergens orchestrator: exposes
`run(target, mode)` for synchronous calls, `run_streaming(...)` for SSE,
a Flask blueprint mounted at `/api/ssl/scan`, and `self_check()` runtime
diagnostics.

Detection coverage
------------------
  • Custom port, split connect + handshake timeouts
  • Granular exception handling: DNS, TCP, TLS, cert-chain, cert-parse
  • Full certificate chain extraction (Python 3.10+ native; falls back
    to leaf-only on older runtimes)
  • Chain validation — issuer / subject linkage, self-signed detection,
    known-CA registry, expired intermediates, CA basic-constraints
  • OCSP stapling detection (True / False / None)
  • Public-key introspection (RSA / DSA / EC / Ed25519 / Ed448) via
    `cryptography`, with graceful fallback to stdlib
  • SHA-256 / SHA-1 / SHA-512 fingerprints of every cert in the chain
  • Subject Alternative Names (DNS, IP, email, URI)
  • Key usage, extended key usage, certificate policies, AIA, CRL DP
  • Weak protocol / weak cipher detection with proper classification
  • Days-until-expiry countdown, expiring-soon flag, expired flag
  • Bulk `scan_many()` with ThreadPoolExecutor
  • Streaming generator mirroring the app.py SSE envelope
  • Isolated logger — never duplicates Flask / root handlers
  • `run()` never raises — all errors returned in `result["error"]`
  • Flask Blueprint: POST|GET /api/ssl/scan
  • Module aliases: ssl_check, scan_ssl, check_ssl, scan_ssl_check

----------------------------------------------------------------------------
Changelog v3.1.0  (Emergens integration + hardening)
----------------------------------------------------------------------------
  ✔ FIXED  — `_extract_chain_der()` now correctly uses
             `ssl.Certificate.public_bytes(ssl.ENCODING_DER)` (Python 3.10+)
             instead of the broken `__import__("cryptography").hazmat...`
             chain that raised at runtime.
  ✔ NEW    — Flask Blueprint `ssl_bp` exposing
             `POST|GET /api/ssl/scan` so terminal.py's
             `_client.post("/api/ssl/scan", ...)` works out-of-the-box.
  ✔ NEW    — `register_blueprint(app)` helper for app.py wiring.
  ✔ NEW    — Aliases `ssl_check`, `scan_ssl`, `check_ssl`, `scan_ssl_check`.
  ✔ NEW    — `self_check()` runtime diagnostic + CLI `--self-check`.
  ✔ HARD   — Chain extraction honours `max_chain_depth` at source, skips
             unparsable certs, never raises on exotic runtimes.
  ✔ HARD   — OCSP stapling gracefully degrades on stripped Python builds.
  ✔ HARD   — Response envelope always guarantees `data.subject` and
             `data.issuer` are dicts so renderers never see KeyError.

----------------------------------------------------------------------------
Acknowledgment
----------------------------------------------------------------------------
  • Author        : Yanxzyx  (#credit ~ Yanxzyx)
  • Framework     : Emergens / Oxysintx orchestrator stack
  • Dependencies  : stdlib `ssl` (3.10+ chain APIs) + optional
                    `cryptography` for deep X.509 introspection,
                    `Flask` for the /api/ssl/scan endpoint
  • References    : RFC 5280 (X.509), RFC 6960 (OCSP), RFC 8446 (TLS 1.3),
                    RFC 6797 (HSTS)
  • With thanks to the CPython `ssl` maintainers for exposing
    `get_unverified_chain()` and the `cryptography` team for
    a sane X.509 object model.

----------------------------------------------------------------------------
Testing
----------------------------------------------------------------------------
  Quick smoke test (CLI):
      python3 -m modules.ssl_check example.com --mode expert
      python3 -m modules.ssl_check --self-check

  Programmatic:
      from modules.ssl_check import run, self_check
      print(self_check())                        # runtime diagnostics
      print(run("example.com", mode="expert"))   # full result dict

  Flask wiring (in app.py):
      from modules.ssl_check import register_blueprint
      register_blueprint(app)
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import ipaddress
import json as _json
import logging
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

# ── Optional dependency: cryptography (deep cert parsing) ────────────────
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (
        rsa, dsa, ec, ed25519, ed448,
    )
    from cryptography.x509.oid import ExtensionOID, NameOID
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False

# ── Optional dependency: Flask (blueprint for orchestrator endpoint) ────
try:
    from flask import Blueprint, jsonify, request
    _HAS_FLASK = True
except Exception:
    _HAS_FLASK = False


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING — isolated, no propagation to Flask root logger
# ═══════════════════════════════════════════════════════════════════════════
logger = logging.getLogger("oxysintx.ssl_check")
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
# METADATA — orchestrator contract
# ═══════════════════════════════════════════════════════════════════════════
__version__ = "3.1.0"
__author__  = "Yanxzyx"
__credit__  = "#credit ~ Yanxzyx"

TOOL_INFO = {
    "name": "SSL/TLS Certificate Inspector",
    "version": __version__,
    "description": (
        "Certificate validity, issuer, protocol version, cipher suite, "
        "expiry countdown, chain of trust, and OCSP stapling. Expert mode "
        "adds SANs, fingerprints, public-key details, key usages, policies, "
        "AIA/CRL endpoints, and per-chain fingerprint listings."
    ),
    "category": "Recon",
    "author": __author__,
    "credit": __credit__,
}
TOOL_KIND = "scanner"

DEFAULT_PORT              = 443
DEFAULT_CONNECT_TIMEOUT   = 6.0
DEFAULT_HANDSHAKE_TIMEOUT = 10.0
DEFAULT_MAX_CHAIN_DEPTH   = 10


# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
KNOWN_CAS = {
    "Let's Encrypt", "DigiCert Inc", "DigiCert, Inc.",
    "Sectigo Limited", "The USERTRUST Network",
    "GlobalSign nv-sa", "GlobalSign",
    "Amazon", "Amazon.com, Inc.",
    "Google Trust Services LLC", "Google Trust Services",
    "Cloudflare, Inc.", "IdenTrust",
    "GoDaddy.com, Inc.", "Starfield Technologies, Inc.",
    "Microsoft Corporation", "ZeroSSL",
    "COMODO CA Limited", "COMODO Certification Authority",
    "Baltimore", "Entrust, Inc.", "Entrust Certification Authority",
    "Certum Trusted Network CA", "Certigna",
    "Buypass AS-983163327", "Buypass",
    "DST Root CA X3", "ISRG Root X1", "ISRG Root X2",
    "USERTrust RSA Certification Authority",
    "USERTrust ECC Certification Authority",
    "DigiCert Global Root CA", "DigiCert Global Root G2",
    "DigiCert Global Root G3", "DigiCert High Assurance EV Root CA",
    "GTS Root R1", "GTS Root R2", "GTS Root R3", "GTS Root R4",
    "Actalis S.p.A./03358520967",
    "QuoVadis Limited", "QuoVadis",
    "SwissSign AG", "TeliaSonera", "Trustwave",
    "T-Systems Enterprise Services GmbH",
    "SSL.com", "SSL.com Root Certification Authority",
    "Hongkong Post Root CA 3",
    "Certainly", "HARICA", "HARICA TLS",
    "SECOM Trust Systems CO.,LTD.",
    "Network Solutions L.L.C.",
    "Certinomis - Autorité Racine",
    "IdenTrust Commercial Root CA 1",
    "Autoridad de Certificacion Firmaprofesional CIF A62634068",
    "AC Camerfirma S.A.", "Camerfirma",
}

# Matches `SSLSocket.version()` output exactly
_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

_WEAK_CIPHER_MARKERS = (
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON", "ADH", "AECDH",
)


# ═══════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def _utcnow() -> datetime.datetime:
    """Naive UTC now (avoids deprecated utcnow() on Python 3.12+)."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _normalize_target(target: str) -> str:
    """Strip scheme / path / port from a user-supplied target string."""
    s = (target or "").strip()
    if not s:
        return ""
    for prefix in ("https://", "http://", "ssl://", "tls://"):
        if s.lower().startswith(prefix):
            s = s[len(prefix):]
            break
    s = s.split("/", 1)[0]
    if s.startswith("[") and "]" in s:
        return s[1:s.index("]")]
    if s.count(":") == 1:
        s = s.split(":", 1)[0]
    return s


def _parse_date(date_str: str) -> Optional[datetime.datetime]:
    if not date_str:
        return None
    cleaned = date_str.strip()
    for suffix in (" GMT", " UTC", "Z"):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)]
            break
    for fmt in (
        "%b %d %H:%M:%S %Y",
        "%b  %d %H:%M:%S %Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.datetime.strptime(cleaned, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _fingerprint(der_bytes: bytes, algo: str = "sha256") -> str:
    try:
        h = hashlib.new(algo)
        h.update(der_bytes)
        return h.hexdigest()
    except (ValueError, TypeError):
        return ""


def _safe_oid_name(oid: Any) -> str:
    try:
        name = getattr(oid, "_name", None)
        if name:
            return name
    except Exception:
        pass
    try:
        return oid.dotted_string
    except Exception:
        return str(oid)


def _dictify_name(items: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for entry in items or []:
        try:
            for key, value in entry:
                out[key] = value
        except (TypeError, ValueError):
            continue
    return out


def _get_extension(cert: Any, oid: Any) -> Any:
    if cert is None:
        return None
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except Exception:
        return None


def _decode_name(name: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    mapping = {
        NameOID.COMMON_NAME:              "commonName",
        NameOID.ORGANIZATION_NAME:        "organizationName",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
        NameOID.COUNTRY_NAME:             "countryName",
        NameOID.STATE_OR_PROVINCE_NAME:   "stateOrProvinceName",
        NameOID.LOCALITY_NAME:            "localityName",
        NameOID.EMAIL_ADDRESS:            "emailAddress",
        NameOID.SERIAL_NUMBER:            "serialNumber",
        NameOID.BUSINESS_CATEGORY:        "businessCategory",
        NameOID.POSTAL_CODE:              "postalCode",
        NameOID.STREET_ADDRESS:           "streetAddress",
    }
    try:
        for attr in name:
            key = mapping.get(attr.oid) or _safe_oid_name(attr.oid)
            out[key] = attr.value
    except Exception as e:
        logger.debug("Failed to fully decode x509 name: %s", e)
    return out


def _get_validity_dates(cert: Any) -> Tuple[Optional[datetime.datetime],
                                            Optional[datetime.datetime]]:
    if cert is None:
        return None, None
    try:
        nb = cert.not_valid_before_utc.replace(tzinfo=None)
        na = cert.not_valid_after_utc.replace(tzinfo=None)
        return nb, na
    except AttributeError:
        pass
    try:
        return cert.not_valid_before, cert.not_valid_after
    except Exception as e:
        logger.debug("Could not read validity from certificate: %s", e)
        return None, None


def _public_key_info(cert: Any) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    if cert is None:
        return info
    try:
        pub = cert.public_key()
    except Exception:
        return info

    try:
        if isinstance(pub, rsa.RSAPublicKey):
            info["algorithm"] = "RSA"
            info["size_bits"] = pub.key_size
            info["exponent"]  = pub.public_numbers().e
        elif isinstance(pub, dsa.DSAPublicKey):
            info["algorithm"] = "DSA"
            info["size_bits"] = pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            info["algorithm"] = "EC"
            info["size_bits"] = pub.key_size
            try:
                info["curve"] = pub.curve.name
            except Exception:
                pass
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            info["algorithm"] = "Ed25519"
            info["size_bits"] = 256
        elif isinstance(pub, ed448.Ed448PublicKey):
            info["algorithm"] = "Ed448"
            info["size_bits"] = 456
        else:
            info["algorithm"] = type(pub).__name__
    except Exception as e:
        logger.debug("Failed to introspect public key: %s", e)
    return info


def _key_usage_str(usage: Any) -> List[str]:
    if usage is None:
        return []
    flags = []
    try:
        if usage.digital_signature:  flags.append("digitalSignature")
        if usage.content_commitment: flags.append("contentCommitment")
        if usage.key_encipherment:   flags.append("keyEncipherment")
        if usage.data_encipherment:  flags.append("dataEncipherment")
        if usage.key_agreement:      flags.append("keyAgreement")
        if usage.key_cert_sign:      flags.append("keyCertSign")
        if usage.crl_sign:           flags.append("cRLSign")
        if usage.encipher_only:      flags.append("encipherOnly")
        if usage.decipher_only:      flags.append("decipherOnly")
    except Exception:
        pass
    return flags


def _extended_key_usage_str(eku: Any) -> List[str]:
    if eku is None:
        return []
    out: List[str] = []
    try:
        for oid in eku:
            out.append(_safe_oid_name(oid))
    except Exception:
        pass
    return out


def _san_list(san: Any) -> List[Dict[str, str]]:
    if san is None:
        return []
    out: List[Dict[str, str]] = []
    pairs = [
        ("DNS",   x509.DNSName),
        ("IP",    x509.IPAddress),
        ("email", x509.RFC822Name),
        ("URI",   x509.UniformResourceIdentifier),
    ]
    for label, attr in pairs:
        try:
            for value in san.get_values_for_type(attr):
                out.append({"type": label, "value": str(value)})
        except Exception:
            continue
    return out


def _is_self_signed_x509(cert: Any) -> bool:
    if cert is None:
        return False
    try:
        return cert.subject == cert.issuer
    except Exception:
        return False


def _is_publicly_trusted_x509(cert: Any) -> Optional[bool]:
    if cert is None:
        return None
    if _is_self_signed_x509(cert):
        return False
    issuer_dict = _decode_name(cert.issuer)
    org = issuer_dict.get("organizationName", "")
    if org and org in KNOWN_CAS:
        return True
    return None


def _is_self_signed_fallback(cert_dict: Dict[str, Any]) -> bool:
    def flatten(items):
        out = set()
        for entry in items or []:
            try:
                for k, v in entry:
                    out.add((k, v))
            except (TypeError, ValueError):
                continue
        return frozenset(out)
    return flatten(cert_dict.get("subject")) == flatten(cert_dict.get("issuer"))


def _is_publicly_trusted_fallback(cert_dict: Dict[str, Any]) -> Optional[bool]:
    issuer = _dictify_name(cert_dict.get("issuer", []))
    org = issuer.get("organizationName", "")
    if org and org in KNOWN_CAS:
        return True
    if _is_self_signed_fallback(cert_dict):
        return False
    return None


# ═══════════════════════════════════════════════════════════════════════════
# CHAIN EXTRACTION — FIXED in v3.1.0
# ═══════════════════════════════════════════════════════════════════════════
def _extract_chain_der(ssock: ssl.SSLSocket) -> List[bytes]:
    """
    Return the DER chain as a list of bytes, leaf first.

    Python 3.10+ exposes `SSLSocket.get_unverified_chain()` which returns a
    list of `ssl.Certificate` objects. We call `public_bytes(ssl.ENCODING_DER)`
    on each — this is the *correct* API. The pre-v3.1 code incorrectly used
    `__import__("cryptography").hazmat.primitives.serialization.Encoding.DER`
    which does not exist on `ssl.Certificate` objects and raised at runtime.

    On older runtimes (< 3.10) or stripped builds, we fall back to leaf-only
    via `getpeercert(binary_form=True)`.
    """
    # Preferred: full chain (Python 3.10+)
    for meth in ("get_unverified_chain", "get_verified_chain"):
        fn = getattr(ssock, meth, None)
        if fn is None:
            continue
        try:
            chain = fn()
            if not chain:
                continue
            out: List[bytes] = []
            for cert in chain:
                try:
                    der = cert.public_bytes(ssl.ENCODING_DER)
                    if der:
                        out.append(der)
                except Exception as e:
                    logger.debug("public_bytes failed on chain element: %s", e)
            if out:
                return out
        except Exception as e:
            logger.debug("Chain extraction via %s failed: %s", meth, e)

    # Fallback: leaf only
    try:
        leaf_der = ssock.getpeercert(binary_form=True)
        return [leaf_der] if leaf_der else []
    except Exception:
        return []


def _parse_chain(chain_der: List[bytes]) -> List[Any]:
    if not _HAVE_CRYPTO:
        return []
    out: List[Any] = []
    for der in chain_der:
        try:
            out.append(x509.load_der_x509_certificate(der))
        except Exception as e:
            logger.debug("Failed to parse cert in chain: %s", e)
    return out


def _validate_chain(x509_chain: List[Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "length":          len(x509_chain),
        "linked":          None,
        "has_root":        None,
        "broken_at":       None,
        "expired_certs":   [],
        "non_ca_in_chain": [],
        "self_signed_top": None,
    }
    if not x509_chain:
        out["linked"] = False
        return out

    now = _utcnow()
    ok_linked = True

    for i, cert in enumerate(x509_chain):
        _, na = _get_validity_dates(cert)
        if na and na < now:
            try:
                out["expired_certs"].append({
                    "index": i,
                    "subject": _decode_name(cert.subject).get("commonName")
                               or _safe_oid_name(cert.subject),
                    "not_after": na.isoformat(),
                })
            except Exception:
                out["expired_certs"].append({"index": i,
                                             "not_after": na.isoformat()})

        if i > 0:
            bc = _get_extension(cert, ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = None
            try:
                is_ca = bool(bc.ca) if bc is not None else None
            except Exception:
                pass
            if is_ca is False:
                out["non_ca_in_chain"].append({
                    "index": i,
                    "subject": _decode_name(cert.subject).get("commonName") or "?",
                })

        if i + 1 < len(x509_chain):
            child, parent = cert, x509_chain[i + 1]
            try:
                if child.issuer != parent.subject:
                    ok_linked = False
                    if out["broken_at"] is None:
                        out["broken_at"] = i
            except Exception:
                ok_linked = False

    out["linked"] = ok_linked

    try:
        top = x509_chain[-1]
        out["self_signed_top"] = _is_self_signed_x509(top)
        out["has_root"] = out["self_signed_top"]
    except Exception:
        out["has_root"] = None

    return out


# ═══════════════════════════════════════════════════════════════════════════
# OCSP STAPLING
# ═══════════════════════════════════════════════════════════════════════════
def _check_ocsp_stapling(ssock: ssl.SSLSocket) -> Optional[bool]:
    try:
        response = ssock.ocsp_response()  # type: ignore[attr-defined]
        return bool(response)
    except (AttributeError, NotImplementedError):
        return None
    except Exception as e:
        logger.debug("OCSP stapling check failed: %s", e)
        return None


# ═══════════════════════════════════════════════════════════════════════════
# PROTOCOL / CIPHER CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════
def _classify_protocol(protocol_str: Optional[str]) -> Dict[str, Any]:
    if not protocol_str:
        return {"name": None, "weak": None, "description": "Unknown"}

    name = protocol_str
    norm = name.upper().replace(" ", "")
    weak = name in _WEAK_PROTOCOLS or norm in _WEAK_PROTOCOLS

    if norm in ("TLSV1.3", "TLSV1.2"):
        desc = "Modern and recommended"
        weak = False
    elif norm in ("TLSV1.1", "TLSV1", "SSLV3", "SSLV2"):
        desc = "Deprecated — upgrade recommended"
        weak = True
    else:
        desc = "Unknown or custom"

    return {"name": name, "weak": weak, "description": desc}


def _classify_cipher(cipher_name: Optional[str],
                     bits: Optional[int]) -> Dict[str, Any]:
    if not cipher_name:
        return {"name": None, "bits": bits, "weak": None,
                "reason": "Unknown cipher"}
    upper = cipher_name.upper()
    for marker in _WEAK_CIPHER_MARKERS:
        if marker in upper:
            return {"name": cipher_name, "bits": bits, "weak": True,
                    "reason": f"Contains weak marker '{marker}'"}
    if bits is not None and bits < 128:
        return {"name": cipher_name, "bits": bits, "weak": True,
                "reason": f"Key size {bits} bits is below 128"}
    return {"name": cipher_name, "bits": bits, "weak": False,
            "reason": "Acceptable"}


# ═══════════════════════════════════════════════════════════════════════════
# CORE CHECKER
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class SSLConfig:
    port:              int   = DEFAULT_PORT
    connect_timeout:   float = DEFAULT_CONNECT_TIMEOUT
    handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT
    verify:            bool  = True
    sni:               bool  = True
    min_tls_version:   Optional[str] = None
    max_chain_depth:   int   = DEFAULT_MAX_CHAIN_DEPTH


class SSLChecker:
    """Encapsulated SSL/TLS inspector. Safe to reuse across calls."""

    def __init__(self, config: Optional[SSLConfig] = None):
        self.config = config or SSLConfig()

    # ── Public API ────────────────────────────────────────────────────
    def check(self, target: str, mode: str = "basic") -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "tool":    "ssl_check",
            "version": __version__,
            "target":  target,
            "data":    {},
            "error":   None,
        }

        host = _normalize_target(target)
        if not host:
            result["error"] = "Empty target — provide a hostname or IP."
            return result

        port = self.config.port
        if not (1 <= port <= 65535):
            result["error"] = f"Port out of range: {port}"
            return result

        # ── DNS ─────────────────────────────────────────────────────
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            result["error"] = f"DNS resolution failed: {e}"
            return result
        except Exception as e:
            result["error"] = f"Address resolution error: {e}"
            return result
        if not infos:
            result["error"] = f"No addresses found for {host}"
            return result

        infos.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
        family, socktype, proto, _canon, sockaddr = infos[0]

        # ── TCP connect ─────────────────────────────────────────────
        raw_sock: Optional[socket.socket] = None
        try:
            raw_sock = socket.socket(family, socktype, proto)
            raw_sock.settimeout(self.config.connect_timeout)
            raw_sock.connect(sockaddr)
        except socket.timeout:
            if raw_sock: raw_sock.close()
            result["error"] = (f"TCP connect timed out after "
                               f"{self.config.connect_timeout}s")
            return result
        except ConnectionRefusedError:
            if raw_sock: raw_sock.close()
            result["error"] = f"Connection refused on port {port}"
            return result
        except OSError as e:
            if raw_sock: raw_sock.close()
            result["error"] = f"Network error: {e}"
            return result
        except Exception as e:
            if raw_sock: raw_sock.close()
            result["error"] = f"Unexpected connection error: {e}"
            return result

        # ── TLS context ─────────────────────────────────────────────
        try:
            if self.config.verify:
                ctx = ssl.create_default_context()
            else:
                ctx = ssl._create_unverified_context()  # noqa: SLF001
            try:
                min_ver = self._resolve_min_version()
                if min_ver is not None:
                    ctx.minimum_version = min_ver
            except (AttributeError, ValueError):
                pass
        except Exception as e:
            raw_sock.close()
            result["error"] = f"Failed to build SSL context: {e}"
            return result

        server_hostname: Optional[str] = (
            host if self.config.sni and not _is_ip_literal(host) else None
        )

        # ── Handshake ───────────────────────────────────────────────
        raw_sock.settimeout(self.config.handshake_timeout)
        ssock: Optional[ssl.SSLSocket] = None
        try:
            try:
                ssock = ctx.wrap_socket(raw_sock,
                                         server_hostname=server_hostname)
            except ssl.SSLCertVerificationError as e:
                msg = getattr(e, "verify_message", None) or str(e)
                result["error"] = f"Certificate verification failed: {msg}"
                return result
            except ssl.SSLError as e:
                result["error"] = f"TLS handshake failed: {e}"
                return result
            except socket.timeout:
                result["error"] = (f"TLS handshake timed out after "
                                   f"{self.config.handshake_timeout}s")
                return result
            except OSError as e:
                result["error"] = f"Connection error during handshake: {e}"
                return result

            # ── Certificate + cipher ────────────────────────────────
            try:
                cert_dict = ssock.getpeercert(binary_form=False) or {}
                der_leaf  = ssock.getpeercert(binary_form=True)
            except ssl.SSLError as e:
                result["error"] = f"Failed to read peer certificate: {e}"
                return result

            cipher       = ssock.cipher()
            protocol_str = ssock.version()

            # ── Chain extraction (FIXED) ────────────────────────────
            chain_der = _extract_chain_der(ssock)[: self.config.max_chain_depth]
            if not chain_der and der_leaf:
                chain_der = [der_leaf]
            chain_x509 = _parse_chain(chain_der)

            leaf_x509: Optional[Any] = chain_x509[0] if chain_x509 else None
            if leaf_x509 is None and _HAVE_CRYPTO and der_leaf:
                try:
                    leaf_x509 = x509.load_der_x509_certificate(der_leaf)
                except Exception as e:
                    logger.debug("Leaf parse failed: %s", e)

            # ── Core fields ─────────────────────────────────────────
            if leaf_x509 is not None:
                subject  = _decode_name(leaf_x509.subject)
                issuer   = _decode_name(leaf_x509.issuer)
                nb_dt, na_dt = _get_validity_dates(leaf_x509)
                not_before_str = nb_dt.isoformat() if nb_dt else ""
                not_after_str  = na_dt.isoformat() if na_dt else ""
                self_signed    = _is_self_signed_x509(leaf_x509)
                publicly_trusted = _is_publicly_trusted_x509(leaf_x509)
                serial_hex = format(leaf_x509.serial_number, "x")
                if len(serial_hex) % 2 == 1:
                    serial_hex = "0" + serial_hex
                serial = serial_hex
            else:
                subject  = _dictify_name(cert_dict.get("subject", []))
                issuer   = _dictify_name(cert_dict.get("issuer", []))
                not_before_str = cert_dict.get("notBefore", "")
                not_after_str  = cert_dict.get("notAfter", "")
                self_signed    = _is_self_signed_fallback(cert_dict)
                publicly_trusted = _is_publicly_trusted_fallback(cert_dict)
                serial = cert_dict.get("serialNumber")

            protocol_info = _classify_protocol(protocol_str)
            cipher_class  = _classify_cipher(
                cipher[0] if cipher else None,
                cipher[2] if cipher else None,
            )

            # v3.1.0 — guarantee subject and issuer are dicts
            if not isinstance(subject, dict):
                subject = {}
            if not isinstance(issuer, dict):
                issuer = {}

            data: Dict[str, Any] = {
                "subject":          subject,
                "issuer":           issuer,
                "valid_from":       not_before_str,
                "valid_until":      not_after_str,
                "protocol":         protocol_str,
                "protocol_weak":    protocol_info["weak"],
                "protocol_note":    protocol_info["description"],
                "cipher_suite":     cipher[0] if cipher else "unknown",
                "cipher_protocol":  cipher[1] if cipher else None,
                "cipher_bits":      cipher[2] if cipher else None,
                "cipher_weak":      cipher_class["weak"],
                "cipher_note":      cipher_class["reason"],
                "self_signed":      self_signed,
                "publicly_trusted": publicly_trusted,
                "serial_number":    serial,
                "chain_length":     len(chain_der),
                "host":             host,
                "port":             port,
            }

            # ── Expiry ──────────────────────────────────────────────
            expiry_dt: Optional[datetime.datetime] = None
            if leaf_x509 is not None:
                _, expiry_dt = _get_validity_dates(leaf_x509)
            if expiry_dt is None:
                expiry_dt = _parse_date(not_after_str)

            if expiry_dt:
                delta = expiry_dt - _utcnow()
                data["days_until_expiry"] = delta.days
                data["is_expired"]        = delta.days < 0
                data["expiring_soon"]     = 0 <= delta.days <= 30
            else:
                data["days_until_expiry"] = None
                data["is_expired"]        = None
                data["expiring_soon"]     = None

            # ── Expert mode ─────────────────────────────────────────
            if mode == "expert":
                self._populate_expert(data, leaf_x509, chain_der, chain_x509,
                                       cert_dict, ssock)

            result["data"] = data
            return result

        finally:
            if ssock is not None:
                try: ssock.close()
                except Exception: pass
            elif raw_sock is not None:
                try: raw_sock.close()
                except Exception: pass

    # ── Internals ─────────────────────────────────────────────────────
    def _resolve_min_version(self) -> Optional[ssl.TLSVersion]:
        v = (self.config.min_tls_version or "").strip()
        if not v:
            return None
        table = {
            "TLSv1":   ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }
        return table.get(v)

    def _populate_expert(self,
                         data: Dict[str, Any],
                         leaf_x509: Optional[Any],
                         chain_der: List[bytes],
                         chain_x509: List[Any],
                         cert_dict: Dict[str, Any],
                         ssock: ssl.SSLSocket) -> None:
        for key in ("subject_alt_names", "public_key", "key_usage",
                    "extended_key_usage", "certificate_policies",
                    "ocsp_urls", "ca_issuers_urls", "crl_urls",
                    "chain_fingerprints"):
            data.setdefault(key, [] if key != "public_key" else {})
        data.setdefault("signature_algorithm", None)
        data.setdefault("is_ca", None)
        data.setdefault("path_length", None)
        data.setdefault("ocsp_stapled", None)
        data.setdefault("chain_validation", None)

        if leaf_x509 is not None:
            san_ext = _get_extension(
                leaf_x509, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            )
            data["subject_alt_names"] = _san_list(san_ext)
            data["public_key"] = _public_key_info(leaf_x509)

            try:
                data["signature_algorithm"] = _safe_oid_name(
                    leaf_x509.signature_algorithm_oid,
                )
            except Exception:
                data["signature_algorithm"] = None

            ku = _get_extension(leaf_x509, ExtensionOID.KEY_USAGE)
            data["key_usage"] = _key_usage_str(ku)

            eku = _get_extension(leaf_x509, ExtensionOID.EXTENDED_KEY_USAGE)
            data["extended_key_usage"] = _extended_key_usage_str(eku)

            bc = _get_extension(leaf_x509, ExtensionOID.BASIC_CONSTRAINTS)
            if bc is not None:
                try: data["is_ca"] = bool(bc.ca)
                except Exception: pass
                try: data["path_length"] = bc.path_length
                except Exception: data["path_length"] = None

            cp = _get_extension(leaf_x509, ExtensionOID.CERTIFICATE_POLICIES)
            if cp is not None:
                try:
                    data["certificate_policies"] = [
                        pol.policy_identifier.dotted_string for pol in cp
                    ]
                except Exception:
                    pass

            aia = _get_extension(
                leaf_x509, ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
            )
            if aia is not None:
                try:
                    OCSP_OID = x509.oid.AuthorityInformationAccessOID.OCSP
                    CA_OID   = x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
                    data["ocsp_urls"] = [
                        d.access_location.value
                        for d in aia if d.access_method == OCSP_OID
                    ]
                    data["ca_issuers_urls"] = [
                        d.access_location.value
                        for d in aia if d.access_method == CA_OID
                    ]
                except Exception:
                    pass

            crl_ext = _get_extension(
                leaf_x509, ExtensionOID.CRL_DISTRIBUTION_POINTS,
            )
            if crl_ext is not None:
                urls: List[str] = []
                try:
                    for dp in crl_ext:
                        try:
                            urls.append(dp.full_name[0].value)
                        except (AttributeError, IndexError):
                            continue
                except Exception:
                    pass
                data["crl_urls"] = urls
        else:
            data["subject_alt_names"] = [
                {"type": t, "value": v}
                for t, v in cert_dict.get("subjectAltName", [])
            ]
            data["public_key"] = {
                "algorithm": "unknown",
                "size_bits": None,
                "hint": "install 'cryptography' for detailed public key info",
            }

        data["ocsp_stapled"] = _check_ocsp_stapling(ssock)

        if chain_der:
            data["fingerprint_sha256"] = _fingerprint(chain_der[0], "sha256")
            data["fingerprint_sha1"]   = _fingerprint(chain_der[0], "sha1")
            data["fingerprint_sha512"] = _fingerprint(chain_der[0], "sha512")
            data["cert_size_bytes"]    = len(chain_der[0])

        chain_fps: List[Dict[str, Any]] = []
        for idx, der in enumerate(chain_der):
            entry: Dict[str, Any] = {
                "index":          idx,
                "role":           "leaf" if idx == 0 else
                                  ("root" if idx == len(chain_der) - 1
                                   else "intermediate"),
                "size_bytes":     len(der),
                "fingerprint_sha256": _fingerprint(der, "sha256"),
                "fingerprint_sha1":   _fingerprint(der, "sha1"),
            }
            if idx < len(chain_x509):
                try:
                    cn = _decode_name(chain_x509[idx].subject).get("commonName")
                    entry["subject_cn"] = cn or "?"
                except Exception:
                    entry["subject_cn"] = "?"
            chain_fps.append(entry)
        data["chain_fingerprints"] = chain_fps

        data["chain_validation"] = _validate_chain(chain_x509)
        data["chain_depth_known"] = len(chain_der)


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINTS — orchestrator contract
# ═══════════════════════════════════════════════════════════════════════════
def run(
    target: str,
    mode: str = "basic",
    port: int = DEFAULT_PORT,
    timeout: Optional[float] = None,
    verify: bool = True,
    sni: bool = True,
) -> Dict[str, Any]:
    """Backward-compatible orchestrator entry point. Never raises."""
    cfg = SSLConfig(
        port=port,
        connect_timeout=timeout if timeout is not None else DEFAULT_CONNECT_TIMEOUT,
        handshake_timeout=timeout if timeout is not None else DEFAULT_HANDSHAKE_TIMEOUT,
        verify=verify,
        sni=sni,
    )
    return SSLChecker(cfg).check(target, mode=mode)


# Aliases — terminal.py registry + backward compat
ssl_check      = run
check_ssl      = run
scan_ssl       = run
scan_ssl_check = run
ssl_scan       = run


def run_streaming(
    target: str,
    options: Optional[Dict[str, Any]] = None,
    cancel_event: Optional[Any] = None,
) -> Iterator[Dict[str, Any]]:
    """SSE-friendly generator mirroring the Emergens app SSE envelope."""
    options = options or {}
    mode    = options.get("mode", "basic")
    port    = int(options.get("port", DEFAULT_PORT))
    timeout = options.get("timeout")
    verify  = bool(options.get("verify", True))
    sni     = bool(options.get("sni", True))

    started = time.time()
    yield {"type": "start", "target": target, "options": {
        "mode": mode, "port": port, "verify": verify, "sni": sni,
    }}

    if cancel_event is not None and getattr(cancel_event, "is_set",
                                             lambda: False)():
        yield {"type": "error", "message": "cancelled before start"}
        return

    yield {"type": "stage", "stage": "resolve"}
    yield {"type": "stage", "stage": "connect"}
    yield {"type": "stage", "stage": "handshake"}

    try:
        result = run(target, mode=mode, port=port,
                     timeout=timeout, verify=verify, sni=sni)
    except Exception as e:
        yield {"type": "error", "message": str(e)}
        return

    yield {"type": "stage", "stage": "parse"}

    if cancel_event is not None and getattr(cancel_event, "is_set",
                                             lambda: False)():
        yield {"type": "error", "message": "cancelled after handshake"}
        return

    yield {"type": "result", "data": result}
    yield {"type": "summary",
           "duration_ms": int((time.time() - started) * 1000),
           "ok": result.get("error") is None}
    yield {"type": "stage", "stage": "done"}


def scan_many(
    targets: Iterable[str],
    mode: str = "basic",
    port: int = DEFAULT_PORT,
    timeout: Optional[float] = None,
    verify: bool = True,
    sni: bool = True,
    workers: int = 8,
    on_result: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> List[Dict[str, Any]]:
    """Concurrent scan of many targets. Returns results in input order."""
    targets = list(targets)
    results: List[Optional[Dict[str, Any]]] = [None] * len(targets)

    def _one(idx: int, tgt: str) -> Tuple[int, Dict[str, Any]]:
        r = run(tgt, mode=mode, port=port, timeout=timeout,
                verify=verify, sni=sni)
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
                logger.warning("Batch worker raised: %s", e)

    return [r for r in results if r is not None]


# ═══════════════════════════════════════════════════════════════════════════
# SELF-CHECK — quick runtime diagnostic
# ═══════════════════════════════════════════════════════════════════════════
def self_check() -> Dict[str, Any]:
    """Return a diagnostic dict describing what this runtime supports."""
    py = sys.version_info
    has_chain_api = hasattr(ssl.SSLSocket, "get_unverified_chain")
    return {
        "module":       "modules.ssl_check",
        "version":      __version__,
        "author":       __author__,
        "credit":       __credit__,
        "python":       f"{py.major}.{py.minor}.{py.micro}",
        "python_ok":    py >= (3, 8),
        "cryptography": _HAVE_CRYPTO,
        "flask":        _HAS_FLASK,
        "chain_api":    has_chain_api,
        "ocsp_api":     hasattr(ssl.SSLSocket, "ocsp_response"),
        "tls13":        hasattr(ssl.TLSVersion, "TLSv1_3"),
        "aliases":      ["run", "ssl_check", "check_ssl", "scan_ssl",
                         "scan_ssl_check", "ssl_scan"],
        "endpoint":     "/api/ssl/scan" if _HAS_FLASK else None,
        "ready":        has_chain_api or _HAVE_CRYPTO,
    }


# ═══════════════════════════════════════════════════════════════════════════
# FLASK BLUEPRINT — endpoint for terminal.py  →  POST /api/ssl/scan
# ═══════════════════════════════════════════════════════════════════════════
if _HAS_FLASK:
    ssl_bp = Blueprint("ssl_check", __name__)

    @ssl_bp.route("/api/ssl/scan", methods=["POST", "GET"])
    def _ssl_scan_endpoint():
        """
        Payload (JSON or query):
            { "target": "example.com", "mode": "basic|expert",
              "port": 443, "timeout": 10,
              "verify": true, "sni": true }

        Response shape — matches terminal.py `_render_ssl()`:
            {
              "tool": "ssl_check", "version": "3.1.0",
              "target": "example.com",
              "data": { subject: {...}, issuer: {...},
                        protocol, cipher_suite, valid_from, valid_until,
                        days_until_expiry, is_expired, expiring_soon,
                        self_signed, publicly_trusted, chain_length, ... },
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

        try:
            port = int(payload.get("port") or request.args.get("port")
                       or DEFAULT_PORT)
        except (TypeError, ValueError):
            port = DEFAULT_PORT

        try:
            timeout = payload.get("timeout")
            if timeout is None:
                timeout = request.args.get("timeout")
            timeout = float(timeout) if timeout is not None else None
        except (TypeError, ValueError):
            timeout = None

        verify = payload.get("verify", request.args.get("verify", "1"))
        verify = str(verify).lower() not in ("0", "false", "no", "off")
        sni = payload.get("sni", request.args.get("sni", "1"))
        sni = str(sni).lower() not in ("0", "false", "no", "off")

        if not target:
            return jsonify({
                "tool": "ssl_check", "version": __version__,
                "target": "", "data": {},
                "error": "missing 'target' parameter",
            }), 400

        result = run(target, mode=mode, port=port,
                     timeout=timeout, verify=verify, sni=sni)
        return jsonify(result)


    def register_blueprint(app) -> None:
        """Convenience helper for app.py: `register_blueprint(app)`."""
        app.register_blueprint(ssl_bp)
        logger.info("ssl_check blueprint registered at /api/ssl/scan")


# ═══════════════════════════════════════════════════════════════════════════
# CLI — ad-hoc testing
# ═══════════════════════════════════════════════════════════════════════════
def _print_human(r: Dict[str, Any]) -> None:
    if r.get("error"):
        print(f"[FAIL] {r['target']:40s}  {r['error']}")
        return
    d = r["data"]
    subj = (d.get("subject") or {}).get("commonName") or "(no CN)"
    iss  = (d.get("issuer") or {}).get("organizationName") or "(unknown)"
    prot = d.get("protocol") or "?"
    exp  = d.get("days_until_expiry")
    tag  = "⚠ weak" if d.get("protocol_weak") else "✓"
    print(f"[OK]   {r['target']:40s}  {subj:35s}  {prot:8s}  "
          f"expires in {exp} days  {tag}")
    print(f"        issuer: {iss}")
    if d.get("chain_length"):
        print(f"        chain : {d['chain_length']} cert(s)")


def _main() -> int:
    ap = argparse.ArgumentParser(
        description=f"SSL/TLS Certificate Inspector v{__version__}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("targets", nargs="*", help="hostnames / IPs / URLs")
    ap.add_argument("--mode", choices=["basic", "expert"], default="basic")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--timeout", type=float, default=None)
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--no-sni", action="store_true")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--json", action="store_true", help="raw JSON output")
    ap.add_argument("--self-check", action="store_true",
                    help="print runtime diagnostics and exit")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args()

    if args.self_check or not args.targets:
        print(_json.dumps(self_check(), indent=2))
        if not args.targets and not args.self_check:
            print("\nTip: pass at least one target, e.g. `example.com`.")
        return 0

    if len(args.targets) == 1:
        r = run(args.targets[0], mode=args.mode, port=args.port,
                timeout=args.timeout, verify=not args.no_verify,
                sni=not args.no_sni)
        if args.json:
            print(_json.dumps(r, indent=2, default=str))
        else:
            _print_human(r)
            print()
            print(_json.dumps(r, indent=2, default=str))
        return 0

    scan_many(
        args.targets, mode=args.mode, port=args.port,
        timeout=args.timeout, verify=not args.no_verify,
        sni=not args.no_sni, workers=args.workers,
        on_result=(lambda t, r: print(_json.dumps(r, indent=2, default=str)))
                    if args.json else _print_human,
    )
    return 0


if __name__ == "__main__":
    sys.exit(_main())