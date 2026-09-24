#!/usr/bin/env python3
"""
SSL/TLS Certificate Inspector — comprehensive & production-ready (v3.0.0)

Reads exactly what any browser padlock shows, plus deeper fields in expert
mode. Designed to slot directly into the Emergens orchestrator: exposes
`run(target, mode)` for synchronous calls and `run_streaming(...)` for SSE.

Core features
-------------
  • Custom port, split timeouts (connect + handshake).
  • Granular exception handling: DNS, TCP, TLS, cert-chain, cert-parse.
  • Full certificate chain extraction (Python 3.10+ native; falls back
    to leaf-only on older runtimes).
  • Chain validation — issuer / subject linkage, self-signed detection,
    known-CA registry, expired intermediates.
  • OCSP stapling detection (returns True / False / None).
  • Public-key introspection (RSA / DSA / EC / Ed25519 / Ed448) via
    `cryptography`, with graceful fallback to stdlib.
  • SHA-256 / SHA-1 / SHA-512 fingerprints of every cert in the chain.
  • Subject Alternative Names (DNS, IP, email, URI).
  • Key usage, extended key usage, certificate policies, AIA, CRL DP.
  • Weak protocol / weak cipher detection with proper classification.
  • Days-until-expiry countdown, expiring-soon flag, expired flag.
  • Bulk `scan_many()` with ThreadPoolExecutor.
  • Streaming generator that mirrors the app.py SSE envelope.
  • Isolated logger — never duplicates Flask / root handlers.
  • `run()` never raises. All errors are returned in `result["error"]`.

Author : Yanxzyx
Version: 3.0.0 — chain extraction, streaming, batch, split timeouts
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import logging
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

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


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING  — isolated, no propagation to Flask root logger
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

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ═══════════════════════════════════════════════════════════════════════════
# TOOL METADATA  — orchestrator contract
# ═══════════════════════════════════════════════════════════════════════════
__version__ = "3.0.0"
__author__  = "Yanxzyx"

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
}
TOOL_KIND = "scanner"

DEFAULT_PORT             = 443
DEFAULT_CONNECT_TIMEOUT  = 6.0
DEFAULT_HANDSHAKE_TIMEOUT = 10.0
DEFAULT_MAX_CHAIN_DEPTH  = 10


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

# Matches `SSLSocket.version()` output exactly: no spaces between
# protocol and version, e.g. "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3".
_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

_WEAK_CIPHER_MARKERS = (
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON", "ADH", "AECDH",
)

# OIDs used when walking the chain
_OID_OCSP  = "1.3.6.1.5.5.7.48.1"
_OID_CAISS = "1.3.6.1.5.5.7.48.2"


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
    # IPv6 literal in brackets: [::1]:443
    if s.startswith("[") and "]" in s:
        return s[1:s.index("]")]
    # IPv4 / hostname with :port (exactly one colon)
    if s.count(":") == 1:
        s = s.split(":", 1)[0]
    return s


def _parse_date(date_str: str) -> Optional[datetime.datetime]:
    """
    Parse ASN.1 date strings. Handles ' GMT' / ' UTC' / 'Z' suffixes.
    `%Z` on Windows is unreliable, so we strip manually first.
    """
    if not date_str:
        return None
    cleaned = date_str.strip()
    for suffix in (" GMT", " UTC", "Z"):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)]
            break
    for fmt in (
        "%b %d %H:%M:%S %Y",
        "%b  %d %H:%M:%S %Y",   # ASN.1 sometimes emits double-space day
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.datetime.strptime(cleaned, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _fingerprint(der_bytes: bytes, algo: str = "sha256") -> str:
    """Hex fingerprint of DER bytes. Returns '' if the algo is missing."""
    try:
        h = hashlib.new(algo)
        h.update(der_bytes)
        return h.hexdigest()
    except (ValueError, TypeError):
        return ""


def _safe_oid_name(oid: Any) -> str:
    """Human-readable OID name; falls back to dotted string. Never raises."""
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
    """Flatten Python's stdlib SSL name structure into a dict."""
    out: Dict[str, str] = {}
    for entry in items or []:
        try:
            for key, value in entry:
                out[key] = value
        except (TypeError, ValueError):
            continue
    return out


def _get_extension(cert: Any, oid: Any) -> Any:
    """Fetch an X.509 extension value or None if absent / undecodable."""
    if cert is None:
        return None
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except Exception:
        return None


def _decode_name(name: Any) -> Dict[str, str]:
    """Flatten a cryptography x509.Name into a readable dict."""
    out: Dict[str, str] = {}
    mapping = {
        NameOID.COMMON_NAME:             "commonName",
        NameOID.ORGANIZATION_NAME:       "organizationName",
        NameOID.ORGANIZATIONAL_UNIT_NAME:"organizationalUnitName",
        NameOID.COUNTRY_NAME:            "countryName",
        NameOID.STATE_OR_PROVINCE_NAME:  "stateOrProvinceName",
        NameOID.LOCALITY_NAME:           "localityName",
        NameOID.EMAIL_ADDRESS:           "emailAddress",
        NameOID.SERIAL_NUMBER:           "serialNumber",
        NameOID.BUSINESS_CATEGORY:       "businessCategory",
        NameOID.POSTAL_CODE:             "postalCode",
        NameOID.STREET_ADDRESS:          "streetAddress",
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
    """
    Return (not_before_utc, not_after_utc) as naive UTC datetimes.
    Uses modern `*_utc` properties when available (cryptography ≥ 42),
    falls back to the deprecated naive properties otherwise.
    """
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
    """Extract public-key algorithm, size, and curve (if applicable)."""
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
        ("DNS", x509.DNSName),
        ("IP",  x509.IPAddress),
        ("email", x509.RFC822Name),
        ("URI", x509.UniformResourceIdentifier),
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
# CHAIN EXTRACTION (Python 3.10+) + VALIDATION
# ═══════════════════════════════════════════════════════════════════════════
def _extract_chain_der(ssock: ssl.SSLSocket) -> List[bytes]:
    """
    Return the DER chain as a list of bytes, leaf first.

    Python 3.10+ exposes `get_unverified_chain()` — the actual chain the
    server sent. On older runtimes we fall back to leaf-only via
    `getpeercert(binary_form=True)`.
    """
    # Preferred: full chain (3.10+)
    for meth in ("get_unverified_chain", "get_verified_chain"):
        fn = getattr(ssock, meth, None)
        if fn is None:
            continue
        try:
            chain = fn()
            if chain:
                return [c.public_bytes(__import__("cryptography").hazmat
                                       .primitives.serialization
                                       .Encoding.DER)
                        for c in chain]
        except Exception as e:
            logger.debug("Chain extraction via %s failed: %s", meth, e)

    # Fallback: leaf only
    try:
        leaf_der = ssock.getpeercert(binary_form=True)
        return [leaf_der] if leaf_der else []
    except Exception:
        return []


def _parse_chain(chain_der: List[bytes]) -> List[Any]:
    """Parse DER chain into x509 objects; skips certs that fail to parse."""
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
    """
    Best-effort chain validation:
      • issuer[N].subject == subject[N-1]?  → linked
      • top-of-chain is self-signed?        → root trust anchor present
      • intermediates expired?              → broken
      • is_ca basic constraint on non-leaf? → structural sanity
    Note: this is *not* a full PKIX path validation. It catches the common
    problems: missing intermediates, expired intermediates, non-CA used
    as intermediate, and self-signed root vs missing root.
    """
    out: Dict[str, Any] = {
        "length":             len(x509_chain),
        "linked":             None,
        "has_root":           None,
        "broken_at":          None,
        "expired_certs":      [],
        "non_ca_in_chain":    [],
        "self_signed_top":    None,
    }
    if not x509_chain:
        out["linked"] = False
        return out

    now = _utcnow()
    ok_linked = True

    for i, cert in enumerate(x509_chain):
        # Expiry check
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
                out["expired_certs"].append({"index": i, "not_after": na.isoformat()})

        # Basic constraints — non-leaf should be CA
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

        # Linkage: child.issuer == parent.subject
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

    # Top-of-chain self-signed?
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
    """
    Return True / False / None:
      True  — server stapled a non-empty OCSP response
      False — server sent no OCSP response
      None  — stdlib doesn't expose the API (Python < 3.8 / stripped builds)
    """
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

    name  = protocol_str
    norm  = name.upper().replace(" ", "")
    weak  = name in _WEAK_PROTOCOLS or norm in _WEAK_PROTOCOLS

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
# CORE CHECKER CLASS
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class SSLConfig:
    port:              int   = DEFAULT_PORT
    connect_timeout:   float = DEFAULT_CONNECT_TIMEOUT
    handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT
    verify:            bool  = True
    sni:               bool  = True
    min_tls_version:   Optional[str] = None   # "TLSv1.2", "TLSv1.3", None=default
    max_chain_depth:   int   = DEFAULT_MAX_CHAIN_DEPTH


class SSLChecker:
    """
    Encapsulated SSL/TLS inspector. Instantiate once, call `check()` many
    times — the socket is always closed on the way out.
    """

    def __init__(self, config: Optional[SSLConfig] = None):
        self.config = config or SSLConfig()

    # ── Public API ────────────────────────────────────────────────────
    def check(self, target: str, mode: str = "basic") -> Dict[str, Any]:
        """
        Inspect `target` and return the structured result. Never raises.
        """
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

        # ── Resolve ─────────────────────────────────────────────────
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
                ssock = ctx.wrap_socket(raw_sock, server_hostname=server_hostname)
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

            # ── Chain extraction ────────────────────────────────────
            chain_der = _extract_chain_der(ssock)[: self.config.max_chain_depth]
            if not chain_der and der_leaf:
                chain_der = [der_leaf]
            chain_x509 = _parse_chain(chain_der)

            # Leaf: prefer the parsed chain[0] (identical to der_leaf)
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
        """Fill the expert-mode block. Never raises; sets defaults first."""
        # Sensible defaults so consumers never see a KeyError
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
            # SANs
            san_ext = _get_extension(
                leaf_x509, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            )
            data["subject_alt_names"] = _san_list(san_ext)

            # Public key
            data["public_key"] = _public_key_info(leaf_x509)

            # Signature algorithm
            try:
                data["signature_algorithm"] = _safe_oid_name(
                    leaf_x509.signature_algorithm_oid,
                )
            except Exception:
                data["signature_algorithm"] = None

            # Key usage
            ku = _get_extension(leaf_x509, ExtensionOID.KEY_USAGE)
            data["key_usage"] = _key_usage_str(ku)

            # Extended key usage
            eku = _get_extension(leaf_x509, ExtensionOID.EXTENDED_KEY_USAGE)
            data["extended_key_usage"] = _extended_key_usage_str(eku)

            # Basic constraints
            bc = _get_extension(leaf_x509, ExtensionOID.BASIC_CONSTRAINTS)
            if bc is not None:
                try: data["is_ca"] = bool(bc.ca)
                except Exception: pass
                try: data["path_length"] = bc.path_length
                except Exception: data["path_length"] = None

            # Certificate policies
            cp = _get_extension(leaf_x509, ExtensionOID.CERTIFICATE_POLICIES)
            if cp is not None:
                try:
                    data["certificate_policies"] = [
                        pol.policy_identifier.dotted_string for pol in cp
                    ]
                except Exception:
                    pass

            # AIA — OCSP + CA Issuers
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

            # CRL distribution points
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
            # Fallback when cryptography unavailable
            data["subject_alt_names"] = [
                {"type": t, "value": v}
                for t, v in cert_dict.get("subjectAltName", [])
            ]
            data["public_key"] = {
                "algorithm": "unknown",
                "size_bits": None,
                "hint": "install 'cryptography' for detailed public key info",
            }

        # OCSP stapling
        data["ocsp_stapled"] = _check_ocsp_stapling(ssock)

        # Fingerprints (per cert in chain)
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
            # Subject CN for readability
            if idx < len(chain_x509):
                try:
                    cn = _decode_name(chain_x509[idx].subject).get("commonName")
                    entry["subject_cn"] = cn or "?"
                except Exception:
                    entry["subject_cn"] = "?"
            chain_fps.append(entry)
        data["chain_fingerprints"] = chain_fps

        # Chain validation summary
        data["chain_validation"] = _validate_chain(chain_x509)
        data["chain_depth_known"] = len(chain_der)


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINTS  — orchestrator contract
# ═══════════════════════════════════════════════════════════════════════════
def run(
    target: str,
    mode: str = "basic",
    port: int = DEFAULT_PORT,
    timeout: Optional[float] = None,
    verify: bool = True,
    sni: bool = True,
) -> Dict[str, Any]:
    """
    Backward-compatible entry point.

    Call:  run(target, mode)  or  run(target, mode, port=8443, verify=False)
    Returns a dict with keys: tool, version, target, data, error.
    """
    cfg = SSLConfig(
        port=port,
        connect_timeout=timeout if timeout is not None else DEFAULT_CONNECT_TIMEOUT,
        handshake_timeout=timeout if timeout is not None else DEFAULT_HANDSHAKE_TIMEOUT,
        verify=verify,
        sni=sni,
    )
    return SSLChecker(cfg).check(target, mode=mode)


def run_streaming(
    target: str,
    options: Optional[Dict[str, Any]] = None,
    cancel_event: Optional[Any] = None,
) -> Iterable[Dict[str, Any]]:
    """
    SSE-friendly generator. Yields event dicts consumed by
    `app._sse_format` / `app._sse_response`.

    Event types:
        {"type": "start",   "target": <str>, "options": <dict>}
        {"type": "stage",   "stage": "resolve|connect|handshake|parse|done"}
        {"type": "result",  "data": <result dict>}
        {"type": "summary", "duration_ms": <int>, "ok": <bool>}
        {"type": "error",   "message": <str>}          (on hard failure)
    """
    options = options or {}
    mode           = options.get("mode", "basic")
    port           = int(options.get("port", DEFAULT_PORT))
    timeout        = options.get("timeout")
    verify         = bool(options.get("verify", True))
    sni            = bool(options.get("sni", True))

    started = time.time()
    yield {"type": "start", "target": target, "options": {
        "mode": mode, "port": port, "verify": verify, "sni": sni,
    }}

    if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
        yield {"type": "error", "message": "cancelled before start"}
        return

    yield {"type": "stage", "stage": "resolve"}
    yield {"type": "stage", "stage": "connect"}
    yield {"type": "stage", "stage": "handshake"}

    try:
        result = run(
            target, mode=mode, port=port,
            timeout=timeout, verify=verify, sni=sni,
        )
    except Exception as e:
        yield {"type": "error", "message": str(e)}
        return

    yield {"type": "stage", "stage": "parse"}

    if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
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
    """
    Concurrent scan of many targets. Returns results in input order.

    `on_result(target, result)` is invoked from the worker thread as each
    target finishes — useful for live progress in a CLI or SSE bridge.
    """
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
# CLI (optional — invoke directly for ad-hoc checks)
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse
    import json as _json

    ap = argparse.ArgumentParser(
        description=f"SSL/TLS Certificate Inspector v{__version__}"
    )
    ap.add_argument("targets", nargs="+", help="hostnames / IPs / URLs")
    ap.add_argument("--mode", choices=["basic", "expert"], default="basic")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--timeout", type=float, default=None)
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--no-sni", action="store_true")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--json", action="store_true", help="raw JSON output")
    args = ap.parse_args()

    def _print(t: str, r: Dict[str, Any]):
        if args.json:
            print(_json.dumps(r, indent=2, default=str))
            return
        if r.get("error"):
            print(f"[FAIL] {t:40s}  {r['error']}")
            return
        d = r["data"]
        subj = d.get("subject", {}).get("commonName") or "(no CN)"
        print(f"[OK]   {t:40s}  {subj:35s}  "
              f"{d.get('protocol'):8s}  "
              f"expires in {d.get('days_until_expiry')} days  "
              f"{'⚠ weak' if d.get('protocol_weak') else '✓'}")

    if len(args.targets) == 1:
        r = run(args.targets[0], mode=args.mode, port=args.port,
                timeout=args.timeout, verify=not args.no_verify,
                sni=not args.no_sni)
        print(_json.dumps(r, indent=2, default=str))
    else:
        scan_many(
            args.targets, mode=args.mode, port=args.port,
            timeout=args.timeout, verify=not args.no_verify,
            sni=not args.no_sni, workers=args.workers,
            on_result=_print,
        )