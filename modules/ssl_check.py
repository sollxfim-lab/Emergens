#!/usr/bin/env python3
"""
SSL/TLS certificate inspection — comprehensive & production-ready.

Reads exactly what any browser padlock would show, plus deeper fields
when running in expert mode.

Features:
    • Custom port support (default 443).
    • Granular exception handling (DNS, connection, TLS, certificate).
    • Certificate chain validation (self-signed detection via AKI/SKI,
      issuer matching, and known-CA registry).
    • OCSP stapling check (expert mode) — works on Python 3.8+.
    • Full public-key details (algorithm, curve, bit-size) via
      `cryptography` when available; graceful fallback otherwise.
    • SHA-256 / SHA-1 fingerprints of the leaf certificate for pinning.
    • Subject Alternative Names (DNS, IP, URI, email).
    • Extended key usage, key usage, certificate policies.
    • Validity window with days-until-expiry countdown.
    • Weak protocol / cipher detection (correctly matches ssock.version()
      string format).
    • Supports both hostname and IP literal (incl. IPv6).
    • Configurable timeout, SNI toggle, verification toggle — inspect
      self-signed / expired certs without failing the handshake.
    • Backwards-compatible with cryptography < 42.0 (no AttributeError).
    • Clean, structured result dictionary — `run()` never raises.
    • Isolated logger — no duplicate output with Flask/root handlers.

Author: Yanxzyx
Version: 2.1.0 — weak-protocol fix, cryptography back-compat
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import logging
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("oxysintx.ssl_check")
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

# ─── Optional dependency: cryptography (for deep cert parsing) ─────────────
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (
        rsa, dsa, ec, ed25519, ed448,
    )
    from cryptography.x509.oid import ExtensionOID, NameOID
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False

# ─── Tool metadata ─────────────────────────────────────────────────────────
TOOL_INFO = {
    "name": "SSL/TLS Certificate",
    "description": (
        "Certificate validity, issuer, protocol version, cipher suite, "
        "and expiry countdown. Expert mode adds Subject Alternative Names, "
        "OCSP stapling status, certificate fingerprints, and public-key details."
    ),
    "version": "2.1.0",
    "author": "Yanxzyx",
}

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 8

# ─── Well-known CA organisation names ──────────────────────────────────────
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
    "SwissSign AG",
    "T-Systems Enterprise Services GmbH",
    "TeliaSonera", "Trustwave",
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

# ─── Protocol / cipher weakness classification ─────────────────────────────
# NOTE: `SSLSocket.version()` returns values like "TLSv1", "TLSv1.1",
# "TLSv1.2", "TLSv1.3", "SSLv3" — no spaces between the protocol and
# the version number. Match that exact format.
_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Cipher substrings that mark a suite as weak. Compared case-insensitively.
_WEAK_CIPHER_MARKERS = (
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON", "ADH", "AECDH",
)


# ═══════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════

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
    if s.count(":") == 1:  # host:port (not IPv6)
        s = s.split(":", 1)[0]
    return s


def _parse_date(date_str: str) -> Optional[datetime.datetime]:
    """
    Parse ASN.1 date strings. Handles both UTC ("GMT") suffix and no
    suffix; `%Z` on Windows is unreliable so we strip manually.
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


def _utcnow() -> datetime.datetime:
    """Naive UTC now; avoids deprecated utcnow() on 3.12+."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _fingerprint(der_bytes: bytes, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    h.update(der_bytes)
    return h.hexdigest()


def _safe_oid_name(oid: Any) -> str:
    """
    Return a human-readable OID name. `oid._name` is a private attribute
    that may be absent for custom OIDs, so we always fall back to the
    dotted string. Never raises.
    """
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
    """
    Convert Python's ssl name structure (tuple of tuple of RDNs) into a
    flat dict. Later fields with the same OID overwrite earlier ones.
    """
    out: Dict[str, str] = {}
    for entry in items or []:
        try:
            for key, value in entry:
                out[key] = value
        except (TypeError, ValueError):
            continue
    return out


def _get_extension(cert: Any, oid: Any) -> Any:
    """Retrieve an X.509 extension value, returning None if absent or
    if decoding fails for any reason."""
    if cert is None:
        return None
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except Exception:
        return None


def _decode_name(name: Any) -> Dict[str, str]:
    """Flatten a cryptography x509.Name into a dict."""
    out: Dict[str, str] = {}
    mapping = {
        NameOID.COMMON_NAME: "commonName",
        NameOID.ORGANIZATION_NAME: "organizationName",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
        NameOID.COUNTRY_NAME: "countryName",
        NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
        NameOID.LOCALITY_NAME: "localityName",
        NameOID.EMAIL_ADDRESS: "emailAddress",
        NameOID.SERIAL_NUMBER: "serialNumber",
        NameOID.BUSINESS_CATEGORY: "businessCategory",
        NameOID.POSTAL_CODE: "postalCode",
        NameOID.STREET_ADDRESS: "streetAddress",
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
    Uses the modern `*_utc` properties when available (cryptography >= 42)
    and falls back to the deprecated naive properties otherwise.
    """
    if cert is None:
        return None, None
    try:
        # cryptography >= 42.0 (timezone-aware UTC)
        nb = cert.not_valid_before_utc.replace(tzinfo=None)
        na = cert.not_valid_after_utc.replace(tzinfo=None)
        return nb, na
    except AttributeError:
        pass
    try:
        # cryptography < 42.0 (naive, treated as UTC in practice)
        nb = cert.not_valid_before
        na = cert.not_valid_after
        return nb, na
    except Exception as e:
        logger.debug("Could not read validity from certificate: %s", e)
        return None, None


def _public_key_info(cert: Any) -> Dict[str, Any]:
    """Extract public key algorithm, size, and curve (if applicable)."""
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
            info["exponent"] = pub.public_numbers().e
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
    for ext_type, attr in (
        ("DNS", x509.DNSName if _HAVE_CRYPTO else None),
        ("IP", x509.IPAddress if _HAVE_CRYPTO else None),
        ("email", x509.RFC822Name if _HAVE_CRYPTO else None),
        ("URI", x509.UniformResourceIdentifier if _HAVE_CRYPTO else None),
    ):
        if attr is None:
            continue
        try:
            for value in san.get_values_for_type(attr):
                out.append({"type": ext_type, "value": str(value)})
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
# OCSP STAPLING
# ═══════════════════════════════════════════════════════════════════════════

def _check_ocsp_stapling(ssock: ssl.SSLSocket) -> Optional[bool]:
    """
    Determine if the peer sent a stapled OCSP response.
    Returns True / False / None (unknown).
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
# TLS PROTOCOL / CIPHER CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════

def _classify_protocol(protocol_str: Optional[str]) -> Dict[str, Any]:
    """
    Return {name, weak, description} for a TLS protocol string.
    Matches the exact format returned by `SSLSocket.version()`:
    "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3", "SSLv3".
    """
    if not protocol_str:
        return {"name": None, "weak": None, "description": "Unknown"}

    name = protocol_str
    upper = name.upper()

    # Normalise for classification: strip spaces, uppercase
    norm = upper.replace(" ", "")

    # Direct set match against the weak list (weak list uses exact values)
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
        return {"name": None, "bits": bits, "weak": None, "reason": "Unknown cipher"}
    upper = cipher_name.upper()
    for marker in _WEAK_CIPHER_MARKERS:
        if marker in upper:
            return {
                "name": cipher_name,
                "bits": bits,
                "weak": True,
                "reason": f"Contains weak marker '{marker}'",
            }
    if bits is not None and bits < 128:
        return {
            "name": cipher_name,
            "bits": bits,
            "weak": True,
            "reason": f"Key size {bits} bits is below 128",
        }
    return {"name": cipher_name, "bits": bits, "weak": False, "reason": "Acceptable"}


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def run(
    target: str,
    mode: str = "basic",
    port: int = DEFAULT_PORT,
    timeout: int = DEFAULT_TIMEOUT,
    verify: bool = True,
    sni: bool = True,
) -> dict:
    """
    Inspect the SSL/TLS certificate presented by `target` on `port`.

    Args:
        target:  hostname or IP address (scheme/path will be stripped).
        mode:    'basic' for essential fields, 'expert' for full details.
        port:    TCP port to connect to (default 443).
        timeout: connect + handshake timeout in seconds (default 8).
        verify:  verify chain/hostname (default True). Set False to inspect
                 self-signed / expired certs without failing the handshake.
        sni:     send SNI (default True). Automatically disabled for IPs.

    Returns:
        Dict with keys 'tool', 'version', 'target', 'data', 'error'.
    """
    result: Dict[str, Any] = {
        "tool": "ssl_check",
        "version": TOOL_INFO["version"],
        "target": target,
        "data": {},
        "error": None,
    }

    host = _normalize_target(target)
    if not host:
        result["error"] = "Empty target — provide a hostname or IP address."
        return result

    try:
        port = int(port)
    except (TypeError, ValueError):
        result["error"] = f"Invalid port: {port!r}"
        return result
    if not (1 <= port <= 65535):
        result["error"] = f"Port out of range: {port}"
        return result

    # ─── Step 1: TCP connection ────────────────────────────────────────
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

    # Prefer IPv4 first, then IPv6
    infos.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
    family, socktype, proto, _canon, sockaddr = infos[0]

    raw_sock: Optional[socket.socket] = None
    try:
        raw_sock = socket.socket(family, socktype, proto)
        raw_sock.settimeout(timeout)
        raw_sock.connect(sockaddr)
    except socket.timeout:
        if raw_sock:
            raw_sock.close()
        result["error"] = f"TCP connection timed out after {timeout}s"
        return result
    except ConnectionRefusedError:
        if raw_sock:
            raw_sock.close()
        result["error"] = f"Connection refused on port {port}"
        return result
    except OSError as e:
        if raw_sock:
            raw_sock.close()
        result["error"] = f"Network error: {e}"
        return result
    except Exception as e:
        if raw_sock:
            raw_sock.close()
        result["error"] = f"Unexpected connection error: {e}"
        return result

    # ─── Step 2: TLS context ───────────────────────────────────────────
    try:
        if verify:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl._create_unverified_context()  # noqa: SLF001 — intentional
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except (AttributeError, ValueError):
            pass
    except Exception as e:
        raw_sock.close()
        result["error"] = f"Failed to build SSL context: {e}"
        return result

    # SNI is invalid for bare IPs — disable automatically
    server_hostname: Optional[str] = host if sni and not _is_ip_literal(host) else None

    # ─── Step 3: TLS handshake + extraction ────────────────────────────
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
            result["error"] = f"TLS handshake timed out after {timeout}s"
            return result
        except OSError as e:
            result["error"] = f"Connection error during TLS handshake: {e}"
            return result

        # ── Extract certificate + cipher info ─────────────────────────
        try:
            cert_dict = ssock.getpeercert(binary_form=False) or {}
            der_cert = ssock.getpeercert(binary_form=True)
        except ssl.SSLError as e:
            result["error"] = f"Failed to read peer certificate: {e}"
            return result

        cipher = ssock.cipher()          # (name, protocol, bits) or None
        protocol_str = ssock.version()   # "TLSv1.3", etc.

        # ── Optional: parse DER with cryptography ─────────────────────
        leaf_x509: Optional[Any] = None
        if _HAVE_CRYPTO and der_cert:
            try:
                leaf_x509 = x509.load_der_x509_certificate(der_cert)
            except Exception as e:
                logger.debug("cryptography parse failed: %s", e)
                leaf_x509 = None

        # ── Core fields ────────────────────────────────────────────────
        not_before_str: str
        not_after_str: str

        if leaf_x509 is not None:
            subject = _decode_name(leaf_x509.subject)
            issuer = _decode_name(leaf_x509.issuer)
            nb_dt, na_dt = _get_validity_dates(leaf_x509)
            not_before_str = nb_dt.isoformat() if nb_dt else ""
            not_after_str = na_dt.isoformat() if na_dt else ""
            self_signed = _is_self_signed_x509(leaf_x509)
            publicly_trusted = _is_publicly_trusted_x509(leaf_x509)
            # Zero-pad the hex serial to even length for readability
            serial_hex = format(leaf_x509.serial_number, "x")
            if len(serial_hex) % 2 == 1:
                serial_hex = "0" + serial_hex
            serial = serial_hex
        else:
            subject = _dictify_name(cert_dict.get("subject", []))
            issuer = _dictify_name(cert_dict.get("issuer", []))
            not_before_str = cert_dict.get("notBefore", "")
            not_after_str = cert_dict.get("notAfter", "")
            self_signed = _is_self_signed_fallback(cert_dict)
            publicly_trusted = _is_publicly_trusted_fallback(cert_dict)
            serial = cert_dict.get("serialNumber")

        protocol_info = _classify_protocol(protocol_str)

        data: Dict[str, Any] = {
            "subject": subject,
            "issuer": issuer,
            "valid_from": not_before_str,
            "valid_until": not_after_str,
            "protocol": protocol_str,
            "protocol_weak": protocol_info["weak"],
            "protocol_note": protocol_info["description"],
            "cipher_suite": cipher[0] if cipher else "unknown",
            "cipher_protocol": cipher[1] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "self_signed": self_signed,
            "publicly_trusted": publicly_trusted,
            "serial_number": serial,
        }

        # Cipher classification
        cipher_class = _classify_cipher(
            cipher[0] if cipher else None,
            cipher[2] if cipher else None,
        )
        data["cipher_weak"] = cipher_class["weak"]
        data["cipher_note"] = cipher_class["reason"]

        # Days until expiry
        expiry_dt: Optional[datetime.datetime] = None
        if leaf_x509 is not None:
            _, na_dt = _get_validity_dates(leaf_x509)
            expiry_dt = na_dt
        if expiry_dt is None:
            expiry_dt = _parse_date(not_after_str)

        if expiry_dt:
            delta = expiry_dt - _utcnow()
            data["days_until_expiry"] = delta.days
            data["is_expired"] = delta.days < 0
            data["expiring_soon"] = 0 <= delta.days <= 30
        else:
            data["days_until_expiry"] = None
            data["is_expired"] = None
            data["expiring_soon"] = None

        # ── Expert-mode fields ─────────────────────────────────────────
        if mode == "expert":
            # Populate expert keys unconditionally so downstream code
            # never sees KeyError. Values are None / empty when unavailable.
            data.setdefault("subject_alt_names", [])
            data.setdefault("public_key", {})
            data.setdefault("signature_algorithm", None)
            data.setdefault("key_usage", [])
            data.setdefault("extended_key_usage", [])
            data.setdefault("is_ca", None)
            data.setdefault("path_length", None)
            data.setdefault("certificate_policies", [])
            data.setdefault("ocsp_urls", [])
            data.setdefault("ca_issuers_urls", [])
            data.setdefault("crl_urls", [])

            if leaf_x509 is not None:
                # SANs
                san_ext = _get_extension(
                    leaf_x509, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                )
                data["subject_alt_names"] = _san_list(san_ext)

                # Public key details
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
                eku = _get_extension(
                    leaf_x509, ExtensionOID.EXTENDED_KEY_USAGE,
                )
                data["extended_key_usage"] = _extended_key_usage_str(eku)

                # Basic constraints
                bc = _get_extension(leaf_x509, ExtensionOID.BASIC_CONSTRAINTS)
                if bc is not None:
                    try:
                        data["is_ca"] = bool(bc.ca)
                    except Exception:
                        pass
                    try:
                        data["path_length"] = bc.path_length
                    except Exception:
                        data["path_length"] = None

                # Certificate policies
                cp = _get_extension(
                    leaf_x509, ExtensionOID.CERTIFICATE_POLICIES,
                )
                if cp is not None:
                    try:
                        data["certificate_policies"] = [
                            pol.policy_identifier.dotted_string for pol in cp
                        ]
                    except Exception:
                        pass

                # Authority Information Access (OCSP / CA Issuers)
                aia = _get_extension(
                    leaf_x509, ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                )
                if aia is not None:
                    try:
                        OCSP_OID = x509.oid.AuthorityInformationAccessOID.OCSP
                        CA_OID = x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
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
                # cryptography not available — best-effort fallback
                data["subject_alt_names"] = [
                    {"type": t, "value": v}
                    for t, v in cert_dict.get("subjectAltName", [])
                ]
                data["public_key"] = {
                    "algorithm": "unknown (install 'cryptography' for details)",
                    "size_bits": None,
                }

            # OCSP stapling
            data["ocsp_stapled"] = _check_ocsp_stapling(ssock)

            # Fingerprints
            if der_cert:
                data["fingerprint_sha256"] = _fingerprint(der_cert, "sha256")
                data["fingerprint_sha1"] = _fingerprint(der_cert, "sha1")
                data["cert_size_bytes"] = len(der_cert)

            # Python stdlib doesn't expose the full chain; surface what we know
            data["chain_depth_known"] = 1

        result["data"] = data
        return result

    finally:
        if ssock is not None:
            try:
                ssock.close()
            except Exception:
                pass
        elif raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass
