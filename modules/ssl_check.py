#!/usr/bin/env python3
"""
SSL/TLS Certificate Inspector — comprehensive & production-ready (v3.3.0)
=========================================================================

Reads exactly what any browser padlock shows, plus deeper fields in expert
mode. Drop-in compatible with the Emergens orchestrator: exposes
`run(target, mode)` for synchronous calls, `run_streaming(...)` for SSE,
a Flask blueprint mounted at `/api/ssl/scan`, and `self_check()` runtime
diagnostics.

----------------------------------------------------------------------------
Changelog v3.3.0
----------------------------------------------------------------------------
  ✔ VERIFIED — Response contract matches `renderSslResult()` in dashboard.js.
             Every field the padlock panel reads is now documented in
             RENDERER_CONTRACT below and always present in the response.
  ✔ NEW    — RENDERER_CONTRACT constant + `renderer_contract()` helper so
             the shape can be inspected from the CLI at any time.
  ✔ DOCS   — Testing section expanded with the badssl.com matrix
             (self-signed / expired / wrong-host / untrusted-root) that
             exercises the unverified-retry path end-to-end.
  ✔ DOCS   — Acknowledgment section aligned with the Emergens dashboard.
  ✔ HARD   — All v3.2.0 behavior preserved (unverified retry, flattened
             convenience fields, expert enrichment, Flask blueprint).

----------------------------------------------------------------------------
Changelog v3.2.0 (from v3.1.0)
----------------------------------------------------------------------------
  ✔ FIXED  — UI showed `--` for Subject / Issuer / Protocol / Days Left
             whenever the TLS handshake failed certificate verification
             (self-signed, expired, hostname mismatch, untrusted CA).
             The check now retries the handshake with verification OFF
             and still extracts the full certificate, reporting the
             verification failure separately via `data.verified` /
             `data.verify_error`.
  ✔ NEW    — Flattened convenience fields: `subject_str`, `issuer_str`,
             `common_name`, `issuer_cn`, `issuer_org`,
             `cipher_strength_bits`, `chain_length`.
  ✔ NEW    — `_connect_tls()` helper.

----------------------------------------------------------------------------
Renderer contract — verified against dashboard.js `renderSslResult()`
----------------------------------------------------------------------------
The dashboard reads the following fields from `result["data"]` (basic mode):

    subject              dict   {commonName, organizationName, ...}
    issuer               dict   {commonName, organizationName, ...}
    subject_str          str    "CN=example.com · O=Example Inc · C=US"
    issuer_str           str    flattened issuer DN
    common_name          str    subject CN ("" if absent)
    issuer_cn            str    issuer CN
    issuer_org           str    issuer organization
    valid_from           str    ISO-8601
    valid_until          str    ISO-8601
    protocol             str    "TLSv1.3" / "TLSv1.2" / ...
    protocol_weak        bool
    protocol_note        str
    cipher_suite         str
    cipher_protocol      str
    cipher_bits          int
    cipher_strength_bits int    (alias of cipher_bits)
    cipher_weak          bool
    cipher_note          str
    self_signed          bool
    publicly_trusted     bool | null
    serial_number        str    hex
    chain_length         int
    days_until_expiry    int    (negative if expired)
    days_left            int    (alias)
    is_expired           bool
    expiring_soon        bool
    verified             bool   False when unverified retry succeeded
    verify_error         str | null

Expert mode additionally populates:

    subject_alt_names       list[{type, value}]
    public_key              dict{algorithm, size_bits, curve?, exponent?}
    signature_algorithm     str
    key_usage               list[str]
    extended_key_usage      list[str]
    certificate_policies    list[str]
    is_ca                   bool
    path_length             int | null
    ocsp_stapled            bool | null
    ocsp_urls               list[str]
    ca_issuers_urls         list[str]
    crl_urls                list[str]
    fingerprint_sha256      str
    fingerprint_sha1        str
    fingerprint_sha512      str
    cert_size_bytes         int
    chain_fingerprints      list[{index, role, subject_cn, fingerprint_sha256, ...}]
    chain_validation        dict{length, linked, has_root, expired_certs, ...}

After a successful TCP + TLS handshake, `data` is guaranteed non-empty and
the four padlock KPIs (Days Left / Protocol / Cipher Strength / Chain Certs)
are always populated — the only way `data` stays empty is if the handshake
itself failed, in which case `result["error"]` explains why.

----------------------------------------------------------------------------
Acknowledgment
----------------------------------------------------------------------------
  • Author        : Yanxzyx  (#credit ~ Yanxzyx)
  • Framework     : Emergens / Oxysintx orchestrator stack
  • Dashboard     : dashboard.js (renderSslResult) — the exact consumer of
                    this module's response shape; both the flattened
                    convenience fields (v3.2.0) and the unverified retry
                    (v3.2.0) were added specifically so the padlock panel
                    never shows `--` on a reachable host.
  • Dependencies  : stdlib `ssl` (3.10+ chain APIs) + optional
                    `cryptography` for deep X.509 introspection,
                    `Flask` for the /api/ssl/scan endpoint
  • References    : RFC 5280 (X.509), RFC 6960 (OCSP), RFC 8446 (TLS 1.3),
                    RFC 6797 (HSTS), RFC 6125 (SNI / identity).
  • With thanks to the CPython `ssl` maintainers for exposing
    `get_unverified_chain()` and the `cryptography` team for a sane
    X.509 object model.

----------------------------------------------------------------------------
Testing
----------------------------------------------------------------------------
  Runtime diagnostics:
      python3 -m modules.ssl_check --self-check

  CLI smoke tests:
      python3 -m modules.ssl_check example.com
      python3 -m modules.ssl_check example.com --mode expert
      python3 -m modules.ssl_check --json example.com | jq .data.subject

  Unverified-retry path — exercises every failure mode the fix addresses:
      python3 -m modules.ssl_check self-signed.badssl.com     # self-signed
      python3 -m modules.ssl_check expired.badssl.com         # expired
      python3 -m modules.ssl_check wrong.host.badssl.com      # CN mismatch
      python3 -m modules.ssl_check untrusted-root.badssl.com  # bad root
      # → each should still show Subject / Issuer / Protocol / Days Left
      #   and set data.verified=false + data.verify_error.

  Programmatic:
      from modules.ssl_check import run, self_check, renderer_contract
      print(self_check())                        # runtime diagnostics
      print(renderer_contract())                 # response-shape reference
      r = run("example.com", mode="expert")
      assert r["error"] is None
      assert isinstance(r["data"]["subject"], dict)
      assert isinstance(r["data"]["issuer"], dict)

  Flask wiring (in app.py):
      from modules.ssl_check import register_blueprint
      register_blueprint(app)

  Dashboard integration smoke test:
      curl -sX POST localhost:5000/api/ssl/scan \\
        -H 'Content-Type: application/json' \\
        -d '{"target":"example.com","mode":"expert"}' | jq .data.subject
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
__version__ = "3.3.0"
__author__  = "Yanxzyx"
__credit__  = "#credit ~ Yanxzyx"
__all__ = [
    "run", "ssl_check", "check_ssl", "scan_ssl", "scan_ssl_check",
    "ssl_scan", "run_streaming", "scan_many",
    "self_check", "renderer_contract", "register_blueprint",
    "SSLChecker", "SSLConfig", "TOOL_INFO", "TOOL_KIND",
]

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
# RENDERER CONTRACT — matches dashboard.js `renderSslResult()`
# ═══════════════════════════════════════════════════════════════════════════
RENDERER_CONTRACT: Dict[str, Any] = {
    "consumer": "dashboard.js :: renderSslResult()",
    "basic_fields": {
        "subject":              "dict   — decoded X.509 name {commonName, organizationName, ...}",
        "issuer":               "dict   — decoded X.509 name",
        "subject_str":          "str    — flattened DN: 'CN=… · O=… · C=…'",
        "issuer_str":           "str    — flattened issuer DN",
        "common_name":          "str    — subject CN ('' when absent)",
        "issuer_cn":            "str",
        "issuer_org":           "str",
        "valid_from":           "str    — ISO-8601",
        "valid_until":          "str    — ISO-8601",
        "protocol":             "str    — 'TLSv1.3' | 'TLSv1.2' | …",
        "protocol_weak":        "bool",
        "protocol_note":        "str",
        "cipher_suite":         "str",
        "cipher_protocol":      "str",
        "cipher_bits":          "int",
        "cipher_strength_bits": "int    — alias of cipher_bits",
        "cipher_weak":          "bool",
        "cipher_note":          "str",
        "self_signed":          "bool",
        "publicly_trusted":     "bool | null",
        "serial_number":        "str    — hex",
        "chain_length":         "int",
        "days_until_expiry":    "int    — negative if expired",
        "days_left":            "int    — alias",
        "is_expired":           "bool",
        "expiring_soon":        "bool",
        "verified":             "bool   — False when unverified retry succeeded",
        "verify_error":         "str | null",
    },
    "expert_fields": {
        "subject_alt_names":    "list[{type, value}]",
        "public_key":           "dict{algorithm, size_bits, curve?, exponent?}",
        "signature_algorithm":  "str",
        "key_usage":            "list[str]",
        "extended_key_usage":   "list[str]",
        "certificate_policies": "list[str]",
        "is_ca":                "bool | null",
        "path_length":          "int | null",
        "ocsp_stapled":         "bool | null",
        "ocsp_urls":            "list[str]",
        "ca_issuers_urls":      "list[str]",
        "crl_urls":             "list[str]",
        "fingerprint_sha256":   "str",
        "fingerprint_sha1":     "str",
        "fingerprint_sha512":   "str",
        "cert_size_bytes":      "int",
        "chain_fingerprints":   "list[{index, role, subject_cn, fingerprint_sha256, ...}]",
        "chain_validation":     "dict{length, linked, has_root, expired_certs, ...}",
    },
    "guarantees": [
        "After TCP+TLS handshake, `data` is always non-empty.",
        "`subject` and `issuer` are always dicts (never None/list/str).",
        "Padlock KPIs (protocol, cipher_bits, chain_length, days_until_expiry) "
        "are always present.",
        "Unverified retry populates every basic field and sets "
        "`verified=false` + `verify_error`.",
    ],
}


def renderer_contract() -> Dict[str, Any]:
    """Return the response-shape reference for dashboard.js consumers."""
    return _json.loads(_json.dumps(RENDERER_CONTRACT))


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

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

_WEAK_CIPHER_MARKERS = (
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON", "ADH", "AECDH",
)

_DN_SHORT = {
    "commonName":              "CN",
    "organizationName":        "O",
    "organizationalUnitName":  "OU",
    "countryName":             "C",
    "stateOrProvinceName":     "ST",
    "localityName":            "L",
    "emailAddress":            "E",
    "serialNumber":            "serialNumber",
}


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


def _format_dict_dn(dn: Dict[str, str]) -> str:
    """Format a decoded-DN dict into an RFC 2253-ish single-line string."""
    if not dn:
        return ""
    order = ["commonName", "organizationName", "organizationalUnitName",
             "localityName", "stateOrProvinceName", "countryName",
             "emailAddress"]
    parts: List[str] = []
    seen = set()
    for key in order:
        if key in dn and dn[key]:
            parts.append(f"{_DN_SHORT.get(key, key)}={dn[key]}")
            seen.add(key)
    for key, value in dn.items():
        if key in seen or not value:
            continue
        parts.append(f"{_DN_SHORT.get(key, key)}={value}")
    return ", ".join(parts)


def _format_x509_dn(name: Any) -> str:
    """Format an x509.Name object as an RFC 2253-ish string."""
    if name is None:
        return ""
    try:
        return _format_dict_dn(_decode_name(name))
    except Exception:
        return ""


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
# CHAIN EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════
def _extract_chain_der(ssock: ssl.SSLSocket) -> List[bytes]:
    """Return the DER chain as a list of bytes, leaf first."""
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
# CONFIG + CORE CHECKER
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

        server_hostname: Optional[str] = (
            host if self.config.sni and not _is_ip_literal(host) else None
        )

        # ── TLS handshake (with graceful verify fallback) ────────────
        ssock: Optional[ssl.SSLSocket] = None
        verify_error: Optional[str] = None
        used_verify = self.config.verify

        try:
            ssock = self._connect_tls(
                sockaddr, family, socktype, proto,
                server_hostname, verify=self.config.verify,
            )
        except ssl.SSLCertVerificationError as e:
            msg = getattr(e, "verify_message", None) or str(e)
            if self.config.verify:
                logger.info("Verification failed (%s) — retrying unverified "
                            "to still extract certificate details.", msg)
                verify_error = msg
                used_verify = False
                try:
                    ssock = self._connect_tls(
                        sockaddr, family, socktype, proto,
                        server_hostname, verify=False,
                    )
                except socket.timeout:
                    result["error"] = (
                        f"TLS handshake timed out after "
                        f"{self.config.handshake_timeout}s"
                    )
                    return result
                except Exception as e2:
                    result["error"] = (
                        f"Certificate verification failed: {msg} "
                        f"(unverified fallback also failed: {e2})"
                    )
                    return result
            else:
                result["error"] = f"Certificate verification failed: {msg}"
                return result
        except socket.timeout:
            result["error"] = (f"TCP/TLS handshake timed out after "
                               f"{self.config.handshake_timeout}s")
            return result
        except ConnectionRefusedError:
            result["error"] = f"Connection refused on port {port}"
            return result
        except ssl.SSLError as e:
            result["error"] = f"TLS handshake failed: {e}"
            return result
        except OSError as e:
            result["error"] = f"Network error: {e}"
            return result
        except Exception as e:
            result["error"] = f"Unexpected TLS error: {e}"
            return result

        # ── Extract certificate data ──────────────────────────────────
        try:
            data = self._extract_data(
                ssock, host, port, mode, verify_error, used_verify,
            )
            result["data"] = data
            return result
        finally:
            try:
                ssock.close()
            except Exception:
                pass

    # ── Internals ─────────────────────────────────────────────────────
    def _connect_tls(self,
                     sockaddr: Any,
                     family: int,
                     socktype: int,
                     proto: int,
                     server_hostname: Optional[str],
                     verify: bool) -> ssl.SSLSocket:
        """Do TCP connect + TLS handshake. Caller owns returned socket."""
        raw = socket.socket(family, socktype, proto)
        raw.settimeout(self.config.connect_timeout)
        try:
            raw.connect(sockaddr)
        except Exception:
            try: raw.close()
            except Exception: pass
            raise

        try:
            ctx = (ssl.create_default_context()
                   if verify else ssl._create_unverified_context())  # noqa: SLF001
            min_ver = self._resolve_min_version()
            if min_ver is not None:
                try:
                    ctx.minimum_version = min_ver
                except (AttributeError, ValueError):
                    pass

            raw.settimeout(self.config.handshake_timeout)
            ssock = ctx.wrap_socket(raw, server_hostname=server_hostname)
            return ssock
        except Exception:
            try: raw.close()
            except Exception: pass
            raise

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

    def _extract_data(self,
                      ssock: ssl.SSLSocket,
                      host: str,
                      port: int,
                      mode: str,
                      verify_error: Optional[str],
                      used_verify: bool) -> Dict[str, Any]:
        """Build the `data` dict from a live SSLSocket. Never raises."""
        try:
            cert_dict = ssock.getpeercert(binary_form=False) or {}
        except Exception:
            cert_dict = {}
        try:
            der_leaf = ssock.getpeercert(binary_form=True)
        except Exception:
            der_leaf = None

        try:
            cipher = ssock.cipher()
        except Exception:
            cipher = None
        try:
            protocol_str = ssock.version()
        except Exception:
            protocol_str = None

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

        # ── Core subject / issuer / validity ─────────────────────────
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
            subject_str = _format_x509_dn(leaf_x509.subject)
            issuer_str  = _format_x509_dn(leaf_x509.issuer)
        else:
            subject  = _dictify_name(cert_dict.get("subject", []))
            issuer   = _dictify_name(cert_dict.get("issuer", []))
            not_before_str = cert_dict.get("notBefore", "") or ""
            not_after_str  = cert_dict.get("notAfter", "") or ""
            self_signed    = _is_self_signed_fallback(cert_dict)
            publicly_trusted = _is_publicly_trusted_fallback(cert_dict)
            serial = cert_dict.get("serialNumber")
            subject_str = _format_dict_dn(subject)
            issuer_str  = _format_dict_dn(issuer)

        if not isinstance(subject, dict):
            subject = {}
        if not isinstance(issuer, dict):
            issuer = {}

        protocol_info = _classify_protocol(protocol_str)
        cipher_class  = _classify_cipher(
            cipher[0] if cipher else None,
            cipher[2] if cipher else None,
        )

        data: Dict[str, Any] = {
            # ── Core (dashboard.js reads these) ─────────────────────
            "subject":          subject,
            "issuer":           issuer,

            # ── Flattened convenience fields ────────────────────────
            "subject_str":      subject_str,
            "issuer_str":       issuer_str,
            "common_name":      subject.get("commonName", "") or "",
            "issuer_cn":        issuer.get("commonName", "") or "",
            "issuer_org":       issuer.get("organizationName", "") or "",

            # ── Validity ────────────────────────────────────────────
            "valid_from":       not_before_str,
            "valid_until":      not_after_str,
            "not_before":       not_before_str,
            "not_after":        not_after_str,

            # ── Protocol ────────────────────────────────────────────
            "protocol":         protocol_str,
            "protocol_weak":    protocol_info["weak"],
            "protocol_note":    protocol_info["description"],

            # ── Cipher ──────────────────────────────────────────────
            "cipher_suite":        cipher[0] if cipher else "unknown",
            "cipher_protocol":     cipher[1] if cipher else None,
            "cipher_bits":         cipher[2] if cipher else None,
            "cipher_strength_bits": cipher[2] if cipher else None,
            "cipher_weak":         cipher_class["weak"],
            "cipher_note":         cipher_class["reason"],

            # ── Identity ────────────────────────────────────────────
            "self_signed":      self_signed,
            "publicly_trusted": publicly_trusted,
            "serial_number":    serial,

            # ── Verification result ─────────────────────────────────
            "verified":         bool(used_verify and not verify_error),
            "verify_error":     verify_error,

            # ── Chain ───────────────────────────────────────────────
            "chain_length":      len(chain_der),
            "chain_depth_known": len(chain_der),

            # ── Connection ──────────────────────────────────────────
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
            data["days_left"]         = delta.days
            data["is_expired"]        = delta.days < 0
            data["expiring_soon"]     = 0 <= delta.days <= 30
        else:
            data["days_until_expiry"] = None
            data["days_left"]         = None
            data["is_expired"]        = None
            data["expiring_soon"]     = None

        # ── Expert mode ─────────────────────────────────────────
        if mode == "expert":
            try:
                self._populate_expert(data, leaf_x509, chain_der,
                                      chain_x509, cert_dict, ssock)
            except Exception as e:
                logger.warning("Expert enrichment failed: %s", e)

        return data

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
        "renderer":     "dashboard.js :: renderSslResult()",
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

        Response shape — see RENDERER_CONTRACT / renderSslResult().
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
    d = r.get("data") or {}
    subj = (d.get("common_name")
            or (d.get("subject") or {}).get("commonName")
            or "(no CN)")
    iss  = (d.get("issuer_org")
            or (d.get("issuer") or {}).get("organizationName")
            or "(unknown)")
    prot = d.get("protocol") or "?"
    exp  = d.get("days_until_expiry")
    tag  = "⚠ weak" if d.get("protocol_weak") else "✓"
    if d.get("verified") is False:
        tag = "⚠ unverified"
    print(f"[OK]   {r['target']:40s}  {subj:35s}  {prot:8s}  "
          f"expires in {exp} days  {tag}")
    print(f"        issuer: {iss}")
    if d.get("chain_length"):
        print(f"        chain : {d['chain_length']} cert(s)")
    if d.get("verify_error"):
        print(f"        verify: {d['verify_error']}")


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
    ap.add_argument("--contract", action="store_true",
                    help="print the dashboard renderer contract and exit")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args()

    if args.contract:
        print(_json.dumps(renderer_contract(), indent=2))
        return 0

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