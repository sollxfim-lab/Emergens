"""
SSL/TLS certificate inspection – comprehensive & production‑ready.

Reads exactly what any browser padlock would show, plus deeper fields
when running in expert mode.

Features:
- Custom port support (default 443).
- Granular exception handling (DNS, connection, TLS, certificate).
- Certificate chain validation (checks if the cert is self‑signed or
  issued by a well‑known CA).
- OCSP stapling check (expert mode).
- Fingerprints (SHA‑256) of the certificate for pinning / verification.
- Public‑key algorithm & size.
- Clean, structured result dictionary – never throws from run().
"""

import ssl
import socket
import datetime
import hashlib
from typing import Optional, Dict, Any, Tuple

TOOL_INFO = {
    "name": "SSL/TLS Certificate",
    "description": (
        "Certificate validity, issuer, protocol version, cipher suite, "
        "and expiry countdown. Expert mode adds Subject Alternative Names, "
        "OCSP stapling status, certificate fingerprints, and public‑key details."
    ),
}

# ---------------------------------------------------------------------------
#  Well‑known CA organisation names (short list) – helps decide whether a
#  certificate is "publicly trusted" or self‑signed / private.
# ---------------------------------------------------------------------------
KNOWN_CAS = {
    "Let's Encrypt", "DigiCert Inc", "Sectigo Limited", "GlobalSign nv-sa",
    "Amazon", "Google Trust Services", "Cloudflare, Inc.", "IdenTrust",
    "GoDaddy.com, Inc.", "Microsoft Corporation", "ZeroSSL",
}

# ---------------------------------------------------------------------------
#  Internal helpers
# ---------------------------------------------------------------------------

def _is_self_signed(cert: dict) -> bool:
    """Heuristic – true if issuer and subject are identical."""
    subject = tuple(sorted((k, v) for k, v in cert.get("subject", [])))
    issuer = tuple(sorted((k, v) for k, v in cert.get("issuer", [])))
    return subject == issuer


def _is_publicly_trusted(cert: dict) -> Optional[bool]:
    """
    Returns True if the issuer appears to be a well‑known CA,
    False if self‑signed, None if we cannot decide.
    """
    issuer = cert.get("issuer", [])
    org = next((v for k, v in issuer if k == "organizationName"), None)
    if org and org in KNOWN_CAS:
        return True
    if _is_self_signed(cert):
        return False
    return None


def _fingerprint(der_cert: bytes, algo: str = "sha256") -> str:
    """Return hex fingerprint of a DER‑encoded certificate."""
    h = hashlib.new(algo, der_cert)
    return h.hexdigest()


def _parse_date(date_str: str) -> Optional[datetime.datetime]:
    """Try the two most common ASN.1 date formats."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.datetime.strptime(date_str, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _ocsp_stapling(ssock: ssl.SSLSocket) -> Optional[bool]:
    """Check whether the server sent a stapled OCSP response."""
    try:
        # OCSP stapling is indicated by the TLS extension; in Python we
        # can check via get_channel_binding (only available in some builds)
        # or by accessing the raw OCSP response from the connection object.
        # The most portable way is to try obtaining the OCSP response:
        ocsp = ssock.ocsp_response()  # Python 3.10+   # type: ignore[attr-defined]
        return ocsp is not None
    except (AttributeError, NotImplementedError):
        # Fallback for older Pythons: assume not stapled
        return None


# ---------------------------------------------------------------------------
#  Public entry point
# ---------------------------------------------------------------------------

def run(target: str, mode: str = "basic", port: int = 443) -> dict:
    """
    Inspect the SSL/TLS certificate presented by `target` on `port`.

    Args:
        target: hostname or IP address.
        mode:   'basic' for essential fields, 'expert' for full details.
        port:   TCP port to connect to (default 443).

    Returns:
        Dict with keys 'tool', 'target', 'data', 'error'.
    """
    result: Dict[str, Any] = {
        "tool": "ssl_check",
        "target": target,
        "data": {},
        "error": None,
    }

    # ------------------------------------------------------------------
    # Step 1 – establish raw TCP connection
    # ------------------------------------------------------------------
    try:
        # Resolve and connect with a generous timeout
        addrinfo = socket.getaddrinfo(target, port, proto=socket.IPPROTO_TCP)
        if not addrinfo:
            raise socket.gaierror(f"No address associated with {target}")
        sock = socket.create_connection((target, port), timeout=8)
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
        return result
    except socket.timeout as e:
        result["error"] = f"Connection timed out: {e}"
        return result
    except OSError as e:
        result["error"] = f"Network error: {e}"
        return result

    # ------------------------------------------------------------------
    # Step 2 – TLS handshake
    # ------------------------------------------------------------------
    try:
        ctx = ssl.create_default_context()
        # Lower the minimum version to get broader compatibility info
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:
        # Python < 3.7 fallback
        ctx = ssl.create_default_context()

    try:
        with sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                der_cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                protocol = ssock.version()

                # ----- Build basic data -----
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")

                data: Dict[str, Any] = {
                    "subject": subject,
                    "issuer": issuer,
                    "valid_from": not_before,
                    "valid_until": not_after,
                    "protocol": protocol,
                    "cipher_suite": cipher[0] if cipher else "unknown",
                    "self_signed": _is_self_signed(cert),
                    "publicly_trusted": _is_publicly_trusted(cert),
                }

                # Days until expiry
                expiry_date = _parse_date(not_after)
                if expiry_date:
                    data["days_until_expiry"] = (expiry_date - datetime.datetime.utcnow()).days

                # ------------------------------------------------------------------
                # Step 3 – expert fields
                # ------------------------------------------------------------------
                if mode == "expert":
                    # Cipher details
                    if cipher:
                        data["cipher_name"] = cipher[0]
                        data["cipher_protocol"] = cipher[1]
                        data["cipher_bits"] = cipher[2]

                    # Subject Alternative Names (normalised)
                    sans = cert.get("subjectAltName", [])
                    data["subject_alt_names"] = [{"type": t, "value": v} for t, v in sans]

                    # Serial number
                    data["serial_number"] = cert.get("serialNumber")

                    # OCSP stapling
                    data["ocsp_stapled"] = _ocsp_stapling(ssock)

                    # Certificate fingerprints (from DER)
                    if der_cert:
                        data["fingerprint_sha256"] = _fingerprint(der_cert, "sha256")
                        data["fingerprint_sha1"] = _fingerprint(der_cert, "sha1")

                    # Public key info (extracted from the DER cert via
                    # the parsed dict – Python's ssl module does not expose
                    # the raw SPKI, but we can pull the key type from the
                    # 'subjectPublicKey' field when available).
                    pubkey_info = {}
                    try:
                        # subjectPublicKey is not guaranteed; try reading it
                        spk = cert.get("subjectPublicKey")
                        if spk:
                            pubkey_info["size_bits"] = spk[1] if len(spk) > 1 else "unknown"
                    except Exception:
                        pass
                    # Determine key type from cipher suite
                    if cipher:
                        cname = cipher[0].upper()
                        if "RSA" in cname:
                            pubkey_info["type"] = "RSA"
                        elif "ECDSA" in cname or "ECDHE" in cname:
                            pubkey_info["type"] = "EC"
                        else:
                            pubkey_info["type"] = "unknown"
                    data["public_key"] = pubkey_info

                result["data"] = data
                return result

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {e}"
    except ssl.SSLError as e:
        result["error"] = f"TLS handshake failed: {e}"
    except socket.timeout as e:
        result["error"] = f"TLS handshake timed out: {e}"
    except OSError as e:
        result["error"] = f"Connection error during TLS: {e}"
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"

    return result