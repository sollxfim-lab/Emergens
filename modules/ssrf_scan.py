"""
SSRF (Server-Side Request Forgery) scanner.

Basic mode: purely analytical — inspects URL parameters for
request-fetching names (url=, fetch=, proxy=, redirect=, host=, …)
and reports which parameters are *candidates* for SSRF. No payloads
are sent to the target.

Expert mode: additionally injects harmless probe values into candidate
parameters (loopback IPs, internal metadata addresses, webhook-style
endpoints) and observes the response for confirmation signals — the
standard technique used by Burp Collaborator-style tooling.

Authorization: run only against targets you own or have written
permission to test.
"""
import ipaddress
import re
import socket
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

TOOL_KIND = "scanner"

TOOL_INFO = {
    "name": "SSRF Scanner",
    "description": "Finds URL-fetch parameters and, in expert mode, probes "
    "them for Server-Side Request Forgery (loopback, internal "
    "metadata service, and redirect candidates).",
    "version": "1.0.0",
}

_FETCH_PARAM_NAMES = {
    "url", "uri", "path", "dest", "destination", "domain", "site", "host",
    "ip", "src", "source", "fetch", "load", "proxy", "redirect", "next",
    "target", "rurl", "rurl", "goto", "image", "img", "file", "document",
    "folder", "pg", "php_path", "feed", "host", "port", "to", "out",
    "view", "dir", "show", "navigation", "open", "callback", "webhook",
    "endpoint", "service", "api_url", "base_url", "web", "reference",
}

_PROBE_TARGETS = [
    # (probe value, what confirmation means)
    ("127.0.0.1", "loopback"),
    ("localhost", "loopback"),
    ("169.254.169.254", "cloud-metadata"),
    ("0.0.0.0", "wildcard-bind"),
    ("[::1]", "loopback-v6"),
]

_METADATA_HOSTS = {"169.254.169.254"}
_TIMEOUT = 6.0
_UA = {"User-Agent": "Emergens-SSRF-Scanner/1.0 (+authorized-testing)"}


def _normalize_target(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t


def _is_internal(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _find_fetch_candidates(url: str) -> list:
    """Passive analysis: which query parameters look like they fetch URLs?"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    candidates = []
    for name, values in params.items():
        lname = name.lower()
        if lname in _FETCH_PARAM_NAMES or any(k in lname for k in ("url", "uri", "path", "fetch", "proxy", "redirect")):
            candidates.append({
                "parameter": name,
                "current_value": values[0] if values else "",
                "suspicion": "high" if lname in _FETCH_PARAM_NAMES else "medium",
            })
    return candidates


def _probe_parameter(url: str, param: str, mode: str) -> list:
    """Expert mode: inject probe values and observe the response."""
    findings = []
    parsed = urlparse(url)
    for probe, kind in _PROBE_TARGETS:
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [probe]
        probe_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        started = time.perf_counter()
        try:
            resp = requests.get(probe_url, headers=_UA, timeout=_TIMEOUT,
                                allow_redirects=False, verify=False)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
            body = resp.text[:4096] if resp.text else ""
            signals = []
            if kind == "cloud-metadata" and any(
                m in body.lower() for m in ("ami-id", "instance-id", "iam", "security-credentials")
            ):
                signals.append("metadata-content-echoed")
            if resp.status_code == 302 and any(
                h in (resp.headers.get("Location", "") or "").lower()
                for h in ("127.0.0.1", "localhost", "169.254")
            ):
                signals.append("redirect-to-internal")
            if resp.status_code == 200 and probe in body:
                signals.append("probe-value-reflected")
            # Metadata endpoint often responds very slowly when blocked,
            # or instantly with 200 when reachable.
            if kind == "cloud-metadata" and resp.status_code == 200:
                signals.append("metadata-endpoint-reachable")
            findings.append({
                "parameter": param,
                "probe": probe,
                "kind": kind,
                "status_code": resp.status_code,
                "elapsed_ms": elapsed_ms,
                "signals": signals,
                "confirmed": bool(signals),
            })
        except requests.exceptions.ConnectionError:
            findings.append({
                "parameter": param, "probe": probe, "kind": kind,
                "status_code": None, "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                "signals": ["connection-refused"], "confirmed": False,
            })
        except requests.exceptions.Timeout:
            findings.append({
                "parameter": param, "probe": probe, "kind": kind,
                "status_code": None, "elapsed_ms": round(_TIMEOUT * 1000, 1),
                "signals": ["timeout"], "confirmed": False,
            })
        except Exception:
            continue
    return findings


def run(target: str, mode: str = "basic") -> dict:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    url = _normalize_target(target)
    data: dict = {"scanned": url, "mode": mode}

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        resolved_ip = socket.gethostbyname(hostname)
        data["resolved_ip"] = resolved_ip
        data["target_is_internal"] = _is_internal(resolved_ip)
    except socket.gaierror:
        return {
            "tool": "ssrf_scan", "target": target, "data": data,
            "error": f"Could not resolve host: {hostname}",
        }

    candidates = _find_fetch_candidates(url)
    data["fetch_candidates"] = candidates
    data["candidate_count"] = len(candidates)

    findings = []
    if mode == "expert" and candidates:
        for cand in candidates:
            findings.extend(_probe_parameter(url, cand["parameter"], mode))
    data["findings"] = findings
    data["confirmed_findings"] = [f for f in findings if f.get("confirmed")]

    if data["confirmed_findings"]:
        risk = "high"
    elif mode == "expert" and findings:
        risk = "medium"
    elif candidates:
        risk = "low"
    else:
        risk = "info"
    data["risk"] = risk

    return {"tool": "ssrf_scan", "target": target, "data": data, "error": None}
