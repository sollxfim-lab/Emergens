#!/usr/bin/env python3
"""
XSS Scanner – Reflected XSS detection
Oxysintx Framework

Location: modules/xss.py
"""

import requests
from typing import Dict, List

PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
]

def run_xss(url: str, method: str = "GET", params: Dict = None) -> Dict:
    findings = []
    session = requests.Session()
    session.verify = False

    for payload in PAYLOADS:
        try:
            if method.upper() == "GET":
                resp = session.get(url, params=params or {'q': payload}, timeout=5)
            else:
                resp = session.post(url, data=params or {'q': payload}, timeout=5)
            if payload in resp.text:
                findings.append({
                    'payload': payload,
                    'url': url,
                    'method': method,
                    'reflected': True
                })
        except:
            continue
    return {
        'scanned': url,
        'payloads_tested': len(PAYLOADS),
        'findings': findings,
        'vulnerable': len(findings) > 0
    }