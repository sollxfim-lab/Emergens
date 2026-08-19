#!/usr/bin/env python3
"""
SQL Injection Scanner – Basic detection
Oxysintx Framework

Location: modules/sql_injection.py
"""

import requests
import urllib.parse
from typing import List, Dict

# Common SQLi test payloads
PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "\" OR 1=1 --",
    "' UNION SELECT NULL--",
    "' AND SLEEP(5)--",
]

def run_sql_injection(url: str, method: str = "GET", params: Dict = None) -> Dict:
    """
    Test a URL for basic SQL injection vulnerabilities.
    Returns findings with payload and response indicators.
    """
    findings = []
    session = requests.Session()
    session.verify = False
    test_url = url
    if method.upper() == "POST":
        post_data = params or {}
    else:
        params = params or {}

    for payload in PAYLOADS:
        try:
            if method.upper() == "GET":
                test_params = {k: v + payload for k, v in params.items()} if params else {'q': payload}
                resp = session.get(test_url, params=test_params, timeout=5)
            else:
                test_data = {k: v + payload for k, v in post_data.items()} if post_data else {'q': payload}
                resp = session.post(test_url, data=test_data, timeout=5)

            content = resp.text.lower()
            indicators = ['sql syntax', 'mysql_fetch', 'odbc', 'warning', 'error in your sql']
            if resp.status_code == 500 or any(ind in content for ind in indicators) or ('sleep' in payload and resp.elapsed.total_seconds() > 4):
                findings.append({
                    'payload': payload,
                    'url': test_url,
                    'method': method,
                    'status_code': resp.status_code,
                    'indicator': 'error' if resp.status_code == 500 else 'time-based' if 'sleep' in payload else 'syntax'
                })
        except Exception as e:
            continue
    return {
        'scanned': url,
        'payloads_tested': len(PAYLOADS),
        'findings': findings,
        'vulnerable': len(findings) > 0
    }