"""Tech fingerprinting - flags likely CMS/framework/server from what the page already
publicly serves to any visitor (same idea as BuiltWith/Wappalyzer)."""
import re
import requests

from modules._common import default_headers

TOOL_INFO = {
    "name": "Tech Fingerprint",
    "description": "Flags likely CMS/framework/server based on public response "
    "headers and markers already present in the homepage.",
}

SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r'generator" content="WordPress'],
    "Shopify": [r"cdn\.shopify\.com", r"Shopify\.theme"],
    "Joomla": [r"/media/jui/", r'generator" content="Joomla'],
    "Drupal": [r"Drupal\.settings", r"/sites/default/files"],
    "React": [r"__NEXT_DATA__|react-root|data-reactroot"],
    "Vue.js": [r"__vue__|data-v-"],
    "Cloudflare": [r"cloudflare"],
    "Nginx": [r"nginx"],
    "Apache": [r"apache"],
    "PHP": [r"X-Powered-By.*PHP"],
}


def run(target: str, mode: str = "basic") -> dict:
    url = target if target.startswith("http") else f"https://{target}"
    try:
        resp = requests.get(url, timeout=8, headers=default_headers())
        haystack = resp.text[:200000] + " " + " ".join(f"{k}:{v}" for k, v in resp.headers.items())

        detected = [
            tech for tech, patterns in SIGNATURES.items()
            if any(re.search(p, haystack, re.IGNORECASE) for p in patterns)
        ]

        data = {
            "detected": sorted(set(detected)),
            "server_header": resp.headers.get("Server"),
            "powered_by": resp.headers.get("X-Powered-By"),
        }
        return {"tool": "tech_fingerprint", "target": target, "data": data, "error": None}
    except Exception as e:
        return {"tool": "tech_fingerprint", "target": target, "data": {}, "error": str(e)}
