"""
Subdomain discovery.

Basic mode: queries public Certificate Transparency logs (crt.sh) only -
a fully passive lookup of data that is already public.

Expert mode: additionally resolves a short list of common subdomain
names via DNS. This is a standard, widely-used recon technique (the same
thing tools like Sublist3r/Amass do) - it is simply asking "does this DNS
name resolve?", not a password/credential brute force.
"""
import socket
import requests

TOOL_INFO = {
    "name": "Subdomain Discovery",
    "description": "Passive lookup via Certificate Transparency (crt.sh). Expert mode "
    "adds a DNS resolution check of common subdomain names.",
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel",
    "autodiscover", "api", "dev", "staging", "test", "admin", "portal",
    "vpn", "remote", "blog", "shop", "m", "app", "cdn", "static", "media",
    "support", "help", "docs", "status", "beta", "secure", "mx", "webdisk",
]


def _from_crtsh(domain: str) -> set:
    found = set()
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
        if resp.status_code == 200:
            for entry in resp.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name.endswith(domain) and "*" not in name:
                        found.add(name)
    except Exception:
        pass
    return found


def _from_dns_probe(domain: str) -> set:
    found = set()
    for sub in COMMON_SUBDOMAINS:
        candidate = f"{sub}.{domain}"
        try:
            socket.gethostbyname(candidate)
            found.add(candidate)
        except socket.gaierror:
            continue
    return found


def run(target: str, mode: str = "basic") -> dict:
    subdomains = _from_crtsh(target)
    methods = ["certificate_transparency"]

    if mode == "expert":
        subdomains |= _from_dns_probe(target)
        methods.append("dns_probe_common_names")

    return {
        "tool": "subdomain_enum",
        "target": target,
        "data": {
            "count": len(subdomains),
            "subdomains": sorted(subdomains),
            "methods_used": methods,
        },
        "error": None,
    }
