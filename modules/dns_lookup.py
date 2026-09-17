"""DNS records lookup - standard public DNS resolution, same as `dig`/`nslookup`."""
import dns.resolver

TOOL_INFO = {
    "name": "DNS Records",
    "description": "Resolves A/AAAA/MX records (Basic) or adds TXT/NS/CNAME/SOA (Expert).",
}

RECORD_TYPES_BASIC = ["A", "AAAA", "MX"]
RECORD_TYPES_EXPERT = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


def run(target: str, mode: str = "basic") -> dict:
    record_types = RECORD_TYPES_EXPERT if mode == "expert" else RECORD_TYPES_BASIC
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            results[rtype] = [r.to_text() for r in answers]
        except Exception:
            results[rtype] = []

    return {"tool": "dns_lookup", "target": target, "data": results, "error": None}
