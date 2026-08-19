"""WHOIS lookup - passive domain registration info (same as any public WHOIS site)."""
import whois as pywhois

TOOL_INFO = {
    "name": "WHOIS Lookup",
    "description": "Domain registration info: registrar, creation/expiry dates. "
    "Expert mode adds nameservers, status, and contact emails where disclosed.",
}


def _as_str(value):
    if isinstance(value, list):
        return [str(v) for v in value]
    if value is None:
        return None
    return str(value)


def run(target: str, mode: str = "basic") -> dict:
    try:
        w = pywhois.whois(target)
        data = {
            "domain_name": _as_str(w.domain_name),
            "registrar": _as_str(w.registrar),
            "creation_date": _as_str(w.creation_date),
            "expiration_date": _as_str(w.expiration_date),
        }
        if mode == "expert":
            data.update(
                {
                    "updated_date": _as_str(w.updated_date),
                    "name_servers": _as_str(w.name_servers),
                    "status": _as_str(w.status),
                    "emails": _as_str(w.emails),
                    "org": _as_str(getattr(w, "org", None)),
                    "country": _as_str(getattr(w, "country", None)),
                }
            )
        return {"tool": "whois_lookup", "target": target, "data": data, "error": None}
    except Exception as e:
        return {"tool": "whois_lookup", "target": target, "data": {}, "error": str(e)}
