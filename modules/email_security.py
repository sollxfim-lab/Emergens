"""Email security posture - reads public SPF/DMARC DNS TXT records, and (Expert)
checks a handful of common DKIM selector names."""
import dns.resolver

TOOL_INFO = {
    "name": "Email Security (SPF/DKIM/DMARC)",
    "description": "Reads SPF and DMARC DNS records. Expert mode probes a few "
    "common DKIM selector names.",
}

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail"]


def run(target: str, mode: str = "basic") -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    data = {}

    try:
        txt_records = resolver.resolve(target, "TXT")
        spf = [r.to_text() for r in txt_records if "v=spf1" in r.to_text()]
        data["spf"] = spf[0] if spf else None
    except Exception:
        data["spf"] = None

    try:
        dmarc_records = resolver.resolve(f"_dmarc.{target}", "TXT")
        data["dmarc"] = dmarc_records[0].to_text() if dmarc_records else None
    except Exception:
        data["dmarc"] = None

    if mode == "expert":
        found_dkim = {}
        for sel in DKIM_SELECTORS:
            try:
                rec = resolver.resolve(f"{sel}._domainkey.{target}", "TXT")
                found_dkim[sel] = rec[0].to_text()
            except Exception:
                continue
        data["dkim_selectors_found"] = found_dkim

    return {"tool": "email_security", "target": target, "data": data, "error": None}
