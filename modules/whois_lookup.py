"""WHOIS lookup — passive domain registration intelligence.

Same public data any WHOIS site exposes, presented with a clean two-tier view:

    Basic  — the essentials: registrar, key dates, and an at-a-glance expiry
             countdown / domain age so you instantly see the domain's health.
    Expert — everything Basic returns plus nameservers, full status codes,
             DNSSEC, WHOIS server, registrar URL, organisation/country and any
             disclosed contact emails.

No active probing is performed — this only queries the registry's WHOIS record.

Author: Yanxzyx
"""

from datetime import datetime, timezone

import whois as pywhois

TOOL_INFO = {
    "name": "WHOIS Lookup",
    "version": "2.0.0",
    "description": (
        "Domain registration intelligence: registrar, creation/expiry dates, and a "
        "live expiry countdown + domain age. Expert mode adds nameservers, status "
        "codes, DNSSEC, WHOIS server, organisation/country and disclosed emails."
    ),
    "author": "Yanxzyx",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _as_str(value):
    """Coerce a WHOIS field to a str / list[str] / None without losing data."""
    if isinstance(value, list):
        cleaned = [str(v).strip() for v in value if v is not None and str(v).strip()]
        # De-duplicate while preserving order (WHOIS often repeats values)
        seen = set()
        result = []
        for item in cleaned:
            key = item.lower()
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result or None
    if value is None:
        return None
    return str(value).strip() or None


def _first_datetime(value):
    """WHOIS date fields are often a datetime or a list of them — return the first."""
    if isinstance(value, list):
        for v in value:
            if isinstance(v, datetime):
                return v
        return None
    return value if isinstance(value, datetime) else None


def _iso(value):
    """Human/ISO friendly rendering of a WHOIS date value (or list)."""
    dt = _first_datetime(value)
    if dt is not None:
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt.tzinfo is None else dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return _as_str(value)


def _days_between(dt, *, future: bool):
    """Whole days from now to `dt` (future=True) or from `dt` to now (future=False)."""
    dt = _first_datetime(dt)
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = (dt - now) if future else (now - dt)
    return int(delta.total_seconds() // 86400)


def _normalize_domain(target: str) -> str:
    """Strip scheme, path, port and a leading www. so the registry gets a bare domain."""
    t = (target or "").strip()
    for scheme in ("https://", "http://"):
        if t.lower().startswith(scheme):
            t = t[len(scheme):]
            break
    t = t.split("/")[0].split(":")[0].strip()
    if t.lower().startswith("www."):
        t = t[4:]
    return t


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run(target: str, mode: str = "basic", **kwargs) -> dict:
    domain = _normalize_domain(target)
    try:
        w = pywhois.whois(domain)

        # A missing domain_name is python-whois's signal that nothing was found.
        if not w or w.domain_name is None:
            return {
                "tool": "whois_lookup",
                "version": TOOL_INFO["version"],
                "target": target,
                "data": {"queried_domain": domain, "found": False},
                "error": "No WHOIS record found (domain may be unregistered or the TLD is not supported).",
            }

        days_to_expiry = _days_between(w.expiration_date, future=True)
        domain_age_days = _days_between(w.creation_date, future=False)

        data = {
            "queried_domain": domain,
            "found": True,
            "domain_name": _as_str(w.domain_name),
            "registrar": _as_str(w.registrar),
            "creation_date": _iso(w.creation_date),
            "expiration_date": _iso(w.expiration_date),
            "updated_date": _iso(w.updated_date),
            "days_until_expiry": days_to_expiry,
            "domain_age_days": domain_age_days,
            "is_expired": (days_to_expiry is not None and days_to_expiry < 0),
            "expiring_soon": (days_to_expiry is not None and 0 <= days_to_expiry <= 30),
        }

        if mode == "expert":
            data.update(
                {
                    "name_servers": _as_str(w.name_servers),
                    "status": _as_str(w.status),
                    "dnssec": _as_str(getattr(w, "dnssec", None)),
                    "whois_server": _as_str(getattr(w, "whois_server", None)),
                    "registrar_url": _as_str(getattr(w, "registrar_url", None)),
                    "emails": _as_str(w.emails),
                    "org": _as_str(getattr(w, "org", None)),
                    "registrant_name": _as_str(getattr(w, "name", None)),
                    "country": _as_str(getattr(w, "country", None)),
                    "state": _as_str(getattr(w, "state", None)),
                    "city": _as_str(getattr(w, "city", None)),
                }
            )

        return {
            "tool": "whois_lookup",
            "version": TOOL_INFO["version"],
            "target": target,
            "data": data,
            "error": None,
        }
    except Exception as e:
        return {
            "tool": "whois_lookup",
            "version": TOOL_INFO["version"],
            "target": target,
            "data": {"queried_domain": domain, "found": False},
            "error": str(e),
        }
