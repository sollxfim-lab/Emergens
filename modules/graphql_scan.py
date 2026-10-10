"""
GraphQL endpoint analyzer.

Basic mode: passively checks the conventional GraphQL paths
(/graphql, /api/graphql, /graphiql, ...) and reports which respond
and whether the interactive GraphiQL / Playground IDE is exposed.

Expert mode: additionally sends a harmless introspection query
(`{ __schema { queryType { name } } }`) to determine whether
introspection is enabled — the standard first step in GraphQL
security review.
"""
import requests

TOOL_KIND = "scanner"

TOOL_INFO = {
    "name": "GraphQL Analyzer",
    "description": "Discovers GraphQL endpoints, checks IDE exposure and, in "
    "expert mode, whether schema introspection is enabled.",
    "version": "1.0.0",
}

_COMMON_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphql/console",
    "/graphiql",
    "/playground",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/graphql/batch",
]

_INTROSPECTION_QUERY = {"query": "{ __schema { queryType { name } } }"}
_TIMEOUT = 6.0
_UA = {"User-Agent": "Emergens-GraphQL-Scanner/1.0 (+authorized-testing)",
       "Content-Type": "application/json"}


def _normalize(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t.rstrip("/")


def _probe(base: str, path: str, do_introspection: bool) -> dict:
    url = base + path
    result: dict = {"path": path, "url": url}
    try:
        resp = requests.get(url, headers=_UA, timeout=_TIMEOUT, verify=False, allow_redirects=False)
        result["status_code"] = resp.status_code
        body_head = (resp.text or "")[:2048].lower()
        result["ide_exposed"] = any(
            k in body_head for k in ("graphiql", "apollo studio", "graphql-playground", "altair")
        )
        if resp.status_code >= 400:
            result["exists"] = False
            return result
        result["exists"] = True
    except Exception as e:
        result["error"] = str(e)
        result["exists"] = False
        return result

    if do_introspection:
        try:
            iresp = requests.post(url, json=_INTROSPECTION_QUERY, headers=_UA,
                                  timeout=_TIMEOUT, verify=False)
            itext = (iresp.text or "")[:2048]
            if iresp.status_code == 200 and "__schema" in itext:
                result["introspection_enabled"] = True
            elif "introspection" in itext.lower() and iresp.status_code in (400, 403):
                result["introspection_enabled"] = False
            elif iresp.status_code == 400 and "query" in itext.lower():
                # Parse errors usually mean the endpoint IS GraphQL.
                result["introspection_enabled"] = "unclear"
                result["is_graphql"] = True
            else:
                result["introspection_enabled"] = "unclear"
        except Exception as e:
            result["introspection_error"] = str(e)

    return result


def run(target: str, mode: str = "basic") -> dict:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    base = _normalize(target)

    paths = _COMMON_PATHS[:3] if mode == "basic" else list(_COMMON_PATHS)
    endpoints = []
    for p in paths:
        r = _probe(base, p, do_introspection=(mode == "expert"))
        if r.get("exists") or r.get("ide_exposed"):
            endpoints.append(r)

    found = [e for e in endpoints if e.get("exists")]
    data = {
        "scanned": base,
        "mode": mode,
        "paths_checked": len(paths),
        "endpoints": endpoints,
        "endpoint_count": len(found),
        "ide_exposed_any": any(e.get("ide_exposed") for e in endpoints),
        "introspection_enabled_any": any(
            e.get("introspection_enabled") is True for e in endpoints
        ),
    }

    if data["introspection_enabled_any"]:
        data["risk"] = "medium"
    elif data["ide_exposed_any"]:
        data["risk"] = "low"
    else:
        data["risk"] = "info"

    return {"tool": "graphql_scan", "target": target, "data": data, "error": None}
