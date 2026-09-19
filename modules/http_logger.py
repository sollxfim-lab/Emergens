# ═══════════════════════════════════════════════════════════════════════════
# HTTP Logger API
# ═══════════════════════════════════════════════════════════════════════════
import queue as _queue_mod
from flask import Response as _FlaskResponse, stream_with_context as _swc


def _require_logger():
    if http_logger is None:
        return jsonify({"error": "http_logger module not available"}), 503
    return None


@app.route("/api/logger/requests")
@login_required
def api_logger_list():
    guard = _require_logger()
    if guard: return guard

    try:
        page = int(request.args.get("page", 1))
        size = int(request.args.get("size", 100))
        status_min = request.args.get("status_min", type=int)
        status_max = request.args.get("status_max", type=int)
        since_ms = request.args.get("since_ms", type=int)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid query parameters"}), 400

    result = http_logger.list(
        page=page, size=size,
        q=request.args.get("q"),
        method=request.args.get("method"),
        status_min=status_min,
        status_max=status_max,
        anomaly=request.args.get("anomaly"),
        tag=request.args.get("tag"),
        ip=request.args.get("ip"),
        since_ms=since_ms,
    )
    return jsonify(result)


@app.route("/api/logger/requests/<entry_id>")
@login_required
def api_logger_detail(entry_id):
    guard = _require_logger()
    if guard: return guard
    entry = http_logger.get(entry_id)
    if entry is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(entry)


@app.route("/api/logger/requests", methods=["DELETE"])
@login_required
def api_logger_clear():
    guard = _require_logger()
    if guard: return guard
    n = http_logger.clear()
    return jsonify({"success": True, "cleared": n})


@app.route("/api/logger/requests/<entry_id>/tag", methods=["POST"])
@login_required
def api_logger_tag(entry_id):
    guard = _require_logger()
    if guard: return guard
    body = request.get_json(silent=True) or {}
    tag = (body.get("tag") or "").strip()
    add = bool(body.get("add", True))
    if not tag:
        return jsonify({"error": "tag required"}), 400
    ok = http_logger.tag(entry_id, tag, add=add)
    if not ok:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"success": True})


@app.route("/api/logger/stats")
@login_required
def api_logger_stats():
    guard = _require_logger()
    if guard: return guard
    return jsonify(http_logger.stats())


@app.route("/api/logger/export")
@login_required
def api_logger_export():
    guard = _require_logger()
    if guard: return guard
    fmt = (request.args.get("format") or "har").lower()
    since_ms = request.args.get("since_ms", type=int)
    method = request.args.get("method")
    q = request.args.get("q")

    # Reuse list() with a large page so we honour the same filters
    result = http_logger.list(page=1, size=500, q=q, method=method, since_ms=since_ms)
    items = result.get("items") or []

    if fmt == "har":
        har = http_logger.to_har(items)
        payload = json.dumps(har, ensure_ascii=False, indent=2)
        filename = f"http-logger-{int(time.time())}.har"
        mimetype = "application/json"
    elif fmt == "json":
        payload = json.dumps({"entries": items}, ensure_ascii=False, indent=2)
        filename = f"http-logger-{int(time.time())}.json"
        mimetype = "application/json"
    elif fmt == "jsonl":
        payload = "\n".join(json.dumps(e, ensure_ascii=False) for e in items)
        filename = f"http-logger-{int(time.time())}.jsonl"
        mimetype = "application/x-ndjson"
    else:
        return jsonify({"error": f"unsupported format: {fmt}"}), 400

    return _FlaskResponse(
        payload, mimetype=mimetype,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/logger/stream")
@login_required
def api_logger_stream():
    guard = _require_logger()
    if guard: return guard

    subscriber = http_logger.subscribe()

    def _gen():
        try:
            # Prime the connection with a heartbeat comment
            yield ": connected\n\n"
            last_heartbeat = time.time()
            while True:
                try:
                    event = subscriber.get(timeout=15)
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                    last_heartbeat = time.time()
                except _queue_mod.Empty:
                    # Send a keepalive comment every 15 s to defeat idle proxies
                    if time.time() - last_heartbeat > 12:
                        yield ": ping\n\n"
                        last_heartbeat = time.time()
        except GeneratorExit:
            pass
        finally:
            http_logger.unsubscribe(subscriber)

    return _FlaskResponse(
        _swc(_gen()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/logger/replay/<entry_id>", methods=["POST"])
@login_required
def api_logger_replay(entry_id):
    """Replay a captured request against its original host."""
    guard = _require_logger()
    if guard: return guard
    entry = http_logger.get(entry_id)
    if not entry:
        return jsonify({"error": "not_found"}), 404

    body = request.get_json(silent=True) or {}
    # Allow the caller to override the target host — useful when the original
    # endpoint is no longer reachable but you want to test a sibling.
    override_host = (body.get("override_host") or "").strip()

    headers = entry.get("headers") or {}
    host = override_host or headers.get("Host", "")
    if not host:
        return jsonify({"error": "no target host"}), 400

    scheme = entry.get("scheme") or "http"
    path = entry.get("path") or "/"
    query = entry.get("query") or ""
    url = f"{scheme}://{host}{path}" + (f"?{query}" if query else "")

    # Remove headers that are unsafe to forward
    safe_headers = {}
    for k, v in headers.items():
        if k.lower() in ("host", "content-length", "connection", "transfer-encoding"):
            continue
        safe_headers[k] = v
    safe_headers["User-Agent"] = "Emergens-Replay/1.0"

    method = entry.get("method", "GET")
    body_data = entry.get("body_preview") if method not in ("GET", "HEAD") else None

    try:
        r = requests.request(
            method, url, headers=safe_headers, data=body_data,
            timeout=15, allow_redirects=False, verify=False,
        )
        return jsonify({
            "success": True,
            "url": url,
            "method": method,
            "status": r.status_code,
            "elapsed_ms": round(r.elapsed.total_seconds() * 1000, 1),
            "response_headers": dict(r.headers),
            "body_preview": r.text[:2000],
        })
    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": str(e), "url": url}), 502
