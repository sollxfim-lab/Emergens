# ═══════════════════════════════════════════════════════════════════════════
# DIRFUZZ — async job + SSE stream (v2 module)
# ═══════════════════════════════════════════════════════════════════════════
try:
    from modules import dirfuzz as dirfuzz_module  # type: ignore
    _dirfuzz_available = True
except ImportError:
    dirfuzz_module = None
    _dirfuzz_available = False

_DIRFUZZ_JOB_TTL = 1800
_DIRFUZZ_MAX_CONCURRENT = 4
_dirfuzz_jobs: Dict[str, Dict[str, Any]] = {}
_dirfuzz_jobs_lock = threading.Lock()


def _dirfuzz_sweep_jobs() -> None:
    cutoff = time.time() - _DIRFUZZ_JOB_TTL
    with _dirfuzz_jobs_lock:
        for jid in [k for k, v in _dirfuzz_jobs.items() if v["created"] < cutoff]:
            ev = _dirfuzz_jobs[jid].get("cancel")
            if ev:
                ev.set()
            del _dirfuzz_jobs[jid]


def _dirfuzz_normalise(body: Dict[str, Any]) -> Dict[str, Any]:
    def _i(key, default, lo, hi):
        try: return max(lo, min(hi, int(body.get(key, default))))
        except (TypeError, ValueError): return default

    def _f(key, default, lo, hi):
        try: return max(lo, min(hi, float(body.get(key, default))))
        except (TypeError, ValueError): return default

    def _b(key, default):
        v = body.get(key, default)
        return bool(v) if v is not None else default

    return {
        "wordlist_name":    (body.get("wordlist_name") or "lottery-dirs.txt").strip(),
        "wordlist":         body.get("wordlist") or None,
        "max_paths":        _i("max_paths", 300, 10, 2000),
        "concurrency":      _i("concurrency", 24, 1, 64),
        "rate_limit":       _f("rate_limit", 40.0, 1.0, 200.0),
        "timeout":          _f("timeout", 4.0, 1.0, 15.0),
        "max_duration":     _f("max_duration", 90.0, 10.0, 300.0),
        "follow_redirects": _b("follow_redirects", False),
    }


@app.route("/api/exploit/dirfuzz/start", methods=["POST"])
@login_required
def api_exploit_dirfuzz_start():
    if not _dirfuzz_available or dirfuzz_module is None:
        return jsonify({"error": "dirfuzz module not available"}), 503

    body = request.get_json(silent=True) or {}
    base = (body.get("base") or body.get("url") or "").strip()
    if not base:
        return jsonify({"error": "base URL required"}), 400

    _dirfuzz_sweep_jobs()

    with _dirfuzz_jobs_lock:
        active = sum(1 for v in _dirfuzz_jobs.values() if v["status"] == "running")
        if active >= _DIRFUZZ_MAX_CONCURRENT:
            return jsonify({
                "error": "too_many_active_jobs",
                "active": active, "limit": _DIRFUZZ_MAX_CONCURRENT,
            }), 429

        job_id = "DRF-" + uuid.uuid4().hex[:8].upper()
        cancel_ev = threading.Event()
        options = _dirfuzz_normalise(body)
        _dirfuzz_jobs[job_id] = {
            "job_id": job_id,
            "base": base,
            "status": "running",
            "created": time.time(),
            "started_at": _now_iso(),
            "finished_at": None,
            "results": None,
            "error": None,
            "cancel": cancel_ev,
            "options": options,
        }

    def _worker() -> None:
        try:
            result = dirfuzz_module.run(base, {**options, "cancel_event": cancel_ev})
            with _dirfuzz_jobs_lock:
                job = _dirfuzz_jobs.get(job_id)
                if not job:
                    return
                job["results"] = result
                job["finished_at"] = _now_iso()
                job["status"] = "cancelled" if cancel_ev.is_set() else "completed"
        except Exception as e:
            logger.exception("Dirfuzz job %s failed", job_id)
            with _dirfuzz_jobs_lock:
                job = _dirfuzz_jobs.get(job_id)
                if job:
                    job["status"] = "failed"
                    job["error"] = str(e)
                    job["finished_at"] = _now_iso()

    threading.Thread(target=_worker, daemon=True, name=f"drf-{job_id}").start()
    return jsonify({"job_id": job_id, "status": "running", "options": options}), 202


@app.route("/api/exploit/dirfuzz/status/<job_id>")
@login_required
def api_exploit_dirfuzz_status(job_id):
    with _dirfuzz_jobs_lock:
        job = _dirfuzz_jobs.get(job_id)
        if not job:
            return jsonify({"error": "not_found"}), 404
        return jsonify({
            "job_id":      job_id,
            "base":        job["base"],
            "status":      job["status"],
            "started_at":  job["started_at"],
            "finished_at": job["finished_at"],
            "results":     job["results"],
            "error":       job["error"],
        })


@app.route("/api/exploit/dirfuzz/cancel/<job_id>", methods=["POST"])
@login_required
def api_exploit_dirfuzz_cancel(job_id):
    with _dirfuzz_jobs_lock:
        job = _dirfuzz_jobs.get(job_id)
        if not job:
            return jsonify({"error": "not_found"}), 404
        if job["status"] != "running":
            return jsonify({"error": "job_not_running", "status": job["status"]}), 400
        job["cancel"].set()
        job["status"] = "cancelling"
    return jsonify({"success": True, "job_id": job_id})


@app.route("/api/exploit/dirfuzz/wordlists")
@login_required
def api_exploit_dirfuzz_wordlists():
    if not _dirfuzz_available or dirfuzz_module is None:
        return jsonify({"error": "dirfuzz module not available"}), 503
    return jsonify({
        "wordlists": dirfuzz_module.list_wordlists(),
        "sources":   dirfuzz_module.WORDLIST_SOURCES,
    })


@app.route("/api/exploit/dirfuzz/stream", methods=["POST"])
@login_required
def api_exploit_dirfuzz_stream():
    if not _dirfuzz_available or dirfuzz_module is None:
        return jsonify({"error": "dirfuzz module not available"}), 503

    body = request.get_json(silent=True) or {}
    base = (body.get("base") or body.get("url") or "").strip()
    if not base:
        return jsonify({"error": "base URL required"}), 400

    options = _dirfuzz_normalise(body)

    def _gen():
        try:
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            for event in dirfuzz_module.run_streaming(base, options):
                yield f"data: {json.dumps(event, ensure_ascii=False, default=str)}\n\n"
                if event.get("type") in ("progress", "result", "error"):
                    yield ": flush\n\n"
        except GeneratorExit:
            return
        except Exception as e:
            logger.exception("Dirfuzz stream failed")
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return Response(
        stream_with_context(_gen()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Pragma": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
