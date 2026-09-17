import os
import sys
import traceback

# Tambahkan project root ke sys.path supaya `from app import app` bisa ketemu
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, jsonify

def _load_real_app():
    """Coba import aplikasi utama dari ./app.py atau ./app/__init__.py"""
    try:
        from app import app as real_app
        return real_app
    except Exception as e:
        err_detail = {
            "error": "application_failed_to_start",
            "detail": str(e),
            "traceback": traceback.format_exc(),
        }
        fallback = Flask(__name__)

        @fallback.route("/", defaults={"path": ""})
        @fallback.route("/<path:path>")
        def catch_all(path):
            return jsonify(err_detail), 500

        return fallback

# WAJIB: variabel top-level bernama `app` (dibaca oleh @vercel/python)
app = _load_real_app()

# Alias opsional, kalau ada config lain yang expect `handler`
handler = app
