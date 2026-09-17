import os
import sys
import traceback

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from app import app
    handler = app
except Exception as e:
    # Jika import gagal, return error detail supaya senang debug
    from flask import Flask, jsonify
    fallback_app = Flask(__name__)

    @fallback_app.route("/", defaults={"path": ""})
    @fallback_app.route("/<path:path>")
    def catch_all(path):
        return jsonify({
            "error": "application_failed_to_start",
            "detail": str(e),
            "traceback": traceback.format_exc()
        }), 500

    handler = fallback_app
