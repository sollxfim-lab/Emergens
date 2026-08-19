"""
Vercel serverless entry point for Oxysintx / Emergens.

This file wraps the Flask application so it can run as a
single serverless function on Vercel.

Route:
    All incoming HTTP requests will be forwarded to Flask.

Deployment requirement:
    - Place this file inside the /api folder at project root.
    - Ensure vercel.json points to this file as the build source.
"""

import os
import sys

# ---------------------------------------------------------------------------
# Add the project root to sys.path so that imports from app.py and
# other modules work correctly in the serverless environment.
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Import the Flask app from app.py
# ---------------------------------------------------------------------------
try:
    from app import app as flask_app
except Exception as e:
    # If app import fails, create a minimal Flask app to return the error.
    from flask import Flask, jsonify
    flask_app = Flask(__name__)

    @flask_app.route("/", defaults={"path": ""})
    @flask_app.route("/<path:path>")
    def catch_all(path):
        return jsonify({
            "error": "application_failed_to_start",
            "detail": str(e),
        }), 500

# ---------------------------------------------------------------------------
# Vercel expects a callable named `handler`
# ---------------------------------------------------------------------------
handler = flask_app
