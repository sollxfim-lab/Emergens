"""
WSGI entry point for traditional hosting (Render, Railway, Heroku).

Run with:
    gunicorn wsgi:app
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app  # noqa: E402

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3052))
    app.run(host="0.0.0.0", port=port, debug=False)
