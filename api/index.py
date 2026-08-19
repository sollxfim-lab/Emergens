"""
Vercel serverless entry point for Oxysintx / Emergens.

This file wraps the Flask app so it can run as a serverless function.
"""

import os
import sys

# Add project root to path so imports work
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import the Flask app from app.py
from app import app  # noqa: E402

# Vercel requires a callable named "handler"
handler = app
