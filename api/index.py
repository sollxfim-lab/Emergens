import os
import sys

# Tambah project root ke sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import Flask app
from app import app

# Vercel mesti jumpa `handler` top-level
handler = app
