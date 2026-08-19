"""
Oxysintx Configuration

Values are read from environment variables first, with safe defaults.
For local development, copy .env.example to .env and set values there.
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent

# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")

# Port only used for local dev (not Vercel)
PORT = int(os.environ.get("PORT", "3052"))

# Session config
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Database (SQLite for local, MySQL if configured)
# ---------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", None)  # Set to MySQL URL if available

# SQLite paths
INSTANCE_DIR = PROJECT_ROOT / "instance"
USERS_DB_PATH = os.environ.get("USERS_DB_PATH", str(INSTANCE_DIR / "users.db"))
HISTORY_DB_PATH = os.environ.get("HISTORY_DB_PATH", str(INSTANCE_DIR / "history.db"))
CHAT_DB_PATH = os.environ.get("CHAT_DB_PATH", str(INSTANCE_DIR / "chat.db"))

# Ensure instance dir exists (skip on serverless read-only FS)
try:
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
SERVER_LOG_FILE = os.environ.get("SERVER_LOG_FILE", str(INSTANCE_DIR / "server.log"))

# ---------------------------------------------------------------------------
# Anthropic (AI Chat)
# ---------------------------------------------------------------------------
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")

# ---------------------------------------------------------------------------
# Directories for scan data
# ---------------------------------------------------------------------------
USERDATA_DIR = os.environ.get("USERDATA_DIR", str(PROJECT_ROOT / "userdata"))
LISTSCHOOL_DIR = os.environ.get("LISTSCHOOL_DIR", str(PROJECT_ROOT / "listschool"))
