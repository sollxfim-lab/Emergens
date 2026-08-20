"""
Oxysintx / Emergens Configuration

Values are read from environment variables first, with safe defaults.
For local development, copy .env.example to .env and set values there.

This module exposes a `Config` class so other modules can import it
as: from config import Config
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class Config:
    """Central configuration for the Flask application."""

    # -------------------------------------------------------------------------
    # Paths
    # -------------------------------------------------------------------------
    PROJECT_ROOT = Path(__file__).parent

    # -------------------------------------------------------------------------
    # Flask
    # -------------------------------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    PORT = int(os.environ.get("PORT", "3052"))

    # -------------------------------------------------------------------------
    # Instance directory (writable local directory for SQLite, logs, etc.)
    # -------------------------------------------------------------------------
    INSTANCE_DIR = PROJECT_ROOT / "instance"

    # -------------------------------------------------------------------------
    # Database paths
    # -------------------------------------------------------------------------
    USERS_DB_PATH = os.environ.get("USERS_DB_PATH", str(INSTANCE_DIR / "users.db"))
    HISTORY_DB_PATH = os.environ.get("HISTORY_DB_PATH", str(INSTANCE_DIR / "history.db"))
    CHAT_DB_PATH = os.environ.get("CHAT_DB_PATH", str(INSTANCE_DIR / "chat.db"))

    # Aliases for modules that use shorter attribute names
    USERS_DB = USERS_DB_PATH
    HISTORY_DB = HISTORY_DB_PATH
    CHAT_DB = CHAT_DB_PATH

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------
    SERVER_LOG_FILE = os.environ.get(
        "SERVER_LOG_FILE",
        str(INSTANCE_DIR / "server.log")
    )

    # -------------------------------------------------------------------------
    # Anthropic (AI Chat)
    # -------------------------------------------------------------------------
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

    # -------------------------------------------------------------------------
    # Telegram
    # -------------------------------------------------------------------------
    TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")

    # -------------------------------------------------------------------------
    # Data directories
    # -------------------------------------------------------------------------
    USERDATA_DIR = os.environ.get("USERDATA_DIR", str(PROJECT_ROOT / "userdata"))
    LISTSCHOOL_DIR = os.environ.get("LISTSCHOOL_DIR", str(PROJECT_ROOT / "listschool"))


# ---------------------------------------------------------------------------
# Ensure writable directories exist (safe for Render, local, and serverless)
# ---------------------------------------------------------------------------
try:
    Config.INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    # Permission error or read-only filesystem — ignore during import
    pass
