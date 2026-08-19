import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration loaded from environment variables."""
    # Project root directory
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    # Flask
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-change-in-production')
    PORT = int(os.getenv('PORT', 2207))

    # Anthropic (Claude) API
    ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')

    # DeepSeek R1 API (OpenAI‑compatible endpoint)
    DEEPSEEK_API_KEY = os.getenv('DEEPSEEK_API_KEY', '')
    DEEPSEEK_BASE_URL = os.getenv('DEEPSEEK_BASE_URL', 'https://app.siputzx.my.id/v1')
    DEEPSEEK_MODEL = os.getenv('DEEPSEEK_MODEL', 'deepseek-r1')

    # Database / storage paths
    USERS_DB = os.getenv('USERS_DB', 'users.db')
    HISTORY_DB = os.getenv('HISTORY_DB', 'history.db')
    CHAT_DB = os.getenv('CHAT_DB', 'chat_history.json')

    # Logging
    SERVER_LOG_FILE = os.getenv('SERVER_LOG_FILE', 'server.log')