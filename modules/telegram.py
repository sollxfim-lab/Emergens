# modules/telegram.py
"""
Oxysintx Telegram Bot Module v2.0.3

Full lifecycle Telegram bot with live scan integration.
- /start – branded photo + inline menu
- /scan <domain> [basic|expert] – launches a scan, shows live progress,
  and delivers results to the same chat when finished.
- Public / private access mode
- Persists state across restarts

Requires python-telegram-bot >= 21.0 on Python 3.13+.

Integration:
    After creating ScanOrchestrator and HistoryStore in app.py, call:
        from modules import telegram as tg
        tg.set_orchestrator(scan_orchestrator)
        tg.set_history_store(history_store)

v2.0.3 fix: use context.bot.loop (public property) instead of private _loop.

Author: Yanxzyx
"""

import os
import json
import sys
import time
import threading
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("oxysintx.telegram")

# ---------------------------------------------------------------------------
# Python 3.13 / library compatibility check
# ---------------------------------------------------------------------------
_MIN_PTB_MAJOR = 21
try:
    import telegram as _ptb
    _ptb_version = tuple(int(x) for x in _ptb.__version__.split("."))
except Exception:
    _ptb_version = (0, 0)

if sys.version_info >= (3, 13) and _ptb_version < (_MIN_PTB_MAJOR, 0):
    _msg = (
        f"python-telegram-bot {_MIN_PTB_MAJOR}.x is required on Python 3.13+. "
        f"Installed: {_ptb.__version__}. "
        "Run: pip install \"python-telegram-bot>=21.0\""
    )
    raise RuntimeError(_msg)

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------
_INSTANCE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance"
)
_STATE_FILE = os.path.join(_INSTANCE_DIR, "telegram_state.json")
_DATA_FILE = os.path.join(_INSTANCE_DIR, "telegram_data.json")
_BOT_PHOTO_URL = "https://files.catbox.moe/cyi0lp.png"

# ---------------------------------------------------------------------------
# Module-level state (guarded by _lock for thread safety)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_stop_event = threading.Event()
_bot_thread: Optional[threading.Thread] = None

_state: Dict = {
    "connected": False,
    "token": "",
    "username": "",
    "owner_id": "",
    "public_mode": True,
    "started_at": None,
}

_data: Dict = {
    "chat_ids": [],
    "messages_today": 0,
    "last_reset": "",
}

# References to core services – set by app.py after startup
_orchestrator = None        # ScanOrchestrator instance
_history_store = None       # HistoryStore instance


def set_orchestrator(orch) -> None:
    """Store a reference to the application's ScanOrchestrator."""
    global _orchestrator
    _orchestrator = orch


def set_history_store(store) -> None:
    """Store a reference to the application's HistoryStore."""
    global _history_store
    _history_store = store


# ---------------------------------------------------------------------------
# Internal helpers -- persistence
# ---------------------------------------------------------------------------
def _ensure_instance_dir() -> None:
    os.makedirs(_INSTANCE_DIR, exist_ok=True)


def _load_state() -> None:
    global _state, _data
    _ensure_instance_dir()
    if os.path.exists(_STATE_FILE):
        try:
            with open(_STATE_FILE, "r") as fh:
                _state.update(json.load(fh))
        except (json.JSONDecodeError, IOError):
            logger.warning("Could not parse %s, using defaults.", _STATE_FILE)
    if os.path.exists(_DATA_FILE):
        try:
            with open(_DATA_FILE, "r") as fh:
                _data.update(json.load(fh))
        except (json.JSONDecodeError, IOError):
            logger.warning("Could not parse %s, using defaults.", _DATA_FILE)

    today = datetime.now().strftime("%Y-%m-%d")
    if _data.get("last_reset") != today:
        _data["messages_today"] = 0
        _data["last_reset"] = today


def _save_state() -> None:
    _ensure_instance_dir()
    with open(_STATE_FILE, "w") as fh:
        json.dump(_state, fh, indent=2)
    with open(_DATA_FILE, "w") as fh:
        json.dump(_data, fh, indent=2)


def _is_authorized(chat_id: int) -> bool:
    if _state.get("public_mode", True):
        return True
    return str(chat_id) == str(_state.get("owner_id", ""))


def _register_chat(chat_id: int) -> None:
    sid = str(chat_id)
    if sid not in _data["chat_ids"]:
        _data["chat_ids"].append(sid)
        _save_state()


def _increment_counter() -> None:
    _data["messages_today"] = _data.get("messages_today", 0) + 1
    _save_state()


# ---------------------------------------------------------------------------
# Bot application builder
# ---------------------------------------------------------------------------
def _build_application():
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import (
        Application,
        CommandHandler,
        MessageHandler,
        CallbackQueryHandler,
        filters,
        ContextTypes,
    )

    token = _state.get("token", "")
    if not token:
        return None

    app_bot = Application.builder().token(token).build()

    # ---- Keyboards --------------------------------------------------------
    def _main_menu_keyboard() -> InlineKeyboardMarkup:
        keyboard = [
            [
                InlineKeyboardButton("Quick Scan", callback_data="menu_scan"),
                InlineKeyboardButton("Status", callback_data="menu_status"),
            ],
            [
                InlineKeyboardButton("DNS Lookup", callback_data="menu_dns"),
                InlineKeyboardButton("SSL Check", callback_data="menu_ssl"),
            ],
            [
                InlineKeyboardButton("Headers Audit", callback_data="menu_headers"),
                InlineKeyboardButton("Email Security", callback_data="menu_email"),
            ],
            [
                InlineKeyboardButton("Subdomain Scan", callback_data="menu_subdomains"),
                InlineKeyboardButton("Port Scan", callback_data="menu_ports"),
            ],
            [
                InlineKeyboardButton("Help", callback_data="menu_help"),
                InlineKeyboardButton("About", callback_data="menu_about"),
            ],
        ]
        return InlineKeyboardMarkup(keyboard)

    def _back_keyboard() -> InlineKeyboardMarkup:
        return InlineKeyboardMarkup(
            [[InlineKeyboardButton("Back to Menu", callback_data="menu_main")]]
        )

    # ---- Uptime helper ----------------------------------------------------
    def _format_uptime() -> str:
        started = _state.get("started_at")
        if not started:
            return "just now"
        try:
            start_dt = datetime.fromisoformat(started)
            diff = datetime.now() - start_dt
            hours, remainder = divmod(diff.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            if hours:
                return f"{hours}h {minutes}m"
            return f"{minutes}m {seconds}s"
        except (ValueError, TypeError):
            return "unknown"

    # ---- Command handlers -------------------------------------------------
    async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
        chat_id = update.effective_chat.id
        _register_chat(chat_id)
        _increment_counter()

        if not _is_authorized(chat_id):
            await update.message.reply_text(
                "This bot is in private mode. Only the owner can interact with it."
            )
            return

        welcome = (
            "[ Oxysintx Bot ]\n\n"
            f"Welcome, {update.effective_user.first_name}.\n\n"
            "I am your Oxysintx Field Intelligence assistant. "
            "I can run security scans, DNS lookups, SSL checks, "
            "and more -- all from Telegram.\n\n"
            f"Status  : Online\n"
            f"Uptime  : {_format_uptime()}\n"
            f"Mode    : {'Public' if _state.get('public_mode', True) else 'Private'}\n\n"
            "Choose an option from the menu below:"
        )

        try:
            await context.bot.send_photo(
                chat_id=chat_id,
                photo=_BOT_PHOTO_URL,
                caption=welcome,
                reply_markup=_main_menu_keyboard(),
            )
        except Exception:
            await update.message.reply_text(
                welcome,
                reply_markup=_main_menu_keyboard(),
            )

    async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
        chat_id = update.effective_chat.id
        if not _is_authorized(chat_id):
            return
        _increment_counter()
        await update.message.reply_text(
            "[ Oxysintx Bot Commands ]\n\n"
            "/start   - Show the main menu with photo\n"
            "/help    - Show this help message\n"
            "/status  - Bot and system status\n"
            "/scan <domain> [basic|expert] - Run a live scan\n\n"
            "Additional features are available via the inline menu.",
        )

    async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
        chat_id = update.effective_chat.id
        if not _is_authorized(chat_id):
            return
        _increment_counter()
        _register_chat(chat_id)

        await update.message.reply_text(
            "[ Oxysintx Status ]\n\n"
            f"Bot       : Online\n"
            f"Uptime    : {_format_uptime()}\n"
            f"Mode      : {'Public' if _state.get('public_mode', True) else 'Private'}\n"
            f"Your ID   : {chat_id}\n"
            f"Total IDs : {len(_data.get('chat_ids', []))}\n"
            f"Msg Today : {_data.get('messages_today', 0)}\n\n"
            "Dashboard: Oxysintx Field Intelligence Console",
        )

    async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
        chat_id = update.effective_chat.id
        if not _is_authorized(chat_id):
            return
        _increment_counter()

        if not context.args:
            await update.message.reply_text(
                "Usage: /scan <domain> [basic|expert]\nExample: /scan example.com expert",
                reply_markup=_back_keyboard(),
            )
            return

        target = context.args[0]
        mode = "basic"
        if len(context.args) > 1 and context.args[1].lower() == "expert":
            mode = "expert"

        if _orchestrator is None or _history_store is None:
            await update.message.reply_text(
                "Scan service is not available right now. Please try again later."
            )
            return

        # Start the scan
        try:
            job_id = _orchestrator.start_scan(
                target, mode, tools=[],  # empty tools => default set for the mode
                history_store=_history_store,
            )
        except Exception as exc:
            logger.error("Failed to start scan: %s", exc)
            await update.message.reply_text("Could not start the scan. Check the server logs.")
            return

        # Send initial status message
        status_msg = await update.message.reply_text(
            f"[Scan] {target} ({mode} mode)\n\nStarting..."
        )

        # Poll the job in a background thread, editing the message with progress
        def poll_progress():
            while True:
                time.sleep(3)
                with _lock:
                    if _orchestrator is None:
                        break
                progress = _orchestrator.get_progress(job_id)
                if progress is None:
                    break

                pct = progress.get("percent", 0)
                status = progress.get("status", "running")
                current = progress.get("current_tool", "")

                text = f"[Scan] {target} ({mode} mode)\n\n"
                text += f"Progress: {pct}%"
                if current:
                    text += f"\nCurrent tool: {current}"

                async def update_status():
                    try:
                        await status_msg.edit_text(text)
                    except Exception:
                        pass

                # Schedule on the bot's asyncio event loop (public loop property)
                asyncio.run_coroutine_threadsafe(update_status(), context.bot.loop)

                if status in ("completed", "cancelled", "timeout", "error"):
                    break

            # After loop: fetch final results
            final = _orchestrator.get_progress(job_id)
            if final is None:
                return

            results = final.get("results", {})
            # Build a short summary for Telegram
            summary = f"[Scan completed] {target} ({mode} mode)\n"
            if final["status"] == "completed":
                summary += "Status: COMPLETED\n\n"
                for tool, res in results.items():
                    data = res.get("data", {})
                    err = res.get("error")
                    if err:
                        summary += f"{tool}: ERROR - {err}\n"
                    else:
                        if tool == "whois_lookup":
                            summary += f"WHOIS: {data.get('registrar', '?')}\n"
                        elif tool == "dns_lookup":
                            a_records = data.get("A", [])
                            summary += f"DNS: {len(a_records)} A record(s)\n"
                        elif tool == "ssl_check":
                            valid = data.get("valid", "unknown")
                            summary += f"SSL: {'Valid' if valid else 'Invalid'}\n"
                        elif tool == "headers_check":
                            score = data.get("score_percent", "?")
                            summary += f"Headers Score: {score}%\n"
                        elif tool == "port_scan":
                            open_ports = data.get("open_count", 0)
                            summary += f"Open ports: {open_ports}\n"
                        else:
                            summary += f"{tool}: OK\n"
            else:
                summary += f"Status: {final['status'].upper()}\nError: {final.get('error', 'none')}"

            async def send_summary():
                try:
                    await context.bot.send_message(chat_id, summary)
                except Exception:
                    pass

            asyncio.run_coroutine_threadsafe(send_summary(), context.bot.loop)

        threading.Thread(target=poll_progress, daemon=True).start()

    # ---- Callback handler -------------------------------------------------
    async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        chat_id = update.effective_chat.id

        if not _is_authorized(chat_id):
            await query.edit_message_text("Access denied. Private mode is active.")
            return

        _increment_counter()
        cb_data = query.data

        responses = {
            "menu_main": ("[ Oxysintx Main Menu ]", _main_menu_keyboard()),
            "menu_scan": (
                "Send /scan <domain> [basic|expert] to run a live scan.",
                _back_keyboard(),
            ),
            "menu_status": (
                "Use /status for full system information.",
                _back_keyboard(),
            ),
            "menu_dns": (
                "DNS Lookup -- check your dashboard or use the API directly.",
                _back_keyboard(),
            ),
            "menu_ssl": (
                "SSL Check -- check your dashboard or use the API directly.",
                _back_keyboard(),
            ),
            "menu_headers": (
                "Headers Audit -- check your dashboard or use the API directly.",
                _back_keyboard(),
            ),
            "menu_email": (
                "Email Security -- check your dashboard or use the API directly.",
                _back_keyboard(),
            ),
            "menu_subdomains": (
                "Subdomain Scan -- check your dashboard or use the API directly.",
                _back_keyboard(),
            ),
            "menu_ports": (
                "Port Scan -- check your dashboard or use the API directly.",
                _back_keyboard(),
            ),
            "menu_help": (
                "Send /help for the full command list.",
                _back_keyboard(),
            ),
            "menu_about": (
                "Oxysintx Bot v2.0\nField Intelligence Console\nBuilt for security professionals.",
                _back_keyboard(),
            ),
        }

        if cb_data in responses:
            text, markup = responses[cb_data]
            try:
                await query.edit_message_caption(caption=text, reply_markup=markup)
            except Exception:
                await query.edit_message_text(text, reply_markup=markup)

    # ---- Catch-all text handler -------------------------------------------
    async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
        chat_id = update.effective_chat.id
        if not _is_authorized(chat_id):
            await update.message.reply_text("This bot is in private mode.")
            return
        _register_chat(chat_id)
        _increment_counter()
        await update.message.reply_text(
            f"Message received. Use /help to see available commands.\nYour Chat ID: {chat_id}"
        )

    # ---- Register handlers ------------------------------------------------
    app_bot.add_handler(CommandHandler("start", start_command))
    app_bot.add_handler(CommandHandler("help", help_command))
    app_bot.add_handler(CommandHandler("status", status_command))
    app_bot.add_handler(CommandHandler("scan", scan_command))
    app_bot.add_handler(CallbackQueryHandler(button_handler))
    app_bot.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler)
    )

    return app_bot


# ---------------------------------------------------------------------------
# Background bot runner
# ---------------------------------------------------------------------------
def _run_bot() -> None:
    application = _build_application()
    if application is None:
        logger.error("Cannot start bot: no token configured.")
        with _lock:
            _state["connected"] = False
            _save_state()
        return

    logger.info("Telegram bot polling started.")
    try:
        application.run_polling(
            allowed_updates=["message", "callback_query"],
            stop_signals=[],
        )
    except Exception as exc:
        logger.error("Bot polling crashed: %s", exc)
    finally:
        with _lock:
            _state["connected"] = False
            _save_state()
        logger.info("Telegram bot polling stopped.")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def connect_bot(
    token: str,
    username: str,
    owner_id: str = "",
    public_mode: bool = True,
) -> Tuple[bool, str]:
    global _bot_thread, _stop_event

    with _lock:
        if _bot_thread and _bot_thread.is_alive():
            _stop_event.set()
            _bot_thread.join(timeout=5)
            _bot_thread = None

        _stop_event = threading.Event()

        _state.update(
            {
                "token": token,
                "username": username,
                "owner_id": str(owner_id).strip(),
                "public_mode": bool(public_mode),
                "connected": True,
                "started_at": datetime.now().isoformat(),
            }
        )
        _save_state()

        _bot_thread = threading.Thread(target=_run_bot, daemon=True)
        _bot_thread.start()

    time.sleep(1.5)

    if _bot_thread.is_alive():
        logger.info("Bot %s started successfully.", username)
        return True, "connected"
    else:
        _state["connected"] = False
        _save_state()
        logger.error("Bot thread failed to start.")
        return False, "bot_thread_failed"


def disconnect_bot() -> None:
    global _bot_thread, _stop_event

    with _lock:
        if _bot_thread and _bot_thread.is_alive():
            _stop_event.set()
            _bot_thread.join(timeout=5)
        _bot_thread = None
        _stop_event = threading.Event()
        _state["connected"] = False
        _state["started_at"] = None
        _save_state()

    logger.info("Bot disconnected.")


def get_bot_status() -> Dict:
    with _lock:
        status = dict(_state)
    status["chat_ids"] = list(_data.get("chat_ids", []))
    status["messages_today"] = _data.get("messages_today", 0)
    return status


def update_bot_settings(**kwargs) -> Dict:
    with _lock:
        if "owner_id" in kwargs:
            _state["owner_id"] = str(kwargs["owner_id"]).strip()
        if "public_mode" in kwargs:
            _state["public_mode"] = bool(kwargs["public_mode"])
        _save_state()

    if _state.get("connected"):
        token = _state.get("token", "")
        username = _state.get("username", "")
        if token and username:
            connect_bot(
                token=token,
                username=username,
                owner_id=_state.get("owner_id", ""),
                public_mode=_state.get("public_mode", True),
            )

    return get_bot_status()


def broadcast_message(message: str) -> Dict:
    chat_ids = list(_data.get("chat_ids", []))
    if not chat_ids:
        return {"count": 0, "status": "no_chats"}

    token = _state.get("token", "")
    if not token:
        return {"count": 0, "status": "no_token"}

    from telegram import Bot

    bot = Bot(token=token)
    sent = 0
    for cid in chat_ids:
        try:
            bot.send_message(chat_id=int(cid), text=message)
            sent += 1
        except Exception as exc:
            logger.warning("Broadcast to %s failed: %s", cid, exc)

    return {"count": sent, "status": "ok"}


def auto_restart_bot() -> bool:
    _load_state()

    if not _state.get("connected"):
        return False

    token = _state.get("token", "")
    username = _state.get("username", "")
    if not token or not username:
        _state["connected"] = False
        _save_state()
        return False

    logger.info("Auto-restarting Telegram bot '%s' ...", username)
    success, _ = connect_bot(
        token=token,
        username=username,
        owner_id=_state.get("owner_id", ""),
        public_mode=_state.get("public_mode", True),
    )
    return success