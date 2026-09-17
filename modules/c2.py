#!/usr/bin/env python3
"""
Oxysintx C2 Backend (c2.py) — Real Production Version

A standalone Flask application that provides:
- Token-based authentication (title, lock, password)
- Global lock/unlock toggle
- Real system metrics (CPU, memory, disk, network, ping) via psutil
- SQLite‑backed device registry and activity logging
- REST API for Android clients to register, heartbeat, and push activities
- No simulated data – all endpoints interact with real database

Usage:
    python c2.py [--port PORT]

Author: Yanxzyx
"""

import os
import sys
import time
import json
import hashlib
import secrets
import sqlite3
import logging
import subprocess
import re
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Any, Dict, List, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from flask import Flask, request, jsonify
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_PORT = 2061
TOKEN_EXPIRY_MINUTES = 30
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "c2.db")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] c2: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("c2")

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------
def get_db():
    """Return a new SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create tables if they don't exist."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                title TEXT UNIQUE NOT NULL,
                lock_code TEXT NOT NULL,
                password_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at REAL NOT NULL,
                FOREIGN KEY(username) REFERENCES users(username)
            );

            CREATE TABLE IF NOT EXISTS lock_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                locked INTEGER NOT NULL,
                locked_by TEXT,
                locked_at TEXT
            );

            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                model TEXT,
                serial TEXT,
                status TEXT DEFAULT 'offline',
                battery INTEGER,
                android_version TEXT,
                cpu TEXT,
                ram TEXT,
                storage TEXT,
                location TEXT,
                temperature TEXT,
                last_seen TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(device_id) REFERENCES devices(id)
            );
        """)
    # Insert default lock state if not exists
    with get_db() as conn:
        row = conn.execute("SELECT id FROM lock_state WHERE id = 1").fetchone()
        if row is None:
            conn.execute("INSERT INTO lock_state (id, locked, locked_by, locked_at) VALUES (1, 1, NULL, NULL)")

def seed_users():
    """Create default users if they don't exist."""
    with get_db() as conn:
        # AlphaWolf
        existing = conn.execute("SELECT username FROM users WHERE title = ?", ("AlphaWolf",)).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO users (username, title, lock_code, password_hash) VALUES (?, ?, ?, ?)",
                ("alpha", "AlphaWolf", "wolf123", hashlib.sha256("admin123".encode()).hexdigest())
            )
        # ShadowFox
        existing = conn.execute("SELECT username FROM users WHERE title = ?", ("ShadowFox",)).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO users (username, title, lock_code, password_hash) VALUES (?, ?, ?, ?)",
                ("shadow", "ShadowFox", "fox456", hashlib.sha256("admin456".encode()).hexdigest())
            )

# Initialize DB at import
init_db()
seed_users()

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("C2_SECRET_KEY", secrets.token_hex(32))
CORS(app)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def generate_token() -> str:
    return secrets.token_hex(32)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def require_auth(f):
    """Decorator to protect routes with X-C2-Token header."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-C2-Token")
        if not token:
            data = request.get_json(silent=True) or {}
            token = data.get("token")
        if not token:
            return jsonify({"error": "Unauthorized"}), 401

        with get_db() as conn:
            row = conn.execute(
                "SELECT s.token, s.username, s.created_at, u.title FROM sessions s JOIN users u ON s.username = u.username WHERE s.token = ?",
                (token,)
            ).fetchone()
            if row is None:
                return jsonify({"error": "Unauthorized"}), 401

            # Check expiry
            if time.time() - row["created_at"] > TOKEN_EXPIRY_MINUTES * 60:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                return jsonify({"error": "Session expired"}), 401

        # Attach session info to request context
        request.c2_session = {"username": row["username"], "title": row["title"]}
        return f(*args, **kwargs)
    return wrapper

# ---------------------------------------------------------------------------
# System Monitoring (real via psutil or OS fallback)
# ---------------------------------------------------------------------------
def get_cpu_percent() -> Optional[float]:
    if PSUTIL_AVAILABLE:
        try:
            return psutil.cpu_percent(interval=0.1)
        except Exception:
            pass
    # Fallback: /proc/stat
    try:
        with open('/proc/stat', 'r') as f:
            fields = f.readline().split()
            if len(fields) < 5:
                return None
            user, nice, system, idle = map(int, fields[1:5])
            total = user + nice + system + idle
            idle_time = idle
            return round((1.0 - idle_time / total) * 100, 1)
    except Exception:
        return None

def get_memory_info() -> Optional[Dict[str, Any]]:
    if PSUTIL_AVAILABLE:
        try:
            mem = psutil.virtual_memory()
            return {
                "total_mb": round(mem.total / (1024 * 1024), 1),
                "used_mb": round(mem.used / (1024 * 1024), 1),
                "available_mb": round(mem.available / (1024 * 1024), 1),
                "percent": mem.percent,
            }
        except Exception:
            pass
    try:
        meminfo = {}
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if ':' in line:
                    key, value = line.split(':')
                    meminfo[key.strip()] = value.strip().split()[0]
        total_kb = int(meminfo.get('MemTotal', 0))
        avail_kb = int(meminfo.get('MemAvailable', int(meminfo.get('MemFree', 0))))
        used_kb = total_kb - avail_kb
        return {
            "total_mb": round(total_kb / 1024, 1),
            "used_mb": round(used_kb / 1024, 1),
            "available_mb": round(avail_kb / 1024, 1),
            "percent": round((used_kb / total_kb) * 100, 1) if total_kb else 0,
        }
    except Exception:
        return None

def get_disk_info() -> Optional[Dict[str, Any]]:
    if PSUTIL_AVAILABLE:
        try:
            disk = psutil.disk_usage('/')
            return {
                "total_gb": round(disk.total / (1024 ** 3), 1),
                "used_gb": round(disk.used / (1024 ** 3), 1),
                "free_gb": round(disk.free / (1024 ** 3), 1),
                "percent": disk.percent,
            }
        except Exception:
            pass
    try:
        st = os.statvfs('/')
        total = st.f_blocks * st.f_frsize
        free = st.f_bfree * st.f_frsize
        used = total - free
        return {
            "total_gb": round(total / (1024 ** 3), 1),
            "used_gb": round(used / (1024 ** 3), 1),
            "free_gb": round(free / (1024 ** 3), 1),
            "percent": round((used / total) * 100, 1) if total else 0,
        }
    except Exception:
        return None

def get_ping_latency(host: str = "8.8.8.8", count: int = 1) -> Optional[float]:
    try:
        cmd = f"ping -c {count} -W 1 {host}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
        output = result.stdout
        for line in output.split('\n'):
            if 'time=' in line:
                match = re.search(r'time=([\d.]+)\s*ms', line)
                if match:
                    return float(match.group(1))
        for line in output.split('\n'):
            if 'min/avg/max' in line:
                match = re.search(r'=\s*[\d.]+/([\d.]+)/', line)
                if match:
                    return float(match.group(1))
        return None
    except Exception:
        return None

def get_network_info() -> Optional[Dict[str, Any]]:
    if PSUTIL_AVAILABLE:
        try:
            net = psutil.net_io_counters()
            return {
                "sent_mb": round(net.bytes_sent / (1024 * 1024), 2),
                "recv_mb": round(net.bytes_recv / (1024 * 1024), 2),
            }
        except Exception:
            pass
    try:
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()[2:]
            sent = 0
            recv = 0
            for line in lines:
                if ':' in line:
                    parts = line.split(':')
                    data = parts[1].split()
                    recv += int(data[0])
                    sent += int(data[8])
            return {
                "sent_mb": round(sent / (1024 * 1024), 2),
                "recv_mb": round(recv / (1024 * 1024), 2),
            }
    except Exception:
        return None

def get_system_stats() -> Dict[str, Any]:
    return {
        "cpu_percent": get_cpu_percent(),
        "memory": get_memory_info(),
        "disk": get_disk_info(),
        "ping_ms": get_ping_latency(),
        "network": get_network_info(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/api/c2/login", methods=["POST"])
def login():
    """Authenticate with title, lock code, and password."""
    data = request.get_json(silent=True) or {}
    title = data.get("title", "").strip()
    lock = data.get("lock", "").strip()
    password = data.get("password", "").strip()

    if not title or not lock or not password:
        return jsonify({"error": "Title, lock, and password are required"}), 400

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE title = ? AND lock_code = ?",
            (title, lock)
        ).fetchone()
        if user is None:
            return jsonify({"error": "Invalid credentials"}), 401
        if user["password_hash"] != hash_password(password):
            return jsonify({"error": "Invalid credentials"}), 401

        token = generate_token()
        conn.execute(
            "INSERT INTO sessions (token, username, created_at) VALUES (?, ?, ?)",
            (token, user["username"], time.time())
        )

    logger.info("Successful login for user %s (title=%s)", user["username"], title)
    return jsonify({
        "success": True,
        "token": token,
        "username": user["username"],
        "title": user["title"],
    })

@app.route("/api/c2/status", methods=["GET"])
@require_auth
def status():
    """Return current user info, lock state, device summary, and system metrics."""
    with get_db() as conn:
        lock_row = conn.execute("SELECT * FROM lock_state WHERE id = 1").fetchone()
        device_rows = conn.execute("SELECT * FROM devices").fetchall()
        online = sum(1 for d in device_rows if d["status"] == "online")
        total = len(device_rows)
    lock_state = {
        "locked": bool(lock_row["locked"]),
        "locked_by": lock_row["locked_by"],
        "locked_at": lock_row["locked_at"],
    }
    return jsonify({
        "authenticated": True,
        "username": request.c2_session["username"],
        "title": request.c2_session["title"],
        "lock_state": lock_state,
        "device_summary": {
            "total": total,
            "online": online,
            "offline": total - online,
        },
        "system_stats": get_system_stats(),
    })

@app.route("/api/c2/system_stats", methods=["GET"])
@require_auth
def system_stats():
    """Dedicated endpoint for system monitoring metrics."""
    return jsonify(get_system_stats())

@app.route("/api/c2/devices", methods=["GET"])
@require_auth
def devices():
    """Return the full list of devices from database."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
    return jsonify({"devices": [dict(r) for r in rows]})

@app.route("/api/c2/activities", methods=["GET"])
@require_auth
def activities():
    """Return recent activities (last 100) from database."""
    limit = request.args.get("limit", 100, type=int)
    if limit > 500:
        limit = 500
    with get_db() as conn:
        rows = conn.execute(
            "SELECT a.*, d.name as device_name FROM activities a JOIN devices d ON a.device_id = d.id ORDER BY a.timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return jsonify({"activities": [dict(r) for r in rows]})

@app.route("/api/c2/register_device", methods=["POST"])
@require_auth
def register_device():
    """Register a new Android device."""
    data = request.get_json(silent=True) or {}
    device_id = data.get("id", "").strip()
    if not device_id:
        return jsonify({"error": "Device ID is required"}), 400
    name = data.get("name", device_id)
    model = data.get("model", "")
    serial = data.get("serial", "")
    android_version = data.get("android", "")
    cpu = data.get("cpu", "")
    ram = data.get("ram", "")
    storage = data.get("storage", "")
    location = data.get("location", "")
    temperature = data.get("temperature", "")
    battery = data.get("battery")
    status = "online"

    with get_db() as conn:
        existing = conn.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone()
        if existing:
            conn.execute(
                """UPDATE devices SET name=?, model=?, serial=?, status=?, battery=?, android_version=?, cpu=?, ram=?, storage=?, location=?, temperature=?, last_seen=? WHERE id=?""",
                (name, model, serial, status, battery, android_version, cpu, ram, storage, location, temperature, datetime.now(timezone.utc).isoformat(), device_id)
            )
        else:
            conn.execute(
                """INSERT INTO devices (id, name, model, serial, status, battery, android_version, cpu, ram, storage, location, temperature, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (device_id, name, model, serial, status, battery, android_version, cpu, ram, storage, location, temperature, datetime.now(timezone.utc).isoformat())
            )
    return jsonify({"success": True, "device_id": device_id})

@app.route("/api/c2/heartbeat", methods=["POST"])
@require_auth
def heartbeat():
    """Update device status and battery for an existing device."""
    data = request.get_json(silent=True) or {}
    device_id = data.get("id", "").strip()
    if not device_id:
        return jsonify({"error": "Device ID is required"}), 400
    battery = data.get("battery")
    status = data.get("status", "online")
    location = data.get("location")
    with get_db() as conn:
        conn.execute(
            "UPDATE devices SET status=?, battery=?, location=?, last_seen=? WHERE id=?",
            (status, battery, location, datetime.now(timezone.utc).isoformat(), device_id)
        )
    return jsonify({"success": True})

@app.route("/api/c2/log_activity", methods=["POST"])
@require_auth
def log_activity():
    """Store an activity event from a device."""
    data = request.get_json(silent=True) or {}
    device_id = data.get("device_id", "").strip()
    action = data.get("action", "").strip()
    if not device_id or not action:
        return jsonify({"error": "device_id and action are required"}), 400
    timestamp = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO activities (device_id, action, timestamp) VALUES (?, ?, ?)",
            (device_id, action, timestamp)
        )
    return jsonify({"success": True})

@app.route("/api/c2/toggle_lock", methods=["POST"])
@require_auth
def toggle_lock():
    """Toggle the global lock state."""
    with get_db() as conn:
        current = conn.execute("SELECT locked FROM lock_state WHERE id=1").fetchone()
        new_locked = 1 if not current["locked"] else 0
        locked_by = None
        locked_at = None
        if new_locked:
            locked_by = request.c2_session["username"]
            locked_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE lock_state SET locked=?, locked_by=?, locked_at=? WHERE id=1",
            (new_locked, locked_by, locked_at)
        )
    lock_state = {
        "locked": bool(new_locked),
        "locked_by": locked_by,
        "locked_at": locked_at,
    }
    logger.info("System %s by %s", "locked" if new_locked else "unlocked", request.c2_session["username"])
    return jsonify({"success": True, "lock_state": lock_state})

@app.route("/api/c2/logout", methods=["POST"])
@require_auth
def logout():
    """Invalidate the current session."""
    token = request.headers.get("X-C2-Token")
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    return jsonify({"success": True})

# ---------------------------------------------------------------------------
# Health check (no auth)
# ---------------------------------------------------------------------------
@app.route("/api/c2/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[1] == "--port" else int(os.getenv("C2_PORT", DEFAULT_PORT))
    logger.info("Starting C2 server on port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False)