Emergens — Security Testing & Exploiter Dashboard
https://img.shields.io/badge/version-4.4.2-blue?style=for-the-badge
https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white
https://img.shields.io/badge/flask-runtime-000000?style=for-the-badge&logo=flask&logoColor=white
https://img.shields.io/badge/license-authorized%20use%20only-red?style=for-the-badge

Authorization notice — Use of this tool is permitted only when you have obtained explicit authorization from the system owner and only for lawful purposes, such as authorized security testing or use on websites you own or control. The creator and contributors provide this tool "as is," without warranties of any kind, and assume no liability for any misuse, damage, loss, service interruption, legal consequence, or other outcome arising from its use. You are solely responsible for obtaining proper authorization and complying with all applicable laws and regulations. By using this tool, you accept full responsibility for your actions.

A modular, plugin-driven field intelligence console for authorized reconnaissance and security testing. Passive enumeration, active web scanners, an MHDDoS control panel, Telegram integration, a global chat, an AI assistant, and a full utility toolset — all behind a role-based authentication layer with no public registration.

Table of contents
Highlights

Quick start

Roles and permissions

Reconnaissance modules

Exploit Suite

LFI / RFI Scanner

MHDDoS Control Panel

Emergens DB — leak data search

Integrations

Tools Hub

Dashboard and UX

Project structure

Adding your own tool

Version manifest

Security notes

Changelog

Highlights
Zero public registration	Accounts are created by an Owner only. The default Yanxzyx owner is provisioned on first run and the password is shown once.
Server-side role enforcement	Every API endpoint verifies the role. Viewer write attempts receive HTTP 403 regardless of what the UI hides.
Modular plugin backend	Drop a .py file into modules/ and it auto-registers. No edits to app.py or scan_orchestrator.py needed.
Self-contained UI	All CSS and JS live under templates/. No build step, no bundler, no node_modules.
Intrusive-tool gating	LFI/RFI, XSS, SQLMap, SQLi, Dirfuzz, and Sniper are excluded from the basic-mode auto fallback — a dashboard Quick Scan can never fire them without an explicit selection.
Live SSE streaming	Long-running scans stream progress to the console in real time.
Two languages	English and Bahasa Malaysia, switchable at runtime.
Dark / light theme + Theme Studio	Presets, custom accent colors, brand name, logo, custom page title.
Quick start
bash
git clone <repo-url> emergens
cd emergens

python -m venv venv
source venv/bin/activate                # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Optional — enables the AI Assistant
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY=sk-ant-...

python app.py
First run — the console auto-provisions the Yanxzyx account with the Owner role. The password is printed once in the terminal. Save it — it is not shown again.

Rotate the password at any time:

bash
python app.py reset-password
Default port is 8080. Override with the PORT environment variable:

bash
PORT=9090 python app.py
Open http://localhost:8080 and log in.

Non-interactive stdin (Docker, CI, piped installs) automatically skips the port prompt and uses the default — docker run -i never hangs.

Roles and permissions
Role	Tools (scan / history / chat)	Delete / Clear	Settings	Theme Studio
Owner	Yes	Yes	Yes	Yes
Analyst	Yes	Yes	No	No
Viewer	Read only	No	No	No
Owner — full access. Creates and deletes accounts, manages API keys, views Panel Manager, applies Theme Studio presets. The last remaining Owner cannot be deleted.

Analyst — full scan, history, and chat access. Cannot create accounts or change system-wide settings. API-key creation is capped at 2.

Viewer — read-only. Start Scan, Quick Scan, delete, and AI Chat send/clear are blocked server-side, not just hidden in the UI.

Reconnaissance modules
Eleven passive, read-only modules. Equivalent to what whois, dig, openssl s_client, securityheaders.com, or crt.sh would return. No exploits are sent.

#	Module	Description
1	WHOIS	Registrar, creation and expiry dates, name servers, organization, status flags.
2	DNS Records	A / AAAA / MX / NS / CNAME / SOA / TXT with TTLs.
3	SSL/TLS Inspector	Full chain, key algorithm, expiry countdown, SANs, OCSP stapling, cipher strength, A+–F grade.
4	HTTP Security Headers	30+ headers, CSP analyzer, cookie audit, OWASP / PCI-DSS / HIPAA / SOC2 mapping, Cloudflare bypass.
5	Subdomain Discovery	Certificate Transparency logs, DNS brute-force, passive OSINT.
6	Technology Fingerprint	Server, framework, CMS, CDN, JS libraries, favicon hash, multi-path probing.
7	IP / ASN Info	Geolocation, ISP, ASN, hosting provider, reverse DNS, threat flags.
8	Email Security	SPF, DKIM, DMARC parser with plain-language verdict.
9	Port Scan	Wordlist-driven TCP scanner — 1000-port basic cap, full-range expert mode.
10	Connectivity Check	Multi-probe latency, packet loss, min / avg / max.
11	LFI / RFI Scanner	Local and Remote File Inclusion — see below.
Exploit Suite
Active scanners — run only against authorized targets. Each supports live SSE streaming.

Module	Purpose	Techniques
Dirfuzz	Directory and file discovery	Wordlist-driven, tunable concurrency
SQLi Engine	Lightweight SQL injection	error / boolean / time / union — up to 15 params in expert mode
SQLMap	Comprehensive SQLi	All SQLMap techniques, tunable threads and duration
XSS Exploiter	Reflected XSS	Wordlist-based, WAF bypass
XSS (lightweight)	Fast XSS probe	400 payloads, optional mutation
Sniper	Combined audit	Chains Dirfuzz + XSS + takeover enumeration under one budget
Every module respects --max-duration, --rate-limit, and --concurrency. Wordlists are exposed via /api/<module>/wordlists and refreshed with POST /api/<module>/wordlists/sync.

LFI / RFI Scanner
Nation-grade file inclusion scanner with ~200 curated payloads across:

Linux sensitive files — /etc/passwd, /etc/shadow, /etc/hosts, /proc/self/environ, /proc/self/cmdline, Apache / Nginx / auth logs, SSH keys, .bash_history.

Windows sensitive files — win.ini, boot.ini, system.ini, web.config, sysprep.inf, system32\drivers\etc\hosts.

Traversal styles — ../, ..%2f, %2e%2e%2f, ..%252f, ....//, ..%c0%af (overlong UTF-8), ..\ (Windows).

PHP wrappers — php://filter (base64 / rot13 / zlib / iconv chains), data://, expect://, zip://, phar://, php://input.

RFI — http://, https://, //, ftp://, \\smb, data://, plus out-of-band callback support via --callback-url.

Detection signals
Signature match on response body

Base64-decoded PHP source disclosure

PHP error delta

Content-type flip

Body-length divergence

Every finding is scored 0–100 for confidence and tagged critical / high / medium / low.

Modes
basic — approximately 70 payloads, fast.

expert — approximately 200 payloads, exhaustive.

Dashboard output
Dedicated result card with:

Six KPIs — Findings · Params · Payloads · Tests · Requests · Duration

Clickable severity filter

Per-finding confidence bars

Collapsible payload and excerpt blocks (so multi-kilobyte Cloudflare challenges never stretch the card)

Collapsible params drawer

CLI
bash
python3 -m modules.lfi_rfi http://target/page.php?file=x
python3 -m modules.lfi_rfi http://target/ --mode expert --json
python3 -m modules.lfi_rfi --self-check
python3 -m modules.lfi_rfi --list-payloads
MHDDoS Control Panel
The MHDDoS engine runs as an external subprocess managed by app.py.

Layer 7 methods — GET, POST, HEAD, CFB, CFBUAM, BYPASS, OVH, STRESS, DYN, SLOW, NULL, COOKIE, PPS, EVEN, GSB, DGB, AVB, APACHE, XMLRPC, BOT, BOMB, DOWNLOADER, KILLER, TOR, RHEX, STOMP.

Layer 4 methods — TCP, UDP, SYN, VSE, MINECRAFT, MCBOT, CONNECTION, CPS, FIVEM, FIVEM-TOKEN, TS3, MCPE, ICMP, OVH-UDP, MEM, NTP, DNS, ARD, CLDAP, CHAR, RDP.

Reflector support — MEM / NTP / DNS / ARD / CLDAP / CHAR / RDP accept a reflector file.

Proxy rotation — proxy file selector, proxy type, RPC index.

Live monitoring — running attacks, per-attack status, 50-entry history, stop and stop-all.

Use only against systems you own or are authorized to test.

Emergens DB — leak data search
A private lookup tool for JSON datasets placed in userdata/. Designed for internal OSINT research and data analysis during authorized testing.

Supported JSON layouts
School structure — school, classes, students arrays.

Legacy flat records — nama_penuh or name fields.

json
{
  "school": {
    "name": "SMK (L) METHODIST",
    "alias": "Methodist Boys' School",
    "address": "250 Jalan Air Itam, 10460 George Town, Malaysia",
    "year": 2026
  },
  "classes": [
    {
      "className": "1A",
      "teacher": "IRDINA BATRISYIA BINTI MOHAMAD ZAHIR",
      "students": [
        { "no": 1, "name": "ADAM INDRA MIKAIL BIN SHARAIZHI", "ic": "130728070155" }
      ]
    }
  ]
}
The backend flattens this structure into individual records before searching, so you can query by any student detail and get full context back.

Searchable fields
Full name · IC number · Class name · Student number · School name — all case-insensitive.

Access
Open http://localhost:8080/Emergens_DB.html. The page verifies your session before showing content and redirects to /login.html if invalid.

Integrations
Telegram Bot
Command Emergens from any Telegram client.

Commands — /start, /scan <domain>, /history, /status, /help.

Modes — Public (any chat) or Owner-only (restricted to the configured Owner Chat ID).

Per-chat registry — every chat that has sent /start is listed with its Chat ID.

Broadcast — one message to every registered chat.

Auto-restart — the bot restarts on every server boot if credentials are stored.

Setup: create a bot via @BotFather, paste the token and username into Telegram Bot in the sidebar, optionally set your Chat ID (via @userinfobot) to lock it to Owner-only mode, and press Connect Bot.

Global Chat
Every signed-in account sees the same real-time conversation. Tap any name to view that user's profile (avatar, role). Owners can lock chat — non-owners then see a locked banner and are blocked from sending.

AI Assistant
Bring-your-own Anthropic API key. Set ANTHROPIC_API_KEY in .env; the console uses claude-sonnet-5. Chat history is stored server-side and can be cleared at any time.

Prayer times (Waktu Solat)
Live prayer times from the Aladhan API for Malaysia (JAKIM method) and Indonesia (Kemenag method). Cross-check against official sources for compliance.

Network traffic
Inbound — real request counter, sampled every few seconds from /api/system/stats.

Outbound — every fetch() the dashboard itself issues, bucketed into a 60-second rolling window.

Both rendered as SVG spark-lines with hover tooltips.

Tools Hub
A floating toolbox accessible from the sidebar's Tools entry. Each tool opens in a fullscreen workspace inside the hub modal.

Tool	Purpose
Brat Generator	Brat-style cover generator — offline canvas renderer, optional remote API.
Reels	TikTok keyword video search with in-console preview.
OSINT	Username / email / number lookup across configured sources.
Anime	OtakOtaku search — anime, characters, articles.
WiFi Scanner	Honest network info panel — shows what browsers are permitted to read (connection type, approximate location).
IP Check	Geolocate any IP or domain via ipwho.is; "Check My IP" for your own.
Music Downloader	Apple Music search + direct-audio fetch (when configured).
Downloader	TikTok watermark-free fetch / Pinterest image search.
MCTOOLS	MCPEDL search for Minecraft skins, mods, shaders, texture packs.
Quick Access	Reserved for user-added quick links.
Every tool endpoint is a public third-party API consumed by the browser. When an endpoint is not configured or returns an error, the tool shows an honest error rather than fabricated data.

Dashboard and UX
Theme Studio (Owner-only)
Presets · Custom primary and secondary accent colors · Brand name · Custom page title · Custom logo (upload or link) · AI provider override · Auto-open console after scans.

Sidebar customizer (Preferences)
Accent color (7 presets) · Sidebar style (Solid / Glass / Minimal) · Show or hide navigation labels · Default-open state.

Display overrides
Auto / Phone / Laptop layout modes · Detected device and battery level · Language toggle (English / Bahasa Malaysia).

Quick Menu
A draggable floating action button in the bottom-right corner. Click to open a radial menu with shortcuts to Basic Scan, Expert Scan, History, Console, AI Chat, Telegram, and any custom links you add. Up to 5 user links can be pinned. Long-press a custom item to remove it.

Floating windows
Every Quick Menu action opens a draggable, resizable, minimizable popup. Windows remember position and size per browser. Minimized windows dock to the bottom-left corner.

Notes
A local-only scratchpad that auto-saves to localStorage on input. No server round-trip.

Profile
Avatar upload or link · Scan count · API keys · Telegram chats · Session time · Current theme and storage mode · Sign out.

Project structure
text
emergens/
├── app.py                        # Flask routing. Modular backend.
├── config.py                     # Paths, secrets, .env loader.
├── requirements.txt
├── .env.example
│
├── auth/                         # SQLite-backed users and roles
│   ├── user_store.py
│   └── token_store.py            # Bearer tokens for external API v1
│
├── core/                         # Shared infrastructure
│   ├── logger_setup.py
│   ├── history_store.py          # SQLite history
│   └── system_monitor.py
│
├── modules/                      # Plugin directory — one file per tool
│   ├── scan_orchestrator.py      # Job manager + module discovery
│   ├── fixes.py                  # Runtime patches (port_scan hardening)
│   │
│   ├── whois_lookup.py
│   ├── dns_lookup.py
│   ├── ssl_check.py
│   ├── headers_check.py
│   ├── subdomain_enum.py
│   ├── tech_fingerprint.py
│   ├── ip_info.py
│   ├── email_security.py
│   ├── port_scan.py
│   ├── connectivity_check.py
│   ├── lfi_rfi.py                # Local / Remote File Inclusion scanner
│   │
│   ├── dirfuzz.py                # Exploit Suite
│   ├── sqli_engine.py
│   ├── sql_map.py
│   ├── xss_exploiter.py
│   ├── xss.py
│   ├── sniper.py
│   │
│   ├── scan_apikey.py            # Secret and API-key discovery
│   ├── scan_school.py            # School search backend
│   ├── search_user.py            # Emergens DB — leak data search
│   ├── source_viewer.py          # VS Code-style source fetch
│   ├── git_scraper_wordlist.py   # Wordlist sync from public repos
│   ├── telegram.py               # Telegram bot bridge
│   ├── downsea.py                # Downsea blueprint
│   └── analytic_manager.py       # Exploit repository and analytics
│
├── ai_chat/                      # Anthropic wrapper
│   └── chat_handler.py
│
├── userdata/                     # JSON datasets for Emergens DB
├── porttxt/                      # Port wordlists — port2.txt … port1000.txt
├── wordlist/                     # Runtime-cached payload wordlists
│
└── templates/                    # All UI, self-contained
    ├── get-started.html
    ├── login.html
    ├── dashboard.html
    ├── payment.html
    ├── management_payment.html
    ├── Emergens_DB.html
    ├── Emergens_osint.html
    ├── remote_access.html
    ├── MyEspT.html
    ├── structure_folder_file.html
    ├── password_lock.html
    ├── docs.html
    ├── privacy.html
    ├── terms.html
    │
    ├── css/
    │   └── style.css             # Single stylesheet
    │
    └── js/
        ├── script.js             # Core dashboard logic
        ├── script2.js            # LFI/RFI renderer addon
        ├── app-mh5783.js         # MHDDoS Control panel
        └── app-ex3bve.js         # Exploit Suite panel
All CSS and JavaScript are served from templates/ — there is no static/ directory. The only external runtime dependencies are the Google Fonts stylesheet and the Font Awesome CDN, both loaded from dashboard.html's <head>.

Adding your own tool
Create a file in modules/. Minimum viable shape:

python
# modules/my_tool.py
TOOL_INFO = {
    "name": "My Tool",
    "version": "1.0.0",
    "description": "Short description.",
    "category": "Recon",
    "author": "YourName",
}

# Optional but recommended
TOOL_KIND    = "scanner"   # a non-scanner kind excludes the module
IS_SCAN_TOOL = True        # set False to keep it out of the registry

def run(target: str, mode: str = "basic", **kwargs) -> dict:
    return {
        "tool":   "my_tool",
        "target": target,
        "data":   {},
        "error":  None,
    }
scan_orchestrator.discover_tools() walks modules/ at import time. Any module that exposes a callable run, does not start with _, is not in the exclusion list, and does not set TOOL_KIND to a non-scanner value is registered automatically.

Optional helpers recognised by the orchestrator
Attribute	Purpose
TOOL_INFO	Metadata rendered in the Security Testing carousel
TOOL_KIND	Filter — non-scanner kinds are excluded
IS_SCAN_TOOL	Hard on/off switch
run_streaming(target, options, cancel_event)	SSE streaming support
to_sarif(result)	SARIF export for CI integration
If your module is intrusive — sends payloads, probes for injection, makes outbound requests beyond passive recon — add its name to _INTRUSIVE_TOOLS in scan_orchestrator.py. This excludes it from the automatic basic-mode fallback so a dashboard Quick Scan never fires it without an explicit selection.

Version manifest
Component	Version	File
Core application	4.4.2	app.py
Scan orchestrator	3.8.0	modules/scan_orchestrator.py
Runtime patches	1.1.0	modules/fixes.py
LFI / RFI scanner	1.0.2	modules/lfi_rfi.py
SSL inspector	3.3.0	modules/scan_ssl.py
HTTP header analyzer	3.2.0	modules/scan_headers.py
Stylesheet	6.2	templates/css/style.css
LFI / RFI renderer	1.1.0	templates/js/script2.js
Dashboard shell	6.2	templates/dashboard.html
Verify at runtime
bash
# Python modules
python3 -c "from modules.scan_orchestrator import __version__; print(__version__)"   # 3.8.0
python3 -c "from modules.lfi_rfi import __version__; print(__version__)"             # 1.0.2

# HTTP endpoints
curl -s localhost:8080/api/lfi_rfi/status | jq '.version'                            # "1.0.2"
javascript
// Browser console
window.LfiRfiRenderer.selfCheck()
// { version: "1.1.0", ... }
Security notes
Password storage — Werkzeug hashes with per-user salt. No plaintext anywhere.

Server-side enforcement — every /api/ endpoint verifies the session role. Viewer write attempts receive HTTP 403 regardless of what the UI hides.

Login rate limiting — 5 failed attempts trigger a 5-minute lockout per client IP. Trust X-Forwarded-For only when TRUST_PROXY=1 is set.

Session cookies — HttpOnly, SameSite=Lax. Set SESSION_COOKIE_SECURE=1 when serving over HTTPS.

Runtime patches — modules/fixes.py hard-caps basic port scans at 1000 ports so a single malformed porttxt/*.txt file can never balloon a passive scan into a 65535-port sweep.

Intrusive-tool gating — LFI/RFI, XSS, SQLMap, SQLi, Dirfuzz, and Sniper are excluded from automatic basic-mode execution.

HTTPS — run behind a reverse proxy with a valid certificate before exposing to the internet. If your browser shows a "not secure" warning, TLS has not been configured yet.

Legal — the operator is solely responsible for obtaining written authorization and complying with all applicable laws.

Changelog
4.4.2
Core (app.py)

Logger namespace rebranded oxysintx → opencode across app.py, scan_orchestrator.py, fixes.py.

Boot sequence — animated blue spinner, per-step status, first-run password banner.

Ctrl+C on the port prompt exits cleanly (code 130).

Ctrl+C while serving exits cleanly (code 0).

Non-TTY stdin auto-falls back to the default port.

Default port changed to 8080.

Bootstrap dedup — ensure_default_user() and auto_restart_bot() run once per process.

Chat cache mtime race fixed.

_read_bounded() closes the response in a finally block.

404 handler HTML cached at import time.

4.4.0
LFI / RFI scanner integrated end-to-end — import guard, 4 endpoints, availability entry, module-status entry, boot-screen line.

Ally color theme applied across all CLI output.

Removed /downloader_pinterest_tiktok.html and /data_main.html.

Bootstrap duplicate log lines removed.

3.8.0 — scan_orchestrator.py
_INTRUSIVE_TOOLS gating — lfi_rfi, xss, xss_exploiter, sql_map, sql_injection, sqli_engine, sniper, dirfuzz excluded from automatic basic mode.

get_registry_snapshot() exposes intrusive_tools and filtered basic_tools.

list_tools() output includes "intrusive": bool and "available": bool on every entry.

Tool-list announcement word-wraps at 68 columns and colors intrusive entries differently.

3.7.0 — scan_orchestrator.py
Registry announcement bypasses the root logger, writes blue to sys.stdout.

Embedded-mode detection skips the announcement when app.py already prints its own boot screen.

Non-TTY fallback prints one clean line.

1.1.0 — lfi_rfi.py CLI renderer
All colored strings precomputed outside f-strings (fixes SyntaxError).

Docstring Windows path escaped (fixes SyntaxWarning).

1.1.0 — templates/js/script2.js
Redesigned LFI/RFI card — compact KPI row, cleaner typography, tighter spacing.

Clickable severity filter chips.

Collapsible payload and excerpt blocks — solves the multi-kilobyte Cloudflare challenge overflow.

Collapsible params drawer.

Zero emoji — every glyph is a Font Awesome icon class.

Event delegation on #scanResultGrid — one listener instead of per-card.

Fixed duplicate render (extracts LFI entries before delegating to the original renderer).

6.2 — templates/css/style.css
Section 51 — IP Info hero card.

Section 52 — SSL/TLS certificate helpers.

Section 53 — Country flag / map link polish.

Section 54 — Light-theme overrides for new panels.

Section 55 — Tech Fingerprint cards.

Section 56 — LFI/RFI result card.

1.0.0 — lfi_rfi.py
Initial release — approximately 200 payloads, 6 traversal styles, PHP wrappers, RFI out-of-band.

Multi-signal detection with confidence scoring.

SARIF export, SSE streaming, Flask blueprint.

<div align="center">
Emergens — Field Intelligence Console

Authorized testing only. You are responsible for the targets you touch.

</div>