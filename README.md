Emergens
<p align="center"> <img src="templates/favicon.svg" alt="Emergens" width="80" height="80"> </p><h1 align="center">Emergens</h1><p align="center"> <strong>Field Intelligence Console — Passive Reconnaissance & Authorized Security Testing</strong> </p><p align="center"> <a href="#quick-start"><img src="https://img.shields.io/badge/quick%20start-2%20minutes-blue?style=for-the-badge" alt="Quick Start"></a> <a href="LICENSE"><img src="https://img.shields.io/badge/license-authorized%20use%20only-red?style=for-the-badge" alt="License"></a> <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/version-4.4.2-blue?style=for-the-badge" alt="Version"></a> <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a> <a href="https://flask.palletsprojects.com"><img src="https://img.shields.io/badge/flask-runtime-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask"></a> </p><p align="center"> <a href="#features">Features</a> · <a href="#quick-start">Quick Start</a> · <a href="#architecture">Architecture</a> · <a href="#modules">Modules</a> · <a href="#dashboard">Dashboard</a> · <a href="#extending">Extending</a> · <a href="#faq">FAQ</a> · <a href="#license">License</a> </p>
[!WARNING]
Authorized testing only. Use of this tool is permitted only when you have obtained explicit authorization from the system owner and only for lawful purposes, such as authorized security testing or use on websites you own or control. The creator and contributors provide this tool "as is," without warranties of any kind, and assume no liability for any misuse, damage, loss, service interruption, legal consequence, or other outcome arising from its use. You are solely responsible for obtaining proper authorization and complying with all applicable laws and regulations. By using this tool, you accept full responsibility for your actions.

Why Emergens
Emergens is a modular, plugin-driven field intelligence console for authorized reconnaissance and security testing. It bundles passive enumeration (WHOIS, DNS, TLS, HTTP headers), active web scanning (SQLi, XSS, LFI/RFI, directory fuzzing), an MHDDoS control panel, Telegram integration, a global chat, an AI assistant, and a full utility toolset — all behind a role-based authentication layer with zero public registration.

Built for security teams who need one console instead of ten CLI tools.

What makes it different	
Plugin backend	Drop a .py file into modules/ — it auto-registers. No edits to app.py.
Server-side RBAC	Every endpoint verifies the role. Viewer write attempts get HTTP 403, not just a hidden button.
Self-contained UI	All CSS and JS ship under templates/. No bundler. No node_modules. No build step.
Intrusive-tool gating	Active scanners are excluded from automatic basic-mode runs. A Quick Scan never fires payloads.
Live SSE streaming	Long-running scans stream progress in real time.
Streamlined first run	python app.py provisions the owner account, prints the password once, and serves on port 8080.
Features
<details open> <summary><strong>Reconnaissance — 11 passive modules</strong></summary>
#	Module	Returns
1	WHOIS	Registrar, creation / expiry dates, name servers, organization, status flags
2	DNS Records	A · AAAA · MX · NS · CNAME · SOA · TXT with TTLs
3	SSL / TLS Inspector	Full chain, key algorithm, expiry countdown, SANs, OCSP stapling, cipher grade A+–F
4	HTTP Security Headers	30+ headers, CSP analyzer, cookie audit, OWASP / PCI-DSS / HIPAA / SOC2 mapping
5	Subdomain Discovery	Certificate Transparency logs, DNS brute-force, passive OSINT
6	Technology Fingerprint	Server, framework, CMS, CDN, JS libraries, favicon hash
7	IP / ASN Info	Geolocation, ISP, ASN, hosting provider, reverse DNS, threat flags
8	Email Security	SPF, DKIM, DMARC parser with plain-language verdict
9	Port Scan	Wordlist-driven TCP — 1000-port basic cap, full-range expert
10	Connectivity Check	Multi-probe latency, packet loss, min / avg / max
11	LFI / RFI Scanner	Local and Remote File Inclusion — see below
</details><details> <summary><strong>Exploit Suite — 6 active scanners</strong></summary>
Module	Purpose
Dirfuzz	Directory and file discovery
SQLi Engine	Lightweight SQL injection — error / boolean / time / union
SQLMap	Comprehensive SQL injection
XSS Exploiter	Reflected XSS with WAF bypass
XSS (lightweight)	Fast XSS probe — 400 payloads
Sniper	Combined audit — Dirfuzz + XSS + takeover enumeration
Each supports live SSE streaming to the console.

</details><details> <summary><strong>Operations and integrations</strong></summary>
Feature	Description
MHDDoS Control Panel	External subprocess manager — 27 Layer 7 methods, 22 Layer 4 methods
Telegram Bot	/scan, /history, /status, /help — Public or Owner-only mode
Global Chat	Shared real-time conversation, owner-lockable
AI Assistant	Bring-your-own Anthropic key, claude-sonnet-5
Emergens DB	Leak-data search across userdata/*.json
Tools Hub	Brat Generator, Reels, OSINT, Anime, WiFi, IP Check, Music, Downloader, MCTOOLS
Live Console	CPU · RAM · Disk · streamed logs with syntax coloring
Theme Studio	Presets, custom colors, brand name, logo, custom page title
i18n	English and Bahasa Malaysia
</details>
Quick start
Requirements
Python 3.10+

A Unix-like shell (macOS, Linux, WSL) or PowerShell on Windows

Optional: an Anthropic API key for the AI Assistant

Install
bash
git clone <repo-url> emergens
cd emergens

python -m venv venv
source venv/bin/activate              # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Optional — edit .env and set ANTHROPIC_API_KEY=sk-ant-...
Run
bash
python app.py
First run — the console auto-provisions the Yanxzyx account with the Owner role. The password prints once. Save it.

Default port is 8080. Override it with the PORT environment variable:

bash
PORT=9090 python app.py
Open http://localhost:8080 and log in.

Rotate the owner password
bash
python app.py reset-password
Docker (optional)
bash
docker run -d \
  --name emergens \
  -p 8080:8080 \
  -e PORT=8080 \
  -v $(pwd)/userdata:/app/userdata \
  -v $(pwd)/data:/app/data \
  emergens:latest
Non-interactive stdin (Docker, CI, piped installs) automatically skips the port prompt and uses the default — docker run -i never hangs.

Architecture
text
┌─────────────────────────────────────────────────────────────────┐
│                       EMERGENS ARCHITECTURE                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   BROWSER                                                       │
│   ├── templates/dashboard.html   ← shell + inline i18n          │
│   ├── templates/css/style.css    ← 56 sections, design tokens   │
│   └── templates/js/              ← script.js + 3 addons         │
│                                                                 │
│        │ HTTPS / SSE                                            │
│        ▼                                                        │
│                                                                 │
│   FLASK (app.py)                                                │
│   ├── auth/          SQLite users + RBAC                        │
│   ├── core/          logger · history · system monitor          │
│   └── ai_chat/       Anthropic wrapper                          │
│                                                                 │
│        │ plugin discovery                                       │
│        ▼                                                        │
│                                                                 │
│   SCAN ORCHESTRATOR                                             │
│   ├── registry       walks modules/ on import                   │
│   ├── dispatcher     mode-string vs options-dict                │
│   └── jobs           bounded semaphore · cancellation · SSE     │
│                                                                 │
│        │                                                         │
│        ▼                                                         │
│                                                                 │
│   MODULES/            one file per tool — auto-registered       │
│   ├── recon/          whois · dns · ssl · headers · ip · …      │
│   ├── exploit/        dirfuzz · sql_map · xss · sniper · lfi_rfi│
│   ├── integrations/   telegram · search_user · scan_school      │
│   └── fixes.py        runtime patches                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
Request flow for a scan
text
Browser           app.py              Orchestrator          Module
   │                 │                      │                  │
   │  POST /api/scan/start                 │                  │
   ├────────────────►│                      │                  │
   │                 │  start_scan()        │                  │
   │                 ├─────────────────────►│                  │
   │                 │                      │  discover_tools  │
   │   { job_id }    │                      │  ──────────────► │
   │◄────────────────┤                      │                  │
   │                 │                      │                  │
   │  GET /api/scan/<id>/status            │   run(target)    │
   ├────────────────►│  get_progress()      ├─────────────────►│
   │                 ├─────────────────────►│                  │
   │   { percent }   │                      │   { data }       │
   │◄────────────────┤◄─────────────────────┤◄─────────────────┤
   │                 │                      │                  │
   │   repeat until status = "completed"   │                  │
Roles and permissions
Role	Tools (scan / history / chat)	Delete / Clear	Settings	Theme Studio
Owner	Yes	Yes	Yes	Yes
Analyst	Yes	Yes	No	No
Viewer	Read only	No	No	No
Owner — full access. Creates and deletes accounts, manages API keys, views Panel Manager, applies Theme Studio presets. The last remaining Owner cannot be deleted.

Analyst — full scan, history, and chat access. Cannot create accounts or change system-wide settings. API-key creation is capped at 2.

Viewer — read-only. Start Scan, Quick Scan, delete, and AI Chat send/clear are blocked server-side, not just hidden in the UI.

Modules
LFI / RFI Scanner
Nation-grade file inclusion scanner with ~200 curated payloads.

Coverage

Linux — /etc/passwd, /etc/shadow, /etc/hosts, /proc/self/environ, /proc/self/cmdline, Apache / Nginx / auth logs, SSH keys, .bash_history

Windows — win.ini, boot.ini, system.ini, web.config, sysprep.inf, system32\drivers\etc\hosts

Traversal styles — ../, ..%2f, %2e%2e%2f, ..%252f, ....//, ..%c0%af (overlong UTF-8), ..\

PHP wrappers — php://filter (base64 / rot13 / zlib / iconv), data://, expect://, zip://, phar://, php://input

RFI — http://, https://, //, ftp://, \\smb, data://, plus out-of-band callback

Detection signals

Signal	Weight
Signature match on body	High
Base64-decoded PHP source disclosure	High
PHP error delta	Medium
Content-type flip	Low
Body-length divergence	Low
Every finding is scored 0–100 for confidence and tagged critical / high / medium / low.

Modes — basic (~70 payloads, fast) and expert (~200 payloads, exhaustive).

Dashboard output — Six KPIs · clickable severity filter · per-finding confidence bars · collapsible payload and excerpt blocks · collapsible params drawer.

CLI

bash
python3 -m modules.lfi_rfi http://target/page.php?file=x
python3 -m modules.lfi_rfi http://target/ --mode expert --json
python3 -m modules.lfi_rfi --self-check
python3 -m modules.lfi_rfi --list-payloads
Emergens DB — Leak data search
A private lookup tool for JSON datasets placed in userdata/. Designed for internal OSINT research and data analysis during authorized testing.

Supported layouts

School structure — school, classes, students arrays

Legacy flat records — nama_penuh or name fields

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

Searchable fields — Full name · IC number · Class name · Student number · School name (case-insensitive).

Access — http://localhost:8080/Emergens_DB.html. The page verifies your session before showing content.

Dashboard
Theme Studio (Owner-only)
Presets · Custom primary and secondary accent colors · Brand name · Custom page title · Custom logo (upload or link) · AI provider override · Auto-open console after scans.

Sidebar customizer
Accent color (7 presets) · Sidebar style (Solid / Glass / Minimal) · Show or hide navigation labels · Default-open state.

Quick Menu
A draggable floating action button in the bottom-right. Opens a radial menu with shortcuts to Basic Scan, Expert Scan, History, Console, AI Chat, Telegram, and any custom links you add. Up to 5 user links can be pinned.

Floating windows
Every Quick Menu action opens a draggable, resizable, minimizable popup. Windows remember position and size per browser.

Profile
Avatar upload or link · Scan count · API keys · Telegram chats · Session time · Current theme and storage mode · Sign out.

Project structure
text
emergens/
├── app.py                        # Flask routing — modular backend
├── config.py                     # Paths, secrets, .env loader
├── requirements.txt
├── .env.example
│
├── auth/                         # SQLite-backed users and roles
│   ├── user_store.py
│   └── token_store.py            # Bearer tokens for external API v1
│
├── core/                         # Shared infrastructure
│   ├── logger_setup.py
│   ├── history_store.py
│   └── system_monitor.py
│
├── modules/                      # Plugin directory
│   ├── scan_orchestrator.py      # Job manager + module discovery
│   ├── fixes.py                  # Runtime patches
│   │
│   ├── whois_lookup.py           # Reconnaissance
│   ├── dns_lookup.py
│   ├── ssl_check.py
│   ├── headers_check.py
│   ├── subdomain_enum.py
│   ├── tech_fingerprint.py
│   ├── ip_info.py
│   ├── email_security.py
│   ├── port_scan.py
│   ├── connectivity_check.py
│   ├── lfi_rfi.py                # LFI / RFI scanner
│   │
│   ├── dirfuzz.py                # Exploit Suite
│   ├── sqli_engine.py
│   ├── sql_map.py
│   ├── xss_exploiter.py
│   ├── xss.py
│   ├── sniper.py
│   │
│   ├── scan_apikey.py            # Secret & API-key discovery
│   ├── scan_school.py
│   ├── search_user.py            # Emergens DB
│   ├── source_viewer.py          # VS Code-style source fetch
│   ├── git_scraper_wordlist.py
│   ├── telegram.py
│   ├── downsea.py
│   └── analytic_manager.py
│
├── ai_chat/
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
    │   └── style.css             # 56 sections, design tokens
    │
    └── js/
        ├── script.js             # Core dashboard logic
        ├── script2.js            # LFI / RFI renderer addon
        ├── app-mh5783.js         # MHDDoS Control panel
        └── app-ex3bve.js         # Exploit Suite panel
All CSS and JavaScript are served from templates/ — there is no static/ directory. The only external runtime dependencies are the Google Fonts stylesheet and the Font Awesome CDN, both loaded from dashboard.html's <head>.

Extending
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
[!IMPORTANT]
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
FAQ
<details> <summary><strong>Why is the default port 8080?</strong></summary>
Port 8080 is the conventional unprivileged HTTP alternative to 80. It does not require root, is not blocked by most corporate proxies, and does not collide with development servers that commonly bind to 3000, 5000, or 8000. Override it with the PORT environment variable.

</details><details> <summary><strong>How do I reset the owner password?</strong></summary>
bash
python app.py reset-password
This generates a new random password for Yanxzyx while keeping the Owner role. The old password stops working immediately.

</details><details> <summary><strong>Why does the dashboard say "not secure" in the browser bar?</strong></summary>
TLS has not been configured. Before exposing the console to the internet, run it behind a reverse proxy (Nginx, Caddy, Traefik) with a valid certificate, and set SESSION_COOKIE_SECURE=1.

</details><details> <summary><strong>Why is <code>lfi_rfi</code> excluded from Quick Scan?</strong></summary>
LFI/RFI is an active intrusion technique — it sends traversal payloads and probes for inclusion. Basic mode is deliberately limited to passive reconnaissance. The scanner remains selectable from the Security Testing carousel in expert mode.

</details><details> <summary><strong>How do I add a new module?</strong></summary>
Drop a .py file in modules/ that exposes a callable run(target, mode, **kwargs). See Extending for the full contract. No edits to app.py or scan_orchestrator.py required.

</details><details> <summary><strong>Where is the database?</strong></summary>
Users and history are stored in SQLite files under userdata/ and data/. Back up those directories to preserve state.

</details><details> <summary><strong>The AI Assistant doesn't reply.</strong></summary>
Set ANTHROPIC_API_KEY in .env. Without it the assistant endpoint returns an error rather than fabricating a response.

</details><details> <summary><strong>Can I use Emergens against a domain I don't own?</strong></summary>
Only with explicit written authorization — a signed penetration-test agreement or an active bug-bounty program that names the domain in scope. Running scans against infrastructure without permission may violate computer-misuse laws in your jurisdiction, even when every module used is purely passive.

</details>
Security notes
Password storage — Werkzeug hashes with per-user salt. No plaintext anywhere.

Server-side enforcement — every /api/ endpoint verifies the session role. Viewer write attempts receive HTTP 403 regardless of what the UI hides.

Login rate limiting — 5 failed attempts trigger a 5-minute lockout per client IP. Trust X-Forwarded-For only when TRUST_PROXY=1 is set.

Session cookies — HttpOnly, SameSite=Lax. Set SESSION_COOKIE_SECURE=1 when serving over HTTPS.

Runtime patches — modules/fixes.py hard-caps basic port scans at 1000 ports so a single malformed porttxt/*.txt file can never balloon a passive scan into a 65535-port sweep.

Intrusive-tool gating — LFI/RFI, XSS, SQLMap, SQLi, Dirfuzz, and Sniper are excluded from automatic basic-mode execution.

HTTPS — run behind a reverse proxy with a valid certificate before exposing to the internet.

Legal — the operator is solely responsible for obtaining written authorization and complying with all applicable laws.

Changelog
See CHANGELOG.md for the full release history.

4.4.2 — latest
Logger namespace rebranded oxysintx → opencode.

Boot sequence — animated blue spinner, per-step status, first-run password banner.

Ctrl+C on port prompt exits cleanly (code 130). While serving exits cleanly (code 0).

Non-TTY stdin auto-falls back to default port.

Default port changed to 8080.

Bootstrap dedup — ensure_default_user() and auto_restart_bot() run once per process.

Chat cache mtime race fixed.

_read_bounded() closes response in a finally block.

404 handler HTML cached at import time.

4.4.0
LFI / RFI scanner integrated end-to-end — 4 endpoints, availability entry, boot-screen line.

Ally color theme across all CLI output.

Removed /downloader_pinterest_tiktok.html and /data_main.html.

3.8.0 — scan_orchestrator.py
_INTRUSIVE_TOOLS gating.

list_tools() output includes intrusive and available flags.

Tool-list announcement word-wraps at 68 columns.

1.1.0 — templates/js/script2.js
Redesigned LFI/RFI card — compact KPI row, clickable severity filter, collapsible payload / excerpt blocks.

Zero emoji — Font Awesome icons only.

Event delegation on #scanResultGrid.

Fixed duplicate render.

Contributing
Fork the repository.

Create a feature branch — git checkout -b feature/my-feature.

Commit with conventional commits — feat: add X, fix: resolve Y.

Test locally — python app.py and verify in the dashboard.

Open a pull request describing the motivation and the change.

Keep PRs focused. One feature or fix per PR. Include a short description of the "why" — the "what" is visible in the diff.

Acknowledgments
Built on the shoulders of these projects and communities:

Flask — the runtime

Werkzeug — password hashing and WSGI

Font Awesome — icons

Space Grotesk and JetBrains Mono — typography

Aladhan API — prayer times

mcstatus.io — Minecraft server status

OWASP WSTG — methodology reference for the scanner suite

License
Authorized use only. No license is granted for use against infrastructure you do not own or lack written authorization to test. See the authorization notice at the top of this document.

<p align="center"> <sub>Built by <a href="https://github.com/Yanxzyx">Yanxzyx</a> · Emergens v4.4.2</sub> </p><p align="center"> <strong>Authorized testing only. You are responsible for the targets you touch.</strong> </p>
