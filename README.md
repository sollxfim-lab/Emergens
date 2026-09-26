<p align="center"> <strong>Field Intelligence Console</strong><br> Passive reconnaissance & authorized security testing </p><p align="center"> <img src="https://img.shields.io/badge/version-4.4.2-blue?style=flat-square" alt="Version"> <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"> <img src="https://img.shields.io/badge/license-authorized%20use%20only-red?style=flat-square" alt="License"> </p>
Authorized testing only. Use is permitted only with explicit written authorization from the system owner. The operator is solely responsible for complying with all applicable laws.

Overview
Emergens is a modular, plugin-driven console for authorized reconnaissance and security testing. Passive enumeration, active web scanners, an MHDDoS control panel, Telegram integration, a global chat, an AI assistant, and a utility toolset — behind role-based authentication with no public registration.

Plugin backend — drop a .py file into modules/, it auto-registers

Server-side RBAC — every endpoint enforces role; UI hiding is only cosmetic

Self-contained UI — no bundler, no node_modules, no build step

Intrusive-tool gating — active scanners are excluded from automatic passive runs

Live SSE streaming — long-running scans report progress in real time

Quick start
bash
git clone <repo-url> emergens && cd emergens
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # optional — set ANTHROPIC_API_KEY for AI Chat
python app.py
First run provisions Yanxzyx with Owner role; password prints once. Default port is 8080 (override with PORT=...). Rotate the password:

bash
python app.py reset-password
Open http://localhost:8080.

Roles
Role	Scan / History / Chat	Delete	Settings
Owner	Yes	Yes	Yes
Analyst	Yes	Yes	No
Viewer	Read only	No	No
Owner cannot be removed if it is the last one. Analyst API keys are capped at 2. Viewer write attempts return HTTP 403.

Modules
Reconnaissance — passive, read-only

Module	Returns
WHOIS	Registrar, dates, name servers, organization
DNS	A · AAAA · MX · NS · CNAME · SOA · TXT
SSL / TLS	Chain, key, expiry, SANs, OCSP, cipher grade
HTTP Headers	30+ headers, CSP, cookies, OWASP / PCI-DSS mapping
Subdomain Discovery	Certificate Transparency, DNS brute-force, OSINT
Tech Fingerprint	Server, framework, CMS, CDN, favicon hash
IP / ASN Info	Geolocation, ISP, ASN, hosting, reverse DNS
Email Security	SPF, DKIM, DMARC with verdict
Port Scan	Wordlist-driven TCP (1000 basic · full expert)
Connectivity	Latency, packet loss, min / avg / max
LFI / RFI	File inclusion — ~200 payloads across Linux, Windows, PHP wrappers
Exploit Suite — active scanners, SSE streaming

Dirfuzz · SQLi Engine · SQLMap · XSS Exploiter · XSS (lightweight) · Sniper

Integrations

MHDDoS Control · Telegram Bot · Global Chat · AI Assistant · Emergens DB (leak-data search) · Tools Hub (Brat, Reels, OSINT, Anime, WiFi, IP Check, Music, Downloader, MCTOOLS)

LFI / RFI Scanner
Approximately 200 curated payloads across six traversal styles, two OS families, and every modern wrapper.

Linux — /etc/passwd, /etc/shadow, /proc/self/environ, Apache / Nginx / auth logs, SSH keys

Windows — win.ini, boot.ini, web.config, sysprep.inf, system32\drivers\etc\hosts

Traversal — ../, ..%2f, %2e%2e%2f, ..%252f, ....//, ..%c0%af

PHP wrappers — php://filter, data://, expect://, zip://, phar://, php://input

RFI — http(s)://, //, ftp://, \\smb, with out-of-band callback

Detected via signature match, base64-disclosed source, PHP error delta, content-type flip, and body-length divergence. Every finding is scored 0–100 for confidence.

bash
python3 -m modules.lfi_rfi http://target/page.php?file=x --mode expert
python3 -m modules.lfi_rfi --self-check
Extending
Create modules/my_tool.py:

python
TOOL_INFO = {"name": "My Tool", "version": "1.0.0", "description": "..."}
TOOL_KIND = "scanner"          # a non-scanner kind excludes the module
IS_SCAN_TOOL = True            # False keeps it out of the registry

def run(target: str, mode: str = "basic", **kwargs) -> dict:
    return {"tool": "my_tool", "target": target, "data": {}, "error": None}
Auto-registered on next import. Optional helpers: run_streaming() for SSE, to_sarif() for CI export, TOOL_INFO for carousel metadata.

Intrusive modules must be added to _INTRUSIVE_TOOLS in scan_orchestrator.py to keep them out of automatic basic-mode runs.

Versions
Component	Version
Core application	4.4.2
Scan orchestrator	3.8.0
Runtime patches	1.1.0
LFI / RFI scanner	1.0.2
Stylesheet	6.2
LFI / RFI renderer	1.1.0
bash
python3 -c "from modules.lfi_rfi import __version__; print(__version__)"     # 1.0.2
curl -s localhost:8080/api/lfi_rfi/status | jq '.version'                    # "1.0.2"
Security
Werkzeug password hashing with per-user salt

Server-side role checks on every /api/ endpoint

Login rate limit: 5 attempts → 5-minute lockout per IP

Session cookies: HttpOnly, SameSite=Lax; SESSION_COOKIE_SECURE=1 under HTTPS

Runtime patch caps basic port scans at 1000 ports

Active scanners excluded from automatic passive runs

Run behind a TLS-terminating reverse proxy before exposing publicly

Structure
text
emergens/
├── app.py                Flask routing
├── config.py             Paths, secrets, .env
├── auth/                 SQLite users + RBAC
├── core/                 Logger, history, system monitor
├── modules/              Plugin directory — one file per tool
├── ai_chat/              Anthropic wrapper
├── userdata/             JSON datasets (Emergens DB)
├── porttxt/              Port wordlists
├── wordlist/             Cached payloads
└── templates/            All UI — CSS and JS, no static/ directory
FAQ
Why port 8080? Conventional unprivileged HTTP port. Override with PORT.

Reset owner password? python app.py reset-password.

Why "not secure" in the browser? TLS not configured. Use a reverse proxy and set SESSION_COOKIE_SECURE=1.

Why is LFI/RFI excluded from Quick Scan? It is an active intrusion technique. Basic mode is passive by design; the scanner remains selectable in expert mode.

Where is the database? SQLite files under userdata/ and data/.

Changelog
4.4.2
Logger namespace rebranded oxysintx → opencode

Animated blue boot sequence with per-step status

Ctrl+C exits cleanly (130 at prompt, 0 while serving)

Non-TTY stdin falls back to default port

Default port changed to 8080

Bootstrap dedup — setup runs once per process

Chat cache mtime race fixed

_read_bounded() closes response in finally

404 HTML cached at import

4.4.0
LFI/RFI scanner integrated — 4 endpoints, availability entry, boot line

Ally color theme across CLI output

Removed legacy downloader routes

3.8.0
_INTRUSIVE_TOOLS gating

list_tools() exposes intrusive and available per entry

1.1.0 — script2.js
Redesigned LFI/RFI card

Clickable severity filter

Collapsible payload / excerpt blocks

Zero emoji, Font Awesome icons only

Fixed duplicate render

License
Authorized use only. No license is granted for testing infrastructure you do not own or lack written authorization to test.

<p align="center"> <sub>Emergens · Yanxzyx · v4.4.2</sub> </p>