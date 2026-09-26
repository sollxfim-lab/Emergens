<div align="center"> <img alt="Emergens" src="https://img.shields.io/badge/Emergens-Field%20Intelligence%20Console-3b82f6?style=for-the-badge" /> <br> <strong>Field Intelligence Console</strong><br> <em>Passive reconnaissance &amp; authorized security testing</em> <br><br> <img alt="Version" src="https://img.shields.io/badge/version-4.4.2-blue?style=flat-square"> <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white"> <img alt="Flask" src="https://img.shields.io/badge/flask-runtime-000000?style=flat-square&logo=flask&logoColor=white"> <img alt="License" src="https://img.shields.io/badge/license-authorized%20use%20only-red?style=flat-square"> <br><br> <a href="#overview">Overview</a> · <a href="#quick-start">Quick Start</a> · <a href="#roles">Roles</a> · <a href="#modules">Modules</a> · <a href="#lfi--rfi-scanner">LFI/RFI</a> · <a href="#extending">Extending</a> · <a href="#versions">Versions</a> · <a href="#security">Security</a> · <a href="#faq">FAQ</a> </div>
[!WARNING]
Authorized testing only. Use is permitted only with explicit written authorization from the system owner. The operator is solely responsible for complying with all applicable laws.

Overview
Emergens is a modular, plugin-driven console for authorized reconnaissance and security testing. Passive enumeration, active web scanners, an MHDDoS control panel, Telegram integration, a global chat, an AI assistant, and a utility toolset — behind role-based authentication with no public registration.

<table> <tr> <td width="50%" valign="top">
Architecture

Plugin backend — drop a .py file into modules/, it auto-registers

Server-side RBAC — every endpoint enforces role; UI hiding is only cosmetic

Self-contained UI — no bundler, no node_modules, no build step

</td> <td width="50%" valign="top">
Behaviour

Intrusive-tool gating — active scanners are excluded from automatic passive runs

Live SSE streaming — long-running scans report progress in real time

Modular — each tool is a self-contained module

</td> </tr> </table>
Quick Start
bash
git clone <repo-url> emergens && cd emergens

python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env                                 # optional — set ANTHROPIC_API_KEY
python app.py
Item	Value
Default port	8080 — override with PORT=9090 python app.py
First run	Provisions Yanxzyx with Owner role; password prints once
Rotate password	python app.py reset-password
Dashboard	Open http://localhost:8080
Non-interactive stdin (Docker, CI, piped installs) automatically skips the port prompt and uses the default — docker run -i never hangs.

Roles
Role	Scan / History / Chat	Delete	Settings
Owner	Yes	Yes	Yes
Analyst	Yes	Yes	No
Viewer	Read only	No	No
Owner cannot be removed if it is the last one

Analyst API keys are capped at 2

Viewer write attempts return HTTP 403 — enforced server-side, not just hidden in the UI

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
Port Scan	Wordlist-driven TCP — 1000 basic · full expert
Connectivity	Latency, packet loss, min / avg / max
LFI / RFI	File inclusion — ~200 payloads across Linux, Windows, PHP wrappers
Exploit Suite — active scanners, SSE streaming
Dirfuzz · SQLi Engine · SQLMap · XSS Exploiter · XSS (lightweight) · Sniper

Integrations
MHDDoS Control · Telegram Bot · Global Chat · AI Assistant · Emergens DB (leak-data search) · Tools Hub (Brat · Reels · OSINT · Anime · WiFi · IP Check · Music · Downloader · MCTOOLS)

LFI / RFI Scanner
Approximately 200 curated payloads across six traversal styles, two OS families, and every modern wrapper.

Category	Coverage
Linux	/etc/passwd, /etc/shadow, /proc/self/environ, Apache / Nginx / auth logs, SSH keys
Windows	win.ini, boot.ini, web.config, sysprep.inf, system32\drivers\etc\hosts
Traversal	../ · ..%2f · %2e%2e%2f · ..%252f · ....// · ..%c0%af
PHP wrappers	php://filter · data:// · expect:// · zip:// · phar:// · php://input
RFI	http(s):// · // · ftp:// · \\smb — with out-of-band callback
Detection signals — signature match · base64-disclosed source · PHP error delta · content-type flip · body-length divergence. Every finding is scored 0–100 for confidence.

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
Auto-registered on next import.

Optional helpers

run_streaming() for SSE

to_sarif() for CI export

TOOL_INFO for carousel metadata

⚠️ Intrusive modules must be added to _INTRUSIVE_TOOLS in scan_orchestrator.py to keep them out of automatic basic-mode runs.

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

Session cookies: HttpOnly, SameSite=Lax; set SESSION_COOKIE_SECURE=1 under HTTPS

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
<details> <summary><strong>Why port 8080?</strong></summary> <br> Conventional unprivileged HTTP port. Override with <code>PORT=…</code>. </details><details> <summary><strong>Reset owner password?</strong></summary> <br> <code>python app.py reset-password</code> </details><details> <summary><strong>Why "not secure" in the browser?</strong></summary> <br> TLS not configured. Use a reverse proxy and set <code>SESSION_COOKIE_SECURE=1</code>. </details><details> <summary><strong>Why is LFI/RFI excluded from Quick Scan?</strong></summary> <br> It is an active intrusion technique. Basic mode is passive by design; the scanner remains selectable in expert mode. </details><details> <summary><strong>Where is the database?</strong></summary> <br> SQLite files under <code>userdata/</code> and <code>data/</code>. </details>
Changelog
4.4.2 — current
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

<div align="center"> <sub><strong>Emergens</strong> · Yanxzyx · v4.4.2</sub>
<sub><em>Authorized testing only. You are responsible for the targets you touch.</em></sub>

</div>