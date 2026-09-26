<p align="center">
  <strong>Field Intelligence Console</strong><br>
  <sub>Version 4.4.2</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/port-8080-blue?style=flat-square" alt="Port">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=flat-square" alt="Platform">
</p>

> **Authorized testing only.**  
> Use is permitted only with explicit written authorization from the system owner.  
> The operator is solely responsible for complying with all applicable laws.

---

## Table of Contents

- [Requirements](#requirements)
- [Install](#install)
- [Start](#start)
- [First Run](#first-run)
- [Rotate the Owner Password](#rotate-the-owner-password)
- [Run Under HTTPS](#run-under-https)
- [Run with Docker](#run-with-docker)
- [Environment Variables](#environment-variables)
- [CLI Reference](#cli-reference)
- [Directory Layout After First Run](#directory-layout-after-first-run)
- [Stopping](#stopping)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Requirements

| Requirement | Detail |
|---|---|
| Python | 3.10 or newer |
| Shell | Unix-like (macOS, Linux, WSL) or PowerShell on Windows |
| Optional | Anthropic API key — enables the AI Assistant |
| Optional | FlareSolverr URL — enables the external Cloudflare bypass strategy |

---

## Install

```bash
git clone <repo-url> emergens
cd emergens

python -m venv venv
source venv/bin/activate              # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env                  # optional — set ANTHROPIC_API_KEY for AI Chat
Start
bash
python app.py
The console listens on http://localhost:8080 by default.

Override the port
bash
PORT=9090 python app.py
Non-interactive environments
Docker, CI pipelines, and piped installs skip the port prompt automatically and use the default. No -it flag is needed.

First Run
On first boot, the console provisions the default owner account:

Field	Value
Username	Yanxzyx
Role	Owner
Password	Printed once in the terminal
Save the password — it is not shown again.

The startup banner reports:

Number of registered scan modules

Runtime patches applied

Wordlist loading status

Cloudflare bypass availability

Any module that failed to load — usually a sign of an incomplete pip install

Rotate the Owner Password
bash
python app.py reset-password
Generates a new random password for Yanxzyx while keeping the Owner role. The previous password stops working immediately.

Run Under HTTPS
Run behind a reverse proxy (Nginx, Caddy, Traefik) with a valid certificate before exposing the console to the internet.

bash
SESSION_COOKIE_SECURE=1 python app.py
Set TRUST_PROXY=1 if the proxy sets X-Forwarded-For and X-Real-IP:

bash
SESSION_COOKIE_SECURE=1 TRUST_PROXY=1 python app.py
Run with Docker
bash
docker run -d \
  --name emergens \
  -p 8080:8080 \
  -e PORT=8080 \
  -e SESSION_COOKIE_SECURE=1 \
  -v $(pwd)/userdata:/app/userdata \
  -v $(pwd)/data:/app/data \
  emergens:latest
Volume mounts preserve user accounts, scan history, and JSON datasets across container rebuilds.

Environment Variables
Variable	Default	Purpose
PORT	8080	HTTP listen port
SESSION_COOKIE_SECURE	0	Set to 1 when serving over HTTPS
TRUST_PROXY	0	Set to 1 to honour X-Forwarded-For and X-Real-IP
ANTHROPIC_API_KEY	—	Enables the AI Assistant
FLARESOLVERR_URL	—	External Cloudflare bypass endpoint
OPENCODE_QUIET	0	Set to 1 to suppress startup animation
NO_COLOR	—	Set to 1 to disable ANSI colours
FORCE_COLOR	—	Set to 1 to force colours in non-TTY output
CLI Reference
bash
python app.py                     # Start the console
python app.py reset-password      # Rotate the default owner password
python app.py --version           # Print version and exit
Directory Layout After First Run
text
emergens/
├── data/                 Scan history, uploads, chat cache, settings
├── logs/                 Server logs
├── userdata/             SQLite — users, tokens, profiles, datasets
├── wordlist/             Runtime-cached payload libraries
├── porttxt/              Port wordlists
└── payment_data.json     Optional payment records
Back up data/ and userdata/ to preserve state. Both are plain files.

Stopping
Press Ctrl+C in the terminal.

At the port prompt → exits with code 130

While serving → exits with code 0 after a graceful shutdown

Both paths print a clean status line — no Python traceback.

Troubleshooting
Symptom	Cause	Fix
Address already in use	Port 8080 taken	Set PORT= to a free port
ModuleNotFoundError	Missing dependency	Re-run pip install -r requirements.txt
Fewer modules loaded than expected	Import error	Check the boot log; install optional extras (curl_cffi, cloudscraper)
Browser shows "not secure"	TLS not configured	Use a reverse proxy and set SESSION_COOKIE_SECURE=1
AI Assistant returns error	Missing key	Set ANTHROPIC_API_KEY in .env
Forgot owner password	—	python app.py reset-password
License
Authorized use only. No license is granted for testing infrastructure you do not own or lack written authorization to test.

<p align="center"> <sub><strong>Emergens</strong> · v4.4.2 · Yanxzyx</sub> </p>
