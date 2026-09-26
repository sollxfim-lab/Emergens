<!-- Header -->
<p align="center">
  <a href="https://github.com/sollxfim-lab/Emergens">
    <img src="https://img.shields.io/badge/GitHub-Emergens-181717?style=for-the-badge&logo=github" alt="GitHub">
  </a>
  <img src="https://img.shields.io/badge/version-4.4.2-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT%20%2B%20Authorized%20Use-red?style=for-the-badge" alt="License">
</p>

<h1 align="center">Field Intelligence Console</h1>
<p align="center"><em>Passive reconnaissance &amp; authorized security testing</em></p>

---

> **Authorized testing only.**  
> Use is permitted only with explicit written authorization from the system owner.  
> The operator is solely responsible for complying with all applicable laws.  
> *See [License](#license) for details.*

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Requirements](#requirements)
- [Installation Step by Step](#installation-step-by-step)
  - [Step 1: Check Prerequisites](#step-1-check-prerequisites)
  - [Step 2: Clone Repository](#step-2-clone-repository)
  - [Step 3: Create Virtual Environment](#step-3-create-virtual-environment)
  - [Step 4: Activate Virtual Environment](#step-4-activate-virtual-environment)
  - [Step 5: Install Dependencies](#step-5-install-dependencies)
  - [Step 6: Configure Environment (Optional)](#step-6-configure-environment-optional)
  - [Step 7: Start Application](#step-7-start-application)
  - [Step 8: Access Console](#step-8-access-console)
  - [Step 9: First Run Setup](#step-9-first-run-setup)
  - [Step 10: Verify Installation (Optional)](#step-10-verify-installation-optional)
  - [Step 11: Docker Installation (Alternative)](#step-11-docker-installation-alternative)
  - [Step 12: HTTPS Setup (Production)](#step-12-https-setup-production)
- [Configuration](#configuration)
- [CLI Reference](#cli-reference)
- [Directory Layout](#directory-layout)
- [Stopping the Server](#stopping-the-server)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

**Emergens** is a modular security testing console designed for passive reconnaissance and authorized penetration testing. It provides a unified dashboard for orchestrating scans, inspecting SSL/TLS configurations, analyzing HTTP headers, and detecting LFI/RFI vulnerabilities. The console is built with Python 3.10+ and runs on Linux, macOS, and Windows (via WSL or PowerShell).

The project is actively maintained and available on GitHub:  
https://github.com/sollxfim-lab/Emergens

---

## Key Features

- **Scan Orchestrator** – Centralized management of multiple scan modules.
- **LFI / RFI Scanner** – Detect local and remote file inclusion vulnerabilities.
- **SSL Inspector** – Analyze certificates, ciphers, and protocol configurations.
- **HTTP Header Analyzer** – Identify security misconfigurations in HTTP responses.
- **AI Assistant** – Optional integration with Anthropic API for intelligent analysis.
- **Cloudflare Bypass** – Optional FlareSolverr integration for external bypass strategy.
- **Modular Architecture** – Easily extendable with custom modules.
- **Docker Support** – Ready-to-deploy container image with persistent volumes.

---

## Requirements

| Component | Requirement |
|-----------|-------------|
| **Python** | 3.10 or newer |
| **Shell** | Unix-like (macOS, Linux, WSL) or PowerShell on Windows |
| **Optional** | Anthropic API key – enables the AI Assistant |
| **Optional** | FlareSolverr URL – enables external Cloudflare bypass |

---

## Installation Step by Step

Follow the steps below in order. Each step includes the exact commands to run.

### Step 1: Check Prerequisites

Ensure you have Python 3.10+ and Git installed.

```bash
python3 --version
git --version
If Python is not installed, download it from https://www.python.org/downloads/.
If Git is not installed, download it from https://git-scm.com/downloads.

Step 2: Clone Repository
bash
git clone https://github.com/sollxfim-lab/Emergens.git emergens
cd emergens
Step 3: Create Virtual Environment
bash
python3 -m venv venv
This creates an isolated Python environment in the venv/ folder.

Step 4: Activate Virtual Environment
Choose the command for your operating system.

Linux / macOS:

bash
source venv/bin/activate
Windows PowerShell:

powershell
.\venv\Scripts\Activate.ps1
Windows Command Prompt (CMD):

cmd
venv\Scripts\activate.bat
After activation, your terminal prompt should show (venv).

Step 5: Install Dependencies
bash
pip install --upgrade pip
pip install -r requirements.txt
This installs all required Python packages.

Step 6: Configure Environment (Optional)
Copy the example environment file:

bash
cp .env.example .env
Edit .env to set optional variables:

env
ANTHROPIC_API_KEY=your_key_here
FLARESOLVERR_URL=http://localhost:8191
If you do not need the AI Assistant or Cloudflare bypass, you can skip this step.

Step 7: Start Application
bash
python app.py
The console listens on http://localhost:8080 by default.

To override the port:

bash
PORT=9090 python app.py
Non-interactive environments (Docker, CI, piped installs) automatically skip the port prompt and use the default.

Step 8: Access Console
Open your browser and navigate to:

text
http://localhost:8080
Step 9: First Run Setup
On first boot, the console provisions the default owner account:

Field	Value
Username	Yanxzyx
Role	Owner
Password	Printed once in the terminal
Save the password immediately. It is not shown again.

The startup banner reports:

Number of registered scan modules

Runtime patches applied

Wordlist loading status

Cloudflare bypass availability

Any module that failed to load – usually a sign of an incomplete pip install

To rotate the owner password later:

bash
python app.py reset-password
Generates a new random password for Yanxzyx while keeping the Owner role.
The previous password stops working immediately.

Step 10: Verify Installation (Optional)
Check the application version:

bash
python app.py --version
Verify module versions:

bash
python3 -c "from modules.lfi_rfi import __version__; print(__version__)"
python3 -c "from modules.scan_orchestrator import __version__; print(__version__)"
Step 11: Docker Installation (Alternative)
If you prefer Docker, run:

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

Step 12: HTTPS Setup (Production)
Always run behind a reverse proxy (Nginx, Caddy, Traefik) with a valid TLS certificate before exposing the console to the internet.

bash
SESSION_COOKIE_SECURE=1 python app.py
If your proxy sets X-Forwarded-For and X-Real-IP, also set:

bash
SESSION_COOKIE_SECURE=1 TRUST_PROXY=1 python app.py
Configuration
Environment variables can be set in a .env file or exported directly.

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
Directory Layout
After the first run, the following structure is created:

text
emergens/
├── data/                 Scan history, uploads, chat cache, settings
├── logs/                 Server logs
├── userdata/             SQLite — users, tokens, profiles, datasets
├── wordlist/             Runtime-cached payload libraries
├── porttxt/              Port wordlists
└── payment_data.json     Optional payment records
Backup tip: Back up data/ and userdata/ to preserve state. Both are plain files.

Stopping the Server
Press Ctrl+C in the terminal.

At the port prompt → exits with code 130

While serving → exits with code 0 after a graceful shutdown

Both paths print a clean status line — no Python traceback.

Troubleshooting
Symptom	Cause	Fix
Address already in use	Port 8080 taken	Set PORT= to a free port
ModuleNotFoundError	Missing dependency	Re-run pip install -r requirements.txt
Fewer modules loaded than expected	Import error	Check boot log; install optional extras (curl_cffi, cloudscraper)
Browser shows "not secure"	TLS not configured	Use reverse proxy and set SESSION_COOKIE_SECURE=1
AI Assistant returns error	Missing key	Set ANTHROPIC_API_KEY in .env
Forgot owner password	—	python app.py reset-password
License
This project is released under the MIT License.
However, usage is strictly limited to authorized security testing only.
No license is granted for testing infrastructure you do not own or lack written authorization to test.

See the LICENSE file for full details.

<p align="center"> <sub><strong>Emergens</strong> · v4.4.2 · Yanxzyx</sub><br> <sub>Made for the security community</sub> </p> ```
