<p align="center">
  <strong>Field Intelligence Console</strong><br>
  Passive reconnaissance &amp; authorized security testing
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-4.4.2-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-authorized%20use%20only-red?style=flat-square" alt="License">
</p>

> **Authorized testing only.**  
> Use is permitted only with explicit written authorization from the system owner.  
> The operator is solely responsible for complying with all applicable laws.

---

## Table of Contents

- [Overview](#overview)
- [Version Matrix](#version-matrix)
- [Runtime Verification](#runtime-verification)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [First Run](#first-run)
- [Rotate Owner Password](#rotate-owner-password)
- [Docker](#docker)
- [Run Behind HTTPS](#run-behind-https)
- [License](#license)

---

## Overview

**Field Intelligence Console** is a security testing dashboard designed for passive reconnaissance and authorized security assessments. It provides modular components for scan orchestration, LFI/RFI scanning, SSL inspection, HTTP header analysis, and dashboard visualization.

---

## Version Matrix

| Component | Version |
|---|---|
| Core application | 4.4.2 |
| Scan orchestrator | 3.8.0 |
| Runtime patches | 1.1.0 |
| LFI / RFI scanner | 1.0.2 |
| SSL inspector | 3.3.0 |
| HTTP header analyzer | 3.2.0 |
| Stylesheet | 6.2 |
| LFI / RFI renderer | 1.1.0 |
| Dashboard shell | 6.2 |

---

## Runtime Verification

Verify installed component versions at runtime:

```bash
python3 -c "from modules.lfi_rfi import __version__; print(__version__)"           # 1.0.2
python3 -c "from modules.scan_orchestrator import __version__; print(__version__)" # 3.8.0
curl -s localhost:8080/api/lfi_rfi/status | jq '.version'                          # "1.0.2"
```

---

## Requirements

- Python 3.10 or newer
- A Unix-like shell (macOS, Linux, WSL) or PowerShell on Windows
- Optional: an Anthropic API key for the AI Assistant

---

## Installation

```bash
git clone <repo-url> emergens
cd emergens

python -m venv venv
source venv/bin/activate              # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env                  # optional — set ANTHROPIC_API_KEY for AI Chat
```

---

## Running the Application

Start the console:

```bash
python app.py
```

The default port is `8080`. To override it, set the `PORT` environment variable:

```bash
PORT=9090 python app.py
```

Then open:

```text
http://localhost:8080
```

---

## First Run

On first run, the console provisions the `Yanxzyx` account with the **Owner** role.

The password is printed once in the terminal. Save it immediately. It is not shown again.

---

## Rotate Owner Password

To reset the owner password:

```bash
python app.py reset-password
```

---

## Docker

Run the application with Docker:

```bash
docker run -d \
  --name emergens \
  -p 8080:8080 \
  -e PORT=8080 \
  -v $(pwd)/userdata:/app/userdata \
  -v $(pwd)/data:/app/data \
  emergens:latest
```

Non-interactive stdin environments such as Docker, CI, and piped installs automatically skip the port prompt and use the default port.

---

## Run Behind HTTPS

Before exposing the console to the internet, place it behind a reverse proxy with a valid TLS certificate and enable secure session cookies:

```bash
SESSION_COOKIE_SECURE=1 python app.py
```

---

## License

Authorized use only.

No license is granted for testing infrastructure you do not own or lack written authorization to test.

---

<p align="center">
  <sub><strong>Emergens</strong> · v4.4.2</sub>
</p>
