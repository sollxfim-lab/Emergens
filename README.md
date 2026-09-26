<!-- Header -->
<p align="center">
  <img src="templates/logo.png" alt="Emergens logo" width="180">
</p>

<p align="center">
  <a href="https://github.com/sollxfim-lab/Emergens">
    <img src="https://img.shields.io/badge/GitHub-Emergens-181717?style=for-the-badge&logo=github" alt="GitHub">
  </a>
  <img src="https://img.shields.io/badge/version-4.4.2-blue?style=for-the-badge" alt="Version 4.4.2">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10 or newer">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge" alt="Supported platforms">
  <img src="https://img.shields.io/badge/license-MIT%20%2B%20Authorized%20Use-red?style=for-the-badge" alt="MIT license with authorized-use requirements">
</p>

<h1 align="center">Emergens</h1>
<p align="center"><strong>Field Intelligence Console</strong></p>
<p align="center"><em>Passive reconnaissance and authorized security testing</em></p>

> [!WARNING]
> **Authorized use only.** Emergens must be used only against systems for which you have explicit written authorization. You are solely responsible for complying with all applicable laws, regulations, and contractual requirements. See the [License](#license) section before using this project.

## Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [CLI reference](#cli-reference)
- [Directory layout](#directory-layout)
- [Stopping the server](#stopping-the-server)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Overview

**Emergens** is a modular security-testing console for passive reconnaissance and authorized penetration-testing workflows. It provides a unified dashboard for running scan modules, reviewing results, and inspecting common web and TLS security signals.

The project is maintained at [github.com/sollxfim-lab/Emergens](https://github.com/sollxfim-lab/Emergens).

## Features

- **Scan orchestrator** — Centralized management of registered scan modules.
- **LFI/RFI scanner** — Test for local and remote file-inclusion issues in authorized environments.
- **SSL/TLS inspector** — Review certificates, ciphers, and protocol configuration.
- **HTTP header analyzer** — Identify common security misconfigurations in HTTP responses.
- **Optional AI assistant** — Integrate with the Anthropic API for analysis assistance.
- **Optional external integration** — Connect to a FlareSolverr instance when permitted by your test scope.
- **Modular architecture** — Add and maintain custom modules independently.
- **Docker support** — Run the console with persistent data volumes.

## Requirements

| Component | Requirement |
| --- | --- |
| Python | 3.10 or newer |
| Git | Required for installation from source |
| Operating system | Linux, macOS, Windows, or WSL |
| Optional | Anthropic API key for the AI assistant |
| Optional | FlareSolverr URL for the external integration |

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/sollxfim-lab/Emergens.git emergens
cd emergens
```

### 2. Create and activate a virtual environment

**Linux/macOS/WSL:**

```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows PowerShell:**

```powershell
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
```

**Windows Command Prompt:**

```bat
py -3 -m venv venv
venv\Scripts\activate.bat
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Configure the environment (optional)

If the repository provides an example environment file, copy it before editing:

```bash
cp .env.example .env
```

Then add only the integrations you need:

```dotenv
ANTHROPIC_API_KEY=your_key_here
FLARESOLVERR_URL=http://localhost:8191
```

Do not commit `.env` files or API keys to the repository.

### 5. Start the application

```bash
python app.py
```

The console listens on `http://localhost:8080` by default. To use another port:

```bash
PORT=9090 python app.py
```

On Windows PowerShell:

```powershell
$env:PORT = "9090"
python app.py
```

Open <http://localhost:8080> in your browser, or use the port you configured.

### First-run setup

On first startup, Emergens provisions the default owner account and prints the generated password once in the terminal. Save that password securely; it is not displayed again.

The startup output also reports registered modules, runtime patches, wordlist status, external-integration availability, and module-load errors.

To rotate the owner password later:

```bash
python app.py reset-password
```

The generated password replaces the previous password immediately.

### Verify the installation (optional)

```bash
python app.py --version
python -c "from modules.lfi_rfi import __version__; print(__version__)"
python -c "from modules.scan_orchestrator import __version__; print(__version__)"
```

### Docker (alternative)

Build the image from the repository, then run it with persistent volumes:

```bash
docker build -t emergens:latest .
docker run -d \
  --name emergens \
  -p 8080:8080 \
  -e PORT=8080 \
  -v "$(pwd)/userdata:/app/userdata" \
  -v "$(pwd)/data:/app/data" \
  emergens:latest
```

The volume mounts preserve user accounts, scan history, and application data across container rebuilds.

> **Windows note:** Replace `$(pwd)` with an absolute Windows path or use Docker Desktop's path-mounting syntax.

## Configuration

Environment variables can be placed in `.env` or exported in the shell.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | HTTP listen port. |
| `SESSION_COOKIE_SECURE` | `0` | Set to `1` when serving through HTTPS. |
| `TRUST_PROXY` | `0` | Set to `1` only when a trusted reverse proxy sets forwarding headers. |
| `ANTHROPIC_API_KEY` | — | Enables the optional AI assistant. |
| `FLARESOLVERR_URL` | — | Configures the optional external integration. |
| `OPENCODE_QUIET` | `0` | Set to `1` to suppress startup animation. |
| `NO_COLOR` | — | Set to `1` to disable ANSI colors. |
| `FORCE_COLOR` | — | Set to `1` to force colors in non-TTY output. |

### Production HTTPS

Do not expose the development server directly to the internet. Use a properly configured reverse proxy such as Nginx, Caddy, or Traefik with a valid TLS certificate.

When HTTPS is enabled at the proxy, set:

```bash
SESSION_COOKIE_SECURE=1 python app.py
```

If the proxy supplies `X-Forwarded-For` and `X-Real-IP`, enable proxy handling only when that proxy is trusted:

```bash
SESSION_COOKIE_SECURE=1 TRUST_PROXY=1 python app.py
```

## CLI reference

```text
python app.py                     Start the console
python app.py reset-password      Rotate the owner password
python app.py --version           Print the application version
```

## Directory layout

After the first run, the following directories and files may be created:

```text
emergens/
├── data/                 Scan history, uploads, chat cache, and settings
├── logs/                 Server logs
├── userdata/             SQLite database for users, tokens, profiles, and datasets
├── wordlist/             Runtime-cached payload libraries
├── porttxt/              Port wordlists
└── payment_data.json     Optional payment records
```

Back up `data/` and `userdata/` to preserve application state. Review backups carefully because they may contain sensitive information.

## Stopping the server

Press <kbd>Ctrl</kbd>+<kbd>C</kbd> in the terminal. Emergens performs a graceful shutdown and exits without printing a Python traceback.

## Troubleshooting

| Symptom | Likely cause | Recommended fix |
| --- | --- | --- |
| Address already in use | Port `8080` is occupied | Set `PORT` to an available port. |
| `ModuleNotFoundError` | A dependency is missing | Re-run `python -m pip install -r requirements.txt`. |
| Fewer modules loaded than expected | A module failed to import | Review the startup log and install the required optional dependencies. |
| Browser reports an insecure connection | TLS is not configured | Put the application behind a reverse proxy with HTTPS. |
| AI assistant returns an error | API key is missing or invalid | Set `ANTHROPIC_API_KEY` in `.env` and restart the application. |
| Owner password is unavailable | The one-time password was not saved | Run `python app.py reset-password`. |

## License

Emergens is distributed under the MIT License, subject to the authorized-use requirements described in the repository's [`LICENSE`](LICENSE) file. No permission is granted to test, scan, or access infrastructure that you do not own or have explicit written authorization to assess.

<p align="center">
  <sub><strong>Emergens</strong> · v4.4.2 · Made for the security community</sub>
</p>
