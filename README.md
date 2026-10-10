# Emergens

Field Intelligence Console for Authorized Security Testing

<p align="center">
  <img src="templates/logo.png" alt="Emergens logo" width="180">
</p>

<p align="center">
  <strong>Reconnaissance, asset intelligence, scan orchestration, and operational visibility in one focused workspace.</strong>
</p>

> [!WARNING]
> ## Authorized use only
> Emergens is intended exclusively for systems, networks, and applications that you own or have explicit written permission to assess. Do not use it to disrupt services, evade controls, access data without authorization, or operate outside your approved scope.

## Overview

Emergens is a modular security-testing console built for security researchers, defenders, and authorized assessment teams. It centralizes reconnaissance, scan execution, operational visibility, and review workflows in a single project environment.

The codebase includes a web interface, API layer, terminal console, and multiple scan/recon modules for approved testing and defensive engineering work.

## Features

- Unified operator workspace for web and terminal workflows
- Modular architecture for adding and managing capabilities
- Reconnaissance utilities for DNS, host, HTTP, service, and technology context
- Scan orchestration and job visibility
- Security-oriented reporting and evidence review
- Local runtime state, logs, and artifact storage
- Optional AI-assisted workflows and integrations
- Cross-platform support for Linux, macOS, and Windows
- Local Python deployment and Docker deployment support

## Requirements

- Python 3.10 or newer
- `pip` and `venv`
- Git
- Node.js and npm when working on the `web/` client (if used in your environment)
- Docker and Docker Compose for containerized deployment
- Network access to approved systems only

> Some modules may require optional system packages, elevated privileges, external services, or database drivers depending on the workflow.

## Quick start

### Option A — Local Python environment

```bash
git clone https://github.com/sollxfim-lab/Emergens.git
cd Emergens

python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate         # Windows PowerShell

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

The app defaults to port 8080 unless configured otherwise. Open the browser at:

```text
http://127.0.0.1:8080
```

### Option B — Conda environment

```bash
conda env create -f environment.yml
conda activate emergens-ci
python app.py
```

### Option C — Docker

```bash
docker compose up --build
```

Or build/run manually:

```bash
docker build -t emergens .
docker run --rm -p 8080:8080 emergens
```

## Configuration

Keep environment-specific settings outside source control whenever possible. Before starting work:

1. Confirm your approved target list and test window.
2. Review `config.py`, `config.json`, and deployment environment variables.
3. Enable only the integrations required for your workflow.
4. Use dedicated test credentials and least-privilege access.
5. Set conservative timeouts, concurrency, and request limits.
6. Store logs and exported artifacts according to your organization’s retention policy.

Avoid committing API keys, passwords, private keys, production data, or sensitive scan results to the repository.

## Usage principles

Emergens includes both passive and active testing capabilities. Follow these rules:

- Test only assets explicitly listed in the authorization document.
- Prefer passive collection and low-impact validation before intrusive checks.
- Obtain written approval before testing authentication, injection, file access, brute-force, or availability-sensitive functionality.
- Do not use amplification, traffic-flooding, service-disruption, evasion, or third-party proxy infrastructure against systems you do not control.
- Stop immediately when a test causes instability or unexpected impact.
- Preserve evidence responsibly and redact secrets or personal data from reports.

For module-specific behavior, inspect the source and documentation before enabling a module. This repository is not intended to provide attack recipes or disruption guidance.

## Repository structure

```text
Emergens/
├── .flake8
├── CHANGELOG.md
├── Dockerfile
├── LICENSE
├── README.md
├── app.py
├── config.json
├── config.py
├── docker-compose.yml
├── environment.yml
├── requirements.txt
├── terminal.py
├── vercel.json
├── wsgi.py
├── __pycache__/
├── ai_chat/
├── api/
│   └── index.py
├── auth/
├── brute-force-text/
├── core/
├── data/
│   ├── http_logs/
│   └── takeover_state/
├── files/
│   ├── proxies/
│   ├── referers.txt
│   └── useragent.txt
├── instance/
├── logs/
├── modules/
│   ├── __init__.py
│   ├── _common.py
│   ├── analytic_manager.py
│   ├── brute_force.py
│   ├── connectivity_check.py
│   ├── dirfuzz.py
│   ├── dns_lookup.py
│   ├── downsea.py
│   ├── email_security.py
│   ├── exploit_repository.py
│   ├── fixes.py
│   ├── git_scraper_wordlist.py
│   ├── headers_check.py
│   ├── ip_info.py
│   ├── lfi_rfi.py
│   ├── port_scan.py
│   ├── quick_menu.py
│   ├── scan_apikey.py
│   ├── scan_orchestrator.py
│   ├── scan_school.py
│   ├── search_user.py
│   ├── sniper.py
│   ├── source_viewer.py
│   ├── sql_injection.py
│   ├── sql_map.py
│   ├── sqli_engine.py
│   ├── ssl_check.py
│   ├── subdomain_enum.py
│   ├── subdomain_takeover.py
│   ├── tech_fingerprint.py
│   ├── telegram.py
│   ├── whois_lookup.py
│   ├── xss.py
│   └── xss_exploiter.py
├── porttxt/
├── proxy/
│   ├── http.txt
│   ├── meta.json
│   ├── proxies.txt
│   ├── socks4.txt
│   └── socks5.txt
├── static/
├── templates/
│   ├── css/
│   ├── img/
│   ├── js/
│   ├── artifact-structure.png
│   ├── dashboard.html
│   ├── docs.html
│   ├── favicon-180.png
│   ├── favicon-32.png
│   ├── favicon.ico
│   ├── get-started.html
│   ├── login.html
│   ├── logo.png
│   ├── privacy.html
│   ├── remote_access.html
│   ├── status.html
│   ├── terms.html
│   └── webps.html
├── wordlist/
└── ... additional runtime-generated folders and artifacts
```

### Directory overview

- `api/` — API routes and service interfaces
- `auth/` — authentication and access handlers
- `core/` — orchestration, configuration, utilities, and shared services
- `modules/` — reconnaissance, scanning, and security-testing modules
- `templates/` — dashboard and web UI templates
- `static/` — front-end static assets
- `data/` — runtime and state data, logs, and artifacts
- `files/` — supporting wordlists, user agents, referers, proxies, and data files
- `logs/` — application logs and diagnostic output
- `proxy/` and `porttxt/` — proxy and port-related datasets
- `wordlist/` — wordlists and custom dictionaries for enumeration workflows
- `ai_chat/` — optional AI chat integration components
- `instance/` — local instance data and settings
- `__pycache__/` — Python bytecode cache generated during local runs

## Troubleshooting

### Application does not start

- Confirm that Python 3.10+ is active: `python --version`
- Recreate the virtual environment and reinstall dependencies
- Check `logs/` and the terminal output for the first reported error
- Verify that the configured port is available

### A module is unavailable

- Install dependencies listed in `requirements.txt`
- Verify the module’s expected input files, configuration, and dependencies
- Check optional services or runtimes required by the module
- Run local validation steps before starting a scan

### Docker deployment issues

- Rebuild after dependency changes: `docker compose build --no-cache`
- Inspect container output with `docker compose logs`
- Confirm port mappings and mounted directories
- Avoid running the container with unnecessary privileges

## Development

Contributions are welcome when they improve safety, reliability, maintainability, and authorized defensive testing. Please:

1. Create a focused branch from the default branch.
2. Keep changes small and explain the security impact.
3. Do not add functionality intended to harm, disrupt, evade, or gain unauthorized access.
4. Add tests or reproducible validation where practical.
5. Never include real credentials, private targets, or sensitive scan output.
6. Open a pull request with a clear summary, test notes, and limitations.

## Versioning

The current documented release is 4.4.2. See [`CHANGELOG.md`](CHANGELOG.md) for release notes and implementation history.

## License

Emergens is distributed under the MIT License subject to the project’s authorized-use requirements. See [`LICENSE`](LICENSE) for the complete terms.

## Disclaimer

Emergens is provided for legitimate security research, defensive engineering, and authorized assessment only. The maintainers do not endorse or accept responsibility for unlawful access, disruption, or unauthorized testing.

<p align="center">
  <sub>Built for disciplined security work. Use responsibly.</sub>
</p>
