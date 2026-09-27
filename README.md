<p align="center">
  <img src="templates/logo.png" alt="Emergens logo" width="180">
</p>

<h1 align="center">Emergens</h1>

<p align="center">
  <strong>Field Intelligence Console for Authorized Security Testing</strong>
</p>

<p align="center">
  Reconnaissance, asset intelligence, scan orchestration, and operational visibility in one focused workspace.
</p>

<p align="center">
  <a href="https://github.com/sollxfim-lab/Emergens"><img src="https://img.shields.io/badge/GitHub-Emergens-181717?style=flat-square&logo=github" alt="GitHub repository"></a>
  <img src="https://img.shields.io/badge/version-4.4.2-2563eb?style=flat-square" alt="Version 4.4.2">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10 or newer">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-64748b?style=flat-square" alt="Supported platforms">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%20%2B%20authorized%20use-dc2626?style=flat-square" alt="MIT license with authorized-use requirements"></a>
</p>

> [!WARNING]
> ## Authorized use only
> Emergens is intended exclusively for systems, networks, and applications that you own or have explicit written permission to assess. Do not use it to disrupt services, evade controls, access data without authorization, or exceed the scope of your authorization document.

## What is Emergens?

Emergens is a modular security-testing console built for security researchers, defenders, and authorized penetration-testing teams. It brings reconnaissance utilities, scan modules, result review, and integrated logging to organized security workflows.

The project is designed to help teams move from an approved target scope to structured findings with clearer visibility and repeatable workflows—without losing control of authorization and test boundaries.

## Highlights

- **Unified operator workspace** — access web and terminal workflows from one project.
- **Modular architecture** — add, inspect, and manage capabilities without coupling every workflow together.
- **Reconnaissance utilities** — collect useful DNS, host, service, HTTP, and technology context for approved targets.
- **Scan orchestration** — coordinate available modules and distinguish basic workflows from intrusive checks.
- **Security-focused reporting** — review findings, severity, evidence, excerpts, and scan status in a consistent UI.
- **Streaming visibility** — follow long-running jobs and monitor progress from the dashboard.
- **AI-assisted analysis** — optionally connect supported AI services for investigation and workflow assistance.
- **Operational logging** — retain application events and scan activity for troubleshooting and review.
- **Flexible deployment** — run locally with Python or use the included Docker configuration.
- **Cross-platform tooling** — supported development targets include Linux, macOS, and Windows.

## Architecture

<p align="center">
  <img src="templates/artifact-structure.png" alt="Emergens artifact structure and component organization" width="900">
</p>

<p align="center">
  <em>Emergens component structure and artifact flow</em>
</p>

At a high level, Emergens is organized around:

- **Web application** — the dashboard, API endpoints, templates, and static assets.
- **Core services** — configuration, logging, orchestration, authentication, and shared utilities.
- **Modules** — focused reconnaissance and security-testing capabilities.
- **Artifacts** — logs, wordlists, proxy data, scan output, and local application state.
- **Optional integrations** — AI, messaging, database, and external service connectors.

## Requirements

- Python **3.10 or newer**
- `pip` and `venv`
- Git
- Node.js and npm when working on the `web/` client
- Docker and Docker Compose for containerized deployment
- Network access to the approved systems and services in your test scope

> Requirements may vary by module. Some capabilities depend on optional system packages, elevated privileges, external services, or database drivers.

## Installation

### Option A — Local Python environment

```bash
git clone https://github.com/sollxfim-lab/Emergens.git
cd Emergens

python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate         # Windows PowerShell

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python start.py
```

The application uses **port 8080 by default**. Open `http://127.0.0.1:8080` after startup unless your local configuration specifies another port.

### Option B — Docker

```bash
docker compose up --build
```

Or build and run the image directly:

```bash
docker build -t emergens .
docker run --rm -p 8080:8080 emergens
```

Review `docker-compose.yml` and your local environment before starting. Do not expose an administrative or testing console to the public internet without appropriate authentication, network controls, and access restrictions.

## Configuration

Keep environment-specific values outside source control whenever possible. Before starting a session:

1. Confirm the approved target list and testing window.
2. Review `config.json` and any environment variables used by your deployment.
3. Configure only the integrations required for your workflow.
4. Use dedicated test credentials and least-privilege access.
5. Set conservative timeouts, concurrency, and request limits.
6. Store logs and exported artifacts according to your organization's retention policy.

Never commit API keys, passwords, private keys, proxy credentials, production data, or scan results to the repository. Use a local `.env` file or a secret manager where supported.

## Usage principles

Emergens can include both passive and active testing capabilities. Use the following operating rules:

- Test only assets explicitly listed in the authorization document.
- Prefer passive collection and low-impact validation before intrusive checks.
- Obtain written approval before testing authentication, injection, file access, brute-force, or availability-sensitive functionality.
- Do not use amplification, traffic-flooding, service-disruption, evasion, or third-party proxy infrastructure against systems you do not control.
- Pause immediately when a test causes instability or unexpected impact.
- Preserve evidence responsibly and redact secrets or personal data from reports.

For module-specific behavior, inspect the module documentation and source code before enabling it. This README intentionally does not provide attack recipes or instructions for disrupting services.

## Project layout

```text
Emergens/
├── app.py                  # Application entry point
├── start.py                # Startup and terminal entry point
├── api/                    # API routes and service interfaces
├── auth/                   # Authentication components
├── core/                   # Shared services and orchestration
├── modules/                # Reconnaissance and testing modules
├── templates/              # Web templates and project artwork
├── static/                 # Front-end assets
├── web/                    # Optional web-side tooling
├── data/                   # Local data and supporting resources
├── files/                  # Wordlists, proxy data, and runtime files
├── logs/                   # Runtime logs
├── config.json             # Local configuration
├── requirements.txt        # Python dependencies
├── Dockerfile              # Container image definition
└── docker-compose.yml       # Containerized deployment
```

## Troubleshooting

### The application does not start

- Confirm that Python 3.10+ is active: `python --version`.
- Recreate the virtual environment and reinstall dependencies.
- Check `logs/` and the terminal output for the first reported error.
- Confirm that port 8080 is available or select a different local port.

### A module is unavailable

- Install the dependencies listed in `requirements.txt`.
- Check the module's expected files, wordlists, and configuration.
- Verify that optional services are running and reachable.
- Run the built-in module or dependency checks before starting a scan.

### Docker deployment has problems

- Rebuild after dependency changes: `docker compose build --no-cache`.
- Inspect container output with `docker compose logs`.
- Confirm port mappings and mounted directories.
- Avoid running the container with unnecessary host privileges.

## Development

Contributions are welcome when they improve safety, reliability, maintainability, or authorized defensive testing. Please:

1. Create a focused branch from the default branch.
2. Keep changes small and explain the security impact.
3. Do not add functionality intended to harm, disrupt, evade, or gain unauthorized access.
4. Add tests or reproducible validation where practical.
5. Never include real credentials, private targets, or sensitive scan output.
6. Open a pull request with a clear summary, test notes, and limitations.

## Versioning

The current documented release is **4.4.2**. See [`CHANGELOG.md`](CHANGELOG.md) for release notes and implementation history.

## License

Emergens is distributed under the MIT License subject to the project's authorized-use requirements. See [`LICENSE`](LICENSE) for the complete terms.

## Disclaimer

Emergens is provided for legitimate security research, defensive engineering, and authorized assessment only. The maintainers do not endorse or accept responsibility for unlawful access, disruption, abuse, or misuse of this tool.

<p align="center">
  <sub>Built for disciplined security work. Use responsibly.</sub>
</p>
