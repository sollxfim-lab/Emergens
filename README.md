<p align="center"> <strong>Field Intelligence Console</strong><br> Passive reconnaissance &amp; authorized security testing </p><p align="center"> <img src="https://img.shields.io/badge/version-4.4.2-blue?style=flat-square" alt="Version"> <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"> <img src="https://img.shields.io/badge/license-authorized%20use%20only-red?style=flat-square" alt="License"> </p>
Authorized testing only. Use is permitted only with explicit written authorization from the system owner. The operator is solely responsible for complying with all applicable laws.

Version
Component	Version
Core application	4.4.2
Scan orchestrator	3.8.0
Runtime patches	1.1.0
LFI / RFI scanner	1.0.2
SSL inspector	3.3.0
HTTP header analyzer	3.2.0
Stylesheet	6.2
LFI / RFI renderer	1.1.0
Dashboard shell	6.2
Verify at runtime:

bash
python3 -c "from modules.lfi_rfi import __version__; print(__version__)"     # 1.0.2
python3 -c "from modules.scan_orchestrator import __version__; print(__version__)"  # 3.8.0
curl -s localhost:8080/api/lfi_rfi/status | jq '.version'                    # "1.0.2"
Run
Requirements
Python 3.10 or newer

A Unix-like shell (macOS, Linux, WSL) or PowerShell on Windows

Optional: an Anthropic API key for the AI Assistant

Install
bash
git clone <repo-url> emergens
cd emergens

python -m venv venv
source venv/bin/activate              # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env                  # optional — set ANTHROPIC_API_KEY for AI Chat
Start
bash
python app.py
Default port is 8080. Override with the PORT environment variable:

bash
PORT=9090 python app.py
Open http://localhost:8080 in a browser.

First run
The console provisions the Yanxzyx account with the Owner role. The password is printed once in the terminal — save it. It is not shown again.

Rotate the owner password
bash
python app.py reset-password
Docker
bash
docker run -d \
  --name emergens \
  -p 8080:8080 \
  -e PORT=8080 \
  -v $(pwd)/userdata:/app/userdata \
  -v $(pwd)/data:/app/data \
  emergens:latest
Non-interactive stdin (Docker, CI, piped installs) automatically skips the port prompt and uses the default.

Run behind HTTPS
Use a reverse proxy with a valid certificate before exposing the console to the internet, and set SESSION_COOKIE_SECURE=1.

bash
SESSION_COOKIE_SECURE=1 python app.py
License
Authorized use only. No license is granted for testing infrastructure you do not own or lack written authorization to test.

<p align="center"> <sub><strong>Emergens</strong> · v4.4.2</sub> </p>