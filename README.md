# Emergens — Security Testing & OSINT Dashboard

A private dashboard for passive security testing and OSINT on domains you own or have written authorization to test.

## Features

- Username and password login with roles: Owner, Analyst, Viewer. No public account registration. The `Yanxzyx` account with Owner role is created automatically by `app.py` on first run. The password is shown once in the console.
- Settings available to Owner only: create a new account after selecting a role first. The password is generated automatically and shown once. List all accounts. Delete accounts. The last remaining Owner cannot be deleted.
- Analyst role has full access to all tools but no access to Settings.
- Viewer role is read-only: can view History, Docs, and scan results, but Start Scan, Quick Scan, Delete, and AI Chat send/clear are blocked server-side, not just hidden in the UI.
- `login.html` and `dashboard.html` are self-contained. All project CSS and JavaScript are inline directly inside the HTML files. There are no separate `static/css` or `static/js` files. The backend (`app.py`, `modules/`, and others) remains modular and separate.
- Red and black theme, dark and light mode, smooth animations, Font Awesome icons, no emoji.
- 10 reconnaissance and security tools with Basic and Expert modes: WHOIS, DNS, SSL/TLS, HTTP Security Headers, Subdomain Discovery, Tech Fingerprint, IP/ASN Info, Email Security (SPF/DKIM/DMARC), Port Scan, Connectivity Check.
- Overview: Quick Scan and Recent Scans list directly on the main page.
- History: search and filter by target, download results as JSON, delete individual entries.
- Live server console with log tail and CPU, RAM, and Disk monitoring.
- Code and text viewer with VS Code-style syntax highlighting using highlight.js. Extract and directly open script, CSS, and image links from fetched HTML.
- AI Chat using your own Anthropic API key with the `claude-sonnet-5` model. Chat history can be cleared.
- Detailed documentation in 6 categories. Each tool is explained with what it does, why it matters, and how to read the results, plus security concepts.
- Toast notifications, mobile responsive with hamburger menu, skeleton loading.
- Modular plugin backend. Add a new tool by placing a file in the `modules/` folder.
- **Emergens DB / Leak Data Search**: a dedicated search page (`/Emergens_DB.html`) that reads JSON files from the `userdata/` folder and searches leaked personal records by full name, IC number, class name, or student number. The search runs entirely locally through the backend and returns matches in a clean, responsive table. The page includes its own session verification overlay before allowing access.

All tools are passive and read-only. They only read public information similar to securityheaders.com, crt.sh, or the `whois` command. No exploits are sent.

## Install and Run

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Optional for AI Chat: copy .env.example to .env and set ANTHROPIC_API_KEY
cp .env.example .env

python app.py
```

On first run, the `Yanxzyx` account with Owner role is created automatically and the password is displayed in the terminal. Save this password because it is not shown again. To generate a new password for this account at any time while keeping the role:

```bash
python app.py reset-password
```

Open `http://localhost:5000` and log in with username `Yanxzyx` and the displayed password. The startup log also reports if any tools failed to load, which usually means the `pip install` step was incomplete.

## Roles and Settings

| Role    | Tools (scan/history/chat) | Delete/Clear | Settings |
|---------|:--------------------------:|:------------:|:--------:|
| Owner   | Yes                        | Yes          | Yes      |
| Analyst | Yes                        | Yes          | No       |
| Viewer  | Read only                  | No           | No       |

As an Owner, go to Settings to create a new account. Enter a username, select the role first, then submit. The new username and password are displayed once. There is no way to view an old password again. The last remaining Owner cannot be deleted, preventing complete account lockout.

## Emergens DB / Leak Data Search

This feature is a private lookup tool for searching JSON data placed in the `userdata/` folder. It is designed for internal OSINT research and data analysis during authorized testing.

### How it works

- JSON files must be placed in the `userdata/` folder in the project root.
- The search module supports two layouts:
  1. **School structure** with `school`, `classes`, and `students` arrays.
  2. **Legacy flat records** with `nama_penuh` or `name` fields.
- The search matches query text case-insensitively against:
  - Full name
  - IC number
  - Class name
  - Student number
  - School name
- The results are returned as JSON by the backend and rendered in a table by `Emergens_DB.html`.

### Access

- Log in with a valid account.
- Open `http://localhost:5000/Emergens_DB.html`.
- The page verifies your session before displaying any content.
- If the session is invalid, you are redirected to the login page.

### Supported JSON example

```json
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
        {"no": 1, "name": "ADAM INDRA MIKAIL BIN SHARAIZHI", "ic": "130728070155"}
      ]
    }
  ]
}
```

The backend flattens this structure into individual student records before searching, so you can search by any student detail and get the full context back.

## Add Your Own Tool

Create a new file in `modules/`, for example `modules/my_tool.py`:

```python
TOOL_INFO = {"name": "My Tool", "description": "Short description."}

def run(target: str, mode: str = "basic") -> dict:
    # Your logic here. mode can be "basic" or "expert".
    return {"tool": "my_tool", "target": target, "data": {}, "error": None}
```

The tool is auto-detected and appears in the dashboard tool list. No edits to `app.py` or `scan_orchestrator.py` are required.

## Project Structure

```
emergens/
├── app.py             # Routing only. Backend remains separate and modular.
├── config.py          # Paths, secrets, .env
├── requirements.txt
├── auth/              # user_store.py - username/password and role using SQLite
├── core/              # Logging, system monitor, history using SQLite
├── modules/           # Each file is one reconnaissance tool in plugin style
│   └── search_user.py # Leak data search (Emergens DB)
├── ai_chat/           # Anthropic API wrapper
├── userdata/          # JSON files for leak data search
└── templates/         # login.html, dashboard.html, Emergens_DB.html
                        # Self-contained. Project CSS and JavaScript are inline
                        # No separate static/css or static/js folders
```

## Security Notes

- Passwords are stored as hashes using Werkzeug, not plaintext.
- Every API endpoint checks the role on the server. Viewers trying to call write endpoints receive HTTP 403.
- The `/api/login` endpoint has rate limiting with 5 failed attempts causing a 5 minute lockout.
- Run behind HTTPS or a reverse proxy if exposed to the internet. The browser not secure warning means you have not done this yet.
- Use only on domains you own or have written authorization to test. This is entirely your responsibility.
