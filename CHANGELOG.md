# Changelog

## [4.4.2] — current

### Core (app.py)
- Logger namespace rebrand `oxysintx` → `opencode`
- Boot sequence — animated blue spinner, per-step status, first-run banner
- Ctrl+C on port prompt exits cleanly (code 130)
- Ctrl+C while serving exits cleanly (code 0)
- Non-TTY stdin auto-falls back to default port
- Default port is **8080**
- Bootstrap dedup — `ensure_default_user()` and `auto_restart_bot()` run once per process
- Chat cache mtime race fixed
- `_read_bounded()` closes response in finally block
- 404 handler HTML cached at import time

## [4.4.0]
- LFI/RFI scanner integrated end-to-end
- 4 new endpoints: `/api/lfi_rfi/{status,scan,scan/stream,payloads}`
- Removed `/downloader_pinterest_tiktok.html` and `/data_main.html`
- Boot screen added to startup

## [3.8.0] — scan_orchestrator.py
- `_INTRUSIVE_TOOLS` gating — LFI/RFI, XSS, SQLi, Dirfuzz, Sniper excluded from automatic basic mode
- `get_registry_snapshot()` exposes `intrusive_tools`
- `list_tools()` output includes `intrusive` and `available` flags
- Tool-list announcement word-wraps at 68 columns and colours intrusive entries

## [3.7.0] — scan_orchestrator.py
- Registry announcement bypasses root logger, writes blue to stdout
- Embedded-mode detection skips redundant announcement when app.py boots
- Non-TTY fallback prints one clean line

## [1.1.0] — lfi_rfi.py CLI renderer
- All coloured strings precomputed outside f-strings (fixes SyntaxError)
- Docstring Windows path escaped (fixes SyntaxWarning)
- Version bumped 1.0.0 → 1.0.1 → 1.0.2

## [1.1.0] — templates/js/script2.js
- Redesigned LFI/RFI card
- Clickable severity filter chips
- Collapsible payload / excerpt blocks (fixes long Cloudflare challenge overflow)
- Collapsible params drawer
- Zero emoji — all Font Awesome icons
- Event delegation on `#scanResultGrid`

## [6.2] — templates/css/style.css
- Section 51 — IP Info hero card
- Section 52 — SSL/TLS certificate helpers
- Section 53 — Country flag / map link polish
- Section 54 — Light-theme overrides for new panels
- Section 55 — Tech Fingerprint cards
- Section 56 — LFI/RFI result card

## [1.0.0] — lfi_rfi.py
- Initial release — ~200 payloads, 6 traversal styles, PHP wrappers, RFI OOB
- Multi-signal detection with confidence scoring
- SARIF export, SSE streaming, Flask blueprint
