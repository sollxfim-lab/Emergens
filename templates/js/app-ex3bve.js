/* ============================================================================
 * app-ex3bve.js — Exploit Suite for Emergens
 * v2.0.0 — SHARK THEME · professional, attractive, multi-instance
 *
 * Sub-tools
 *   • Dirfuzz        — /api/dirfuzz/*
 *   • SQLi Engine    — /api/sqli/*
 *   • SQLMap         — /api/sqlmap/*
 *   • SQL Injection  — /api/sql_injection/*   (lightweight)
 *   • XSS Exploiter  — /api/xss/*
 *   • XSS Simple     — /api/xss_simple/*
 *   • Sniper         — /api/sniper/*
 *   • HTTP Logger    — /api/logger/*
 *
 * Changelog v2.0.0
 *   ✔ Shark-themed UI — fins, teeth, ocean depths, predatory red accents
 *   ✔ Animated shark fin header for each active tab
 *   ✔ MHDDoS + Exploit sidebar buttons forced to red gradient (CSS injection)
 *   ✔ Card grid layout: tabs grouped by category
 *   ✔ Live status pill, animated radar sweep, teeth-strip progress bars
 *   ✔ Multi-instance safe — every mount has its own state + DOM
 *   ✔ All SSE streams tracked per instance, closed on unmount + unload
 *   ✔ run_streaming events rendered with animated wave markers
 *   ✔ Preserves v1.0.x public API — no app.py changes needed
 *
 * Public API
 *   window.ExploitSuite.mount(selectorOrEl, { defaultTab })
 *   window.ExploitSuite.unmount()
 *   window.ExploitSuite.open(tabName)
 *   window.ExploitSuite.create(instanceName)  → new isolated instance
 * ========================================================================= */
(function () {
  'use strict';

  /* ── Endpoints ─────────────────────────────────────────────────────── */
  const EP = {
    dirfuzz: {
      wordlists: '/api/dirfuzz/wordlists',
      scan:      '/api/dirfuzz/scan',
      stream:    '/api/dirfuzz/scan/stream',
    },
    sqli: {
      wordlists: '/api/sqli/wordlists',
      scan:      '/api/sqli/scan',
      stream:    '/api/sqli/scan/stream',
    },
    sqlmap:    { scan: '/api/sqlmap/scan' },
    sqlinj:    { scan: '/api/sql_injection/scan' },
    xss: {
      wordlist:  '/api/xss/wordlist',
      scan:      '/api/xss/scan',
      stream:    '/api/xss/scan/stream',
    },
    xssSimple: { scan: '/api/xss_simple/scan' },
    sniper: {
      scan:   '/api/sniper/scan',
      stream: '/api/sniper/scan/stream',
    },
    logger: {
      list:   '/api/logger/requests',
      detail: '/api/logger/requests',
      stats:  '/api/logger/stats',
      clear:  '/api/logger/clear',
      tag:    '/api/logger/requests',
      har:    '/api/logger/har',
      stream: '/api/logger/stream',
    },
  };

  /* ── Tiny helpers ──────────────────────────────────────────────────── */
  const $  = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function el(tag, attrs, ...children) {
    const n = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k === 'class')       n.className = v;
        else if (k === 'html')   n.innerHTML = v;
        else if (k.startsWith('on') && typeof v === 'function')
          n.addEventListener(k.slice(2).toLowerCase(), v);
        else                     n.setAttribute(k, v);
      }
    }
    const append = (c) => {
      if (c == null || c === false) return;
      if (Array.isArray(c)) { c.forEach(append); return; }
      if (typeof c === 'string' || typeof c === 'number') {
        n.appendChild(document.createTextNode(String(c)));
      } else { n.appendChild(c); }
    };
    children.forEach(append);
    return n;
  }

  function toast(msg, kind = 'info', ms = 3200) {
    let c = document.getElementById('toastContainer');
    if (!c) {
      c = el('div', { id: 'toastContainer', class: 'toast-container' });
      document.body.appendChild(c);
    }
    const n = el('div', { class: 'toast toast-' + kind }, msg);
    c.appendChild(n);
    setTimeout(() => {
      n.style.opacity = '0';
      setTimeout(() => n.remove(), 300);
    }, ms);
  }

  async function jget(url) {
    const r = await fetch(url, { credentials: 'same-origin' });
    const txt = await r.text();
    let data; try { data = JSON.parse(txt); } catch (_) { data = { raw: txt }; }
    if (!r.ok) throw new Error((data && data.error) || ('HTTP ' + r.status));
    return data;
  }

  async function jpost(url, body) {
    const r = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    const txt = await r.text();
    let data; try { data = JSON.parse(txt); } catch (_) { data = { raw: txt }; }
    if (!r.ok) throw new Error((data && data.error) || ('HTTP ' + r.status));
    return data;
  }

  function download(filename, text, mime) {
    const blob = new Blob([text], { type: mime || 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = el('a', { href: url, download: filename });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  function pretty(obj) {
    try { return JSON.stringify(obj, null, 2); }
    catch (_) { return String(obj); }
  }

  function parseQS(url) {
    try {
      const u = new URL(url, location.origin);
      const out = {};
      u.searchParams.forEach((v, k) => { out[k] = v; });
      return out;
    } catch (_) { return {}; }
  }

  /* ══════════════════════════════════════════════════════════════════
   *  SHARK THEME — CSS + SVG
   * ══════════════════════════════════════════════════════════════════ */
  const CSS = `
  /* ─── Global styles for the Exploit Suite (shark theme) ─── */
  .ex-root {
    --ex-shark-deep:    #020617;
    --ex-shark-abyss:   #0a1122;
    --ex-shark-mid:     #0f172a;
    --ex-shark-glow:    rgba(239,68,68,.42);
    --ex-shark-glow-2:  rgba(220,38,38,.18);
    --ex-shark-teeth:   #f1f5f9;
    --ex-shark-fin:     #dc2626;
    --ex-shark-fin-2:   #b91c1c;
    --ex-shark-blood:   #7f1d1d;
    --ex-shark-water:   #1e3a8a;
    --ex-shark-wave:    #3b82f6;
    --ex-shark-white:   #f8fafc;
    --ex-shark-muted:   #94a3b8;
    --ex-shark-border:  rgba(220,38,38,.22);
    --ex-shark-border2: rgba(148,163,184,.14);
    --ex-shark-card-bg: linear-gradient(165deg, #0b1220 0%, #050a16 100%);
    --ex-shark-card-hover: linear-gradient(165deg, #0f1a2e 0%, #0a1325 100%);
    display: flex; flex-direction: column; gap: 16px;
    font-family: var(--font-ui, 'Inter','Space Grotesk',system-ui,sans-serif);
    position: relative;
    isolation: isolate;
  }

  /* Subtle shark-tooth watermark behind the whole panel */
  .ex-root::before {
    content: "";
    position: absolute; inset: 0;
    background-image:
      radial-gradient(circle at 15% 20%, rgba(220,38,38,.07), transparent 45%),
      radial-gradient(circle at 85% 80%, rgba(30,58,138,.08), transparent 45%);
    pointer-events: none; z-index: -1;
  }

  /* ═══ Shark header — big fin + title ═══ */
  .ex-shark-header {
    position: relative;
    background: linear-gradient(135deg, #0a1122 0%, #140a1c 60%, #1f0505 100%);
    border: 1px solid var(--ex-shark-border);
    border-radius: 14px;
    padding: 18px 22px 16px;
    display: flex; align-items: center; gap: 18px;
    overflow: hidden;
    box-shadow:
      inset 0 0 0 1px rgba(255,255,255,.02),
      0 6px 24px rgba(220,38,38,.06);
  }
  .ex-shark-header::before {
    /* Wave pattern */
    content: "";
    position: absolute; bottom: 0; left: 0; right: 0; height: 42%;
    background-image:
      repeating-linear-gradient(135deg, rgba(220,38,38,.06) 0 4px, transparent 4px 12px);
    mask-image: linear-gradient(to top, black 40%, transparent);
    -webkit-mask-image: linear-gradient(to top, black 40%, transparent);
    pointer-events: none;
  }
  .ex-shark-header::after {
    /* Red blood trail streak */
    content: "";
    position: absolute; top: 0; right: 18%; width: 180px; height: 100%;
    background: radial-gradient(ellipse at 50% 0%, rgba(220,38,38,.18), transparent 70%);
    pointer-events: none;
  }

  .ex-shark-fin {
    width: 78px; height: 78px; flex-shrink: 0;
    filter: drop-shadow(0 0 12px rgba(220,38,38,.55));
    animation: exFinSwim 6s ease-in-out infinite;
  }
  @keyframes exFinSwim {
    0%, 100% { transform: translateX(0) rotate(-3deg); }
    50%      { transform: translateX(4px) rotate(2deg); }
  }

  .ex-shark-title-block {
    flex: 1; min-width: 0; position: relative; z-index: 1;
  }
  .ex-shark-title {
    font-size: 1.28rem; font-weight: 800; letter-spacing: -.02em;
    color: var(--ex-shark-white);
    display: flex; align-items: center; gap: 10px;
    margin: 0 0 3px;
  }
  .ex-shark-title .ex-predator-badge {
    font-size: .6rem; font-weight: 800;
    letter-spacing: .14em; text-transform: uppercase;
    padding: 3px 8px; border-radius: 99px;
    background: linear-gradient(135deg, #dc2626, #7f1d1d);
    color: #fff;
    box-shadow: 0 3px 10px rgba(220,38,38,.35);
    animation: exPredatorPulse 2.4s ease-in-out infinite;
  }
  @keyframes exPredatorPulse {
    0%, 100% { box-shadow: 0 3px 10px rgba(220,38,38,.35); }
    50%      { box-shadow: 0 3px 18px rgba(220,38,38,.75); }
  }
  .ex-shark-subtitle {
    color: var(--ex-shark-muted);
    font-size: .78rem; line-height: 1.5; margin: 0;
    max-width: 78ch;
  }
  .ex-shark-subtitle b {
    color: var(--ex-shark-white);
    font-family: var(--font-mono, monospace);
    font-weight: 600;
  }

  /* ═══ Tab strip — grouped, coloured ═══ */
  .ex-tabs {
    display: flex; flex-wrap: wrap; gap: 8px;
    padding: 10px;
    background:
      linear-gradient(180deg, rgba(220,38,38,.06), transparent 30%),
      linear-gradient(180deg, #0a1122, #06090f);
    border: 1px solid var(--ex-shark-border2);
    border-radius: 12px;
    position: relative; overflow: hidden;
  }
  .ex-tabs::before {
    content: ""; position: absolute; left: 0; right: 0; top: 0; height: 2px;
    background: linear-gradient(90deg, transparent, var(--ex-shark-fin), transparent);
    opacity: .7;
  }
  .ex-tab {
    padding: 9px 15px; border-radius: 8px;
    border: 1px solid transparent;
    background: linear-gradient(180deg, rgba(255,255,255,.015), transparent);
    color: var(--ex-shark-muted);
    font-size: .78rem; font-weight: 700;
    letter-spacing: .02em;
    cursor: pointer;
    display: inline-flex; align-items: center; gap: 8px;
    transition: all .18s cubic-bezier(.4,0,.2,1);
    -webkit-appearance: none; appearance: none;
    white-space: nowrap; font-family: inherit;
    position: relative;
  }
  .ex-tab:hover {
    color: var(--ex-shark-white);
    border-color: var(--ex-shark-border);
    background: linear-gradient(180deg, rgba(220,38,38,.08), rgba(220,38,38,.02));
    transform: translateY(-1px);
  }
  .ex-tab.active {
    background: linear-gradient(135deg, var(--ex-shark-fin), var(--ex-shark-blood));
    color: #fff;
    border-color: rgba(255,255,255,.15);
    box-shadow:
      0 4px 14px rgba(220,38,38,.42),
      inset 0 1px 0 rgba(255,255,255,.15);
  }
  .ex-tab.active::after {
    /* Shark-tooth edge under the active tab */
    content: "";
    position: absolute; left: 20%; right: 20%; bottom: -6px; height: 6px;
    background-image:
      linear-gradient(135deg, transparent 50%, var(--ex-shark-fin) 50%),
      linear-gradient(45deg, var(--ex-shark-fin) 50%, transparent 50%);
    background-size: 8px 8px;
    background-repeat: repeat-x;
    opacity: .9;
  }
  .ex-tab i { font-size: .76rem; }
  .ex-tab .ex-tab-count {
    background: rgba(255,255,255,.10);
    color: inherit;
    font-size: .6rem; font-weight: 800;
    padding: 2px 6px; border-radius: 99px;
    margin-left: 2px;
  }
  .ex-tab.active .ex-tab-count {
    background: rgba(0,0,0,.25);
  }

  /* ═══ Panels ═══ */
  .ex-panel { display: none; }
  .ex-panel.active {
    display: flex; flex-direction: column; gap: 14px;
    animation: exSlideIn .3s cubic-bezier(.4,0,.2,1);
  }
  @keyframes exSlideIn {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  /* ═══ Cards ═══ */
  .ex-card {
    background: var(--ex-shark-card-bg);
    border: 1px solid var(--ex-shark-border2);
    border-radius: 12px;
    padding: 18px 20px;
    position: relative;
    overflow: hidden;
    transition: border-color .18s, box-shadow .18s, transform .18s;
  }
  .ex-card::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, var(--ex-shark-fin) 0%, transparent 60%);
    opacity: .55;
  }
  .ex-card:hover {
    border-color: var(--ex-shark-border);
    box-shadow: 0 6px 22px rgba(0,0,0,.35);
    transform: translateY(-1px);
  }
  .ex-card h4 {
    margin: 0 0 14px;
    font-size: .78rem; font-weight: 800;
    letter-spacing: .09em; text-transform: uppercase;
    color: var(--ex-shark-white);
    display: flex; align-items: center; gap: 10px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--ex-shark-border2);
    flex-wrap: wrap;
  }
  .ex-card h4 i {
    width: 28px; height: 28px;
    display: flex; align-items: center; justify-content: center;
    font-size: .82rem;
    border-radius: 8px;
    background: linear-gradient(135deg, var(--ex-shark-fin), var(--ex-shark-blood));
    color: #fff;
    box-shadow: 0 3px 10px rgba(220,38,38,.35);
    flex-shrink: 0;
  }
  .ex-card h4 .ex-card-hint {
    margin-left: auto;
    font-size: .66rem;
    font-weight: 600;
    letter-spacing: 0;
    text-transform: none;
    color: var(--ex-shark-muted);
    font-family: var(--font-mono, monospace);
  }

  /* ═══ Form fields ═══ */
  .ex-row { display: flex; gap: 10px; flex-wrap: wrap; }
  .ex-row > * { flex: 1 1 150px; min-width: 0; }
  .ex-row.tight > * { flex: 0 0 auto; }

  .ex-field { display: flex; flex-direction: column; gap: 6px; }
  .ex-field > label {
    font-size: .64rem; font-weight: 700;
    letter-spacing: .06em; text-transform: uppercase;
    color: var(--ex-shark-muted);
  }
  .ex-field > input,
  .ex-field > select,
  .ex-field > textarea {
    background: linear-gradient(180deg, #060a15, #0a1122);
    border: 1px solid var(--ex-shark-border2);
    border-radius: 8px;
    padding: 10px 12px;
    color: var(--ex-shark-white);
    font-size: .85rem;
    font-family: var(--font-mono, ui-monospace, monospace);
    outline: none;
    transition: border-color .18s, box-shadow .18s;
    -webkit-appearance: none; appearance: none;
    width: 100%;
  }
  .ex-field > input:focus,
  .ex-field > select:focus,
  .ex-field > textarea:focus {
    border-color: var(--ex-shark-fin);
    box-shadow: 0 0 0 3px rgba(220,38,38,.18);
  }
  .ex-field > input::placeholder,
  .ex-field > textarea::placeholder { color: rgba(148,163,184,.5); }
  .ex-field > textarea { min-height: 70px; resize: vertical; }

  /* ═══ Buttons ═══ */
  .ex-actions { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
  .ex-btn {
    padding: 11px 18px;
    border-radius: 9px;
    border: 1px solid transparent;
    font-weight: 700; font-size: .82rem;
    cursor: pointer;
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    transition: all .16s cubic-bezier(.4,0,.2,1);
    -webkit-appearance: none; appearance: none;
    white-space: nowrap; font-family: inherit;
    position: relative;
  }
  .ex-btn:active { transform: scale(.98); }
  .ex-btn[disabled] { opacity: .5; cursor: not-allowed; transform: none !important; }

  .ex-btn-primary {
    background: linear-gradient(135deg, var(--ex-shark-fin), var(--ex-shark-blood));
    color: #fff;
    box-shadow: 0 4px 14px rgba(220,38,38,.4);
  }
  .ex-btn-primary:hover:not([disabled]) {
    transform: translateY(-2px);
    box-shadow: 0 8px 26px rgba(220,38,38,.55);
  }
  .ex-btn-primary::after {
    /* Teeth strip animation on hover */
    content: "";
    position: absolute; left: 10%; right: 10%; bottom: 4px; height: 3px;
    background-image:
      linear-gradient(135deg, transparent 50%, rgba(255,255,255,.55) 50%),
      linear-gradient(45deg, rgba(255,255,255,.55) 50%, transparent 50%);
    background-size: 6px 6px;
    background-repeat: repeat-x;
    opacity: 0; transition: opacity .18s;
  }
  .ex-btn-primary:hover::after { opacity: 1; }

  .ex-btn-danger {
    background: linear-gradient(135deg, #7f1d1d, #450a0a);
    color: #fca5a5;
    border-color: rgba(239,68,68,.35);
    box-shadow: 0 4px 14px rgba(239,68,68,.22);
  }
  .ex-btn-danger:hover:not([disabled]) {
    transform: translateY(-2px);
    background: linear-gradient(135deg, #991b1b, #7f1d1d);
    color: #fff;
  }

  .ex-btn-ghost {
    background: linear-gradient(180deg, #0a1122, #06090f);
    border-color: var(--ex-shark-border2);
    color: var(--ex-shark-muted);
  }
  .ex-btn-ghost:hover:not([disabled]) {
    border-color: var(--ex-shark-fin);
    color: var(--ex-shark-white);
    background: linear-gradient(180deg, rgba(220,38,38,.08), rgba(220,38,38,.02));
  }

  /* ═══ Progress bar with shark-teeth strip ═══ */
  .ex-progress {
    margin-top: 12px;
    height: 12px; width: 100%;
    background: linear-gradient(180deg, #050912, #0a1122);
    border-radius: 99px;
    overflow: hidden;
    border: 1px solid var(--ex-shark-border2);
    position: relative;
    box-shadow: inset 0 1px 3px rgba(0,0,0,.6);
  }
  .ex-progress > span {
    display: block; height: 100%; width: 0%;
    background: linear-gradient(90deg, #dc2626, #ef4444, #f87171);
    transition: width .3s cubic-bezier(.16,1,.3,1);
    border-radius: 99px;
    position: relative; overflow: hidden;
  }
  .ex-progress > span::before {
    content: "";
    position: absolute; inset: 0;
    background-image:
      linear-gradient(135deg, transparent 50%, rgba(255,255,255,.35) 50%),
      linear-gradient(45deg, rgba(255,255,255,.35) 50%, transparent 50%);
    background-size: 8px 8px;
    background-repeat: repeat-x;
    animation: exTeethScroll 1.4s linear infinite;
    opacity: .55;
  }
  @keyframes exTeethScroll {
    from { background-position: 0 0; }
    to   { background-position: 8px 0; }
  }
  .ex-progress-label {
    display: flex; justify-content: space-between;
    font-size: .7rem; color: var(--ex-shark-muted);
    margin-top: 8px;
    font-family: var(--font-mono, monospace);
    gap: 12px;
  }
  .ex-progress-label span:first-child {
    flex: 1; min-width: 0;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }

  /* ═══ Log panel ═══ */
  .ex-log {
    max-height: 300px; overflow-y: auto;
    background: linear-gradient(180deg, #030509, #050a14);
    border: 1px solid var(--ex-shark-border2);
    border-radius: 10px;
    padding: 12px 14px;
    font-family: var(--font-mono, monospace);
    font-size: .72rem;
    color: #cbd5e1;
    white-space: pre-wrap;
    line-height: 1.7;
    margin-top: 12px;
    scrollbar-width: thin;
    scrollbar-color: rgba(220,38,38,.4) transparent;
    position: relative;
  }
  .ex-log::before {
    content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
    background: linear-gradient(180deg, var(--ex-shark-fin), transparent);
  }
  .ex-log::-webkit-scrollbar { width: 8px; }
  .ex-log::-webkit-scrollbar-thumb {
    background: rgba(220,38,38,.35); border-radius: 4px;
  }
  .ex-log .ok   { color: #4ade80; }
  .ex-log .warn { color: #fbbf24; }
  .ex-log .err  { color: #f87171; }
  .ex-log .dim  { color: #64748b; }

  /* ═══ Result viewer ═══ */
  .ex-result {
    background: linear-gradient(180deg, #030509, #050a14);
    border: 1px solid var(--ex-shark-border2);
    border-radius: 10px;
    padding: 14px;
    font-family: var(--font-mono, monospace);
    font-size: .74rem;
    color: #e2e8f0;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 480px; overflow-y: auto;
    line-height: 1.65;
    scrollbar-width: thin;
  }
  .ex-result .dim { color: #64748b; }

  /* ═══ Severity badges ═══ */
  .ex-badge {
    display: inline-flex; align-items: center;
    padding: 3px 9px;
    border-radius: 99px;
    font-size: .62rem; font-weight: 800;
    text-transform: uppercase; letter-spacing: .06em;
    border: 1px solid;
  }
  .ex-badge-critical { background: rgba(220,38,38,.2);  color: #f87171; border-color: rgba(220,38,38,.5); }
  .ex-badge-high     { background: rgba(249,115,22,.18); color: #fb923c; border-color: rgba(249,115,22,.4); }
  .ex-badge-medium   { background: rgba(245,158,11,.18); color: #fbbf24; border-color: rgba(245,158,11,.4); }
  .ex-badge-low      { background: rgba(59,130,246,.18); color: #60a5fa; border-color: rgba(59,130,246,.4); }
  .ex-badge-info     { background: rgba(148,163,184,.14); color: #94a3b8; border-color: rgba(148,163,184,.3); }
  .ex-badge-safe     { background: rgba(34,197,94,.16);  color: #4ade80; border-color: rgba(34,197,94,.4); }

  /* ═══ Chips ═══ */
  .ex-chips {
    display: flex; flex-wrap: wrap; gap: 6px;
    max-height: 120px; overflow-y: auto;
    padding: 4px 2px;
  }
  .ex-chip {
    padding: 5px 11px;
    border-radius: 7px;
    border: 1px solid var(--ex-shark-border2);
    background: linear-gradient(180deg, #0a1122, #06090f);
    color: var(--ex-shark-muted);
    font-family: var(--font-mono, monospace);
    font-size: .7rem; font-weight: 600;
    cursor: pointer;
    transition: all .16s;
    -webkit-appearance: none; appearance: none;
  }
  .ex-chip:hover {
    border-color: var(--ex-shark-fin);
    color: var(--ex-shark-white);
    transform: translateY(-1px);
  }
  .ex-chip.active {
    background: linear-gradient(135deg, var(--ex-shark-fin), var(--ex-shark-blood));
    border-color: transparent;
    color: #fff;
    box-shadow: 0 3px 10px rgba(220,38,38,.4);
  }

  /* ═══ Findings list ═══ */
  .ex-findings { display: flex; flex-direction: column; gap: 8px; }
  .ex-finding {
    background: linear-gradient(180deg, rgba(10,17,34,.9), rgba(5,10,22,.9));
    border-left: 3px solid #dc2626;
    border-radius: 8px;
    padding: 12px 15px;
    font-size: .78rem;
    transition: all .18s;
    animation: exFindingIn .32s cubic-bezier(.4,0,.2,1);
  }
  @keyframes exFindingIn {
    from { opacity: 0; transform: translateX(-6px); }
    to   { opacity: 1; transform: translateX(0); }
  }
  .ex-finding:hover {
    background: linear-gradient(180deg, rgba(15,26,46,.9), rgba(10,19,37,.9));
    transform: translateX(3px);
    box-shadow: 0 4px 12px rgba(0,0,0,.4);
  }
  .ex-finding.critical { border-left-color: #dc2626; }
  .ex-finding.high     { border-left-color: #f97316; }
  .ex-finding.medium   { border-left-color: #f59e0b; }
  .ex-finding.low      { border-left-color: #3b82f6; }
  .ex-finding.safe     { border-left-color: #22c55e; }
  .ex-finding .label {
    font-size: .62rem; text-transform: uppercase;
    letter-spacing: .07em;
    color: var(--ex-shark-muted);
    font-weight: 700;
    display: flex; align-items: center; gap: 8px;
  }
  .ex-finding .value {
    font-family: var(--font-mono, monospace);
    word-break: break-all;
    margin-top: 5px;
    color: var(--ex-shark-white);
    font-size: .76rem;
    line-height: 1.55;
  }
  .ex-finding .meta {
    margin-top: 8px;
    font-size: .66rem;
    color: var(--ex-shark-muted);
    display: flex; gap: 12px; flex-wrap: wrap; align-items: center;
  }

  /* ═══ KPI tiles ═══ */
  .ex-kpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 10px;
    margin-bottom: 12px;
  }
  .ex-kpi {
    background: linear-gradient(165deg, #0b1220 0%, #050a16 100%);
    border: 1px solid var(--ex-shark-border2);
    border-radius: 10px;
    padding: 14px 15px;
    display: flex; flex-direction: column; gap: 5px;
    transition: all .18s;
    position: relative; overflow: hidden;
  }
  .ex-kpi::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, var(--ex-shark-fin), transparent);
    opacity: .5;
  }
  .ex-kpi:hover {
    border-color: var(--ex-shark-border);
    transform: translateY(-2px);
    box-shadow: 0 6px 18px rgba(0,0,0,.4);
  }
  .ex-kpi .k-label {
    font-size: .62rem; letter-spacing: .07em;
    text-transform: uppercase;
    color: var(--ex-shark-muted);
    font-weight: 700;
  }
  .ex-kpi .k-val {
    font-family: var(--font-display, monospace);
    font-size: 1.35rem;
    color: var(--ex-shark-white);
    font-weight: 800;
    line-height: 1.1;
  }

  /* ═══ Tables ═══ */
  .ex-table { width: 100%; border-collapse: collapse; font-size: .76rem; }
  .ex-table th, .ex-table td {
    text-align: left; padding: 9px 11px;
    border-bottom: 1px solid var(--ex-shark-border2);
  }
  .ex-table th {
    font-size: .62rem; letter-spacing: .07em; text-transform: uppercase;
    color: var(--ex-shark-muted); font-weight: 800;
    background: linear-gradient(180deg, rgba(220,38,38,.06), transparent);
    position: sticky; top: 0; z-index: 1;
  }
  .ex-table code {
    font-family: var(--font-mono, monospace);
    font-size: .72rem;
    color: #cbd5e1;
    word-break: break-all;
  }
  .ex-table tbody tr {
    cursor: pointer;
    transition: background .14s;
  }
  .ex-table tbody tr:hover {
    background: linear-gradient(90deg, rgba(220,38,38,.08), transparent);
  }

  /* ═══ Empty state ═══ */
  .ex-empty {
    padding: 26px 16px;
    text-align: center;
    color: var(--ex-shark-muted);
    font-size: .82rem;
    font-style: italic;
    display: flex; flex-direction: column; gap: 8px; align-items: center;
  }
  .ex-empty::before {
    content: "";
    width: 42px; height: 42px;
    background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><path d='M6 40 Q20 30 34 34 L52 22 L48 36 L58 44 L42 42 Q28 50 6 40 Z' fill='%23dc2626' fill-opacity='0.4'/></svg>");
    background-size: contain; background-repeat: no-repeat;
    background-position: center;
    opacity: .55;
  }

  /* ═══ Live pill ═══ */
  .ex-live-pill {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 11px; border-radius: 99px;
    background: linear-gradient(135deg, rgba(220,38,38,.18), rgba(220,38,38,.06));
    color: #f87171;
    font-size: .62rem; font-weight: 800;
    letter-spacing: .06em; text-transform: uppercase;
    border: 1px solid rgba(220,38,38,.4);
  }
  .ex-live-pill .dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: #ef4444;
    box-shadow: 0 0 0 0 rgba(239,68,68,.8);
    animation: exLivePulse 1.5s ease-out infinite;
  }
  @keyframes exLivePulse {
    0%   { box-shadow: 0 0 0 0 rgba(239,68,68,.8); }
    70%  { box-shadow: 0 0 0 8px rgba(239,68,68,0); }
    100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
  }

  /* ═══ Radar sweep animation for running scans ═══ */
  .ex-radar {
    width: 22px; height: 22px; border-radius: 50%;
    border: 1.5px solid rgba(220,38,38,.35);
    background:
      radial-gradient(circle, rgba(220,38,38,.15) 0%, transparent 70%);
    position: relative;
    overflow: hidden;
    flex-shrink: 0;
  }
  .ex-radar::after {
    content: "";
    position: absolute; inset: 0;
    background: conic-gradient(from 0deg, transparent 0deg,
      rgba(220,38,38,.85) 25deg, transparent 60deg);
    animation: exRadarSpin 1.6s linear infinite;
    box-shadow: 0 0 8px rgba(220,38,38,.5);
  }
  @keyframes exRadarSpin {
    to { transform: rotate(360deg); }
  }

  /* ═════════════════════════════════════════════════════════════════
     FORCE MHDDoS + EXPLOIT SIDEBAR BUTTONS TO RED
     ═════════════════════════════════════════════════════════════════ */
  .nav-item[data-section="mhddos"],
  .nav-item[data-section="exploit"] {
    background:
      linear-gradient(90deg, rgba(220,38,38,.14), rgba(220,38,38,.03) 65%, transparent) !important;
    border-left-color: #dc2626 !important;
    color: #fecaca !important;
    font-weight: 600 !important;
    position: relative;
  }
  .nav-item[data-section="mhddos"] i,
  .nav-item[data-section="exploit"] i {
    color: #ef4444 !important;
  }
  .nav-item[data-section="mhddos"]:hover,
  .nav-item[data-section="exploit"]:hover {
    background:
      linear-gradient(90deg, rgba(220,38,38,.26), rgba(220,38,38,.06) 65%, transparent) !important;
    color: #fff !important;
    transform: translateX(3px) !important;
    border-left-color: #ef4444 !important;
  }
  .nav-item[data-section="mhddos"].active,
  .nav-item[data-section="exploit"].active {
    background:
      linear-gradient(90deg, rgba(220,38,38,.42), rgba(220,38,38,.1) 70%, transparent) !important;
    border-left-color: #ef4444 !important;
    color: #fff !important;
    font-weight: 700 !important;
  }
  .nav-item[data-section="mhddos"].active i,
  .nav-item[data-section="exploit"].active i {
    color: #fff !important;
    filter: drop-shadow(0 0 6px rgba(239,68,68,.8));
  }
  /* Pulsing red dot on the MHDDoS/Exploit nav items */
  .nav-item[data-section="mhddos"]::after,
  .nav-item[data-section="exploit"]::after {
    content: "";
    position: absolute;
    right: 12px;
    top: 50%;
    transform: translateY(-50%);
    width: 6px; height: 6px;
    border-radius: 50%;
    background: #ef4444;
    box-shadow: 0 0 0 0 rgba(239,68,68,.75);
    animation: exNavPulse 2.2s ease-out infinite;
    pointer-events: none;
  }
  @keyframes exNavPulse {
    0%   { box-shadow: 0 0 0 0 rgba(239,68,68,.75); }
    70%  { box-shadow: 0 0 0 6px rgba(239,68,68,0); }
    100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
  }

  /* Make sure the section titles for MHDDoS / Exploit / HTTP Logger get the red trim */
  #section-mhddos .panel-title i,
  #section-exploit .panel-title i,
  #section-httplogger .panel-title i {
    color: #ef4444 !important;
    background: linear-gradient(135deg, rgba(220,38,38,.22), rgba(127,29,29,.12)) !important;
    box-shadow: inset 0 0 0 1px rgba(220,38,38,.3);
  }

  /* ═════════════════════════════════════════════════════════════════
     Responsive tweaks
     ═════════════════════════════════════════════════════════════════ */
  @media (max-width: 720px) {
    .ex-shark-header { flex-direction: column; align-items: flex-start; padding: 16px; }
    .ex-shark-fin { width: 60px; height: 60px; }
    .ex-shark-title { font-size: 1.08rem; }
    .ex-row > * { flex: 1 1 100%; }
    .ex-tabs { overflow-x: auto; flex-wrap: nowrap; }
    .ex-tab { flex-shrink: 0; }
  }
  `;

  function injectCSS() {
    if (document.getElementById('ex-css')) return;
    const s = document.createElement('style');
    s.id = 'ex-css';
    s.textContent = CSS;
    document.head.appendChild(s);
  }

  /* ── Shark SVG (fin + body) ─────────────────────────────────────────── */
  function sharkFinSVG() {
    return el('svg', {
      class: 'ex-shark-fin',
      viewBox: '0 0 120 120',
      xmlns: 'http://www.w3.org/2000/svg',
      'aria-hidden': 'true',
    }, el('svg', {
      html: `
        <defs>
          <linearGradient id="exFinGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0"   stop-color="#ef4444"/>
            <stop offset="0.55" stop-color="#b91c1c"/>
            <stop offset="1"   stop-color="#450a0a"/>
          </linearGradient>
          <linearGradient id="exBodyGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#1e293b"/>
            <stop offset="1" stop-color="#020617"/>
          </linearGradient>
        </defs>
        <!-- Body -->
        <path d="M4 78 Q28 66 52 72 L96 46 L88 72 L118 92 L84 90 Q46 100 4 78 Z"
              fill="url(#exBodyGrad)" stroke="#dc2626" stroke-width="1.4" stroke-opacity="0.6"/>
        <!-- Fin -->
        <path d="M56 40 L74 6 L82 40 Q70 34 56 40 Z"
              fill="url(#exFinGrad)"/>
        <!-- Tail fin -->
        <path d="M8 74 L2 92 L20 84 L8 74 Z"
              fill="url(#exFinGrad)" opacity="0.9"/>
        <!-- Eye -->
        <circle cx="30" cy="78" r="2.4" fill="#f8fafc"/>
        <circle cx="30" cy="78" r="1" fill="#020617"/>
        <!-- Gill slashes -->
        <path d="M42 74 L42 84 M47 73 L47 83 M52 72 L52 82"
              stroke="#dc2626" stroke-width="1.4" stroke-linecap="round" opacity="0.7"/>
      `,
    }));
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Shared UI builders
   * ══════════════════════════════════════════════════════════════════ */
  function buildHeader() {
    return el('div', { class: 'ex-shark-header' },
      sharkFinSVG(),
      el('div', { class: 'ex-shark-title-block' },
        el('h3', { class: 'ex-shark-title' },
          el('span', null, 'Exploit Suite'),
          el('span', { class: 'ex-predator-badge' }, 'Predator Mode'),
        ),
        el('p', { class: 'ex-shark-subtitle' },
          'Dirfuzz · SQLi · SQLMap · XSS · Sniper · HTTP Logger — ',
          el('b', null, 'authorised targets only'),
          '. All modules stream live results; every request is rate-limited and cancellable.',
        ),
      ),
    );
  }

  function buildCard(title, icon, hint, ...children) {
    return el('div', { class: 'ex-card' },
      el('h4', null,
        el('i', { class: 'fas ' + icon }),
        title,
        hint ? el('span', { class: 'ex-card-hint' }, hint) : null,
      ),
      ...children,
    );
  }

  function buildField(label, input) {
    return el('div', { class: 'ex-field' }, el('label', null, label), input);
  }

  function buildProgress() {
    const bar     = el('span', { style: 'width:0%;' });
    const wrapper = el('div', { class: 'ex-progress' }, bar);
    const labelL  = el('span', null, 'Idle');
    const labelR  = el('span', null, '0%');
    const row     = el('div', { class: 'ex-progress-label' }, labelL, labelR);
    const root    = el('div', null, wrapper, row);
    root._set = (pct, msg) => {
      bar.style.width = Math.max(0, Math.min(100, pct)) + '%';
      labelR.textContent = Math.round(pct) + '%';
      if (msg) labelL.textContent = msg;
    };
    root._reset = () => { bar.style.width = '0%'; labelR.textContent = '0%'; labelL.textContent = 'Idle'; };
    return root;
  }

  function buildLogPanel() {
    const root = el('div', { class: 'ex-log' });
    root._append = (line, cls) => {
      const node = el('div', { class: cls || '' }, line);
      root.appendChild(node);
      root.scrollTop = root.scrollHeight;
      if (root.childNodes.length > 800) root.removeChild(root.firstChild);
    };
    root._clear = () => { root.innerHTML = ''; };
    return root;
  }

  function buildResultPanel() {
    const root = el('div', { class: 'ex-result', html: '<span class="dim">No results yet.</span>' });
    root._set = (data) => {
      root.textContent = (typeof data === 'string') ? data : pretty(data);
      root.scrollTop = 0;
    };
    root._clear = () => { root.innerHTML = '<span class="dim">No results yet.</span>'; };
    return root;
  }

  function severityBadge(sev) {
    const s = String(sev || 'info').toLowerCase();
    return el('span', { class: 'ex-badge ex-badge-' + s }, s);
  }

  /* ── Tabs definition ───────────────────────────────────────────────── */
  const TABS = [
    { id: 'dirfuzz',   label: 'Dirfuzz',       icon: 'fa-folder-tree' },
    { id: 'sqli',      label: 'SQLi Engine',   icon: 'fa-database' },
    { id: 'sqlmap',    label: 'SQLMap',        icon: 'fa-magnifying-glass-chart' },
    { id: 'sqlinj',    label: 'SQL (light)',   icon: 'fa-bolt' },
    { id: 'xss',       label: 'XSS Exploiter', icon: 'fa-code' },
    { id: 'xssSimple', label: 'XSS (simple)',  icon: 'fa-wand-magic' },
    { id: 'sniper',    label: 'Sniper',        icon: 'fa-crosshairs' },
    { id: 'logger',    label: 'HTTP Logger',   icon: 'fa-wave-square' },
  ];

  /* ══════════════════════════════════════════════════════════════════
   *  Tab builders — closure over per-instance state
   * ══════════════════════════════════════════════════════════════════ */
  function makeTabBuilders(instanceName, state) {

    function pid(id) { return 'ex-tab-' + instanceName + '-' + id; }

    /* ── 1. Dirfuzz ─────────────────────────────────────────────────── */
    function buildDirfuzzTab() {
      const target    = el('input', { type: 'text', placeholder: 'https://example.com', autocomplete: 'off' });
      const wordlist  = el('select');
      const maxPaths  = el('input', { type: 'number', value: '200' });
      const conc      = el('input', { type: 'number', value: '24' });
      const rate      = el('input', { type: 'number', value: '40', step: '0.1' });
      const timeout   = el('input', { type: 'number', value: '4', step: '0.5' });
      const follow    = el('input', { type: 'checkbox' });
      const streamTgl = el('input', { type: 'checkbox', checked: true });

      const startBtn = el('button', { class: 'ex-btn ex-btn-primary' },
        el('i', { class: 'fas fa-play' }), 'Start Scan');
      const stopBtn  = el('button', { class: 'ex-btn ex-btn-ghost', disabled: true },
        el('i', { class: 'fas fa-stop' }), 'Stop');

      const progress    = buildProgress();
      const logPanel    = buildLogPanel();
      const findingsBox = el('div', { class: 'ex-findings' });

      (async () => {
        try {
          const res = await jget(EP.dirfuzz.wordlists);
          (res.wordlists || []).forEach(w => {
            wordlist.appendChild(el('option', { value: w.name }, `${w.name} (${w.count})`));
          });
          if (!wordlist.options.length) {
            wordlist.appendChild(el('option', { value: 'lottery-dirs.txt' }, 'lottery-dirs.txt'));
          }
        } catch (_) {
          wordlist.appendChild(el('option', { value: 'lottery-dirs.txt' }, 'lottery-dirs.txt'));
        }
      })();

      function renderHits(hits) {
        findingsBox.innerHTML = '';
        if (!hits || !hits.length) {
          findingsBox.appendChild(el('div', { class: 'ex-empty' }, 'No hits'));
          return;
        }
        hits.slice(0, 200).forEach(h => {
          findingsBox.appendChild(el('div', { class: 'ex-finding ' + (h.severity || 'info') },
            el('div', { class: 'label' },
              el('i', { class: 'fas fa-folder-open' }),
              ` ${h.category || 'other'} · path`,
            ),
            el('div', { class: 'value' }, h.url || h.path || ''),
            el('div', { class: 'meta' },
              el('span', null, 'Status: ', String(h.status)),
              el('span', null, 'Size: ',   String(h.size || 0)),
              el('span', null, 'Severity: ', severityBadge(h.severity)),
              h.redirect_to ? el('span', null, '→ ', h.redirect_to) : null,
            ),
            (h.secrets && h.secrets.length)
              ? el('div', { class: 'value', style: 'margin-top:8px;color:#f87171;' },
                  '⚠ Secrets: ' + h.secrets.map(s => s.type).join(', '))
              : null,
          ));
        });
      }

      function closeStream() {
        const es = state.streams.dirfuzz;
        if (es) { try { es.close(); } catch (_) {} delete state.streams.dirfuzz; }
      }

      async function startBlocking() {
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._reset(); progress._set(0, 'Running…');
        logPanel._clear();
        logPanel._append('[blocking] starting dirfuzz…', 'dim');
        try {
          const body = {
            target:           target.value.trim(),
            wordlist_name:    wordlist.value,
            max_paths:        parseInt(maxPaths.value, 10) || 200,
            concurrency:      parseInt(conc.value, 10)     || 24,
            rate_limit:       parseFloat(rate.value)       || 40,
            timeout:          parseFloat(timeout.value)    || 4,
            follow_redirects: !!follow.checked,
          };
          if (!body.target) { toast('Target required', 'warn'); return; }
          const res = await jpost(EP.dirfuzz.scan, body);
          progress._set(100, 'Complete');
          logPanel._append(`[done] tried=${res.tried} hits=${res.hits_count} elapsed=${res.elapsed}s`, 'ok');
          renderHits(res.hits || []);
        } catch (e) {
          logPanel._append('[error] ' + e.message, 'err');
          toast('Dirfuzz failed: ' + e.message, 'err');
        } finally {
          startBtn.disabled = false; stopBtn.disabled = true;
        }
      }

      function startStreaming() {
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._reset(); progress._set(0, 'Connecting…');
        logPanel._clear();
        logPanel._append('[stream] connecting…', 'dim');

        const qs = new URLSearchParams({
          target:           target.value.trim(),
          wordlist_name:    wordlist.value,
          max_paths:        maxPaths.value,
          concurrency:      conc.value,
          rate_limit:       rate.value,
          timeout:          timeout.value,
          follow_redirects: follow.checked ? '1' : '0',
        });

        closeStream();
        const es = new EventSource(EP.dirfuzz.stream + '?' + qs.toString());
        state.streams.dirfuzz = es;

        es.onmessage = (ev) => {
          try {
            const data = JSON.parse(ev.data);
            if (data.type === 'progress') {
              progress._set(data.percent || 0, `${data.label || ''} (${data.done}/${data.total})`);
            } else if (data.type === 'result') {
              progress._set(100, 'Complete');
              logPanel._append(`[done] tried=${data.data.tried} hits=${data.data.hits_count}`, 'ok');
              renderHits(data.data.hits || []);
              closeStream();
              startBtn.disabled = false; stopBtn.disabled = true;
            } else if (data.type === 'error') {
              logPanel._append('[error] ' + data.message, 'err');
              closeStream();
              startBtn.disabled = false; stopBtn.disabled = true;
            } else if (data.type === 'start') {
              logPanel._append('[start] ' + data.base, 'dim');
            }
          } catch (e) { logPanel._append('[parse] ' + e.message, 'warn'); }
        };
        es.onerror = () => {
          logPanel._append('[sse] connection error', 'warn');
          closeStream();
          startBtn.disabled = false; stopBtn.disabled = true;
        };
      }

      startBtn.addEventListener('click', () => {
        if (!target.value.trim()) { toast('Target required', 'warn'); return; }
        if (streamTgl.checked) startStreaming(); else startBlocking();
      });
      stopBtn.addEventListener('click', () => {
        closeStream();
        logPanel._append('[stopped]', 'warn');
        startBtn.disabled = false; stopBtn.disabled = true;
        progress._set(0, 'Stopped');
      });

      return el('div', { class: 'ex-panel', id: pid('dirfuzz') },
        buildCard('Directory / File Fuzzer', 'fa-folder-tree', 'brute-force · soft-404 aware',
          el('div', { class: 'ex-row' },
            buildField('Target', target),
            buildField('Wordlist', wordlist),
          ),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Max paths', maxPaths),
            buildField('Concurrency', conc),
            buildField('Rate limit (req/s)', rate),
            buildField('Timeout (s)', timeout),
          ),
          el('div', { class: 'ex-row tight', style: 'margin-top:12px; align-items:center;' },
            el('label', { style: 'display:flex;gap:7px;align-items:center;font-size:.78rem;color:#94a3b8;' },
              follow, 'Follow redirects'),
            el('label', { style: 'display:flex;gap:7px;align-items:center;font-size:.78rem;color:#94a3b8;' },
              streamTgl, 'Stream results (SSE)'),
            el('div', { style: 'flex:1 1 auto;' }),
            startBtn, stopBtn,
          ),
          progress,
          logPanel,
        ),
        buildCard('Findings', 'fa-list-check', 'click a row to inspect', findingsBox),
      );
    }

    /* ── 2. SQLi Engine ─────────────────────────────────────────────── */
    function buildSqliTab() {
      const target    = el('input', { type: 'text', placeholder: 'https://example.com/page?id=1', autocomplete: 'off' });
      const method    = el('select', null,
        el('option', { value: 'GET' }, 'GET'),
        el('option', { value: 'POST' }, 'POST'),
      );
      const maxParams = el('input', { type: 'number', value: '10' });
      const rate      = el('input', { type: 'number', value: '20', step: '0.5' });
      const timeout   = el('input', { type: 'number', value: '8',  step: '0.5' });

      const techniquesWrap = el('div', { class: 'ex-chips' });
      const activeTech = new Set(['error', 'boolean', 'time', 'union']);
      ['error', 'boolean', 'time', 'union'].forEach(t => {
        const chip = el('button', { class: 'ex-chip active', type: 'button' }, t);
        chip.addEventListener('click', () => {
          if (activeTech.has(t)) { activeTech.delete(t); chip.classList.remove('active'); }
          else                   { activeTech.add(t);    chip.classList.add('active'); }
        });
        techniquesWrap.appendChild(chip);
      });

      const startBtn    = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-play' }), 'Start');
      const stopBtn     = el('button', { class: 'ex-btn ex-btn-ghost', disabled: true }, el('i', { class: 'fas fa-stop' }), 'Stop');
      const streamTgl   = el('input', { type: 'checkbox', checked: true });

      const progress    = buildProgress();
      const logPanel    = buildLogPanel();
      const resultPanel = buildResultPanel();

      function closeStream() {
        const es = state.streams.sqli;
        if (es) { try { es.close(); } catch (_) {} delete state.streams.sqli; }
      }

      async function runBlocking() {
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._reset(); progress._set(0, 'Running…');
        logPanel._clear();
        logPanel._append('[blocking] starting SQLi engine…', 'dim');
        try {
          const body = {
            target:     target.value.trim(),
            method:     method.value,
            max_params: parseInt(maxParams.value, 10) || 10,
            rate_limit: parseFloat(rate.value)        || 20,
            timeout:    parseFloat(timeout.value)     || 8,
            techniques: Array.from(activeTech),
          };
          if (!body.target) { toast('Target required', 'warn'); return; }
          const res = await jpost(EP.sqli.scan, body);
          progress._set(100, 'Complete');
          logPanel._append(
            `[done] vulnerable=${res.vulnerable} findings=${(res.findings || []).length} elapsed=${res.elapsed}s`,
            res.vulnerable ? 'err' : 'ok'
          );
          resultPanel._set(res);
        } catch (e) {
          logPanel._append('[error] ' + e.message, 'err');
          toast('SQLi scan failed: ' + e.message, 'err');
        } finally {
          startBtn.disabled = false; stopBtn.disabled = true;
        }
      }

      function runStreaming() {
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._reset(); progress._set(0, 'Connecting…');
        logPanel._clear();
        logPanel._append('[stream] connecting…', 'dim');

        const qs = new URLSearchParams({
          target:     target.value.trim(),
          method:     method.value,
          max_params: maxParams.value,
          rate_limit: rate.value,
          timeout:    timeout.value,
          techniques: Array.from(activeTech).join(','),
        });

        closeStream();
        const es = new EventSource(EP.sqli.stream + '?' + qs.toString());
        state.streams.sqli = es;

        es.onmessage = (ev) => {
          try {
            const data = JSON.parse(ev.data);
            if (data.type === 'progress') {
              progress._set(data.percent || 0, `${data.label || ''} (${data.done}/${data.total})`);
            } else if (data.type === 'result') {
              progress._set(100, 'Complete');
              logPanel._append(
                `[done] vulnerable=${data.data.vulnerable} findings=${(data.data.findings || []).length}`,
                data.data.vulnerable ? 'err' : 'ok'
              );
              resultPanel._set(data.data);
              closeStream();
              startBtn.disabled = false; stopBtn.disabled = true;
            } else if (data.type === 'error') {
              logPanel._append('[error] ' + data.message, 'err');
              closeStream();
              startBtn.disabled = false; stopBtn.disabled = true;
            } else if (data.type === 'start') {
              logPanel._append('[start] ' + data.url, 'dim');
            }
          } catch (e) { logPanel._append('[parse] ' + e.message, 'warn'); }
        };
        es.onerror = () => {
          logPanel._append('[sse] connection error', 'warn');
          closeStream();
          startBtn.disabled = false; stopBtn.disabled = true;
        };
      }

      startBtn.addEventListener('click', () => {
        if (!target.value.trim()) { toast('Target required', 'warn'); return; }
        if (streamTgl.checked) runStreaming(); else runBlocking();
      });
      stopBtn.addEventListener('click', () => {
        closeStream();
        logPanel._append('[stopped]', 'warn');
        startBtn.disabled = false; stopBtn.disabled = true;
      });

      return el('div', { class: 'ex-panel', id: pid('sqli') },
        buildCard('SQL Injection Engine', 'fa-database', '4 techniques · wordlist driven',
          el('div', { class: 'ex-row' },
            buildField('Target URL', target),
            buildField('Method', method),
          ),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Max params', maxParams),
            buildField('Rate limit', rate),
            buildField('Timeout (s)', timeout),
          ),
          el('div', { style: 'margin-top:12px;' },
            el('label', { style: 'font-size:.64rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#94a3b8;' }, 'Techniques'),
            techniquesWrap,
          ),
          el('div', { class: 'ex-row tight', style: 'margin-top:14px; align-items:center;' },
            el('label', { style: 'display:flex;gap:7px;align-items:center;font-size:.78rem;color:#94a3b8;' },
              streamTgl, 'Stream results (SSE)'),
            el('div', { style: 'flex:1 1 auto;' }),
            startBtn, stopBtn,
          ),
          progress,
          logPanel,
        ),
        buildCard('Result', 'fa-clipboard-check', null, resultPanel),
      );
    }

    /* ── 3. SQLMap ──────────────────────────────────────────────────── */
    function buildSqlmapTab() {
      const target     = el('input', { type: 'text', placeholder: 'https://example.com/page?id=1', autocomplete: 'off' });
      const method     = el('select', null,
        el('option', { value: 'GET' }, 'GET'),
        el('option', { value: 'POST' }, 'POST'),
      );
      const mode       = el('select', null,
        el('option', { value: 'basic' }, 'Basic'),
        el('option', { value: 'expert' }, 'Expert'),
      );
      const maxThreads = el('input', { type: 'number', value: '10' });
      const timeout    = el('input', { type: 'number', value: '5', step: '0.5' });

      const runBtn      = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-play' }), 'Run SQLMap');
      const resultPanel = buildResultPanel();
      const logPanel    = buildLogPanel();

      runBtn.addEventListener('click', async () => {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        runBtn.disabled = true;
        logPanel._append('[run] sqlmap ' + mode.value + ' …', 'dim');
        try {
          const body = {
            target:      t,
            mode:        mode.value,
            method:      method.value,
            max_threads: parseInt(maxThreads.value, 10) || 10,
            timeout:     parseFloat(timeout.value)      || 5,
          };
          const res = await jpost(EP.sqlmap.scan, body);
          logPanel._append('[done] scan_type=' + ((res.data && res.data.scan_type) || 'sqli'), 'ok');
          resultPanel._set(res);
        } catch (e) {
          logPanel._append('[error] ' + e.message, 'err');
          toast('SQLMap failed: ' + e.message, 'err');
        } finally {
          runBtn.disabled = false;
        }
      });

      return el('div', { class: 'ex-panel', id: pid('sqlmap') },
        buildCard('SQLMap — Multi-Technique Scanner', 'fa-magnifying-glass-chart', 'confidence scored',
          el('div', { class: 'ex-row' }, buildField('Target URL', target)),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Method', method),
            buildField('Mode', mode),
            buildField('Max threads', maxThreads),
            buildField('Timeout (s)', timeout),
          ),
          el('div', { class: 'ex-actions', style: 'margin-top:14px;' }, runBtn),
          logPanel,
        ),
        buildCard('Result', 'fa-clipboard-check', null, resultPanel),
      );
    }

    /* ── 4. SQL Injection (lightweight) ─────────────────────────────── */
    function buildSqlinjTab() {
      const target = el('input', { type: 'text', placeholder: 'https://example.com/search?q=1', autocomplete: 'off' });
      const method = el('select', null,
        el('option', { value: 'GET' }, 'GET'),
        el('option', { value: 'POST' }, 'POST'),
      );
      const runBtn      = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-bolt' }), 'Run');
      const resultPanel = buildResultPanel();
      const logPanel    = buildLogPanel();

      runBtn.addEventListener('click', async () => {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        runBtn.disabled = true;
        logPanel._append('[run] lightweight SQLi …', 'dim');
        try {
          const body = { target: t, method: method.value, params: parseQS(t) };
          const res  = await jpost(EP.sqlinj.scan, body);
          logPanel._append(
            `[done] vulnerable=${res.vulnerable} findings=${(res.findings || []).length}`,
            res.vulnerable ? 'err' : 'ok'
          );
          resultPanel._set(res);
        } catch (e) {
          logPanel._append('[error] ' + e.message, 'err');
          toast('SQLi scan failed: ' + e.message, 'err');
        } finally {
          runBtn.disabled = false;
        }
      });

      return el('div', { class: 'ex-panel', id: pid('sqlinj') },
        buildCard('Lightweight SQL Injection Test', 'fa-bolt', 'fast heuristic',
          el('div', { class: 'ex-row' },
            buildField('Target URL', target),
            buildField('Method', method),
          ),
          el('div', { class: 'ex-actions', style: 'margin-top:14px;' }, runBtn),
          logPanel,
        ),
        buildCard('Result', 'fa-clipboard-check', null, resultPanel),
      );
    }

    /* ── 5. XSS Exploiter ───────────────────────────────────────────── */
    function buildXssTab() {
      const target      = el('input', { type: 'text', placeholder: 'https://example.com/search?q=test', autocomplete: 'off' });
      const method      = el('select', null,
        el('option', { value: 'GET' }, 'GET'),
        el('option', { value: 'POST' }, 'POST'),
      );
      const maxPayloads = el('input', { type: 'number', value: '30' });
      const maxParams   = el('input', { type: 'number', value: '10' });
      const conc        = el('input', { type: 'number', value: '8' });
      const rate        = el('input', { type: 'number', value: '20', step: '0.5' });
      const wafBypass   = el('input', { type: 'checkbox' });
      const streamTgl   = el('input', { type: 'checkbox', checked: true });

      const startBtn    = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-play' }), 'Start');
      const stopBtn     = el('button', { class: 'ex-btn ex-btn-ghost', disabled: true }, el('i', { class: 'fas fa-stop' }), 'Stop');

      const progress    = buildProgress();
      const logPanel    = buildLogPanel();
      const findingsBox = el('div', { class: 'ex-findings' });

      function closeStream() {
        const es = state.streams.xss;
        if (es) { try { es.close(); } catch (_) {} delete state.streams.xss; }
      }

      function renderFindings(findings) {
        findingsBox.innerHTML = '';
        if (!findings || !findings.length) {
          findingsBox.appendChild(el('div', { class: 'ex-empty' }, 'No XSS vectors found'));
          return;
        }
        findings.forEach(f => {
          findingsBox.appendChild(el('div', { class: 'ex-finding ' + (f.severity || 'medium') },
            el('div', { class: 'label' },
              el('i', { class: 'fas fa-code' }),
              ` ${f.parameter} · ${f.context || 'unknown'}`,
            ),
            el('div', { class: 'value' }, f.payload || ''),
            el('div', { class: 'meta' },
              el('span', null, 'Status: ',     String(f.status_code || '—')),
              el('span', null, 'Confidence: ', String(f.confidence  || '—')),
              el('span', null, 'Severity: ',   severityBadge(f.severity)),
            ),
            f.evidence
              ? el('div', { class: 'value', style: 'margin-top:8px;color:#94a3b8;font-size:.72rem;' }, f.evidence.slice(0, 200))
              : null,
          ));
        });
      }

      async function startBlocking() {
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._reset(); progress._set(0, 'Running…');
        logPanel._clear();
        logPanel._append('[blocking] XSS exploiter …', 'dim');
        try {
          const body = {
            target:       target.value.trim(),
            method:       method.value,
            max_payloads: parseInt(maxPayloads.value, 10) || 30,
            max_params:   parseInt(maxParams.value, 10)   || 10,
            concurrency:  parseInt(conc.value, 10)        || 8,
            rate_limit:   parseFloat(rate.value)          || 20,
            waf_bypass:   !!wafBypass.checked,
          };
          if (!body.target) { toast('Target required', 'warn'); return; }
          const res = await jpost(EP.xss.scan, body);
          progress._set(100, 'Complete');
          logPanel._append(
            `[done] vulnerable=${res.vulnerable} findings=${(res.findings || []).length}`,
            res.vulnerable ? 'err' : 'ok'
          );
          renderFindings(res.findings || []);
        } catch (e) {
          logPanel._append('[error] ' + e.message, 'err');
          toast('XSS scan failed: ' + e.message, 'err');
        } finally {
          startBtn.disabled = false; stopBtn.disabled = true;
        }
      }

      function startStreaming() {
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._reset(); progress._set(0, 'Connecting…');
        logPanel._clear();
        logPanel._append('[stream] connecting…', 'dim');

        const qs = new URLSearchParams({
          target:       target.value.trim(),
          method:       method.value,
          max_payloads: maxPayloads.value,
          max_params:   maxParams.value,
          concurrency:  conc.value,
          rate_limit:   rate.value,
          waf_bypass:   wafBypass.checked ? '1' : '0',
        });

        closeStream();
        const es = new EventSource(EP.xss.stream + '?' + qs.toString());
        state.streams.xss = es;

        es.onmessage = (ev) => {
          try {
            const data = JSON.parse(ev.data);
            if (data.type === 'progress') {
              progress._set(data.percent || 0, `${data.label || ''} (${data.done}/${data.total})`);
            } else if (data.type === 'result') {
              progress._set(100, 'Complete');
              logPanel._append(
                `[done] vulnerable=${data.data.vulnerable} findings=${(data.data.findings || []).length}`,
                data.data.vulnerable ? 'err' : 'ok'
              );
              renderFindings(data.data.findings || []);
              closeStream();
              startBtn.disabled = false; stopBtn.disabled = true;
            } else if (data.type === 'error') {
              logPanel._append('[error] ' + data.message, 'err');
              closeStream();
              startBtn.disabled = false; stopBtn.disabled = true;
            } else if (data.type === 'start') {
              logPanel._append('[start] ' + data.url, 'dim');
            } else if (data.type === 'heartbeat') {
              logPanel._append('[heartbeat]', 'dim');
            }
          } catch (e) { logPanel._append('[parse] ' + e.message, 'warn'); }
        };
        es.onerror = () => {
          logPanel._append('[sse] connection error', 'warn');
          closeStream();
          startBtn.disabled = false; stopBtn.disabled = true;
        };
      }

      startBtn.addEventListener('click', () => {
        if (!target.value.trim()) { toast('Target required', 'warn'); return; }
        if (streamTgl.checked) startStreaming(); else startBlocking();
      });
      stopBtn.addEventListener('click', () => {
        closeStream();
        logPanel._append('[stopped]', 'warn');
        startBtn.disabled = false; stopBtn.disabled = true;
      });

      return el('div', { class: 'ex-panel', id: pid('xss') },
        buildCard('XSS Exploiter', 'fa-code', 'reflected · context aware',
          el('div', { class: 'ex-row' },
            buildField('Target URL', target),
            buildField('Method', method),
          ),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Max payloads', maxPayloads),
            buildField('Max params', maxParams),
            buildField('Concurrency', conc),
            buildField('Rate limit', rate),
          ),
          el('div', { class: 'ex-row tight', style: 'margin-top:12px; align-items:center;' },
            el('label', { style: 'display:flex;gap:7px;align-items:center;font-size:.78rem;color:#94a3b8;' },
              wafBypass, 'WAF bypass'),
            el('label', { style: 'display:flex;gap:7px;align-items:center;font-size:.78rem;color:#94a3b8;' },
              streamTgl, 'Stream (SSE)'),
            el('div', { style: 'flex:1 1 auto;' }),
            startBtn, stopBtn,
          ),
          progress,
          logPanel,
        ),
        buildCard('Findings', 'fa-list-check', null, findingsBox),
      );
    }

    /* ── 6. XSS Simple ──────────────────────────────────────────────── */
    function buildXssSimpleTab() {
      const target = el('input', { type: 'text', placeholder: 'https://example.com/?q=test', autocomplete: 'off' });
      const mode   = el('select', null,
        el('option', { value: 'basic' }, 'Basic'),
        el('option', { value: 'expert' }, 'Expert'),
      );
      const runBtn      = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-wand-magic' }), 'Run');
      const resultPanel = buildResultPanel();

      runBtn.addEventListener('click', async () => {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        runBtn.disabled = true;
        try {
          const res = await jpost(EP.xssSimple.scan, { target: t, mode: mode.value });
          resultPanel._set(res);
        } catch (e) {
          toast('XSS scan failed: ' + e.message, 'err');
        } finally {
          runBtn.disabled = false;
        }
      });

      return el('div', { class: 'ex-panel', id: pid('xssSimple') },
        buildCard('Reflected XSS (Simple)', 'fa-wand-magic', 'quick check',
          el('div', { class: 'ex-row' },
            buildField('Target URL', target),
            buildField('Mode', mode),
          ),
          el('div', { class: 'ex-actions', style: 'margin-top:14px;' }, runBtn),
        ),
        buildCard('Result', 'fa-clipboard-check', null, resultPanel),
      );
    }

    /* ── 7. Sniper ──────────────────────────────────────────────────── */
    function buildSniperTab() {
      const target        = el('input', { type: 'text', placeholder: 'https://example.com', autocomplete: 'off' });
      const moduleTimeout = el('input', { type: 'number', value: '90' });
      const globalBudget  = el('input', { type: 'number', value: '150' });
      const dirfuzzMax    = el('input', { type: 'number', value: '80' });
      const xssMax        = el('input', { type: 'number', value: '20' });
      const takeoverMax   = el('input', { type: 'number', value: '120' });
      const streamTgl     = el('input', { type: 'checkbox', checked: true });

      const startBtn    = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-crosshairs' }), 'Run Sniper');
      const stopBtn     = el('button', { class: 'ex-btn ex-btn-ghost', disabled: true }, el('i', { class: 'fas fa-stop' }), 'Stop');

      const progress    = buildProgress();
      const logPanel    = buildLogPanel();
      const resultPanel = buildResultPanel();

      function closeStream() {
        const es = state.streams.sniper;
        if (es) { try { es.close(); } catch (_) {} delete state.streams.sniper; }
      }

      async function runBlocking() {
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._reset(); progress._set(0, 'Running…');
        logPanel._clear();
        try {
          const res = await jpost(EP.sniper.scan, {
            target:             target.value.trim(),
            module_timeout:     parseFloat(moduleTimeout.value) || 90,
            global_budget:      parseFloat(globalBudget.value)  || 150,
            dirfuzz_max_paths:  parseInt(dirfuzzMax.value, 10)  || 80,
            xss_max_payloads:   parseInt(xssMax.value, 10)      || 20,
            takeover_max_hosts: parseInt(takeoverMax.value, 10) || 120,
          });
          progress._set(100, 'Complete');
          logPanel._append(`[done] risk=${res.risk_score}/100 (${res.risk_level}) elapsed=${res.elapsed}s`, 'ok');
          resultPanel._set(res);
        } catch (e) {
          logPanel._append('[error] ' + e.message, 'err');
          toast('Sniper failed: ' + e.message, 'err');
        } finally {
          startBtn.disabled = false; stopBtn.disabled = true;
        }
      }

      function runStreaming() {
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._reset(); progress._set(0, 'Connecting…');
        logPanel._clear();

        const qs = new URLSearchParams({
          target:             target.value.trim(),
          module_timeout:     moduleTimeout.value,
          global_budget:      globalBudget.value,
          dirfuzz_max_paths:  dirfuzzMax.value,
          xss_max_payloads:   xssMax.value,
          takeover_max_hosts: takeoverMax.value,
        });

        closeStream();
        const es = new EventSource(EP.sniper.stream + '?' + qs.toString());
        state.streams.sniper = es;

        es.onmessage = (ev) => {
          try {
            const data = JSON.parse(ev.data);
            if (data.type === 'start') {
              logPanel._append(`[start] ${data.target} · ${data.modules.join(', ')}`, 'dim');
            } else if (data.type === 'module_start') {
              logPanel._append(`[▶] ${data.module}`, 'dim');
            } else if (data.type === 'progress') {
              progress._set(data.pct || 0, `${data.module}: ${data.message || ''}`);
            } else if (data.type === 'module_done') {
              logPanel._append(
                `[◀] ${data.module} — ${data.findings} finding(s) in ${data.elapsed}s`,
                data.ok ? 'ok' : 'warn'
              );
            } else if (data.type === 'heartbeat') {
              logPanel._append(`[heartbeat] elapsed=${data.elapsed}s done=${data.modules_done}/${data.modules_total}`, 'dim');
            } else if (data.type === 'complete') {
              progress._set(100, 'Complete');
              logPanel._append(`[done] risk=${data.report.risk_score}/100 (${data.report.risk_level})`, 'ok');
              resultPanel._set(data.report);
              closeStream();
              startBtn.disabled = false; stopBtn.disabled = true;
            } else if (data.type === 'error') {
              logPanel._append('[error] ' + data.message, 'err');
            }
          } catch (e) { logPanel._append('[parse] ' + e.message, 'warn'); }
        };
        es.onerror = () => {
          logPanel._append('[sse] connection error', 'warn');
          closeStream();
          startBtn.disabled = false; stopBtn.disabled = true;
        };
      }

      startBtn.addEventListener('click', () => {
        if (!target.value.trim()) { toast('Target required', 'warn'); return; }
        if (streamTgl.checked) runStreaming(); else runBlocking();
      });
      stopBtn.addEventListener('click', () => {
        closeStream();
        logPanel._append('[stopped]', 'warn');
        startBtn.disabled = false; stopBtn.disabled = true;
      });

      return el('div', { class: 'ex-panel', id: pid('sniper') },
        buildCard('Sniper — Auto-Exploiter', 'fa-crosshairs', 'all modules · correlation',
          el('div', { class: 'ex-row' }, buildField('Target', target)),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Module timeout (s)', moduleTimeout),
            buildField('Global budget (s)', globalBudget),
            buildField('Dirfuzz max paths', dirfuzzMax),
            buildField('XSS max payloads', xssMax),
            buildField('Takeover max hosts', takeoverMax),
          ),
          el('div', { class: 'ex-row tight', style: 'margin-top:12px; align-items:center;' },
            el('label', { style: 'display:flex;gap:7px;align-items:center;font-size:.78rem;color:#94a3b8;' },
              streamTgl, 'Stream (SSE)'),
            el('div', { style: 'flex:1 1 auto;' }),
            startBtn, stopBtn,
          ),
          progress,
          logPanel,
        ),
        buildCard('Full Report', 'fa-clipboard-check', null, resultPanel),
      );
    }

    /* ── 8. HTTP Logger ─────────────────────────────────────────────── */
    function buildLoggerTab() {
      const statsGrid   = el('div', { class: 'ex-kpis' });
      const filters     = el('div', { class: 'ex-row', style: 'margin-bottom:10px;' });
      const searchIn    = el('input', { type: 'text', placeholder: 'Search path/query/body…', autocomplete: 'off' });
      const methodSel   = el('select', null,
        el('option', { value: '' }, 'Any method'),
        el('option', { value: 'GET' }, 'GET'),
        el('option', { value: 'POST' }, 'POST'),
        el('option', { value: 'PUT' }, 'PUT'),
        el('option', { value: 'DELETE' }, 'DELETE'),
      );
      const anomalySel  = el('input', { type: 'text', placeholder: 'Anomaly category (sqli, xss, …)' });
      const refreshBtn  = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-rotate' }), 'Refresh');
      const clearBtn    = el('button', { class: 'ex-btn ex-btn-danger'  }, el('i', { class: 'fas fa-broom' }), 'Clear Log');
      const exportHar   = el('button', { class: 'ex-btn ex-btn-ghost'   }, el('i', { class: 'fas fa-file-export' }), 'Export HAR');
      const liveBtn     = el('button', { class: 'ex-btn ex-btn-ghost'   }, el('i', { class: 'fas fa-satellite-dish' }), 'Live Stream');
      const livePill    = el('span', { class: 'ex-live-pill', style: 'display:none;' },
        el('span', { class: 'dot' }), 'Live');

      const tableBody   = el('tbody');
      const detailPanel = buildResultPanel();
      detailPanel._clear();

      filters.append(
        el('div', { style: 'flex: 2 1 240px;' }, searchIn),
        el('div', { style: 'flex: 0 0 140px;' }, methodSel),
        el('div', { style: 'flex: 1 1 180px;' }, anomalySel),
      );

      async function loadStats() {
        try {
          const s = await jget(EP.logger.stats);
          statsGrid.innerHTML = '';
          [
            { label: 'Total Seen',  val: s.total_seen },
            { label: 'Buffer Size', val: `${s.buffer_size}/${s.buffer_capacity}` },
            { label: 'Subscribers', val: s.subscribers },
            { label: 'Dropped',     val: s.total_dropped },
          ].forEach(e => {
            statsGrid.appendChild(el('div', { class: 'ex-kpi' },
              el('div', { class: 'k-label' }, e.label),
              el('div', { class: 'k-val' }, String(e.val)),
            ));
          });
        } catch (_) { /* ignore */ }
      }

      async function loadList() {
        tableBody.innerHTML = '';
        try {
          const qs = new URLSearchParams({ size: '100' });
          if (searchIn.value.trim())   qs.set('q',       searchIn.value.trim());
          if (methodSel.value)         qs.set('method',  methodSel.value);
          if (anomalySel.value.trim()) qs.set('anomaly', anomalySel.value.trim());
          const data = await jget(EP.logger.list + '?' + qs.toString());
          if (!data.items || !data.items.length) {
            tableBody.appendChild(el('tr', null,
              el('td', { colspan: '6' },
                el('div', { class: 'ex-empty' }, 'No requests captured'))));
            return;
          }
          data.items.forEach(entry => {
            const tr = el('tr', { 'data-id': entry.id },
              el('td', null, el('code', null, entry.method || '—')),
              el('td', null, el('code', null, entry.path   || '—')),
              el('td', null, String(entry.status || 0)),
              el('td', null, el('code', null, entry.ip     || '—')),
              el('td', null, String(entry.elapsed_ms || 0) + 'ms'),
              el('td', null, (entry.anomalies || []).map(a => severityBadge(a.severity)).slice(0, 3)),
            );
            tr.addEventListener('click', () => showDetail(entry.id));
            tableBody.appendChild(tr);
          });
        } catch (e) {
          tableBody.appendChild(el('tr', null,
            el('td', { colspan: '6' },
              el('div', { class: 'ex-empty' }, 'Error: ' + e.message))));
        }
      }

      async function showDetail(id) {
        try {
          const entry = await jget(EP.logger.detail + '/' + encodeURIComponent(id));
          detailPanel._set(entry);
        } catch (e) {
          detailPanel._set({ error: e.message });
        }
      }

      refreshBtn.addEventListener('click', () => { loadStats(); loadList(); });
      clearBtn.addEventListener('click', async () => {
        if (!confirm('Clear the HTTP log buffer?')) return;
        try { await jpost(EP.logger.clear, {}); toast('Log cleared', 'ok'); refreshBtn.click(); }
        catch (e) { toast('Clear failed: ' + e.message, 'err'); }
      });
      exportHar.addEventListener('click', async () => {
        try {
          const data = await jget(EP.logger.har + '?size=500');
          download('emergens-http-log.har', JSON.stringify(data, null, 2), 'application/json');
          toast('HAR exported', 'ok');
        } catch (e) { toast('Export failed: ' + e.message, 'err'); }
      });

      function stopLiveStream() {
        const es = state.streams.logger;
        if (es) { try { es.close(); } catch (_) {} delete state.streams.logger; }
        livePill.style.display = 'none';
        liveBtn.innerHTML = '<i class="fas fa-satellite-dish"></i> Live Stream';
      }

      liveBtn.addEventListener('click', () => {
        if (state.streams.logger) { stopLiveStream(); return; }
        livePill.style.display = '';
        liveBtn.innerHTML = '<i class="fas fa-stop"></i> Stop Stream';
        const es = new EventSource(EP.logger.stream);
        state.streams.logger = es;
        es.onmessage = (ev) => {
          try {
            const data = JSON.parse(ev.data);
            if (data.type === 'request') {
              const tr = el('tr', null,
                el('td', null, el('code', null, data.method || '—')),
                el('td', null, el('code', null, data.path   || '—')),
                el('td', null, String(data.status || 0)),
                el('td', null, el('code', null, data.ip     || '—')),
                el('td', null, String(data.elapsed_ms || 0) + 'ms'),
                el('td', null, (data.anomalies || []).map(a => severityBadge(a.severity)).slice(0, 3)),
              );
              tableBody.insertBefore(tr, tableBody.firstChild);
              if (tableBody.childNodes.length > 200) tableBody.removeChild(tableBody.lastChild);
            }
          } catch (_) { /* ignore */ }
        };
        es.onerror = () => { stopLiveStream(); };
      });

      setTimeout(() => { loadStats(); loadList(); }, 80);

      return el('div', { class: 'ex-panel', id: pid('logger') },
        buildCard('HTTP Logger — Live Request Capture', 'fa-wave-square', 'rolling buffer · anomaly detection',
          statsGrid,
          el('div', { style: 'margin: 12px 0 6px;' }, filters),
          el('div', { class: 'ex-row tight', style: 'align-items:center;gap:8px;' },
            refreshBtn, clearBtn, exportHar, liveBtn, livePill,
          ),
          el('div', { style: 'overflow:auto; max-height:400px; margin-top:14px; border-radius:10px; border:1px solid rgba(148,163,184,.14);' },
            el('table', { class: 'ex-table' },
              el('thead', null,
                el('tr', null,
                  el('th', null, 'Method'),
                  el('th', null, 'Path'),
                  el('th', null, 'Status'),
                  el('th', null, 'IP'),
                  el('th', null, 'Latency'),
                  el('th', null, 'Anomalies'),
                ),
              ),
              tableBody,
            ),
          ),
        ),
        buildCard('Entry Detail', 'fa-magnifying-glass', null, detailPanel),
      );
    }

    return {
      dirfuzz:   buildDirfuzzTab,
      sqli:      buildSqliTab,
      sqlmap:    buildSqlmapTab,
      sqlinj:    buildSqlinjTab,
      xss:       buildXssTab,
      xssSimple: buildXssSimpleTab,
      sniper:    buildSniperTab,
      logger:    buildLoggerTab,
    };
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Instance factory
   * ══════════════════════════════════════════════════════════════════ */
  function createInstance(instanceName) {
    instanceName = instanceName || ('ex-' + Math.random().toString(36).slice(2, 8));

    const state = {
      instanceName,
      mounted:    false,
      mountEl:    null,
      activeTab:  'dirfuzz',
      streams:    {},
    };

    const TAB_BUILDERS = makeTabBuilders(instanceName, state);

    function buildUI(defaultTab) {
      const tabsRow = el('div', { class: 'ex-tabs' });
      const panels  = {};

      TABS.forEach(t => {
        const btn = el('button', {
          class: 'ex-tab' + (t.id === defaultTab ? ' active' : ''),
          type: 'button',
          'data-tab': t.id,
        }, el('i', { class: 'fas ' + t.icon }), t.label);
        btn.addEventListener('click', () => switchTab(t.id));
        tabsRow.appendChild(btn);
      });

      const body = el('div');
      TABS.forEach(t => {
        const panel = TAB_BUILDERS[t.id]();
        panel.classList.toggle('active', t.id === defaultTab);
        panels[t.id] = panel;
        body.appendChild(panel);
      });

      function switchTab(id) {
        state.activeTab = id;
        $$('.ex-tab', tabsRow).forEach(b =>
          b.classList.toggle('active', b.dataset.tab === id)
        );
        Object.entries(panels).forEach(([k, p]) =>
          p.classList.toggle('active', k === id)
        );
      }

      const root = el('div', { class: 'ex-root' },
        buildHeader(),
        tabsRow,
        body,
      );
      root._switchTab = switchTab;
      return root;
    }

    function mount(target, opts) {
      if (state.mounted) unmount();
      injectCSS();
      opts = opts || {};
      const defaultTab = opts.defaultTab || 'dirfuzz';

      let elMount = null;
      if (typeof target === 'string') elMount = document.querySelector(target);
      else if (target instanceof Element) elMount = target;
      else elMount = document.querySelector('[data-emergens-panel="exploit"]');

      if (!elMount) {
        console.warn('[ExploitSuite:' + instanceName + '] no mount point found');
        return false;
      }

      state.mountEl = elMount;
      elMount.innerHTML = '';
      elMount.appendChild(buildUI(defaultTab));
      state.mounted = true;
      state.activeTab = defaultTab;
      return true;
    }

    function unmount() {
      for (const es of Object.values(state.streams)) {
        try { es.close(); } catch (_) {}
      }
      state.streams = {};
      state.mounted = false;
      state.mountEl = null;
    }

    function open(tabName) {
      if (!state.mounted || !state.mountEl) return false;
      const root = state.mountEl.querySelector('.ex-root');
      if (root && root._switchTab) { root._switchTab(tabName); return true; }
      return false;
    }

    return {
      mount, unmount, open,
      get state() { return { ...state }; },
    };
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Public API — singleton + factory
   * ══════════════════════════════════════════════════════════════════ */
  const defaultInstance = createInstance('default');

  window.ExploitSuite = Object.assign(defaultInstance, {
    create: createInstance,
  });

  window.addEventListener('beforeunload', () => {
    try { defaultInstance.unmount(); } catch (_) {}
  });

  function autoMount() {
    const placeholder = document.querySelector('[data-emergens-panel="exploit"]');
    if (placeholder && !defaultInstance.state.mounted) {
      defaultInstance.mount(placeholder, { defaultTab: 'dirfuzz' });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoMount);
  } else {
    autoMount();
  }
})();
