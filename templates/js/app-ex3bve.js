/* ============================================================================
 * app-ex3bve.js — Exploit Suite for Emergens
 * v3.0.0 — SHARK THEME ENCHANTED · professional, attractive, multi-instance
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
 * Changelog v3.0.0
 *   ✔ ENCHANTED shark: realistic great white with swimming tail, water
 *     caustics, dual-layer wake, and 7 animated rising bubbles
 *   ✔ Underwater ambience: light rays, deep-blue / blood-red gradient
 *   ✔ Glass-morphic cards with backdrop blur + inner glow
 *   ✔ Enchanted tabs: pill shape with icon-badge + soft glow on active
 *   ✔ Refined progress bars: animated teeth strip + pulse when active
 *   ✔ Better severity badges with gradient background + pulse on running
 *   ✔ Enhanced KPI tiles with mini top accent + hover bloom
 *   ✔ Refined tables: sticky header with backdrop blur + row hover glow
 *   ✔ Enhanced empty states: bigger shark silhouette
 *   ✔ Micro-interactions on buttons, inputs, chips
 *   ✔ Public API unchanged — mount / unmount / open / create
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
   *  SHARK THEME ENCHANTED — CSS
   * ══════════════════════════════════════════════════════════════════ */
  const CSS = `
  /* ─── Exploit Suite root — enchanted underwater theme ─── */
  .ex-root {
    --ex-red:         #dc2626;
    --ex-red-2:       #b91c1c;
    --ex-red-3:       #7f1d1d;
    --ex-red-bright:  #ef4444;
    --ex-red-glow:    rgba(220,38,38,.45);
    --ex-red-soft:    rgba(220,38,38,.18);
    --ex-red-line:    rgba(220,38,38,.32);
    --ex-ocean-1:     #020617;
    --ex-ocean-2:     #060e1e;
    --ex-ocean-3:     #0a1122;
    --ex-ocean-4:     #0f1a2e;
    --ex-teal:        #0891b2;
    --ex-teal-glow:   rgba(8,145,178,.35);
    --ex-border:      rgba(148,163,184,.14);
    --ex-border-2:    rgba(148,163,184,.08);
    --ex-border-red:  rgba(220,38,38,.28);
    --ex-white:       #f8fafc;
    --ex-text:        #e2e8f0;
    --ex-muted:       #94a3b8;
    --ex-muted-2:     #64748b;
    --ex-gold:        #fbbf24;

    display: flex; flex-direction: column; gap: 16px;
    font-family: var(--font-ui, 'Inter','Space Grotesk',system-ui,sans-serif);
    color: var(--ex-text);
    position: relative;
    isolation: isolate;
  }

  /* Ambient underwater backdrop behind the whole suite */
  .ex-root::before {
    content: "";
    position: absolute; inset: -20px;
    background:
      radial-gradient(ellipse at 20% 0%,  rgba(8,145,178,.08), transparent 55%),
      radial-gradient(ellipse at 85% 100%, rgba(220,38,38,.06), transparent 55%);
    pointer-events: none;
    z-index: -1;
  }

  /* ═════════════════════════════════════════════════════════════════
     HEADER — enchanted underwater hero
     ═════════════════════════════════════════════════════════════════ */
  .ex-shark-header {
    position: relative;
    background:
      radial-gradient(ellipse at 12% 100%, rgba(220,38,38,.24), transparent 55%),
      radial-gradient(ellipse at 90% 0%,   rgba(30,58,138,.28),  transparent 55%),
      radial-gradient(ellipse at 50% 50%,  rgba(8,145,178,.08),  transparent 70%),
      linear-gradient(135deg, #0a1122 0%, #0b0715 55%, #150404 100%);
    border: 1px solid var(--ex-border-red);
    border-radius: 18px;
    padding: 26px 30px;
    display: flex; align-items: center; gap: 28px;
    overflow: hidden;
    box-shadow:
      inset 0 1px 0 rgba(255,255,255,.06),
      inset 0 -40px 80px -40px rgba(220,38,38,.14),
      0 14px 40px rgba(0,0,0,.5),
      0 2px 10px rgba(220,38,38,.16);
  }

  /* Water ripple background */
  .ex-shark-header::before {
    content: "";
    position: absolute; inset: 0;
    background-image:
      repeating-radial-gradient(
        circle at 15% 100%,
        rgba(220,38,38,.06) 0 12px,
        transparent 12px 40px
      ),
      repeating-linear-gradient(
        115deg,
        rgba(255,255,255,.018) 0 2px,
        transparent 2px 12px
      );
    opacity: .8;
    pointer-events: none;
  }

  /* Caustic light rays from above */
  .ex-shark-header::after {
    content: "";
    position: absolute; left: 0; right: 0; top: -20%; bottom: -20%;
    background:
      linear-gradient(105deg,
        transparent 10%, rgba(8,145,178,.045) 22%,
        transparent 30%, transparent 55%,
        rgba(220,38,38,.035) 65%, transparent 75%);
    background-size: 220% 100%;
    animation: exCaustics 14s ease-in-out infinite;
    pointer-events: none;
    mix-blend-mode: screen;
  }
  @keyframes exCaustics {
    0%, 100% { background-position: 0% 0; }
    50%      { background-position: 100% 0; }
  }

  /* ═══ Shark figure ═══ */
  .ex-shark-figure {
    position: relative;
    width: 220px; height: 130px;
    flex-shrink: 0;
    filter: drop-shadow(0 14px 26px rgba(220,38,38,.36));
    animation: exSharkCruise 8s ease-in-out infinite;
    z-index: 1;
  }
  .ex-shark-figure svg { width: 100%; height: 100%; display: block; overflow: visible; }
  .ex-shark-figure .ex-tail {
    transform-origin: 30px 100px;
    animation: exTailSway 1.6s ease-in-out infinite;
  }
  @keyframes exSharkCruise {
    0%, 100% { transform: translateX(0)  rotate(-2deg); }
    50%      { transform: translateX(10px) rotate(1deg);  }
  }
  @keyframes exTailSway {
    0%, 100% { transform: rotate(-6deg); }
    50%      { transform: rotate(6deg); }
  }

  /* Bubbles */
  .ex-shark-bubbles {
    position: absolute; inset: 0; pointer-events: none;
    overflow: visible;
  }
  .ex-shark-bubbles span {
    position: absolute;
    bottom: 10px;
    border-radius: 50%;
    background: radial-gradient(circle at 30% 30%, #fff, rgba(220,38,38,.55));
    opacity: 0;
    animation: exBubbleRise 6s linear infinite;
    box-shadow: 0 0 6px rgba(255,255,255,.35);
  }
  .ex-shark-bubbles span:nth-child(1) { left: 52%; width: 5px; height: 5px; animation-delay: 0s;    }
  .ex-shark-bubbles span:nth-child(2) { left: 62%; width: 3px; height: 3px; animation-delay: 0.9s;  }
  .ex-shark-bubbles span:nth-child(3) { left: 72%; width: 6px; height: 6px; animation-delay: 1.8s;  }
  .ex-shark-bubbles span:nth-child(4) { left: 80%; width: 4px; height: 4px; animation-delay: 2.7s;  }
  .ex-shark-bubbles span:nth-child(5) { left: 88%; width: 3px; height: 3px; animation-delay: 3.6s;  }
  .ex-shark-bubbles span:nth-child(6) { left: 42%; width: 4px; height: 4px; animation-delay: 4.5s;  }
  .ex-shark-bubbles span:nth-child(7) { left: 30%; width: 3px; height: 3px; animation-delay: 5.4s;  }
  @keyframes exBubbleRise {
    0%   { transform: translateY(0) scale(.5); opacity: 0; }
    15%  { opacity: .85; }
    85%  { opacity: .55; }
    100% { transform: translateY(-90px) scale(1.3); opacity: 0; }
  }

  /* ═══ Header copy ═══ */
  .ex-shark-copy { flex: 1; min-width: 0; position: relative; z-index: 1; }

  .ex-shark-eyebrow {
    display: inline-flex; align-items: center; gap: 9px;
    font-size: .64rem; letter-spacing: .22em; text-transform: uppercase;
    font-weight: 800; color: #fca5a5;
    margin-bottom: 8px;
    padding: 4px 12px 4px 10px;
    border-radius: 99px;
    background: linear-gradient(135deg, rgba(220,38,38,.14), rgba(220,38,38,.02));
    border: 1px solid rgba(220,38,38,.28);
    box-shadow: 0 2px 8px rgba(220,38,38,.14);
    width: fit-content;
  }
  .ex-shark-eyebrow::before {
    content: "";
    width: 6px; height: 6px; border-radius: 50%;
    background: var(--ex-red-bright);
    box-shadow: 0 0 0 0 rgba(239,68,68,.85);
    animation: exEyeDot 2s ease-out infinite;
  }
  @keyframes exEyeDot {
    0%   { box-shadow: 0 0 0 0 rgba(239,68,68,.85); }
    70%  { box-shadow: 0 0 0 8px rgba(239,68,68,0); }
    100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
  }

  .ex-shark-title {
    font-size: 1.6rem; font-weight: 800; letter-spacing: -.03em;
    color: var(--ex-white);
    margin: 0 0 8px; line-height: 1.1;
    text-shadow: 0 2px 20px rgba(0,0,0,.5);
  }
  .ex-shark-title .ex-title-red {
    background: linear-gradient(135deg, #f87171 0%, #dc2626 45%, #7f1d1d 100%);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
    filter: drop-shadow(0 2px 12px rgba(220,38,38,.5));
  }

  .ex-shark-subtitle {
    color: var(--ex-muted);
    font-size: .82rem; line-height: 1.65; margin: 0;
    max-width: 78ch;
  }
  .ex-shark-subtitle b {
    color: var(--ex-white);
    font-family: var(--font-mono, ui-monospace, monospace);
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 5px;
    background: rgba(220,38,38,.14);
    border: 1px solid rgba(220,38,38,.2);
  }

  /* ═════════════════════════════════════════════════════════════════
     TABS — pill shape with icon-badge
     ═════════════════════════════════════════════════════════════════ */
  .ex-tabs {
    display: flex; flex-wrap: wrap; gap: 7px;
    padding: 12px;
    background:
      linear-gradient(180deg, rgba(220,38,38,.05), transparent 40%),
      linear-gradient(180deg, #0a1122, #050a14);
    border: 1px solid var(--ex-border);
    border-radius: 14px;
    position: relative; overflow: hidden;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
  }
  .ex-tabs::before {
    content: ""; position: absolute; left: 0; right: 0; top: 0; height: 2px;
    background: linear-gradient(90deg, transparent, var(--ex-red), transparent);
    opacity: .6;
  }
  .ex-tab {
    padding: 8px 14px 8px 10px;
    border-radius: 99px;
    border: 1px solid transparent;
    background: transparent;
    color: var(--ex-muted);
    font-size: .78rem; font-weight: 700;
    letter-spacing: .01em;
    cursor: pointer;
    display: inline-flex; align-items: center; gap: 8px;
    transition: all .18s cubic-bezier(.4,0,.2,1);
    -webkit-appearance: none; appearance: none;
    white-space: nowrap; font-family: inherit;
    position: relative;
  }
  .ex-tab .ex-tab-ico {
    width: 22px; height: 22px;
    display: inline-flex; align-items: center; justify-content: center;
    font-size: .72rem;
    border-radius: 50%;
    background: rgba(148,163,184,.10);
    color: inherit;
    transition: all .18s;
    flex-shrink: 0;
  }
  .ex-tab:hover {
    color: var(--ex-white);
    border-color: var(--ex-border-red);
    background: linear-gradient(180deg, rgba(220,38,38,.10), rgba(220,38,38,.02));
    transform: translateY(-1px);
  }
  .ex-tab:hover .ex-tab-ico {
    background: rgba(220,38,38,.22);
    color: #fca5a5;
  }
  .ex-tab.active {
    background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
    color: #fff;
    border-color: rgba(255,255,255,.2);
    box-shadow:
      0 6px 20px rgba(220,38,38,.45),
      0 0 0 1px rgba(255,255,255,.06) inset,
      inset 0 1px 0 rgba(255,255,255,.2);
  }
  .ex-tab.active .ex-tab-ico {
    background: rgba(0,0,0,.28);
    color: #fff;
  }

  /* ═════════════════════════════════════════════════════════════════
     PANELS
     ═════════════════════════════════════════════════════════════════ */
  .ex-panel { display: none; }
  .ex-panel.active {
    display: flex; flex-direction: column; gap: 14px;
    animation: exSlideIn .32s cubic-bezier(.4,0,.2,1);
  }
  @keyframes exSlideIn {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  /* ═════════════════════════════════════════════════════════════════
     CARDS — glass-morphic with inner glow
     ═════════════════════════════════════════════════════════════════ */
  .ex-card {
    background:
      linear-gradient(165deg, rgba(11,18,32,.85) 0%, rgba(5,10,22,.95) 100%);
    border: 1px solid var(--ex-border);
    border-radius: 14px;
    padding: 20px 22px;
    position: relative;
    overflow: hidden;
    transition: border-color .2s, box-shadow .2s, transform .2s;
    backdrop-filter: blur(8px) saturate(1.1);
    -webkit-backdrop-filter: blur(8px) saturate(1.1);
  }
  .ex-card::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, var(--ex-red) 0%, transparent 55%);
    opacity: .6;
  }
  .ex-card::after {
    content: ""; position: absolute; inset: 0;
    background: radial-gradient(ellipse at 0% 0%, rgba(220,38,38,.04), transparent 40%);
    pointer-events: none;
  }
  .ex-card:hover {
    border-color: var(--ex-border-red);
    box-shadow:
      0 10px 30px rgba(0,0,0,.45),
      0 0 0 1px rgba(220,38,38,.1) inset,
      0 0 40px -10px rgba(220,38,38,.2);
    transform: translateY(-1px);
  }
  .ex-card h4 {
    margin: 0 0 16px;
    font-size: .78rem; font-weight: 800;
    letter-spacing: .1em; text-transform: uppercase;
    color: var(--ex-white);
    display: flex; align-items: center; gap: 11px;
    padding-bottom: 14px;
    border-bottom: 1px solid var(--ex-border-2);
    flex-wrap: wrap;
    position: relative;
  }
  .ex-card h4 i {
    width: 30px; height: 30px;
    display: flex; align-items: center; justify-content: center;
    font-size: .84rem;
    border-radius: 9px;
    background: linear-gradient(135deg, var(--ex-red-bright), var(--ex-red-3));
    color: #fff;
    box-shadow:
      0 4px 14px rgba(220,38,38,.45),
      inset 0 1px 0 rgba(255,255,255,.2);
    flex-shrink: 0;
  }
  .ex-card h4 .ex-card-hint {
    margin-left: auto;
    font-size: .66rem; font-weight: 600;
    letter-spacing: 0; text-transform: none;
    color: var(--ex-muted);
    font-family: var(--font-mono, monospace);
    padding: 3px 9px;
    border-radius: 99px;
    background: rgba(148,163,184,.08);
    border: 1px solid var(--ex-border);
  }

  /* ═════════════════════════════════════════════════════════════════
     FORMS
     ═════════════════════════════════════════════════════════════════ */
  .ex-row { display: flex; gap: 10px; flex-wrap: wrap; }
  .ex-row > * { flex: 1 1 150px; min-width: 0; }
  .ex-row.tight > * { flex: 0 0 auto; }

  .ex-field { display: flex; flex-direction: column; gap: 6px; }
  .ex-field > label {
    font-size: .64rem; font-weight: 700;
    letter-spacing: .07em; text-transform: uppercase;
    color: var(--ex-muted);
  }
  .ex-field > input,
  .ex-field > select,
  .ex-field > textarea {
    background: linear-gradient(180deg, #050a14, #0a1122);
    border: 1px solid var(--ex-border);
    border-radius: 9px;
    padding: 11px 13px;
    color: var(--ex-white);
    font-size: .85rem;
    font-family: var(--font-mono, ui-monospace, monospace);
    outline: none;
    transition: border-color .18s, box-shadow .18s, background .18s;
    -webkit-appearance: none; appearance: none;
    width: 100%;
  }
  .ex-field > input:hover,
  .ex-field > select:hover,
  .ex-field > textarea:hover { border-color: rgba(148,163,184,.28); }
  .ex-field > input:focus,
  .ex-field > select:focus,
  .ex-field > textarea:focus {
    border-color: var(--ex-red);
    box-shadow:
      0 0 0 3px rgba(220,38,38,.18),
      0 0 20px -4px rgba(220,38,38,.35);
    background: linear-gradient(180deg, #060b17, #0b1226);
  }
  .ex-field > input::placeholder,
  .ex-field > textarea::placeholder { color: rgba(148,163,184,.45); }
  .ex-field > textarea { min-height: 70px; resize: vertical; }

  /* ═════════════════════════════════════════════════════════════════
     BUTTONS — enchanted with hover bloom
     ═════════════════════════════════════════════════════════════════ */
  .ex-actions { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
  .ex-btn {
    padding: 11px 18px;
    border-radius: 10px;
    border: 1px solid transparent;
    font-weight: 700; font-size: .82rem;
    cursor: pointer;
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    transition: all .18s cubic-bezier(.4,0,.2,1);
    -webkit-appearance: none; appearance: none;
    white-space: nowrap; font-family: inherit;
    position: relative;
    overflow: hidden;
  }
  .ex-btn::before {
    content: "";
    position: absolute; inset: 0;
    background: radial-gradient(circle at center, rgba(255,255,255,.22), transparent 60%);
    opacity: 0;
    transition: opacity .25s;
    pointer-events: none;
  }
  .ex-btn:active { transform: scale(.97); }
  .ex-btn[disabled] { opacity: .5; cursor: not-allowed; transform: none !important; }

  .ex-btn-primary {
    background: linear-gradient(135deg, var(--ex-red-bright), var(--ex-red-3));
    color: #fff;
    box-shadow:
      0 4px 14px rgba(220,38,38,.4),
      inset 0 1px 0 rgba(255,255,255,.18);
  }
  .ex-btn-primary:hover:not([disabled]) {
    transform: translateY(-2px);
    box-shadow:
      0 12px 32px rgba(220,38,38,.6),
      inset 0 1px 0 rgba(255,255,255,.22);
    filter: brightness(1.08);
  }
  .ex-btn-primary:hover:not([disabled])::before { opacity: 1; }

  .ex-btn-danger {
    background: linear-gradient(135deg, #7f1d1d, #450a0a);
    color: #fca5a5;
    border-color: rgba(239,68,68,.4);
    box-shadow: 0 4px 14px rgba(239,68,68,.22);
  }
  .ex-btn-danger:hover:not([disabled]) {
    transform: translateY(-2px);
    background: linear-gradient(135deg, #991b1b, #7f1d1d);
    color: #fff;
    box-shadow: 0 10px 26px rgba(239,68,68,.4);
  }

  .ex-btn-ghost {
    background: linear-gradient(180deg, #0a1122, #06090f);
    border-color: var(--ex-border);
    color: var(--ex-muted);
  }
  .ex-btn-ghost:hover:not([disabled]) {
    border-color: var(--ex-red);
    color: var(--ex-white);
    background: linear-gradient(180deg, rgba(220,38,38,.10), rgba(220,38,38,.02));
    box-shadow: 0 4px 14px rgba(220,38,38,.18);
  }

  /* ═════════════════════════════════════════════════════════════════
     PROGRESS — enhanced teeth strip + pulse when active
     ═════════════════════════════════════════════════════════════════ */
  .ex-progress {
    margin-top: 12px;
    height: 14px; width: 100%;
    background: linear-gradient(180deg, #050912, #0a1122);
    border-radius: 99px;
    overflow: hidden;
    border: 1px solid var(--ex-border);
    position: relative;
    box-shadow:
      inset 0 2px 4px rgba(0,0,0,.6),
      0 1px 0 rgba(255,255,255,.03);
  }
  .ex-progress > span {
    display: block; height: 100%; width: 0%;
    background:
      linear-gradient(180deg, rgba(255,255,255,.18), transparent 40%),
      linear-gradient(90deg, #991b1b, #dc2626, #ef4444, #f87171);
    transition: width .35s cubic-bezier(.16,1,.3,1);
    border-radius: 99px;
    position: relative; overflow: hidden;
    box-shadow:
      0 0 20px rgba(220,38,38,.5),
      inset 0 -2px 4px rgba(0,0,0,.3);
  }
  .ex-progress > span::before {
    content: "";
    position: absolute; inset: 0;
    background-image:
      linear-gradient(135deg, transparent 50%, rgba(255,255,255,.4) 50%),
      linear-gradient(45deg, rgba(255,255,255,.4) 50%, transparent 50%);
    background-size: 9px 9px;
    background-repeat: repeat-x;
    animation: exTeethScroll 1.2s linear infinite;
    opacity: .6;
  }
  .ex-progress > span::after {
    content: "";
    position: absolute; inset: 0;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,.35), transparent);
    background-size: 200% 100%;
    animation: exShimmer 2.2s linear infinite;
    opacity: .55;
  }
  @keyframes exTeethScroll {
    from { background-position: 0 0; }
    to   { background-position: 9px 0; }
  }
  @keyframes exShimmer {
    0%   { background-position: -200% 0; }
    100% { background-position: 200% 0; }
  }
  .ex-progress-label {
    display: flex; justify-content: space-between;
    font-size: .7rem; color: var(--ex-muted);
    margin-top: 8px;
    font-family: var(--font-mono, monospace);
    gap: 12px;
  }
  .ex-progress-label span:first-child {
    flex: 1; min-width: 0;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }

  /* ═════════════════════════════════════════════════════════════════
     LOG — terminal-style
     ═════════════════════════════════════════════════════════════════ */
  .ex-log {
    max-height: 300px; overflow-y: auto;
    background: linear-gradient(180deg, #030509, #050a14);
    border: 1px solid var(--ex-border);
    border-radius: 11px;
    padding: 14px 16px 14px 22px;
    font-family: var(--font-mono, monospace);
    font-size: .72rem;
    color: #cbd5e1;
    white-space: pre-wrap;
    line-height: 1.7;
    margin-top: 12px;
    scrollbar-width: thin;
    scrollbar-color: rgba(220,38,38,.5) transparent;
    position: relative;
  }
  .ex-log::before {
    content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px;
    background: linear-gradient(180deg, var(--ex-red-bright), var(--ex-red-3), transparent);
    border-radius: 2px;
  }
  .ex-log::-webkit-scrollbar { width: 8px; }
  .ex-log::-webkit-scrollbar-track { background: transparent; }
  .ex-log::-webkit-scrollbar-thumb {
    background: rgba(220,38,38,.4); border-radius: 4px;
  }
  .ex-log::-webkit-scrollbar-thumb:hover { background: rgba(220,38,38,.6); }
  .ex-log .ok   { color: #4ade80; }
  .ex-log .warn { color: #fbbf24; }
  .ex-log .err  { color: #f87171; }
  .ex-log .dim  { color: #64748b; }

  /* ═════════════════════════════════════════════════════════════════
     RESULT VIEWER
     ═════════════════════════════════════════════════════════════════ */
  .ex-result {
    background: linear-gradient(180deg, #030509, #050a14);
    border: 1px solid var(--ex-border);
    border-radius: 11px;
    padding: 15px;
    font-family: var(--font-mono, monospace);
    font-size: .74rem;
    color: #e2e8f0;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 480px; overflow-y: auto;
    line-height: 1.7;
    scrollbar-width: thin;
    box-shadow: inset 0 2px 6px rgba(0,0,0,.4);
  }
  .ex-result .dim { color: #64748b; }

  /* ═════════════════════════════════════════════════════════════════
     BADGES — gradients + running pulse
     ═════════════════════════════════════════════════════════════════ */
  .ex-badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 3px 10px;
    border-radius: 99px;
    font-size: .62rem; font-weight: 800;
    text-transform: uppercase; letter-spacing: .07em;
    border: 1px solid;
    position: relative;
  }
  .ex-badge-critical {
    background: linear-gradient(135deg, rgba(220,38,38,.28), rgba(127,29,29,.18));
    color: #fca5a5; border-color: rgba(220,38,38,.55);
    box-shadow: 0 0 12px -2px rgba(220,38,38,.35);
  }
  .ex-badge-high {
    background: linear-gradient(135deg, rgba(249,115,22,.24), rgba(154,52,18,.15));
    color: #fdba74; border-color: rgba(249,115,22,.5);
  }
  .ex-badge-medium {
    background: linear-gradient(135deg, rgba(245,158,11,.24), rgba(120,53,15,.15));
    color: #fcd34d; border-color: rgba(245,158,11,.5);
  }
  .ex-badge-low {
    background: linear-gradient(135deg, rgba(59,130,246,.22), rgba(30,58,138,.15));
    color: #93c5fd; border-color: rgba(59,130,246,.5);
  }
  .ex-badge-info {
    background: linear-gradient(135deg, rgba(148,163,184,.18), rgba(71,85,105,.1));
    color: #cbd5e1; border-color: rgba(148,163,184,.35);
  }
  .ex-badge-safe {
    background: linear-gradient(135deg, rgba(34,197,94,.22), rgba(20,83,45,.15));
    color: #86efac; border-color: rgba(34,197,94,.5);
  }

  /* ═════════════════════════════════════════════════════════════════
     CHIPS
     ═════════════════════════════════════════════════════════════════ */
  .ex-chips {
    display: flex; flex-wrap: wrap; gap: 6px;
    max-height: 120px; overflow-y: auto;
    padding: 4px 2px;
  }
  .ex-chip {
    padding: 6px 12px;
    border-radius: 8px;
    border: 1px solid var(--ex-border);
    background: linear-gradient(180deg, #0a1122, #06090f);
    color: var(--ex-muted);
    font-family: var(--font-mono, monospace);
    font-size: .7rem; font-weight: 600;
    cursor: pointer;
    transition: all .16s;
    -webkit-appearance: none; appearance: none;
  }
  .ex-chip:hover {
    border-color: var(--ex-red);
    color: var(--ex-white);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(220,38,38,.2);
  }
  .ex-chip.active {
    background: linear-gradient(135deg, var(--ex-red-bright), var(--ex-red-3));
    border-color: transparent;
    color: #fff;
    box-shadow:
      0 4px 14px rgba(220,38,38,.45),
      inset 0 1px 0 rgba(255,255,255,.18);
  }

  /* ═════════════════════════════════════════════════════════════════
     FINDINGS
     ═════════════════════════════════════════════════════════════════ */
  .ex-findings { display: flex; flex-direction: column; gap: 8px; }
  .ex-finding {
    background:
      linear-gradient(180deg, rgba(10,17,34,.9), rgba(5,10,22,.9));
    border-left: 4px solid #dc2626;
    border-radius: 9px;
    padding: 13px 16px;
    font-size: .78rem;
    transition: all .18s;
    animation: exFindingIn .34s cubic-bezier(.4,0,.2,1);
    position: relative;
  }
  .ex-finding::before {
    content: "";
    position: absolute; left: -4px; top: 0; bottom: 0; width: 4px;
    border-radius: 9px 0 0 9px;
    background: inherit;
  }
  @keyframes exFindingIn {
    from { opacity: 0; transform: translateX(-8px); }
    to   { opacity: 1; transform: translateX(0); }
  }
  .ex-finding:hover {
    background: linear-gradient(180deg, rgba(15,26,46,.9), rgba(10,19,37,.9));
    transform: translateX(4px);
    box-shadow:
      0 6px 20px rgba(0,0,0,.45),
      0 0 0 1px rgba(220,38,38,.1) inset;
  }
  .ex-finding.critical { border-left-color: #dc2626; box-shadow: 0 0 18px -8px rgba(220,38,38,.4); }
  .ex-finding.high     { border-left-color: #f97316; }
  .ex-finding.medium   { border-left-color: #f59e0b; }
  .ex-finding.low      { border-left-color: #3b82f6; }
  .ex-finding.safe     { border-left-color: #22c55e; }
  .ex-finding .label {
    font-size: .62rem; text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--ex-muted);
    font-weight: 700;
    display: flex; align-items: center; gap: 8px;
  }
  .ex-finding .label i { color: var(--ex-red-bright); }
  .ex-finding .value {
    font-family: var(--font-mono, monospace);
    word-break: break-all;
    margin-top: 6px;
    color: var(--ex-white);
    font-size: .76rem;
    line-height: 1.55;
  }
  .ex-finding .meta {
    margin-top: 9px;
    font-size: .66rem;
    color: var(--ex-muted);
    display: flex; gap: 14px; flex-wrap: wrap; align-items: center;
  }

  /* ═════════════════════════════════════════════════════════════════
     KPI TILES
     ═════════════════════════════════════════════════════════════════ */
  .ex-kpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 10px;
    margin-bottom: 12px;
  }
  .ex-kpi {
    background: linear-gradient(165deg, #0b1220 0%, #050a16 100%);
    border: 1px solid var(--ex-border);
    border-radius: 11px;
    padding: 15px 16px;
    display: flex; flex-direction: column; gap: 5px;
    transition: all .2s;
    position: relative; overflow: hidden;
  }
  .ex-kpi::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, var(--ex-red), transparent);
    opacity: .5;
  }
  .ex-kpi::after {
    content: ""; position: absolute; inset: 0;
    background: radial-gradient(circle at 0% 0%, rgba(220,38,38,.05), transparent 50%);
    pointer-events: none;
  }
  .ex-kpi:hover {
    border-color: var(--ex-border-red);
    transform: translateY(-2px);
    box-shadow:
      0 8px 22px rgba(0,0,0,.45),
      0 0 0 1px rgba(220,38,38,.08) inset;
  }
  .ex-kpi .k-label {
    font-size: .62rem; letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--ex-muted);
    font-weight: 700;
  }
  .ex-kpi .k-val {
    font-family: var(--font-display, monospace);
    font-size: 1.4rem;
    color: var(--ex-white);
    font-weight: 800;
    line-height: 1.1;
    text-shadow: 0 2px 12px rgba(220,38,38,.15);
  }

  /* ═════════════════════════════════════════════════════════════════
     TABLES — sticky header + hover glow
     ═════════════════════════════════════════════════════════════════ */
  .ex-table { width: 100%; border-collapse: collapse; font-size: .76rem; }
  .ex-table th, .ex-table td {
    text-align: left; padding: 10px 12px;
    border-bottom: 1px solid var(--ex-border);
  }
  .ex-table th {
    font-size: .62rem; letter-spacing: .08em; text-transform: uppercase;
    color: var(--ex-muted); font-weight: 800;
    background:
      linear-gradient(180deg, rgba(220,38,38,.08), rgba(220,38,38,.02));
    position: sticky; top: 0; z-index: 1;
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
  }
  .ex-table code {
    font-family: var(--font-mono, monospace);
    font-size: .72rem;
    color: #cbd5e1;
    word-break: break-all;
  }
  .ex-table tbody tr {
    cursor: pointer;
    transition: background .14s, box-shadow .14s;
  }
  .ex-table tbody tr:hover {
    background: linear-gradient(90deg, rgba(220,38,38,.1), transparent);
    box-shadow: inset 3px 0 0 var(--ex-red);
  }

  /* ═════════════════════════════════════════════════════════════════
     EMPTY STATE — bigger shark silhouette
     ═════════════════════════════════════════════════════════════════ */
  .ex-empty {
    padding: 32px 16px;
    text-align: center;
    color: var(--ex-muted);
    font-size: .82rem;
    font-style: italic;
    display: flex; flex-direction: column; gap: 14px; align-items: center;
  }
  .ex-empty svg {
    width: 90px; height: 68px;
    opacity: .42;
    filter: drop-shadow(0 6px 18px rgba(220,38,38,.45));
    animation: exEmptyFloat 4s ease-in-out infinite;
  }
  @keyframes exEmptyFloat {
    0%, 100% { transform: translateY(0); }
    50%      { transform: translateY(-4px); }
  }

  /* ═════════════════════════════════════════════════════════════════
     LIVE PILL
     ═════════════════════════════════════════════════════════════════ */
  .ex-live-pill {
    display: inline-flex; align-items: center; gap: 7px;
    padding: 5px 12px; border-radius: 99px;
    background: linear-gradient(135deg, rgba(220,38,38,.22), rgba(220,38,38,.06));
    color: #f87171;
    font-size: .62rem; font-weight: 800;
    letter-spacing: .07em; text-transform: uppercase;
    border: 1px solid rgba(220,38,38,.45);
    box-shadow: 0 0 12px -2px rgba(220,38,38,.35);
  }
  .ex-live-pill .dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: #ef4444;
    box-shadow: 0 0 0 0 rgba(239,68,68,.8);
    animation: exLivePulse 1.5s ease-out infinite;
  }
  @keyframes exLivePulse {
    0%   { box-shadow: 0 0 0 0 rgba(239,68,68,.85); }
    70%  { box-shadow: 0 0 0 9px rgba(239,68,68,0); }
    100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
  }

  /* ═════════════════════════════════════════════════════════════════
     SIDEBAR NAV — NEUTRAL BY DEFAULT, RED ONLY ON HOVER / ACTIVE
     ═════════════════════════════════════════════════════════════════ */
  .nav-item[data-section="mhddos"],
  .nav-item[data-section="exploit"] {
    position: relative;
    transition: all .18s cubic-bezier(.4,0,.2,1);
  }
  .nav-item[data-section="mhddos"] i,
  .nav-item[data-section="exploit"] i { transition: color .18s; }

  .nav-item[data-section="mhddos"]:hover,
  .nav-item[data-section="exploit"]:hover {
    background: linear-gradient(90deg, rgba(220,38,38,.18), transparent 75%) !important;
    border-left-color: #dc2626 !important;
    color: #fff !important;
  }
  .nav-item[data-section="mhddos"]:hover i,
  .nav-item[data-section="exploit"]:hover i { color: #ef4444 !important; }

  .nav-item[data-section="mhddos"].active,
  .nav-item[data-section="exploit"].active {
    background: linear-gradient(90deg, rgba(220,38,38,.42), rgba(220,38,38,.10) 75%, transparent) !important;
    border-left-color: #ef4444 !important;
    color: #fff !important;
    font-weight: 700 !important;
    box-shadow:
      inset 3px 0 0 rgba(239,68,68,.85),
      0 0 18px -6px rgba(220,38,38,.55);
  }
  .nav-item[data-section="mhddos"].active i,
  .nav-item[data-section="exploit"].active i {
    color: #fff !important;
    filter: drop-shadow(0 0 8px rgba(239,68,68,.85));
  }

  /* Section-title red chips only when active */
  .content-section.active#section-mhddos   .panel-title i,
  .content-section.active#section-exploit  .panel-title i,
  .content-section.active#section-httplogger .panel-title i {
    color: #ef4444 !important;
    background: linear-gradient(135deg, rgba(220,38,38,.26), rgba(127,29,29,.14)) !important;
    box-shadow: inset 0 0 0 1px rgba(220,38,38,.35);
  }

  /* ═════════════════════════════════════════════════════════════════
     Responsive
     ═════════════════════════════════════════════════════════════════ */
  @media (max-width: 820px) {
    .ex-shark-header { flex-direction: column; align-items: flex-start; padding: 20px; gap: 16px; }
    .ex-shark-figure { width: 170px; height: 105px; }
    .ex-shark-title  { font-size: 1.28rem; }
    .ex-shark-header::after { animation: none; }
  }
  @media (max-width: 720px) {
    .ex-row > * { flex: 1 1 100%; }
    .ex-tabs { overflow-x: auto; flex-wrap: nowrap; padding: 10px; }
    .ex-tab  { flex-shrink: 0; }
  }
  @media (max-width: 480px) {
    .ex-shark-figure { width: 140px; height: 88px; }
    .ex-shark-title  { font-size: 1.12rem; }
  }
  `;

  function injectCSS() {
    if (document.getElementById('ex-css')) return;
    const s = document.createElement('style');
    s.id = 'ex-css';
    s.textContent = CSS;
    document.head.appendChild(s);
  }

  /* ── Enchanted shark SVG (great white with tail motion) ─────────── */
  function sharkFigure() {
    const wrap = el('div', { class: 'ex-shark-figure', 'aria-hidden': 'true' });
    const svg = el('div', {
      html: `
        <svg viewBox="0 0 260 150" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="exBodyGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stop-color="#475569"/>
              <stop offset="0.5" stop-color="#1e293b"/>
              <stop offset="1" stop-color="#0a1120"/>
            </linearGradient>
            <linearGradient id="exBellyGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stop-color="#f1f5f9"/>
              <stop offset="0.7" stop-color="#cbd5e1"/>
              <stop offset="1" stop-color="#64748b"/>
            </linearGradient>
            <linearGradient id="exFinGrad" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stop-color="#fca5a5"/>
              <stop offset="0.35" stop-color="#ef4444"/>
              <stop offset="0.75" stop-color="#b91c1c"/>
              <stop offset="1" stop-color="#7f1d1d"/>
            </linearGradient>
            <linearGradient id="exTailGrad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0" stop-color="#b91c1c"/>
              <stop offset="1" stop-color="#7f1d1d"/>
            </linearGradient>
            <radialGradient id="exEyeGlow" cx="0.5" cy="0.5" r="0.5">
              <stop offset="0" stop-color="#f8fafc"/>
              <stop offset="1" stop-color="#020617"/>
            </radialGradient>
            <filter id="exSoftGlow" x="-40%" y="-40%" width="180%" height="180%">
              <feGaussianBlur stdDeviation="3" result="b"/>
              <feMerge>
                <feMergeNode in="b"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
            <filter id="exFinShadow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="2" result="s"/>
              <feMerge>
                <feMergeNode in="s"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>

          <!-- Water wake (double layer) -->
          <path d="M4 126 Q70 118 136 126 T268 126"
                fill="none" stroke="#0891b2" stroke-width="1.6"
                stroke-opacity="0.4" stroke-linecap="round"/>
          <path d="M18 134 Q84 128 148 134 T276 134"
                fill="none" stroke="#0891b2" stroke-width="1"
                stroke-opacity="0.22" stroke-linecap="round"/>

          <!-- Tail (animated) -->
          <g class="ex-tail">
            <path d="M28 106 L4 126 L40 122 L32 106 Z"
                  fill="url(#exTailGrad)" stroke="#450a0a" stroke-width="1.2"/>
            <path d="M30 106 L16 90 L42 102 Z"
                  fill="url(#exTailGrad)" stroke="#450a0a" stroke-width="1"/>
          </g>

          <!-- Body — long, tapered, great-white proportions -->
          <path d="M26 100
                   Q66 78 118 76
                   Q178 74 226 90
                   L236 100
                   Q178 120 118 114
                   Q66 108 26 100 Z"
                fill="url(#exBodyGrad)" stroke="#0f172a" stroke-width="1.6"/>

          <!-- Belly highlight -->
          <path d="M44 102
                   Q100 114 158 111
                   Q202 108 232 100
                   L222 100
                   Q168 112 118 110
                   Q76 108 44 102 Z"
                fill="url(#exBellyGrad)" opacity="0.9"/>

          <!-- Dorsal fin (main) -->
          <path d="M112 74 L148 16 L164 74 Q134 64 112 74 Z"
                fill="url(#exFinGrad)" stroke="#450a0a" stroke-width="1.6"
                filter="url(#exSoftGlow)"/>

          <!-- Dorsal fin highlight -->
          <path d="M118 72 L146 30 L154 72 Q136 66 118 72 Z"
                fill="#fca5a5" opacity="0.28"/>

          <!-- Second dorsal fin -->
          <path d="M168 78 L182 58 L192 80 Q178 76 168 78 Z"
                fill="url(#exFinGrad)" opacity="0.85"
                filter="url(#exFinShadow)"/>

          <!-- Pectoral fin (long, pointed — signature of great white) -->
          <path d="M118 112 L98 142 L134 122 Z"
                fill="url(#exFinGrad)" opacity="0.95"
                filter="url(#exFinShadow)"/>

          <!-- Anal / pelvic fins -->
          <path d="M156 112 L162 130 L176 114 Z"
                fill="url(#exFinGrad)" opacity="0.75"/>

          <!-- Gills (five slashes, great-white signature) -->
          <g stroke="#dc2626" stroke-width="1.8" stroke-linecap="round" opacity="0.9">
            <path d="M162 84 L160 102"/>
            <path d="M171 83 L169 102"/>
            <path d="M180 82 L178 102"/>
            <path d="M189 82 L187 102"/>
            <path d="M198 82 L196 102"/>
          </g>

          <!-- Eye with glow -->
          <circle cx="218" cy="90" r="4"   fill="url(#exEyeGlow)"/>
          <circle cx="218" cy="90" r="1.3" fill="#020617"/>

          <!-- Teeth strip (upper jaw) -->
          <g fill="#f8fafc" opacity="0.95">
            <path d="M212 99 L214 106 L216 99 Z"/>
            <path d="M218 99 L220 107 L222 99 Z"/>
            <path d="M224 99 L226 106 L228 99 Z"/>
            <path d="M230 99 L232 105 L234 99 Z"/>
          </g>

          <!-- Teeth strip (lower jaw hint) -->
          <g fill="#e2e8f0" opacity="0.55">
            <path d="M215 103 L216 99 L217 103 Z"/>
            <path d="M221 103 L222 98 L223 103 Z"/>
            <path d="M227 103 L228 99 L229 103 Z"/>
          </g>

          <!-- Mouth line (cruel smirk) -->
          <path d="M208 98 Q222 106 238 100"
                fill="none" stroke="#7f1d1d" stroke-width="1.6"
                stroke-linecap="round"/>

          <!-- Nostril / snout detail -->
          <path d="M244 96 Q250 98 252 100"
                fill="none" stroke="#1e293b" stroke-width="1.2"
                stroke-linecap="round" opacity="0.8"/>
        </svg>
      `,
    });
    const bubbles = el('div', { class: 'ex-shark-bubbles' },
      el('span'), el('span'), el('span'), el('span'),
      el('span'), el('span'), el('span'),
    );
    wrap.appendChild(svg);
    wrap.appendChild(bubbles);
    return wrap;
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Shared UI builders
   * ══════════════════════════════════════════════════════════════════ */
  function buildHeader() {
    return el('div', { class: 'ex-shark-header' },
      sharkFigure(),
      el('div', { class: 'ex-shark-copy' },
        el('div', { class: 'ex-shark-eyebrow' }, 'Predator Mode'),
        el('h3', { class: 'ex-shark-title' },
          'Exploit ',
          el('span', { class: 'ex-title-red' }, 'Suite'),
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

  function emptyState(text) {
    const wrap = el('div', { class: 'ex-empty' });
    wrap.innerHTML = `
      <svg viewBox="0 0 140 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <defs>
          <linearGradient id="exEmptyFin" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#f87171"/>
            <stop offset="0.55" stop-color="#dc2626"/>
            <stop offset="1" stop-color="#7f1d1d"/>
          </linearGradient>
          <linearGradient id="exEmptyBody" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#334155"/>
            <stop offset="1" stop-color="#0f172a"/>
          </linearGradient>
        </defs>
        <path d="M14 72 Q46 58 82 62 L118 34 L108 64 L132 82 L92 80 Q46 90 14 72 Z"
              fill="url(#exEmptyBody)" stroke="#dc2626" stroke-width="1.2" stroke-opacity="0.65"/>
        <path d="M66 32 L86 4 L94 36 Q78 30 66 32 Z" fill="url(#exEmptyFin)"/>
        <path d="M22 66 L10 86 L36 78 L22 66 Z" fill="url(#exEmptyFin)" opacity="0.85"/>
        <circle cx="48" cy="70" r="2" fill="#f8fafc"/>
        <path d="M112 70 L114 74 L116 70 Z" fill="#f8fafc"/>
        <path d="M117 70 L119 75 L121 70 Z" fill="#f8fafc"/>
      </svg>
    `;
    if (text) wrap.appendChild(el('span', null, text));
    return wrap;
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
          findingsBox.appendChild(emptyState('No hits'));
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
            el('label', { style: 'font-size:.64rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#94a3b8;' }, 'Techniques'),
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
          findingsBox.appendChild(emptyState('No XSS vectors found'));
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
              el('td', { colspan: '6' }, emptyState('No requests captured'))));
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
              emptyState('Error: ' + e.message))));
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
          el('div', { style: 'overflow:auto; max-height:400px; margin-top:14px; border-radius:11px; border:1px solid rgba(148,163,184,.14);' },
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
        },
          el('span', { class: 'ex-tab-ico' }, el('i', { class: 'fas ' + t.icon })),
          t.label,
        );
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
