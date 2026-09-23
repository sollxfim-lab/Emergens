/* ============================================================================
 * app-mh5783.js — MHDDoS Control Panel for Emergens
 * v2.0.0 — SHARK THEME · professional, matching app-ex3bve.js
 *
 * Talks to:
 *   GET  /api/mhddos/methods
 *   POST /api/mhddos/start
 *   POST /api/mhddos/stop
 *   POST /api/mhddos/stop_all
 *   GET  /api/mhddos/status
 *   GET  /api/mhddos/history
 *
 * Changelog v2.0.0
 *   ✔ Shark-themed UI matching app-ex3bve.js (dark navy + red)
 *   ✔ Animated shark header with "Predator Mode" eyebrow
 *   ✔ Live status pill (auto-syncing with running count)
 *   ✔ Quick-load presets (Recon / Stress / UDP / Mixed)
 *   ✔ Running attacks get a live elapsed-time bar + per-row stop button
 *   ✔ Neutral sidebar button by default; red only on hover / active
 *   ✔ Better method selector: searchable chips grouped by Layer 7 / 4
 *   ✔ All legacy APIs kept: mount / unmount / refresh + state
 *
 * Public API
 *   window.MHDDoSControl.mount(selectorOrEl)
 *   window.MHDDoSControl.unmount()
 *   window.MHDDoSControl.refresh()
 * ========================================================================= */
(function () {
  'use strict';

  const API = {
    methods:  '/api/mhddos/methods',
    start:    '/api/mhddos/start',
    stop:     '/api/mhddos/stop',
    stopAll:  '/api/mhddos/stop_all',
    status:   '/api/mhddos/status',
    history:  '/api/mhddos/history',
  };

  const POLL_MS = 2000;

  const state = {
    mounted:    false,
    mountEl:    null,
    methods:    [],
    layer7:     [],
    layer4:     [],
    running:    [],
    history:    [],
    pollTimer:  null,
    busy:       false,
  };

  /* ── helpers ─────────────────────────────────────────────────────── */
  const $  = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k === 'class')       node.className = v;
        else if (k === 'html')   node.innerHTML = v;
        else if (k.startsWith('on') && typeof v === 'function') {
          node.addEventListener(k.slice(2).toLowerCase(), v);
        } else node.setAttribute(k, v);
      }
    }
    const append = (c) => {
      if (c == null || c === false) return;
      if (Array.isArray(c)) { c.forEach(append); return; }
      if (typeof c === 'string' || typeof c === 'number') {
        node.appendChild(document.createTextNode(String(c)));
      } else {
        node.appendChild(c);
      }
    };
    children.forEach(append);
    return node;
  }

  function toast(msg, kind = 'info', ms = 3200) {
    let container = document.getElementById('toastContainer');
    if (!container) {
      container = el('div', { id: 'toastContainer', class: 'toast-container' });
      document.body.appendChild(container);
    }
    const node = el('div', { class: 'toast toast-' + kind }, msg);
    container.appendChild(node);
    setTimeout(() => {
      node.style.opacity = '0';
      setTimeout(() => node.remove(), 300);
    }, ms);
  }

  async function jget(url) {
    const r = await fetch(url, { credentials: 'same-origin' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }

  async function jpost(url, body) {
    const r = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    let data = null;
    try { data = await r.json(); } catch (_) { /* ignore */ }
    if (!r.ok) throw new Error((data && data.error) || ('HTTP ' + r.status));
    return data;
  }

  function fmtTime(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleTimeString(); }
    catch (_) { return iso; }
  }

  function shortId(id) { return id ? id.slice(0, 12) : '—'; }

  function elapsedSince(iso) {
    if (!iso) return '—';
    try {
      const t0 = new Date(iso).getTime();
      const s  = Math.max(0, Math.floor((Date.now() - t0) / 1000));
      const m  = Math.floor(s / 60);
      const r  = s % 60;
      return m ? `${m}m ${String(r).padStart(2,'0')}s` : `${s}s`;
    } catch (_) { return '—'; }
  }

  /* ══════════════════════════════════════════════════════════════════
   *  SHARK-THEMED CSS — matches app-ex3bve.js palette
   * ══════════════════════════════════════════════════════════════════ */
  const CSS = `
  .mhd-root {
    --mhd-red:        #dc2626;
    --mhd-red-2:      #b91c1c;
    --mhd-red-3:      #7f1d1d;
    --mhd-red-line:   rgba(220,38,38,.32);
    --mhd-border:     rgba(148,163,184,.14);
    --mhd-border-red: rgba(220,38,38,.25);
    --mhd-white:      #f8fafc;
    --mhd-text:       #e2e8f0;
    --mhd-muted:      #94a3b8;
    --mhd-muted-2:    #64748b;
    display: flex; flex-direction: column; gap: 16px;
    font-family: var(--font-ui, 'Inter','Space Grotesk',system-ui,sans-serif);
    color: var(--mhd-text);
  }

  /* ═══ Header ═══ */
  .mhd-header {
    position: relative;
    background:
      radial-gradient(ellipse at 12% 100%, rgba(220,38,38,.20), transparent 55%),
      radial-gradient(ellipse at 90% 0%,   rgba(30,58,138,.22),  transparent 55%),
      linear-gradient(135deg, #0a1122 0%, #0b0715 55%, #150404 100%);
    border: 1px solid var(--mhd-border-red);
    border-radius: 16px;
    padding: 20px 24px;
    display: flex; align-items: center; gap: 20px;
    overflow: hidden;
    box-shadow:
      inset 0 1px 0 rgba(255,255,255,.05),
      0 10px 30px rgba(0,0,0,.45),
      0 2px 8px rgba(220,38,38,.12);
  }
  .mhd-header::before {
    content: "";
    position: absolute; inset: 0;
    background-image:
      repeating-radial-gradient(circle at 15% 100%,
        rgba(220,38,38,.06) 0 12px, transparent 12px 40px),
      repeating-linear-gradient(115deg,
        rgba(255,255,255,.018) 0 2px, transparent 2px 12px);
    opacity: .8; pointer-events: none;
  }
  .mhd-header::after {
    content: "";
    position: absolute; left: 0; right: 0; bottom: 0; height: 12px;
    background-image:
      linear-gradient(135deg, transparent 50%, rgba(220,38,38,.35) 50%),
      linear-gradient(45deg, rgba(220,38,38,.35) 50%, transparent 50%);
    background-size: 12px 12px;
    background-repeat: repeat-x;
    opacity: .28; pointer-events: none;
  }
  .mhd-header svg.mhd-shark {
    width: 130px; height: 82px; flex-shrink: 0;
    filter: drop-shadow(0 10px 20px rgba(220,38,38,.32));
    animation: mhdCruise 8s ease-in-out infinite;
    position: relative; z-index: 1;
  }
  @keyframes mhdCruise {
    0%, 100% { transform: translateX(0) rotate(-2deg); }
    50%      { transform: translateX(6px) rotate(1deg); }
  }
  .mhd-header-copy { flex: 1; min-width: 0; position: relative; z-index: 1; }
  .mhd-eyebrow {
    display: inline-flex; align-items: center; gap: 8px;
    font-size: .62rem; letter-spacing: .18em; text-transform: uppercase;
    font-weight: 800; color: #fca5a5;
    margin-bottom: 5px;
  }
  .mhd-eyebrow::before {
    content: ""; width: 20px; height: 2px;
    background: linear-gradient(90deg, var(--mhd-red), transparent);
    border-radius: 2px;
  }
  .mhd-title {
    font-size: 1.24rem; font-weight: 800; letter-spacing: -.02em;
    color: var(--mhd-white); margin: 0 0 5px; line-height: 1.15;
  }
  .mhd-title .mhd-title-red {
    background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
    -webkit-background-clip: text; background-clip: text;
    color: transparent;
  }
  .mhd-subtitle {
    color: var(--mhd-muted);
    font-size: .78rem; line-height: 1.55; margin: 0; max-width: 78ch;
  }
  .mhd-subtitle b {
    color: var(--mhd-white);
    font-family: var(--font-mono, ui-monospace, monospace);
    font-weight: 600;
  }

  /* ═══ Live status pill ═══ */
  .mhd-live-pill {
    display: inline-flex; align-items: center; gap: 7px;
    padding: 5px 12px; border-radius: 99px;
    background: linear-gradient(135deg, rgba(220,38,38,.18), rgba(220,38,38,.06));
    color: #f87171;
    font-size: .64rem; font-weight: 800;
    letter-spacing: .07em; text-transform: uppercase;
    border: 1px solid rgba(220,38,38,.4);
    flex-shrink: 0;
    position: relative; z-index: 1;
  }
  .mhd-live-pill.idle {
    background: linear-gradient(135deg, rgba(148,163,184,.14), rgba(148,163,184,.04));
    color: var(--mhd-muted); border-color: var(--mhd-border);
  }
  .mhd-live-pill .dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: #ef4444;
    box-shadow: 0 0 0 0 rgba(239,68,68,.8);
    animation: mhdLivePulse 1.5s ease-out infinite;
  }
  .mhd-live-pill.idle .dot {
    background: var(--mhd-muted);
    animation: none;
    box-shadow: none;
  }
  @keyframes mhdLivePulse {
    0%   { box-shadow: 0 0 0 0 rgba(239,68,68,.8); }
    70%  { box-shadow: 0 0 0 8px rgba(239,68,68,0); }
    100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
  }

  /* ═══ Cards ═══ */
  .mhd-card {
    background: linear-gradient(165deg, #0b1220 0%, #050a16 100%);
    border: 1px solid var(--mhd-border);
    border-radius: 13px;
    padding: 18px 20px;
    position: relative; overflow: hidden;
    transition: border-color .18s, box-shadow .18s, transform .18s;
  }
  .mhd-card::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, var(--mhd-red) 0%, transparent 55%);
    opacity: .55;
  }
  .mhd-card:hover {
    border-color: var(--mhd-border-red);
    box-shadow: 0 8px 24px rgba(0,0,0,.42);
    transform: translateY(-1px);
  }
  .mhd-card h4 {
    margin: 0 0 14px;
    font-size: .78rem; font-weight: 800;
    letter-spacing: .09em; text-transform: uppercase;
    color: var(--mhd-white);
    display: flex; align-items: center; gap: 10px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--mhd-border);
    flex-wrap: wrap;
  }
  .mhd-card h4 i {
    width: 28px; height: 28px;
    display: flex; align-items: center; justify-content: center;
    font-size: .82rem; border-radius: 8px;
    background: linear-gradient(135deg, var(--mhd-red), var(--mhd-red-3));
    color: #fff;
    box-shadow: 0 3px 12px rgba(220,38,38,.4);
    flex-shrink: 0;
  }
  .mhd-card h4 .mhd-hint {
    margin-left: auto;
    font-size: .66rem; font-weight: 600;
    letter-spacing: 0; text-transform: none;
    color: var(--mhd-muted);
    font-family: var(--font-mono, monospace);
  }

  /* ═══ Layout rows ═══ */
  .mhd-row { display: flex; gap: 10px; flex-wrap: wrap; }
  .mhd-row > * { flex: 1 1 160px; min-width: 0; }
  .mhd-row.tight > * { flex: 0 0 auto; }

  .mhd-field { display: flex; flex-direction: column; gap: 6px; }
  .mhd-field > label {
    font-size: .64rem; font-weight: 700;
    letter-spacing: .06em; text-transform: uppercase;
    color: var(--mhd-muted);
  }
  .mhd-field > input,
  .mhd-field > select {
    background: linear-gradient(180deg, #060a15, #0a1122);
    border: 1px solid var(--mhd-border);
    border-radius: 8px;
    padding: 10px 12px;
    color: var(--mhd-white);
    font-size: .85rem;
    font-family: var(--font-mono, ui-monospace, monospace);
    outline: none;
    transition: border-color .18s, box-shadow .18s;
    -webkit-appearance: none; appearance: none;
    width: 100%;
  }
  .mhd-field > input:focus,
  .mhd-field > select:focus {
    border-color: var(--mhd-red);
    box-shadow: 0 0 0 3px rgba(220,38,38,.18);
  }
  .mhd-field > input::placeholder { color: rgba(148,163,184,.5); }

  /* ═══ Quick presets ═══ */
  .mhd-presets {
    display: flex; flex-wrap: wrap; gap: 8px;
    margin-bottom: 14px;
  }
  .mhd-preset {
    padding: 8px 14px; border-radius: 8px;
    border: 1px solid var(--mhd-border);
    background: linear-gradient(180deg, #0a1122, #06090f);
    color: var(--mhd-muted);
    font-family: inherit; font-size: .72rem; font-weight: 700;
    letter-spacing: .02em;
    cursor: pointer;
    display: inline-flex; align-items: center; gap: 7px;
    transition: all .16s;
    -webkit-appearance: none; appearance: none;
  }
  .mhd-preset:hover {
    border-color: var(--mhd-red);
    color: var(--mhd-white);
    background: linear-gradient(180deg, rgba(220,38,38,.08), rgba(220,38,38,.02));
    transform: translateY(-1px);
  }
  .mhd-preset i { color: var(--mhd-red); font-size: .78rem; }

  /* ═══ Method groups ═══ */
  .mhd-method-groups { display: flex; gap: 14px; flex-wrap: wrap; }
  .mhd-method-groups > div { flex: 1 1 240px; min-width: 0; }
  .mhd-method-groups h5 {
    margin: 0 0 8px;
    font-size: .64rem; font-weight: 800;
    letter-spacing: .09em; text-transform: uppercase;
    color: var(--mhd-muted);
    display: flex; align-items: center; gap: 7px;
  }
  .mhd-method-groups h5::before {
    content: ""; width: 3px; height: 12px;
    background: linear-gradient(180deg, var(--mhd-red), transparent);
    border-radius: 2px;
  }
  .mhd-chips {
    display: flex; flex-wrap: wrap; gap: 5px;
    max-height: 190px; overflow-y: auto;
    padding: 2px 4px 4px 2px;
    scrollbar-width: thin;
    scrollbar-color: rgba(220,38,38,.4) transparent;
  }
  .mhd-chips::-webkit-scrollbar { width: 6px; }
  .mhd-chips::-webkit-scrollbar-thumb { background: rgba(220,38,38,.35); border-radius: 3px; }

  .mhd-chip {
    padding: 5px 10px;
    border-radius: 6px;
    border: 1px solid var(--mhd-border);
    background: linear-gradient(180deg, #0a1122, #06090f);
    color: var(--mhd-muted);
    font-family: var(--font-mono, monospace);
    font-size: .7rem; font-weight: 600;
    cursor: pointer;
    transition: all .14s;
    -webkit-appearance: none; appearance: none;
  }
  .mhd-chip:hover {
    border-color: var(--mhd-red);
    color: var(--mhd-white);
    transform: translateY(-1px);
  }
  .mhd-chip.active {
    background: linear-gradient(135deg, var(--mhd-red), var(--mhd-red-3));
    border-color: transparent;
    color: #fff;
    box-shadow: 0 3px 12px rgba(220,38,38,.4);
  }

  /* ═══ Buttons ═══ */
  .mhd-actions {
    display: flex; gap: 10px; flex-wrap: wrap; margin-top: 16px;
  }
  .mhd-btn {
    flex: 1 1 160px;
    padding: 11px 18px; border-radius: 9px;
    border: 1px solid transparent;
    font-weight: 700; font-size: .82rem;
    cursor: pointer;
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    transition: all .16s cubic-bezier(.4,0,.2,1);
    -webkit-appearance: none; appearance: none;
    white-space: nowrap; font-family: inherit;
    position: relative;
  }
  .mhd-btn:active { transform: scale(.98); }
  .mhd-btn[disabled] { opacity: .5; cursor: not-allowed; transform: none !important; }

  .mhd-btn-primary {
    background: linear-gradient(135deg, var(--mhd-red), var(--mhd-red-3));
    color: #fff;
    box-shadow: 0 4px 14px rgba(220,38,38,.36);
  }
  .mhd-btn-primary:hover:not([disabled]) {
    transform: translateY(-2px);
    box-shadow: 0 10px 28px rgba(220,38,38,.55);
    filter: brightness(1.06);
  }

  .mhd-btn-danger {
    background: linear-gradient(135deg, #7f1d1d, #450a0a);
    color: #fca5a5;
    border-color: rgba(239,68,68,.35);
    box-shadow: 0 4px 14px rgba(239,68,68,.2);
  }
  .mhd-btn-danger:hover:not([disabled]) {
    transform: translateY(-2px);
    background: linear-gradient(135deg, #991b1b, #7f1d1d);
    color: #fff;
  }

  .mhd-btn-ghost {
    background: linear-gradient(180deg, #0a1122, #06090f);
    border-color: var(--mhd-border);
    color: var(--mhd-muted);
  }
  .mhd-btn-ghost:hover:not([disabled]) {
    border-color: var(--mhd-red);
    color: var(--mhd-white);
    background: linear-gradient(180deg, rgba(220,38,38,.08), rgba(220,38,38,.02));
  }

  /* ═══ Tables ═══ */
  .mhd-table {
    width: 100%; border-collapse: collapse; font-size: .76rem;
    border-radius: 10px; overflow: hidden;
  }
  .mhd-table th,
  .mhd-table td {
    text-align: left; padding: 9px 11px;
    border-bottom: 1px solid var(--mhd-border);
    vertical-align: middle;
  }
  .mhd-table th {
    font-size: .62rem; letter-spacing: .07em; text-transform: uppercase;
    color: var(--mhd-muted); font-weight: 800;
    background: linear-gradient(180deg, rgba(220,38,38,.06), transparent);
  }
  .mhd-table tr:last-child td { border-bottom: none; }
  .mhd-table tbody tr {
    transition: background .14s;
  }
  .mhd-table tbody tr:hover {
    background: linear-gradient(90deg, rgba(220,38,38,.06), transparent);
  }
  .mhd-table code {
    font-family: var(--font-mono, monospace);
    font-size: .72rem; color: #cbd5e1;
    word-break: break-all;
  }

  /* ═══ Status badges ═══ */
  .mhd-badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 3px 9px; border-radius: 99px;
    font-size: .62rem; font-weight: 800;
    letter-spacing: .06em; text-transform: uppercase;
    border: 1px solid;
  }
  .mhd-badge::before {
    content: ""; width: 6px; height: 6px; border-radius: 50%;
  }
  .mhd-badge-running  { background: rgba(34,197,94,.14); color:#4ade80; border-color: rgba(34,197,94,.4); }
  .mhd-badge-running::before  { background: #22c55e; animation: mhdBlink 1.2s ease-in-out infinite; }
  .mhd-badge-stopped  { background: rgba(148,163,184,.12); color:#94a3b8; border-color: rgba(148,163,184,.25); }
  .mhd-badge-stopped::before  { background: #94a3b8; }
  .mhd-badge-failed   { background: rgba(220,38,38,.18); color:#f87171; border-color: rgba(220,38,38,.4); }
  .mhd-badge-failed::before   { background: #dc2626; }
  .mhd-badge-done     { background: rgba(59,130,246,.16); color:#60a5fa; border-color: rgba(59,130,246,.4); }
  .mhd-badge-done::before     { background: #3b82f6; }
  .mhd-badge-timeout  { background: rgba(245,158,11,.16); color:#fbbf24; border-color: rgba(245,158,11,.4); }
  .mhd-badge-timeout::before  { background: #f59e0b; }
  @keyframes mhdBlink {
    0%, 100% { opacity: 1; }
    50%      { opacity: .3; }
  }

  /* ═══ Empty state ═══ */
  .mhd-empty {
    padding: 26px 16px; text-align: center;
    color: var(--mhd-muted); font-size: .82rem; font-style: italic;
    display: flex; flex-direction: column; gap: 10px; align-items: center;
  }
  .mhd-empty svg {
    width: 52px; height: 40px; opacity: .35;
    filter: drop-shadow(0 4px 12px rgba(220,38,38,.35));
  }

  /* ═══ Small inline stop button in tables ═══ */
  .mhd-btn-mini {
    padding: 5px 11px; border-radius: 7px;
    border: 1px solid var(--mhd-border);
    background: linear-gradient(180deg, #0a1122, #06090f);
    color: var(--mhd-muted);
    font-family: inherit;
    font-size: .68rem; font-weight: 700;
    letter-spacing: .04em; text-transform: uppercase;
    cursor: pointer;
    display: inline-flex; align-items: center; gap: 5px;
    transition: all .14s;
    -webkit-appearance: none; appearance: none;
  }
  .mhd-btn-mini:hover:not([disabled]) {
    border-color: var(--mhd-red);
    color: #f87171;
    background: linear-gradient(180deg, rgba(220,38,38,.10), rgba(220,38,38,.02));
  }
  .mhd-btn-mini[disabled] { opacity: .5; cursor: not-allowed; }

  /* ═════════════════════════════════════════════════════════════════
     SIDEBAR NAV — NEUTRAL BY DEFAULT, RED ONLY ON HOVER / ACTIVE
     (matches app-ex3bve.js — no always-on red dot / red tint)
     ═════════════════════════════════════════════════════════════════ */
  .nav-item[data-section="mhddos"]:hover {
    background: linear-gradient(90deg, rgba(220,38,38,.16), transparent 75%) !important;
    border-left-color: #dc2626 !important;
    color: #fff !important;
  }
  .nav-item[data-section="mhddos"]:hover i {
    color: #ef4444 !important;
  }
  .nav-item[data-section="mhddos"].active {
    background: linear-gradient(90deg, rgba(220,38,38,.38), rgba(220,38,38,.08) 75%, transparent) !important;
    border-left-color: #ef4444 !important;
    color: #fff !important;
    font-weight: 700 !important;
  }
  .nav-item[data-section="mhddos"].active i {
    color: #fff !important;
    filter: drop-shadow(0 0 6px rgba(239,68,68,.75));
  }
  .content-section.active#section-mhddos .panel-title i {
    color: #ef4444 !important;
    background: linear-gradient(135deg, rgba(220,38,38,.22), rgba(127,29,29,.12)) !important;
    box-shadow: inset 0 0 0 1px rgba(220,38,38,.3);
  }

  /* ═══ Responsive ═══ */
  @media (max-width: 780px) {
    .mhd-header { flex-direction: column; align-items: flex-start; padding: 18px; gap: 14px; }
    .mhd-header svg.mhd-shark { width: 110px; height: 70px; }
    .mhd-title { font-size: 1.1rem; }
    .mhd-row > * { flex: 1 1 100%; }
    .mhd-actions .mhd-btn { flex: 1 1 100%; }
  }
  `;

  function injectCSS() {
    if (document.getElementById('mhd-css')) return;
    const style = document.createElement('style');
    style.id = 'mhd-css';
    style.textContent = CSS;
    document.head.appendChild(style);
  }

  /* ── Shark SVG (matching the Exploit Suite) ──────────────────────── */
  function sharkSVG() {
    return el('svg', {
      class: 'mhd-shark',
      viewBox: '0 0 240 140',
      xmlns: 'http://www.w3.org/2000/svg',
      'aria-hidden': 'true',
    }, el('svg', {
      html: `
        <defs>
          <linearGradient id="mhdBodyGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#334155"/>
            <stop offset="0.55" stop-color="#1e293b"/>
            <stop offset="1" stop-color="#0f172a"/>
          </linearGradient>
          <linearGradient id="mhdBellyGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#e2e8f0"/>
            <stop offset="1" stop-color="#94a3b8"/>
          </linearGradient>
          <linearGradient id="mhdFinGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#f87171"/>
            <stop offset="0.55" stop-color="#dc2626"/>
            <stop offset="1" stop-color="#7f1d1d"/>
          </linearGradient>
          <radialGradient id="mhdEyeGlow" cx="0.5" cy="0.5" r="0.5">
            <stop offset="0" stop-color="#f8fafc"/>
            <stop offset="1" stop-color="#020617"/>
          </radialGradient>
          <filter id="mhdSoftGlow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="3" result="b"/>
            <feMerge>
              <feMergeNode in="b"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>

        <path d="M0 118 Q60 110 120 118 T240 118" fill="none"
              stroke="#1e40af" stroke-width="1.4" stroke-opacity="0.35" stroke-linecap="round"/>
        <path d="M12 126 Q72 120 132 126 T252 126" fill="none"
              stroke="#1e40af" stroke-width="1" stroke-opacity="0.2" stroke-linecap="round"/>

        <path d="M18 100 L2 118 L32 112 L26 100 Z"
              fill="url(#mhdFinGrad)" stroke="#7f1d1d" stroke-width="1"/>

        <path d="M22 96 Q60 78 110 76 Q170 74 214 92 L222 100
                 Q170 118 110 112 Q60 106 22 96 Z"
              fill="url(#mhdBodyGrad)" stroke="#0f172a" stroke-width="1.4"/>

        <path d="M40 100 Q90 110 150 108 Q190 106 214 100 L206 100
                 Q160 108 110 108 Q70 106 40 100 Z"
              fill="url(#mhdBellyGrad)" opacity="0.85"/>

        <path d="M108 74 L138 22 L152 74 Q128 66 108 74 Z"
              fill="url(#mhdFinGrad)" stroke="#7f1d1d" stroke-width="1.4"
              filter="url(#mhdSoftGlow)"/>

        <path d="M154 78 L168 62 L176 80 Q164 76 154 78 Z"
              fill="url(#mhdFinGrad)" opacity="0.85"/>

        <path d="M112 108 L96 132 L128 118 Z"
              fill="url(#mhdFinGrad)" opacity="0.9"/>

        <g stroke="#dc2626" stroke-width="1.6" stroke-linecap="round" opacity="0.85">
          <path d="M152 84 L150 100"/>
          <path d="M160 83 L158 100"/>
          <path d="M168 82 L166 100"/>
        </g>

        <circle cx="200" cy="90" r="3.4" fill="url(#mhdEyeGlow)"/>
        <circle cx="200" cy="90" r="1.1" fill="#020617"/>

        <g fill="#f8fafc" opacity="0.9">
          <path d="M196 99 L198 104 L200 99 Z"/>
          <path d="M201 99 L203 105 L205 99 Z"/>
          <path d="M206 99 L208 104 L210 99 Z"/>
          <path d="M211 99 L213 104 L215 99 Z"/>
        </g>

        <path d="M192 98 Q204 104 216 99" fill="none"
              stroke="#7f1d1d" stroke-width="1.4" stroke-linecap="round"/>
      `,
    }));
  }

  function emptyState(text) {
    const wrap = el('div', { class: 'mhd-empty' });
    wrap.innerHTML = `
      <svg viewBox="0 0 120 90" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <defs>
          <linearGradient id="mhdEmptyFin" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#f87171"/>
            <stop offset="1" stop-color="#7f1d1d"/>
          </linearGradient>
        </defs>
        <path d="M14 66 Q46 54 78 58 L108 34 L100 58 L118 74 L86 72 Q46 82 14 66 Z"
              fill="#1e293b" stroke="#dc2626" stroke-width="1" stroke-opacity="0.55"/>
        <path d="M62 30 L78 6 L84 32 Q72 28 62 30 Z" fill="url(#mhdEmptyFin)"/>
        <path d="M20 62 L12 78 L32 72 L20 62 Z" fill="url(#mhdEmptyFin)" opacity="0.85"/>
        <circle cx="42" cy="64" r="1.8" fill="#f8fafc"/>
      </svg>
    `;
    if (text) wrap.appendChild(el('span', null, text));
    return wrap;
  }

  /* ── Presets ─────────────────────────────────────────────────────── */
  const PRESETS = {
    recon: {
      label: 'Recon', icon: 'fa-eye',
      config: { threads: 5, duration: 30, proxy_type: 0, rpc: 1 },
    },
    stress: {
      label: 'Stress', icon: 'fa-fire',
      config: { threads: 100, duration: 120, proxy_type: 0, rpc: 1 },
    },
    udp: {
      label: 'UDP Flood', icon: 'fa-wave-square',
      config: { threads: 200, duration: 180, proxy_type: 0, rpc: 1 },
    },
    mixed: {
      label: 'Mixed', icon: 'fa-shuffle',
      config: { threads: 250, duration: 300, proxy_type: 1, rpc: 2 },
    },
  };

  /* ── DOM builder ─────────────────────────────────────────────────── */
  function buildUI() {
    const selectedMethod = { value: '' };

    /* Header */
    const livePill = el('span', { class: 'mhd-live-pill idle' },
      el('span', { class: 'dot' }),
      el('span', { class: 'mhd-live-text' }, 'Idle'),
    );
    const header = el('div', { class: 'mhd-header' },
      sharkSVG(),
      el('div', { class: 'mhd-header-copy' },
        el('div', { class: 'mhd-eyebrow' }, 'Predator Mode'),
        el('h3', { class: 'mhd-title' },
          'MHDDoS ',
          el('span', { class: 'mhd-title-red' }, 'Control'),
        ),
        el('p', { class: 'mhd-subtitle' },
          'Real-time DDoS engine — ',
          el('b', null, 'authorised targets only'),
          '. Every attack is cancellable, rate-limited, and streamed to the console.',
        ),
      ),
      livePill,
    );

    /* Preset row */
    const presetRow = el('div', { class: 'mhd-presets' });
    Object.entries(PRESETS).forEach(([key, p]) => {
      const btn = el('button', { class: 'mhd-preset', type: 'button', 'data-preset': key },
        el('i', { class: 'fas ' + p.icon }),
        p.label,
      );
      presetRow.appendChild(btn);
    });

    /* Method select + chips */
    const methodSelect = el('select', { id: 'mhdMethodSelect' },
      el('option', { value: '' }, 'Select a method…')
    );

    const l7chips = el('div', { class: 'mhd-chips', id: 'mhdL7Chips' });
    const l4chips = el('div', { class: 'mhd-chips', id: 'mhdL4Chips' });
    const chipGroups = el('div', { class: 'mhd-method-groups' },
      el('div', null,
        el('h5', null, 'Layer 7'),
        l7chips,
      ),
      el('div', null,
        el('h5', null, 'Layer 4'),
        l4chips,
      ),
    );

    /* Config inputs */
    const targetInput      = el('input', { type: 'text',   id: 'mhdTarget',     placeholder: 'https://example.com or 1.2.3.4:80', autocomplete: 'off' });
    const threadsInput     = el('input', { type: 'number', id: 'mhdThreads',    value: '10',  min: '1', max: '1000' });
    const durationInput    = el('input', { type: 'number', id: 'mhdDuration',   value: '60',  min: '1', max: '3600' });
    const proxyTypeInput   = el('input', { type: 'number', id: 'mhdProxyType',  value: '0',   min: '0', max: '5' });
    const proxyFileInput   = el('input', { type: 'text',   id: 'mhdProxyFile',  value: 'proxies.txt' });
    const rpcInput         = el('input', { type: 'number', id: 'mhdRpc',        value: '1',   min: '1', max: '5' });
    const reflectorInput   = el('input', { type: 'text',   id: 'mhdReflector',  placeholder: 'reflectors.txt (AMP only)' });

    /* Buttons */
    const startBtn = el('button', { class: 'mhd-btn mhd-btn-primary', id: 'mhdStartBtn' },
      el('i', { class: 'fas fa-rocket' }), 'Launch Attack');
    const stopAllBtn = el('button', { class: 'mhd-btn mhd-btn-danger', id: 'mhdStopAllBtn' },
      el('i', { class: 'fas fa-hand' }), 'Stop All');

    /* Tables */
    const runningTableBody = el('tbody', { id: 'mhdRunningBody' });
    const historyTableBody = el('tbody', { id: 'mhdHistoryBody' });

    /* Assemble root */
    const root = el('div', { class: 'mhd-root' },

      header,

      /* ── Attack Configuration ─────────────────────────────── */
      el('div', { class: 'mhd-card' },
        el('h4', null,
          el('i', { class: 'fas fa-bullseye' }),
          'Attack Configuration',
          el('span', { class: 'mhd-hint' }, 'all fields optional except target + method'),
        ),

        presetRow,

        el('div', { class: 'mhd-row', style: 'margin-bottom:12px;' },
          el('div', { class: 'mhd-field', style: 'flex:2 1 260px;' },
            el('label', null, 'Target'),
            targetInput,
          ),
          el('div', { class: 'mhd-field', style: 'flex:1 1 160px;' },
            el('label', null, 'Method'),
            methodSelect,
          ),
        ),

        chipGroups,

        el('div', { class: 'mhd-row', style: 'margin-top:14px;' },
          el('div', { class: 'mhd-field' }, el('label', null, 'Threads'),     threadsInput),
          el('div', { class: 'mhd-field' }, el('label', null, 'Duration (s)'), durationInput),
          el('div', { class: 'mhd-field' }, el('label', null, 'Proxy type'),  proxyTypeInput),
          el('div', { class: 'mhd-field' }, el('label', null, 'RPC'),         rpcInput),
        ),
        el('div', { class: 'mhd-row', style: 'margin-top:12px;' },
          el('div', { class: 'mhd-field', style: 'flex:2 1 220px;' },
            el('label', null, 'Proxy file'),
            proxyFileInput,
          ),
          el('div', { class: 'mhd-field', style: 'flex:2 1 220px;' },
            el('label', null, 'Reflector file'),
            reflectorInput,
          ),
        ),

        el('div', { class: 'mhd-actions' }, startBtn, stopAllBtn),
      ),

      /* ── Running Attacks ──────────────────────────────────── */
      el('div', { class: 'mhd-card' },
        el('h4', null,
          el('i', { class: 'fas fa-tower-broadcast' }),
          'Running Attacks',
          el('span', { class: 'mhd-hint mhd-running-count' }, '0 active'),
        ),
        el('div', { style: 'overflow-x:auto;' },
          el('table', { class: 'mhd-table' },
            el('thead', null,
              el('tr', null,
                el('th', null, 'ID'),
                el('th', null, 'Method'),
                el('th', null, 'Target'),
                el('th', null, 'Threads'),
                el('th', null, 'Duration'),
                el('th', null, 'Elapsed'),
                el('th', null, 'Status'),
                el('th', null, ''),
              ),
            ),
            runningTableBody,
          ),
        ),
      ),

      /* ── Recent History ───────────────────────────────────── */
      el('div', { class: 'mhd-card' },
        el('h4', null,
          el('i', { class: 'fas fa-clock-rotate-left' }),
          'Recent History',
          el('span', { class: 'mhd-hint' }, 'last 25 attacks'),
        ),
        el('div', { style: 'overflow-x:auto;' },
          el('table', { class: 'mhd-table' },
            el('thead', null,
              el('tr', null,
                el('th', null, 'ID'),
                el('th', null, 'Method'),
                el('th', null, 'Target'),
                el('th', null, 'Started'),
                el('th', null, 'Status'),
              ),
            ),
            historyTableBody,
          ),
        ),
      ),
    );

    /* ── Event wiring ──────────────────────────────────────────────── */
    function pickMethod(name) {
      selectedMethod.value = name;
      methodSelect.value = name;
      $$('.mhd-chip', root).forEach(c => {
        c.classList.toggle('active', c.dataset.method === name);
      });
    }

    methodSelect.addEventListener('change', () => pickMethod(methodSelect.value));

    const renderChips = () => {
      l7chips.innerHTML = '';
      l4chips.innerHTML = '';
      (state.layer7 || []).forEach(name => {
        const chip = el('button', { class: 'mhd-chip', type: 'button', 'data-method': name }, name);
        chip.addEventListener('click', () => pickMethod(name));
        l7chips.appendChild(chip);
      });
      (state.layer4 || []).forEach(name => {
        const chip = el('button', { class: 'mhd-chip', type: 'button', 'data-method': name }, name);
        chip.addEventListener('click', () => pickMethod(name));
        l4chips.appendChild(chip);
      });
    };

    /* Presets */
    presetRow.addEventListener('click', (e) => {
      const btn = e.target.closest('.mhd-preset');
      if (!btn) return;
      const key = btn.dataset.preset;
      const cfg = PRESETS[key] && PRESETS[key].config;
      if (!cfg) return;
      if (cfg.threads  != null) threadsInput.value  = String(cfg.threads);
      if (cfg.duration != null) durationInput.value = String(cfg.duration);
      if (cfg.proxy_type != null) proxyTypeInput.value = String(cfg.proxy_type);
      if (cfg.rpc != null)      rpcInput.value = String(cfg.rpc);
      toast(`Preset "${PRESETS[key].label}" applied`, 'ok');
    });

    /* Launch */
    startBtn.addEventListener('click', async () => {
      if (state.busy) return;
      const method = (selectedMethod.value || methodSelect.value || '').trim().toUpperCase();
      const target = targetInput.value.trim();
      if (!method) { toast('Pick a method first', 'warn'); return; }
      if (!target) { toast('Enter a target', 'warn'); return; }
      state.busy = true;
      startBtn.disabled = true;
      startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Launching…';
      try {
        const payload = {
          method,
          target,
          threads:        parseInt(threadsInput.value, 10)   || 10,
          duration:       parseInt(durationInput.value, 10)  || 60,
          proxy_type:     parseInt(proxyTypeInput.value, 10) || 0,
          proxy_file:     proxyFileInput.value.trim() || 'proxies.txt',
          rpc:            parseInt(rpcInput.value, 10)       || 1,
          reflector_file: reflectorInput.value.trim(),
        };
        const res = await jpost(API.start, payload);
        if (res.success) {
          toast(`Attack ${shortId(res.attack_id)} launched`, 'ok');
          await refresh();
        } else {
          toast(res.error || 'Launch failed', 'err');
        }
      } catch (e) {
        toast('Launch failed: ' + e.message, 'err');
      } finally {
        state.busy = false;
        startBtn.disabled = false;
        startBtn.innerHTML = '<i class="fas fa-rocket"></i> Launch Attack';
      }
    });

    /* Stop All */
    stopAllBtn.addEventListener('click', async () => {
      if (!confirm('Stop every running attack?')) return;
      try {
        const r = await jpost(API.stopAll, {});
        toast(`Stopped ${r.stopped || 0} attack(s)`, 'ok');
        await refresh();
      } catch (e) {
        toast('Stop all failed: ' + e.message, 'err');
      }
    });

    root._refs = {
      runningTableBody,
      historyTableBody,
      runningCount: root.querySelector('.mhd-running-count'),
      livePill,
      liveText: root.querySelector('.mhd-live-text'),
      renderChips,
      methodSelect,
      pickMethod,
    };
    return root;
  }

  /* ── Rendering ───────────────────────────────────────────────────── */
  function statusBadge(status) {
    const cls = {
      running:  'mhd-badge-running',
      stopped:  'mhd-badge-stopped',
      failed:   'mhd-badge-failed',
      completed:'mhd-badge-done',
      done:     'mhd-badge-done',
      timeout:  'mhd-badge-timeout',
    }[status] || 'mhd-badge-stopped';
    return el('span', { class: 'mhd-badge ' + cls }, status || 'unknown');
  }

  function updateLivePill(refs) {
    if (!refs || !refs.livePill) return;
    const n = (state.running || []).length;
    if (n > 0) {
      refs.livePill.classList.remove('idle');
      if (refs.liveText) refs.liveText.textContent = `${n} running`;
    } else {
      refs.livePill.classList.add('idle');
      if (refs.liveText) refs.liveText.textContent = 'Idle';
    }
  }

  function renderRunning(root) {
    const tbody = root._refs.runningTableBody;
    const refs  = root._refs;
    tbody.innerHTML = '';

    if (refs.runningCount) {
      const n = (state.running || []).length;
      refs.runningCount.textContent = n ? `${n} active` : '0 active';
    }

    if (!state.running.length) {
      tbody.appendChild(el('tr', null,
        el('td', { colspan: '8' }, emptyState('No attacks running'))));
      return;
    }

    for (const atk of state.running) {
      const stopBtn = el('button', {
        class: 'mhd-btn-mini', type: 'button', title: 'Stop this attack',
      }, el('i', { class: 'fas fa-stop' }), 'Stop');
      stopBtn.addEventListener('click', async () => {
        stopBtn.disabled = true;
        stopBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        try {
          await jpost(API.stop, { attack_id: atk.attack_id });
          toast(`Stopped ${shortId(atk.attack_id)}`, 'ok');
          await refresh();
        } catch (e) {
          toast('Stop failed: ' + e.message, 'err');
          stopBtn.disabled = false;
          stopBtn.innerHTML = '<i class="fas fa-stop"></i> Stop';
        }
      });

      tbody.appendChild(el('tr', null,
        el('td', null, el('code', null, shortId(atk.attack_id))),
        el('td', null, el('code', null, atk.method || '—')),
        el('td', null, el('code', null, atk.target || '—')),
        el('td', null, String(atk.threads ?? '—')),
        el('td', null, (atk.duration ?? '—') + 's'),
        el('td', null, elapsedSince(atk.started_at)),
        el('td', null, statusBadge(atk.status)),
        el('td', null, stopBtn),
      ));
    }
  }

  function renderHistory(root) {
    const tbody = root._refs.historyTableBody;
    tbody.innerHTML = '';

    if (!state.history.length) {
      tbody.appendChild(el('tr', null,
        el('td', { colspan: '5' }, emptyState('No history yet'))));
      return;
    }

    for (const entry of state.history.slice(-25).reverse()) {
      tbody.appendChild(el('tr', null,
        el('td', null, el('code', null, shortId(entry.attack_id))),
        el('td', null, el('code', null, entry.method || '—')),
        el('td', null, el('code', null, entry.target || '—')),
        el('td', null, fmtTime(entry.started_at)),
        el('td', null, statusBadge(entry.status)),
      ));
    }
  }

  /* ── Polling ─────────────────────────────────────────────────────── */
  function startPolling() {
    stopPolling();
    state.pollTimer = setInterval(refresh, POLL_MS);
  }
  function stopPolling() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  async function refresh() {
    if (!state.mounted) return;
    try {
      const data = await jget(API.status);
      state.running = data.running || [];
      state.history = data.history || [];

      if (data.methods) {
        const changed = state.methods.length !== data.methods.length;
        state.methods = data.methods || [];
        state.layer7  = data.layer7  || [];
        state.layer4  = data.layer4  || [];

        if (changed && state.mountEl) {
          const root = state.mountEl.querySelector('.mhd-root');
          if (root && root._refs) {
            const sel  = root._refs.methodSelect;
            const prev = sel.value;
            sel.innerHTML = '<option value="">Select a method…</option>';
            state.methods.forEach(m => sel.appendChild(el('option', { value: m }, m)));
            sel.value = prev;
            root._refs.renderChips();
          }
        }
      }

      const root = state.mountEl && state.mountEl.querySelector('.mhd-root');
      if (root) {
        renderRunning(root);
        renderHistory(root);
        updateLivePill(root._refs);
      }
    } catch (_) {
      /* silent — polling runs often */
    }
  }

  /* ── Mount / unmount ─────────────────────────────────────────────── */
  function mount(target) {
    if (state.mounted) unmount();
    injectCSS();

    let elMount = null;
    if (typeof target === 'string') elMount = document.querySelector(target);
    else if (target instanceof Element) elMount = target;
    else elMount = document.querySelector('[data-emergens-panel="mhddos"]');

    if (!elMount) {
      console.warn('[MHDDoSControl] no mount point found');
      return false;
    }

    state.mountEl = elMount;
    elMount.innerHTML = '';
    elMount.appendChild(buildUI());
    state.mounted = true;

    (async () => {
      try {
        const data = await jget(API.methods);
        state.methods = data.methods || [];
        state.layer7  = data.layer7  || [];
        state.layer4  = data.layer4  || [];

        const root = state.mountEl.querySelector('.mhd-root');
        if (root && root._refs) {
          const sel = root._refs.methodSelect;
          sel.innerHTML = '<option value="">Select a method…</option>';
          state.methods.forEach(m => sel.appendChild(el('option', { value: m }, m)));
          root._refs.renderChips();
        }
      } catch (e) {
        toast('Failed to load methods: ' + e.message, 'err');
      }

      await refresh();
      startPolling();
    })();

    return true;
  }

  function unmount() {
    stopPolling();
    state.mounted = false;
    state.mountEl = null;
  }

  /* ── Auto-mount if placeholder present ───────────────────────────── */
  function autoMount() {
    const placeholder = document.querySelector('[data-emergens-panel="mhddos"]');
    if (placeholder) mount(placeholder);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoMount);
  } else {
    autoMount();
  }

  /* ── Public API ──────────────────────────────────────────────────── */
  window.MHDDoSControl = {
    mount,
    unmount,
    refresh,
    get state() { return { ...state }; },
  };
})();
