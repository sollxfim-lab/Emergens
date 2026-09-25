/* ============================================================================
 * app-ex3bve.js — Exploit Suite for Emergens
 * v3.3.0 — APEX PREDATOR · professional, multi-instance, logger-free
 *
 * Sub-tools
 *   • Dirfuzz · SQLi · SQLMap · SQL-lite · XSS · XSS-lite · Sniper
 *
 * Changelog v3.3.0
 *   ✔ HTTP Logger fully removed (endpoints, tab, UI, sidebar, CSS)
 *   ✔ Shark UI from v3.2.0 retained (real anatomy, clean animation)
 *   ✔ SSE close-race fixed · XSS-safe rendering · keyboard nav
 *   ✔ Public API unchanged — mount / unmount / open / create
 * ========================================================================= */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════════════
   *  Endpoints
   * ══════════════════════════════════════════════════════════════════ */
  const EP = {
    dirfuzz:   { wordlists: '/api/dirfuzz/wordlists', scan: '/api/dirfuzz/scan', stream: '/api/dirfuzz/scan/stream' },
    sqli:      { wordlists: '/api/sqli/wordlists',    scan: '/api/sqli/scan',    stream: '/api/sqli/scan/stream' },
    sqlmap:    { scan: '/api/sqlmap/scan' },
    sqlinj:    { scan: '/api/sql_injection/scan' },
    xss:       { wordlist: '/api/xss/wordlist', scan: '/api/xss/scan', stream: '/api/xss/scan/stream' },
    xssSimple: { scan: '/api/xss_simple/scan' },
    sniper:    { scan: '/api/sniper/scan', stream: '/api/sniper/scan/stream' },
  };

  /* ══════════════════════════════════════════════════════════════════
   *  Helpers
   * ══════════════════════════════════════════════════════════════════ */
  const $  = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function el(tag, attrs, ...children) {
    const n = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k === 'class')                    n.className = v;
        else if (k === 'html')                n.innerHTML = v; // trusted only
        else if (k === 'text')                n.textContent = v;
        else if (k === 'style')               n.style.cssText = v;
        else if (k.startsWith('on') && typeof v === 'function')
                                              n.addEventListener(k.slice(2).toLowerCase(), v);
        else if (v === true)                  n.setAttribute(k, '');
        else                                  n.setAttribute(k, v);
      }
    }
    const append = (c) => {
      if (c == null || c === false) return;
      if (Array.isArray(c)) { c.forEach(append); return; }
      if (typeof c === 'string' || typeof c === 'number') {
        n.appendChild(document.createTextNode(String(c)));
      } else if (c instanceof Node) {
        n.appendChild(c);
      }
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
      n.style.transform = 'translateX(20px)';
      setTimeout(() => n.remove(), 300);
    }, ms);
  }

  async function _fetchJSON(url, opts) {
    const r = await fetch(url, Object.assign({ credentials: 'same-origin' }, opts || {}));
    const txt = await r.text();
    let data;
    try { data = txt ? JSON.parse(txt) : {}; }
    catch (_) { data = { raw: txt }; }
    if (!r.ok) throw new Error((data && data.error) || ('HTTP ' + r.status));
    return data;
  }

  const jget  = (url)       => _fetchJSON(url);
  const jpost = (url, body) => _fetchJSON(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });

  const pretty = (obj) => { try { return JSON.stringify(obj, null, 2); } catch (_) { return String(obj); } };

  function parseQS(url) {
    try {
      const u = new URL(url, location.origin);
      const out = {};
      u.searchParams.forEach((v, k) => { out[k] = v; });
      return out;
    } catch (_) { return {}; }
  }

  /* ══════════════════════════════════════════════════════════════════
   *  CSS
   * ══════════════════════════════════════════════════════════════════ */
  const CSS = `
  /* ─── Root ─── */
  .ex-root {
    --ex-red:        #dc2626;
    --ex-red-2:      #b91c1c;
    --ex-red-3:      #7f1d1d;
    --ex-red-bright: #ef4444;
    --ex-teal:       #0891b2;
    --ex-border:     rgba(148,163,184,.14);
    --ex-border-2:   rgba(148,163,184,.08);
    --ex-border-red: rgba(220,38,38,.28);
    --ex-white:      #f8fafc;
    --ex-text:       #e2e8f0;
    --ex-muted:      #94a3b8;
    --ex-muted-2:    #64748b;

    display: flex; flex-direction: column; gap: 16px;
    font-family: var(--font-ui,'Inter','Space Grotesk',system-ui,sans-serif);
    color: var(--ex-text);
    position: relative; isolation: isolate;
  }
  .ex-root::before {
    content: ""; position: absolute; inset: -20px;
    background:
      radial-gradient(ellipse at 20% 0%,  rgba(8,145,178,.08), transparent 55%),
      radial-gradient(ellipse at 85% 100%, rgba(220,38,38,.06), transparent 55%);
    pointer-events: none; z-index: -1;
  }

  /* ═══ HERO HEADER ═══ */
  .ex-shark-header {
    position: relative;
    background:
      radial-gradient(ellipse at 12% 100%, rgba(220,38,38,.28), transparent 55%),
      radial-gradient(ellipse at 90% 0%,   rgba(30,58,138,.30), transparent 55%),
      radial-gradient(ellipse at 50% 50%,  rgba(8,145,178,.09), transparent 70%),
      linear-gradient(135deg, #0a1122 0%, #0b0715 55%, #150404 100%);
    border: 1px solid var(--ex-border-red);
    border-radius: 18px;
    padding: 26px 30px;
    display: flex; align-items: center; gap: 30px;
    overflow: hidden;
    box-shadow:
      inset 0 1px 0 rgba(255,255,255,.06),
      inset 0 -60px 100px -60px rgba(220,38,38,.2),
      0 16px 44px rgba(0,0,0,.55),
      0 3px 12px rgba(220,38,38,.18);
  }
  .ex-shark-header::before {
    content: ""; position: absolute; inset: 0;
    background-image:
      repeating-radial-gradient(circle at 15% 100%,
        rgba(220,38,38,.06) 0 12px, transparent 12px 40px),
      repeating-linear-gradient(115deg,
        rgba(255,255,255,.018) 0 2px, transparent 2px 12px);
    opacity: .8; pointer-events: none;
  }
  .ex-shark-header::after {
    content: ""; position: absolute; left: 0; right: 0; top: -20%; bottom: -20%;
    background: linear-gradient(108deg,
      transparent 10%, rgba(8,145,178,.06) 22%,
      transparent 30%, transparent 52%,
      rgba(220,38,38,.05) 62%, transparent 72%);
    background-size: 220% 100%;
    animation: exCaustics 13s ease-in-out infinite;
    pointer-events: none; mix-blend-mode: screen;
  }
  @keyframes exCaustics {
    0%,100% { background-position: 0% 0; }
    50%     { background-position: 100% 0; }
  }

  /* ═══ Shark figure ═══ */
  .ex-shark-figure {
    position: relative;
    width: 280px; height: 160px;
    flex-shrink: 0;
    filter:
      drop-shadow(0 16px 30px rgba(220,38,38,.42))
      drop-shadow(0 4px 12px rgba(0,0,0,.6));
    z-index: 1;
  }
  .ex-shark-figure svg {
    width: 100%; height: 100%;
    display: block; overflow: visible;
    animation: exSharkGlide 9s ease-in-out infinite;
  }
  @keyframes exSharkGlide {
    0%,100% { transform: translateX(0) translateY(0) rotate(-1deg); }
    25%     { transform: translateX(4px) translateY(-2px) rotate(0deg); }
    50%     { transform: translateX(8px) translateY(0) rotate(1deg); }
    75%     { transform: translateX(4px) translateY(2px) rotate(0deg); }
  }

  .ex-shark-figure svg .ex-body-group {
    transform-origin: 55% 58%;
    animation: exBodyFlex 3.5s ease-in-out infinite;
  }
  @keyframes exBodyFlex {
    0%,100% { transform: scaleY(1) rotate(0deg); }
    50%     { transform: scaleY(1.012) rotate(0.35deg); }
  }

  .ex-shark-figure svg .ex-tail {
    transform-origin: 74px 100px;
    animation: exTailSwing 1.4s cubic-bezier(.45,0,.55,1) infinite;
  }
  @keyframes exTailSwing {
    0%,100% { transform: rotate(-8deg); }
    50%     { transform: rotate(8deg); }
  }

  .ex-shark-figure svg .ex-pect {
    transform-origin: 172px 118px;
    animation: exPectSway 2.6s ease-in-out infinite;
  }
  @keyframes exPectSway {
    0%,100% { transform: rotate(-4deg); }
    50%     { transform: rotate(4deg); }
  }

  .ex-shark-figure svg .ex-blood-drop {
    animation: exBloodDrip 2.4s ease-in infinite;
  }
  .ex-shark-figure svg .ex-blood-drop:nth-of-type(2) { animation-delay: .7s; }
  .ex-shark-figure svg .ex-blood-drop:nth-of-type(3) { animation-delay: 1.4s; }
  @keyframes exBloodDrip {
    0%   { transform: translateY(-3px); opacity: 0; }
    20%  { opacity: 1; }
    100% { transform: translateY(14px); opacity: 0; }
  }

  /* ═══ Bubbles ═══ */
  .ex-shark-bubbles {
    position: absolute; inset: 0; pointer-events: none; overflow: visible;
  }
  .ex-shark-bubbles span {
    position: absolute; bottom: 14px; border-radius: 50%;
    background: radial-gradient(circle at 32% 32%, #fff, rgba(220,38,38,.55));
    opacity: 0;
    animation: exBubbleRise 6.5s linear infinite;
    box-shadow: 0 0 8px rgba(255,255,255,.4);
    will-change: transform, opacity;
  }
  .ex-shark-bubbles span:nth-child(1) { left: 48%; width: 6px; height: 6px; animation-delay: 0s;   }
  .ex-shark-bubbles span:nth-child(2) { left: 57%; width: 4px; height: 4px; animation-delay: .8s;  }
  .ex-shark-bubbles span:nth-child(3) { left: 65%; width: 7px; height: 7px; animation-delay: 1.6s; }
  .ex-shark-bubbles span:nth-child(4) { left: 73%; width: 5px; height: 5px; animation-delay: 2.4s; }
  .ex-shark-bubbles span:nth-child(5) { left: 81%; width: 4px; height: 4px; animation-delay: 3.2s; }
  .ex-shark-bubbles span:nth-child(6) { left: 89%; width: 3px; height: 3px; animation-delay: 4.0s; }
  .ex-shark-bubbles span:nth-child(7) { left: 40%; width: 5px; height: 5px; animation-delay: 4.8s; }
  .ex-shark-bubbles span:nth-child(8) { left: 28%; width: 3px; height: 3px; animation-delay: 5.4s; }
  .ex-shark-bubbles span:nth-child(9) { left: 17%; width: 4px; height: 4px; animation-delay: 5.9s; }
  @keyframes exBubbleRise {
    0%   { transform: translateY(0) scale(.5);     opacity: 0; }
    12%  { opacity: .9; }
    88%  { opacity: .55; }
    100% { transform: translateY(-105px) scale(1.35); opacity: 0; }
  }

  /* ═══ Header copy ═══ */
  .ex-shark-copy { flex: 1; min-width: 0; position: relative; z-index: 1; }

  .ex-shark-eyebrow {
    display: inline-flex; align-items: center; gap: 9px;
    font-size: .64rem; letter-spacing: .24em; text-transform: uppercase;
    font-weight: 800; color: #fca5a5; margin-bottom: 10px;
    padding: 4px 12px 4px 10px; border-radius: 99px;
    background: linear-gradient(135deg, rgba(220,38,38,.16), rgba(220,38,38,.02));
    border: 1px solid rgba(220,38,38,.32);
    box-shadow: 0 2px 10px rgba(220,38,38,.18);
    width: fit-content;
  }
  .ex-shark-eyebrow::before {
    content: ""; width: 6px; height: 6px; border-radius: 50%;
    background: var(--ex-red-bright);
    animation: exEyeDot 2s ease-out infinite;
  }
  @keyframes exEyeDot {
    0%   { box-shadow: 0 0 0 0 rgba(239,68,68,.85); }
    70%  { box-shadow: 0 0 0 8px rgba(239,68,68,0); }
    100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
  }

  .ex-shark-title {
    font-size: 1.65rem; font-weight: 800; letter-spacing: -.03em;
    color: var(--ex-white); margin: 0 0 8px; line-height: 1.1;
    text-shadow: 0 2px 24px rgba(0,0,0,.55);
  }
  .ex-shark-title .ex-title-red {
    background: linear-gradient(135deg, #fca5a5 0%, #dc2626 45%, #7f1d1d 100%);
    -webkit-background-clip: text; background-clip: text;
    color: transparent;
    filter: drop-shadow(0 2px 16px rgba(220,38,38,.55));
  }
  .ex-shark-subtitle {
    color: var(--ex-muted); font-size: .82rem; line-height: 1.65;
    margin: 0; max-width: 78ch;
  }
  .ex-shark-subtitle b {
    color: var(--ex-white);
    font-family: var(--font-mono, ui-monospace, monospace);
    font-weight: 600; padding: 1px 6px; border-radius: 5px;
    background: rgba(220,38,38,.14);
    border: 1px solid rgba(220,38,38,.22);
  }

  /* ═══ Tabs ═══ */
  .ex-tabs {
    display: flex; flex-wrap: wrap; gap: 7px; padding: 12px;
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
    padding: 8px 14px 8px 10px; border-radius: 99px;
    border: 1px solid transparent; background: transparent;
    color: var(--ex-muted); font-size: .78rem; font-weight: 700;
    letter-spacing: .01em; cursor: pointer;
    display: inline-flex; align-items: center; gap: 8px;
    transition: all .18s cubic-bezier(.4,0,.2,1);
    -webkit-appearance: none; appearance: none;
    white-space: nowrap; font-family: inherit; position: relative;
  }
  .ex-tab .ex-tab-ico {
    width: 22px; height: 22px;
    display: inline-flex; align-items: center; justify-content: center;
    font-size: .72rem; border-radius: 50%;
    background: rgba(148,163,184,.10);
    color: inherit; transition: all .18s; flex-shrink: 0;
  }
  .ex-tab:hover {
    color: var(--ex-white);
    border-color: var(--ex-border-red);
    background: linear-gradient(180deg, rgba(220,38,38,.10), rgba(220,38,38,.02));
    transform: translateY(-1px);
  }
  .ex-tab:hover .ex-tab-ico { background: rgba(220,38,38,.22); color: #fca5a5; }
  .ex-tab.active {
    background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
    color: #fff;
    border-color: rgba(255,255,255,.2);
    box-shadow:
      0 6px 20px rgba(220,38,38,.45),
      0 0 0 1px rgba(255,255,255,.06) inset,
      inset 0 1px 0 rgba(255,255,255,.2);
  }
  .ex-tab.active .ex-tab-ico { background: rgba(0,0,0,.28); color: #fff; }
  .ex-tab:focus-visible {
    outline: 2px solid var(--ex-red-bright);
    outline-offset: 2px;
  }

  /* ═══ Panels ═══ */
  .ex-panel { display: none; }
  .ex-panel.active {
    display: flex; flex-direction: column; gap: 14px;
    animation: exSlideIn .32s cubic-bezier(.4,0,.2,1);
  }
  @keyframes exSlideIn {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  /* ═══ Cards ═══ */
  .ex-card {
    background: linear-gradient(165deg, rgba(11,18,32,.85) 0%, rgba(5,10,22,.95) 100%);
    border: 1px solid var(--ex-border);
    border-radius: 14px;
    padding: 20px 22px;
    position: relative; overflow: hidden;
    transition: border-color .2s, box-shadow .2s, transform .2s;
    backdrop-filter: blur(8px) saturate(1.1);
    -webkit-backdrop-filter: blur(8px) saturate(1.1);
  }
  .ex-card::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, var(--ex-red) 0%, transparent 55%);
    opacity: .6;
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
    margin: 0 0 16px; font-size: .78rem; font-weight: 800;
    letter-spacing: .1em; text-transform: uppercase;
    color: var(--ex-white);
    display: flex; align-items: center; gap: 11px;
    padding-bottom: 14px;
    border-bottom: 1px solid var(--ex-border-2);
    flex-wrap: wrap;
  }
  .ex-card h4 i {
    width: 30px; height: 30px;
    display: flex; align-items: center; justify-content: center;
    font-size: .84rem; border-radius: 9px;
    background: linear-gradient(135deg, var(--ex-red-bright), var(--ex-red-3));
    color: #fff;
    box-shadow: 0 4px 14px rgba(220,38,38,.45), inset 0 1px 0 rgba(255,255,255,.2);
    flex-shrink: 0;
  }
  .ex-card h4 .ex-card-hint {
    margin-left: auto;
    font-size: .66rem; font-weight: 600;
    letter-spacing: 0; text-transform: none;
    color: var(--ex-muted);
    font-family: var(--font-mono, monospace);
    padding: 3px 9px; border-radius: 99px;
    background: rgba(148,163,184,.08);
    border: 1px solid var(--ex-border);
  }

  /* ═══ Forms ═══ */
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
    box-shadow: 0 0 0 3px rgba(220,38,38,.18), 0 0 20px -4px rgba(220,38,38,.35);
    background: linear-gradient(180deg, #060b17, #0b1226);
  }
  .ex-field > input::placeholder,
  .ex-field > textarea::placeholder { color: rgba(148,163,184,.45); }
  .ex-field > textarea { min-height: 70px; resize: vertical; }

  /* ═══ Buttons ═══ */
  .ex-actions { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
  .ex-btn {
    padding: 11px 18px; border-radius: 10px;
    border: 1px solid transparent;
    font-weight: 700; font-size: .82rem;
    cursor: pointer;
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    transition: all .18s cubic-bezier(.4,0,.2,1);
    -webkit-appearance: none; appearance: none;
    white-space: nowrap; font-family: inherit;
    position: relative; overflow: hidden;
  }
  .ex-btn:active { transform: scale(.97); }
  .ex-btn[disabled] { opacity: .5; cursor: not-allowed; transform: none !important; }
  .ex-btn-primary {
    background: linear-gradient(135deg, var(--ex-red-bright), var(--ex-red-3));
    color: #fff;
    box-shadow: 0 4px 14px rgba(220,38,38,.4), inset 0 1px 0 rgba(255,255,255,.18);
  }
  .ex-btn-primary:hover:not([disabled]) {
    transform: translateY(-2px);
    box-shadow: 0 12px 32px rgba(220,38,38,.6), inset 0 1px 0 rgba(255,255,255,.22);
    filter: brightness(1.08);
  }
  .ex-btn-danger {
    background: linear-gradient(135deg, #7f1d1d, #450a0a);
    color: #fca5a5; border-color: rgba(239,68,68,.4);
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
    border-color: var(--ex-border); color: var(--ex-muted);
  }
  .ex-btn-ghost:hover:not([disabled]) {
    border-color: var(--ex-red); color: var(--ex-white);
    background: linear-gradient(180deg, rgba(220,38,38,.10), rgba(220,38,38,.02));
    box-shadow: 0 4px 14px rgba(220,38,38,.18);
  }

  /* ═══ Progress ═══ */
  .ex-progress {
    margin-top: 12px;
    height: 14px; width: 100%;
    background: linear-gradient(180deg, #050912, #0a1122);
    border-radius: 99px; overflow: hidden;
    border: 1px solid var(--ex-border);
    position: relative;
    box-shadow: inset 0 2px 4px rgba(0,0,0,.6), 0 1px 0 rgba(255,255,255,.03);
  }
  .ex-progress > span {
    display: block; height: 100%; width: 0%;
    background:
      linear-gradient(180deg, rgba(255,255,255,.18), transparent 40%),
      linear-gradient(90deg, #991b1b, #dc2626, #ef4444, #f87171);
    transition: width .35s cubic-bezier(.16,1,.3,1);
    border-radius: 99px; position: relative; overflow: hidden;
    box-shadow: 0 0 20px rgba(220,38,38,.5), inset 0 -2px 4px rgba(0,0,0,.3);
  }
  .ex-progress > span::after {
    content: ""; position: absolute; inset: 0;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,.35), transparent);
    background-size: 200% 100%;
    animation: exShimmer 2.2s linear infinite;
    opacity: .55;
  }
  @keyframes exShimmer {
    0%   { background-position: -200% 0; }
    100% { background-position:  200% 0; }
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

  /* ═══ Log / Result ═══ */
  .ex-log {
    max-height: 300px; overflow-y: auto;
    background: linear-gradient(180deg, #030509, #050a14);
    border: 1px solid var(--ex-border); border-radius: 11px;
    padding: 14px 16px 14px 22px;
    font-family: var(--font-mono, monospace);
    font-size: .72rem; color: #cbd5e1;
    white-space: pre-wrap; line-height: 1.7;
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
  .ex-log::-webkit-scrollbar-thumb { background: rgba(220,38,38,.4); border-radius: 4px; }
  .ex-log::-webkit-scrollbar-thumb:hover { background: rgba(220,38,38,.6); }
  .ex-log .ok   { color: #4ade80; }
  .ex-log .warn { color: #fbbf24; }
  .ex-log .err  { color: #f87171; }
  .ex-log .dim  { color: #64748b; }

  .ex-result {
    background: linear-gradient(180deg, #030509, #050a14);
    border: 1px solid var(--ex-border); border-radius: 11px;
    padding: 15px;
    font-family: var(--font-mono, monospace);
    font-size: .74rem; color: #e2e8f0;
    white-space: pre-wrap; word-break: break-word;
    max-height: 480px; overflow-y: auto;
    line-height: 1.7; scrollbar-width: thin;
    box-shadow: inset 0 2px 6px rgba(0,0,0,.4);
  }
  .ex-result .dim { color: #64748b; }

  /* ═══ Badges ═══ */
  .ex-badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 3px 10px; border-radius: 99px;
    font-size: .62rem; font-weight: 800;
    text-transform: uppercase; letter-spacing: .07em;
    border: 1px solid; position: relative;
  }
  .ex-badge-critical { background: linear-gradient(135deg, rgba(220,38,38,.28), rgba(127,29,29,.18)); color: #fca5a5; border-color: rgba(220,38,38,.55); box-shadow: 0 0 12px -2px rgba(220,38,38,.35); }
  .ex-badge-high     { background: linear-gradient(135deg, rgba(249,115,22,.24), rgba(154,52,18,.15)); color: #fdba74; border-color: rgba(249,115,22,.5); }
  .ex-badge-medium   { background: linear-gradient(135deg, rgba(245,158,11,.24), rgba(120,53,15,.15)); color: #fcd34d; border-color: rgba(245,158,11,.5); }
  .ex-badge-low      { background: linear-gradient(135deg, rgba(59,130,246,.22), rgba(30,58,138,.15)); color: #93c5fd; border-color: rgba(59,130,246,.5); }
  .ex-badge-info     { background: linear-gradient(135deg, rgba(148,163,184,.18), rgba(71,85,105,.1)); color: #cbd5e1; border-color: rgba(148,163,184,.35); }
  .ex-badge-safe     { background: linear-gradient(135deg, rgba(34,197,94,.22), rgba(20,83,45,.15)); color: #86efac; border-color: rgba(34,197,94,.5); }

  /* ═══ Chips ═══ */
  .ex-chips {
    display: flex; flex-wrap: wrap; gap: 6px;
    max-height: 120px; overflow-y: auto;
    padding: 4px 2px;
  }
  .ex-chip {
    padding: 6px 12px; border-radius: 8px;
    border: 1px solid var(--ex-border);
    background: linear-gradient(180deg, #0a1122, #06090f);
    color: var(--ex-muted);
    font-family: var(--font-mono, monospace);
    font-size: .7rem; font-weight: 600;
    cursor: pointer; transition: all .16s;
    -webkit-appearance: none; appearance: none;
  }
  .ex-chip:hover {
    border-color: var(--ex-red); color: var(--ex-white);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(220,38,38,.2);
  }
  .ex-chip.active {
    background: linear-gradient(135deg, var(--ex-red-bright), var(--ex-red-3));
    border-color: transparent; color: #fff;
    box-shadow: 0 4px 14px rgba(220,38,38,.45), inset 0 1px 0 rgba(255,255,255,.18);
  }

  /* ═══ Findings ═══ */
  .ex-findings { display: flex; flex-direction: column; gap: 8px; }
  .ex-finding {
    background: linear-gradient(180deg, rgba(10,17,34,.9), rgba(5,10,22,.9));
    border-left: 4px solid #dc2626;
    border-radius: 9px;
    padding: 13px 16px; font-size: .78rem;
    transition: all .18s;
    animation: exFindingIn .34s cubic-bezier(.4,0,.2,1);
    position: relative;
  }
  @keyframes exFindingIn {
    from { opacity: 0; transform: translateX(-8px); }
    to   { opacity: 1; transform: translateX(0); }
  }
  .ex-finding:hover {
    background: linear-gradient(180deg, rgba(15,26,46,.9), rgba(10,19,37,.9));
    transform: translateX(4px);
    box-shadow: 0 6px 20px rgba(0,0,0,.45), 0 0 0 1px rgba(220,38,38,.1) inset;
  }
  .ex-finding.critical { border-left-color: #dc2626; box-shadow: 0 0 18px -8px rgba(220,38,38,.4); }
  .ex-finding.high     { border-left-color: #f97316; }
  .ex-finding.medium   { border-left-color: #f59e0b; }
  .ex-finding.low      { border-left-color: #3b82f6; }
  .ex-finding.safe     { border-left-color: #22c55e; }
  .ex-finding .label {
    font-size: .62rem; text-transform: uppercase;
    letter-spacing: .08em; color: var(--ex-muted);
    font-weight: 700;
    display: flex; align-items: center; gap: 8px;
  }
  .ex-finding .label i { color: var(--ex-red-bright); }
  .ex-finding .value {
    font-family: var(--font-mono, monospace);
    word-break: break-all; margin-top: 6px;
    color: var(--ex-white); font-size: .76rem; line-height: 1.55;
  }
  .ex-finding .meta {
    margin-top: 9px; font-size: .66rem; color: var(--ex-muted);
    display: flex; gap: 14px; flex-wrap: wrap; align-items: center;
  }

  /* ═══ KPIs ═══ */
  .ex-kpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 10px; margin-bottom: 12px;
  }
  .ex-kpi {
    background: linear-gradient(165deg, #0b1220 0%, #050a16 100%);
    border: 1px solid var(--ex-border); border-radius: 11px;
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
  .ex-kpi:hover {
    border-color: var(--ex-border-red);
    transform: translateY(-2px);
    box-shadow: 0 8px 22px rgba(0,0,0,.45), 0 0 0 1px rgba(220,38,38,.08) inset;
  }
  .ex-kpi .k-label {
    font-size: .62rem; letter-spacing: .08em;
    text-transform: uppercase; color: var(--ex-muted); font-weight: 700;
  }
  .ex-kpi .k-val {
    font-family: var(--font-display, monospace);
    font-size: 1.4rem; color: var(--ex-white); font-weight: 800;
    line-height: 1.1;
    text-shadow: 0 2px 12px rgba(220,38,38,.15);
  }

  /* ═══ Tables ═══ */
  .ex-table { width: 100%; border-collapse: collapse; font-size: .76rem; }
  .ex-table th, .ex-table td {
    text-align: left; padding: 10px 12px;
    border-bottom: 1px solid var(--ex-border);
  }
  .ex-table th {
    font-size: .62rem; letter-spacing: .08em; text-transform: uppercase;
    color: var(--ex-muted); font-weight: 800;
    background: linear-gradient(180deg, rgba(220,38,38,.08), rgba(220,38,38,.02));
    position: sticky; top: 0; z-index: 1;
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
  }
  .ex-table code {
    font-family: var(--font-mono, monospace);
    font-size: .72rem; color: #cbd5e1; word-break: break-all;
  }
  .ex-table tbody tr {
    cursor: pointer;
    transition: background .14s, box-shadow .14s;
  }
  .ex-table tbody tr:hover {
    background: linear-gradient(90deg, rgba(220,38,38,.1), transparent);
    box-shadow: inset 3px 0 0 var(--ex-red);
  }

  /* ═══ Empty ═══ */
  .ex-empty {
    padding: 32px 16px; text-align: center;
    color: var(--ex-muted); font-size: .82rem; font-style: italic;
    display: flex; flex-direction: column; gap: 14px; align-items: center;
  }
  .ex-empty svg {
    width: 130px; height: 90px; opacity: .6;
    filter: drop-shadow(0 6px 18px rgba(220,38,38,.45));
    animation: exEmptyFloat 4s ease-in-out infinite;
  }
  @keyframes exEmptyFloat {
    0%,100% { transform: translateY(0); }
    50%     { transform: translateY(-5px); }
  }

  /* ═══ Live pill ═══ */
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
    animation: exLivePulse 1.5s ease-out infinite;
  }
  @keyframes exLivePulse {
    0%   { box-shadow: 0 0 0 0 rgba(239,68,68,.85); }
    70%  { box-shadow: 0 0 0 9px rgba(239,68,68,0); }
    100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
  }

  /* ═══ Sidebar — exploit + mhddos only (no httplogger) ═══ */
  .nav-item[data-section="mhddos"],
  .nav-item[data-section="exploit"] {
    position: relative;
    transition: all .18s cubic-bezier(.4,0,.2,1);
  }
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
    color: #fff !important; font-weight: 700 !important;
    box-shadow: inset 3px 0 0 rgba(239,68,68,.85), 0 0 18px -6px rgba(220,38,38,.55);
  }
  .nav-item[data-section="mhddos"].active i,
  .nav-item[data-section="exploit"].active i {
    color: #fff !important;
    filter: drop-shadow(0 0 8px rgba(239,68,68,.85));
  }
  .content-section.active#section-mhddos  .panel-title i,
  .content-section.active#section-exploit .panel-title i {
    color: #ef4444 !important;
    background: linear-gradient(135deg, rgba(220,38,38,.26), rgba(127,29,29,.14)) !important;
    box-shadow: inset 0 0 0 1px rgba(220,38,38,.35);
  }

  /* ═══ Responsive ═══ */
  @media (max-width: 900px) {
    .ex-shark-header { flex-direction: column; align-items: flex-start; padding: 22px; gap: 18px; }
    .ex-shark-figure { width: 240px; height: 138px; }
    .ex-shark-title  { font-size: 1.35rem; }
    .ex-shark-header::after { animation: none; }
  }
  @media (max-width: 720px) {
    .ex-row > * { flex: 1 1 100%; }
    .ex-tabs { overflow-x: auto; flex-wrap: nowrap; padding: 10px; }
    .ex-tab  { flex-shrink: 0; }
  }
  @media (max-width: 480px) {
    .ex-shark-figure { width: 190px; height: 112px; }
    .ex-shark-title  { font-size: 1.15rem; }
  }

  @media (prefers-reduced-motion: reduce) {
    .ex-shark-figure svg,
    .ex-shark-figure svg .ex-body-group,
    .ex-shark-figure svg .ex-tail,
    .ex-shark-figure svg .ex-pect,
    .ex-shark-figure svg .ex-blood-drop,
    .ex-shark-bubbles span,
    .ex-empty svg { animation: none !important; }
  }
  `;

  function injectCSS() {
    if (document.getElementById('ex-css')) return;
    const s = document.createElement('style');
    s.id = 'ex-css';
    s.textContent = CSS;
    document.head.appendChild(s);
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Shark figure — anatomically corrected
   * ══════════════════════════════════════════════════════════════════ */
  function sharkFigure() {
    const wrap = el('div', { class: 'ex-shark-figure', 'aria-hidden': 'true' });
    const svg  = el('div', {
      html: `
      <svg viewBox="0 0 340 180" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">
        <defs>
          <linearGradient id="exBodyTop" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0"    stop-color="#6b7a8c"/>
            <stop offset="0.35" stop-color="#475569"/>
            <stop offset="0.75" stop-color="#1e293b"/>
            <stop offset="1"    stop-color="#0f172a"/>
          </linearGradient>
          <linearGradient id="exBodyBelly" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0"    stop-color="#f1f5f9"/>
            <stop offset="0.55" stop-color="#cbd5e1"/>
            <stop offset="1"    stop-color="#64748b"/>
          </linearGradient>
          <linearGradient id="exFinMain" x1="0" y1="1" x2="0.4" y2="0">
            <stop offset="0"    stop-color="#7f1d1d"/>
            <stop offset="0.45" stop-color="#b91c1c"/>
            <stop offset="0.85" stop-color="#ef4444"/>
            <stop offset="1"    stop-color="#fca5a5"/>
          </linearGradient>
          <linearGradient id="exFinTail" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#dc2626"/>
            <stop offset="0.5" stop-color="#991b1b"/>
            <stop offset="1" stop-color="#450a0a"/>
          </linearGradient>
          <linearGradient id="exMouth" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#450a0a"/>
            <stop offset="1" stop-color="#1c0505"/>
          </linearGradient>
          <radialGradient id="exEye" cx="0.35" cy="0.35" r="0.75">
            <stop offset="0"    stop-color="#1e293b"/>
            <stop offset="0.55" stop-color="#020617"/>
            <stop offset="1"    stop-color="#000000"/>
          </radialGradient>
          <radialGradient id="exGlow" cx="0.5" cy="0.5" r="0.5">
            <stop offset="0"   stop-color="rgba(220,38,38,.42)"/>
            <stop offset="1"   stop-color="rgba(220,38,38,0)"/>
          </radialGradient>
          <filter id="exGlowFilter" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="3.2" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <filter id="exSoftShadow" x="-25%" y="-25%" width="150%" height="150%">
            <feGaussianBlur stdDeviation="1.8" result="s"/>
            <feMerge><feMergeNode in="s"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>

        <ellipse cx="180" cy="100" rx="155" ry="78" fill="url(#exGlow)" opacity="0.55"/>

        <path d="M0 152 Q85 142 170 150 T340 152"
              stroke="#0891b2" stroke-width="1.8" fill="none"
              stroke-opacity="0.5" stroke-linecap="round" stroke-dasharray="16 10">
          <animate attributeName="stroke-dashoffset" from="0" to="-52" dur="4s" repeatCount="indefinite"/>
        </path>
        <path d="M14 164 Q99 156 184 164 T354 164"
              stroke="#0891b2" stroke-width="1" fill="none"
              stroke-opacity="0.28" stroke-linecap="round"/>

        <g class="ex-tail">
          <path d="M70 100 L60 98 L70 104 Z" fill="#1e293b"/>
          <path d="M70 100 L60 102 L70 106 Z" fill="#1e293b"/>
          <path d="M72 100
                   C 58 92, 34 66, 6 44
                   C 22 62, 44 82, 60 94
                   L 72 100 Z"
                fill="url(#exFinTail)" stroke="#450a0a" stroke-width="1.4" stroke-linejoin="round"/>
          <path d="M68 96 C 56 88, 36 66, 14 50 L 26 66 L 62 94 Z"
                fill="#fca5a5" opacity="0.25"/>
          <path d="M72 108
                   C 60 114, 40 132, 20 152
                   C 36 138, 54 122, 68 112
                   L 72 108 Z"
                fill="url(#exFinTail)" stroke="#450a0a" stroke-width="1.4" stroke-linejoin="round"/>
          <path d="M68 112 C 58 118, 42 132, 28 146 L 44 132 L 64 114 Z"
                fill="#fca5a5" opacity="0.2"/>
        </g>

        <g class="ex-body-group">
          <path d="M74 104
                   C 92 88, 128 76, 176 74
                   C 226 72, 268 80, 292 92
                   L 304 100
                   L 304 104
                   C 296 116, 270 124, 236 128
                   C 190 132, 132 128, 96 118
                   C 82 114, 76 108, 74 104 Z"
                fill="url(#exBodyTop)" stroke="#0f172a" stroke-width="1.6"/>

          <path d="M96 118
                   C 132 128, 190 132, 236 128
                   C 266 124, 288 116, 302 104
                   L 296 108
                   C 274 120, 236 126, 194 126
                   C 148 124, 112 118, 96 118 Z"
                fill="url(#exBodyBelly)" opacity="0.98"/>

          <path d="M104 106 C 150 110, 210 110, 264 104"
                stroke="#94a3b8" stroke-width="0.55" fill="none"
                stroke-opacity="0.45" stroke-dasharray="2 4"/>

          <path d="M172 76
                   C 196 32, 214 12, 224 8
                   L 222 44
                   C 222 58, 224 68, 228 78
                   C 210 74, 190 74, 172 76 Z"
                fill="url(#exFinMain)" stroke="#450a0a" stroke-width="1.6"
                stroke-linejoin="round" filter="url(#exGlowFilter)"/>
          <path d="M180 74 C 200 38, 212 20, 220 16 L 218 46 L 222 74 C 208 72, 194 72, 180 74 Z"
                fill="#fca5a5" opacity="0.28"/>

          <path d="M262 88 L274 66 L286 88 Q274 86 262 88 Z"
                fill="url(#exFinMain)" opacity="0.92"
                stroke="#450a0a" stroke-width="0.9" filter="url(#exSoftShadow)"/>

          <g class="ex-pect">
            <path d="M170 120 L144 172 L204 134 Z"
                  fill="url(#exFinMain)" opacity="0.96"
                  stroke="#450a0a" stroke-width="1.3"
                  stroke-linejoin="round" filter="url(#exGlowFilter)"/>
            <path d="M172 122 L150 164 L198 134 Z"
                  fill="#fca5a5" opacity="0.22"/>
          </g>

          <path d="M244 124 L252 148 L272 126 Z"
                fill="url(#exFinMain)" opacity="0.78" stroke="#450a0a" stroke-width="0.85"/>

          <path d="M276 120 L284 140 L298 122 Z"
                fill="url(#exFinMain)" opacity="0.72" stroke="#450a0a" stroke-width="0.85"/>

          <g stroke="#7f1d1d" stroke-width="2.2" stroke-linecap="round" opacity="0.95" fill="none">
            <path d="M226 88 Q224 100 224 112"/>
            <path d="M238 88 Q236 100 236 112"/>
            <path d="M250 88 Q248 100 248 112"/>
            <path d="M262 90 Q260 100 260 110"/>
            <path d="M274 92 Q272 100 272 108"/>
          </g>

          <ellipse cx="282" cy="92" rx="1.4" ry="1" fill="#1e293b" opacity="0.6"/>
          <ellipse cx="306" cy="100" rx="2.8" ry="1.8" fill="#0f172a" opacity="0.55"/>

          <path d="M298 104
                   C 306 116, 318 122, 326 116
                   C 318 120, 306 118, 298 110
                   Z"
                fill="url(#exMouth)" stroke="#450a0a" stroke-width="1" stroke-linejoin="round"/>

          <g fill="#f8fafc" opacity="0.97">
            <path d="M300 106 L302 114 L304 106 Z"/>
            <path d="M305 106 L307 115 L309 106 Z"/>
            <path d="M310 106 L312 115 L314 106 Z"/>
            <path d="M315 106 L317 114 L319 106 Z"/>
            <path d="M320 107 L322 113 L324 107 Z"/>
          </g>
          <g fill="#e2e8f0" opacity="0.7">
            <path d="M302 112 L303 106 L304 112 Z"/>
            <path d="M307 113 L308 105 L309 113 Z"/>
            <path d="M312 113 L313 105 L314 113 Z"/>
            <path d="M317 112 L318 106 L319 112 Z"/>
          </g>

          <circle cx="292" cy="94" r="4.6" fill="url(#exEye)"/>
          <circle cx="290.4" cy="92.4" r="1.25" fill="#f8fafc" opacity="0.92"/>
          <circle cx="290.4" cy="92.4" r="0.5" fill="#000" opacity="0.7"/>

          <g fill="#7f1d1d">
            <ellipse class="ex-blood-drop" cx="302" cy="124" rx="1.8" ry="3.8"/>
            <ellipse class="ex-blood-drop" cx="310" cy="128" rx="1.4" ry="3.2"/>
            <ellipse class="ex-blood-drop" cx="316" cy="126" rx="1.6" ry="3.6"/>
          </g>
          <g fill="#7f1d1d" opacity="0.68">
            <ellipse cx="158" cy="156" rx="1.5" ry="3.2"/>
            <ellipse cx="188" cy="148" rx="1.2" ry="2.8"/>
          </g>
        </g>
      </svg>
      `,
    });
    const bubbles = el('div', { class: 'ex-shark-bubbles' },
      el('span'), el('span'), el('span'), el('span'), el('span'),
      el('span'), el('span'), el('span'), el('span'));
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
          el('span', { class: 'ex-title-red' }, 'Suite')),
        el('p', { class: 'ex-shark-subtitle' },
          'Dirfuzz · SQLi · SQLMap · XSS · Sniper — ',
          el('b', null, 'authorised targets only'),
          '. All modules stream live results; every request is rate-limited and cancellable.'),
      ),
    );
  }

  function buildCard(title, icon, hint, ...children) {
    return el('div', { class: 'ex-card' },
      el('h4', null,
        el('i', { class: 'fas ' + icon }),
        title,
        hint ? el('span', { class: 'ex-card-hint' }, hint) : null),
      ...children);
  }

  function buildField(label, input) {
    return el('div', { class: 'ex-field' }, el('label', null, label), input);
  }

  function buildProgress() {
    const bar    = el('span', { style: 'width:0%;' });
    const wrap   = el('div', { class: 'ex-progress' }, bar);
    const labelL = el('span', null, 'Idle');
    const labelR = el('span', null, '0%');
    const row    = el('div', { class: 'ex-progress-label' }, labelL, labelR);
    const root   = el('div', null, wrap, row);
    root._set   = (pct, msg) => {
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
      root.appendChild(el('div', { class: cls || '' }, line));
      root.scrollTop = root.scrollHeight;
      if (root.childNodes.length > 800) root.removeChild(root.firstChild);
    };
    root._clear = () => { root.textContent = ''; };
    return root;
  }

  function buildResultPanel() {
    const root = el('div', { class: 'ex-result' });
    root.textContent = 'No results yet.';
    root._set = (data) => {
      root.textContent = (typeof data === 'string') ? data : pretty(data);
      root.scrollTop = 0;
    };
    root._clear = () => { root.textContent = 'No results yet.'; };
    return root;
  }

  function severityBadge(sev) {
    const s = String(sev || 'info').toLowerCase();
    return el('span', { class: 'ex-badge ex-badge-' + s }, s);
  }

  function emptyState(text) {
    const wrap = el('div', { class: 'ex-empty' });
    wrap.innerHTML = `
      <svg viewBox="0 0 180 120" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <defs>
          <linearGradient id="exEmptyFin" x1="0" y1="1" x2="0.4" y2="0">
            <stop offset="0" stop-color="#7f1d1d"/>
            <stop offset="0.5" stop-color="#dc2626"/>
            <stop offset="1" stop-color="#fca5a5"/>
          </linearGradient>
          <linearGradient id="exEmptyBody" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#475569"/>
            <stop offset="1" stop-color="#0f172a"/>
          </linearGradient>
        </defs>
        <path d="M38 76 C 28 70, 14 54, 6 40 C 16 52, 30 66, 40 72 Z"
              fill="url(#exEmptyFin)" opacity="0.9"/>
        <path d="M38 82 C 28 88, 18 100, 10 112 C 22 100, 32 90, 42 84 Z"
              fill="url(#exEmptyFin)" opacity="0.75"/>
        <path d="M42 78 C 60 62, 92 54, 120 54 C 144 54, 158 62, 166 72
                 C 160 82, 144 88, 120 90 C 92 90, 60 84, 42 78 Z"
              fill="url(#exEmptyBody)" stroke="#dc2626" stroke-width="1.2" stroke-opacity="0.55"/>
        <path d="M60 84 C 92 90, 144 88, 164 74 L 158 80 C 140 88, 100 88, 66 84 Z"
              fill="#cbd5e1" opacity="0.75"/>
        <path d="M92 56 C 104 32, 114 20, 120 18 L 118 42 C 118 48, 120 52, 122 56
                 C 112 54, 100 54, 92 56 Z"
              fill="url(#exEmptyFin)" stroke="#7f1d1d" stroke-width="0.8"/>
        <path d="M96 82 L 82 106 L 112 88 Z"
              fill="url(#exEmptyFin)" opacity="0.88"/>
        <g stroke="#7f1d1d" stroke-width="1.4" stroke-linecap="round" fill="none" opacity="0.85">
          <path d="M126 66 Q125 74 125 82"/>
          <path d="M134 66 Q133 74 133 82"/>
          <path d="M142 66 Q141 74 141 82"/>
        </g>
        <circle cx="152" cy="70" r="2.6" fill="#020617"/>
        <circle cx="151.2" cy="69.2" r="0.8" fill="#f8fafc" opacity="0.9"/>
        <path d="M156 76 C 160 82, 166 84, 170 82 C 164 84, 160 82, 156 78 Z"
              fill="#450a0a"/>
      </svg>`;
    if (text) wrap.appendChild(el('span', null, text));
    return wrap;
  }

  /* ── Tab definitions (no logger) ──────────────────────────────────── */
  const TABS = [
    { id: 'dirfuzz',   label: 'Dirfuzz',       icon: 'fa-folder-tree' },
    { id: 'sqli',      label: 'SQLi Engine',   icon: 'fa-database' },
    { id: 'sqlmap',    label: 'SQLMap',        icon: 'fa-magnifying-glass-chart' },
    { id: 'sqlinj',    label: 'SQL (light)',   icon: 'fa-bolt' },
    { id: 'xss',       label: 'XSS Exploiter', icon: 'fa-code' },
    { id: 'xssSimple', label: 'XSS (simple)',  icon: 'fa-wand-magic' },
    { id: 'sniper',    label: 'Sniper',        icon: 'fa-crosshairs' },
  ];

  /* ══════════════════════════════════════════════════════════════════
   *  Per-instance tab builders
   * ══════════════════════════════════════════════════════════════════ */
  function makeTabBuilders(instanceName, state) {
    const pid = (id) => 'ex-tab-' + instanceName + '-' + id;

    function openSSE(key, url, handlers) {
      closeSSE(key);
      const es = new EventSource(url);
      let closed = false;
      const close = () => {
        if (closed) return;
        closed = true;
        try { es.close(); } catch (_) {}
        if (state.streams[key] === es) delete state.streams[key];
      };
      es.addEventListener('message', (ev) => {
        if (closed) return;
        let data;
        try { data = JSON.parse(ev.data); }
        catch (_) { return; }
        try { handlers.message(data); }
        catch (err) { handlers.parse && handlers.parse(err); }
        if (data && (data.type === 'result' || data.type === 'complete' || data.type === 'error')) {
          if (handlers.shouldAutoClose === false) return;
          close();
          handlers.onEnd && handlers.onEnd(data);
        }
      });
      es.addEventListener('error', () => {
        if (closed) return;
        if (es.readyState === EventSource.CLOSED) {
          close();
          handlers.onEnd && handlers.onEnd({ type: 'closed' });
        } else {
          handlers.onError && handlers.onError();
        }
      });
      state.streams[key] = es;
      return { close, es };
    }

    function closeSSE(key) {
      const es = state.streams[key];
      if (!es) return;
      try { es.close(); } catch (_) {}
      delete state.streams[key];
    }

    /* ── 1. Dirfuzz ────────────────────────────────────────────────── */
    function buildDirfuzzTab() {
      const target    = el('input', { type: 'text', placeholder: 'https://example.com', autocomplete: 'off' });
      const wordlist  = el('select');
      const maxPaths  = el('input', { type: 'number', value: '200' });
      const conc      = el('input', { type: 'number', value: '24' });
      const rate      = el('input', { type: 'number', value: '40', step: '0.1' });
      const timeout   = el('input', { type: 'number', value: '4', step: '0.5' });
      const follow    = el('input', { type: 'checkbox' });
      const streamTgl = el('input', { type: 'checkbox', checked: true });

      const startBtn = el('button', { class: 'ex-btn ex-btn-primary', type: 'button' },
        el('i', { class: 'fas fa-play' }), 'Start Scan');
      const stopBtn  = el('button', { class: 'ex-btn ex-btn-ghost', type: 'button', disabled: true },
        el('i', { class: 'fas fa-stop' }), 'Stop');

      const progress    = buildProgress();
      const logPanel    = buildLogPanel();
      const findingsBox = el('div', { class: 'ex-findings' });

      (async () => {
        try {
          const res = await jget(EP.dirfuzz.wordlists);
          (res.wordlists || []).forEach(w => {
            wordlist.appendChild(el('option', { value: w.name }, `${w.name} (${w.count || 0})`));
          });
        } catch (_) { /* fall through */ }
        if (!wordlist.options.length) {
          wordlist.appendChild(el('option', { value: 'lottery-dirs.txt' }, 'lottery-dirs.txt'));
        }
      })();

      function renderHits(hits) {
        findingsBox.textContent = '';
        if (!hits || !hits.length) {
          findingsBox.appendChild(emptyState('No hits'));
          return;
        }
        hits.slice(0, 200).forEach(h => {
          const secrets = Array.isArray(h.secrets)
            ? h.secrets.map(s => (s && s.type) ? s.type : String(s)).join(', ')
            : '';
          findingsBox.appendChild(el('div', { class: 'ex-finding ' + (h.severity || 'info') },
            el('div', { class: 'label' },
              el('i', { class: 'fas fa-folder-open' }),
              ` ${h.category || 'other'} · path`),
            el('div', { class: 'value' }, h.url || h.path || ''),
            el('div', { class: 'meta' },
              el('span', null, 'Status: ',   String(h.status)),
              el('span', null, 'Size: ',     String(h.size || 0)),
              el('span', null, 'Severity: ', severityBadge(h.severity)),
              h.redirect_to ? el('span', null, '→ ', h.redirect_to) : null),
            secrets
              ? el('div', { class: 'value', style: 'margin-top:8px;color:#f87171;' },
                  '⚠ Secrets: ' + secrets)
              : null));
        });
      }

      const resetButtons = () => { startBtn.disabled = false; stopBtn.disabled = true; };

      function applyResult(data) {
        progress._set(100, 'Complete');
        logPanel._append(`[done] tried=${data.tried} hits=${data.hits_count} elapsed=${data.elapsed}s`, 'ok');
        renderHits(data.hits || []);
        resetButtons();
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
          if (!body.target) { toast('Target required', 'warn'); resetButtons(); return; }
          applyResult(await jpost(EP.dirfuzz.scan, body));
        } catch (e) {
          logPanel._append('[error] ' + e.message, 'err');
          toast('Dirfuzz failed: ' + e.message, 'err');
          resetButtons();
        }
      }

      function startStreaming() {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._reset(); progress._set(0, 'Connecting…');
        logPanel._clear();
        logPanel._append('[stream] connecting…', 'dim');

        const qs = new URLSearchParams({
          target:           t,
          wordlist_name:    wordlist.value,
          max_paths:        maxPaths.value,
          concurrency:      conc.value,
          rate_limit:       rate.value,
          timeout:          timeout.value,
          follow_redirects: follow.checked ? '1' : '0',
        });

        openSSE('dirfuzz', EP.dirfuzz.stream + '?' + qs.toString(), {
          message: (data) => {
            if (data.type === 'progress') {
              progress._set(data.percent || 0, `${data.label || ''} (${data.done}/${data.total})`);
            } else if (data.type === 'result') {
              applyResult(data.data || {});
            } else if (data.type === 'error') {
              logPanel._append('[error] ' + data.message, 'err');
            } else if (data.type === 'start') {
              logPanel._append('[start] ' + (data.base || ''), 'dim');
            }
          },
          onError: () => { logPanel._append('[sse] connection error', 'warn'); resetButtons(); },
          onEnd:   (data) => { if (data && data.type === 'error') resetButtons(); },
          parse:   (e) => logPanel._append('[parse] ' + e.message, 'warn'),
        });
      }

      startBtn.addEventListener('click', () => {
        if (!target.value.trim()) { toast('Target required', 'warn'); return; }
        if (streamTgl.checked) startStreaming(); else startBlocking();
      });
      stopBtn.addEventListener('click', () => {
        closeSSE('dirfuzz');
        logPanel._append('[stopped]', 'warn');
        resetButtons();
        progress._set(0, 'Stopped');
      });

      return el('div', { class: 'ex-panel', id: pid('dirfuzz') },
        buildCard('Directory / File Fuzzer', 'fa-folder-tree', 'brute-force · soft-404 aware',
          el('div', { class: 'ex-row' },
            buildField('Target', target),
            buildField('Wordlist', wordlist)),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Max paths', maxPaths),
            buildField('Concurrency', conc),
            buildField('Rate limit (req/s)', rate),
            buildField('Timeout (s)', timeout)),
          el('div', { class: 'ex-row tight', style: 'margin-top:12px; align-items:center;' },
            el('label', { style: 'display:flex;gap:7px;align-items:center;font-size:.78rem;color:#94a3b8;' },
              follow, 'Follow redirects'),
            el('label', { style: 'display:flex;gap:7px;align-items:center;font-size:.78rem;color:#94a3b8;' },
              streamTgl, 'Stream results (SSE)'),
            el('div', { style: 'flex:1 1 auto;' }),
            startBtn, stopBtn),
          progress, logPanel),
        buildCard('Findings', 'fa-list-check', 'top 200 shown', findingsBox));
    }

    /* ── 2. SQLi Engine ───────────────────────────────────────────── */
    function buildSqliTab() {
      const target    = el('input', { type: 'text', placeholder: 'https://example.com/page?id=1', autocomplete: 'off' });
      const method    = el('select', null,
        el('option', { value: 'GET' },  'GET'),
        el('option', { value: 'POST' }, 'POST'));
      const maxParams = el('input', { type: 'number', value: '10' });
      const rate      = el('input', { type: 'number', value: '20', step: '0.5' });
      const timeout   = el('input', { type: 'number', value: '8', step: '0.5' });

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

      const startBtn    = el('button', { class: 'ex-btn ex-btn-primary', type: 'button' },
        el('i', { class: 'fas fa-play' }), 'Start');
      const stopBtn     = el('button', { class: 'ex-btn ex-btn-ghost', type: 'button', disabled: true },
        el('i', { class: 'fas fa-stop' }), 'Stop');
      const streamTgl   = el('input', { type: 'checkbox', checked: true });

      const progress    = buildProgress();
      const logPanel    = buildLogPanel();
      const resultPanel = buildResultPanel();

      const resetButtons = () => { startBtn.disabled = false; stopBtn.disabled = true; };

      function applyResult(data) {
        progress._set(100, 'Complete');
        logPanel._append(
          `[done] vulnerable=${data.vulnerable} findings=${(data.findings || []).length} elapsed=${data.elapsed}s`,
          data.vulnerable ? 'err' : 'ok');
        resultPanel._set(data);
        resetButtons();
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
          if (!body.target) { toast('Target required', 'warn'); resetButtons(); return; }
          applyResult(await jpost(EP.sqli.scan, body));
        } catch (e) {
          logPanel._append('[error] ' + e.message, 'err');
          toast('SQLi scan failed: ' + e.message, 'err');
          resetButtons();
        }
      }

      function runStreaming() {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._reset(); progress._set(0, 'Connecting…');
        logPanel._clear();
        logPanel._append('[stream] connecting…', 'dim');

        const qs = new URLSearchParams({
          target:     t,
          method:     method.value,
          max_params: maxParams.value,
          rate_limit: rate.value,
          timeout:    timeout.value,
          techniques: Array.from(activeTech).join(','),
        });

        openSSE('sqli', EP.sqli.stream + '?' + qs.toString(), {
          message: (data) => {
            if (data.type === 'progress') {
              progress._set(data.percent || 0, `${data.label || ''} (${data.done}/${data.total})`);
            } else if (data.type === 'result') {
              applyResult(data.data || {});
            } else if (data.type === 'error') {
              logPanel._append('[error] ' + data.message, 'err');
            } else if (data.type === 'start') {
              logPanel._append('[start] ' + (data.url || ''), 'dim');
            }
          },
          onError: () => { logPanel._append('[sse] connection error', 'warn'); resetButtons(); },
          onEnd:   (data) => { if (data && data.type === 'error') resetButtons(); },
          parse:   (e) => logPanel._append('[parse] ' + e.message, 'warn'),
        });
      }

      startBtn.addEventListener('click', () => {
        if (!target.value.trim()) { toast('Target required', 'warn'); return; }
        if (streamTgl.checked) runStreaming(); else runBlocking();
      });
      stopBtn.addEventListener('click', () => {
        closeSSE('sqli');
        logPanel._append('[stopped]', 'warn');
        resetButtons();
      });

      return el('div', { class: 'ex-panel', id: pid('sqli') },
        buildCard('SQL Injection Engine', 'fa-database', '4 techniques · wordlist driven',
          el('div', { class: 'ex-row' },
            buildField('Target URL', target),
            buildField('Method', method)),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Max params', maxParams),
            buildField('Rate limit',  rate),
            buildField('Timeout (s)', timeout)),
          el('div', { style: 'margin-top:12px;' },
            el('label', { style: 'font-size:.64rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#94a3b8;' },
              'Techniques'),
            techniquesWrap),
          el('div', { class: 'ex-row tight', style: 'margin-top:14px; align-items:center;' },
            el('label', { style: 'display:flex;gap:7px;align-items:center;font-size:.78rem;color:#94a3b8;' },
              streamTgl, 'Stream results (SSE)'),
            el('div', { style: 'flex:1 1 auto;' }),
            startBtn, stopBtn),
          progress, logPanel),
        buildCard('Result', 'fa-clipboard-check', null, resultPanel));
    }

    /* ── 3. SQLMap ─────────────────────────────────────────────────── */
    function buildSqlmapTab() {
      const target     = el('input', { type: 'text', placeholder: 'https://example.com/page?id=1', autocomplete: 'off' });
      const method     = el('select', null,
        el('option', { value: 'GET' },  'GET'),
        el('option', { value: 'POST' }, 'POST'));
      const mode       = el('select', null,
        el('option', { value: 'basic' },  'Basic'),
        el('option', { value: 'expert' }, 'Expert'));
      const maxThreads = el('input', { type: 'number', value: '10' });
      const timeout    = el('input', { type: 'number', value: '5', step: '0.5' });

      const runBtn      = el('button', { class: 'ex-btn ex-btn-primary', type: 'button' },
        el('i', { class: 'fas fa-play' }), 'Run SQLMap');
      const resultPanel = buildResultPanel();
      const logPanel    = buildLogPanel();

      runBtn.addEventListener('click', async () => {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        runBtn.disabled = true;
        logPanel._append('[run] sqlmap ' + mode.value + ' …', 'dim');
        try {
          const res = await jpost(EP.sqlmap.scan, {
            target:      t,
            mode:        mode.value,
            method:      method.value,
            max_threads: parseInt(maxThreads.value, 10) || 10,
            timeout:     parseFloat(timeout.value)      || 5,
          });
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
            buildField('Timeout (s)', timeout)),
          el('div', { class: 'ex-actions', style: 'margin-top:14px;' }, runBtn),
          logPanel),
        buildCard('Result', 'fa-clipboard-check', null, resultPanel));
    }

    /* ── 4. SQL Injection (lightweight) ───────────────────────────── */
    function buildSqlinjTab() {
      const target = el('input', { type: 'text', placeholder: 'https://example.com/search?q=1', autocomplete: 'off' });
      const method = el('select', null,
        el('option', { value: 'GET' },  'GET'),
        el('option', { value: 'POST' }, 'POST'));
      const runBtn      = el('button', { class: 'ex-btn ex-btn-primary', type: 'button' },
        el('i', { class: 'fas fa-bolt' }), 'Run');
      const resultPanel = buildResultPanel();
      const logPanel    = buildLogPanel();

      runBtn.addEventListener('click', async () => {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        runBtn.disabled = true;
        logPanel._append('[run] lightweight SQLi …', 'dim');
        try {
          const res = await jpost(EP.sqlinj.scan, {
            target: t,
            method: method.value,
            params: parseQS(t),
          });
          logPanel._append(
            `[done] vulnerable=${res.vulnerable} findings=${(res.findings || []).length}`,
            res.vulnerable ? 'err' : 'ok');
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
            buildField('Method', method)),
          el('div', { class: 'ex-actions', style: 'margin-top:14px;' }, runBtn),
          logPanel),
        buildCard('Result', 'fa-clipboard-check', null, resultPanel));
    }

    /* ── 5. XSS Exploiter ─────────────────────────────────────────── */
    function buildXssTab() {
      const target      = el('input', { type: 'text', placeholder: 'https://example.com/search?q=test', autocomplete: 'off' });
      const method      = el('select', null,
        el('option', { value: 'GET' },  'GET'),
        el('option', { value: 'POST' }, 'POST'));
      const maxPayloads = el('input', { type: 'number', value: '30' });
      const maxParams   = el('input', { type: 'number', value: '10' });
      const conc        = el('input', { type: 'number', value: '8' });
      const rate        = el('input', { type: 'number', value: '20', step: '0.5' });
      const wafBypass   = el('input', { type: 'checkbox' });
      const streamTgl   = el('input', { type: 'checkbox', checked: true });

      const startBtn    = el('button', { class: 'ex-btn ex-btn-primary', type: 'button' },
        el('i', { class: 'fas fa-play' }), 'Start');
      const stopBtn     = el('button', { class: 'ex-btn ex-btn-ghost', type: 'button', disabled: true },
        el('i', { class: 'fas fa-stop' }), 'Stop');

      const progress    = buildProgress();
      const logPanel    = buildLogPanel();
      const findingsBox = el('div', { class: 'ex-findings' });

      const resetButtons = () => { startBtn.disabled = false; stopBtn.disabled = true; };

      function renderFindings(findings) {
        findingsBox.textContent = '';
        if (!findings || !findings.length) {
          findingsBox.appendChild(emptyState('No XSS vectors found'));
          return;
        }
        findings.forEach(f => {
          findingsBox.appendChild(el('div', { class: 'ex-finding ' + (f.severity || 'medium') },
            el('div', { class: 'label' },
              el('i', { class: 'fas fa-code' }),
              ` ${f.parameter} · ${f.context || 'unknown'}`),
            el('div', { class: 'value' }, f.payload || ''),
            el('div', { class: 'meta' },
              el('span', null, 'Status: ',     String(f.status_code || '—')),
              el('span', null, 'Confidence: ', String(f.confidence  || '—')),
              el('span', null, 'Severity: ',   severityBadge(f.severity))),
            f.evidence
              ? el('div', { class: 'value', style: 'margin-top:8px;color:#94a3b8;font-size:.72rem;' },
                  String(f.evidence).slice(0, 200))
              : null));
        });
      }

      function applyResult(data) {
        progress._set(100, 'Complete');
        logPanel._append(
          `[done] vulnerable=${data.vulnerable} findings=${(data.findings || []).length}`,
          data.vulnerable ? 'err' : 'ok');
        renderFindings(data.findings || []);
        resetButtons();
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
          if (!body.target) { toast('Target required', 'warn'); resetButtons(); return; }
          applyResult(await jpost(EP.xss.scan, body));
        } catch (e) {
          logPanel._append('[error] ' + e.message, 'err');
          toast('XSS scan failed: ' + e.message, 'err');
          resetButtons();
        }
      }

      function startStreaming() {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._reset(); progress._set(0, 'Connecting…');
        logPanel._clear();
        logPanel._append('[stream] connecting…', 'dim');

        const qs = new URLSearchParams({
          target:       t,
          method:       method.value,
          max_payloads: maxPayloads.value,
          max_params:   maxParams.value,
          concurrency:  conc.value,
          rate_limit:   rate.value,
          waf_bypass:   wafBypass.checked ? '1' : '0',
        });

        openSSE('xss', EP.xss.stream + '?' + qs.toString(), {
          message: (data) => {
            if (data.type === 'progress') {
              progress._set(data.percent || 0, `${data.label || ''} (${data.done}/${data.total})`);
            } else if (data.type === 'result') {
              applyResult(data.data || {});
            } else if (data.type === 'error') {
              logPanel._append('[error] ' + data.message, 'err');
            } else if (data.type === 'start') {
              logPanel._append('[start] ' + (data.url || ''), 'dim');
            } else if (data.type === 'heartbeat') {
              /* quiet */
            }
          },
          onError: () => { logPanel._append('[sse] connection error', 'warn'); resetButtons(); },
          onEnd:   (data) => { if (data && data.type === 'error') resetButtons(); },
          parse:   (e) => logPanel._append('[parse] ' + e.message, 'warn'),
        });
      }

      startBtn.addEventListener('click', () => {
        if (!target.value.trim()) { toast('Target required', 'warn'); return; }
        if (streamTgl.checked) startStreaming(); else startBlocking();
      });
      stopBtn.addEventListener('click', () => {
        closeSSE('xss');
        logPanel._append('[stopped]', 'warn');
        resetButtons();
      });

      return el('div', { class: 'ex-panel', id: pid('xss') },
        buildCard('XSS Exploiter', 'fa-code', 'reflected · context aware',
          el('div', { class: 'ex-row' },
            buildField('Target URL', target),
            buildField('Method', method)),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Max payloads', maxPayloads),
            buildField('Max params',   maxParams),
            buildField('Concurrency',  conc),
            buildField('Rate limit',   rate)),
          el('div', { class: 'ex-row tight', style: 'margin-top:12px; align-items:center;' },
            el('label', { style: 'display:flex;gap:7px;align-items:center;font-size:.78rem;color:#94a3b8;' },
              wafBypass, 'WAF bypass'),
            el('label', { style: 'display:flex;gap:7px;align-items:center;font-size:.78rem;color:#94a3b8;' },
              streamTgl, 'Stream (SSE)'),
            el('div', { style: 'flex:1 1 auto;' }),
            startBtn, stopBtn),
          progress, logPanel),
        buildCard('Findings', 'fa-list-check', null, findingsBox));
    }

    /* ── 6. XSS Simple ────────────────────────────────────────────── */
    function buildXssSimpleTab() {
      const target = el('input', { type: 'text', placeholder: 'https://example.com/?q=test', autocomplete: 'off' });
      const mode   = el('select', null,
        el('option', { value: 'basic' },  'Basic'),
        el('option', { value: 'expert' }, 'Expert'));
      const runBtn      = el('button', { class: 'ex-btn ex-btn-primary', type: 'button' },
        el('i', { class: 'fas fa-wand-magic' }), 'Run');
      const resultPanel = buildResultPanel();

      runBtn.addEventListener('click', async () => {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        runBtn.disabled = true;
        try {
          resultPanel._set(await jpost(EP.xssSimple.scan, { target: t, mode: mode.value }));
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
            buildField('Mode', mode)),
          el('div', { class: 'ex-actions', style: 'margin-top:14px;' }, runBtn)),
        buildCard('Result', 'fa-clipboard-check', null, resultPanel));
    }

    /* ── 7. Sniper ─────────────────────────────────────────────────── */
    function buildSniperTab() {
      const target        = el('input', { type: 'text', placeholder: 'https://example.com', autocomplete: 'off' });
      const moduleTimeout = el('input', { type: 'number', value: '90' });
      const globalBudget  = el('input', { type: 'number', value: '150' });
      const dirfuzzMax    = el('input', { type: 'number', value: '80' });
      const xssMax        = el('input', { type: 'number', value: '20' });
      const takeoverMax   = el('input', { type: 'number', value: '120' });
      const streamTgl     = el('input', { type: 'checkbox', checked: true });

      const startBtn    = el('button', { class: 'ex-btn ex-btn-primary', type: 'button' },
        el('i', { class: 'fas fa-crosshairs' }), 'Run Sniper');
      const stopBtn     = el('button', { class: 'ex-btn ex-btn-ghost', type: 'button', disabled: true },
        el('i', { class: 'fas fa-stop' }), 'Stop');

      const progress    = buildProgress();
      const logPanel    = buildLogPanel();
      const resultPanel = buildResultPanel();

      const resetButtons = () => { startBtn.disabled = false; stopBtn.disabled = true; };

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
          resetButtons();
        }
      }

      function runStreaming() {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._reset(); progress._set(0, 'Connecting…');
        logPanel._clear();

        const qs = new URLSearchParams({
          target:             t,
          module_timeout:     moduleTimeout.value,
          global_budget:      globalBudget.value,
          dirfuzz_max_paths:  dirfuzzMax.value,
          xss_max_payloads:   xssMax.value,
          takeover_max_hosts: takeoverMax.value,
        });

        openSSE('sniper', EP.sniper.stream + '?' + qs.toString(), {
          message: (data) => {
            if (data.type === 'start') {
              logPanel._append(`[start] ${data.target} · ${(data.modules || []).join(', ')}`, 'dim');
            } else if (data.type === 'module_start') {
              logPanel._append(`[▶] ${data.module}`, 'dim');
            } else if (data.type === 'progress') {
              progress._set(data.pct || 0, `${data.module}: ${data.message || ''}`);
            } else if (data.type === 'module_done') {
              logPanel._append(
                `[◀] ${data.module} — ${data.findings} finding(s) in ${data.elapsed}s`,
                data.ok ? 'ok' : 'warn');
            } else if (data.type === 'heartbeat') {
              logPanel._append(`[heartbeat] elapsed=${data.elapsed}s done=${data.modules_done}/${data.modules_total}`, 'dim');
            } else if (data.type === 'complete') {
              progress._set(100, 'Complete');
              const rep = data.report || {};
              logPanel._append(`[done] risk=${rep.risk_score}/100 (${rep.risk_level})`, 'ok');
              resultPanel._set(rep);
            } else if (data.type === 'error') {
              logPanel._append('[error] ' + data.message, 'err');
            }
          },
          onError: () => { logPanel._append('[sse] connection error', 'warn'); resetButtons(); },
          onEnd:   (data) => { if (data && data.type === 'error') resetButtons(); },
          parse:   (e) => logPanel._append('[parse] ' + e.message, 'warn'),
        });
      }

      startBtn.addEventListener('click', () => {
        if (!target.value.trim()) { toast('Target required', 'warn'); return; }
        if (streamTgl.checked) runStreaming(); else runBlocking();
      });
      stopBtn.addEventListener('click', () => {
        closeSSE('sniper');
        logPanel._append('[stopped]', 'warn');
        resetButtons();
      });

      return el('div', { class: 'ex-panel', id: pid('sniper') },
        buildCard('Sniper — Auto-Exploiter', 'fa-crosshairs', 'all modules · correlation',
          el('div', { class: 'ex-row' }, buildField('Target', target)),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Module timeout (s)', moduleTimeout),
            buildField('Global budget (s)',  globalBudget),
            buildField('Dirfuzz max paths',  dirfuzzMax),
            buildField('XSS max payloads',   xssMax),
            buildField('Takeover max hosts', takeoverMax)),
          el('div', { class: 'ex-row tight', style: 'margin-top:12px; align-items:center;' },
            el('label', { style: 'display:flex;gap:7px;align-items:center;font-size:.78rem;color:#94a3b8;' },
              streamTgl, 'Stream (SSE)'),
            el('div', { style: 'flex:1 1 auto;' }),
            startBtn, stopBtn),
          progress, logPanel),
        buildCard('Full Report', 'fa-clipboard-check', null, resultPanel));
    }

    return {
      dirfuzz:   buildDirfuzzTab,
      sqli:      buildSqliTab,
      sqlmap:    buildSqlmapTab,
      sqlinj:    buildSqlinjTab,
      xss:       buildXssTab,
      xssSimple: buildXssSimpleTab,
      sniper:    buildSniperTab,
    };
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Instance factory
   * ══════════════════════════════════════════════════════════════════ */
  function createInstance(instanceName) {
    instanceName = instanceName || ('ex-' + Math.random().toString(36).slice(2, 8));

    const state = {
      instanceName,
      mounted:   false,
      mountEl:   null,
      activeTab: 'dirfuzz',
      streams:   Object.create(null),
    };

    const TAB_BUILDERS = makeTabBuilders(instanceName, state);

    function buildUI(defaultTab) {
      const tabsRow = el('div', { class: 'ex-tabs', role: 'tablist', 'aria-label': 'Exploit Suite' });
      const panels  = {};
      const buttons = {};

      TABS.forEach(t => {
        const btn = el('button', {
          class: 'ex-tab' + (t.id === defaultTab ? ' active' : ''),
          type: 'button',
          role: 'tab',
          'aria-selected': t.id === defaultTab ? 'true' : 'false',
          'aria-controls': 'ex-tab-' + instanceName + '-' + t.id,
          'data-tab': t.id,
          tabindex: t.id === defaultTab ? '0' : '-1',
        },
          el('span', { class: 'ex-tab-ico', 'aria-hidden': 'true' }, el('i', { class: 'fas ' + t.icon })),
          t.label);
        btn.addEventListener('click', () => switchTab(t.id));
        btn.addEventListener('keydown', (ev) => {
          const order = TABS.map(x => x.id);
          const i = order.indexOf(t.id);
          if (ev.key === 'ArrowRight') { ev.preventDefault(); buttons[order[(i + 1) % order.length]].focus(); }
          if (ev.key === 'ArrowLeft')  { ev.preventDefault(); buttons[order[(i - 1 + order.length) % order.length]].focus(); }
          if (ev.key === 'Home')       { ev.preventDefault(); buttons[order[0]].focus(); }
          if (ev.key === 'End')        { ev.preventDefault(); buttons[order[order.length - 1]].focus(); }
        });
        buttons[t.id] = btn;
        tabsRow.appendChild(btn);
      });

      const body = el('div');
      TABS.forEach(t => {
        const panel = TAB_BUILDERS[t.id]();
        panel.classList.toggle('active', t.id === defaultTab);
        panel.setAttribute('role', 'tabpanel');
        panel.setAttribute('aria-labelledby', 'ex-tab-btn-' + instanceName + '-' + t.id);
        panels[t.id] = panel;
        body.appendChild(panel);
      });

      function switchTab(id) {
        if (!TABS.some(t => t.id === id)) return false;
        state.activeTab = id;
        TABS.forEach(t => {
          const active = t.id === id;
          buttons[t.id].classList.toggle('active', active);
          buttons[t.id].setAttribute('aria-selected', active ? 'true' : 'false');
          buttons[t.id].tabIndex = active ? 0 : -1;
          panels[t.id].classList.toggle('active', active);
        });
        return true;
      }

      const root = el('div', { class: 'ex-root' },
        buildHeader(),
        tabsRow,
        body);
      root._switchTab = switchTab;
      return root;
    }

    function mount(target, opts) {
      if (state.mounted) unmount();
      injectCSS();
      opts = opts || {};
      const defaultTab = opts.defaultTab || 'dirfuzz';

      let elMount = null;
      if (typeof target === 'string')                 elMount = document.querySelector(target);
      else if (target instanceof Element)             elMount = target;
      else                                            elMount = document.querySelector('[data-emergens-panel="exploit"]');

      if (!elMount) {
        console.warn('[ExploitSuite:' + instanceName + '] no mount point found');
        return false;
      }

      state.mountEl = elMount;
      elMount.textContent = '';
      elMount.appendChild(buildUI(defaultTab));
      state.mounted = true;
      state.activeTab = defaultTab;
      return true;
    }

    function unmount() {
      for (const key of Object.keys(state.streams)) {
        try { state.streams[key].close(); } catch (_) {}
      }
      state.streams = Object.create(null);
      if (state.mountEl) state.mountEl.textContent = '';
      state.mounted = false;
      state.mountEl = null;
    }

    function open(tabName) {
      if (!state.mounted || !state.mountEl) return false;
      const root = state.mountEl.querySelector('.ex-root');
      if (root && root._switchTab) return root._switchTab(tabName);
      return false;
    }

    return {
      mount, unmount, open,
      get state() { return Object.assign({}, state, { streams: Object.keys(state.streams) }); },
    };
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Public API
   * ══════════════════════════════════════════════════════════════════ */
  const defaultInstance = createInstance('default');

  window.ExploitSuite = Object.assign(defaultInstance, { create: createInstance });

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