/* ============================================================================
 * app-ex3bve.js — Exploit Suite for Emergens
 * v4.0.0 — COMMAND DECK · professional tactical redesign
 *
 * Sub-tools
 *   • Dirfuzz · SQLi · SQLMap · SQL-lite · XSS · XSS-lite · Sniper
 *
 * Changelog v4.0.0
 *   ✔ Complete visual overhaul — matches MHDDoS Command Deck family
 *   ✔ Grouped tabs: Recon / Injection / XSS · keyboard navigable
 *   ✔ Session KPI ribbon: Scans · Findings · Critical · Time
 *   ✔ Cinematic shark hero with sonar rings + scan sweep
 *   ✔ Glass morphism cards with red edge-glow on hover
 *   ✔ Progress bar with phase label + live percentage
 *   ✔ Log panel with per-line timestamps & severity colouring
 *   ✔ Findings rendered as severity-aware tactical cards
 *   ✔ Confirm overlay · toast system · inline validation
 *   ✔ Full a11y: focus rings, ARIA, reduced-motion
 *   ✔ Public API unchanged — mount / unmount / open / create
 *   ✔ HTTP Logger removed (kept from v3.3.0)
 * ========================================================================= */
(function () {
  'use strict';

  const VERSION = '4.0.0';

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

  const SVG_NS = 'http://www.w3.org/2000/svg';

  /* ══════════════════════════════════════════════════════════════════
   *  DOM helpers
   * ══════════════════════════════════════════════════════════════════ */
  const $  = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function el(tag, attrs, ...children) {
    const n = document.createElement(tag);
    if (attrs) {
      for (const k in attrs) {
        const v = attrs[k];
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
      if (typeof c === 'string' || typeof c === 'number')
        n.appendChild(document.createTextNode(String(c)));
      else if (c instanceof Node)
        n.appendChild(c);
    };
    children.forEach(append);
    return n;
  }

  function svg(tag, attrs, ...children) {
    const n = document.createElementNS(SVG_NS, tag);
    if (attrs) for (const k in attrs) {
      const v = attrs[k];
      if (v == null || v === false) continue;
      n.setAttribute(k, v);
    }
    const append = (c) => {
      if (c == null || c === false) return;
      if (Array.isArray(c)) { c.forEach(append); return; }
      n.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
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
    const icon = {
      ok: 'fa-circle-check', err: 'fa-circle-xmark',
      warn: 'fa-triangle-exclamation', info: 'fa-circle-info',
    }[kind] || 'fa-circle-info';
    const n = el('div', { class: 'toast toast-' + kind },
      el('i', { class: 'fas ' + icon }), el('span', null, msg));
    c.appendChild(n);
    requestAnimationFrame(() => n.classList.add('toast-in'));
    setTimeout(() => {
      n.classList.remove('toast-in');
      n.classList.add('toast-out');
      setTimeout(() => n.remove(), 320);
    }, ms);
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Fetch helpers
   * ══════════════════════════════════════════════════════════════════ */
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

  function timeStamp() {
    const d = new Date();
    return String(d.getHours()).padStart(2,'0') + ':' +
           String(d.getMinutes()).padStart(2,'0') + ':' +
           String(d.getSeconds()).padStart(2,'0');
  }

  function fmtDuration(sec) {
    if (sec == null || !isFinite(sec)) return '—';
    sec = Math.max(0, Math.floor(sec));
    const m = Math.floor(sec / 60), s = sec % 60;
    if (m) return `${m}m ${String(s).padStart(2,'0')}s`;
    return `${s}s`;
  }

  /* ══════════════════════════════════════════════════════════════════
   *  CSS — Command Deck Theme
   * ══════════════════════════════════════════════════════════════════ */
  const CSS = `
  /* ═══ ROOT ═══ */
  .ex-root{
    --red:#dc2626;--red-hi:#ef4444;--red-lo:#7f1d1d;--red-deep:#450a0a;
    --ink:#05060a;--ink2:#0a0d15;--ink3:#0f131f;
    --white:#f8fafc;--text:#e2e8f0;--muted:#8b95a7;--slate:#64748b;
    --amber:#f59e0b;--green:#22c55e;--blue:#3b82f6;--orange:#f97316;
    --border:rgba(148,163,184,.12);--border-hi:rgba(148,163,184,.22);
    --border-red:rgba(220,38,38,.28);
    --ui:var(--font-ui,'Inter','Space Grotesk',system-ui,sans-serif);
    --mono:var(--font-mono,ui-monospace,'JetBrains Mono',monospace);
    --ease:cubic-bezier(.4,0,.2,1);--ease-out:cubic-bezier(.16,1,.3,1);
    display:flex;flex-direction:column;gap:16px;
    font-family:var(--ui);color:var(--text);position:relative;
  }

  /* ═══ HERO ═══ */
  .ex-hero{
    position:relative;border-radius:18px;padding:24px 26px;
    display:grid;grid-template-columns:200px 1fr auto;
    align-items:center;gap:24px;overflow:hidden;isolation:isolate;
    background:
      radial-gradient(ellipse 55% 120% at 0% 100%,rgba(220,38,38,.32),transparent 62%),
      radial-gradient(ellipse 60% 100% at 100% 0%,rgba(127,29,29,.30),transparent 60%),
      radial-gradient(ellipse 40% 60% at 50% 50%,rgba(8,145,178,.06),transparent 70%),
      linear-gradient(135deg,#05060a 0%,#0a0512 50%,#150404 100%);
    border:1px solid var(--border-red);
    box-shadow:
      inset 0 1px 0 rgba(255,255,255,.06),
      inset 0 0 60px rgba(220,38,38,.06),
      0 18px 48px rgba(0,0,0,.6),
      0 4px 16px rgba(220,38,38,.15);
  }
  .ex-hero::before{
    content:"";position:absolute;inset:0;
    background-image:
      repeating-radial-gradient(circle at 12% 100%,rgba(220,38,38,.07) 0 14px,transparent 14px 52px),
      repeating-linear-gradient(115deg,rgba(255,255,255,.015) 0 2px,transparent 2px 14px);
    pointer-events:none;z-index:0;opacity:.9;
  }
  .ex-hero::after{
    content:"";position:absolute;inset:0;
    background:linear-gradient(105deg,transparent 0%,transparent 42%,rgba(220,38,38,.07) 50%,transparent 58%,transparent 100%);
    background-size:200% 100%;animation:exScan 7s linear infinite;
    pointer-events:none;z-index:1;
  }
  @keyframes exScan{0%{background-position:200% 0;}100%{background-position:-100% 0;}}
  .ex-hero-teeth{
    position:absolute;left:0;right:0;bottom:0;height:12px;
    background-image:
      linear-gradient(135deg,transparent 50%,rgba(220,38,38,.5) 50%),
      linear-gradient(45deg,rgba(220,38,38,.5) 50%,transparent 50%);
    background-size:12px 12px;background-repeat:repeat-x;
    opacity:.32;z-index:2;pointer-events:none;
  }
  .ex-hero>*{position:relative;z-index:3;}

  /* Shark arena */
  .ex-shark-arena{
    position:relative;width:200px;height:130px;
    display:flex;align-items:center;justify-content:center;
  }
  .ex-sonar{
    position:absolute;inset:0;
    display:flex;align-items:center;justify-content:center;
    pointer-events:none;
  }
  .ex-sonar span{
    position:absolute;width:80px;height:80px;border-radius:50%;
    border:1px solid rgba(239,68,68,.5);
    animation:exPing 3.4s cubic-bezier(.4,0,.2,1) infinite;
  }
  .ex-sonar span:nth-child(2){animation-delay:1.13s;}
  .ex-sonar span:nth-child(3){animation-delay:2.26s;}
  @keyframes exPing{
    0%{transform:scale(.35);opacity:.9;}
    100%{transform:scale(2.15);opacity:0;}
  }
  .ex-shark{
    width:190px;height:125px;position:relative;z-index:2;
    filter:
      drop-shadow(0 12px 26px rgba(220,38,38,.45))
      drop-shadow(0 4px 10px rgba(0,0,0,.7));
    animation:exCruise 7s ease-in-out infinite;
  }
  @keyframes exCruise{
    0%,100%{transform:translate(0,0) rotate(-1.2deg);}
    50%{transform:translate(8px,-3px) rotate(1.2deg);}
  }

  /* Bubbles */
  .ex-bubbles{position:absolute;inset:0;pointer-events:none;z-index:1;}
  .ex-bubbles i{
    position:absolute;width:5px;height:5px;border-radius:50%;
    background:radial-gradient(circle at 32% 32%,rgba(248,250,252,.9),rgba(220,38,38,.45));
    animation:exBubble 4.2s linear infinite;
  }
  .ex-bubbles i:nth-child(1){left:22%;top:78%;animation-delay:0s;width:5px;height:5px;}
  .ex-bubbles i:nth-child(2){left:52%;top:86%;animation-delay:1.05s;width:3px;height:3px;}
  .ex-bubbles i:nth-child(3){left:74%;top:72%;animation-delay:2.1s;width:4px;height:4px;}
  .ex-bubbles i:nth-child(4){left:38%;top:92%;animation-delay:3.15s;width:3px;height:3px;}
  @keyframes exBubble{
    0%{transform:translateY(0) scale(.4);opacity:0;}
    20%{opacity:.85;}
    100%{transform:translateY(-88px) scale(1);opacity:0;}
  }

  /* Hero copy */
  .ex-hero-copy{min-width:0;}
  .ex-eyebrow{
    display:inline-flex;align-items:center;gap:8px;
    font-size:.6rem;letter-spacing:.22em;text-transform:uppercase;
    font-weight:800;color:#fca5a5;margin-bottom:8px;
  }
  .ex-eyebrow::before{
    content:"";width:24px;height:2px;
    background:linear-gradient(90deg,var(--red-hi),transparent);border-radius:2px;
  }
  .ex-eyebrow .ex-ver{
    color:#7f1d1d;font-family:var(--mono);font-size:.56rem;letter-spacing:.04em;
    padding:2px 7px;border-radius:5px;
    background:rgba(220,38,38,.14);border:1px solid rgba(220,38,38,.3);
    text-transform:none;
  }
  .ex-title{
    font-size:1.5rem;font-weight:800;letter-spacing:-.03em;
    color:var(--white);margin:0 0 8px;line-height:1.12;
    display:flex;align-items:center;gap:10px;flex-wrap:wrap;
  }
  .ex-title-red{
    background:linear-gradient(135deg,#ef4444 0%,#dc2626 45%,#7f1d1d 100%);
    -webkit-background-clip:text;background-clip:text;color:transparent;
    text-shadow:0 0 30px rgba(220,38,38,.3);
  }
  .ex-pulse-dot{
    display:inline-block;width:9px;height:9px;border-radius:50%;background:#ef4444;
    box-shadow:0 0 0 0 rgba(239,68,68,.9);
    animation:exPulse 1.6s ease-out infinite;
    flex-shrink:0;margin-top:4px;
  }
  @keyframes exPulse{
    0%{box-shadow:0 0 0 0 rgba(239,68,68,.9);}
    70%{box-shadow:0 0 0 12px rgba(239,68,68,0);}
    100%{box-shadow:0 0 0 0 rgba(239,68,68,0);}
  }
  .ex-subtitle{
    color:var(--muted);font-size:.79rem;line-height:1.6;
    margin:0;max-width:74ch;
  }
  .ex-subtitle b{
    color:var(--white);font-family:var(--mono);font-weight:600;
    background:rgba(220,38,38,.1);padding:1px 7px;border-radius:5px;
    border:1px solid rgba(220,38,38,.22);
  }

  /* Hero side — status */
  .ex-hero-side{
    display:flex;flex-direction:column;align-items:flex-end;gap:10px;
    flex-shrink:0;min-width:150px;
  }
  .ex-status-pill{
    display:inline-flex;align-items:center;gap:8px;
    padding:7px 15px;border-radius:99px;
    background:linear-gradient(135deg,rgba(220,38,38,.28),rgba(220,38,38,.06));
    color:#fca5a5;font-size:.62rem;font-weight:800;
    letter-spacing:.1em;text-transform:uppercase;
    border:1px solid rgba(220,38,38,.5);
    box-shadow:0 0 20px rgba(220,38,38,.22),inset 0 1px 0 rgba(255,255,255,.08);
    transition:all .35s var(--ease);
  }
  .ex-status-pill.is-idle{
    background:linear-gradient(135deg,rgba(148,163,184,.14),rgba(148,163,184,.03));
    color:#94a3b8;border-color:var(--border-hi);box-shadow:none;
  }
  .ex-status-pill .dot{
    width:8px;height:8px;border-radius:50%;background:#ef4444;
    box-shadow:0 0 0 0 rgba(239,68,68,.85);
    animation:exLive 1.5s ease-out infinite;
  }
  .ex-status-pill.is-idle .dot{background:#94a3b8;animation:none;box-shadow:none;}
  @keyframes exLive{
    0%{box-shadow:0 0 0 0 rgba(239,68,68,.85);}
    70%{box-shadow:0 0 0 10px rgba(239,68,68,0);}
    100%{box-shadow:0 0 0 0 rgba(239,68,68,0);}
  }
  .ex-clock{
    display:flex;align-items:center;gap:7px;
    font-family:var(--mono);font-size:.68rem;color:var(--muted);
    letter-spacing:.05em;padding:6px 12px;
    background:rgba(5,6,10,.6);
    border:1px solid var(--border);border-radius:8px;
    backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);
  }
  .ex-clock i{color:var(--red-hi);font-size:.7rem;}
  .ex-clock b{color:var(--white);font-weight:600;}

  /* ═══ KPI RIBBON ═══ */
  .ex-kpis{
    display:grid;grid-template-columns:repeat(4,minmax(0,1fr));
    gap:12px;
  }
  .ex-kpi{
    position:relative;
    background:linear-gradient(165deg,var(--ink2) 0%,var(--ink) 100%);
    border:1px solid var(--border);border-radius:12px;
    padding:15px 17px 14px;overflow:hidden;
    transition:all .25s var(--ease);
  }
  .ex-kpi::before{
    content:"";position:absolute;left:0;top:0;bottom:0;width:3px;
    background:linear-gradient(180deg,var(--red-hi),var(--red-lo),transparent);
    opacity:.85;transition:opacity .25s;
  }
  .ex-kpi::after{
    content:"";position:absolute;inset:0;
    background:radial-gradient(circle at 100% 0%,rgba(220,38,38,.14),transparent 60%);
    pointer-events:none;opacity:0;transition:opacity .3s;
  }
  .ex-kpi:hover{
    border-color:var(--border-red);transform:translateY(-3px);
    box-shadow:0 8px 28px rgba(220,38,38,.25),0 12px 28px rgba(0,0,0,.4);
  }
  .ex-kpi:hover::after{opacity:1;}
  .ex-kpi-head{
    display:flex;align-items:center;gap:7px;
    font-size:.6rem;font-weight:800;
    letter-spacing:.12em;text-transform:uppercase;
    color:var(--muted);margin-bottom:7px;
  }
  .ex-kpi-head i{
    color:var(--red-hi);font-size:.7rem;
    filter:drop-shadow(0 0 6px rgba(239,68,68,.5));
  }
  .ex-kpi-value{
    font-family:var(--mono);font-size:1.45rem;font-weight:800;
    color:var(--white);line-height:1;
    display:flex;align-items:baseline;gap:5px;
    letter-spacing:-.02em;
  }
  .ex-kpi-value small{
    font-size:.62rem;font-weight:600;
    color:var(--slate);letter-spacing:.02em;
  }
  .ex-kpi.flash{animation:exKpiFlash .9s var(--ease-out);}
  @keyframes exKpiFlash{
    0%{background:linear-gradient(165deg,rgba(220,38,38,.26),var(--ink) 100%);}
    100%{background:linear-gradient(165deg,var(--ink2),var(--ink) 100%);}
  }

  /* ═══ TAB BAR — grouped ═══ */
  .ex-tabs-wrap{
    position:relative;padding:8px;
    background:linear-gradient(180deg,rgba(15,19,31,.85),rgba(5,6,10,.92));
    border:1px solid var(--border);border-radius:14px;
    backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
    overflow:hidden;
  }
  .ex-tabs-wrap::before{
    content:"";position:absolute;top:0;left:0;right:0;height:2px;
    background:linear-gradient(90deg,transparent,var(--red-hi),var(--red-lo),transparent);
    opacity:.7;
  }
  .ex-tabs{
    display:flex;flex-wrap:wrap;gap:6px;
    position:relative;z-index:1;
  }
  .ex-tab-group{
    display:inline-flex;align-items:center;gap:6px;
    padding:4px 8px;
    background:rgba(5,6,10,.5);
    border:1px solid var(--border);
    border-radius:11px;
  }
  .ex-tab-group-label{
    font-size:.58rem;letter-spacing:.12em;text-transform:uppercase;
    color:var(--slate);font-weight:800;
    padding:0 8px 0 4px;
    border-right:1px solid var(--border);
    margin-right:2px;
  }
  .ex-tab{
    padding:7px 13px;border-radius:8px;
    border:1px solid transparent;background:transparent;
    color:var(--muted);font-size:.74rem;font-weight:700;
    letter-spacing:.01em;cursor:pointer;
    display:inline-flex;align-items:center;gap:8px;
    transition:all .18s var(--ease);
    -webkit-appearance:none;appearance:none;
    white-space:nowrap;font-family:inherit;position:relative;
  }
  .ex-tab .ex-tab-ico{
    width:20px;height:20px;
    display:inline-flex;align-items:center;justify-content:center;
    font-size:.68rem;border-radius:6px;
    background:rgba(148,163,184,.1);
    color:inherit;transition:all .18s;flex-shrink:0;
  }
  .ex-tab:hover{
    color:var(--white);
    border-color:var(--border-red);
    background:linear-gradient(180deg,rgba(220,38,38,.1),rgba(220,38,38,.02));
    transform:translateY(-1px);
  }
  .ex-tab:hover .ex-tab-ico{background:rgba(220,38,38,.22);color:#fca5a5;}
  .ex-tab.active{
    background:linear-gradient(135deg,var(--red-hi) 0%,var(--red-lo) 100%);
    color:#fff;
    border-color:rgba(255,255,255,.2);
    box-shadow:
      0 6px 18px rgba(220,38,38,.45),
      inset 0 1px 0 rgba(255,255,255,.2);
  }
  .ex-tab.active .ex-tab-ico{background:rgba(0,0,0,.28);color:#fff;}
  .ex-tab:focus-visible{
    outline:none;
    box-shadow:0 0 0 3px rgba(220,38,38,.4),0 0 0 1px var(--red-hi);
  }

  /* ═══ PANELS ═══ */
  .ex-panel{display:none;}
  .ex-panel.active{
    display:flex;flex-direction:column;gap:14px;
    animation:exSlideIn .3s var(--ease);
  }
  @keyframes exSlideIn{
    from{opacity:0;transform:translateY(8px);}
    to{opacity:1;transform:translateY(0);}
  }

  /* ═══ CARDS ═══ */
  .ex-card{
    position:relative;
    background:linear-gradient(165deg,rgba(15,19,31,.85) 0%,rgba(5,6,10,.92) 100%);
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    border:1px solid var(--border);border-radius:14px;
    padding:20px 22px;overflow:hidden;
    transition:border-color .25s,box-shadow .25s,transform .25s;
  }
  .ex-card::before{
    content:"";position:absolute;top:0;left:0;right:0;height:2px;
    background:linear-gradient(90deg,var(--red-hi) 0%,var(--red-lo) 30%,transparent 70%);
    opacity:.7;
  }
  .ex-card:hover{
    border-color:var(--border-red);
    box-shadow:0 12px 32px rgba(0,0,0,.45),0 0 0 1px rgba(220,38,38,.06);
  }
  .ex-card-head{
    display:flex;align-items:center;gap:12px;
    margin:0 0 18px;padding-bottom:15px;
    border-bottom:1px solid var(--border);flex-wrap:wrap;
  }
  .ex-card-head .ico{
    width:34px;height:34px;
    display:flex;align-items:center;justify-content:center;
    font-size:.9rem;border-radius:9px;
    background:linear-gradient(135deg,var(--red-hi) 0%,var(--red-lo) 100%);
    color:#fff;
    box-shadow:0 4px 14px rgba(220,38,38,.45),inset 0 1px 0 rgba(255,255,255,.18);
    flex-shrink:0;position:relative;
  }
  .ex-card-head .ico::after{
    content:"";position:absolute;inset:0;border-radius:9px;
    background:linear-gradient(180deg,rgba(255,255,255,.2),transparent 50%);
    pointer-events:none;
  }
  .ex-card-head h4{
    margin:0;font-size:.82rem;font-weight:800;
    letter-spacing:.1em;text-transform:uppercase;
    color:var(--white);
  }
  .ex-card-head .hint{
    margin-left:auto;font-size:.66rem;font-weight:600;
    letter-spacing:.02em;text-transform:none;
    color:var(--muted);font-family:var(--mono);
    padding:3px 9px;border-radius:5px;
    background:rgba(148,163,184,.07);border:1px solid var(--border);
  }

  /* ═══ ROW / FIELDS ═══ */
  .ex-row{display:flex;gap:12px;flex-wrap:wrap;}
  .ex-row>*{flex:1 1 150px;min-width:0;}
  .ex-row.tight>*{flex:0 0 auto;}
  .ex-field{display:flex;flex-direction:column;gap:7px;}
  .ex-field>label{
    font-size:.64rem;font-weight:700;
    letter-spacing:.08em;text-transform:uppercase;
    color:var(--muted);
    display:flex;align-items:center;gap:7px;
  }
  .ex-field>label .opt{
    color:var(--slate);font-size:.58rem;font-weight:500;
    text-transform:none;letter-spacing:0;
    padding:1px 6px;border-radius:4px;
    background:rgba(148,163,184,.08);
  }
  .ex-field>input,.ex-field>select,.ex-field>textarea{
    background:linear-gradient(180deg,#060810,var(--ink2));
    border:1px solid var(--border);border-radius:9px;
    padding:11px 13px;
    color:var(--white);font-size:.84rem;
    font-family:var(--mono);outline:none;
    transition:all .2s var(--ease);
    -webkit-appearance:none;appearance:none;width:100%;
  }
  .ex-field>input:hover,.ex-field>select:hover,.ex-field>textarea:hover{
    border-color:var(--border-hi);
  }
  .ex-field>input:focus,.ex-field>select:focus,.ex-field>textarea:focus{
    border-color:var(--red-hi);
    box-shadow:0 0 0 3px rgba(220,38,38,.2),0 0 12px rgba(220,38,38,.15);
    background:linear-gradient(180deg,#080c18,#0e1322);
  }
  .ex-field>input::placeholder,.ex-field>textarea::placeholder{
    color:rgba(148,163,184,.4);
  }
  .ex-field>textarea{min-height:70px;resize:vertical;}
  .ex-field.invalid>input,.ex-field.invalid>select{
    border-color:rgba(239,68,68,.7);
    box-shadow:0 0 0 3px rgba(239,68,68,.18);
  }
  .ex-field .err{
    font-size:.62rem;color:#f87171;font-family:var(--mono);
    display:none;align-items:center;gap:5px;
  }
  .ex-field.invalid .err{display:flex;}

  /* ═══ BUTTONS ═══ */
  .ex-actions{
    display:flex;gap:10px;flex-wrap:wrap;margin-top:14px;
    align-items:center;
  }
  .ex-btn{
    padding:11px 20px;border-radius:10px;
    border:1px solid transparent;
    font-weight:700;font-size:.82rem;cursor:pointer;
    display:inline-flex;align-items:center;justify-content:center;gap:9px;
    transition:all .22s var(--ease);
    -webkit-appearance:none;appearance:none;
    white-space:nowrap;font-family:inherit;
    position:relative;overflow:hidden;letter-spacing:.01em;
  }
  .ex-btn:focus-visible{
    outline:none;
    box-shadow:0 0 0 3px rgba(220,38,38,.4),0 0 0 1px var(--red-hi);
  }
  .ex-btn:active:not([disabled]){transform:scale(.985);}
  .ex-btn[disabled]{opacity:.55;cursor:not-allowed;transform:none!important;}
  .ex-btn-primary{
    background:linear-gradient(135deg,var(--red-hi) 0%,var(--red) 45%,var(--red-lo) 100%);
    color:#fff;border-color:rgba(239,68,68,.5);
    box-shadow:0 6px 20px rgba(220,38,38,.45),inset 0 1px 0 rgba(255,255,255,.18);
  }
  .ex-btn-primary::after{
    content:"";position:absolute;top:0;left:-100%;width:100%;height:100%;
    background:linear-gradient(90deg,transparent,rgba(255,255,255,.22),transparent);
    transition:left .6s var(--ease);
  }
  .ex-btn-primary:hover:not([disabled]){
    transform:translateY(-2px);
    box-shadow:0 12px 32px rgba(220,38,38,.6),0 0 0 1px rgba(239,68,68,.3),inset 0 1px 0 rgba(255,255,255,.25);
  }
  .ex-btn-primary:hover:not([disabled])::after{left:100%;}
  .ex-btn-danger{
    background:linear-gradient(135deg,#991b1b 0%,#7f1d1d 60%,var(--red-deep) 100%);
    color:#fecaca;border-color:rgba(239,68,68,.4);
    box-shadow:0 4px 14px rgba(127,29,29,.4),inset 0 1px 0 rgba(255,255,255,.08);
  }
  .ex-btn-danger:hover:not([disabled]){
    transform:translateY(-2px);
    background:linear-gradient(135deg,#b91c1c,#991b1b);
    color:#fff;box-shadow:0 12px 28px rgba(185,28,28,.5);
  }
  .ex-btn-ghost{
    background:linear-gradient(180deg,var(--ink2),var(--ink));
    border-color:var(--border);color:var(--muted);
  }
  .ex-btn-ghost:hover:not([disabled]){
    border-color:var(--red-hi);color:var(--white);
    background:linear-gradient(180deg,rgba(220,38,38,.1),rgba(220,38,38,.02));
  }

  /* ═══ PROGRESS ═══ */
  .ex-progress-wrap{margin-top:14px;}
  .ex-progress{
    height:6px;border-radius:3px;
    background:rgba(148,163,184,.12);
    overflow:hidden;position:relative;
  }
  .ex-progress>span{
    display:block;height:100%;width:0%;
    background:linear-gradient(90deg,var(--red-lo),var(--red-hi),#ef4444);
    border-radius:3px;
    transition:width .4s var(--ease-out);
    box-shadow:0 0 12px rgba(239,68,68,.6);
    position:relative;
  }
  .ex-progress>span::after{
    content:"";position:absolute;inset:0;
    background:linear-gradient(90deg,transparent,rgba(255,255,255,.4),transparent);
    background-size:200% 100%;
    animation:exShimmer 2.2s linear infinite;
    opacity:.55;
  }
  @keyframes exShimmer{
    0%{background-position:-200% 0;}
    100%{background-position:200% 0;}
  }
  .ex-progress-label{
    display:flex;justify-content:space-between;gap:12px;
    font-size:.68rem;color:var(--muted);
    margin-top:8px;font-family:var(--mono);
  }
  .ex-progress-label .phase{
    flex:1;min-width:0;overflow:hidden;
    text-overflow:ellipsis;white-space:nowrap;
    display:flex;align-items:center;gap:6px;
  }
  .ex-progress-label .phase i{
    color:var(--red-hi);font-size:.62rem;
    animation:exSpin 1s linear infinite;
  }
  @keyframes exSpin{to{transform:rotate(360deg);}}
  .ex-progress-label .pct{
    color:var(--white);font-weight:700;flex-shrink:0;
  }

  /* ═══ LOG ═══ */
  .ex-log{
    max-height:280px;overflow-y:auto;
    background:linear-gradient(180deg,#030509,#050a14);
    border:1px solid var(--border);border-radius:10px;
    padding:12px 14px 12px 18px;
    font-family:var(--mono);font-size:.72rem;
    color:#cbd5e1;line-height:1.7;margin-top:12px;
    scrollbar-width:thin;
    scrollbar-color:rgba(220,38,38,.4) transparent;
    position:relative;
  }
  .ex-log::before{
    content:"";position:absolute;left:0;top:0;bottom:0;width:3px;
    background:linear-gradient(180deg,var(--red-hi),var(--red-lo),transparent);
    border-radius:2px;
  }
  .ex-log::-webkit-scrollbar{width:6px;}
  .ex-log::-webkit-scrollbar-thumb{
    background:rgba(220,38,38,.35);border-radius:3px;
  }
  .ex-log::-webkit-scrollbar-thumb:hover{background:rgba(220,38,38,.6);}
  .ex-log-line{
    display:flex;gap:9px;align-items:flex-start;
    animation:exLogIn .2s ease-out;
  }
  @keyframes exLogIn{
    from{opacity:0;transform:translateX(-4px);}
    to{opacity:1;transform:translateX(0);}
  }
  .ex-log-time{
    color:var(--slate);font-size:.66rem;flex-shrink:0;
    padding-top:1px;
  }
  .ex-log-msg{flex:1;min-width:0;word-break:break-word;}
  .ex-log-line.ok    .ex-log-msg{color:#4ade80;}
  .ex-log-line.warn  .ex-log-msg{color:#fbbf24;}
  .ex-log-line.err   .ex-log-msg{color:#f87171;}
  .ex-log-line.dim   .ex-log-msg{color:#64748b;}
  .ex-log-line.info  .ex-log-msg{color:#cbd5e1;}

  /* ═══ RESULT ═══ */
  .ex-result-head{
    display:flex;align-items:center;justify-content:space-between;
    gap:10px;margin-bottom:10px;flex-wrap:wrap;
  }
  .ex-result-meta{
    display:flex;align-items:center;gap:10px;
    font-size:.68rem;color:var(--muted);
    font-family:var(--mono);flex-wrap:wrap;
  }
  .ex-result-meta span{
    display:inline-flex;align-items:center;gap:5px;
  }
  .ex-result-meta i{color:var(--red-hi);font-size:.66rem;}
  .ex-copy-btn{
    padding:5px 11px;border-radius:7px;
    border:1px solid var(--border);
    background:linear-gradient(180deg,var(--ink2),var(--ink));
    color:var(--muted);font-family:inherit;
    font-size:.64rem;font-weight:700;letter-spacing:.05em;
    text-transform:uppercase;cursor:pointer;
    display:inline-flex;align-items:center;gap:6px;
    transition:all .18s var(--ease);
  }
  .ex-copy-btn:hover{
    border-color:var(--red-hi);color:#fca5a5;
    background:linear-gradient(180deg,rgba(220,38,38,.12),rgba(220,38,38,.02));
  }
  .ex-copy-btn.copied{
    border-color:rgba(34,197,94,.5);color:#4ade80;
    background:linear-gradient(180deg,rgba(34,197,94,.15),rgba(34,197,94,.03));
  }
  .ex-result{
    background:linear-gradient(180deg,#030509,#050a14);
    border:1px solid var(--border);border-radius:10px;
    padding:15px;
    font-family:var(--mono);font-size:.74rem;
    color:#e2e8f0;white-space:pre-wrap;
    word-break:break-word;
    max-height:460px;overflow-y:auto;
    line-height:1.7;
    scrollbar-width:thin;
    box-shadow:inset 0 2px 6px rgba(0,0,0,.4);
  }
  .ex-result::-webkit-scrollbar{width:6px;}
  .ex-result::-webkit-scrollbar-thumb{background:rgba(220,38,38,.35);border-radius:3px;}
  .ex-result .dim{color:#64748b;}

  /* ═══ BADGES ═══ */
  .ex-badge{
    display:inline-flex;align-items:center;gap:5px;
    padding:3px 10px;border-radius:99px;
    font-size:.6rem;font-weight:800;
    text-transform:uppercase;letter-spacing:.07em;
    border:1px solid;white-space:nowrap;
    font-family:var(--ui);
  }
  .ex-badge::before{
    content:"";width:5px;height:5px;border-radius:50%;background:currentColor;
  }
  .ex-badge-critical{
    background:rgba(220,38,38,.18);color:#fca5a5;
    border-color:rgba(220,38,38,.5);
    box-shadow:0 0 12px -2px rgba(220,38,38,.35);
  }
  .ex-badge-high{
    background:rgba(249,115,22,.18);color:#fdba74;
    border-color:rgba(249,115,22,.5);
  }
  .ex-badge-medium{
    background:rgba(245,158,11,.18);color:#fcd34d;
    border-color:rgba(245,158,11,.5);
  }
  .ex-badge-low{
    background:rgba(59,130,246,.18);color:#93c5fd;
    border-color:rgba(59,130,246,.5);
  }
  .ex-badge-info{
    background:rgba(148,163,184,.14);color:#cbd5e1;
    border-color:rgba(148,163,184,.35);
  }
  .ex-badge-safe{
    background:rgba(34,197,94,.18);color:#86efac;
    border-color:rgba(34,197,94,.5);
  }

  /* ═══ CHIPS ═══ */
  .ex-chips{
    display:flex;flex-wrap:wrap;gap:6px;
    max-height:120px;overflow-y:auto;
    padding:3px 4px 4px 2px;
  }
  .ex-chip{
    padding:6px 12px;border-radius:7px;
    border:1px solid var(--border);
    background:linear-gradient(180deg,var(--ink2),var(--ink));
    color:var(--muted);
    font-family:var(--mono);font-size:.7rem;font-weight:600;
    cursor:pointer;transition:all .16s var(--ease);
    -webkit-appearance:none;appearance:none;
  }
  .ex-chip:hover{
    border-color:var(--red-hi);color:var(--white);
    transform:translateY(-1px);
    box-shadow:0 4px 12px rgba(220,38,38,.2);
  }
  .ex-chip.active{
    background:linear-gradient(135deg,var(--red-hi),var(--red-lo));
    border-color:transparent;color:#fff;font-weight:700;
    box-shadow:0 4px 14px rgba(220,38,38,.5),inset 0 1px 0 rgba(255,255,255,.18);
  }

  /* ═══ FINDINGS ═══ */
  .ex-findings{
    display:flex;flex-direction:column;gap:8px;
    max-height:520px;overflow-y:auto;
    padding-right:4px;
    scrollbar-width:thin;
    scrollbar-color:rgba(220,38,38,.4) transparent;
  }
  .ex-findings::-webkit-scrollbar{width:6px;}
  .ex-findings::-webkit-scrollbar-thumb{background:rgba(220,38,38,.35);border-radius:3px;}

  .ex-finding{
    position:relative;
    background:linear-gradient(180deg,rgba(10,17,34,.9),rgba(5,10,22,.9));
    border-left:4px solid var(--red);
    border-radius:10px;
    padding:13px 16px;
    font-size:.76rem;
    transition:all .18s var(--ease);
    animation:exFindIn .32s var(--ease-out);
  }
  @keyframes exFindIn{
    from{opacity:0;transform:translateX(-8px);}
    to{opacity:1;transform:translateX(0);}
  }
  .ex-finding:hover{
    background:linear-gradient(180deg,rgba(15,26,46,.9),rgba(10,19,37,.9));
    transform:translateX(4px);
    box-shadow:0 6px 20px rgba(0,0,0,.45),0 0 0 1px rgba(220,38,38,.1) inset;
  }
  .ex-finding.critical{border-left-color:var(--red);box-shadow:0 0 18px -8px rgba(220,38,38,.4);}
  .ex-finding.high    {border-left-color:var(--orange);}
  .ex-finding.medium  {border-left-color:var(--amber);}
  .ex-finding.low     {border-left-color:var(--blue);}
  .ex-finding.safe    {border-left-color:var(--green);}
  .ex-finding.info    {border-left-color:var(--slate);}

  .ex-finding-head{
    display:flex;align-items:center;gap:8px;
    margin-bottom:6px;flex-wrap:wrap;
  }
  .ex-finding-head .f-icon{
    width:22px;height:22px;border-radius:6px;
    display:inline-flex;align-items:center;justify-content:center;
    font-size:.7rem;flex-shrink:0;
    background:rgba(220,38,38,.15);color:#fca5a5;
    border:1px solid rgba(220,38,38,.28);
  }
  .ex-finding-head .f-cat{
    font-size:.58rem;text-transform:uppercase;
    letter-spacing:.1em;color:var(--muted);font-weight:800;
  }
  .ex-finding-head .f-title{
    color:var(--white);font-weight:700;font-size:.78rem;
    flex:1;min-width:0;word-break:break-word;
  }
  .ex-finding-value{
    font-family:var(--mono);word-break:break-all;
    color:var(--white);font-size:.72rem;line-height:1.55;
    padding:6px 9px;border-radius:6px;
    background:rgba(5,6,10,.6);
    border:1px solid var(--border);
    margin-top:4px;
  }
  .ex-finding-meta{
    margin-top:8px;font-size:.64rem;color:var(--muted);
    display:flex;gap:12px;flex-wrap:wrap;align-items:center;
    font-family:var(--mono);
  }
  .ex-finding-meta span{display:inline-flex;align-items:center;gap:5px;}
  .ex-finding-meta span strong{color:#cbd5e1;font-weight:600;}
  .ex-finding-secrets{
    margin-top:8px;padding:7px 9px;border-radius:6px;
    background:rgba(220,38,38,.08);
    border:1px solid rgba(220,38,38,.22);
    color:#f87171;font-size:.7rem;font-family:var(--mono);
    display:flex;align-items:flex-start;gap:6px;
  }
  .ex-finding-secrets i{flex-shrink:0;margin-top:2px;}

  /* ═══ EMPTY ═══ */
  .ex-empty{
    padding:34px 20px;text-align:center;
    color:var(--muted);font-size:.8rem;
    display:flex;flex-direction:column;gap:12px;align-items:center;
  }
  .ex-empty svg{
    width:110px;height:74px;opacity:.55;
    filter:drop-shadow(0 6px 18px rgba(220,38,38,.4));
    animation:exEmptyFloat 4.5s ease-in-out infinite;
  }
  @keyframes exEmptyFloat{
    0%,100%{transform:translateY(0);}
    50%{transform:translateY(-5px);}
  }
  .ex-empty .em-title{
    color:var(--white);font-weight:700;
    font-size:.85rem;font-style:normal;letter-spacing:-.01em;
  }
  .ex-empty .em-sub{
    color:var(--slate);font-style:italic;
    font-size:.74rem;max-width:42ch;line-height:1.5;
  }

  /* ═══ CONFIRM ═══ */
  .ex-confirm-overlay{
    position:fixed;inset:0;
    background:rgba(5,6,10,.75);
    backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);
    z-index:99999;
    display:flex;align-items:center;justify-content:center;
    padding:20px;
    animation:exFadeIn .22s var(--ease);
  }
  @keyframes exFadeIn{from{opacity:0;}to{opacity:1;}}
  .ex-confirm{
    background:linear-gradient(165deg,rgba(15,19,31,.98),rgba(5,6,10,.98));
    border:1px solid var(--border-red);
    border-radius:16px;padding:26px 28px;
    max-width:460px;width:100%;
    box-shadow:0 30px 80px rgba(0,0,0,.7),0 0 0 1px rgba(220,38,38,.2),0 0 60px rgba(220,38,38,.1);
    animation:exPopIn .3s var(--ease-out);
    position:relative;overflow:hidden;
  }
  .ex-confirm::before{
    content:"";position:absolute;top:0;left:0;right:0;height:3px;
    background:linear-gradient(90deg,var(--red-hi),var(--red-lo),transparent);
  }
  @keyframes exPopIn{
    from{transform:scale(.92) translateY(8px);opacity:0;}
    to{transform:scale(1) translateY(0);opacity:1;}
  }
  .ex-confirm-icon{
    width:48px;height:48px;border-radius:13px;
    background:linear-gradient(135deg,rgba(220,38,38,.28),rgba(127,29,29,.12));
    display:flex;align-items:center;justify-content:center;
    color:#fca5a5;font-size:1.15rem;
    margin-bottom:14px;
    border:1px solid rgba(220,38,38,.4);
    box-shadow:0 4px 16px rgba(220,38,38,.25);
  }
  .ex-confirm-title{
    font-size:1.05rem;font-weight:800;
    color:var(--white);margin:0 0 8px;
    letter-spacing:-.01em;
  }
  .ex-confirm-msg{
    font-size:.84rem;color:var(--muted);
    line-height:1.6;margin:0 0 22px;
  }
  .ex-confirm-actions{
    display:flex;gap:10px;justify-content:flex-end;
  }

  /* ═══ TOGGLE CHIPS (checkbox replacement) ═══ */
  .ex-toggle{
    display:inline-flex;align-items:center;gap:8px;
    padding:6px 12px;border-radius:8px;
    border:1px solid var(--border);
    background:linear-gradient(180deg,var(--ink2),var(--ink));
    color:var(--muted);font-size:.74rem;font-weight:600;
    cursor:pointer;transition:all .18s var(--ease);
    -webkit-user-select:none;user-select:none;
  }
  .ex-toggle:hover{border-color:var(--border-hi);color:var(--white);}
  .ex-toggle input{
    position:absolute;opacity:0;pointer-events:none;
    width:0;height:0;
  }
  .ex-toggle .sw{
    width:28px;height:16px;border-radius:99px;
    background:rgba(148,163,184,.2);
    position:relative;transition:background .2s;flex-shrink:0;
  }
  .ex-toggle .sw::after{
    content:"";position:absolute;
    top:2px;left:2px;width:12px;height:12px;
    border-radius:50%;background:#94a3b8;
    transition:all .2s var(--ease);
  }
  .ex-toggle input:checked + .sw{
    background:linear-gradient(135deg,var(--red-hi),var(--red-lo));
  }
  .ex-toggle input:checked + .sw::after{
    left:14px;background:#fff;
    box-shadow:0 0 8px rgba(255,255,255,.5);
  }
  .ex-toggle input:checked ~ .lbl{color:var(--white);}

  /* ═══ SIDEBAR ACCENT ═══ */
  .nav-item[data-section="exploit"]:hover,
  .nav-item[data-section="mhddos"]:hover{
    background:linear-gradient(90deg,rgba(220,38,38,.18),transparent 78%) !important;
    border-left-color:#dc2626 !important;color:#fff !important;
  }
  .nav-item[data-section="exploit"]:hover i,
  .nav-item[data-section="mhddos"]:hover i{color:#ef4444 !important;}
  .nav-item[data-section="exploit"].active,
  .nav-item[data-section="mhddos"].active{
    background:linear-gradient(90deg,rgba(220,38,38,.42),rgba(220,38,38,.1) 78%,transparent) !important;
    border-left-color:#ef4444 !important;color:#fff !important;
    font-weight:700 !important;
    box-shadow:inset 3px 0 0 rgba(239,68,68,.85),0 0 18px -6px rgba(220,38,38,.55);
  }
  .nav-item[data-section="exploit"].active i,
  .nav-item[data-section="mhddos"].active i{
    color:#fff !important;filter:drop-shadow(0 0 8px rgba(239,68,68,.85));
  }
  .content-section.active#section-exploit .panel-title i,
  .content-section.active#section-mhddos  .panel-title i{
    color:#ef4444 !important;
    background:linear-gradient(135deg,rgba(220,38,38,.26),rgba(127,29,29,.14)) !important;
    box-shadow:inset 0 0 0 1px rgba(220,38,38,.35);
  }

  /* ═══ TOAST OVERRIDE ═══ */
  .toast{transition:all .3s var(--ease-out);transform:translateX(20px);opacity:0;}
  .toast.toast-in{transform:translateX(0);opacity:1;}
  .toast.toast-out{transform:translateX(20px);opacity:0;}

  /* ═══ RESPONSIVE ═══ */
  @media (max-width:1000px){
    .ex-kpis{grid-template-columns:repeat(2,minmax(0,1fr));}
  }
  @media (max-width:860px){
    .ex-hero{grid-template-columns:1fr;padding:22px 20px;gap:20px;}
    .ex-shark-arena{width:100%;height:118px;}
    .ex-shark{width:170px;height:112px;}
    .ex-hero-side{
      align-items:flex-start;width:100%;
      flex-direction:row;flex-wrap:wrap;
    }
    .ex-title{font-size:1.28rem;}
    .ex-row>*{flex:1 1 100%;}
    .ex-tab-group{
      flex:1 1 100%;
      overflow-x:auto;
      padding:4px;
    }
    .ex-tabs-wrap{padding:10px;}
  }
  @media (max-width:480px){
    .ex-kpis{grid-template-columns:1fr;}
    .ex-card{padding:16px 14px;}
    .ex-hero{padding:18px 16px;}
    .ex-title{font-size:1.12rem;}
    .ex-shark{width:150px;height:100px;}
  }

  @media (prefers-reduced-motion:reduce){
    .ex-shark,.ex-sonar span,.ex-bubbles i,.ex-hero::after,
    .ex-status-pill .dot,.ex-pulse-dot,
    .ex-progress>span::after,.ex-progress-label .phase i,
    .ex-empty svg{animation:none !important;}
    .ex-card,.ex-kpi,.ex-btn,.ex-chip,.ex-tab{transition:none !important;}
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
   *  Shark SVG — matching MHDDoS Command Deck
   * ══════════════════════════════════════════════════════════════════ */
  function sharkSVG() {
    const s = svg('svg', {
      class: 'ex-shark', viewBox: '0 0 240 160',
      xmlns: SVG_NS, 'aria-hidden': 'true',
    });
    const defs = svg('defs');

    // body
    const g1 = svg('linearGradient', { id: 'exBodyG', x1: '0', y1: '0', x2: '0', y2: '1' });
    g1.appendChild(svg('stop', { offset: '0',    'stop-color': '#4b5563' }));
    g1.appendChild(svg('stop', { offset: '0.45', 'stop-color': '#1e293b' }));
    g1.appendChild(svg('stop', { offset: '1',    'stop-color': '#0a0f1a' }));
    defs.appendChild(g1);

    // belly
    const g2 = svg('linearGradient', { id: 'exBellyG', x1: '0', y1: '0', x2: '0', y2: '1' });
    g2.appendChild(svg('stop', { offset: '0', 'stop-color': '#cbd5e1' }));
    g2.appendChild(svg('stop', { offset: '1', 'stop-color': '#64748b' }));
    defs.appendChild(g2);

    // fin main
    const g3 = svg('linearGradient', { id: 'exFinG', x1: '0', y1: '0', x2: '1', y2: '1' });
    g3.appendChild(svg('stop', { offset: '0',   'stop-color': '#ef4444' }));
    g3.appendChild(svg('stop', { offset: '0.5', 'stop-color': '#dc2626' }));
    g3.appendChild(svg('stop', { offset: '1',   'stop-color': '#7f1d1d' }));
    defs.appendChild(g3);

    // fin tail
    const g4 = svg('linearGradient', { id: 'exFinG2', x1: '0', y1: '0', x2: '0', y2: '1' });
    g4.appendChild(svg('stop', { offset: '0', 'stop-color': '#b91c1c' }));
    g4.appendChild(svg('stop', { offset: '1', 'stop-color': '#450a0a' }));
    defs.appendChild(g4);

    // eye
    const g5 = svg('radialGradient', { id: 'exEyeG', cx: '0.35', cy: '0.35', r: '0.65' });
    g5.appendChild(svg('stop', { offset: '0',   'stop-color': '#fef2f2' }));
    g5.appendChild(svg('stop', { offset: '0.4', 'stop-color': '#fca5a5' }));
    g5.appendChild(svg('stop', { offset: '1',   'stop-color': '#7f1d1d' }));
    defs.appendChild(g5);

    // glow filter
    const f = svg('filter', { id: 'exGlowF', x: '-50%', y: '-50%', width: '200%', height: '200%' });
    f.appendChild(svg('feGaussianBlur', { stdDeviation: '2.5', result: 'b' }));
    const merge = svg('feMerge');
    merge.appendChild(svg('feMergeNode', { in: 'b' }));
    merge.appendChild(svg('feMergeNode', { in: 'SourceGraphic' }));
    f.appendChild(merge);
    defs.appendChild(f);

    s.appendChild(defs);

    // water wake
    s.appendChild(svg('path', {
      d: 'M0 128 Q60 122 120 128 T240 128', fill: 'none',
      stroke: '#7f1d1d', 'stroke-width': '1.6', 'stroke-opacity': '0.45', 'stroke-linecap': 'round',
    }));
    s.appendChild(svg('path', {
      d: 'M14 138 Q74 132 134 138 T254 138', fill: 'none',
      stroke: '#7f1d1d', 'stroke-width': '1', 'stroke-opacity': '0.25', 'stroke-linecap': 'round',
    }));

    // tail
    s.appendChild(svg('path', {
      d: 'M18 108 L0 128 L30 122 L26 108 Z',
      fill: 'url(#exFinG2)', stroke: '#450a0a', 'stroke-width': '1.2',
    }));
    s.appendChild(svg('path', {
      d: 'M22 108 L8 92 L28 104 Z',
      fill: 'url(#exFinG)', stroke: '#7f1d1d', 'stroke-width': '1.2', opacity: '0.9',
    }));

    // body
    s.appendChild(svg('path', {
      d: 'M24 104 Q68 82 122 80 Q186 78 228 98 L236 108 Q186 130 122 122 Q68 114 24 104 Z',
      fill: 'url(#exBodyG)', stroke: '#0a0f1a', 'stroke-width': '1.6',
    }));

    // belly
    s.appendChild(svg('path', {
      d: 'M42 106 Q92 118 158 116 Q200 114 226 106 L214 106 Q168 116 122 116 Q78 114 42 106 Z',
      fill: 'url(#exBellyG)', opacity: '0.85',
    }));

    // dorsal
    s.appendChild(svg('path', {
      d: 'M114 78 L148 18 L162 78 Q138 68 114 78 Z',
      fill: 'url(#exFinG)', stroke: '#7f1d1d', 'stroke-width': '1.8',
      filter: 'url(#exGlowF)',
    }));

    // second dorsal
    s.appendChild(svg('path', {
      d: 'M172 82 L186 62 L194 84 Q182 80 172 82 Z',
      fill: 'url(#exFinG)', opacity: '0.9',
    }));

    // pectoral
    s.appendChild(svg('path', {
      d: 'M118 114 L102 140 L136 122 Z',
      fill: 'url(#exFinG)', opacity: '0.95', stroke: '#7f1d1d', 'stroke-width': '1',
    }));

    // gills
    const gills = svg('g', {
      stroke: '#dc2626', 'stroke-width': '1.8', 'stroke-linecap': 'round', opacity: '0.9',
    });
    gills.appendChild(svg('path', { d: 'M162 88 L160 108' }));
    gills.appendChild(svg('path', { d: 'M172 87 L170 108' }));
    gills.appendChild(svg('path', { d: 'M182 86 L180 108' }));
    s.appendChild(gills);

    // teeth
    const teeth = svg('g', { fill: '#fef2f2', stroke: '#7f1d1d', 'stroke-width': '0.5' });
    teeth.appendChild(svg('path', { d: 'M204 105 L206 112 L208 105 Z' }));
    teeth.appendChild(svg('path', { d: 'M210 104 L212 112 L214 104 Z' }));
    teeth.appendChild(svg('path', { d: 'M216 104 L218 111 L220 104 Z' }));
    teeth.appendChild(svg('path', { d: 'M222 104 L224 110 L226 104 Z' }));
    s.appendChild(teeth);
    s.appendChild(svg('path', {
      d: 'M200 104 Q216 112 230 104', fill: 'none',
      stroke: '#450a0a', 'stroke-width': '1.6', 'stroke-linecap': 'round',
    }));

    // eye
    s.appendChild(svg('circle', {
      cx: '212', cy: '94', r: '4', fill: 'url(#exEyeG)', filter: 'url(#exGlowF)',
    }));
    s.appendChild(svg('circle', { cx: '212', cy: '94', r: '1.6', fill: '#020617' }));
    s.appendChild(svg('circle', { cx: '211', cy: '93', r: '0.7', fill: '#fef2f2' }));

    return s;
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Empty state illustration
   * ══════════════════════════════════════════════════════════════════ */
  function emptyState(title, sub) {
    const w = el('div', { class: 'ex-empty' });
    const s = svg('svg', { viewBox: '0 0 120 90', xmlns: SVG_NS, 'aria-hidden': 'true' });
    const defs = svg('defs');
    const g = svg('linearGradient', { id: 'exEmptyF', x1: '0', y1: '0', x2: '1', y2: '1' });
    g.appendChild(svg('stop', { offset: '0',   'stop-color': '#ef4444' }));
    g.appendChild(svg('stop', { offset: '0.6', 'stop-color': '#b91c1c' }));
    g.appendChild(svg('stop', { offset: '1',   'stop-color': '#450a0a' }));
    defs.appendChild(g);
    s.appendChild(defs);
    s.appendChild(svg('path', {
      d: 'M14 66 Q46 54 78 58 L108 34 L100 58 L118 74 L86 72 Q46 82 14 66 Z',
      fill: '#1e293b', stroke: '#dc2626', 'stroke-width': '1.2', 'stroke-opacity': '0.6',
    }));
    s.appendChild(svg('path', { d: 'M62 30 L78 6 L84 32 Q72 28 62 30 Z', fill: 'url(#exEmptyF)' }));
    s.appendChild(svg('path', { d: 'M20 62 L12 78 L32 72 L20 62 Z', fill: 'url(#exEmptyF)', opacity: '0.9' }));
    s.appendChild(svg('circle', { cx: '42', cy: '64', r: '2', fill: '#fef2f2' }));
    s.appendChild(svg('circle', { cx: '42', cy: '64', r: '1', fill: '#7f1d1d' }));
    w.appendChild(s);
    if (title) w.appendChild(el('div', { class: 'em-title' }, title));
    if (sub)   w.appendChild(el('div', { class: 'em-sub' }, sub));
    return w;
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Confirm dialog
   * ══════════════════════════════════════════════════════════════════ */
  function confirmDialog({ title, message, confirmText = 'Confirm', cancelText = 'Cancel', danger = true }) {
    return new Promise((resolve) => {
      const overlay = el('div', { class: 'ex-confirm-overlay', role: 'dialog', 'aria-modal': 'true' });
      const close = (v) => {
        overlay.style.opacity = '0';
        setTimeout(() => overlay.remove(), 200);
        document.removeEventListener('keydown', onKey);
        resolve(v);
      };
      const onKey = (e) => {
        if (e.key === 'Escape') close(false);
        if (e.key === 'Enter')  close(true);
      };
      const card = el('div', { class: 'ex-confirm' },
        el('div', { class: 'ex-confirm-icon' },
          el('i', { class: danger ? 'fas fa-triangle-exclamation' : 'fas fa-circle-question' })),
        el('h3', { class: 'ex-confirm-title' }, title),
        el('p',  { class: 'ex-confirm-msg' }, message),
        el('div', { class: 'ex-confirm-actions' },
          el('button', {
            class: 'ex-btn ex-btn-ghost', type: 'button',
            onclick: () => close(false),
          }, cancelText),
          el('button', {
            class: 'ex-btn ' + (danger ? 'ex-btn-danger' : 'ex-btn-primary'),
            type: 'button',
            onclick: () => close(true),
          }, confirmText),
        ),
      );
      overlay.appendChild(card);
      document.body.appendChild(overlay);
      document.addEventListener('keydown', onKey);
      setTimeout(() => {
        const btn = card.querySelector('.ex-btn-danger, .ex-btn-primary');
        if (btn) btn.focus();
      }, 60);
    });
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Reusable component builders
   * ══════════════════════════════════════════════════════════════════ */
  function buildHero(statusPill, statusText, clockVal) {
    const sonar = el('div', { class: 'ex-sonar' },
      el('span'), el('span'), el('span'));
    const bubbles = el('div', { class: 'ex-bubbles' },
      el('i'), el('i'), el('i'), el('i'));

    const arena = el('div', { class: 'ex-shark-arena', 'aria-hidden': 'true' },
      sonar, bubbles, sharkSVG());

    return el('div', { class: 'ex-hero' },
      arena,
      el('div', { class: 'ex-hero-copy' },
        el('div', { class: 'ex-eyebrow' },
          'Predator Mode',
          el('span', { class: 'ex-ver' }, 'v' + VERSION)),
        el('h3', { class: 'ex-title' },
          el('span', { class: 'ex-pulse-dot' }),
          'Exploit ',
          el('span', { class: 'ex-title-red' }, 'Command Deck')),
        el('p', { class: 'ex-subtitle' },
          'Dirfuzz · SQLi · SQLMap · SQL-lite · XSS · XSS-lite · Sniper — ',
          el('b', null, 'authorised targets only'),
          '. All modules stream live results; every request is rate-limited and cancellable.'),
      ),
      el('div', { class: 'ex-hero-side' },
        statusPill,
        el('div', { class: 'ex-clock' },
          el('i', { class: 'fas fa-clock' }),
          'UTC ',
          clockVal)),
      el('div', { class: 'ex-hero-teeth', 'aria-hidden': 'true' }),
    );
  }

  function buildKPIs(refs) {
    const kpiScans    = el('div', { class: 'ex-kpi-value' }, '0', el('small', null, 'this session'));
    const kpiFindings = el('div', { class: 'ex-kpi-value' }, '0', el('small', null, 'total'));
    const kpiCritical = el('div', { class: 'ex-kpi-value' }, '0', el('small', null, 'critical+high'));
    const kpiTime     = el('div', { class: 'ex-kpi-value' }, '0s', el('small', null, 'elapsed'));
    refs.kpiScans = kpiScans;
    refs.kpiFindings = kpiFindings;
    refs.kpiCritical = kpiCritical;
    refs.kpiTime = kpiTime;

    return el('div', { class: 'ex-kpis' },
      el('div', { class: 'ex-kpi' },
        el('div', { class: 'ex-kpi-head' },
          el('i', { class: 'fas fa-play-circle' }), 'Scans'),
        kpiScans),
      el('div', { class: 'ex-kpi' },
        el('div', { class: 'ex-kpi-head' },
          el('i', { class: 'fas fa-bug' }), 'Findings'),
        kpiFindings),
      el('div', { class: 'ex-kpi' },
        el('div', { class: 'ex-kpi-head' },
          el('i', { class: 'fas fa-triangle-exclamation' }), 'Critical / High'),
        kpiCritical),
      el('div', { class: 'ex-kpi' },
        el('div', { class: 'ex-kpi-head' },
          el('i', { class: 'fas fa-stopwatch' }), 'Session'),
        kpiTime),
    );
  }

  function buildCard(title, icon, hint, ...children) {
    return el('div', { class: 'ex-card' },
      el('div', { class: 'ex-card-head' },
        el('i', { class: 'ico fas ' + icon }),
        el('h4', null, title),
        hint ? el('span', { class: 'hint' }, hint) : null),
      ...children);
  }

  function buildField(label, input, opt) {
    return el('div', { class: 'ex-field' },
      el('label', null, label, opt ? el('span', { class: 'opt' }, opt) : null),
      input);
  }

  function buildToggle(text, checked = false) {
    const input = el('input', { type: 'checkbox' });
    if (checked) input.checked = true;
    const wrap = el('label', { class: 'ex-toggle' },
      input,
      el('span', { class: 'sw', 'aria-hidden': 'true' }),
      el('span', { class: 'lbl' }, text));
    wrap._input = input;
    return wrap;
  }

  function buildProgress() {
    const bar    = el('span', { style: 'width:0%;' });
    const track  = el('div', { class: 'ex-progress' }, bar);
    const phase  = el('span', null,
      el('i', { class: 'fas fa-spinner' }),
      ' Idle');
    const pct    = el('span', { class: 'pct' }, '0%');
    const label  = el('div', { class: 'ex-progress-label' },
      el('span', { class: 'phase' }, phase), pct);
    const root   = el('div', { class: 'ex-progress-wrap' }, track, label);

    root._set = (p, msg) => {
      const clamped = Math.max(0, Math.min(100, p));
      bar.style.width = clamped + '%';
      pct.textContent = Math.round(clamped) + '%';
      if (msg != null) phase.innerHTML = '';
      if (msg != null) {
        phase.appendChild(el('i', { class: 'fas fa-spinner' }));
        phase.appendChild(document.createTextNode(' ' + msg));
      }
    };
    root._idle = () => {
      bar.style.width = '0%';
      pct.textContent = '0%';
      phase.innerHTML = '';
      phase.appendChild(el('i', { class: 'fas fa-spinner' }));
      phase.appendChild(document.createTextNode(' Idle'));
    };
    root._done = (msg) => {
      bar.style.width = '100%';
      pct.textContent = '100%';
      phase.innerHTML = '';
      phase.appendChild(el('i', { class: 'fas fa-check' }));
      phase.appendChild(document.createTextNode(' ' + (msg || 'Complete')));
    };
    return root;
  }

  function buildLogPanel() {
    const root = el('div', { class: 'ex-log' });
    root._append = (msg, cls) => {
      const line = el('div', { class: 'ex-log-line ' + (cls || 'info') },
        el('span', { class: 'ex-log-time' }, timeStamp()),
        el('span', { class: 'ex-log-msg' }, msg));
      root.appendChild(line);
      root.scrollTop = root.scrollHeight;
      while (root.childNodes.length > 600) root.removeChild(root.firstChild);
    };
    root._clear = () => { root.textContent = ''; };
    return root;
  }

  function buildResultPanel() {
    const body = el('div', { class: 'ex-result' });
    body.textContent = 'No results yet.';
    const meta = el('div', { class: 'ex-result-meta' });
    const copyBtn = el('button', {
      class: 'ex-copy-btn', type: 'button',
    }, el('i', { class: 'fas fa-copy' }), 'Copy JSON');
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(body.textContent);
        copyBtn.classList.add('copied');
        copyBtn.innerHTML = '';
        copyBtn.appendChild(el('i', { class: 'fas fa-check' }));
        copyBtn.appendChild(document.createTextNode(' Copied'));
        setTimeout(() => {
          copyBtn.classList.remove('copied');
          copyBtn.innerHTML = '';
          copyBtn.appendChild(el('i', { class: 'fas fa-copy' }));
          copyBtn.appendChild(document.createTextNode(' Copy JSON'));
        }, 1800);
      } catch (_) { toast('Copy failed', 'warn'); }
    });
    const head = el('div', { class: 'ex-result-head' }, meta, copyBtn);
    const root = el('div', null, head, body);
    root._set = (data) => {
      body.textContent = (typeof data === 'string') ? data : pretty(data);
      body.scrollTop = 0;
    };
    root._clear = () => { body.textContent = 'No results yet.'; meta.innerHTML = ''; };
    root._meta = meta;
    return root;
  }

  function severityBadge(sev) {
    const s = String(sev || 'info').toLowerCase();
    return el('span', { class: 'ex-badge ex-badge-' + s }, s);
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Tab definitions — grouped
   * ══════════════════════════════════════════════════════════════════ */
  const TAB_GROUPS = [
    {
      label: 'Recon',
      tabs: [
        { id: 'dirfuzz', label: 'Dirfuzz', icon: 'fa-folder-tree' },
        { id: 'sniper',  label: 'Sniper',  icon: 'fa-crosshairs' },
      ],
    },
    {
      label: 'Injection',
      tabs: [
        { id: 'sqli',   label: 'SQLi',       icon: 'fa-database' },
        { id: 'sqlmap', label: 'SQLMap',     icon: 'fa-magnifying-glass-chart' },
        { id: 'sqlinj', label: 'SQL · light', icon: 'fa-bolt' },
      ],
    },
    {
      label: 'XSS',
      tabs: [
        { id: 'xss',       label: 'XSS',        icon: 'fa-code' },
        { id: 'xssSimple', label: 'XSS · simple', icon: 'fa-wand-magic' },
      ],
    },
  ];

  const ALL_TABS = TAB_GROUPS.flatMap(g => g.tabs);

  /* ══════════════════════════════════════════════════════════════════
   *  Tab builders
   * ══════════════════════════════════════════════════════════════════ */
  function makeTabBuilders(instanceName, state, refs) {
    const pid = (id) => 'ex-tab-' + instanceName + '-' + id;

    function trackScan() {
      state.kpi.scans += 1;
      updateKPIsUI();
    }
    function trackFindings(list, severityKey = 'severity') {
      let critHigh = 0;
      list.forEach(f => {
        const s = String(f[severityKey] || '').toLowerCase();
        if (s === 'critical' || s === 'high') critHigh++;
      });
      state.kpi.findings += list.length;
      state.kpi.critHigh += critHigh;
      updateKPIsUI();
    }
    function updateKPIsUI() {
      if (!refs.kpiScans) return;
      refs.kpiScans.firstChild.nodeValue = String(state.kpi.scans);
      refs.kpiFindings.firstChild.nodeValue = String(state.kpi.findings);
      refs.kpiCritical.firstChild.nodeValue = String(state.kpi.critHigh);
      flashKpi(refs.kpiScans);
    }
    function flashKpi(node) {
      if (!node) return;
      const kpi = node.closest('.ex-kpi');
      if (!kpi) return;
      kpi.classList.remove('flash');
      void kpi.offsetWidth;
      kpi.classList.add('flash');
      setTimeout(() => kpi.classList.remove('flash'), 900);
    }

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
      const follow    = buildToggle('Follow redirects', false);
      const streamTgl = buildToggle('Stream (SSE)', true);

      const startBtn = el('button', { class: 'ex-btn ex-btn-primary', type: 'button' },
        el('i', { class: 'fas fa-play' }), 'Start Scan');
      const stopBtn  = el('button', { class: 'ex-btn ex-btn-ghost', type: 'button', disabled: true },
        el('i', { class: 'fas fa-stop' }), 'Stop');

      const progress    = buildProgress();
      const logPanel    = buildLogPanel();
      const findingsBox = el('div', { class: 'ex-findings' });
      findingsBox.appendChild(emptyState('No hits yet', 'Run a scan to see directory & file findings here.'));

      (async () => {
        try {
          const res = await jget(EP.dirfuzz.wordlists);
          (res.wordlists || []).forEach(w => {
            wordlist.appendChild(el('option', { value: w.name }, `${w.name} (${w.count || 0})`));
          });
        } catch (_) {}
        if (!wordlist.options.length) {
          wordlist.appendChild(el('option', { value: 'lottery-dirs.txt' }, 'lottery-dirs.txt'));
        }
      })();

      function renderHits(hits) {
        findingsBox.textContent = '';
        if (!hits || !hits.length) {
          findingsBox.appendChild(emptyState('No hits', 'Nothing was found for this wordlist.'));
          return;
        }
        hits.slice(0, 200).forEach(h => {
          const secrets = Array.isArray(h.secrets)
            ? h.secrets.map(s => (s && s.type) ? s.type : String(s)).join(', ')
            : '';
          const f = el('div', { class: 'ex-finding ' + (h.severity || 'info') },
            el('div', { class: 'ex-finding-head' },
              el('span', { class: 'f-icon' }, el('i', { class: 'fas fa-folder-open' })),
              el('span', { class: 'f-cat' }, h.category || 'other'),
              el('span', { class: 'f-title' }, h.url || h.path || '')),
            h.url ? el('div', { class: 'ex-finding-value' }, h.url) : null,
            el('div', { class: 'ex-finding-meta' },
              el('span', null, el('i', { class: 'fas fa-signal', style: 'color:#94a3b8;' }),
                ' Status ', el('strong', null, String(h.status || '—'))),
              el('span', null, el('i', { class: 'fas fa-weight-hanging', style: 'color:#94a3b8;' }),
                ' Size ', el('strong', null, String(h.size || 0))),
              el('span', null, severityBadge(h.severity)),
              h.redirect_to ? el('span', null, '→ ', el('strong', null, h.redirect_to)) : null),
            secrets ? el('div', { class: 'ex-finding-secrets' },
              el('i', { class: 'fas fa-key' }),
              ' Secrets: ', secrets) : null);
          findingsBox.appendChild(f);
        });
      }

      const resetButtons = () => { startBtn.disabled = false; stopBtn.disabled = true; };

      function applyResult(data) {
        progress._done('Complete');
        logPanel._append(`tried=${data.tried} · hits=${data.hits_count} · elapsed=${data.elapsed}s`, 'ok');
        renderHits(data.hits || []);
        trackScan();
        trackFindings(data.hits || []);
        resetButtons();
      }

      async function startBlocking() {
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._idle(); progress._set(0, 'Running…');
        logPanel._clear();
        logPanel._append('Starting dirfuzz (blocking mode)…', 'dim');
        try {
          const body = {
            target:           target.value.trim(),
            wordlist_name:    wordlist.value,
            max_paths:        parseInt(maxPaths.value, 10) || 200,
            concurrency:      parseInt(conc.value, 10)     || 24,
            rate_limit:       parseFloat(rate.value)       || 40,
            timeout:          parseFloat(timeout.value)    || 4,
            follow_redirects: !!follow._input.checked,
          };
          if (!body.target) { toast('Target required', 'warn'); resetButtons(); return; }
          applyResult(await jpost(EP.dirfuzz.scan, body));
        } catch (e) {
          logPanel._append('Error: ' + e.message, 'err');
          toast('Dirfuzz failed: ' + e.message, 'err');
          resetButtons();
        }
      }

      function startStreaming() {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._idle(); progress._set(0, 'Connecting…');
        logPanel._clear();
        logPanel._append('Opening SSE stream…', 'dim');

        const qs = new URLSearchParams({
          target:           t,
          wordlist_name:    wordlist.value,
          max_paths:        maxPaths.value,
          concurrency:      conc.value,
          rate_limit:       rate.value,
          timeout:          timeout.value,
          follow_redirects: follow._input.checked ? '1' : '0',
        });

        openSSE('dirfuzz', EP.dirfuzz.stream + '?' + qs.toString(), {
          message: (data) => {
            if (data.type === 'progress') {
              progress._set(data.percent || 0, `${data.label || ''} · ${data.done}/${data.total}`);
            } else if (data.type === 'result') {
              applyResult(data.data || {});
            } else if (data.type === 'error') {
              logPanel._append('Error: ' + data.message, 'err');
            } else if (data.type === 'start') {
              logPanel._append('Connected · ' + (data.base || ''), 'dim');
            }
          },
          onError: () => { logPanel._append('SSE connection error', 'warn'); resetButtons(); },
          onEnd:   (data) => { if (data && data.type === 'error') resetButtons(); },
          parse:   (e) => logPanel._append('Parse error: ' + e.message, 'warn'),
        });
      }

      startBtn.addEventListener('click', () => {
        if (!target.value.trim()) { toast('Target required', 'warn'); return; }
        if (streamTgl._input.checked) startStreaming(); else startBlocking();
      });
      stopBtn.addEventListener('click', () => {
        closeSSE('dirfuzz');
        logPanel._append('Stopped by operator', 'warn');
        resetButtons();
        progress._set(0, 'Stopped');
      });

      return el('div', { class: 'ex-panel', id: pid('dirfuzz') },
        buildCard('Directory / File Fuzzer', 'fa-folder-tree', 'soft-404 aware',
          el('div', { class: 'ex-row' },
            buildField('Target', target, 'required'),
            buildField('Wordlist', wordlist)),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Max paths', maxPaths),
            buildField('Concurrency', conc),
            buildField('Rate limit (req/s)', rate),
            buildField('Timeout (s)', timeout)),
          el('div', { class: 'ex-actions' },
            follow, streamTgl,
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
      const streamTgl   = buildToggle('Stream (SSE)', true);

      const progress    = buildProgress();
      const logPanel    = buildLogPanel();
      const resultPanel = buildResultPanel();

      const resetButtons = () => { startBtn.disabled = false; stopBtn.disabled = true; };

      function applyResult(data) {
        progress._done('Complete');
        logPanel._append(
          `vulnerable=${data.vulnerable} · findings=${(data.findings || []).length} · elapsed=${data.elapsed}s`,
          data.vulnerable ? 'err' : 'ok');
        resultPanel._set(data);
        trackScan();
        trackFindings(data.findings || []);
        resetButtons();
      }

      async function runBlocking() {
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._idle(); progress._set(0, 'Running…');
        logPanel._clear();
        logPanel._append('Starting SQLi engine (blocking mode)…', 'dim');
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
          logPanel._append('Error: ' + e.message, 'err');
          toast('SQLi scan failed: ' + e.message, 'err');
          resetButtons();
        }
      }

      function runStreaming() {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._idle(); progress._set(0, 'Connecting…');
        logPanel._clear();
        logPanel._append('Opening SSE stream…', 'dim');

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
              progress._set(data.percent || 0, `${data.label || ''} · ${data.done}/${data.total}`);
            } else if (data.type === 'result') {
              applyResult(data.data || {});
            } else if (data.type === 'error') {
              logPanel._append('Error: ' + data.message, 'err');
            } else if (data.type === 'start') {
              logPanel._append('Connected · ' + (data.url || ''), 'dim');
            }
          },
          onError: () => { logPanel._append('SSE connection error', 'warn'); resetButtons(); },
          onEnd:   (data) => { if (data && data.type === 'error') resetButtons(); },
          parse:   (e) => logPanel._append('Parse error: ' + e.message, 'warn'),
        });
      }

      startBtn.addEventListener('click', () => {
        if (!target.value.trim()) { toast('Target required', 'warn'); return; }
        if (streamTgl._input.checked) runStreaming(); else runBlocking();
      });
      stopBtn.addEventListener('click', () => {
        closeSSE('sqli');
        logPanel._append('Stopped by operator', 'warn');
        resetButtons();
      });

      return el('div', { class: 'ex-panel', id: pid('sqli') },
        buildCard('SQL Injection Engine', 'fa-database', '4 techniques · wordlist driven',
          el('div', { class: 'ex-row' },
            buildField('Target URL', target, 'required'),
            buildField('Method', method)),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Max params', maxParams),
            buildField('Rate limit',  rate),
            buildField('Timeout (s)', timeout)),
          el('div', { style: 'margin-top:12px;' },
            el('label', { style: 'font-size:.64rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#8b95a7;display:block;margin-bottom:8px;' },
              'Techniques'),
            techniquesWrap),
          el('div', { class: 'ex-actions' },
            streamTgl,
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
        logPanel._append('Running sqlmap · ' + mode.value + ' mode…', 'dim');
        try {
          const res = await jpost(EP.sqlmap.scan, {
            target:      t,
            mode:        mode.value,
            method:      method.value,
            max_threads: parseInt(maxThreads.value, 10) || 10,
            timeout:     parseFloat(timeout.value)      || 5,
          });
          logPanel._append('Scan complete · type=' + ((res.data && res.data.scan_type) || 'sqli'), 'ok');
          resultPanel._set(res);
          trackScan();
          if (res.findings) trackFindings(res.findings);
        } catch (e) {
          logPanel._append('Error: ' + e.message, 'err');
          toast('SQLMap failed: ' + e.message, 'err');
        } finally {
          runBtn.disabled = false;
        }
      });

      return el('div', { class: 'ex-panel', id: pid('sqlmap') },
        buildCard('SQLMap — Multi-Technique Scanner', 'fa-magnifying-glass-chart', 'confidence scored',
          el('div', { class: 'ex-row' }, buildField('Target URL', target, 'required')),
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
        logPanel._append('Running lightweight SQLi…', 'dim');
        try {
          const res = await jpost(EP.sqlinj.scan, {
            target: t,
            method: method.value,
            params: parseQS(t),
          });
          logPanel._append(
            `vulnerable=${res.vulnerable} · findings=${(res.findings || []).length}`,
            res.vulnerable ? 'err' : 'ok');
          resultPanel._set(res);
          trackScan();
          if (res.findings) trackFindings(res.findings);
        } catch (e) {
          logPanel._append('Error: ' + e.message, 'err');
          toast('SQLi scan failed: ' + e.message, 'err');
        } finally {
          runBtn.disabled = false;
        }
      });

      return el('div', { class: 'ex-panel', id: pid('sqlinj') },
        buildCard('Lightweight SQL Injection Test', 'fa-bolt', 'fast heuristic',
          el('div', { class: 'ex-row' },
            buildField('Target URL', target, 'required'),
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
      const wafBypass   = buildToggle('WAF bypass', false);
      const streamTgl   = buildToggle('Stream (SSE)', true);

      const startBtn    = el('button', { class: 'ex-btn ex-btn-primary', type: 'button' },
        el('i', { class: 'fas fa-play' }), 'Start');
      const stopBtn     = el('button', { class: 'ex-btn ex-btn-ghost', type: 'button', disabled: true },
        el('i', { class: 'fas fa-stop' }), 'Stop');

      const progress    = buildProgress();
      const logPanel    = buildLogPanel();
      const findingsBox = el('div', { class: 'ex-findings' });
      findingsBox.appendChild(emptyState('No XSS vectors yet', 'Run a scan to see findings here.'));

      const resetButtons = () => { startBtn.disabled = false; stopBtn.disabled = true; };

      function renderFindings(findings) {
        findingsBox.textContent = '';
        if (!findings || !findings.length) {
          findingsBox.appendChild(emptyState('No XSS vectors found', 'No reflected payloads were confirmed.'));
          return;
        }
        findings.forEach(f => {
          findingsBox.appendChild(el('div', { class: 'ex-finding ' + (f.severity || 'medium') },
            el('div', { class: 'ex-finding-head' },
              el('span', { class: 'f-icon' }, el('i', { class: 'fas fa-code' })),
              el('span', { class: 'f-cat' }, f.context || 'reflected'),
              el('span', { class: 'f-title' }, f.parameter || '—')),
            el('div', { class: 'ex-finding-value' }, f.payload || ''),
            el('div', { class: 'ex-finding-meta' },
              el('span', null, el('i', { class: 'fas fa-signal', style: 'color:#94a3b8;' }),
                ' Status ', el('strong', null, String(f.status_code || '—'))),
              el('span', null, el('i', { class: 'fas fa-gauge', style: 'color:#94a3b8;' }),
                ' Confidence ', el('strong', null, String(f.confidence || '—'))),
              el('span', null, severityBadge(f.severity))),
            f.evidence
              ? el('div', { class: 'ex-finding-value', style: 'color:#94a3b8;font-size:.7rem;' },
                  String(f.evidence).slice(0, 220))
              : null));
        });
      }

      function applyResult(data) {
        progress._done('Complete');
        logPanel._append(
          `vulnerable=${data.vulnerable} · findings=${(data.findings || []).length}`,
          data.vulnerable ? 'err' : 'ok');
        renderFindings(data.findings || []);
        trackScan();
        trackFindings(data.findings || []);
        resetButtons();
      }

      async function startBlocking() {
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._idle(); progress._set(0, 'Running…');
        logPanel._clear();
        logPanel._append('Starting XSS exploiter (blocking)…', 'dim');
        try {
          const body = {
            target:       target.value.trim(),
            method:       method.value,
            max_payloads: parseInt(maxPayloads.value, 10) || 30,
            max_params:   parseInt(maxParams.value, 10)   || 10,
            concurrency:  parseInt(conc.value, 10)        || 8,
            rate_limit:   parseFloat(rate.value)          || 20,
            waf_bypass:   !!wafBypass._input.checked,
          };
          if (!body.target) { toast('Target required', 'warn'); resetButtons(); return; }
          applyResult(await jpost(EP.xss.scan, body));
        } catch (e) {
          logPanel._append('Error: ' + e.message, 'err');
          toast('XSS scan failed: ' + e.message, 'err');
          resetButtons();
        }
      }

      function startStreaming() {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._idle(); progress._set(0, 'Connecting…');
        logPanel._clear();
        logPanel._append('Opening SSE stream…', 'dim');

        const qs = new URLSearchParams({
          target:       t,
          method:       method.value,
          max_payloads: maxPayloads.value,
          max_params:   maxParams.value,
          concurrency:  conc.value,
          rate_limit:   rate.value,
          waf_bypass:   wafBypass._input.checked ? '1' : '0',
        });

        openSSE('xss', EP.xss.stream + '?' + qs.toString(), {
          message: (data) => {
            if (data.type === 'progress') {
              progress._set(data.percent || 0, `${data.label || ''} · ${data.done}/${data.total}`);
            } else if (data.type === 'result') {
              applyResult(data.data || {});
            } else if (data.type === 'error') {
              logPanel._append('Error: ' + data.message, 'err');
            } else if (data.type === 'start') {
              logPanel._append('Connected · ' + (data.url || ''), 'dim');
            }
          },
          onError: () => { logPanel._append('SSE connection error', 'warn'); resetButtons(); },
          onEnd:   (data) => { if (data && data.type === 'error') resetButtons(); },
          parse:   (e) => logPanel._append('Parse error: ' + e.message, 'warn'),
        });
      }

      startBtn.addEventListener('click', () => {
        if (!target.value.trim()) { toast('Target required', 'warn'); return; }
        if (streamTgl._input.checked) startStreaming(); else startBlocking();
      });
      stopBtn.addEventListener('click', () => {
        closeSSE('xss');
        logPanel._append('Stopped by operator', 'warn');
        resetButtons();
      });

      return el('div', { class: 'ex-panel', id: pid('xss') },
        buildCard('XSS Exploiter', 'fa-code', 'reflected · context aware',
          el('div', { class: 'ex-row' },
            buildField('Target URL', target, 'required'),
            buildField('Method', method)),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Max payloads', maxPayloads),
            buildField('Max params',   maxParams),
            buildField('Concurrency',  conc),
            buildField('Rate limit',   rate)),
          el('div', { class: 'ex-actions' },
            wafBypass, streamTgl,
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
          const res = await jpost(EP.xssSimple.scan, { target: t, mode: mode.value });
          resultPanel._set(res);
          trackScan();
          if (res.findings) trackFindings(res.findings);
        } catch (e) {
          toast('XSS scan failed: ' + e.message, 'err');
        } finally {
          runBtn.disabled = false;
        }
      });

      return el('div', { class: 'ex-panel', id: pid('xssSimple') },
        buildCard('Reflected XSS (Simple)', 'fa-wand-magic', 'quick check',
          el('div', { class: 'ex-row' },
            buildField('Target URL', target, 'required'),
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
      const streamTgl     = buildToggle('Stream (SSE)', true);

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
        progress._idle(); progress._set(0, 'Running…');
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
          progress._done('Complete');
          logPanel._append(`risk=${res.risk_score}/100 (${res.risk_level}) · elapsed=${res.elapsed}s`, 'ok');
          resultPanel._set(res);
          trackScan();
          if (res.findings) trackFindings(res.findings);
        } catch (e) {
          logPanel._append('Error: ' + e.message, 'err');
          toast('Sniper failed: ' + e.message, 'err');
        } finally {
          resetButtons();
        }
      }

      function runStreaming() {
        const t = target.value.trim();
        if (!t) { toast('Target required', 'warn'); return; }
        startBtn.disabled = true; stopBtn.disabled = false;
        progress._idle(); progress._set(0, 'Connecting…');
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
              logPanel._append('Sniper started · modules: ' + (data.modules || []).join(', '), 'dim');
            } else if (data.type === 'module_start') {
              logPanel._append('▶ ' + data.module, 'dim');
            } else if (data.type === 'progress') {
              progress._set(data.pct || 0, `${data.module}: ${data.message || ''}`);
            } else if (data.type === 'module_done') {
              logPanel._append(
                `◀ ${data.module} · ${data.findings} finding(s) · ${data.elapsed}s`,
                data.ok ? 'ok' : 'warn');
            } else if (data.type === 'heartbeat') {
              logPanel._append(`♥ elapsed=${data.elapsed}s · ${data.modules_done}/${data.modules_total}`, 'dim');
            } else if (data.type === 'complete') {
              progress._done('Complete');
              const rep = data.report || {};
              logPanel._append(`risk=${rep.risk_score}/100 (${rep.risk_level})`, 'ok');
              resultPanel._set(rep);
              trackScan();
              if (rep.findings) trackFindings(rep.findings);
            } else if (data.type === 'error') {
              logPanel._append('Error: ' + data.message, 'err');
            }
          },
          onError: () => { logPanel._append('SSE connection error', 'warn'); resetButtons(); },
          onEnd:   (data) => { if (data && data.type === 'error') resetButtons(); },
          parse:   (e) => logPanel._append('Parse error: ' + e.message, 'warn'),
        });
      }

      startBtn.addEventListener('click', () => {
        if (!target.value.trim()) { toast('Target required', 'warn'); return; }
        if (streamTgl._input.checked) runStreaming(); else runBlocking();
      });
      stopBtn.addEventListener('click', () => {
        closeSSE('sniper');
        logPanel._append('Stopped by operator', 'warn');
        resetButtons();
      });

      return el('div', { class: 'ex-panel', id: pid('sniper') },
        buildCard('Sniper — Auto-Exploiter', 'fa-crosshairs', 'all modules · correlation',
          el('div', { class: 'ex-row' }, buildField('Target', target, 'required')),
          el('div', { class: 'ex-row', style: 'margin-top:10px;' },
            buildField('Module timeout (s)', moduleTimeout),
            buildField('Global budget (s)',  globalBudget),
            buildField('Dirfuzz max paths',  dirfuzzMax),
            buildField('XSS max payloads',   xssMax),
            buildField('Takeover max hosts', takeoverMax)),
          el('div', { class: 'ex-actions' },
            streamTgl,
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
      sessionStart: Date.now(),
      kpi: { scans: 0, findings: 0, critHigh: 0 },
      timers: Object.create(null),
    };
    const refs = {};

    const TAB_BUILDERS = makeTabBuilders(instanceName, state, refs);

    function buildUI(defaultTab) {
      /* ── status pill + clock ── */
      const statusText = el('span', { class: 'ex-status-text' }, 'Idle');
      const statusPill = el('span', { class: 'ex-status-pill is-idle', role: 'status', 'aria-live': 'polite' },
        el('span', { class: 'dot' }), statusText);
      refs.statusPill = statusPill;
      refs.statusText = statusText;

      const clockVal = el('b', null, '—');
      refs.clockVal = clockVal;

      /* ── KPI ribbon ── */
      const kpis = buildKPIs(refs);

      /* ── hero ── */
      const hero = buildHero(statusPill, statusText, clockVal);

      /* ── tab bar grouped ── */
      const tabsRow = el('div', { class: 'ex-tabs', role: 'tablist', 'aria-label': 'Exploit modules' });
      const buttons = {};
      const panels = {};

      TAB_GROUPS.forEach(grp => {
        const groupEl = el('div', { class: 'ex-tab-group' });
        groupEl.appendChild(el('span', { class: 'ex-tab-group-label' }, grp.label));
        grp.tabs.forEach(t => {
          const btn = el('button', {
            class: 'ex-tab' + (t.id === defaultTab ? ' active' : ''),
            type: 'button', role: 'tab',
            'aria-selected': t.id === defaultTab ? 'true' : 'false',
            'aria-controls': 'ex-tab-' + instanceName + '-' + t.id,
            'data-tab': t.id,
            tabindex: t.id === defaultTab ? '0' : '-1',
          },
            el('span', { class: 'ex-tab-ico', 'aria-hidden': 'true' },
              el('i', { class: 'fas ' + t.icon })),
            t.label);
          btn.addEventListener('click', () => switchTab(t.id));
          btn.addEventListener('keydown', (ev) => {
            const order = ALL_TABS.map(x => x.id);
            const i = order.indexOf(t.id);
            if (ev.key === 'ArrowRight') { ev.preventDefault(); buttons[order[(i + 1) % order.length]].focus(); }
            if (ev.key === 'ArrowLeft')  { ev.preventDefault(); buttons[order[(i - 1 + order.length) % order.length]].focus(); }
            if (ev.key === 'Home')       { ev.preventDefault(); buttons[order[0]].focus(); }
            if (ev.key === 'End')        { ev.preventDefault(); buttons[order[order.length - 1]].focus(); }
          });
          buttons[t.id] = btn;
          groupEl.appendChild(btn);
        });
        tabsRow.appendChild(groupEl);
      });

      const tabsWrap = el('div', { class: 'ex-tabs-wrap' }, tabsRow);

      /* ── panels ── */
      const body = el('div');
      ALL_TABS.forEach(t => {
        const panel = TAB_BUILDERS[t.id]();
        panel.classList.toggle('active', t.id === defaultTab);
        panel.setAttribute('role', 'tabpanel');
        panels[t.id] = panel;
        body.appendChild(panel);
      });

      function switchTab(id) {
        if (!ALL_TABS.some(t => t.id === id)) return false;
        state.activeTab = id;
        ALL_TABS.forEach(t => {
          const active = t.id === id;
          buttons[t.id].classList.toggle('active', active);
          buttons[t.id].setAttribute('aria-selected', active ? 'true' : 'false');
          buttons[t.id].tabIndex = active ? 0 : -1;
          panels[t.id].classList.toggle('active', active);
        });
        return true;
      }

      const root = el('div', { class: 'ex-root', 'data-ex-version': VERSION },
        hero, kpis, tabsWrap, body);
      root._switchTab = switchTab;

      /* session clock tick */
      state.timers.clock = setInterval(() => {
        if (!refs.clockVal) return;
        const d = new Date();
        refs.clockVal.textContent =
          String(d.getUTCHours()).padStart(2,'0') + ':' +
          String(d.getUTCMinutes()).padStart(2,'0') + ':' +
          String(d.getUTCSeconds()).padStart(2,'0');
        if (refs.kpiTime) {
          const sec = Math.floor((Date.now() - state.sessionStart) / 1000);
          refs.kpiTime.firstChild.nodeValue = fmtDuration(sec);
        }
      }, 1000);

      return root;
    }

    function mount(target, opts) {
      if (state.mounted) unmount();
      injectCSS();
      opts = opts || {};
      const defaultTab = opts.defaultTab || 'dirfuzz';

      let elMount = null;
      if (typeof target === 'string')     elMount = document.querySelector(target);
      else if (target instanceof Element) elMount = target;
      else                                elMount = document.querySelector('[data-emergens-panel="exploit"]');

      if (!elMount) {
        console.warn('[ExploitSuite:' + instanceName + '] no mount point found');
        return false;
      }

      try {
        state.mountEl = elMount;
        elMount.textContent = '';
        elMount.appendChild(buildUI(defaultTab));
        elMount.setAttribute('data-ex-mounted', VERSION);
        state.mounted = true;
        state.activeTab = defaultTab;
        state.sessionStart = Date.now();
        state.kpi = { scans: 0, findings: 0, critHigh: 0 };
        console.log('[ExploitSuite] mounted v' + VERSION + ' at', elMount);
        return true;
      } catch (err) {
        console.error('[ExploitSuite] buildUI() threw:', err);
        elMount.innerHTML = '';
        elMount.appendChild(el('div', { class: 'ex-card' },
          el('div', { class: 'ex-card-head' },
            el('i', { class: 'ico fas fa-triangle-exclamation' }),
            el('h4', null, 'Exploit Suite — render failed')),
          el('pre', { style: 'font-family:var(--mono);font-size:.72rem;color:#fca5a5;background:rgba(0,0,0,.4);padding:12px;border-radius:8px;overflow:auto;white-space:pre-wrap;' },
            (err && (err.stack || err.message)) || String(err))));
        return false;
      }
    }

    function unmount() {
      for (const key of Object.keys(state.streams)) {
        try { state.streams[key].close(); } catch (_) {}
      }
      state.streams = Object.create(null);
      if (state.timers.clock) { clearInterval(state.timers.clock); state.timers.clock = null; }
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
      get state() {
        return Object.assign({}, state, { streams: Object.keys(state.streams) });
      },
    };
  }

  /* ══════════════════════════════════════════════════════════════════
   *  Public API
   * ══════════════════════════════════════════════════════════════════ */
  const defaultInstance = createInstance('default');

  window.ExploitSuite = Object.assign(defaultInstance, { create: createInstance, version: VERSION });

  window.addEventListener('beforeunload', () => {
    try { defaultInstance.unmount(); } catch (_) {}
  });

  function autoMount() {
    const placeholder = document.querySelector('[data-emergens-panel="exploit"]');
    if (!placeholder) return false;
    if (placeholder.getAttribute('data-ex-mounted') === VERSION) return true;
    if (defaultInstance.state.mounted) return true;
    return defaultInstance.mount(placeholder, { defaultTab: 'dirfuzz' });
  }

  function boot() {
    if (autoMount()) return;
    [100, 400, 1200].forEach(ms => setTimeout(() => {
      if (!defaultInstance.state.mounted) autoMount();
    }, ms));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
  window.addEventListener('load', () => {
    if (!defaultInstance.state.mounted) autoMount();
  });
})();