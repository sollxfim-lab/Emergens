/* ============================================================================
 * app-mh5783.js — MHDDoS Control Panel for Emergens
 * v4.1.0 — BLOOD SHARK EDITION · hardened mount + error-proof render
 *
 * Public API
 *   window.MHDDoSControl.mount(selectorOrEl)
 *   window.MHDDoSControl.unmount()
 *   window.MHDDoSControl.refresh()
 *   window.MHDDoSControl.version
 * ========================================================================= */
(function () {
  'use strict';

  if (window.MHDDoSControl && window.MHDDoSControl.version === '4.1.0') return;

  const VERSION = '4.1.0';
  const API = {
    methods: '/api/mhddos/methods', start: '/api/mhddos/start',
    stop:    '/api/mhddos/stop',    stopAll: '/api/mhddos/stop_all',
    status:  '/api/mhddos/status',  history: '/api/mhddos/history',
  };
  const POLL_MS = 2500, TICK_MS = 1000, MAX_HISTORY = 25;
  const SVG_NS = 'http://www.w3.org/2000/svg';

  const state = {
    mounted:false, mountEl:null, methods:[], layer7:[], layer4:[],
    running:[], history:[], pollTimer:null, tickTimer:null,
    busy:false, launched:0, prevCounts:{ active:0, threads:0, launched:0 },
  };

  /* ── helpers ─────────────────────────────────────────────────── */
  const $  = (s,r) => (r||document).querySelector(s);
  const $$ = (s,r) => Array.from((r||document).querySelectorAll(s));
  const esc = (s) => String(s==null?'':s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');

  function el(tag, attrs, ...children) {
    const n = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      const v = attrs[k];
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'style' && typeof v === 'object') Object.assign(n.style, v);
      else if (k === 'dataset' && typeof v === 'object') Object.assign(n.dataset, v);
      else if (k.startsWith('on') && typeof v === 'function')
        n.addEventListener(k.slice(2).toLowerCase(), v);
      else n.setAttribute(k, v);
    }
    const app = (c) => {
      if (c == null || c === false) return;
      if (Array.isArray(c)) { c.forEach(app); return; }
      n.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
    };
    children.forEach(app);
    return n;
  }

  /* SVG element creator (namespaced) */
  function svgEl(tag, attrs, ...children) {
    const n = document.createElementNS(SVG_NS, tag);
    if (attrs) for (const k in attrs) {
      const v = attrs[k];
      if (v == null || v === false) continue;
      if (k === 'class') n.setAttribute('class', v);
      else n.setAttribute(k, v);
    }
    const app = (c) => {
      if (c == null || c === false) return;
      if (Array.isArray(c)) { c.forEach(app); return; }
      n.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
    };
    children.forEach(app);
    return n;
  }

  function toast(msg, kind = 'info', ms = 3200) {
    try {
      let c = document.getElementById('toastContainer');
      if (!c) { c = el('div', { id:'toastContainer', class:'toast-container' }); document.body.appendChild(c); }
      const icon = { ok:'fa-circle-check', err:'fa-circle-xmark',
                     warn:'fa-triangle-exclamation', info:'fa-circle-info' }[kind] || 'fa-circle-info';
      const node = el('div', { class: 'toast toast-'+kind },
        el('i', { class:'fas '+icon }), el('span', null, msg));
      c.appendChild(node);
      requestAnimationFrame(() => node.classList.add('toast-in'));
      setTimeout(() => {
        node.classList.remove('toast-in'); node.classList.add('toast-out');
        setTimeout(() => node.remove(), 320);
      }, ms);
    } catch (e) { console.warn('[MHDDoSControl] toast failed', e); }
  }

  async function jget(url) {
    const r = await fetch(url, { credentials:'same-origin' });
    if (!r.ok) throw new Error('HTTP '+r.status);
    return r.json();
  }
  async function jpost(url, body) {
    const r = await fetch(url, {
      method:'POST', credentials:'same-origin',
      headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify(body || {}),
    });
    let data = null; try { data = await r.json(); } catch(_) {}
    if (!r.ok) throw new Error((data && data.error) || ('HTTP '+r.status));
    return data;
  }

  const fmtTime = (iso) => { try { return iso ? new Date(iso).toLocaleTimeString() : '—'; } catch(_) { return iso || '—'; } };
  const fmtRelative = (iso) => {
    if (!iso) return '—';
    try {
      const s = Math.floor((Date.now()-new Date(iso).getTime())/1000);
      if (s<5) return 'just now';
      if (s<60) return s+'s ago';
      if (s<3600) return Math.floor(s/60)+'m ago';
      if (s<86400) return Math.floor(s/3600)+'h ago';
      return Math.floor(s/86400)+'d ago';
    } catch(_) { return '—'; }
  };
  const shortId = (id) => id ? String(id).slice(0,12) : '—';
  function fmtDuration(sec) {
    if (sec==null || !isFinite(sec)) return '—';
    sec = Math.max(0, Math.floor(sec));
    const h = Math.floor(sec/3600), m = Math.floor((sec%3600)/60), s = sec%60;
    if (h) return `${h}h ${String(m).padStart(2,'0')}m`;
    if (m) return `${m}m ${String(s).padStart(2,'0')}s`;
    return `${s}s`;
  }
  function elapsedSec(iso) {
    if (!iso) return 0;
    try { return Math.max(0, Math.floor((Date.now()-new Date(iso).getTime())/1000)); }
    catch(_) { return 0; }
  }

  /* ══════════════════════════════════════════════════════════════
   *  BLOOD SHARK CSS
   * ══════════════════════════════════════════════════════════════ */
  const CSS = `
  .mhd-root{
    --red:#dc2626;--red-hi:#ef4444;--red-lo:#7f1d1d;--red-deep:#450a0a;
    --ink:#05060a;--ink2:#0a0d15;--ink3:#0f131f;
    --white:#f8fafc;--text:#e2e8f0;--muted:#8b95a7;--slate:#64748b;
    --border:rgba(148,163,184,.12);--border-hi:rgba(148,163,184,.22);
    --border-red:rgba(220,38,38,.28);
    --ui:var(--font-ui,'Inter','Space Grotesk',system-ui,sans-serif);
    --mono:var(--font-mono,ui-monospace,'JetBrains Mono',monospace);
    --ease:cubic-bezier(.4,0,.2,1);--ease-out:cubic-bezier(.16,1,.3,1);
    display:flex;flex-direction:column;gap:18px;
    font-family:var(--ui);color:var(--text);
  }
  /* HERO */
  .sx-hero{
    position:relative;border-radius:18px;padding:26px 28px;
    display:grid;grid-template-columns:220px 1fr auto;
    align-items:center;gap:26px;overflow:hidden;isolation:isolate;
    background:
      radial-gradient(ellipse 60% 120% at 0% 100%,rgba(220,38,38,.35),transparent 62%),
      radial-gradient(ellipse 70% 100% at 100% 0%,rgba(127,29,29,.35),transparent 60%),
      radial-gradient(ellipse 40% 60% at 50% 50%,rgba(220,38,38,.10),transparent 70%),
      linear-gradient(135deg,#05060a 0%,#0a0512 50%,#150404 100%);
    border:1px solid var(--border-red);
    box-shadow:inset 0 1px 0 rgba(255,255,255,.06),inset 0 0 60px rgba(220,38,38,.06),
               0 18px 48px rgba(0,0,0,.6),0 4px 16px rgba(220,38,38,.15);
  }
  .sx-hero::before{content:"";position:absolute;inset:0;
    background-image:
      repeating-radial-gradient(circle at 12% 100%,rgba(220,38,38,.08) 0 14px,transparent 14px 52px),
      repeating-linear-gradient(115deg,rgba(255,255,255,.015) 0 2px,transparent 2px 14px);
    pointer-events:none;z-index:0;opacity:.9;
  }
  .sx-hero::after{content:"";position:absolute;inset:0;
    background:linear-gradient(105deg,transparent 0%,transparent 42%,rgba(220,38,38,.08) 50%,transparent 58%,transparent 100%);
    background-size:200% 100%;animation:sxScan 6s linear infinite;pointer-events:none;z-index:1;
  }
  @keyframes sxScan{0%{background-position:200% 0;}100%{background-position:-100% 0;}}
  .sx-hero-teeth{position:absolute;left:0;right:0;bottom:0;height:14px;
    background-image:linear-gradient(135deg,transparent 50%,rgba(220,38,38,.55) 50%),
                     linear-gradient(45deg,rgba(220,38,38,.55) 50%,transparent 50%);
    background-size:14px 14px;background-repeat:repeat-x;opacity:.35;z-index:2;pointer-events:none;
  }
  .sx-hero>*{position:relative;z-index:3;}
  .sx-shark-arena{position:relative;width:220px;height:140px;display:flex;align-items:center;justify-content:center;}
  .sx-sonar{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;pointer-events:none;}
  .sx-sonar span{position:absolute;width:90px;height:90px;border-radius:50%;
    border:1px solid rgba(239,68,68,.55);animation:sxPing 3.2s cubic-bezier(.4,0,.2,1) infinite;}
  .sx-sonar span:nth-child(2){animation-delay:1.06s;}
  .sx-sonar span:nth-child(3){animation-delay:2.13s;}
  @keyframes sxPing{0%{transform:scale(.35);opacity:.9;}100%{transform:scale(2.2);opacity:0;}}
  .sx-shark{width:200px;height:130px;position:relative;z-index:2;
    filter:drop-shadow(0 14px 28px rgba(220,38,38,.5)) drop-shadow(0 4px 8px rgba(0,0,0,.7));
    animation:sxCruise 6s ease-in-out infinite;}
  @keyframes sxCruise{0%,100%{transform:translate(0,0) rotate(-1.5deg);}50%{transform:translate(10px,-4px) rotate(1.5deg);}}
  .sx-bubbles{position:absolute;inset:0;pointer-events:none;z-index:1;}
  .sx-bubbles i{position:absolute;width:5px;height:5px;border-radius:50%;
    background:radial-gradient(circle at 30% 30%,rgba(248,250,252,.9),rgba(220,38,38,.45));
    animation:sxBubble 4s linear infinite;}
  .sx-bubbles i:nth-child(1){left:20%;top:75%;animation-delay:0s;}
  .sx-bubbles i:nth-child(2){left:55%;top:85%;animation-delay:1.1s;width:3px;height:3px;}
  .sx-bubbles i:nth-child(3){left:78%;top:70%;animation-delay:2.3s;width:4px;height:4px;}
  .sx-bubbles i:nth-child(4){left:40%;top:90%;animation-delay:3.4s;width:3px;height:3px;}
  @keyframes sxBubble{0%{transform:translateY(0) scale(.4);opacity:0;}20%{opacity:.85;}100%{transform:translateY(-90px) scale(1);opacity:0;}}
  .sx-hero-copy{min-width:0;}
  .sx-eyebrow{display:inline-flex;align-items:center;gap:9px;font-size:.6rem;
    letter-spacing:.22em;text-transform:uppercase;font-weight:800;color:#fca5a5;margin-bottom:8px;}
  .sx-eyebrow::before{content:"";width:26px;height:2px;background:linear-gradient(90deg,var(--red-hi),transparent);border-radius:2px;}
  .sx-eyebrow .sx-ver{color:#7f1d1d;font-family:var(--mono);font-size:.56rem;letter-spacing:.04em;
    padding:2px 7px;border-radius:5px;background:rgba(220,38,38,.14);border:1px solid rgba(220,38,38,.3);text-transform:none;}
  .sx-title{font-size:1.55rem;font-weight:800;letter-spacing:-.03em;color:var(--white);
    margin:0 0 8px;line-height:1.1;display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
  .sx-title-red{background:linear-gradient(135deg,#ef4444 0%,#dc2626 45%,#7f1d1d 100%);
    -webkit-background-clip:text;background-clip:text;color:transparent;
    text-shadow:0 0 30px rgba(220,38,38,.3);}
  .sx-pulse-dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#ef4444;
    box-shadow:0 0 0 0 rgba(239,68,68,.9);animation:sxPulse 1.6s ease-out infinite;flex-shrink:0;margin-top:4px;}
  @keyframes sxPulse{0%{box-shadow:0 0 0 0 rgba(239,68,68,.9);}70%{box-shadow:0 0 0 12px rgba(239,68,68,0);}100%{box-shadow:0 0 0 0 rgba(239,68,68,0);}}
  .sx-subtitle{color:var(--muted);font-size:.8rem;line-height:1.6;margin:0;max-width:74ch;}
  .sx-subtitle b{color:var(--white);font-family:var(--mono);font-weight:600;
    background:rgba(220,38,38,.1);padding:1px 7px;border-radius:5px;border:1px solid rgba(220,38,38,.22);}
  .sx-hero-side{display:flex;flex-direction:column;align-items:flex-end;gap:12px;flex-shrink:0;min-width:168px;}
  .sx-status-pill{display:inline-flex;align-items:center;gap:9px;padding:7px 16px;border-radius:99px;
    background:linear-gradient(135deg,rgba(220,38,38,.28),rgba(220,38,38,.06));color:#fca5a5;
    font-size:.65rem;font-weight:800;letter-spacing:.1em;text-transform:uppercase;
    border:1px solid rgba(220,38,38,.5);
    box-shadow:0 0 20px rgba(220,38,38,.22),inset 0 1px 0 rgba(255,255,255,.08);
    transition:all .35s var(--ease);}
  .sx-status-pill.is-idle{background:linear-gradient(135deg,rgba(148,163,184,.14),rgba(148,163,184,.03));
    color:#94a3b8;border-color:var(--border-hi);box-shadow:none;}
  .sx-status-pill .dot{width:8px;height:8px;border-radius:50%;background:#ef4444;
    box-shadow:0 0 0 0 rgba(239,68,68,.85);animation:sxLive 1.5s ease-out infinite;}
  .sx-status-pill.is-idle .dot{background:#94a3b8;animation:none;box-shadow:none;}
  @keyframes sxLive{0%{box-shadow:0 0 0 0 rgba(239,68,68,.85);}70%{box-shadow:0 0 0 10px rgba(239,68,68,0);}100%{box-shadow:0 0 0 0 rgba(239,68,68,0);}}
  .sx-clock{display:flex;align-items:center;gap:8px;font-family:var(--mono);
    font-size:.7rem;color:var(--muted);letter-spacing:.05em;padding:6px 12px;
    background:rgba(5,6,10,.6);border:1px solid var(--border);border-radius:8px;
    backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);}
  .sx-clock i{color:var(--red-hi);font-size:.72rem;}
  .sx-clock b{color:var(--white);font-weight:600;}

  /* KPI RIBBON */
  .sx-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;}
  .sx-kpi{position:relative;background:linear-gradient(165deg,var(--ink2) 0%,var(--ink) 100%);
    border:1px solid var(--border);border-radius:12px;padding:16px 18px 15px;overflow:hidden;
    transition:all .25s var(--ease);}
  .sx-kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;
    background:linear-gradient(180deg,var(--red-hi),var(--red-lo),transparent);opacity:.85;transition:opacity .25s;}
  .sx-kpi::after{content:"";position:absolute;inset:0;
    background:radial-gradient(circle at 100% 0%,rgba(220,38,38,.14),transparent 60%);
    pointer-events:none;opacity:0;transition:opacity .3s;}
  .sx-kpi:hover{border-color:var(--border-red);transform:translateY(-3px);
    box-shadow:0 8px 28px rgba(220,38,38,.28),0 12px 28px rgba(0,0,0,.4);}
  .sx-kpi:hover::after{opacity:1;}
  .sx-kpi-head{display:flex;align-items:center;gap:8px;font-size:.6rem;font-weight:800;
    letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;}
  .sx-kpi-head i{color:var(--red-hi);font-size:.72rem;filter:drop-shadow(0 0 6px rgba(239,68,68,.5));}
  .sx-kpi-head .trend{margin-left:auto;font-family:var(--mono);font-size:.58rem;
    letter-spacing:.02em;padding:1px 6px;border-radius:4px;text-transform:none;font-weight:700;}
  .sx-kpi-head .trend.up{color:#4ade80;background:rgba(34,197,94,.12);}
  .sx-kpi-head .trend.down{color:#f87171;background:rgba(220,38,38,.14);}
  .sx-kpi-head .trend.flat{color:#64748b;background:rgba(148,163,184,.08);}
  .sx-kpi-value{font-family:var(--mono);font-size:1.55rem;font-weight:800;
    color:var(--white);line-height:1;display:flex;align-items:baseline;gap:6px;letter-spacing:-.02em;}
  .sx-kpi-value small{font-size:.64rem;font-weight:600;color:#64748b;letter-spacing:.02em;}
  .sx-kpi.flash{animation:sxKpiGlow .9s var(--ease-out);}
  @keyframes sxKpiGlow{
    0%{background:linear-gradient(165deg,rgba(220,38,38,.28),var(--ink) 100%);}
    100%{background:linear-gradient(165deg,var(--ink2),var(--ink) 100%);}
  }

  /* CARDS */
  .sx-card{position:relative;
    background:linear-gradient(165deg,rgba(15,19,31,.85) 0%,rgba(5,6,10,.92) 100%);
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    border:1px solid var(--border);border-radius:14px;padding:20px 22px;overflow:hidden;
    transition:border-color .25s,box-shadow .25s;}
  .sx-card::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;
    background:linear-gradient(90deg,var(--red-hi) 0%,var(--red-lo) 30%,transparent 70%);opacity:.7;}
  .sx-card:hover{border-color:var(--border-red);
    box-shadow:0 12px 32px rgba(0,0,0,.45),0 0 0 1px rgba(220,38,38,.06);}
  .sx-card-head{display:flex;align-items:center;gap:12px;margin:0 0 18px;
    padding-bottom:15px;border-bottom:1px solid var(--border);flex-wrap:wrap;}
  .sx-card-head .ico{width:34px;height:34px;display:flex;align-items:center;justify-content:center;
    font-size:.9rem;border-radius:9px;
    background:linear-gradient(135deg,var(--red-hi) 0%,var(--red-lo) 100%);color:#fff;
    box-shadow:0 4px 14px rgba(220,38,38,.45),inset 0 1px 0 rgba(255,255,255,.18);flex-shrink:0;position:relative;}
  .sx-card-head .ico::after{content:"";position:absolute;inset:0;border-radius:9px;
    background:linear-gradient(180deg,rgba(255,255,255,.2),transparent 50%);pointer-events:none;}
  .sx-card-head h4{margin:0;font-size:.82rem;font-weight:800;letter-spacing:.1em;
    text-transform:uppercase;color:var(--white);}
  .sx-card-head .hint{margin-left:auto;font-size:.66rem;font-weight:600;
    letter-spacing:.02em;text-transform:none;color:var(--muted);font-family:var(--mono);
    padding:3px 9px;border-radius:5px;background:rgba(148,163,184,.07);border:1px solid var(--border);}

  /* PRESETS */
  .sx-presets{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:20px;}
  .sx-preset{position:relative;padding:13px 15px;border-radius:10px;
    border:1px solid var(--border);background:linear-gradient(180deg,var(--ink2),var(--ink));
    color:var(--muted);font-family:inherit;font-size:.78rem;font-weight:700;text-align:left;
    cursor:pointer;display:flex;flex-direction:column;gap:5px;
    transition:all .2s var(--ease);-webkit-appearance:none;appearance:none;overflow:hidden;}
  .sx-preset::after{content:"";position:absolute;top:0;right:0;width:0;height:0;
    border-top:22px solid rgba(220,38,38,.28);border-left:22px solid transparent;
    transition:border-top-color .25s;}
  .sx-preset:hover{border-color:var(--red);color:var(--white);
    transform:translateY(-2px);box-shadow:0 8px 20px rgba(220,38,38,.2);}
  .sx-preset:hover::after{border-top-color:var(--red-hi);}
  .sx-preset .ps-head{display:flex;align-items:center;gap:9px;color:var(--white);position:relative;z-index:1;}
  .sx-preset .ps-head i{color:var(--red-hi);font-size:.86rem;
    filter:drop-shadow(0 0 6px rgba(239,68,68,.5));}
  .sx-preset .ps-sub{font-family:var(--mono);font-size:.6rem;letter-spacing:.02em;
    color:#64748b;font-weight:500;position:relative;z-index:1;}
  .sx-preset:hover .ps-sub{color:#94a3b8;}

  /* FIELDS */
  .sx-row{display:flex;gap:12px;flex-wrap:wrap;}
  .sx-row>*{flex:1 1 160px;min-width:0;}
  .sx-field{display:flex;flex-direction:column;gap:7px;}
  .sx-field>label{font-size:.64rem;font-weight:700;letter-spacing:.08em;
    text-transform:uppercase;color:var(--muted);display:flex;align-items:center;gap:7px;}
  .sx-field>label .opt{color:#64748b;font-size:.58rem;font-weight:500;
    text-transform:none;letter-spacing:0;padding:1px 6px;border-radius:4px;background:rgba(148,163,184,.08);}
  .sx-field>input,.sx-field>select{
    background:linear-gradient(180deg,#060810,var(--ink2));
    border:1px solid var(--border);border-radius:9px;padding:11px 13px;
    color:var(--white);font-size:.84rem;font-family:var(--mono);outline:none;
    transition:all .2s var(--ease);-webkit-appearance:none;appearance:none;width:100%;}
  .sx-field>input:hover,.sx-field>select:hover{border-color:var(--border-hi);}
  .sx-field>input:focus,.sx-field>select:focus{
    border-color:var(--red-hi);
    box-shadow:0 0 0 3px rgba(220,38,38,.2),0 0 12px rgba(220,38,38,.15);
    background:linear-gradient(180deg,#080c18,#0e1322);}
  .sx-field>input::placeholder{color:rgba(148,163,184,.4);}
  .sx-field.invalid>input,.sx-field.invalid>select{
    border-color:rgba(239,68,68,.7);box-shadow:0 0 0 3px rgba(239,68,68,.18);}
  .sx-field .err{font-size:.62rem;color:#f87171;font-family:var(--mono);display:none;align-items:center;gap:5px;}
  .sx-field.invalid .err{display:flex;}

  /* PICKER */
  .sx-picker-bar{display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap;}
  .sx-tabs{display:inline-flex;padding:3px;background:linear-gradient(180deg,#060810,var(--ink2));
    border:1px solid var(--border);border-radius:10px;}
  .sx-tab{padding:7px 15px;border:none;background:transparent;color:var(--muted);
    font-family:inherit;font-size:.72rem;font-weight:700;letter-spacing:.05em;border-radius:7px;
    cursor:pointer;transition:all .2s var(--ease);-webkit-appearance:none;appearance:none;}
  .sx-tab:hover{color:var(--white);}
  .sx-tab.active{background:linear-gradient(135deg,var(--red-hi),var(--red-lo));color:#fff;
    box-shadow:0 4px 12px rgba(220,38,38,.4),inset 0 1px 0 rgba(255,255,255,.15);}
  .sx-search{flex:1 1 200px;min-width:150px;position:relative;}
  .sx-search i{position:absolute;left:12px;top:50%;transform:translateY(-50%);
    color:#64748b;font-size:.8rem;pointer-events:none;transition:color .2s;}
  .sx-search input{width:100%;background:linear-gradient(180deg,#060810,var(--ink2));
    border:1px solid var(--border);border-radius:10px;padding:9px 13px 9px 34px;
    color:var(--white);font-size:.78rem;font-family:var(--mono);outline:none;transition:all .2s;}
  .sx-search input:focus{border-color:var(--red-hi);box-shadow:0 0 0 3px rgba(220,38,38,.18);}
  .sx-search:focus-within i{color:var(--red-hi);}
  .sx-method-groups{display:flex;gap:16px;flex-wrap:wrap;}
  .sx-method-groups>div{flex:1 1 260px;min-width:0;}
  .sx-method-groups h5{margin:0 0 9px;font-size:.62rem;font-weight:800;
    letter-spacing:.12em;text-transform:uppercase;color:var(--muted);display:flex;align-items:center;gap:8px;}
  .sx-method-groups h5::before{content:"";width:3px;height:12px;
    background:linear-gradient(180deg,var(--red-hi),transparent);border-radius:2px;}
  .sx-method-groups h5 .count{margin-left:auto;font-family:var(--mono);font-size:.58rem;
    letter-spacing:0;color:#64748b;background:rgba(148,163,184,.08);padding:2px 7px;border-radius:4px;}
  .sx-chips{display:flex;flex-wrap:wrap;gap:6px;max-height:210px;overflow-y:auto;
    padding:2px 6px 4px 2px;scrollbar-width:thin;scrollbar-color:rgba(220,38,38,.4) transparent;}
  .sx-chips::-webkit-scrollbar{width:6px;}
  .sx-chips::-webkit-scrollbar-thumb{background:rgba(220,38,38,.35);border-radius:3px;}
  .sx-chip{padding:6px 12px;border-radius:7px;border:1px solid var(--border);
    background:linear-gradient(180deg,var(--ink2),var(--ink));color:var(--muted);
    font-family:var(--mono);font-size:.7rem;font-weight:600;cursor:pointer;
    transition:all .15s var(--ease);-webkit-appearance:none;appearance:none;}
  .sx-chip:hover{border-color:var(--red-hi);color:var(--white);transform:translateY(-1px);
    box-shadow:0 4px 12px rgba(220,38,38,.2);}
  .sx-chip.active{background:linear-gradient(135deg,var(--red-hi),var(--red-lo));
    border-color:transparent;color:#fff;font-weight:700;
    box-shadow:0 4px 14px rgba(220,38,38,.5),inset 0 1px 0 rgba(255,255,255,.18);}
  .sx-chips-empty{padding:16px 8px;width:100%;text-align:center;color:#64748b;font-size:.72rem;font-style:italic;}
  .sx-preview{margin-top:14px;padding:11px 15px;
    background:linear-gradient(135deg,rgba(220,38,38,.09),rgba(220,38,38,.02));
    border:1px dashed rgba(220,38,38,.35);border-radius:10px;
    display:flex;align-items:center;gap:12px;font-family:var(--mono);font-size:.78rem;
    color:var(--white);transition:all .3s var(--ease);}
  .sx-preview.empty{border-color:var(--border);border-style:solid;
    background:rgba(148,163,184,.03);color:#64748b;font-style:italic;}
  .sx-preview i.lead{color:var(--red-hi);font-size:.82rem;filter:drop-shadow(0 0 8px rgba(239,68,68,.5));}
  .sx-preview .lbl{font-size:.58rem;letter-spacing:.12em;text-transform:uppercase;
    color:var(--muted);font-weight:800;font-family:var(--ui);}
  .sx-preview .val{color:var(--white);font-weight:700;padding:2px 9px;border-radius:5px;
    background:rgba(220,38,38,.15);border:1px solid rgba(220,38,38,.28);letter-spacing:.02em;}
  .sx-preview.empty .val{background:transparent;border:none;padding:0;color:#64748b;font-weight:500;}

  /* BUTTONS */
  .sx-actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px;
    padding-top:18px;border-top:1px solid var(--border);}
  .sx-btn{flex:1 1 170px;padding:13px 22px;border-radius:10px;border:1px solid transparent;
    font-weight:700;font-size:.84rem;cursor:pointer;
    display:inline-flex;align-items:center;justify-content:center;gap:10px;
    transition:all .22s var(--ease);-webkit-appearance:none;appearance:none;
    white-space:nowrap;font-family:inherit;position:relative;overflow:hidden;letter-spacing:.01em;}
  .sx-btn:focus-visible{outline:none;box-shadow:0 0 0 3px rgba(220,38,38,.4),0 0 0 1px var(--red-hi);}
  .sx-btn:active:not([disabled]){transform:scale(.985);}
  .sx-btn[disabled]{opacity:.55;cursor:not-allowed;transform:none !important;}
  .sx-btn-primary{background:linear-gradient(135deg,var(--red-hi) 0%,var(--red) 45%,var(--red-lo) 100%);
    color:#fff;border-color:rgba(239,68,68,.5);
    box-shadow:0 6px 20px rgba(220,38,38,.45),inset 0 1px 0 rgba(255,255,255,.18);}
  .sx-btn-primary::after{content:"";position:absolute;top:0;left:-100%;width:100%;height:100%;
    background:linear-gradient(90deg,transparent,rgba(255,255,255,.22),transparent);
    transition:left .6s var(--ease);}
  .sx-btn-primary:hover:not([disabled]){transform:translateY(-2px);
    box-shadow:0 12px 32px rgba(220,38,38,.6),0 0 0 1px rgba(239,68,68,.3),inset 0 1px 0 rgba(255,255,255,.25);}
  .sx-btn-primary:hover:not([disabled])::after{left:100%;}
  .sx-btn-danger{background:linear-gradient(135deg,#991b1b 0%,#7f1d1d 60%,var(--red-deep) 100%);
    color:#fecaca;border-color:rgba(239,68,68,.4);
    box-shadow:0 4px 14px rgba(127,29,29,.4),inset 0 1px 0 rgba(255,255,255,.08);}
  .sx-btn-danger:hover:not([disabled]){transform:translateY(-2px);
    background:linear-gradient(135deg,#b91c1c,#991b1b);color:#fff;
    box-shadow:0 12px 28px rgba(185,28,28,.5);}
  .sx-btn-ghost{background:linear-gradient(180deg,var(--ink2),var(--ink));
    border-color:var(--border);color:var(--muted);}
  .sx-btn-ghost:hover:not([disabled]){border-color:var(--red-hi);color:var(--white);
    background:linear-gradient(180deg,rgba(220,38,38,.1),rgba(220,38,38,.02));}

  /* TABLES */
  .sx-table-wrap{overflow-x:auto;border-radius:11px;border:1px solid var(--border);background:rgba(5,6,10,.55);}
  .sx-table{width:100%;border-collapse:collapse;font-size:.76rem;}
  .sx-table th,.sx-table td{text-align:left;padding:11px 13px;
    border-bottom:1px solid var(--border);vertical-align:middle;}
  .sx-table th{font-size:.62rem;letter-spacing:.1em;text-transform:uppercase;
    color:var(--muted);font-weight:800;
    background:linear-gradient(180deg,rgba(220,38,38,.08),rgba(220,38,38,.01));white-space:nowrap;}
  .sx-table tr:last-child td{border-bottom:none;}
  .sx-table tbody tr{transition:background .18s;}
  .sx-table tbody tr:hover{background:linear-gradient(90deg,rgba(220,38,38,.08),transparent);}
  .sx-table code{font-family:var(--mono);font-size:.73rem;color:#cbd5e1;word-break:break-all;}
  .sx-table td.t-dim{color:var(--muted);font-family:var(--mono);}
  .sx-elapsed-cell{display:flex;flex-direction:column;gap:5px;min-width:96px;}
  .sx-elapsed-label{font-family:var(--mono);font-size:.73rem;color:var(--white);font-weight:700;}
  .sx-elapsed-track{height:4px;border-radius:2px;background:rgba(148,163,184,.15);overflow:hidden;position:relative;}
  .sx-elapsed-fill{height:100%;background:linear-gradient(90deg,var(--red-lo),var(--red-hi),#ef4444);
    border-radius:2px;transition:width .55s linear;
    box-shadow:0 0 10px rgba(239,68,68,.65);position:relative;}
  .sx-elapsed-fill::after{content:"";position:absolute;right:0;top:50%;width:6px;height:6px;
    background:#ef4444;border-radius:50%;transform:translateY(-50%);box-shadow:0 0 8px #ef4444;}

  /* BADGES */
  .sx-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 11px;border-radius:99px;
    font-size:.62rem;font-weight:800;letter-spacing:.07em;text-transform:uppercase;
    border:1px solid;white-space:nowrap;}
  .sx-badge::before{content:"";width:6px;height:6px;border-radius:50%;}
  .sx-badge-running{background:rgba(34,197,94,.14);color:#4ade80;border-color:rgba(34,197,94,.5);}
  .sx-badge-running::before{background:#22c55e;animation:sxBlink 1.2s ease-in-out infinite;}
  .sx-badge-stopped{background:rgba(148,163,184,.12);color:#94a3b8;border-color:rgba(148,163,184,.3);}
  .sx-badge-stopped::before{background:#94a3b8;}
  .sx-badge-failed{background:rgba(220,38,38,.2);color:#f87171;border-color:rgba(220,38,38,.5);}
  .sx-badge-failed::before{background:#dc2626;}
  .sx-badge-done{background:rgba(59,130,246,.16);color:#60a5fa;border-color:rgba(59,130,246,.5);}
  .sx-badge-done::before{background:#3b82f6;}
  .sx-badge-timeout{background:rgba(245,158,11,.16);color:#fbbf24;border-color:rgba(245,158,11,.5);}
  .sx-badge-timeout::before{background:#f59e0b;}
  @keyframes sxBlink{0%,100%{opacity:1;}50%{opacity:.35;}}

  /* EMPTY + MINI */
  .sx-empty{padding:40px 20px;text-align:center;color:var(--muted);font-size:.82rem;
    display:flex;flex-direction:column;gap:14px;align-items:center;}
  .sx-empty svg{width:80px;height:60px;opacity:.6;filter:drop-shadow(0 6px 18px rgba(220,38,38,.45));}
  .sx-empty .em-title{color:var(--white);font-weight:700;font-size:.9rem;
    font-style:normal;letter-spacing:-.01em;}
  .sx-empty .em-sub{color:#64748b;font-style:italic;font-size:.76rem;max-width:42ch;line-height:1.5;}
  .sx-btn-mini{padding:6px 13px;border-radius:8px;border:1px solid var(--border);
    background:linear-gradient(180deg,var(--ink2),var(--ink));color:var(--muted);
    font-family:inherit;font-size:.68rem;font-weight:700;letter-spacing:.05em;
    text-transform:uppercase;cursor:pointer;display:inline-flex;align-items:center;gap:6px;
    transition:all .18s var(--ease);-webkit-appearance:none;appearance:none;}
  .sx-btn-mini:hover:not([disabled]){border-color:var(--red-hi);color:#fca5a5;
    background:linear-gradient(180deg,rgba(220,38,38,.15),rgba(220,38,38,.03));
    transform:translateY(-1px);box-shadow:0 4px 12px rgba(220,38,38,.2);}
  .sx-btn-mini[disabled]{opacity:.5;cursor:not-allowed;}

  /* CONFIRM */
  .sx-confirm-overlay{position:fixed;inset:0;background:rgba(5,6,10,.75);
    backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);z-index:99999;
    display:flex;align-items:center;justify-content:center;padding:20px;
    animation:sxFadeIn .22s var(--ease);}
  @keyframes sxFadeIn{from{opacity:0;}to{opacity:1;}}
  .sx-confirm{background:linear-gradient(165deg,rgba(15,19,31,.98),rgba(5,6,10,.98));
    border:1px solid var(--border-red);border-radius:16px;padding:26px 28px;
    max-width:460px;width:100%;
    box-shadow:0 30px 80px rgba(0,0,0,.7),0 0 0 1px rgba(220,38,38,.2),0 0 60px rgba(220,38,38,.1);
    animation:sxPopIn .3s var(--ease-out);position:relative;overflow:hidden;}
  .sx-confirm::before{content:"";position:absolute;top:0;left:0;right:0;height:3px;
    background:linear-gradient(90deg,var(--red-hi),var(--red-lo),transparent);}
  @keyframes sxPopIn{from{transform:scale(.92) translateY(8px);opacity:0;}to{transform:scale(1) translateY(0);opacity:1;}}
  .sx-confirm-icon{width:48px;height:48px;border-radius:13px;
    background:linear-gradient(135deg,rgba(220,38,38,.28),rgba(127,29,29,.12));
    display:flex;align-items:center;justify-content:center;color:#fca5a5;font-size:1.15rem;
    margin-bottom:14px;border:1px solid rgba(220,38,38,.4);box-shadow:0 4px 16px rgba(220,38,38,.25);}
  .sx-confirm-title{font-size:1.05rem;font-weight:800;color:var(--white);
    margin:0 0 8px;letter-spacing:-.01em;}
  .sx-confirm-msg{font-size:.84rem;color:var(--muted);line-height:1.6;margin:0 0 22px;}
  .sx-confirm-actions{display:flex;gap:10px;justify-content:flex-end;}
  .sx-confirm-actions .sx-btn{flex:0 0 auto;padding:11px 20px;min-width:110px;}

  /* ERROR CARD */
  .sx-error-card{padding:22px 24px;border-radius:14px;
    background:linear-gradient(165deg,rgba(220,38,38,.12),rgba(5,6,10,.9));
    border:1px solid rgba(220,38,38,.5);
    box-shadow:0 12px 32px rgba(220,38,38,.2);}
  .sx-error-card h4{margin:0 0 10px;color:#fca5a5;font-size:.92rem;
    display:flex;align-items:center;gap:9px;letter-spacing:.02em;}
  .sx-error-card pre{margin:0;padding:12px 14px;border-radius:8px;
    background:rgba(0,0,0,.5);color:#fecaca;font-family:var(--mono);
    font-size:.72rem;line-height:1.5;overflow-x:auto;white-space:pre-wrap;word-break:break-all;}

  /* TOAST OVERRIDE */
  .toast{transition:all .3s var(--ease-out);transform:translateX(20px);opacity:0;}
  .toast.toast-in{transform:translateX(0);opacity:1;}
  .toast.toast-out{transform:translateX(20px);opacity:0;}

  /* SIDEBAR ACCENT */
  .nav-item[data-section="mhddos"]:hover{
    background:linear-gradient(90deg,rgba(220,38,38,.18),transparent 78%) !important;
    border-left-color:#dc2626 !important;color:#fff !important;}
  .nav-item[data-section="mhddos"]:hover i{color:#ef4444 !important;}
  .nav-item[data-section="mhddos"].active{
    background:linear-gradient(90deg,rgba(220,38,38,.42),rgba(220,38,38,.1) 78%,transparent) !important;
    border-left-color:#ef4444 !important;color:#fff !important;font-weight:700 !important;
    box-shadow:inset 0 0 20px rgba(220,38,38,.08);}
  .nav-item[data-section="mhddos"].active i{color:#fff !important;filter:drop-shadow(0 0 8px rgba(239,68,68,.85));}
  .content-section.active#section-mhddos .panel-title i{
    color:#ef4444 !important;
    background:linear-gradient(135deg,rgba(220,38,38,.25),rgba(127,29,29,.14)) !important;
    box-shadow:inset 0 0 0 1px rgba(220,38,38,.35),0 0 20px rgba(220,38,38,.15);}

  /* RESPONSIVE */
  @media (max-width:1000px){.sx-kpis{grid-template-columns:repeat(2,minmax(0,1fr));}}
  @media (max-width:820px){
    .sx-hero{grid-template-columns:1fr;padding:22px 20px;gap:20px;}
    .sx-shark-arena{width:100%;height:120px;}
    .sx-shark{width:180px;height:120px;}
    .sx-hero-side{align-items:flex-start;width:100%;flex-direction:row;flex-wrap:wrap;}
    .sx-title{font-size:1.3rem;}
    .sx-row>*{flex:1 1 100%;}
    .sx-actions .sx-btn{flex:1 1 100%;}
    .sx-presets{grid-template-columns:repeat(2,minmax(0,1fr));}
  }
  @media (max-width:480px){
    .sx-kpis{grid-template-columns:1fr;}
    .sx-card{padding:16px 14px;}
    .sx-presets{grid-template-columns:1fr;}
    .sx-hero{padding:18px 16px;}
  }
  @media (prefers-reduced-motion:reduce){
    .sx-shark,.sx-sonar span,.sx-bubbles i,.sx-hero::after,
    .sx-status-pill .dot,.sx-badge-running::before,.sx-pulse-dot,
    .sx-elapsed-fill::after{animation:none !important;}
    .sx-card,.sx-kpi,.sx-btn,.sx-chip,.sx-preset{transition:none !important;}
  }
  `;

  function injectCSS() {
    if (document.getElementById('mhd-css')) return;
    const s = document.createElement('style');
    s.id = 'mhd-css';
    s.textContent = CSS;
    document.head.appendChild(s);
  }

  /* ── SHARK SVG (built with createElementNS) ─────────────────── */
  function sharkSVG() {
    const svg = svgEl('svg', {
      class: 'sx-shark', viewBox: '0 0 240 160',
      xmlns: SVG_NS, 'aria-hidden': 'true',
    });
    const defs = svgEl('defs');

    // Linear gradient: body
    const g1 = svgEl('linearGradient', { id:'sxBodyGrad', x1:'0', y1:'0', x2:'0', y2:'1' });
    g1.appendChild(svgEl('stop', { offset:'0',    'stop-color':'#4b5563' }));
    g1.appendChild(svgEl('stop', { offset:'0.45', 'stop-color':'#1e293b' }));
    g1.appendChild(svgEl('stop', { offset:'1',    'stop-color':'#0a0f1a' }));
    defs.appendChild(g1);

    // Linear gradient: belly
    const g2 = svgEl('linearGradient', { id:'sxBellyGrad', x1:'0', y1:'0', x2:'0', y2:'1' });
    g2.appendChild(svgEl('stop', { offset:'0', 'stop-color':'#cbd5e1' }));
    g2.appendChild(svgEl('stop', { offset:'1', 'stop-color':'#64748b' }));
    defs.appendChild(g2);

    // Linear gradient: fin
    const g3 = svgEl('linearGradient', { id:'sxFinGrad', x1:'0', y1:'0', x2:'1', y2:'1' });
    g3.appendChild(svgEl('stop', { offset:'0',   'stop-color':'#ef4444' }));
    g3.appendChild(svgEl('stop', { offset:'0.5', 'stop-color':'#dc2626' }));
    g3.appendChild(svgEl('stop', { offset:'1',   'stop-color':'#7f1d1d' }));
    defs.appendChild(g3);

    // Linear gradient: fin2
    const g4 = svgEl('linearGradient', { id:'sxFinGrad2', x1:'0', y1:'0', x2:'0', y2:'1' });
    g4.appendChild(svgEl('stop', { offset:'0', 'stop-color':'#b91c1c' }));
    g4.appendChild(svgEl('stop', { offset:'1', 'stop-color':'#450a0a' }));
    defs.appendChild(g4);

    // Radial gradient: eye
    const g5 = svgEl('radialGradient', { id:'sxEyeGlow', cx:'0.35', cy:'0.35', r:'0.65' });
    g5.appendChild(svgEl('stop', { offset:'0',   'stop-color':'#fef2f2' }));
    g5.appendChild(svgEl('stop', { offset:'0.4', 'stop-color':'#fca5a5' }));
    g5.appendChild(svgEl('stop', { offset:'1',   'stop-color':'#7f1d1d' }));
    defs.appendChild(g5);

    // Glow filter
    const f = svgEl('filter', { id:'sxSoftGlow', x:'-50%', y:'-50%', width:'200%', height:'200%' });
    f.appendChild(svgEl('feGaussianBlur', { stdDeviation:'2.5', result:'b' }));
    const merge = svgEl('feMerge');
    merge.appendChild(svgEl('feMergeNode', { in:'b' }));
    merge.appendChild(svgEl('feMergeNode', { in:'SourceGraphic' }));
    f.appendChild(merge);
    defs.appendChild(f);

    svg.appendChild(defs);

    // Water wake
    svg.appendChild(svgEl('path', {
      d:'M0 128 Q60 122 120 128 T240 128', fill:'none',
      stroke:'#7f1d1d', 'stroke-width':'1.6', 'stroke-opacity':'0.45', 'stroke-linecap':'round',
    }));
    svg.appendChild(svgEl('path', {
      d:'M14 138 Q74 132 134 138 T254 138', fill:'none',
      stroke:'#7f1d1d', 'stroke-width':'1', 'stroke-opacity':'0.25', 'stroke-linecap':'round',
    }));

    // Tail fin
    svg.appendChild(svgEl('path', {
      d:'M18 108 L0 128 L30 122 L26 108 Z',
      fill:'url(#sxFinGrad2)', stroke:'#450a0a', 'stroke-width':'1.2',
    }));
    svg.appendChild(svgEl('path', {
      d:'M22 108 L8 92 L28 104 Z',
      fill:'url(#sxFinGrad)', stroke:'#7f1d1d', 'stroke-width':'1.2', opacity:'0.9',
    }));

    // Body
    svg.appendChild(svgEl('path', {
      d:'M24 104 Q68 82 122 80 Q186 78 228 98 L236 108 Q186 130 122 122 Q68 114 24 104 Z',
      fill:'url(#sxBodyGrad)', stroke:'#0a0f1a', 'stroke-width':'1.6',
    }));

    // Belly
    svg.appendChild(svgEl('path', {
      d:'M42 106 Q92 118 158 116 Q200 114 226 106 L214 106 Q168 116 122 116 Q78 114 42 106 Z',
      fill:'url(#sxBellyGrad)', opacity:'0.85',
    }));

    // Dorsal fin
    svg.appendChild(svgEl('path', {
      d:'M114 78 L148 18 L162 78 Q138 68 114 78 Z',
      fill:'url(#sxFinGrad)', stroke:'#7f1d1d', 'stroke-width':'1.8', filter:'url(#sxSoftGlow)',
    }));

    // Second dorsal
    svg.appendChild(svgEl('path', {
      d:'M172 82 L186 62 L194 84 Q182 80 172 82 Z',
      fill:'url(#sxFinGrad)', opacity:'0.9',
    }));

    // Pectoral fin
    svg.appendChild(svgEl('path', {
      d:'M118 114 L102 140 L136 122 Z',
      fill:'url(#sxFinGrad)', opacity:'0.95', stroke:'#7f1d1d', 'stroke-width':'1',
    }));

    // Gill slits
    const gills = svgEl('g', {
      stroke:'#dc2626', 'stroke-width':'1.8', 'stroke-linecap':'round', opacity:'0.9',
    });
    gills.appendChild(svgEl('path', { d:'M162 88 L160 108' }));
    gills.appendChild(svgEl('path', { d:'M172 87 L170 108' }));
    gills.appendChild(svgEl('path', { d:'M182 86 L180 108' }));
    svg.appendChild(gills);

    // Teeth
    const teeth = svgEl('g', { fill:'#fef2f2', stroke:'#7f1d1d', 'stroke-width':'0.5' });
    teeth.appendChild(svgEl('path', { d:'M204 105 L206 112 L208 105 Z' }));
    teeth.appendChild(svgEl('path', { d:'M210 104 L212 112 L214 104 Z' }));
    teeth.appendChild(svgEl('path', { d:'M216 104 L218 111 L220 104 Z' }));
    teeth.appendChild(svgEl('path', { d:'M222 104 L224 110 L226 104 Z' }));
    svg.appendChild(teeth);
    svg.appendChild(svgEl('path', {
      d:'M200 104 Q216 112 230 104', fill:'none',
      stroke:'#450a0a', 'stroke-width':'1.6', 'stroke-linecap':'round',
    }));

    // Eye
    svg.appendChild(svgEl('circle', {
      cx:'212', cy:'94', r:'4', fill:'url(#sxEyeGlow)', filter:'url(#sxSoftGlow)',
    }));
    svg.appendChild(svgEl('circle', { cx:'212', cy:'94', r:'1.6', fill:'#020617' }));
    svg.appendChild(svgEl('circle', { cx:'211', cy:'93', r:'0.7', fill:'#fef2f2' }));

    return svg;
  }

  function emptyState(title, sub) {
    const w = el('div', { class: 'sx-empty' });
    const svg = svgEl('svg', { viewBox:'0 0 120 90', xmlns:SVG_NS, 'aria-hidden':'true' });
    const defs = svgEl('defs');
    const g = svgEl('linearGradient', { id:'sxEmptyFin', x1:'0', y1:'0', x2:'1', y2:'1' });
    g.appendChild(svgEl('stop', { offset:'0',   'stop-color':'#ef4444' }));
    g.appendChild(svgEl('stop', { offset:'0.6', 'stop-color':'#b91c1c' }));
    g.appendChild(svgEl('stop', { offset:'1',   'stop-color':'#450a0a' }));
    defs.appendChild(g);
    svg.appendChild(defs);
    svg.appendChild(svgEl('path', {
      d:'M14 66 Q46 54 78 58 L108 34 L100 58 L118 74 L86 72 Q46 82 14 66 Z',
      fill:'#1e293b', stroke:'#dc2626', 'stroke-width':'1.2', 'stroke-opacity':'0.6',
    }));
    svg.appendChild(svgEl('path', { d:'M62 30 L78 6 L84 32 Q72 28 62 30 Z', fill:'url(#sxEmptyFin)' }));
    svg.appendChild(svgEl('path', { d:'M20 62 L12 78 L32 72 L20 62 Z', fill:'url(#sxEmptyFin)', opacity:'0.9' }));
    svg.appendChild(svgEl('circle', { cx:'42', cy:'64', r:'2', fill:'#fef2f2' }));
    svg.appendChild(svgEl('circle', { cx:'42', cy:'64', r:'1', fill:'#7f1d1d' }));
    w.appendChild(svg);
    if (title) w.appendChild(el('div', { class:'em-title' }, title));
    if (sub)   w.appendChild(el('div', { class:'em-sub' }, sub));
    return w;
  }

  const PRESETS = {
    recon:  { label:'Recon',     sub:'Light · 5t / 30s',   icon:'fa-eye',         config:{ threads:5,   duration:30,  proxy_type:0, rpc:1 } },
    stress: { label:'Stress',    sub:'Medium · 100t / 2m', icon:'fa-fire',        config:{ threads:100, duration:120, proxy_type:0, rpc:1 } },
    udp:    { label:'UDP Flood', sub:'Heavy · 200t / 3m',  icon:'fa-wave-square', config:{ threads:200, duration:180, proxy_type:0, rpc:1 } },
    mixed:  { label:'Mixed',     sub:'Max · 250t / 5m',    icon:'fa-shuffle',     config:{ threads:250, duration:300, proxy_type:1, rpc:2 } },
  };

  /* ── Confirm dialog ─────────────────────────────────────────── */
  function confirmDialog({ title, message, confirmText='Confirm', cancelText='Cancel', danger=true }) {
    return new Promise((resolve) => {
      const overlay = el('div', { class:'sx-confirm-overlay', role:'dialog', 'aria-modal':'true' });
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
      const card = el('div', { class:'sx-confirm' },
        el('div', { class:'sx-confirm-icon' },
          el('i', { class: danger ? 'fas fa-triangle-exclamation' : 'fas fa-circle-question' })),
        el('h3', { class:'sx-confirm-title' }, title),
        el('p',  { class:'sx-confirm-msg' }, message),
        el('div', { class:'sx-confirm-actions' },
          el('button', { class:'sx-btn sx-btn-ghost', type:'button', onclick:()=>close(false) }, cancelText),
          el('button', { class:'sx-btn '+(danger?'sx-btn-danger':'sx-btn-primary'), type:'button', onclick:()=>close(true) }, confirmText),
        ),
      );
      overlay.appendChild(card);
      document.body.appendChild(overlay);
      document.addEventListener('keydown', onKey);
      setTimeout(() => {
        const btn = card.querySelector('.sx-btn-danger, .sx-btn-primary');
        if (btn) btn.focus();
      }, 60);
    });
  }

  /* ══════════════════════════════════════════════════════════════
   *  BUILD UI
   * ══════════════════════════════════════════════════════════════ */
  function buildUI() {
    const selectedMethod = { value: '' };

    /* HERO */
    const clockVal = el('b', null, '—');
    const statusText = el('span', { class:'sx-status-text' }, 'Idle');
    const statusPill = el('span', { class:'sx-status-pill is-idle', role:'status', 'aria-live':'polite' },
      el('span', { class:'dot' }), statusText);

    const sonar = el('div', { class:'sx-sonar' });
    sonar.appendChild(el('span')); sonar.appendChild(el('span')); sonar.appendChild(el('span'));

    const bubbles = el('div', { class:'sx-bubbles' });
    bubbles.appendChild(el('i')); bubbles.appendChild(el('i'));
    bubbles.appendChild(el('i')); bubbles.appendChild(el('i'));

    const sharkArena = el('div', { class:'sx-shark-arena', 'aria-hidden':'true' },
      sonar, bubbles, sharkSVG());

    const hero = el('div', { class:'sx-hero' },
      sharkArena,
      el('div', { class:'sx-hero-copy' },
        el('div', { class:'sx-eyebrow' },
          'Predator Mode',
          el('span', { class:'sx-ver' }, 'v' + VERSION)),
        el('h3', { class:'sx-title' },
          el('span', { class:'sx-pulse-dot' }),
          'MHDDoS ',
          el('span', { class:'sx-title-red' }, 'Blood Shark')),
        el('p', { class:'sx-subtitle' },
          'Real-time DDoS engine — ',
          el('b', null, 'authorised targets only'),
          '. Every attack is cancellable, rate-limited, and streamed to the console.')),
      el('div', { class:'sx-hero-side' },
        statusPill,
        el('div', { class:'sx-clock' },
          el('i', { class:'fas fa-clock' }),
          'UTC ', clockVal)),
      el('div', { class:'sx-hero-teeth', 'aria-hidden':'true' }),
    );

    /* KPI RIBBON */
    const kpiActiveTrend = el('span', { class:'trend flat' }, '—');
    const kpiThreadsTrend = el('span', { class:'trend flat' }, '—');
    const kpiLaunchedTrend = el('span', { class:'trend flat' }, '—');
    const kpiAvgTrend = el('span', { class:'trend flat' }, '—');

    const kpiActive   = el('div', { class:'sx-kpi-value' }, '0', el('small', null, 'attacks'));
    const kpiThreads  = el('div', { class:'sx-kpi-value' }, '0', el('small', null, 'threads'));
    const kpiLaunched = el('div', { class:'sx-kpi-value' }, '0', el('small', null, 'session'));
    const kpiAvg      = el('div', { class:'sx-kpi-value' }, '—', el('small', null, 'per attack'));

    const kpis = el('div', { class:'sx-kpis' },
      el('div', { class:'sx-kpi' },
        el('div', { class:'sx-kpi-head' },
          el('i', { class:'fas fa-bolt' }), 'Active', kpiActiveTrend),
        kpiActive),
      el('div', { class:'sx-kpi' },
        el('div', { class:'sx-kpi-head' },
          el('i', { class:'fas fa-microchip' }), 'Threads', kpiThreadsTrend),
        kpiThreads),
      el('div', { class:'sx-kpi' },
        el('div', { class:'sx-kpi-head' },
          el('i', { class:'fas fa-rocket' }), 'Launched', kpiLaunchedTrend),
        kpiLaunched),
      el('div', { class:'sx-kpi' },
        el('div', { class:'sx-kpi-head' },
          el('i', { class:'fas fa-stopwatch' }), 'Avg Duration', kpiAvgTrend),
        kpiAvg),
    );

    /* PRESETS */
    const presetRow = el('div', { class:'sx-presets' });
    Object.entries(PRESETS).forEach(([k, p]) => {
      presetRow.appendChild(el('button', {
        class:'sx-preset', type:'button', 'data-preset':k,
        title:'Apply '+p.label+' preset',
      },
        el('div', { class:'ps-head' },
          el('i', { class:'fas ' + p.icon }), p.label),
        el('div', { class:'ps-sub' }, p.sub)));
    });

    /* PICKER */
    const methodSelect = el('select', { id:'mhdMethodSelect', 'aria-label':'Method' },
      el('option', { value:'' }, 'Select a method…'));

    const searchInput = el('input', {
      type:'search', placeholder:'Filter methods…',
      'aria-label':'Filter methods', autocomplete:'off',
    });
    const searchWrap = el('div', { class:'sx-search' },
      el('i', { class:'fas fa-magnifying-glass' }), searchInput);

    const tabAll = el('button', { class:'sx-tab active', type:'button', 'data-tab':'all' }, 'All');
    const tabL7  = el('button', { class:'sx-tab', type:'button', 'data-tab':'l7' }, 'Layer 7');
    const tabL4  = el('button', { class:'sx-tab', type:'button', 'data-tab':'l4' }, 'Layer 4');
    const tabsEl = el('div', { class:'sx-tabs', role:'tablist' }, tabAll, tabL7, tabL4);

    const pickerBar = el('div', { class:'sx-picker-bar' }, tabsEl, searchWrap);

    const l7chips = el('div', { class:'sx-chips', id:'mhdL7Chips', role:'listbox', 'aria-label':'Layer 7 methods' });
    const l4chips = el('div', { class:'sx-chips', id:'mhdL4Chips', role:'listbox', 'aria-label':'Layer 4 methods' });

    const l7Count = el('span', { class:'count' }, '0');
    const l4Count = el('span', { class:'count' }, '0');

    const l7Group = el('div', null, el('h5', null, 'Layer 7', l7Count), l7chips);
    const l4Group = el('div', null, el('h5', null, 'Layer 4', l4Count), l4chips);
    const chipGroups = el('div', { class:'sx-method-groups' }, l7Group, l4Group);

    const selectedPreview = el('div', { class:'sx-preview empty' },
      el('i', { class:'fas fa-crosshairs lead' }),
      el('span', { class:'lbl' }, 'Selected'),
      el('span', { class:'val' }, '— none —'));

    /* CONFIG */
    const targetInput    = el('input', { type:'text',   id:'mhdTarget',     placeholder:'https://example.com or 1.2.3.4:80', autocomplete:'off' });
    const threadsInput   = el('input', { type:'number', id:'mhdThreads',    value:'10', min:'1', max:'1000' });
    const durationInput  = el('input', { type:'number', id:'mhdDuration',   value:'60', min:'1', max:'3600' });
    const proxyTypeInput = el('input', { type:'number', id:'mhdProxyType',  value:'0',  min:'0', max:'5' });
    const proxyFileInput = el('input', { type:'text',   id:'mhdProxyFile',  value:'proxies.txt' });
    const rpcInput       = el('input', { type:'number', id:'mhdRpc',        value:'1',  min:'1', max:'5' });
    const reflectorInput = el('input', { type:'text',   id:'mhdReflector',  placeholder:'reflectors.txt (AMP only)' });

    const targetField = el('div', { class:'sx-field', style:{ flex:'2 1 260px' } },
      el('label', null, 'Target', el('span', { class:'opt' }, 'required')),
      targetInput,
      el('div', { class:'err' },
        el('i', { class:'fas fa-circle-exclamation' }), ' Target is required'));

    const methodField = el('div', { class:'sx-field', style:{ flex:'1 1 200px' } },
      el('label', null, 'Method', el('span', { class:'opt' }, 'required')),
      methodSelect,
      el('div', { class:'err' },
        el('i', { class:'fas fa-circle-exclamation' }), ' Method is required'));

    /* BUTTONS */
    const startBtn = el('button', {
      class:'sx-btn sx-btn-primary', id:'mhdStartBtn', type:'button', 'aria-label':'Launch attack',
    }, el('i', { class:'fas fa-rocket' }), 'Launch Attack');

    const stopAllBtn = el('button', {
      class:'sx-btn sx-btn-danger', id:'mhdStopAllBtn', type:'button', 'aria-label':'Stop all running attacks',
    }, el('i', { class:'fas fa-hand' }), 'Stop All');

    /* TABLES */
    const runningTableBody = el('tbody', { id:'mhdRunningBody' });
    const historyTableBody = el('tbody', { id:'mhdHistoryBody' });

    /* ROOT */
    const root = el('div', { class:'mhd-root', 'data-mhd-version':VERSION },

      hero, kpis,

      el('div', { class:'sx-card' },
        el('div', { class:'sx-card-head' },
          el('i', { class:'ico fas fa-bullseye' }),
          el('h4', null, 'Attack Configuration'),
          el('span', { class:'hint' }, 'target + method required')),
        presetRow,
        el('div', { class:'sx-row', style:{ marginBottom:'14px' } }, targetField, methodField),
        pickerBar, chipGroups, selectedPreview,
        el('div', { class:'sx-row', style:{ marginTop:'16px' } },
          el('div', { class:'sx-field' }, el('label', null, 'Threads'),   threadsInput),
          el('div', { class:'sx-field' }, el('label', null, 'Duration', el('span', { class:'opt' }, 'sec')), durationInput),
          el('div', { class:'sx-field' }, el('label', null, 'Proxy type'), proxyTypeInput),
          el('div', { class:'sx-field' }, el('label', null, 'RPC'),       rpcInput)),
        el('div', { class:'sx-row', style:{ marginTop:'14px' } },
          el('div', { class:'sx-field', style:{ flex:'2 1 220px' } },
            el('label', null, 'Proxy file', el('span', { class:'opt' }, 'optional')),
            proxyFileInput),
          el('div', { class:'sx-field', style:{ flex:'2 1 220px' } },
            el('label', null, 'Reflector file', el('span', { class:'opt' }, 'AMP only')),
            reflectorInput)),
        el('div', { class:'sx-actions' }, startBtn, stopAllBtn)),

      el('div', { class:'sx-card' },
        el('div', { class:'sx-card-head' },
          el('i', { class:'ico fas fa-tower-broadcast' }),
          el('h4', null, 'Running Attacks'),
          el('span', { class:'hint mhd-running-count' }, '0 active')),
        el('div', { class:'sx-table-wrap' },
          el('table', { class:'sx-table' },
            el('thead', null, el('tr', null,
              el('th', null, 'ID'), el('th', null, 'Method'),
              el('th', null, 'Target'), el('th', null, 'Threads'),
              el('th', null, 'Duration'), el('th', null, 'Elapsed'),
              el('th', null, 'Status'), el('th', null, ''))),
            runningTableBody))),

      el('div', { class:'sx-card' },
        el('div', { class:'sx-card-head' },
          el('i', { class:'ico fas fa-clock-rotate-left' }),
          el('h4', null, 'Recent History'),
          el('span', { class:'hint' }, 'last ' + MAX_HISTORY + ' attacks')),
        el('div', { class:'sx-table-wrap' },
          el('table', { class:'sx-table' },
            el('thead', null, el('tr', null,
              el('th', null, 'ID'), el('th', null, 'Method'),
              el('th', null, 'Target'), el('th', null, 'Started'),
              el('th', null, 'Status'))),
            historyTableBody))),
    );

    /* ── EVENT WIRING ───────────────────────────────────────────── */
    function pickMethod(name) {
      selectedMethod.value = name;
      methodSelect.value = name;
      $$('.sx-chip', root).forEach(c => {
        const active = c.dataset.method === name;
        c.classList.toggle('active', active);
        c.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      if (name) {
        selectedPreview.classList.remove('empty');
        selectedPreview.innerHTML = '';
        selectedPreview.appendChild(el('i', { class:'fas fa-crosshairs lead' }));
        selectedPreview.appendChild(el('span', { class:'lbl' }, 'Selected'));
        selectedPreview.appendChild(el('span', { class:'val' }, name));
        methodField.classList.remove('invalid');
      } else {
        selectedPreview.classList.add('empty');
        selectedPreview.innerHTML = '';
        selectedPreview.appendChild(el('i', { class:'fas fa-crosshairs lead' }));
        selectedPreview.appendChild(el('span', { class:'lbl' }, 'Selected'));
        selectedPreview.appendChild(el('span', { class:'val' }, '— none —'));
      }
    }

    methodSelect.addEventListener('change', () => pickMethod(methodSelect.value));

    searchInput.addEventListener('input', () => {
      const q = searchInput.value.trim().toLowerCase();
      $$('.sx-chip', root).forEach(c => {
        c.style.display = (!q || c.dataset.method.toLowerCase().includes(q)) ? '' : 'none';
      });
    });

    let activeTab = 'all';
    function applyTab() {
      l7Group.style.display = (activeTab === 'all' || activeTab === 'l7') ? '' : 'none';
      l4Group.style.display = (activeTab === 'all' || activeTab === 'l4') ? '' : 'none';
      [tabAll, tabL7, tabL4].forEach(t => t.classList.toggle('active', t.dataset.tab === activeTab));
    }
    [tabAll, tabL7, tabL4].forEach(t => t.addEventListener('click', () => {
      activeTab = t.dataset.tab; applyTab();
    }));

    const renderChips = () => {
      l7chips.innerHTML = ''; l4chips.innerHTML = '';
      const l7 = state.layer7 || [], l4 = state.layer4 || [];
      l7Count.textContent = String(l7.length);
      l4Count.textContent = String(l4.length);
      l7.forEach(name => {
        const chip = el('button', {
          class:'sx-chip', type:'button', 'data-method':name,
          role:'option', 'aria-selected':'false',
        }, name);
        chip.addEventListener('click', () => pickMethod(name));
        l7chips.appendChild(chip);
      });
      l4.forEach(name => {
        const chip = el('button', {
          class:'sx-chip', type:'button', 'data-method':name,
          role:'option', 'aria-selected':'false',
        }, name);
        chip.addEventListener('click', () => pickMethod(name));
        l4chips.appendChild(chip);
      });
      if (!l7.length) l7chips.appendChild(el('div', { class:'sx-chips-empty' }, 'No Layer 7 methods'));
      if (!l4.length) l4chips.appendChild(el('div', { class:'sx-chips-empty' }, 'No Layer 4 methods'));
      if (selectedMethod.value) {
        const sel = selectedMethod.value;
        $$('.sx-chip', root).forEach(c => {
          const active = c.dataset.method === sel;
          c.classList.toggle('active', active);
          c.setAttribute('aria-selected', active ? 'true' : 'false');
        });
      }
    };

    presetRow.addEventListener('click', (e) => {
      const btn = e.target.closest('.sx-preset');
      if (!btn) return;
      const key = btn.dataset.preset;
      const cfg = PRESETS[key] && PRESETS[key].config;
      if (!cfg) return;
      if (cfg.threads != null)    threadsInput.value   = String(cfg.threads);
      if (cfg.duration != null)   durationInput.value  = String(cfg.duration);
      if (cfg.proxy_type != null) proxyTypeInput.value = String(cfg.proxy_type);
      if (cfg.rpc != null)        rpcInput.value       = String(cfg.rpc);
      toast('Preset "' + PRESETS[key].label + '" applied', 'ok', 2200);
    });

    startBtn.addEventListener('click', async () => {
      if (state.busy) return;
      const method = (selectedMethod.value || methodSelect.value || '').trim().toUpperCase();
      const target = targetInput.value.trim();

      methodField.classList.toggle('invalid', !method);
      targetField.classList.toggle('invalid', !target);

      if (!method) { toast('Pick a method first', 'warn'); searchInput.focus(); return; }
      if (!target) { toast('Enter a target', 'warn'); targetInput.focus(); return; }

      state.busy = true;
      startBtn.disabled = true;
      startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Launching…';

      try {
        const payload = {
          method, target,
          threads:        parseInt(threadsInput.value, 10)   || 10,
          duration:       parseInt(durationInput.value, 10)  || 60,
          proxy_type:     parseInt(proxyTypeInput.value, 10) || 0,
          proxy_file:     proxyFileInput.value.trim() || 'proxies.txt',
          rpc:            parseInt(rpcInput.value, 10)       || 1,
          reflector_file: reflectorInput.value.trim(),
        };
        const res = await jpost(API.start, payload);
        if (res.success) {
          state.launched++;
          toast('Attack ' + shortId(res.attack_id) + ' launched', 'ok');
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

    stopAllBtn.addEventListener('click', async () => {
      const n = (state.running || []).length;
      if (!n) { toast('Nothing running', 'info'); return; }
      const ok = await confirmDialog({
        title:'Stop all attacks?',
        message:'This will halt ' + n + ' running attack' + (n === 1 ? '' : 's') + '. This action cannot be undone.',
        confirmText:'Stop All',
      });
      if (!ok) return;
      try {
        const r = await jpost(API.stopAll, {});
        toast('Stopped ' + (r.stopped || 0) + ' attack(s)', 'ok');
        await refresh();
      } catch (e) {
        toast('Stop all failed: ' + e.message, 'err');
      }
    });

    root._refs = {
      runningTableBody, historyTableBody,
      runningCount: root.querySelector('.mhd-running-count'),
      statusPill, statusText,
      renderChips, methodSelect, pickMethod,
      kpiActive, kpiThreads, kpiLaunched, kpiAvg,
      kpiActiveTrend, kpiThreadsTrend, kpiLaunchedTrend, kpiAvgTrend,
      clockVal,
    };
    return root;
  }

  /* ── Status badge ──────────────────────────────────────────── */
  function statusBadge(status) {
    const cls = {
      running:'sx-badge-running', stopped:'sx-badge-stopped',
      failed:'sx-badge-failed',   completed:'sx-badge-done',
      done:'sx-badge-done',       timeout:'sx-badge-timeout',
    }[status] || 'sx-badge-stopped';
    return el('span', { class:'sx-badge ' + cls }, status || 'unknown');
  }

  function setTrend(node, delta) {
    if (!node) return;
    node.classList.remove('up', 'down', 'flat');
    if (delta === 0 || delta == null) {
      node.classList.add('flat'); node.textContent = '—'; return;
    }
    node.classList.add(delta > 0 ? 'up' : 'down');
    node.textContent = (delta > 0 ? '▲ ' : '▼ ') + Math.abs(delta);
  }

  function flashKpi(node) {
    const kpi = node.closest('.sx-kpi');
    if (!kpi) return;
    kpi.classList.remove('flash');
    void kpi.offsetWidth;
    kpi.classList.add('flash');
    setTimeout(() => kpi.classList.remove('flash'), 900);
  }

  function updateKPIs(refs) {
    if (!refs) return;
    const runCount = (state.running || []).length;
    const totalThreads = (state.running || []).reduce((a, b) => a + (parseInt(b.threads, 10) || 0), 0);

    const pa = refs.kpiActive.firstChild.nodeValue;
    refs.kpiActive.firstChild.nodeValue = String(runCount);
    if (pa !== String(runCount)) flashKpi(refs.kpiActive);
    setTrend(refs.kpiActiveTrend, runCount - state.prevCounts.active);

    const pt = refs.kpiThreads.firstChild.nodeValue;
    refs.kpiThreads.firstChild.nodeValue = String(totalThreads);
    if (pt !== String(totalThreads)) flashKpi(refs.kpiThreads);
    setTrend(refs.kpiThreadsTrend, totalThreads - state.prevCounts.threads);

    refs.kpiLaunched.firstChild.nodeValue = String(state.launched);
    if (state.launched !== state.prevCounts.launched) {
      flashKpi(refs.kpiLaunched);
      setTrend(refs.kpiLaunchedTrend, state.launched - state.prevCounts.launched);
    }

    let avg = '—';
    const hist = state.history || [];
    if (hist.length) {
      const vals = hist.filter(h => h.duration != null)
        .map(h => parseInt(h.duration, 10)).filter(n => !isNaN(n));
      if (vals.length) avg = Math.round(vals.reduce((a, b) => a + b, 0) / vals.length) + 's';
    }
    refs.kpiAvg.firstChild.nodeValue = avg;

    state.prevCounts = { active:runCount, threads:totalThreads, launched:state.launched };
  }

  function updateStatusPill(refs) {
    if (!refs || !refs.statusPill) return;
    const n = (state.running || []).length;
    if (n > 0) {
      refs.statusPill.classList.remove('is-idle');
      if (refs.statusText) refs.statusText.textContent = n + ' running';
    } else {
      refs.statusPill.classList.add('is-idle');
      if (refs.statusText) refs.statusText.textContent = 'Idle';
    }
  }

  /* Safe querySelector for attack row */
  function findRow(tbody, id) {
    const rows = tbody.querySelectorAll('tr[data-attack-id]');
    for (let i = 0; i < rows.length; i++) {
      if (rows[i].getAttribute('data-attack-id') === String(id)) return rows[i];
    }
    return null;
  }

  /* ── Render running ────────────────────────────────────────── */
  function renderRunning(root) {
    const tbody = root._refs.runningTableBody;
    const refs = root._refs;

    if (refs.runningCount) {
      const n = (state.running || []).length;
      refs.runningCount.textContent = n ? n + ' active' : '0 active';
    }

    if (!state.running.length) {
      tbody.innerHTML = '';
      tbody.appendChild(el('tr', null,
        el('td', { colspan:'8' },
          emptyState('No attacks running',
            'Configure a target above and launch to see live activity here.'))));
      return;
    }

    const seen = new Set();

    for (const atk of state.running) {
      const id = atk.attack_id;
      if (!id) continue;
      seen.add(String(id));

      let row = findRow(tbody, id);

      if (!row) {
        const emptyRow = tbody.querySelector('tr td[colspan="8"]');
        if (emptyRow && emptyRow.parentElement) emptyRow.parentElement.remove();

        const stopBtn = el('button', {
          class:'sx-btn-mini', type:'button', title:'Stop this attack',
          'aria-label':'Stop attack ' + shortId(id),
        }, el('i', { class:'fas fa-stop' }), 'Stop');

        stopBtn.addEventListener('click', async () => {
          stopBtn.disabled = true;
          stopBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
          try {
            await jpost(API.stop, { attack_id: id });
            toast('Stopped ' + shortId(id), 'ok');
            await refresh();
          } catch (e) {
            toast('Stop failed: ' + e.message, 'err');
            stopBtn.disabled = false;
            stopBtn.innerHTML = '<i class="fas fa-stop"></i> Stop';
          }
        });

        row = el('tr', { 'data-attack-id': String(id) },
          el('td', null, el('code', null, shortId(id))),
          el('td', null, el('code', null, atk.method || '—')),
          el('td', null, el('code', null, atk.target || '—')),
          el('td', { class:'t-dim' }, String(atk.threads != null ? atk.threads : '—')),
          el('td', { class:'t-dim' }, (atk.duration != null ? atk.duration : '—') + 's'),
          el('td', null,
            el('div', { class:'sx-elapsed-cell' },
              el('div', { class:'sx-elapsed-label' }, '0s'),
              el('div', { class:'sx-elapsed-track' },
                el('div', { class:'sx-elapsed-fill', style:{ width:'0%' } })))),
          el('td', null, statusBadge(atk.status)),
          el('td', null, stopBtn));
        tbody.appendChild(row);
      } else {
        const cells = row.children;
        if (atk.method && cells[1] && cells[1].querySelector('code') &&
            cells[1].querySelector('code').textContent !== atk.method) {
          cells[1].querySelector('code').textContent = atk.method;
        }
        if (atk.target && cells[2] && cells[2].querySelector('code') &&
            cells[2].querySelector('code').textContent !== atk.target) {
          cells[2].querySelector('code').textContent = atk.target;
        }
        if (atk.threads != null && cells[3].textContent !== String(atk.threads)) {
          cells[3].textContent = String(atk.threads);
        }
        if (atk.duration != null && cells[4].textContent !== (atk.duration + 's')) {
          cells[4].textContent = atk.duration + 's';
        }
        const badge = cells[6].firstChild;
        const wantCls = 'sx-badge ' + ({
          running:'sx-badge-running', stopped:'sx-badge-stopped',
          failed:'sx-badge-failed',   completed:'sx-badge-done',
          done:'sx-badge-done',       timeout:'sx-badge-timeout',
        }[atk.status] || 'sx-badge-stopped');
        if (badge && badge.className !== wantCls) {
          cells[6].innerHTML = '';
          cells[6].appendChild(statusBadge(atk.status));
        }
      }
    }

    Array.from(tbody.querySelectorAll('tr[data-attack-id]')).forEach(tr => {
      if (!seen.has(String(tr.getAttribute('data-attack-id')))) tr.remove();
    });

    if (!tbody.querySelector('tr[data-attack-id]') && !tbody.querySelector('td[colspan="8"]')) {
      tbody.appendChild(el('tr', null,
        el('td', { colspan:'8' },
          emptyState('No attacks running',
            'Configure a target above and launch to see live activity here.'))));
    }
  }

  function tickElapsed(root) {
    if (!root || !root._refs) return;
    const tbody = root._refs.runningTableBody;
    if (tbody) {
      const rows = tbody.querySelectorAll('tr[data-attack-id]');
      for (let i = 0; i < rows.length; i++) {
        const tr = rows[i];
        const id = tr.getAttribute('data-attack-id');
        const atk = state.running.find(a => String(a.attack_id) === id);
        if (!atk) continue;
        const sec = elapsedSec(atk.started_at);
        const dur = parseInt(atk.duration, 10) || 60;
        const pct = Math.min(100, (sec / dur) * 100);
        const cell = tr.children[5];
        if (!cell) continue;
        const label = cell.querySelector('.sx-elapsed-label');
        const fill = cell.querySelector('.sx-elapsed-fill');
        if (label) label.textContent = fmtDuration(sec);
        if (fill)  fill.style.width = pct.toFixed(1) + '%';
      }
    }
    if (root._refs.clockVal) {
      const d = new Date();
      root._refs.clockVal.textContent =
        String(d.getUTCHours()).padStart(2,'0') + ':' +
        String(d.getUTCMinutes()).padStart(2,'0') + ':' +
        String(d.getUTCSeconds()).padStart(2,'0');
    }
  }

  function renderHistory(root) {
    const tbody = root._refs.historyTableBody;
    tbody.innerHTML = '';
    if (!state.history.length) {
      tbody.appendChild(el('tr', null,
        el('td', { colspan:'5' },
          emptyState('No history yet',
            'Completed attacks will appear here once the engine reports back.'))));
      return;
    }
    const slice = state.history.slice(-MAX_HISTORY).reverse();
    for (const entry of slice) {
      tbody.appendChild(el('tr', null,
        el('td', null, el('code', null, shortId(entry.attack_id))),
        el('td', null, el('code', null, entry.method || '—')),
        el('td', null, el('code', null, entry.target || '—')),
        el('td', { class:'t-dim', title: fmtTime(entry.started_at) }, fmtRelative(entry.started_at)),
        el('td', null, statusBadge(entry.status))));
    }
  }

  /* ── Polling ───────────────────────────────────────────────── */
  function startPolling() {
    stopPolling();
    state.pollTimer = setInterval(refresh, POLL_MS);
    state.tickTimer = setInterval(() => {
      const root = state.mountEl && state.mountEl.querySelector('.mhd-root');
      if (root) tickElapsed(root);
    }, TICK_MS);
  }
  function stopPolling() {
    if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
    if (state.tickTimer) { clearInterval(state.tickTimer); state.tickTimer = null; }
  }

  async function refresh() {
    if (!state.mounted) return;
    try {
      const data = await jget(API.status);
      state.running = data.running || [];
      state.history = data.history || [];

      const root = state.mountEl && state.mountEl.querySelector('.mhd-root');
      if (!root || !root._refs) return;

      if (data.methods) {
        const changed = state.methods.length !== (data.methods || []).length;
        state.methods = data.methods || [];
        state.layer7  = data.layer7  || [];
        state.layer4  = data.layer4  || [];
        if (changed) {
          const sel = root._refs.methodSelect;
          const prev = sel.value;
          sel.innerHTML = '<option value="">Select a method…</option>';
          state.methods.forEach(m => sel.appendChild(el('option', { value:m }, m)));
          sel.value = prev;
          root._refs.renderChips();
        }
      }

      renderRunning(root);
      renderHistory(root);
      updateStatusPill(root._refs);
      updateKPIs(root._refs);
      tickElapsed(root);
    } catch (e) {
      console.warn('[MHDDoSControl] refresh error', e);
    }
  }

  /* ── Error card ────────────────────────────────────────────── */
  function renderErrorCard(mountEl, err) {
    try {
      mountEl.innerHTML = '';
      const card = el('div', { class:'sx-error-card' },
        el('h4', null,
          el('i', { class:'fas fa-triangle-exclamation' }),
          'MHDDoS Control Panel — render failed'),
        el('p', { style:{ margin:'0 0 12px', color:'#fca5a5', fontSize:'.82rem' } },
          'The panel could not be mounted. Details below (also printed to console):'),
        el('pre', null, (err && (err.stack || err.message)) || String(err)));
      mountEl.appendChild(card);
    } catch (_) {
      mountEl.textContent = 'MHDDoS Control: render failed — see console.';
    }
  }

  /* ── Mount / unmount ───────────────────────────────────────── */
  function mount(target) {
    try {
      let elMount = null;
      if (typeof target === 'string') elMount = document.querySelector(target);
      else if (target instanceof Element) elMount = target;
      else elMount = document.querySelector('[data-emergens-panel="mhddos"]');

      if (!elMount) {
        console.warn('[MHDDoSControl] mount point not found (selector: [data-emergens-panel="mhddos"])');
        return false;
      }

      /* Already mounted here? Skip rebuild if identical. */
      if (state.mounted && state.mountEl === elMount && elMount.querySelector('.mhd-root')) {
        return true;
      }

      if (state.mounted) unmount();

      injectCSS();
      state.mountEl = elMount;
      state.launched = 0;
      state.prevCounts = { active:0, threads:0, launched:0 };

      let root;
      try {
        root = buildUI();
      } catch (err) {
        console.error('[MHDDoSControl] buildUI() threw:', err);
        renderErrorCard(elMount, err);
        return false;
      }

      elMount.innerHTML = '';
      elMount.appendChild(root);
      elMount.setAttribute('data-mhd-mounted', VERSION);
      state.mounted = true;

      console.log('[MHDDoSControl] mounted v' + VERSION + ' at', elMount);

      /* Async: load methods then begin polling */
      (async () => {
        try {
          const data = await jget(API.methods);
          state.methods = data.methods || [];
          state.layer7  = data.layer7  || [];
          state.layer4  = data.layer4  || [];

          const r = state.mountEl && state.mountEl.querySelector('.mhd-root');
          if (r && r._refs) {
            const sel = r._refs.methodSelect;
            sel.innerHTML = '<option value="">Select a method…</option>';
            state.methods.forEach(m => sel.appendChild(el('option', { value:m }, m)));
            r._refs.renderChips();
          }
        } catch (e) {
          console.warn('[MHDDoSControl] methods fetch failed', e);
          toast('Failed to load methods: ' + e.message, 'err');
        }
        await refresh();
        startPolling();
      })();

      return true;
    } catch (err) {
      console.error('[MHDDoSControl] mount() threw:', err);
      try {
        const elMount = document.querySelector('[data-emergens-panel="mhddos"]');
        if (elMount) renderErrorCard(elMount, err);
      } catch (_) {}
      return false;
    }
  }

  function unmount() {
    stopPolling();
    state.mounted = false;
    state.mountEl = null;
  }

  /* ── Auto-mount with retry (defensive) ─────────────────────── */
  function tryAutoMount() {
    const ph = document.querySelector('[data-emergens-panel="mhddos"]');
    if (!ph) return false;
    if (ph.getAttribute('data-mhd-mounted') === VERSION) return true;
    return mount(ph);
  }

  function bootAutoMount() {
    /* Immediate attempt */
    if (tryAutoMount()) return;
    /* Retry at 100 / 400 / 1200 ms */
    [100, 400, 1200].forEach(ms => setTimeout(() => {
      if (!state.mounted) tryAutoMount();
    }, ms));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootAutoMount);
  } else {
    bootAutoMount();
  }
  window.addEventListener('load', () => {
    if (!state.mounted) tryAutoMount();
  });

  /* ── Public API ────────────────────────────────────────────── */
  window.MHDDoSControl = {
    version: VERSION,
    mount, unmount, refresh,
    get state() { return { ...state }; },
  };
})();