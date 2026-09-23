(function () {
  'use strict';

  /* ── endpoints ───────────────────────────────────────────────────── */
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
    sqlmap: {
      scan:      '/api/sqlmap/scan',
    },
    sqlinj: {
      scan:      '/api/sql_injection/scan',
    },
    xss: {
      wordlist:  '/api/xss/wordlist',
      scan:      '/api/xss/scan',
      stream:    '/api/xss/scan/stream',
    },
    xssSimple: {
      scan:      '/api/xss_simple/scan',
    },
    sniper: {
      scan:      '/api/sniper/scan',
      stream:    '/api/sniper/scan/stream',
    },
    logger: {
      list:      '/api/logger/requests',
      detail:    '/api/logger/requests',
      stats:     '/api/logger/stats',
      clear:     '/api/logger/clear',
      tag:       '/api/logger/requests',
      har:       '/api/logger/har',
      stream:    '/api/logger/stream',
    },
  };

  /* ── tiny helpers ────────────────────────────────────────────────── */
  const $  = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function el(tag, attrs, ...children) {
    const n = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'html') n.innerHTML = v;
      else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2).toLowerCase(), v);
      else n.setAttribute(k, v);
    }
    for (const c of children) {
      if (c == null || c === false) continue;
      n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return n;
  }

  function toast(msg, kind = 'info', ms = 3200) {
    let c = document.getElementById('toastContainer');
    if (!c) { c = el('div', { id: 'toastContainer', class: 'toast-container' }); document.body.appendChild(c); }
    const n = el('div', { class: 'toast toast-' + kind }, msg);
    c.appendChild(n);
    setTimeout(() => { n.style.opacity = '0'; setTimeout(() => n.remove(), 300); }, ms);
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

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function download(filename, text, mime) {
    const blob = new Blob([text], { type: mime || 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = el('a', { href: url, download: filename });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  function pretty(obj) { try { return JSON.stringify(obj, null, 2); } catch (_) { return String(obj); } }

  function parseQS(url) {
    try {
      const u = new URL(url, location.origin);
      const out = {};
      u.searchParams.forEach((v, k) => { out[k] = v; });
      return out;
    } catch (_) { return {}; }
  }

  /* ── state ───────────────────────────────────────────────────────── */
  const state = {
    mounted: false,
    mountEl: null,
    activeTab: 'dirfuzz',
    streams: {},     // name → EventSource
    loggerES: null,
    loggerEntries: [],
    loggerStats: null,
  };

  /* ── CSS ─────────────────────────────────────────────────────────── */
  const CSS = `
  .ex-root { display:flex; flex-direction:column; gap:14px; }
  .ex-tabs {
    display:flex; flex-wrap:wrap; gap:6px;
    padding:6px;
    background: var(--bg-tertiary, #14171b);
    border:1px solid var(--border-color,#2a2f36);
    border-radius:10px;
  }
  .ex-tab {
    padding:8px 14px; border-radius:7px; border:1px solid transparent;
    background: transparent; color: var(--text-secondary,#98a1ab);
    font-size:.78rem; font-weight:600; letter-spacing:.03em;
    cursor:pointer; display:flex; align-items:center; gap:6px;
    transition: all .12s ease;
  }
  .ex-tab:hover { color: var(--text-primary,#e5e7eb); background: rgba(255,255,255,.04); }
  .ex-tab.active { background: var(--accent,#60a5fa); color:#0b0d10; }
  .ex-tab i { font-size:.78rem; }

  .ex-panel { display:none; }
  .ex-panel.active { display:flex; flex-direction:column; gap:12px; }

  .ex-card {
    background: var(--bg-tertiary,#14171b);
    border:1px solid var(--border-color,#2a2f36);
    border-radius:10px; padding:14px;
  }
  .ex-card h4 {
    margin:0 0 10px;
    font-size:.78rem; letter-spacing:.09em; text-transform: uppercase;
    color: var(--text-secondary,#98a1ab);
    display:flex; align-items:center; gap:8px;
  }
  .ex-card h4 i { color: var(--accent,#60a5fa); }

  .ex-row { display:flex; gap:8px; flex-wrap:wrap; }
  .ex-row > * { flex:1 1 150px; min-width:0; }
  .ex-row.tight > * { flex: 0 0 auto; }

  .ex-field { display:flex; flex-direction:column; gap:5px; }
  .ex-field > label {
    font-size:.68rem; letter-spacing:.05em;
    color: var(--text-muted,#6b7280); text-transform: uppercase;
  }
  .ex-field > input, .ex-field > select, .ex-field > textarea {
    background: var(--bg-secondary,#0d1013);
    border:1px solid var(--border-color,#2a2f36);
    border-radius:7px; padding:9px 11px;
    color: var(--text-primary,#e5e7eb);
    font-size:.85rem;
    font-family: var(--font-mono, ui-monospace, monospace);
    outline: none; transition: border-color .15s ease;
  }
  .ex-field > input:focus, .ex-field > select:focus, .ex-field > textarea:focus {
    border-color: var(--accent,#60a5fa);
  }
  .ex-field > textarea { min-height: 70px; resize: vertical; }

  .ex-actions { display:flex; gap:8px; margin-top:4px; }
  .ex-btn {
    padding:10px 16px; border-radius:8px; border:1px solid transparent;
    font-weight:700; font-size:.8rem; cursor:pointer;
    display:inline-flex; align-items:center; justify-content:center; gap:7px;
    transition: transform .1s ease, opacity .15s;
  }
  .ex-btn:active { transform: scale(.98); }
  .ex-btn[disabled] { opacity:.5; cursor:not-allowed; }
  .ex-btn-primary { background: linear-gradient(135deg,#3b82f6,#1d4ed8); color:#fff; }
  .ex-btn-danger  { background: linear-gradient(135deg,#ef4444,#b91c1c); color:#fff; }
  .ex-btn-ghost   { background: var(--bg-secondary,#0d1013); border-color: var(--border-color,#2a2f36); color: var(--text-secondary,#98a1ab); }

  .ex-progress {
    margin-top:10px;
    height:8px; width:100%;
    background: var(--bg-secondary,#0d1013);
    border-radius:99px; overflow:hidden;
    border:1px solid var(--border-color,#2a2f36);
  }
  .ex-progress > span {
    display:block; height:100%; width:0%;
    background: linear-gradient(90deg, #3b82f6, #60a5fa);
    transition: width .2s ease;
  }
  .ex-progress-label {
    display:flex; justify-content:space-between;
    font-size:.72rem; color: var(--text-muted,#6b7280); margin-top:6px;
  }

  .ex-log {
    max-height: 280px; overflow:auto;
    background: #08090b; border:1px solid var(--border-color,#2a2f36);
    border-radius:8px; padding:10px;
    font-family: var(--font-mono, monospace); font-size:.72rem;
    color: #d1d5db; white-space: pre-wrap;
  }
  .ex-log .ok   { color:#22c55e; }
  .ex-log .warn { color:#f59e0b; }
  .ex-log .err  { color:#ef4444; }
  .ex-log .dim  { color:#6b7280; }

  .ex-result {
    background: #08090b; border:1px solid var(--border-color,#2a2f36);
    border-radius:8px; padding:12px;
    font-family: var(--font-mono, monospace); font-size:.74rem;
    color: #d1d5db; white-space: pre-wrap;
    max-height: 480px; overflow:auto;
  }

  .ex-badge {
    display:inline-block; padding:3px 8px; border-radius:99px;
    font-size:.66rem; font-weight:700; text-transform: uppercase; letter-spacing:.05em;
  }
  .ex-badge-critical { background: rgba(239,68,68,.18); color:#ef4444; }
  .ex-badge-high     { background: rgba(249,115,22,.18); color:#f97316; }
  .ex-badge-medium   { background: rgba(245,158,11,.18); color:#f59e0b; }
  .ex-badge-low      { background: rgba(59,130,246,.18); color:#3b82f6; }
  .ex-badge-info     { background: rgba(156,163,175,.18); color:#9ca3af; }
  .ex-badge-safe     { background: rgba(34,197,94,.18); color:#22c55e; }

  .ex-chips { display:flex; flex-wrap:wrap; gap:5px; max-height:120px; overflow:auto; padding:4px 0; }
  .ex-chip {
    padding:4px 9px; border-radius:6px;
    border:1px solid var(--border-color,#2a2f36);
    background: var(--bg-secondary,#0d1013);
    color: var(--text-secondary,#98a1ab);
    font-family: var(--font-mono, monospace); font-size:.7rem;
    cursor:pointer; transition: all .12s ease;
  }
  .ex-chip:hover { border-color: var(--accent,#60a5fa); color: var(--text-primary,#e5e7eb); }
  .ex-chip.active { background: var(--accent,#60a5fa); color:#0b0d10; font-weight:700; }

  .ex-findings { display:flex; flex-direction:column; gap:6px; }
  .ex-finding {
    background: var(--bg-secondary,#0d1013);
    border-left: 3px solid var(--accent,#60a5fa);
    border-radius: 6px; padding: 10px 12px;
    font-size:.78rem;
  }
  .ex-finding.critical { border-left-color: #ef4444; }
  .ex-finding.high     { border-left-color: #f97316; }
  .ex-finding.medium   { border-left-color: #f59e0b; }
  .ex-finding.low      { border-left-color: #3b82f6; }
  .ex-finding.safe     { border-left-color: #22c55e; }
  .ex-finding .label { font-size:.66rem; text-transform:uppercase; letter-spacing:.06em; color:var(--text-muted,#6b7280); }
  .ex-finding .value { font-family: var(--font-mono, monospace); word-break:break-all; margin-top:3px; color:var(--text-primary,#e5e7eb); }
  .ex-finding .meta { margin-top:6px; font-size:.68rem; color:var(--text-muted,#6b7280); display:flex; gap:10px; flex-wrap:wrap; }

  .ex-kpis { display:grid; grid-template-columns: repeat(4, 1fr); gap:10px; }
  @media (max-width: 700px) { .ex-kpis { grid-template-columns: repeat(2, 1fr); } }
  .ex-kpi {
    background: var(--bg-secondary,#0d1013);
    border:1px solid var(--border-color,#2a2f36);
    border-radius:9px; padding:12px;
    display:flex; flex-direction:column; gap:4px;
  }
  .ex-kpi .k-label { font-size:.66rem; letter-spacing:.06em; text-transform:uppercase; color:var(--text-muted,#6b7280); }
  .ex-kpi .k-val   { font-family: var(--font-mono, monospace); font-size:1.25rem; color:var(--text-primary,#e5e7eb); }

  .ex-table { width:100%; border-collapse:collapse; font-size:.76rem; }
  .ex-table th, .ex-table td {
    text-align:left; padding:7px 9px;
    border-bottom:1px solid var(--border-color,#2a2f36);
  }
  .ex-table th {
    font-size:.66rem; letter-spacing:.05em; text-transform:uppercase;
    color:var(--text-muted,#6b7280); font-weight:600;
  }
  .ex-table code { font-family: var(--font-mono, monospace); font-size:.72rem; color:var(--text-secondary,#98a1ab); word-break:break-all; }
  .ex-table tbody tr:hover { background: rgba(255,255,255,.03); }
  .ex-table tbody tr { cursor: pointer; }

  .ex-empty { padding:18px; text-align:center; color:var(--text-muted,#6b7280); font-size:.82rem; }

  .ex-live-pill {
    display:inline-flex; align-items:center; gap:5px;
    padding:3px 9px; border-radius:99px;
    background: rgba(34,197,94,.13); color:#22c55e;
    font-size:.66rem; font-weight:700; letter-spacing:.05em; text-transform: uppercase;
  }
  .ex-live-pill .dot {
    width:6px; height:6px; border-radius:50%; background:#22c55e;
    animation: expPulse 1.4s ease-in-out infinite;
  }
  @keyframes expPulse { 0%,100% { opacity:1; } 50% { opacity:.25; } }
  `;

  function injectCSS() {
    if (document.getElementById('ex-css')) return;
    const s = document.createElement('style');
    s.id = 'ex-css';
    s.textContent = CSS;
    document.head.appendChild(s);
  }

  /* ── shared UI builders ──────────────────────────────────────────── */
  function buildCard(title, icon, ...children) {
    return el('div', { class: 'ex-card' },
      el('h4', null, el('i', { class: 'fas ' + icon }), title),
      ...children,
    );
  }

  function buildField(label, input) {
    return el('div', { class: 'ex-field' }, el('label', null, label), input);
  }

  function buildProgress() {
    const bar = el('span', { style: 'width:0%;' });
    const wrapper = el('div', { class: 'ex-progress' }, bar);
    const labelL = el('span', null, 'Idle');
    const labelR = el('span', null, '0%');
    const row = el('div', { class: 'ex-progress-label' }, labelL, labelR);
    const root = el('div', null, wrapper, row);
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
      const line_el = el('div', { class: cls || '' }, line);
      root.appendChild(line_el);
      root.scrollTop = root.scrollHeight;
      if (root.childNodes.length > 800) root.removeChild(root.firstChild);
    };
    root._clear = () => { root.innerHTML = ''; };
    return root;
  }

  function buildResultPanel() {
    const root = el('div', { class: 'ex-result', html: '<span class="dim">No results yet.</span>' });
    root._set = (data) => {
      if (typeof data === 'string') root.textContent = data;
      else root.textContent = pretty(data);
      root.scrollTop = 0;
    };
    root._clear = () => { root.innerHTML = '<span class="dim">No results yet.</span>'; };
    return root;
  }

  function severityBadge(sev) {
    const s = String(sev || 'info').toLowerCase();
    return el('span', { class: 'ex-badge ex-badge-' + s }, s);
  }

  /* ==================================================================
   *  TABS
   * ================================================================== */
  const TABS = [
    { id: 'dirfuzz',    label: 'Dirfuzz',      icon: 'fa-folder-tree' },
    { id: 'sqli',       label: 'SQLi Engine',  icon: 'fa-database' },
    { id: 'sqlmap',     label: 'SQLMap',       icon: 'fa-magnifying-glass-chart' },
    { id: 'sqlinj',     label: 'SQL (light)',  icon: 'fa-bolt' },
    { id: 'xss',        label: 'XSS Exploiter',icon: 'fa-code' },
    { id: 'xssSimple',  label: 'XSS (simple)', icon: 'fa-wand-magic' },
    { id: 'sniper',     label: 'Sniper',       icon: 'fa-crosshairs' },
    { id: 'logger',     label: 'HTTP Logger',  icon: 'fa-wave-square' },
  ];

  /* ==================================================================
   *  TAB BUILDERS
   * ================================================================== */

  /* ── 1. Dirfuzz ─────────────────────────────────────────────────── */
  function buildDirfuzzTab() {
    const target   = el('input', { type: 'text', placeholder: 'https://example.com', autocomplete: 'off' });
    const wordlist = el('select');
    const maxPaths = el('input', { type: 'number', value: '200' });
    const conc     = el('input', { type: 'number', value: '24' });
    const rate     = el('input', { type: 'number', value: '40', step: '0.1' });
    const timeout  = el('input', { type: 'number', value: '4', step: '0.5' });
    const follow   = el('input', { type: 'checkbox' });

    const startBtn = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-play' }), 'Start Scan');
    const stopBtn  = el('button', { class: 'ex-btn ex-btn-ghost', disabled: true }, el('i', { class: 'fas fa-stop' }), 'Stop');
    const streamToggle = el('input', { type: 'checkbox', checked: true });

    const progress = buildProgress();
    const logPanel = buildLogPanel();
    const findingsBox = el('div', { class: 'ex-findings' });

    // Populate wordlists
    (async () => {
      try {
        const res = await jget(EP.dirfuzz.wordlists);
        (res.wordlists || []).forEach(w => {
          wordlist.appendChild(el('option', { value: w.name }, `${w.name} (${w.count})`));
        });
        if (!wordlist.options.length) wordlist.appendChild(el('option', { value: 'lottery-dirs.txt' }, 'lottery-dirs.txt'));
      } catch (_) {
        wordlist.appendChild(el('option', { value: 'lottery-dirs.txt' }, 'lottery-dirs.txt'));
      }
    })();

    let currentES = null;

    function renderDirfuzzHits(hits) {
      findingsBox.innerHTML = '';
      if (!hits || !hits.length) {
        findingsBox.appendChild(el('div', { class: 'ex-empty' }, 'No hits'));
        return;
      }
      hits.slice(0, 200).forEach(h => {
        const f = el('div', { class: 'ex-finding ' + (h.severity || 'info') },
          el('div', { class: 'label' }, `${h.category || 'other'} · path`),
          el('div', { class: 'value' }, h.url || h.path || ''),
          el('div', { class: 'meta' },
            el('span', null, 'Status: ', String(h.status)),
            el('span', null, 'Size: ', String(h.size || 0)),
            el('span', null, 'Severity: ', severityBadge(h.severity)),
            h.redirect_to ? el('span', null, '→ ', h.redirect_to) : null,
          ),
          (h.secrets && h.secrets.length) ? el('div', { class: 'value', style: 'margin-top:6px;color:#ef4444;' },
            'Secrets: ' + h.secrets.map(s => s.type).join(', ')
          ) : null,
        );
        findingsBox.appendChild(f);
      });
    }

    async function startBlocking() {
      startBtn.disabled = true; stopBtn.disabled = false;
      progress._reset(); progress._set(0, 'Running…');
      logPanel._clear();
      logPanel._append('[blocking] starting dirfuzz…', 'dim');
      try {
        const body = {
          target: target.value.trim(),
          wordlist_name: wordlist.value,
          max_paths: parseInt(maxPaths.value, 10) || 200,
          concurrency: parseInt(conc.value, 10) || 24,
          rate_limit: parseFloat(rate.value) || 40,
          timeout: parseFloat(timeout.value) || 4,
          follow_redirects: !!follow.checked,
        };
        if (!body.target) { toast('Target required', 'warn'); return; }
        const res = await jpost(EP.dirfuzz.scan, body);
        progress._set(100, 'Complete');
        logPanel._append(`[done] tried=${res.tried} hits=${res.hits_count} elapsed=${res.elapsed}s`, 'ok');
        renderDirfuzzHits(res.hits || []);
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
        target: target.value.trim(),
        wordlist_name: wordlist.value,
        max_paths: maxPaths.value,
        concurrency: conc.value,
        rate_limit: rate.value,
        timeout: timeout.value,
        follow_redirects: follow.checked ? '1' : '0',
      });
      const es = new EventSource(EP.dirfuzz.stream + '?' + qs.toString());
      currentES = es;

      es.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data);
          if (data.type === 'progress') {
            progress._set(data.percent || 0, `${data.label || ''} (${data.done}/${data.total})`);
          } else if (data.type === 'result') {
            progress._set(100, 'Complete');
            logPanel._append(`[done] tried=${data.data.tried} hits=${data.data.hits_count}`, 'ok');
            renderDirfuzzHits(data.data.hits || []);
            es.close(); currentES = null;
            startBtn.disabled = false; stopBtn.disabled = true;
          } else if (data.type === 'error') {
            logPanel._append('[error] ' + data.message, 'err');
            es.close(); currentES = null;
            startBtn.disabled = false; stopBtn.disabled = true;
          } else if (data.type === 'start') {
            logPanel._append('[start] ' + data.base, 'dim');
          }
        } catch (e) { logPanel._append('[parse] ' + e.message, 'warn'); }
      };
      es.onerror = () => {
        logPanel._append('[sse] connection error', 'warn');
        es.close(); currentES = null;
        startBtn.disabled = false; stopBtn.disabled = true;
      };
    }

    startBtn.addEventListener('click', () => {
      if (!target.value.trim()) { toast('Target required', 'warn'); return; }
      if (streamToggle.checked) startStreaming(); else startBlocking();
    });
    stopBtn.addEventListener('click', () => {
      if (currentES) { currentES.close(); currentES = null; logPanel._append('[stopped]', 'warn'); }
      startBtn.disabled = false; stopBtn.disabled = true;
      progress._set(0, 'Stopped');
    });

    return el('div', { class: 'ex-panel', id: 'ex-tab-dirfuzz' },
      buildCard('Directory / File Fuzzer', 'fa-folder-tree',
        el('div', { class: 'ex-row' },
          buildField('Target', target),
          buildField('Wordlist', wordlist),
        ),
        el('div', { class: 'ex-row', style: 'margin-top:8px;' },
          buildField('Max paths', maxPaths),
          buildField('Concurrency', conc),
          buildField('Rate limit (req/s)', rate),
          buildField('Timeout (s)', timeout),
        ),
        el('div', { class: 'ex-row tight', style: 'margin-top:10px; align-items:center;' },
          el('label', { style: 'display:flex;gap:6px;align-items:center;font-size:.78rem;' },
            follow, 'Follow redirects'),
          el('label', { style: 'display:flex;gap:6px;align-items:center;font-size:.78rem;' },
            streamToggle, 'Stream results (SSE)'),
          el('div', { style: 'flex:1 1 auto;' }),
          startBtn, stopBtn,
        ),
        progress,
        logPanel,
      ),
      buildCard('Findings', 'fa-list-check', findingsBox),
    );
  }

  /* ── 2. SQLi Engine ─────────────────────────────────────────────── */
  function buildSqliTab() {
    const target = el('input', { type: 'text', placeholder: 'https://example.com/page?id=1', autocomplete: 'off' });
    const method = el('select', null,
      el('option', { value: 'GET' }, 'GET'),
      el('option', { value: 'POST' }, 'POST'),
    );
    const maxParams = el('input', { type: 'number', value: '10' });
    const rate = el('input', { type: 'number', value: '20', step: '0.5' });
    const timeout = el('input', { type: 'number', value: '8', step: '0.5' });

    const techniquesWrap = el('div', { class: 'ex-chips' });
    const techniques = ['error', 'boolean', 'time', 'union'];
    const activeTech = new Set(['error', 'boolean', 'time', 'union']);
    techniques.forEach(t => {
      const chip = el('button', { class: 'ex-chip active', type: 'button' }, t);
      chip.addEventListener('click', () => {
        if (activeTech.has(t)) { activeTech.delete(t); chip.classList.remove('active'); }
        else { activeTech.add(t); chip.classList.add('active'); }
      });
      techniquesWrap.appendChild(chip);
    });

    const startBtn = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-play' }), 'Start');
    const stopBtn  = el('button', { class: 'ex-btn ex-btn-ghost', disabled: true }, el('i', { class: 'fas fa-stop' }), 'Stop');
    const streamToggle = el('input', { type: 'checkbox', checked: true });

    const progress = buildProgress();
    const logPanel = buildLogPanel();
    const resultPanel = buildResultPanel();

    let currentES = null;

    async function runBlocking() {
      startBtn.disabled = true; stopBtn.disabled = false;
      progress._reset(); progress._set(0, 'Running…');
      logPanel._clear();
      logPanel._append('[blocking] starting SQLi engine…', 'dim');
      try {
        const body = {
          target: target.value.trim(),
          method: method.value,
          max_params: parseInt(maxParams.value, 10) || 10,
          rate_limit: parseFloat(rate.value) || 20,
          timeout: parseFloat(timeout.value) || 8,
          techniques: Array.from(activeTech),
        };
        if (!body.target) { toast('Target required', 'warn'); return; }
        const res = await jpost(EP.sqli.scan, body);
        progress._set(100, 'Complete');
        logPanel._append(`[done] vulnerable=${res.vulnerable} findings=${(res.findings || []).length} elapsed=${res.elapsed}s`,
          res.vulnerable ? 'err' : 'ok');
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
        target: target.value.trim(),
        method: method.value,
        max_params: maxParams.value,
        rate_limit: rate.value,
        timeout: timeout.value,
        techniques: Array.from(activeTech).join(','),
      });
      const es = new EventSource(EP.sqli.stream + '?' + qs.toString());
      currentES = es;

      es.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data);
          if (data.type === 'progress') {
            progress._set(data.percent || 0, `${data.label || ''} (${data.done}/${data.total})`);
          } else if (data.type === 'result') {
            progress._set(100, 'Complete');
            logPanel._append(`[done] vulnerable=${data.data.vulnerable} findings=${(data.data.findings || []).length}`,
              data.data.vulnerable ? 'err' : 'ok');
            resultPanel._set(data.data);
            es.close(); currentES = null;
            startBtn.disabled = false; stopBtn.disabled = true;
          } else if (data.type === 'error') {
            logPanel._append('[error] ' + data.message, 'err');
            es.close(); currentES = null;
            startBtn.disabled = false; stopBtn.disabled = true;
          } else if (data.type === 'start') {
            logPanel._append('[start] ' + data.url, 'dim');
          }
        } catch (e) { logPanel._append('[parse] ' + e.message, 'warn'); }
      };
      es.onerror = () => {
        logPanel._append('[sse] connection error', 'warn');
        es.close(); currentES = null;
        startBtn.disabled = false; stopBtn.disabled = true;
      };
    }

    startBtn.addEventListener('click', () => {
      if (!target.value.trim()) { toast('Target required', 'warn'); return; }
      if (streamToggle.checked) runStreaming(); else runBlocking();
    });
    stopBtn.addEventListener('click', () => {
      if (currentES) { currentES.close(); currentES = null; logPanel._append('[stopped]', 'warn'); }
      startBtn.disabled = false; stopBtn.disabled = true;
    });

    return el('div', { class: 'ex-panel', id: 'ex-tab-sqli' },
      buildCard('SQL Injection Engine (sqli_engine)', 'fa-database',
        el('div', { class: 'ex-row' },
          buildField('Target URL', target),
          buildField('Method', method),
        ),
        el('div', { class: 'ex-row', style: 'margin-top:8px;' },
          buildField('Max params', maxParams),
          buildField('Rate limit', rate),
          buildField('Timeout (s)', timeout),
        ),
        el('div', { style: 'margin-top:10px;' },
          el('label', { style: 'font-size:.7rem;text-transform:uppercase;color:var(--text-muted);letter-spacing:.05em;' }, 'Techniques'),
          techniquesWrap,
        ),
        el('div', { class: 'ex-row tight', style: 'margin-top:12px; align-items:center;' },
          el('label', { style: 'display:flex;gap:6px;align-items:center;font-size:.78rem;' },
            streamToggle, 'Stream results (SSE)'),
          el('div', { style: 'flex:1 1 auto;' }),
          startBtn, stopBtn,
        ),
        progress,
        logPanel,
      ),
      buildCard('Result', 'fa-clipboard-check', resultPanel),
    );
  }

  /* ── 3. SQLMap ──────────────────────────────────────────────────── */
  function buildSqlmapTab() {
    const target = el('input', { type: 'text', placeholder: 'https://example.com/page?id=1', autocomplete: 'off' });
    const method = el('select', null,
      el('option', { value: 'GET' }, 'GET'),
      el('option', { value: 'POST' }, 'POST'),
    );
    const mode   = el('select', null,
      el('option', { value: 'basic' }, 'Basic'),
      el('option', { value: 'expert' }, 'Expert'),
    );
    const maxThreads = el('input', { type: 'number', value: '10' });
    const timeout = el('input', { type: 'number', value: '5', step: '0.5' });

    const runBtn = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-play' }), 'Run SQLMap');
    const resultPanel = buildResultPanel();
    const logPanel = buildLogPanel();

    runBtn.addEventListener('click', async () => {
      const t = target.value.trim();
      if (!t) { toast('Target required', 'warn'); return; }
      runBtn.disabled = true;
      logPanel._append('[run] sqlmap ' + mode.value + ' …', 'dim');
      try {
        const body = {
          target: t,
          mode: mode.value,
          method: method.value,
          max_threads: parseInt(maxThreads.value, 10) || 10,
          timeout: parseFloat(timeout.value) || 5,
        };
        const res = await jpost(EP.sqlmap.scan, body);
        logPanel._append('[done] scan_type=' + (res.data && res.data.scan_type || 'sqli'), 'ok');
        resultPanel._set(res);
      } catch (e) {
        logPanel._append('[error] ' + e.message, 'err');
        toast('SQLMap failed: ' + e.message, 'err');
      } finally {
        runBtn.disabled = false;
      }
    });

    return el('div', { class: 'ex-panel', id: 'ex-tab-sqlmap' },
      buildCard('SQLMap — Multi-Technique Scanner', 'fa-magnifying-glass-chart',
        el('div', { class: 'ex-row' },
          buildField('Target URL', target),
        ),
        el('div', { class: 'ex-row', style: 'margin-top:8px;' },
          buildField('Method', method),
          buildField('Mode', mode),
          buildField('Max threads', maxThreads),
          buildField('Timeout (s)', timeout),
        ),
        el('div', { class: 'ex-actions', style: 'margin-top:12px;' }, runBtn),
        logPanel,
      ),
      buildCard('Result', 'fa-clipboard-check', resultPanel),
    );
  }

  /* ── 4. SQL Injection (lightweight) ─────────────────────────────── */
  function buildSqlinjTab() {
    const target = el('input', { type: 'text', placeholder: 'https://example.com/search?q=1', autocomplete: 'off' });
    const method = el('select', null,
      el('option', { value: 'GET' }, 'GET'),
      el('option', { value: 'POST' }, 'POST'),
    );
    const runBtn = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-bolt' }), 'Run');
    const resultPanel = buildResultPanel();
    const logPanel = buildLogPanel();

    runBtn.addEventListener('click', async () => {
      const t = target.value.trim();
      if (!t) { toast('Target required', 'warn'); return; }
      runBtn.disabled = true;
      logPanel._append('[run] lightweight SQLi …', 'dim');
      try {
        const body = {
          target: t,
          method: method.value,
          params: parseQS(t),
        };
        const res = await jpost(EP.sqlinj.scan, body);
        logPanel._append(`[done] vulnerable=${res.vulnerable} findings=${(res.findings||[]).length}`,
          res.vulnerable ? 'err' : 'ok');
        resultPanel._set(res);
      } catch (e) {
        logPanel._append('[error] ' + e.message, 'err');
        toast('SQLi scan failed: ' + e.message, 'err');
      } finally {
        runBtn.disabled = false;
      }
    });

    return el('div', { class: 'ex-panel', id: 'ex-tab-sqlinj' },
      buildCard('Lightweight SQL Injection Test', 'fa-bolt',
        el('div', { class: 'ex-row' },
          buildField('Target URL', target),
          buildField('Method', method),
        ),
        el('div', { class: 'ex-actions', style: 'margin-top:12px;' }, runBtn),
        logPanel,
      ),
      buildCard('Result', 'fa-clipboard-check', resultPanel),
    );
  }

  /* ── 5. XSS Exploiter ───────────────────────────────────────────── */
  function buildXssTab() {
    const target = el('input', { type: 'text', placeholder: 'https://example.com/search?q=test', autocomplete: 'off' });
    const method = el('select', null,
      el('option', { value: 'GET' }, 'GET'),
      el('option', { value: 'POST' }, 'POST'),
    );
    const maxPayloads = el('input', { type: 'number', value: '30' });
    const maxParams = el('input', { type: 'number', value: '10' });
    const conc = el('input', { type: 'number', value: '8' });
    const rate = el('input', { type: 'number', value: '20', step: '0.5' });
    const wafBypass = el('input', { type: 'checkbox' });
    const streamToggle = el('input', { type: 'checkbox', checked: true });

    const startBtn = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-play' }), 'Start');
    const stopBtn  = el('button', { class: 'ex-btn ex-btn-ghost', disabled: true }, el('i', { class: 'fas fa-stop' }), 'Stop');

    const progress = buildProgress();
    const logPanel = buildLogPanel();
    const findingsBox = el('div', { class: 'ex-findings' });

    let currentES = null;

    function renderXssFindings(findings) {
      findingsBox.innerHTML = '';
      if (!findings || !findings.length) {
        findingsBox.appendChild(el('div', { class: 'ex-empty' }, 'No XSS vectors found'));
        return;
      }
      findings.forEach(f => {
        findingsBox.appendChild(el('div', { class: 'ex-finding ' + (f.severity || 'medium') },
          el('div', { class: 'label' }, `parameter · ${f.parameter} (${f.context || 'unknown'})`),
          el('div', { class: 'value' }, f.payload || ''),
          el('div', { class: 'meta' },
            el('span', null, 'Status: ', String(f.status_code || '—')),
            el('span', null, 'Confidence: ', String(f.confidence || '—')),
            el('span', null, 'Severity: ', severityBadge(f.severity)),
          ),
          f.evidence ? el('div', { class: 'value', style: 'margin-top:6px;color:#9ca3af;font-size:.72rem;' }, f.evidence.slice(0, 200)) : null,
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
          target: target.value.trim(),
          method: method.value,
          max_payloads: parseInt(maxPayloads.value, 10) || 30,
          max_params: parseInt(maxParams.value, 10) || 10,
          concurrency: parseInt(conc.value, 10) || 8,
          rate_limit: parseFloat(rate.value) || 20,
          waf_bypass: !!wafBypass.checked,
        };
        if (!body.target) { toast('Target required', 'warn'); return; }
        const res = await jpost(EP.xss.scan, body);
        progress._set(100, 'Complete');
        logPanel._append(`[done] vulnerable=${res.vulnerable} findings=${(res.findings||[]).length}`,
          res.vulnerable ? 'err' : 'ok');
        renderXssFindings(res.findings || []);
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
        target: target.value.trim(),
        method: method.value,
        max_payloads: maxPayloads.value,
        max_params: maxParams.value,
        concurrency: conc.value,
        rate_limit: rate.value,
        waf_bypass: wafBypass.checked ? '1' : '0',
      });
      const es = new EventSource(EP.xss.stream + '?' + qs.toString());
      currentES = es;

      es.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data);
          if (data.type === 'progress') {
            progress._set(data.percent || 0, `${data.label || ''} (${data.done}/${data.total})`);
          } else if (data.type === 'result') {
            progress._set(100, 'Complete');
            logPanel._append(`[done] vulnerable=${data.data.vulnerable} findings=${(data.data.findings||[]).length}`,
              data.data.vulnerable ? 'err' : 'ok');
            renderXssFindings(data.data.findings || []);
            es.close(); currentES = null;
            startBtn.disabled = false; stopBtn.disabled = true;
          } else if (data.type === 'error') {
            logPanel._append('[error] ' + data.message, 'err');
            es.close(); currentES = null;
            startBtn.disabled = false; stopBtn.disabled = true;
          } else if (data.type === 'start') {
            logPanel._append('[start] ' + data.url, 'dim');
          }
        } catch (e) { logPanel._append('[parse] ' + e.message, 'warn'); }
      };
      es.onerror = () => {
        logPanel._append('[sse] connection error', 'warn');
        es.close(); currentES = null;
        startBtn.disabled = false; stopBtn.disabled = true;
      };
    }

    startBtn.addEventListener('click', () => {
      if (!target.value.trim()) { toast('Target required', 'warn'); return; }
      if (streamToggle.checked) startStreaming(); else startBlocking();
    });
    stopBtn.addEventListener('click', () => {
      if (currentES) { currentES.close(); currentES = null; logPanel._append('[stopped]', 'warn'); }
      startBtn.disabled = false; stopBtn.disabled = true;
    });

    return el('div', { class: 'ex-panel', id: 'ex-tab-xss' },
      buildCard('XSS Exploiter', 'fa-code',
        el('div', { class: 'ex-row' },
          buildField('Target URL', target),
          buildField('Method', method),
        ),
        el('div', { class: 'ex-row', style: 'margin-top:8px;' },
          buildField('Max payloads', maxPayloads),
          buildField('Max params', maxParams),
          buildField('Concurrency', conc),
          buildField('Rate limit', rate),
        ),
        el('div', { class: 'ex-row tight', style: 'margin-top:12px; align-items:center;' },
          el('label', { style: 'display:flex;gap:6px;align-items:center;font-size:.78rem;' },
            wafBypass, 'WAF bypass'),
          el('label', { style: 'display:flex;gap:6px;align-items:center;font-size:.78rem;' },
            streamToggle, 'Stream (SSE)'),
          el('div', { style: 'flex:1 1 auto;' }),
          startBtn, stopBtn,
        ),
        progress,
        logPanel,
      ),
      buildCard('Findings', 'fa-list-check', findingsBox),
    );
  }

  /* ── 6. XSS Simple ──────────────────────────────────────────────── */
  function buildXssSimpleTab() {
    const target = el('input', { type: 'text', placeholder: 'https://example.com/?q=test', autocomplete: 'off' });
    const mode = el('select', null,
      el('option', { value: 'basic' }, 'Basic'),
      el('option', { value: 'expert' }, 'Expert'),
    );
    const runBtn = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-wand-magic' }), 'Run');
    const resultPanel = buildResultPanel();

    runBtn.addEventListener('click', async () => {
      const t = target.value.trim();
      if (!t) { toast('Target required', 'warn'); return; }
      runBtn.disabled = true;
      try {
        const body = { target: t, mode: mode.value };
        const res = await jpost(EP.xssSimple.scan, body);
        resultPanel._set(res);
      } catch (e) {
        toast('XSS scan failed: ' + e.message, 'err');
      } finally {
        runBtn.disabled = false;
      }
    });

    return el('div', { class: 'ex-panel', id: 'ex-tab-xssSimple' },
      buildCard('Reflected XSS (Simple)', 'fa-wand-magic',
        el('div', { class: 'ex-row' },
          buildField('Target URL', target),
          buildField('Mode', mode),
        ),
        el('div', { class: 'ex-actions', style: 'margin-top:12px;' }, runBtn),
      ),
      buildCard('Result', 'fa-clipboard-check', resultPanel),
    );
  }

  /* ── 7. Sniper ──────────────────────────────────────────────────── */
  function buildSniperTab() {
    const target = el('input', { type: 'text', placeholder: 'https://example.com', autocomplete: 'off' });
    const moduleTimeout = el('input', { type: 'number', value: '90' });
    const globalBudget = el('input', { type: 'number', value: '150' });
    const dirfuzzMax = el('input', { type: 'number', value: '80' });
    const xssMax = el('input', { type: 'number', value: '20' });
    const takeoverMax = el('input', { type: 'number', value: '120' });
    const streamToggle = el('input', { type: 'checkbox', checked: true });

    const startBtn = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-crosshairs' }), 'Run Sniper');
    const stopBtn  = el('button', { class: 'ex-btn ex-btn-ghost', disabled: true }, el('i', { class: 'fas fa-stop' }), 'Stop');

    const progress = buildProgress();
    const logPanel = buildLogPanel();
    const resultPanel = buildResultPanel();

    let currentES = null;

    async function runBlocking() {
      startBtn.disabled = true; stopBtn.disabled = false;
      progress._reset(); progress._set(0, 'Running…');
      logPanel._clear();
      try {
        const res = await jpost(EP.sniper.scan, {
          target: target.value.trim(),
          module_timeout: parseFloat(moduleTimeout.value) || 90,
          global_budget: parseFloat(globalBudget.value) || 150,
          dirfuzz_max_paths: parseInt(dirfuzzMax.value, 10) || 80,
          xss_max_payloads: parseInt(xssMax.value, 10) || 20,
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
        target: target.value.trim(),
        module_timeout: moduleTimeout.value,
        global_budget: globalBudget.value,
        dirfuzz_max_paths: dirfuzzMax.value,
        xss_max_payloads: xssMax.value,
        takeover_max_hosts: takeoverMax.value,
      });
      const es = new EventSource(EP.sniper.stream + '?' + qs.toString());
      currentES = es;

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
            logPanel._append(`[◀] ${data.module} — ${data.findings} finding(s) in ${data.elapsed}s`,
              data.ok ? 'ok' : 'warn');
          } else if (data.type === 'heartbeat') {
            logPanel._append(`[heartbeat] elapsed=${data.elapsed}s done=${data.modules_done}/${data.modules_total}`, 'dim');
          } else if (data.type === 'complete') {
            progress._set(100, 'Complete');
            logPanel._append(`[done] risk=${data.report.risk_score}/100 (${data.report.risk_level})`, 'ok');
            resultPanel._set(data.report);
            es.close(); currentES = null;
            startBtn.disabled = false; stopBtn.disabled = true;
          } else if (data.type === 'error') {
            logPanel._append('[error] ' + data.message, 'err');
          }
        } catch (e) { logPanel._append('[parse] ' + e.message, 'warn'); }
      };
      es.onerror = () => {
        logPanel._append('[sse] connection error', 'warn');
        es.close(); currentES = null;
        startBtn.disabled = false; stopBtn.disabled = true;
      };
    }

    startBtn.addEventListener('click', () => {
      if (!target.value.trim()) { toast('Target required', 'warn'); return; }
      if (streamToggle.checked) runStreaming(); else runBlocking();
    });
    stopBtn.addEventListener('click', () => {
      if (currentES) { currentES.close(); currentES = null; logPanel._append('[stopped]', 'warn'); }
      startBtn.disabled = false; stopBtn.disabled = true;
    });

    return el('div', { class: 'ex-panel', id: 'ex-tab-sniper' },
      buildCard('Sniper — Auto-Exploiter', 'fa-crosshairs',
        el('div', { class: 'ex-row' },
          buildField('Target', target),
        ),
        el('div', { class: 'ex-row', style: 'margin-top:8px;' },
          buildField('Module timeout (s)', moduleTimeout),
          buildField('Global budget (s)', globalBudget),
          buildField('Dirfuzz max paths', dirfuzzMax),
          buildField('XSS max payloads', xssMax),
          buildField('Takeover max hosts', takeoverMax),
        ),
        el('div', { class: 'ex-row tight', style: 'margin-top:12px; align-items:center;' },
          el('label', { style: 'display:flex;gap:6px;align-items:center;font-size:.78rem;' },
            streamToggle, 'Stream (SSE)'),
          el('div', { style: 'flex:1 1 auto;' }),
          startBtn, stopBtn,
        ),
        progress,
        logPanel,
      ),
      buildCard('Full Report', 'fa-clipboard-check', resultPanel),
    );
  }

  /* ── 8. HTTP Logger ────────────────────────────────────────────── */
  function buildLoggerTab() {
    const statsGrid = el('div', { class: 'ex-kpis' });
    const filters = el('div', { class: 'ex-row', style: 'margin-bottom:10px;' });
    const searchIn = el('input', { type: 'text', placeholder: 'Search path/query/body…', autocomplete: 'off' });
    const methodSel = el('select', null,
      el('option', { value: '' }, 'Any method'),
      el('option', { value: 'GET' }, 'GET'),
      el('option', { value: 'POST' }, 'POST'),
      el('option', { value: 'PUT' }, 'PUT'),
      el('option', { value: 'DELETE' }, 'DELETE'),
    );
    const anomalySel = el('input', { type: 'text', placeholder: 'Anomaly category (sqli, xss, …)' });
    const refreshBtn = el('button', { class: 'ex-btn ex-btn-primary' }, el('i', { class: 'fas fa-rotate' }), 'Refresh');
    const clearBtn   = el('button', { class: 'ex-btn ex-btn-danger' }, el('i', { class: 'fas fa-broom' }), 'Clear Log');
    const exportHar  = el('button', { class: 'ex-btn ex-btn-ghost' }, el('i', { class: 'fas fa-file-export' }), 'Export HAR');
    const liveBtn    = el('button', { class: 'ex-btn ex-btn-ghost' }, el('i', { class: 'fas fa-satellite-dish' }), 'Live Stream');
    const livePill   = el('span', { class: 'ex-live-pill', style: 'display:none;' },
      el('span', { class: 'dot' }), 'Live');

    const tableBody = el('tbody');
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
        state.loggerStats = s;
        statsGrid.innerHTML = '';
        const entries = [
          { label: 'Total Seen',  val: s.total_seen },
          { label: 'Buffer Size', val: `${s.buffer_size}/${s.buffer_capacity}` },
          { label: 'Subscribers', val: s.subscribers },
          { label: 'Dropped',     val: s.total_dropped },
        ];
        entries.forEach(e => {
          statsGrid.appendChild(el('div', { class: 'ex-kpi' },
            el('div', { class: 'k-label' }, e.label),
            el('div', { class: 'k-val' }, String(e.val)),
          ));
        });
      } catch (_) {}
    }

    async function loadList() {
      tableBody.innerHTML = '';
      try {
        const qs = new URLSearchParams({ size: '100' });
        if (searchIn.value.trim()) qs.set('q', searchIn.value.trim());
        if (methodSel.value) qs.set('method', methodSel.value);
        if (anomalySel.value.trim()) qs.set('anomaly', anomalySel.value.trim());
        const data = await jget(EP.logger.list + '?' + qs.toString());
        if (!data.items || !data.items.length) {
          tableBody.appendChild(el('tr', null, el('td', { colspan: '6' }, el('div', { class: 'ex-empty' }, 'No requests captured')));
          return;
        }
        data.items.forEach(entry => {
          const tr = el('tr', { 'data-id': entry.id },
            el('td', null, el('code', null, entry.method || '—')),
            el('td', null, el('code', null, entry.path || '—')),
            el('td', null, String(entry.status || 0)),
            el('td', null, el('code', null, entry.ip || '—')),
            el('td', null, String(entry.elapsed_ms || 0) + 'ms'),
            el('td', null, (entry.anomalies || []).map(a => severityBadge(a.severity)).slice(0, 3)),
          );
          tr.addEventListener('click', () => showDetail(entry.id));
          tableBody.appendChild(tr);
        });
      } catch (e) {
        tableBody.appendChild(el('tr', null, el('td', { colspan: '6' }, el('div', { class: 'ex-empty' }, 'Error: ' + e.message)));
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

    let loggerES = null;
    liveBtn.addEventListener('click', () => {
      if (loggerES) {
        loggerES.close();
        loggerES = null;
        livePill.style.display = 'none';
        liveBtn.innerHTML = '<i class="fas fa-satellite-dish"></i> Live Stream';
        return;
      }
      livePill.style.display = '';
      liveBtn.innerHTML = '<i class="fas fa-stop"></i> Stop Stream';
      loggerES = new EventSource(EP.logger.stream);
      loggerES.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data);
          if (data.type === 'request') {
            const tr = el('tr',
              el('td', null, el('code', null, data.method || '—')),
              el('td', null, el('code', null, data.path || '—')),
              el('td', null, String(data.status || 0)),
              el('td', null, el('code', null, data.ip || '—')),
              el('td', null, String(data.elapsed_ms || 0) + 'ms'),
              el('td', null, (data.anomalies || []).map(a => severityBadge(a.severity)).slice(0, 3)),
            );
            tableBody.insertBefore(tr, tableBody.firstChild);
            if (tableBody.childNodes.length > 200) tableBody.removeChild(tableBody.lastChild);
          }
        } catch (_) {}
      };
      loggerES.onerror = () => {
        livePill.style.display = 'none';
        liveBtn.innerHTML = '<i class="fas fa-satellite-dish"></i> Live Stream';
        if (loggerES) { loggerES.close(); loggerES = null; }
      };
    });

    // Initial load
    setTimeout(() => { loadStats(); loadList(); }, 100);

    return el('div', { class: 'ex-panel', id: 'ex-tab-logger' },
      buildCard('HTTP Logger — Live Request Capture', 'fa-wave-square',
        statsGrid,
        el('div', { style: 'margin: 12px 0 6px;' }, filters),
        el('div', { class: 'ex-row tight', style: 'align-items:center;gap:8px;' },
          refreshBtn, clearBtn, exportHar, liveBtn, livePill,
        ),
        el('div', { style: 'overflow:auto; max-height:400px; margin-top:12px;' },
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
      buildCard('Entry Detail', 'fa-magnifying-glass', detailPanel),
    );
  }

  /* ==================================================================
   *  TAB REGISTRY + MOUNT
   * ================================================================== */
  const TAB_BUILDERS = {
    dirfuzz:   buildDirfuzzTab,
    sqli:      buildSqliTab,
    sqlmap:    buildSqlmapTab,
    sqlinj:    buildSqlinjTab,
    xss:       buildXssTab,
    xssSimple: buildXssSimpleTab,
    sniper:    buildSniperTab,
    logger:    buildLoggerTab,
  };

  function buildUI(defaultTab) {
    const tabsRow = el('div', { class: 'ex-tabs' });
    const panels = {};

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
      if (t.id !== defaultTab) panel.classList.remove('active');
      panels[t.id] = panel;
      body.appendChild(panel);
    });

    function switchTab(id) {
      state.activeTab = id;
      $$('.ex-tab', tabsRow).forEach(b => b.classList.toggle('active', b.dataset.tab === id));
      Object.entries(panels).forEach(([k, p]) => p.classList.toggle('active', k === id));
    }

    const root = el('div', { class: 'ex-root' }, tabsRow, body);
    root._switchTab = switchTab;
    return root;
  }

  /* ==================================================================
   *  PUBLIC API
   * ================================================================== */
  function mount(target, opts) {
    if (state.mounted) unmount();
    injectCSS();
    opts = opts || {};
    const defaultTab = opts.defaultTab || 'dirfuzz';

    let elMount = null;
    if (typeof target === 'string') elMount = document.querySelector(target);
    else if (target instanceof Element) elMount = target;
    else elMount = document.querySelector('[data-emergens-panel="exploit"]');

    if (!elMount) { console.warn('[ExploitSuite] no mount point found'); return false; }

    state.mountEl = elMount;
    elMount.innerHTML = '';
    elMount.appendChild(buildUI(defaultTab));
    state.mounted = true;
    state.activeTab = defaultTab;
    return true;
  }

  function unmount() {
    // Close any open streams
    for (const es of Object.values(state.streams)) {
      try { es.close(); } catch (_) {}
    }
    state.streams = {};
    if (state.loggerES) { try { state.loggerES.close(); } catch (_) {} state.loggerES = null; }
    state.mounted = false;
    state.mountEl = null;
  }

  function open(tabName) {
    if (!state.mounted) return false;
    const root = state.mountEl.querySelector('.ex-root');
    if (root && root._switchTab) { root._switchTab(tabName); return true; }
    return false;
  }

  function autoMount() {
    const placeholder = document.querySelector('[data-emergens-panel="exploit"]');
    if (placeholder) mount(placeholder);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoMount);
  } else {
    autoMount();
  }

  window.ExploitSuite = {
    mount,
    unmount,
    open,
    get state() { return { ...state }; },
  };
})();
