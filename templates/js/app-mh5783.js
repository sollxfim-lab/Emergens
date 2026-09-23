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
    mounted: false,
    mountEl: null,
    methods: [],
    layer7: [],
    layer4: [],
    running: [],
    history: [],
    pollTimer: null,
    busy: false,
  };

  /* ── helpers ─────────────────────────────────────────────────────── */
  const $ = (sel, root) => (root || document).querySelector(sel);

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k === 'class') node.className = v;
        else if (k === 'html') node.innerHTML = v;
        else if (k.startsWith('on') && typeof v === 'function') {
          node.addEventListener(k.slice(2).toLowerCase(), v);
        } else node.setAttribute(k, v);
      }
    }
    for (const c of children) {
      if (c == null || c === false) continue;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
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

  /* ── CSS ─────────────────────────────────────────────────────────── */
  const CSS = `
  .mhd-root { display:flex; flex-direction:column; gap:14px; }
  .mhd-grid { display:grid; grid-template-columns: 1fr 1fr; gap:12px; }
  @media (max-width: 780px) { .mhd-grid { grid-template-columns: 1fr; } }

  .mhd-card {
    background: var(--bg-tertiary, #14171b);
    border: 1px solid var(--border-color, #2a2f36);
    border-radius: 10px;
    padding: 14px;
  }
  .mhd-card h4 {
    margin: 0 0 10px;
    font-size: .82rem;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--text-secondary, #98a1ab);
    display: flex; align-items: center; gap: 8px;
  }
  .mhd-card h4 i { color: var(--accent, #60a5fa); }

  .mhd-row { display:flex; gap:8px; flex-wrap:wrap; }
  .mhd-row > * { flex:1 1 160px; min-width: 0; }

  .mhd-field { display:flex; flex-direction:column; gap:5px; }
  .mhd-field > label {
    font-size:.7rem; letter-spacing:.05em;
    color: var(--text-muted, #6b7280); text-transform: uppercase;
  }
  .mhd-field > input,
  .mhd-field > select {
    background: var(--bg-secondary, #0d1013);
    border:1px solid var(--border-color,#2a2f36);
    border-radius:7px;
    padding:9px 11px;
    color: var(--text-primary, #e5e7eb);
    font-size:.85rem;
    font-family: var(--font-mono, ui-monospace, SFMono-Regular, monospace);
    outline:none;
    transition: border-color .15s ease;
  }
  .mhd-field > input:focus,
  .mhd-field > select:focus { border-color: var(--accent, #60a5fa); }

  .mhd-method-groups { display:flex; gap:10px; }
  .mhd-method-groups > div { flex:1 1 0; min-width:0; }
  .mhd-method-groups h5 {
    margin: 0 0 6px; font-size:.68rem; letter-spacing:.09em;
    text-transform: uppercase; color: var(--text-muted,#6b7280);
  }
  .mhd-chips { display:flex; flex-wrap:wrap; gap:5px; max-height: 180px; overflow:auto; }
  .mhd-chip {
    padding: 5px 9px;
    border-radius: 6px;
    border: 1px solid var(--border-color, #2a2f36);
    background: var(--bg-secondary, #0d1013);
    color: var(--text-secondary, #98a1ab);
    font-family: var(--font-mono, monospace);
    font-size:.72rem;
    cursor: pointer;
    transition: all .12s ease;
  }
  .mhd-chip:hover { border-color: var(--accent, #60a5fa); color: var(--text-primary,#e5e7eb); }
  .mhd-chip.active {
    background: var(--accent, #60a5fa);
    border-color: var(--accent, #60a5fa);
    color: #0b0d10;
    font-weight: 700;
  }

  .mhd-actions { display:flex; gap:8px; margin-top:4px; }
  .mhd-btn {
    flex:1; padding:10px 14px; border-radius:8px; border:1px solid transparent;
    font-weight:700; font-size:.82rem; letter-spacing:.03em; cursor:pointer;
    display:flex; align-items:center; justify-content:center; gap:7px;
    transition: transform .1s ease, opacity .15s ease;
  }
  .mhd-btn:active { transform: scale(.98); }
  .mhd-btn[disabled] { opacity:.5; cursor:not-allowed; }
  .mhd-btn-primary { background: linear-gradient(135deg,#ef4444,#dc2626); color:#fff; }
  .mhd-btn-danger  { background: linear-gradient(135deg,#7f1d1d,#450a0a); color:#fff; }
  .mhd-btn-ghost   { background: var(--bg-secondary,#0d1013); border-color: var(--border-color,#2a2f36); color: var(--text-secondary,#98a1ab); }

  .mhd-table { width:100%; border-collapse: collapse; font-size:.78rem; }
  .mhd-table th, .mhd-table td {
    text-align:left; padding:8px 10px;
    border-bottom: 1px solid var(--border-color,#2a2f36);
  }
  .mhd-table th {
    font-size:.68rem; letter-spacing:.06em; text-transform: uppercase;
    color: var(--text-muted,#6b7280); font-weight: 600;
  }
  .mhd-table code { font-family: var(--font-mono, monospace); font-size:.72rem; color: var(--text-secondary,#98a1ab); }

  .mhd-badge { display:inline-block; padding:3px 8px; border-radius:99px; font-size:.66rem; font-weight:700; letter-spacing:.05em; text-transform: uppercase; }
  .mhd-badge-running { background: rgba(34,197,94,.15); color:#22c55e; }
  .mhd-badge-stopped { background: rgba(156,163,175,.15); color:#9ca3af; }
  .mhd-badge-failed  { background: rgba(239,68,68,.15); color:#ef4444; }
  .mhd-badge-done    { background: rgba(59,130,246,.15); color:#3b82f6; }
  .mhd-badge-timeout { background: rgba(245,158,11,.15); color:#f59e0b; }

  .mhd-empty { padding: 22px; text-align:center; color: var(--text-muted,#6b7280); font-size:.82rem; }
  `;

  function injectCSS() {
    if (document.getElementById('mhd-css')) return;
    const style = document.createElement('style');
    style.id = 'mhd-css';
    style.textContent = CSS;
    document.head.appendChild(style);
  }

  /* ── DOM builder ─────────────────────────────────────────────────── */
  function buildUI() {
    const selectedMethod = { value: '' };

    const methodSelect = el('select', { id: 'mhdMethodSelect' },
      el('option', { value: '' }, 'Select a method…')
    );

    const chipGroups = el('div', { class: 'mhd-method-groups' });
    const l7chips = el('div', { class: 'mhd-chips', id: 'mhdL7Chips' });
    const l4chips = el('div', { class: 'mhd-chips', id: 'mhdL4Chips' });
    chipGroups.append(
      el('div', null, el('h5', null, 'Layer 7'), l7chips),
      el('div', null, el('h5', null, 'Layer 4'), l4chips),
    );

    const targetInput = el('input', { type: 'text', id: 'mhdTarget', placeholder: 'https://example.com or 1.2.3.4:80', autocomplete: 'off' });
    const threadsInput = el('input', { type: 'number', id: 'mhdThreads', value: '10', min: '1', max: '1000' });
    const durationInput = el('input', { type: 'number', id: 'mhdDuration', value: '60', min: '1', max: '3600' });
    const proxyTypeInput = el('input', { type: 'number', id: 'mhdProxyType', value: '0', min: '0', max: '5' });
    const proxyFileInput = el('input', { type: 'text', id: 'mhdProxyFile', value: 'proxies.txt' });
    const rpcInput = el('input', { type: 'number', id: 'mhdRpc', value: '1', min: '1', max: '5' });
    const reflectorInput = el('input', { type: 'text', id: 'mhdReflector', placeholder: 'reflectors.txt (AMP only)' });

    const startBtn = el('button', { class: 'mhd-btn mhd-btn-primary', id: 'mhdStartBtn' },
      el('i', { class: 'fas fa-rocket' }), 'Launch Attack');
    const stopAllBtn = el('button', { class: 'mhd-btn mhd-btn-danger', id: 'mhdStopAllBtn' },
      el('i', { class: 'fas fa-hand' }), 'Stop All');

    const runningTableBody = el('tbody', { id: 'mhdRunningBody' });
    const historyTableBody = el('tbody', { id: 'mhdHistoryBody' });

    const root = el('div', { class: 'mhd-root' },

      el('div', { class: 'mhd-card' },
        el('h4', null, el('i', { class: 'fas fa-bullseye' }), 'Attack Configuration'),
        el('div', { class: 'mhd-field', style: 'margin-bottom:12px;' },
          el('label', null, 'Target'),
          targetInput,
        ),
        el('div', { class: 'mhd-row', style: 'margin-bottom:12px;' },
          el('div', { class: 'mhd-field' }, el('label', null, 'Method'), methodSelect),
        ),
        chipGroups,
        el('div', { class: 'mhd-row', style: 'margin-top:12px;' },
          el('div', { class: 'mhd-field' }, el('label', null, 'Threads'), threadsInput),
          el('div', { class: 'mhd-field' }, el('label', null, 'Duration (s)'), durationInput),
          el('div', { class: 'mhd-field' }, el('label', null, 'Proxy type'), proxyTypeInput),
          el('div', { class: 'mhd-field' }, el('label', null, 'RPC'), rpcInput),
        ),
        el('div', { class: 'mhd-row', style: 'margin-top:12px;' },
          el('div', { class: 'mhd-field' }, el('label', null, 'Proxy file'), proxyFileInput),
          el('div', { class: 'mhd-field' }, el('label', null, 'Reflector file'), reflectorInput),
        ),
        el('div', { class: 'mhd-actions', style: 'margin-top:14px;' },
          startBtn, stopAllBtn,
        ),
      ),

      el('div', { class: 'mhd-card' },
        el('h4', null, el('i', { class: 'fas fa-tower-broadcast' }), 'Running Attacks'),
        el('table', { class: 'mhd-table' },
          el('thead', null,
            el('tr', null,
              el('th', null, 'ID'),
              el('th', null, 'Method'),
              el('th', null, 'Target'),
              el('th', null, 'Threads'),
              el('th', null, 'Duration'),
              el('th', null, 'Started'),
              el('th', null, 'Status'),
              el('th', null, ''),
            ),
          ),
          runningTableBody,
        ),
      ),

      el('div', { class: 'mhd-card' },
        el('h4', null, el('i', { class: 'fas fa-clock-rotate-left' }), 'Recent History'),
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
    );

    // ── event wiring ────────────────────────────────────────────────
    function pickMethod(name) {
      selectedMethod.value = name;
      methodSelect.value = name;
      root.querySelectorAll('.mhd-chip').forEach(c => {
        c.classList.toggle('active', c.dataset.method === name);
      });
    }

    methodSelect.addEventListener('change', () => pickMethod(methodSelect.value));

    const renderChips = () => {
      l7chips.innerHTML = '';
      l4chips.innerHTML = '';
      state.layer7.forEach(name => {
        const chip = el('button', { class: 'mhd-chip', type: 'button', 'data-method': name }, name);
        chip.addEventListener('click', () => pickMethod(name));
        l7chips.appendChild(chip);
      });
      state.layer4.forEach(name => {
        const chip = el('button', { class: 'mhd-chip', type: 'button', 'data-method': name }, name);
        chip.addEventListener('click', () => pickMethod(name));
        l4chips.appendChild(chip);
      });
    };

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
          threads:  parseInt(threadsInput.value,  10) || 10,
          duration: parseInt(durationInput.value, 10) || 60,
          proxy_type: parseInt(proxyTypeInput.value, 10) || 0,
          proxy_file: proxyFileInput.value.trim() || 'proxies.txt',
          rpc:      parseInt(rpcInput.value, 10) || 1,
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

    // Store references for updates
    root._refs = { runningTableBody, historyTableBody, renderChips, methodSelect, pickMethod };
    return root;
  }

  /* ── rendering ───────────────────────────────────────────────────── */
  function statusBadge(status) {
    const cls = {
      running:  'mhd-badge-running',
      stopped:  'mhd-badge-stopped',
      failed:   'mhd-badge-failed',
      completed:'mhd-badge-done',
      timeout:  'mhd-badge-timeout',
    }[status] || 'mhd-badge-stopped';
    return el('span', { class: 'mhd-badge ' + cls }, status || 'unknown');
  }

  function renderRunning(root) {
    const tbody = root._refs.runningTableBody;
    tbody.innerHTML = '';
    if (!state.running.length) {
      tbody.appendChild(el('tr', null,
        el('td', { colspan: '8' }, el('div', { class: 'mhd-empty' }, 'No attacks running'))
      ));
      return;
    }
    for (const atk of state.running) {
      const stopBtn = el('button', { class: 'mhd-btn mhd-btn-ghost', style: 'padding:5px 10px;font-size:.7rem;flex:0 0 auto;' },
        el('i', { class: 'fas fa-stop' }), 'Stop');
      stopBtn.addEventListener('click', async () => {
        stopBtn.disabled = true;
        try {
          await jpost(API.stop, { attack_id: atk.attack_id });
          toast(`Stopped ${shortId(atk.attack_id)}`, 'ok');
          await refresh();
        } catch (e) {
          toast('Stop failed: ' + e.message, 'err');
          stopBtn.disabled = false;
        }
      });

      tbody.appendChild(el('tr', null,
        el('td', null, el('code', null, shortId(atk.attack_id))),
        el('td', null, atk.method),
        el('td', null, el('code', null, atk.target)),
        el('td', null, String(atk.threads)),
        el('td', null, atk.duration + 's'),
        el('td', null, fmtTime(atk.started_at)),
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
        el('td', { colspan: '5' }, el('div', { class: 'mhd-empty' }, 'No history yet'))
      ));
      return;
    }
    for (const entry of state.history.slice(-25).reverse()) {
      tbody.appendChild(el('tr', null,
        el('td', null, el('code', null, shortId(entry.attack_id))),
        el('td', null, entry.method),
        el('td', null, el('code', null, entry.target)),
        el('td', null, fmtTime(entry.started_at)),
        el('td', null, statusBadge(entry.status)),
      ));
    }
  }

  /* ── polling ─────────────────────────────────────────────────────── */
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
            // Update the dropdown
            const sel = root._refs.methodSelect;
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
      }
    } catch (e) {
      // silent — poll runs often
    }
  }

  /* ── mount / unmount ─────────────────────────────────────────────── */
  function mount(target) {
    if (state.mounted) unmount();
    injectCSS();

    let elMount = null;
    if (typeof target === 'string') elMount = document.querySelector(target);
    else if (target instanceof Element) elMount = target;
    else {
      elMount = document.querySelector('[data-emergens-panel="mhddos"]');
    }
    if (!elMount) {
      console.warn('[MHDDoSControl] no mount point found');
      return false;
    }
    state.mountEl = elMount;
    elMount.innerHTML = '';
    elMount.appendChild(buildUI());
    state.mounted = true;

    // Prime methods first, then start polling
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

  /* ── auto-mount on DOMContentLoaded if placeholder present ───────── */
  function autoMount() {
    const placeholder = document.querySelector('[data-emergens-panel="mhddos"]');
    if (placeholder) mount(placeholder);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoMount);
  } else {
    autoMount();
  }

  window.MHDDoSControl = {
    mount,
    unmount,
    refresh,
    get state() { return { ...state }; },
  };
})();
