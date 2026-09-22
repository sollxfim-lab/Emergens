/**
 * @file templates/js/osint.js
 * @description Professional OSINT client for Emergens Console.
 *              Multi-source lookup: Username / Email / Phone Number.
 *
 *              Integrates with THREE UIs:
 *                1. School Section (premium panel)  — #schoolOsint*
 *                2. Tools Hub    (compact panel)    — #osint*
 *                3. Security Testing (auto-injected below #scanBtn)
 *
 *              The Security Testing launcher + panel are injected at runtime
 *              via bindSecurityPanel() — no HTML edits required.
 *
 * @version 2.3.0
 * @author  Yanxzyx
 * @license MIT
 */
(function (global) {
  'use strict';

  /* ==================================================================
   * META + CONFIG
   * ================================================================== */

  const TOOL_INFO = Object.freeze({
    name: 'Osint',
    description: 'Multi-source OSINT lookup: username, email, phone number.',
    version: '2.3.0',
    category: 'Recon',
    author: 'Yanxzyx',
    capabilities: ['username', 'email', 'number', 'cache', 'export', 'ripple-ui',
                    'security-testing-inline'],
  });

  const CONFIG = Object.freeze({
    apiEndpoint: '/api/scan/osint',
    fallbackEndpoints: ['/api/osint', '/api/leakdata/search'],
    minQueryLen: 3,
    maxQueryLen: 120,
    requestTimeoutMs: 15000,
    cacheTtlMs: 60_000,
    rateLimitMs: 1_200,
    maxResults: 200,
    retryCount: 2,
    retryBaseMs: 600,
    rippleDurationMs: 600,
    shakeDurationMs: 500,
    /** Inject the OSINT launcher inside the Security Testing section. */
    injectInSecurityTesting: true,
  });

  const METHOD_PLACEHOLDER = Object.freeze({
    username: 'Enter a username (e.g. johndoe)',
    email: 'Enter an email (e.g. user@example.com)',
    number: 'Enter a phone number (e.g. 08123456789)',
  });

  const METHOD_ICON = Object.freeze({
    username: 'fa-at',
    email: 'fa-envelope',
    number: 'fa-phone',
  });

  const METHOD_LABEL = Object.freeze({
    username: 'Username',
    email: 'Email',
    number: 'Number',
  });

  const METHOD_ORDER = Object.freeze(['username', 'email', 'number']);

  /* ==================================================================
   * LOGGER
   * ================================================================== */

  const Logger = (() => {
    let enabled = false;
    try { enabled = localStorage.getItem('OSINT_DEBUG') === '1'; } catch {}
    const tag = '[OSINT]';
    return {
      on:    () => (enabled = true),
      off:   () => (enabled = false),
      debug: (...a) => enabled && console.debug(tag, ...a),
      info:  (...a) => enabled && console.info(tag, ...a),
      warn:  (...a) => enabled && console.warn(tag, ...a),
      error: (...a) => console.error(tag, ...a),
    };
  })();

  /* ==================================================================
   * UTILITIES
   * ================================================================== */

  const Util = {
    esc(s) {
      return String(s ?? '').replace(/[&<>"'`=/]/g, (c) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
        '`': '&#96;',
        '=': '&#61;',
        '/': '&#47;',
      }[c]));
    },

    isEmail(s) {
      return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(s).trim());
    },

    isPhone(s) {
      return /^\+?[\d\s\-().]{6,20}$/.test(String(s).trim());
    },

    normPhone(s) {
      return String(s || '').replace(/\D/g, '');
    },

    normalizeId(s) {
      return String(s || '').replace(/\D/g, '');
    },

    debounce(fn, ms = 300) {
      let t;
      return function (...a) {
        clearTimeout(t);
        t = setTimeout(() => fn.apply(this, a), ms);
      };
    },

    truncate(s, n = 80) {
      s = String(s ?? '');
      return s.length > n ? s.slice(0, n - 1) + '…' : s;
    },

    async fetchWithTimeout(url, opts = {}, timeoutMs = 15000) {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        return await fetch(url, { ...opts, signal: ctrl.signal });
      } finally {
        clearTimeout(t);
      }
    },

    ripple(button, event) {
      if (!button) return;
      const ripple = button.querySelector('.osint-input-premium__ripple');
      if (!ripple) return;

      const rect = button.getBoundingClientRect();
      const size = Math.max(rect.width, rect.height);

      const clientX = event?.clientX ?? rect.left + rect.width / 2;
      const clientY = event?.clientY ?? rect.top + rect.height / 2;

      ripple.style.width  = `${size}px`;
      ripple.style.height = `${size}px`;
      ripple.style.left   = `${clientX - rect.left - size / 2}px`;
      ripple.style.top    = `${clientY - rect.top  - size / 2}px`;

      button.classList.remove('is-rippling');
      void button.offsetWidth;
      button.classList.add('is-rippling');
      setTimeout(() => button.classList.remove('is-rippling'), CONFIG.rippleDurationMs);
    },

    shake(wrapper) {
      if (!wrapper) return;
      wrapper.classList.remove('is-invalid');
      void wrapper.offsetWidth;
      wrapper.classList.add('is-invalid');
      setTimeout(
        () => wrapper.classList.remove('is-invalid'),
        CONFIG.shakeDurationMs
      );
    },
  };

  /* ==================================================================
   * CACHE (TTL)
   * ================================================================== */

  class Cache {
    constructor(ttlMs) {
      this.ttlMs = ttlMs;
      this.map = new Map();
      this.stats = { hits: 0, misses: 0 };
    }

    key(method, query) {
      return `${method}:${String(query).trim().toLowerCase()}`;
    }

    get(method, query) {
      const k = this.key(method, query);
      const e = this.map.get(k);
      if (!e) { this.stats.misses++; return null; }
      if (Date.now() - e.at > this.ttlMs) {
        this.map.delete(k);
        this.stats.misses++;
        return null;
      }
      this.stats.hits++;
      return e.value;
    }

    set(method, query, value) {
      this.map.set(this.key(method, query), { value, at: Date.now() });
    }

    clear() {
      this.map.clear();
      this.stats = { hits: 0, misses: 0 };
    }
  }

  /* ==================================================================
   * RATE LIMITER
   * ================================================================== */

  class RateLimiter {
    constructor(minMs) {
      this.minMs = minMs;
      this.last = 0;
    }
    check() {
      const now = Date.now();
      const delta = now - this.last;
      if (delta >= this.minMs) {
        this.last = now;
        return 0;
      }
      return this.minMs - delta;
    }
  }

  /* ==================================================================
   * STATE
   * ================================================================== */

  const _cache = new Cache(CONFIG.cacheTtlMs);
  const _limiter = new RateLimiter(CONFIG.rateLimitMs);

  const _state = {
    method: 'username',
    lastQuery: '',
    lastPayload: null,
    controller: null,
  };

  /* ==================================================================
   * RENDERER
   * ================================================================== */

  const Renderer = {
    loading(el, msg = 'Searching…') {
      if (!el) return;
      el.innerHTML = `
        <div class="osint-state osint-state--loading">
          <div class="osint-spinner" aria-hidden="true"></div>
          <span>${Util.esc(msg)}</span>
        </div>`;
    },

    empty(el, msg = 'No results found.') {
      if (!el) return;
      el.innerHTML = `
        <div class="osint-state osint-state--empty">
          <i class="fas fa-inbox" aria-hidden="true"></i>
          <strong>${Util.esc(msg)}</strong>
          <span class="hint">Try a different query or method.</span>
        </div>`;
    },

    error(el, msg = 'Request failed.') {
      if (!el) return;
      el.innerHTML = `
        <div class="osint-state osint-state--error">
          <i class="fas fa-triangle-exclamation" aria-hidden="true"></i>
          <strong>${Util.esc(msg)}</strong>
          <span class="hint">Check your connection or try again.</span>
        </div>`;
    },

    results(el, payload, method, query) {
      if (!el) return;
      const data = payload?.data || payload || {};
      const rows = Array.isArray(data.results) ? data.results
                 : Array.isArray(data.matches) ? data.matches
                 : [];
      if (!rows.length) return this.empty(el);

      const count = rows.length;
      const took = data.tookMs ?? '—';

      const header = `
        <div class="osint-result-head">
          <div class="osint-result-head__left">
            <span class="osint-pill">
              <i class="fas ${METHOD_ICON[method] || 'fa-search'}"></i>
              ${Util.esc(METHOD_LABEL[method] || method)}
            </span>
            <code class="osint-query">${Util.esc(Util.truncate(query, 40))}</code>
          </div>
          <div class="osint-result-head__right">
            <span class="osint-count">${count} result${count === 1 ? '' : 's'}</span>
            <span class="osint-took">${Util.esc(took)} ms</span>
            <button class="osint-iconbtn" data-osint-act="export" title="Export JSON" aria-label="Export">
              <i class="fas fa-download"></i>
            </button>
            <button class="osint-iconbtn" data-osint-act="clear" title="Clear" aria-label="Clear">
              <i class="fas fa-xmark"></i>
            </button>
          </div>
        </div>`;

      const cards = rows
        .slice(0, CONFIG.maxResults)
        .map((r, i) => this._card(r, i))
        .join('');

      el.innerHTML = `
        ${header}
        <div class="osint-results-grid">${cards}</div>
        ${rows.length > CONFIG.maxResults
          ? `<div class="osint-more">+${rows.length - CONFIG.maxResults} more (truncated)</div>`
          : ''}`;

      el.querySelector('[data-osint-act="export"]')?.addEventListener(
        'click',
        () => Osint._export(rows, method, query)
      );
      el.querySelector('[data-osint-act="clear"]')?.addEventListener(
        'click',
        () => { el.innerHTML = ''; }
      );

      el.querySelectorAll('[data-copy]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const text = btn.getAttribute('data-copy') || '';
          try {
            await navigator.clipboard.writeText(text);
            btn.classList.add('copied');
            const original = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i>';
            setTimeout(() => {
              btn.classList.remove('copied');
              btn.innerHTML = original;
            }, 1200);
          } catch { /* clipboard unavailable */ }
        });
      });
    },

    _card(record, idx) {
      const fields = Object.entries(record).filter(([k]) => !k.startsWith('_'));
      const primary =
        record.nama_penuh ||
        record.name ||
        record.username ||
        record.email ||
        record.telepon ||
        `Record #${idx + 1}`;

      const score = record._score ?? record.score;
      const match = record._matchedField;

      const metaBits = [];
      if (match) {
        metaBits.push(
          `<span class="osint-tag"><i class="fas fa-bullseye"></i> ${Util.esc(match)}</span>`
        );
      }
      if (typeof score === 'number') {
        const pct = Math.round(score * 100);
        const tone = pct >= 80 ? 'high' : pct >= 50 ? 'mid' : 'low';
        metaBits.push(
          `<span class="osint-tag osint-tag--${tone}">${pct}% match</span>`
        );
      }

      const rows = fields
        .slice(0, 8)
        .map(([k, v]) => {
          const display = Array.isArray(v) ? v.join(', ') : v;
          const copyText = Array.isArray(v) ? v.join(', ') : String(v ?? '');
          return `
            <div class="osint-row">
              <span class="osint-row__key">${Util.esc(k)}</span>
              <span class="osint-row__val">${Util.esc(Util.truncate(display, 90))}</span>
              <button class="osint-iconbtn osint-iconbtn--sm"
                      data-copy="${Util.esc(copyText)}"
                      title="Copy" aria-label="Copy ${Util.esc(k)}">
                <i class="fas fa-copy"></i>
              </button>
            </div>`;
        })
        .join('');

      return `
        <article class="osint-card">
          <header class="osint-card__head">
            <div class="osint-card__avatar" aria-hidden="true">
              <i class="fas fa-user-secret"></i>
            </div>
            <div class="osint-card__title">
              <strong>${Util.esc(Util.truncate(primary, 60))}</strong>
              <div class="osint-card__meta">${metaBits.join('')}</div>
            </div>
          </header>
          <div class="osint-card__body">${rows}</div>
        </article>`;
    },
  };

  /* ==================================================================
   * OSINT PUBLIC OBJECT
   * ================================================================== */

  const Osint = {
    TOOL_INFO,
    CONFIG,

    async search(query, opts = {}) {
      const method = (opts.method || _state.method || 'username').toLowerCase();
      const q = String(query ?? '').trim();

      if (!q || q.length < CONFIG.minQueryLen) {
        return this._fail('query_too_short', {
          message: `Query must be at least ${CONFIG.minQueryLen} characters.`,
        });
      }
      if (q.length > CONFIG.maxQueryLen) {
        return this._fail('query_too_long', {
          message: `Query too long (max ${CONFIG.maxQueryLen}).`,
        });
      }
      if (method === 'email' && !Util.isEmail(q)) {
        return this._fail('invalid_email', { message: 'Invalid email format.' });
      }
      if (method === 'number' && !Util.isPhone(q)) {
        return this._fail('invalid_phone', { message: 'Invalid phone number format.' });
      }

      const cached = _cache.get(method, q);
      if (cached) {
        Logger.debug('cache HIT', method, q);
        return cached;
      }

      const wait = _limiter.check();
      if (wait > 0) {
        Logger.debug('rate-limited, waiting', wait, 'ms');
        await new Promise((r) => setTimeout(r, wait));
      }

      if (_state.controller) {
        try { _state.controller.abort(); } catch { /* noop */ }
      }
      const ctrl = new AbortController();
      _state.controller = ctrl;
      _state.lastQuery = q;

      const payload = {
        query: q,
        method,
        mode: 'basic',
        limit: CONFIG.maxResults,
      };

      const startedAt = Date.now();
      let res, json, err;

      for (let attempt = 0; attempt <= CONFIG.retryCount; attempt++) {
        try {
          res = await Util.fetchWithTimeout(
            CONFIG.apiEndpoint,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'same-origin',
              body: JSON.stringify(payload),
              signal: ctrl.signal,
            },
            CONFIG.requestTimeoutMs
          );

          if (res.status === 404 && attempt === 0) {
            Logger.warn(`primary endpoint 404, trying fallback: ${CONFIG.fallbackEndpoints[0]}`);
            res = await Util.fetchWithTimeout(
              CONFIG.fallbackEndpoints[0],
              {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify(payload),
                signal: ctrl.signal,
              },
              CONFIG.requestTimeoutMs
            );
          }

          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          json = await res.json();
          err = null;
          break;
        } catch (e) {
          err = e;
          if (e.name === 'AbortError') break;
          if (attempt < CONFIG.retryCount) {
            const backoff = CONFIG.retryBaseMs * Math.pow(2, attempt);
            Logger.warn(`retry ${attempt + 1}/${CONFIG.retryCount} in ${backoff}ms`, e.message);
            await new Promise((r) => setTimeout(r, backoff));
          }
        }
      }

      if (err || !json) {
        Logger.error('search failed', err);
        return this._fail('request_failed', {
          message: err?.name === 'AbortError'
            ? 'Request cancelled.'
            : 'Backend unreachable.',
        });
      }

      const out = {
        tool: 'osint',
        method,
        query: q,
        data: {
          results: json?.data?.results || json?.results || [],
          count:
            json?.data?.count ??
            (json?.data?.results?.length || json?.results?.length || 0),
          tookMs: Date.now() - startedAt,
          raw: json,
        },
      };

      _cache.set(method, q, out);
      _state.lastPayload = out;
      Logger.debug('search OK', method, q, out.data.count, 'results');
      return out;
    },

    run(query, mode = 'basic', opts = {}) {
      return this.search(query, { ...opts, mode });
    },

    setMethod(m) {
      if (!METHOD_ORDER.includes(m)) return;
      _state.method = m;
      Logger.debug('method set', m);
    },

    getMethod() {
      return _state.method;
    },

    clearCache() {
      _cache.clear();
      Logger.info('cache cleared');
    },

    _fail(code, extra = {}) {
      return {
        tool: 'osint',
        error: code,
        message: extra.message || code,
        data: { results: [], count: 0 },
      };
    },

    _export(rows, method, query) {
      try {
        const blob = new Blob(
          [
            JSON.stringify(
              {
                generatedAt: new Date().toISOString(),
                method,
                query,
                count: rows.length,
                results: rows,
              },
              null,
              2
            ),
          ],
          { type: 'application/json' }
        );
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `osint-${method}-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (e) {
        Logger.error('export failed', e);
      }
    },
  };

  /* ==================================================================
   * HELPERS — METHOD SLIDER
   * ================================================================== */

  function attachMethodSlider(toggleEl) {
    if (!toggleEl) return null;
    if (toggleEl.dataset.sliderBound === '1') return toggleEl._sliderApi;
    toggleEl.dataset.sliderBound = '1';

    const slider = toggleEl.querySelector('.osint-method-toggle__slider');
    const btns = Array.from(toggleEl.querySelectorAll('.osint-method-btn'));
    if (!btns.length) return null;

    function moveSlider(btn) {
      if (!slider || !btn) return;
      const idx = btns.indexOf(btn);
      if (idx < 0) return;
      const pct = idx * 100;
      const gap = 4;
      slider.style.transform = `translateX(calc(${pct}% + ${idx * gap}px))`;
    }

    function activate(btn, silent) {
      btns.forEach((x) => x.classList.remove('active'));
      btn.classList.add('active');
      moveSlider(btn);

      const method = btn.getAttribute('data-method') || 'username';
      if (!silent) Osint.setMethod(method);

      const panel = toggleEl.closest('.osint-panel-premium, .tool-detail') || document;
      const input = panel.querySelector('.osint-input-premium > input');
      if (input) updatePlaceholder(input, method);

      // Mirror selection across all other OSINT panels on the page
      if (!silent) {
        document.querySelectorAll('.osint-method-toggle').forEach((other) => {
          if (other === toggleEl) return;
          const otherBtns = Array.from(other.querySelectorAll('.osint-method-btn'));
          const otherSlider = other.querySelector('.osint-method-toggle__slider');
          let activeIdx = 0;
          otherBtns.forEach((x, i) => {
            const m = x.getAttribute('data-method');
            const isActive = m === method;
            x.classList.toggle('active', isActive);
            if (isActive) activeIdx = i;
          });
          if (otherSlider) {
            const gap = 4;
            otherSlider.style.transform =
              `translateX(calc(${activeIdx * 100}% + ${activeIdx * gap}px))`;
          }
        });
      }
    }

    btns.forEach((b) => {
      b.addEventListener('click', () => {
        activate(b, false);

        const panel = toggleEl.closest('.osint-panel-premium, .tool-detail') || document;
        const input = panel.querySelector('.osint-input-premium > input');
        if (input && input.value.trim().length >= CONFIG.minQueryLen) {
          const submitBtn = panel.querySelector('.osint-input-premium__submit');
          if (submitBtn) submitBtn.click();
        }
      });
    });

    const active = btns.find((x) => x.classList.contains('active')) || btns[0];
    activate(active, true);

    const api = { moveSlider, activate, btns, slider };
    toggleEl._sliderApi = api;
    return api;
  }

  /* ==================================================================
   * HELPERS — PLACEHOLDER + HAS-VALUE + RIPPLE
   * ================================================================== */

  function updatePlaceholder(input, method) {
    if (!input) return;
    input.placeholder = ' ';
    input.dataset.placeholder = METHOD_PLACEHOLDER[method] || 'Search…';
    input.setAttribute('aria-label', METHOD_PLACEHOLDER[method] || 'Search');
  }

  function attachHasValue(wrapEl) {
    if (!wrapEl) return;
    const input = wrapEl.querySelector('input');
    if (!input || input.dataset.hasValueBound === '1') return;
    input.dataset.hasValueBound = '1';

    const sync = () => wrapEl.classList.toggle('has-value', input.value.length > 0);
    input.addEventListener('input', sync);
    input.addEventListener('change', sync);
    sync();
  }

  function attachRipple(button) {
    if (!button || button.dataset.rippleBound === '1') return;
    button.dataset.rippleBound = '1';
    button.addEventListener('click', (e) => Util.ripple(button, e));
  }

  /* ==================================================================
   * PANEL BINDER
   * ================================================================== */

  function bindPanel(cfg) {
    const {
      name,
      toggleBtn,
      panelEl,
      closeBtn,
      methodToggle,
      inputWrap,
      input,
      submitBtn,
      clearBtn,
      resultArea,
      exportBtn,
      hubBtn,
    } = cfg;

    if (!input || !submitBtn || !resultArea) {
      Logger.debug(`[${name}] required elements missing, skipping.`);
      return null;
    }

    if (submitBtn.dataset.panelBound === '1') {
      Logger.debug(`[${name}] already bound.`);
      return submitBtn._panelApi;
    }
    submitBtn.dataset.panelBound = '1';

    const sliderApi = attachMethodSlider(methodToggle);
    attachHasValue(inputWrap);
    attachRipple(submitBtn);
    if (clearBtn) attachRipple(clearBtn);

    function setOpen(open) {
      if (!panelEl) return;
      panelEl.hidden = !open;
      toggleBtn?.setAttribute('aria-expanded', String(open));
      if (open) {
        setTimeout(() => {
          panelEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          input.focus({ preventScroll: true });
        }, 100);
      }
    }

    toggleBtn?.addEventListener('click', () => setOpen(panelEl?.hidden ?? true));
    closeBtn?.addEventListener('click', () => setOpen(false));

    const initMethod =
      methodToggle?.querySelector('.osint-method-btn.active')?.getAttribute('data-method')
      || _state.method;
    Osint.setMethod(initMethod);
    updatePlaceholder(input, initMethod);

    async function doSearch() {
      const q = input.value.trim();
      if (!q) { Util.shake(inputWrap); input.focus(); return; }

      const method = _state.method;
      if (method === 'email' && !Util.isEmail(q)) {
        Util.shake(inputWrap);
        Renderer.error(resultArea, 'Invalid email format.');
        return;
      }
      if (method === 'number' && !Util.isPhone(q)) {
        Util.shake(inputWrap);
        Renderer.error(resultArea, 'Invalid phone number format.');
        return;
      }

      submitBtn.disabled = true;
      const prevLabel = submitBtn.querySelector('.osint-input-premium__submit-label');
      const prevHtml = prevLabel?.innerHTML ?? 'Search';
      if (prevLabel) prevLabel.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
      Renderer.loading(resultArea, `Searching ${METHOD_LABEL[method]}…`);

      try {
        const res = await Osint.search(q, { method });
        if (res.error) {
          Renderer.error(resultArea, res.message || 'Request failed.');
        } else {
          Renderer.results(resultArea, res, method, q);
          if (exportBtn) exportBtn.style.opacity = '1';
        }
      } catch (err) {
        Logger.error('search threw', err);
        Renderer.error(resultArea, 'Unexpected error.');
      } finally {
        submitBtn.disabled = false;
        if (prevLabel) prevLabel.innerHTML = prevHtml;
      }
    }

    submitBtn.addEventListener('click', doSearch);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        doSearch();
      }
      if (e.key === 'Escape') {
        input.value = '';
        inputWrap?.classList.remove('has-value');
        resultArea.innerHTML = '';
      }
    });

    clearBtn?.addEventListener('click', () => {
      input.value = '';
      inputWrap?.classList.remove('has-value');
      resultArea.innerHTML = '';
      if (exportBtn) exportBtn.style.opacity = '.5';
      input.focus();
    });

    exportBtn?.addEventListener('click', () => {
      const payload = _state.lastPayload;
      if (!payload?.data?.results?.length) return;
      Osint._export(payload.data.results, payload.method, payload.query);
    });

    hubBtn?.addEventListener('click', () => {
      setOpen(false);
      const hubBox = document.querySelector('.tool-box[data-tool="osint"]');
      if (hubBox) hubBox.click();
    });

    // ── Suggestion chips — SCOPED per-panel ─────────────────────────
    // Find chips inside this panel's own suggest row only.
    const localSuggestRow = panelEl?.querySelector('.osint-suggest-premium')
                          || document.getElementById(name + 'Suggest');
    if (localSuggestRow) {
      localSuggestRow.querySelectorAll('.osint-chip').forEach((chip) => {
        if (chip.dataset.chipBound === '1') return;
        chip.dataset.chipBound = '1';

        chip.addEventListener('click', () => {
          const v = chip.getAttribute('data-suggest') || '';
          input.value = v;
          inputWrap?.classList.add('has-value');

          let m = 'username';
          if (Util.isEmail(v)) m = 'email';
          else if (Util.isPhone(v) && Util.normPhone(v).length >= 6) m = 'number';

          Osint.setMethod(m);
          if (sliderApi) {
            const btn = sliderApi.btns.find((x) => x.getAttribute('data-method') === m);
            if (btn) sliderApi.activate(btn, true);
          }
          updatePlaceholder(input, m);

          setTimeout(doSearch, 120);
        });
      });
    }

    const api = { doSearch, setOpen, sliderApi };
    submitBtn._panelApi = api;

    Logger.info(`[${name}] panel bound.`);
    return api;
  }

  /* ==================================================================
   * BIND — SCHOOL PANEL
   * ================================================================== */

  function bindSchoolPanel() {
    return bindPanel({
      name: 'school',
      toggleBtn:    document.getElementById('schoolOsintToggleBtn'),
      panelEl:      document.getElementById('schoolOsintPanel'),
      closeBtn:     document.getElementById('schoolOsintCloseBtn'),
      methodToggle: document.getElementById('schoolOsintMethodToggle'),
      inputWrap:    document.getElementById('schoolOsintInputWrap'),
      input:        document.getElementById('schoolOsintQueryInput'),
      submitBtn:    document.getElementById('schoolOsintSearchBtn'),
      clearBtn:     document.getElementById('schoolOsintClearBtn'),
      resultArea:   document.getElementById('schoolOsintResultArea'),
      exportBtn:    document.getElementById('schoolOsintExportBtn'),
    });
  }

  /* ==================================================================
   * BIND — TOOLS HUB PANEL
   * ================================================================== */

  function bindToolsHubPanel() {
    return bindPanel({
      name: 'hub',
      toggleBtn:    null,
      panelEl:      document.getElementById('toolDetail-osint'),
      closeBtn:     null,
      methodToggle: document.getElementById('osintMethodToggle'),
      inputWrap:    document.getElementById('osintInputWrap'),
      input:        document.getElementById('osintQueryInput'),
      submitBtn:    document.getElementById('osintSearchBtn'),
      clearBtn:     null,
      resultArea:   document.getElementById('osintResultArea'),
      exportBtn:    null,
    });
  }

  /* ==================================================================
   * BIND — SECURITY TESTING (auto-injected)
   * ================================================================== */

  /**
   * Injects a premium OSINT launcher + panel directly below the
   * Security Testing "Start Scan" button (#scanBtn). Reuses the same
   * premium CSS classes as the School panel — no stylesheet edits needed.
   * Idempotent: safe to call repeatedly.
   */
  function bindSecurityPanel() {
    if (!CONFIG.injectInSecurityTesting) return null;

    // ── Locate the anchor — Security Testing's scan button ─────────
    const scanBtn = document.getElementById('scanBtn');
    if (!scanBtn || !scanBtn.parentNode) {
      Logger.debug('[security] #scanBtn not found (yet)');
      return null;
    }
    if (scanBtn.dataset.osintInjected === '1') {
      // Already injected — ensure slider is bound in case DOM was moved
      return bindPanel({
        name: 'sec',
        toggleBtn:    document.getElementById('secOsintToggleBtn'),
        panelEl:      document.getElementById('secOsintPanel'),
        closeBtn:     document.getElementById('secOsintCloseBtn'),
        methodToggle: document.getElementById('secOsintMethodToggle'),
        inputWrap:    document.getElementById('secOsintInputWrap'),
        input:        document.getElementById('secOsintQueryInput'),
        submitBtn:    document.getElementById('secOsintSearchBtn'),
        clearBtn:     document.getElementById('secOsintClearBtn'),
        resultArea:   document.getElementById('secOsintResultArea'),
        exportBtn:    document.getElementById('secOsintExportBtn'),
      });
    }

    // ── Launcher button (uses same CSS as School CTA) ──────────────
    const ctaWrap = document.createElement('div');
    ctaWrap.className = 'osint-cta-wrap osint-cta-wrap--security';
    ctaWrap.style.marginTop = '14px';
    ctaWrap.innerHTML = `
      <button class="osint-cta-premium" id="secOsintToggleBtn"
              aria-expanded="false" aria-controls="secOsintPanel"
              type="button">
        <span class="osint-cta-premium__glow" aria-hidden="true"></span>
        <span class="osint-cta-premium__border" aria-hidden="true"></span>
        <span class="osint-cta-premium__content">
          <span class="osint-cta-premium__icon">
            <i class="fas fa-fingerprint"></i>
            <span class="osint-cta-premium__pulse" aria-hidden="true"></span>
          </span>
          <span class="osint-cta-premium__text">
            <span class="osint-cta-premium__title">Run OSINT Lookup</span>
            <span class="osint-cta-premium__sub">Username · Email · Phone · before you scan</span>
          </span>
          <span class="osint-cta-premium__arrow">
            <i class="fas fa-arrow-right"></i>
          </span>
        </span>
      </button>`;

    // ── Panel markup (uses same premium CSS) ───────────────────────
    const panel = document.createElement('div');
    panel.className = 'osint-panel-premium osint-panel-premium--security';
    panel.id = 'secOsintPanel';
    panel.hidden = true;
    panel.style.marginTop = '14px';
    panel.innerHTML = `
      <div class="osint-panel-premium__bg" aria-hidden="true">
        <span class="osint-panel-premium__grid"></span>
        <span class="osint-panel-premium__scanline"></span>
      </div>

      <div class="osint-panel-premium__inner">
        <div class="osint-panel-premium__head">
          <div class="osint-panel-premium__head-icon">
            <i class="fas fa-shield-halved"></i>
            <span class="osint-panel-premium__head-pulse"></span>
          </div>
          <div class="osint-panel-premium__head-text">
            <div class="osint-panel-premium__head-title">OSINT Lookup Console</div>
            <div class="osint-panel-premium__head-sub">
              Cari maklumat awam sebelum memulakan pengimbasan.
            </div>
          </div>
          <button class="osint-panel-premium__close" id="secOsintCloseBtn"
                  aria-label="Close" type="button">
            <i class="fas fa-xmark"></i>
          </button>
        </div>

        <div class="osint-method-toggle" id="secOsintMethodToggle">
          <span class="osint-method-toggle__slider" aria-hidden="true"></span>
          <button class="osint-method-btn active" data-method="username" type="button">
            <i class="fas fa-at"></i><span>Username</span>
          </button>
          <button class="osint-method-btn" data-method="email" type="button">
            <i class="fas fa-envelope"></i><span>Email</span>
          </button>
          <button class="osint-method-btn" data-method="number" type="button">
            <i class="fas fa-phone"></i><span>Number</span>
          </button>
        </div>

        <div class="osint-input-premium" id="secOsintInputWrap">
          <span class="osint-input-premium__scan" aria-hidden="true"></span>
          <span class="osint-input-premium__icon">
            <i class="fas fa-magnifying-glass"></i>
          </span>
          <input type="text" id="secOsintQueryInput"
                 placeholder=" " autocomplete="off" spellcheck="false"
                 maxlength="120" aria-label="OSINT query">
          <label class="osint-input-premium__label" for="secOsintQueryInput">
            Masukkan username, email atau nombor telefon
          </label>
          <button class="osint-input-premium__clear" id="secOsintClearBtn"
                  type="button" aria-label="Clear">
            <i class="fas fa-xmark"></i>
          </button>
          <button class="osint-input-premium__submit" id="secOsintSearchBtn"
                  type="button">
            <span class="osint-input-premium__submit-label">Search</span>
            <i class="fas fa-arrow-right"></i>
            <span class="osint-input-premium__ripple" aria-hidden="true"></span>
          </button>
        </div>

        <div class="osint-suggest-premium" id="secSuggest">
          <span class="osint-suggest-premium__label">Cuba:</span>
          <button class="osint-chip" data-suggest="johndoe" style="--i:0" type="button">
            <i class="fas fa-at"></i> johndoe</button>
          <button class="osint-chip" data-suggest="admin" style="--i:1" type="button">
            <i class="fas fa-user-shield"></i> admin</button>
          <button class="osint-chip" data-suggest="user@example.com" style="--i:2" type="button">
            <i class="fas fa-envelope"></i> user@example.com</button>
          <button class="osint-chip" data-suggest="08123456789" style="--i:3" type="button">
            <i class="fas fa-phone"></i> 08123456789</button>
        </div>

        <div class="osint-result-premium" id="secOsintResultArea"></div>

        <div class="osint-panel-premium__foot">
          <span class="osint-panel-premium__hint">
            <i class="fas fa-circle-info"></i>
            <span>Hasil diambil dari sumber awam. Sahkan sebelum digunakan.</span>
          </span>
          <button class="osint-panel-premium__export" id="secOsintExportBtn" type="button">
            <i class="fas fa-download"></i>
            <span>Export</span>
          </button>
        </div>
      </div>`;

    // ── Insert below #scanBtn ──────────────────────────────────────
    scanBtn.parentNode.insertBefore(ctaWrap, scanBtn.nextSibling);
    ctaWrap.parentNode.insertBefore(panel, ctaWrap.nextSibling);
    scanBtn.dataset.osintInjected = '1';

    Logger.info('[security] OSINT launcher injected below #scanBtn');

    // ── Hook: when launcher opens, pre-fill from #scanTarget ───────
    const toggleBtn = document.getElementById('secOsintToggleBtn');
    const panelEl   = document.getElementById('secOsintPanel');
    if (toggleBtn && panelEl) {
      toggleBtn.addEventListener('click', () => {
        const targetInput = document.getElementById('scanTarget');
        const osintInput  = document.getElementById('secOsintQueryInput');
        if (targetInput && osintInput && !osintInput.value.trim()) {
          const v = targetInput.value.trim();
          if (v) {
            // Strip scheme/path — keep host only
            const host = v.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
            if (host && host.length >= CONFIG.minQueryLen) {
              osintInput.value = host;
              document.getElementById('secOsintInputWrap')
                ?.classList.add('has-value');
            }
          }
        }
      });
    }

    // ── Bind the new panel ─────────────────────────────────────────
    return bindPanel({
      name: 'sec',
      toggleBtn:    document.getElementById('secOsintToggleBtn'),
      panelEl:      document.getElementById('secOsintPanel'),
      closeBtn:     document.getElementById('secOsintCloseBtn'),
      methodToggle: document.getElementById('secOsintMethodToggle'),
      inputWrap:    document.getElementById('secOsintInputWrap'),
      input:        document.getElementById('secOsintQueryInput'),
      submitBtn:    document.getElementById('secOsintSearchBtn'),
      clearBtn:     document.getElementById('secOsintClearBtn'),
      resultArea:   document.getElementById('secOsintResultArea'),
      exportBtn:    document.getElementById('secOsintExportBtn'),
    });
  }

  /* ==================================================================
   * BOOTSTRAP
   * ================================================================== */

  global.Osint = Osint;

  function initAll() {
    try { bindSchoolPanel(); }    catch (e) { Logger.error('school bind failed', e); }
    try { bindToolsHubPanel(); }  catch (e) { Logger.error('hub bind failed', e); }
    try { bindSecurityPanel(); }  catch (e) { Logger.error('security bind failed', e); }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAll, { once: true });
  } else {
    initAll();
  }

  /* ── Lazy rebind on user navigation ─────────────────────────────── */
  document.addEventListener('click', (e) => {
    const schoolsNav = e.target.closest?.('[data-section="schools"]');
    if (schoolsNav) setTimeout(bindSchoolPanel, 80);

    const hubBox = e.target.closest?.('[data-tool="osint"]');
    if (hubBox) setTimeout(bindToolsHubPanel, 80);

    const toolsNav = e.target.closest?.('#navToolsHub');
    if (toolsNav) setTimeout(bindToolsHubPanel, 120);

    // Security Testing section
    const testingNav = e.target.closest?.('[data-section="testing"]');
    if (testingNav) setTimeout(bindSecurityPanel, 80);
  }, true);

  /* ── Re-inject if #scanBtn appears later (dynamic rendering) ───── */
  if (typeof MutationObserver !== 'undefined') {
    const mo = new MutationObserver(() => {
      try {
        const scanBtn = document.getElementById('scanBtn');
        if (scanBtn && scanBtn.dataset.osintInjected !== '1') {
          bindSecurityPanel();
        }
        const secPanel = document.getElementById('secOsintPanel');
        if (secPanel && !secPanel.hidden) bindSecurityPanel();
        const schoolPanel = document.getElementById('schoolOsintPanel');
        if (schoolPanel && !schoolPanel.hidden) bindSchoolPanel();
        const hubPanel = document.getElementById('toolDetail-osint');
        if (hubPanel && !hubPanel.hidden) bindToolsHubPanel();
      } catch (e) {
        Logger.error('mutation rebind failed', e);
      }
    });

    const startObserving = () => {
      const content = document.querySelector('.content-area')
                   || document.body;
      mo.observe(content, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['hidden', 'class'],
      });
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', startObserving, { once: true });
    } else {
      startObserving();
    }
  }

})(typeof window !== 'undefined' ? window : globalThis);
