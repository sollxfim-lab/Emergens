// ╔══════════════════════════════════════════════════════════╗
// ║  MHDDoS ENGINE — Standalone Attack Console Module           ║
// ║  Self-contained. No dependency on script.js internals.      ║
// ║                                                             ║
// ║  Load with:                                                 ║
// ║    <script src="/static/js/mhddos.js" defer></script>       ║
// ║                                                             ║
// ║  Requires in dashboard.html:                                ║
// ║    • <div class="nav-item" data-section="mhddos">…</div>    ║
// ║    • <section id="section-mhddos">…</section>               ║
// ║  And the CSS block from the MHDDoS styling.                 ║
// ╚══════════════════════════════════════════════════════════╝
(function(){
    'use strict';

    // ── Local helpers, with graceful fallback to globals ───
    const escapeHtml = (typeof window.escapeHtml === 'function')
        ? window.escapeHtml
        : function(u){
            return String(u ?? '')
                .replace(/&/g,'&amp;')
                .replace(/</g,'&lt;')
                .replace(/>/g,'&gt;')
                .replace(/"/g,'&quot;')
                .replace(/'/g,'&#039;');
        };

    const showToast = (typeof window.showToast === 'function')
        ? window.showToast
        : function(msg, type){
            // Minimal toast fallback — only fires if script.js hasn't defined one.
            const c = document.getElementById('toastContainer') || (function(){
                const el = document.createElement('div');
                el.id = 'toastContainer';
                el.style.cssText =
                    'position:fixed;top:18px;right:18px;z-index:99999;' +
                    'display:flex;flex-direction:column;gap:8px;pointer-events:none;';
                document.body.appendChild(el);
                return el;
            })();
            const d = document.createElement('div');
            d.textContent = msg;
            const bg = type === 'error' ? '#e63946'
                     : type === 'warning' ? '#ffa502'
                     : '#2ed573';
            d.style.cssText =
                'background:' + bg + ';color:#fff;padding:10px 16px;' +
                'border-radius:8px;font:600 0.82rem/1.3 system-ui,sans-serif;' +
                'box-shadow:0 8px 24px rgba(0,0,0,0.35);pointer-events:auto;' +
                'animation:mhdFadeIn 0.2s ease;';
            c.appendChild(d);
            setTimeout(function(){
                d.style.transition = 'opacity 0.25s ease';
                d.style.opacity = '0';
                setTimeout(function(){ d.remove(); }, 260);
            }, 3000);
        };

    // Toast keyframe (injected once)
    if(!document.getElementById('mhdToastKeyframes')){
        const s = document.createElement('style');
        s.id = 'mhdToastKeyframes';
        s.textContent = '@keyframes mhdFadeIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}';
        document.head.appendChild(s);
    }

    // ── Per-method icon map ────────────────────────────────
    const METHOD_ICONS = {
        GET:'fa-download', POST:'fa-upload', HEAD:'fa-heading',
        CFB:'fa-cloud', CFBUAM:'fa-cloud-bolt', BYPASS:'fa-shield-halved',
        OVH:'fa-server', STRESS:'fa-fire', DYN:'fa-bolt',
        SLOW:'fa-snail', NULL:'fa-ban', COOKIE:'fa-cookie-bite',
        PPS:'fa-gauge-high', EVEN:'fa-scale-balanced', GSB:'fa-google',
        DGB:'fa-dragon', AVB:'fa-shield', APACHE:'fa-feather',
        XMLRPC:'fa-code', BOT:'fa-robot', BOMB:'fa-bomb',
        DOWNLOADER:'fa-download', KILLER:'fa-skull', TOR:'fa-user-secret',
        RHEX:'fa-rotate', STOMP:'fa-shoe-prints',
        TCP:'fa-plug', UDP:'fa-paper-plane', SYN:'fa-wave-square',
        VSE:'fa-gamepad', MINECRAFT:'fa-cube', MCBOT:'fa-robot',
        CONNECTION:'fa-link', CPS:'fa-bolt-lightning', FIVEM:'fa-car',
        'FIVEM-TOKEN':'fa-key', TS3:'fa-headset', MCPE:'fa-mobile',
        ICMP:'fa-satellite-dish', 'OVH-UDP':'fa-server',
        MEM:'fa-memory', NTP:'fa-clock', DNS:'fa-globe',
        ARD:'fa-apple-whole', CLDAP:'fa-address-book',
        CHAR:'fa-keyboard', RDP:'fa-desktop'
    };
    const pillIcon = (name) =>
        METHOD_ICONS[String(name).toUpperCase()] || 'fa-bolt';

    // ── Module state ───────────────────────────────────────
    const state = {
        section: null,
        navDot: null,
        methods: { layer7: [], layer4: [] },
        selectedMethod: '',
        pollTimer: null,
        pollActive: false,
        statusInFlight: false
    };

    // ── Init — wait for DOM ────────────────────────────────
    function init(){
        state.section = document.getElementById('section-mhddos');
        if(!state.section){
            // Section not on this page — silently exit.
            return;
        }
        state.navDot = document.getElementById('mhdNavDot');

        wireLayerTabs();
        wireMethodDelegate();
        wireFormInputs();
        wireActions();
        wireKeyboard();
        wireSectionLifecycle();

        // Fetch methods up front so the panel is warm when first opened.
        loadMethods();
    }

    // ── Layer tab switching ────────────────────────────────
    function wireLayerTabs(){
        state.section.querySelectorAll('.mhd-layer-tab').forEach(function(tab){
            tab.addEventListener('click', function(){
                state.section.querySelectorAll('.mhd-layer-tab')
                    .forEach(function(t){ t.classList.remove('active'); });
                tab.classList.add('active');

                const layer = tab.dataset.layer;
                state.section.querySelectorAll('.mhd-layer-panel').forEach(function(p){
                    const on = p.dataset.layer === layer;
                    p.hidden = !on;
                    p.classList.toggle('active', on);
                });

                // Reset method selection when switching layer
                state.selectedMethod = '';
                state.section.querySelectorAll('.mhd-pill')
                    .forEach(function(p){ p.classList.remove('selected'); });
                updateStartState();
            });
        });
    }

    // ── Method pill selection (event delegation) ───────────
    function wireMethodDelegate(){
        state.section.addEventListener('click', function(e){
            const pill = e.target.closest('.mhd-pill');
            if(!pill) return;
            state.section.querySelectorAll('.mhd-pill')
                .forEach(function(p){ p.classList.remove('selected'); });
            pill.classList.add('selected');
            state.selectedMethod = pill.dataset.method;
            updateStartState();
        });
    }

    // ── Start button enabled/disabled state ────────────────
    function updateStartState(){
        const btn = state.section.querySelector('#mhdStartBtn');
        if(!btn) return;
        const target = (
            state.section.querySelector('#mhdTargetInput')?.value || ''
        ).trim();
        btn.disabled = !state.selectedMethod || !target;
    }

    // ── Live form input binding ────────────────────────────
    function wireFormInputs(){
        const input = state.section.querySelector('#mhdTargetInput');
        if(input){
            input.addEventListener('input', updateStartState);
            input.addEventListener('keydown', function(e){
                if(e.key === 'Enter' && !e.shiftKey){
                    e.preventDefault();
                    const btn = state.section.querySelector('#mhdStartBtn');
                    if(btn && !btn.disabled) btn.click();
                }
            });
        }
    }

    // ── Start / Stop / Stop-All buttons ────────────────────
    function wireActions(){
        state.section.querySelector('#mhdStartBtn')
            ?.addEventListener('click', startAttack);

        state.section.querySelector('#mhdStopAllBtn')
            ?.addEventListener('click', stopAll);

        // Per-card Stop buttons use event delegation (cards render dynamically)
        state.section.addEventListener('click', function(e){
            const stopBtn = e.target.closest('[data-stop-attack]');
            if(!stopBtn) return;
            const id = stopBtn.dataset.stopAttack;
            stopOne(id, stopBtn);
        });
    }

    // Keyboard shortcut: ESC clears method selection
    function wireKeyboard(){
        document.addEventListener('keydown', function(e){
            if(e.key !== 'Escape') return;
            if(!state.section.classList.contains('active')) return;
            state.selectedMethod = '';
            state.section.querySelectorAll('.mhd-pill')
                .forEach(function(p){ p.classList.remove('selected'); });
            updateStartState();
        });
    }

    // ── Section lifecycle — poll only while visible ────────
    function wireSectionLifecycle(){
        window.addEventListener('section-change', function(e){
            if(e.detail !== 'mhddos') return;
            if(!state.methods.layer7.length && !state.methods.layer4.length){
                loadMethods();
            }
            refreshStatus();
            ensurePolling();
        });

        // Fallback: if another module or page doesn't emit section-change,
        // watch the DOM for the section gaining/losing the .active class.
        if(typeof MutationObserver !== 'undefined'){
            const mo = new MutationObserver(function(){
                const active = state.section.classList.contains('active');
                if(active){
                    if(!state.methods.layer7.length && !state.methods.layer4.length){
                        loadMethods();
                    }
                    refreshStatus();
                    ensurePolling();
                } else {
                    stopPolling();
                }
            });
            mo.observe(state.section, { attributes: true, attributeFilter: ['class'] });
        }
    }

    // ── Engine status badge ────────────────────────────────
    function setEngineBadge(kind){
        const b = state.section.querySelector('#mhdEngineStatus');
        if(!b) return;
        b.classList.remove('busy','error');
        if(kind === 'busy'){
            b.classList.add('busy');
            b.innerHTML = '<i class="fas fa-circle"></i> Attacking';
        } else if(kind === 'error'){
            b.classList.add('error');
            b.innerHTML = '<i class="fas fa-circle"></i> Offline';
        } else {
            b.innerHTML = '<i class="fas fa-circle"></i> Ready';
        }
    }

    // ── Load method catalogue ──────────────────────────────
    async function loadMethods(){
        try{
            const r = await fetch('/api/mhddos/methods');
            if(!r.ok) throw new Error('HTTP ' + r.status);
            const d = await r.json();
            state.methods.layer7 = Array.isArray(d.layer7) ? d.layer7 : [];
            state.methods.layer4 = Array.isArray(d.layer4) ? d.layer4 : [];
            renderPills('7');
            renderPills('4');
        } catch(err){
            const wrap = state.section.querySelector('#mhdMethodGrid-7');
            if(wrap){
                wrap.innerHTML =
                    '<div class="mhd-empty"><i class="fas fa-circle-exclamation"></i> ' +
                    escapeHtml(err.message) + '</div>';
            }
            setEngineBadge('error');
        }
    }

    // ── Render method pills ────────────────────────────────
    function renderPills(layer){
        const wrap = state.section.querySelector('#mhdMethodGrid-' + layer);
        if(!wrap) return;
        const list = layer === '7' ? state.methods.layer7 : state.methods.layer4;
        if(!list.length){
            wrap.innerHTML = '<div class="mhd-empty">No methods returned by the engine.</div>';
            return;
        }
        wrap.innerHTML = list.map(function(m){
            return '<button type="button" class="mhd-pill" data-method="' +
                escapeHtml(m) + '">' +
                '<i class="fas ' + pillIcon(m) + '"></i>' +
                '<span>' + escapeHtml(m) + '</span>' +
                '</button>';
        }).join('');
    }

    // ── Start attack ───────────────────────────────────────
    async function startAttack(){
        const btn = state.section.querySelector('#mhdStartBtn');
        if(!btn) return;

        const target = (
            state.section.querySelector('#mhdTargetInput')?.value || ''
        ).trim();

        if(!state.selectedMethod || !target){
            showToast('Pick a method and enter a target first.', 'error');
            return;
        }

        const payload = {
            method:         state.selectedMethod,
            target:         target,
            threads:        clampInt(state.section.querySelector('#mhdThreads'),    10, 1, 1000),
            duration:       clampInt(state.section.querySelector('#mhdDuration'),   60, 1, 3600),
            proxy_type:     clampInt(state.section.querySelector('#mhdProxyType'),  0,  0, 6),
            proxy_file:     state.section.querySelector('#mhdProxyFile')?.value  || 'proxies.txt',
            rpc:            clampInt(state.section.querySelector('#mhdRpc'),         1,  1, 10000),
            reflector_file: state.section.querySelector('#mhdReflector')?.value  || '',
            debug:          !!state.section.querySelector('#mhdDebug')?.checked
        };

        const origHtml = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Launching…</span>';

        try{
            const r = await fetch('/api/mhddos/start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
            const d = await r.json().catch(function(){ return {}; });

            if(!r.ok || !d.success){
                showToast(d.error || ('Launch failed (' + r.status + ')'), 'error');
                setEngineBadge('error');
            } else {
                showToast('Attack ' + d.attack_id + ' launched.', 'success');
                setEngineBadge('busy');
                refreshStatus();
            }
        } catch(err){
            showToast('Network error: ' + err.message, 'error');
        } finally {
            btn.innerHTML = origHtml;
            updateStartState();
        }
    }

    // ── Stop one attack ────────────────────────────────────
    async function stopOne(attackId, btnEl){
        if(btnEl){
            btnEl.disabled = true;
            btnEl.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        }
        try{
            const r = await fetch('/api/mhddos/stop', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ attack_id: attackId })
            });
            const d = await r.json().catch(function(){ return {}; });
            if(!r.ok || !d.success){
                showToast(d.error || 'Stop failed.', 'error');
            } else {
                showToast('Stopping ' + attackId + '…');
            }
            refreshStatus();
        } catch(err){
            showToast('Stop failed: ' + err.message, 'error');
            if(btnEl){
                btnEl.disabled = false;
                btnEl.innerHTML = '<i class="fas fa-stop"></i> Stop';
            }
        }
    }

    // ── Stop all attacks ───────────────────────────────────
    async function stopAll(){
        try{
            const r = await fetch('/api/mhddos/stop_all', { method: 'POST' });
            const d = await r.json();
            showToast('Stopped ' + (d.stopped || 0) + ' attack(s).');
            refreshStatus();
        } catch(err){
            showToast('Stop-all failed: ' + err.message, 'error');
        }
    }

    // ── Status refresh ─────────────────────────────────────
    async function refreshStatus(){
        if(state.statusInFlight) return;   // guard against overlapping polls
        state.statusInFlight = true;
        try{
            const r = await fetch('/api/mhddos/status');
            if(!r.ok) throw new Error('HTTP ' + r.status);
            const d = await r.json();
            renderActive(d.running || []);
            renderHistory(d.history || []);
        } catch(err){
            setEngineBadge('error');
        } finally {
            state.statusInFlight = false;
        }
    }

    // ── Polling control ────────────────────────────────────
    function ensurePolling(){
        if(state.pollTimer) return;
        state.pollActive = true;
        state.pollTimer = setInterval(function(){
            if(!state.pollActive) return;
            if(state.section.classList.contains('active')) refreshStatus();
        }, 2000);
    }
    function stopPolling(){
        state.pollActive = false;
        if(state.pollTimer){
            clearInterval(state.pollTimer);
            state.pollTimer = null;
        }
    }
    window.addEventListener('beforeunload', stopPolling);

    // ── Active attacks renderer ────────────────────────────
    function renderActive(list){
        const wrap = state.section.querySelector('#mhdActiveList');
        const heroCount = state.section.querySelector('#mhdActiveCount');

        if(heroCount) heroCount.textContent = list.length;
        if(state.navDot) state.navDot.hidden = (list.length === 0);

        if(!wrap) return;

        if(!list.length){
            wrap.innerHTML =
                '<div class="mhd-empty"><i class="fas fa-shield-halved"></i> No active attacks</div>';
            setEngineBadge('ready');
            return;
        }

        setEngineBadge('busy');

        wrap.innerHTML = list.map(function(a){
            const elapsedSec = Math.max(0,
                Math.floor((Date.now() - new Date(a.started_at).getTime()) / 1000));
            const remaining = Math.max(0, (a.duration || 0) - elapsedSec);
            const pct = a.duration
                ? Math.min(100, (1 - remaining / a.duration) * 100)
                : 0;

            return '<div class="mhd-active-card">' +
                '<div class="mhd-active-head">' +
                    '<div>' +
                        '<span class="mhd-active-method">' + escapeHtml(a.method) + '</span>' +
                        '<span class="mhd-active-target">' + escapeHtml(a.target) + '</span>' +
                    '</div>' +
                    '<button class="mhd-stop-btn" data-stop-attack="' +
                        escapeHtml(a.attack_id) + '">' +
                        '<i class="fas fa-stop"></i> Stop' +
                    '</button>' +
                '</div>' +
                '<div class="mhd-active-progress">' +
                    '<div class="mhd-active-fill" style="width:' +
                        pct.toFixed(1) + '%"></div>' +
                '</div>' +
                '<div class="mhd-active-meta">' +
                    '<span><i class="fas fa-hourglass-half"></i>' +
                        fmtElapsed(a.started_at) + ' / ' + a.duration + 's</span>' +
                    '<span><i class="fas fa-microchip"></i>' +
                        a.threads + ' threads</span>' +
                    '<span class="mhd-active-id">' +
                        escapeHtml(a.attack_id) + '</span>' +
                '</div>' +
            '</div>';
        }).join('');
    }

    // ── History renderer ───────────────────────────────────
    function renderHistory(list){
        const wrap = state.section.querySelector('#mhdHistoryList');
        if(!wrap) return;

        if(!list.length){
            wrap.innerHTML = '<div class="mhd-empty">No history yet.</div>';
            return;
        }

        const clsFor = function(s){
            if(s === 'completed') return 'ok';
            if(s === 'running')   return 'run';
            if(s === 'stopped')   return 'stop';
            return 'fail';
        };

        wrap.innerHTML = list.slice().reverse().map(function(h){
            return '<div class="mhd-history-row">' +
                '<span class="mhd-h-method">' + escapeHtml(h.method) + '</span>' +
                '<span class="mhd-h-target" title="' + escapeHtml(h.target) + '">' +
                    escapeHtml(h.target) + '</span>' +
                '<span class="mhd-h-status ' + clsFor(h.status) + '">' +
                    escapeHtml(h.status) + '</span>' +
                '<span class="mhd-h-id">' + escapeHtml(h.attack_id) + '</span>' +
            '</div>';
        }).join('');
    }

    // ── Small utilities ────────────────────────────────────
    function fmtElapsed(startIso){
        const s = Math.max(0,
            Math.floor((Date.now() - new Date(startIso).getTime()) / 1000));
        return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
    }
    function clampInt(el, def, lo, hi){
        if(!el) return def;
        let v = parseInt(el.value, 10);
        if(isNaN(v)) v = def;
        return Math.max(lo, Math.min(hi, v));
    }

    // ── Boot ───────────────────────────────────────────────
    if(document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', init, { once: true });
    } else {
        init();
    }
})();
