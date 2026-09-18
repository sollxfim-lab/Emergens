/* ═══════════════════════════════════════════════════════════════
   EMERGENS — Bug Fix Patch
   Load AFTER script.js. Fixes 8 critical bugs without touching
   your original code.
   ═══════════════════════════════════════════════════════════════ */
(function(){
'use strict';
const $ = id => document.getElementById(id);

/* ─── FIX 1 : Null-safe pollScan ────────────────────────────── */
window.pollScan = function(jobId, target, isQuick, modeUsed){
    if(!jobId) return;
    if(window.scanPollInterval) clearInterval(window.scanPollInterval);
    const start = window.activeScanStart ? parseInt(window.activeScanStart,10) : Date.now();

    const updateTimer = () => {
        const txt = `Elapsed: ${(window.formatElapsed ? window.formatElapsed(Date.now()-start) : '0:00')}`;
        if(typeof forEachScanUi === 'function')
            forEachScanUi(inst => { const e = $(inst.elapsed); if(e) e.textContent = txt; });
    };
    updateTimer();

    const resetBtns = () => {
        const s = $('scanBtn'); if(s) s.disabled = false;
        const q = $('quickScanBtn');
        if(q){ q.disabled = false; q.innerHTML = '<i class="fas fa-play"></i> Run Quick Scan'; }
    };

    window.scanPollInterval = setInterval(async () => {
        try{
            const r = await fetch(`/api/scan/${jobId}/status`);
            if(!r.ok){ clearInterval(window.scanPollInterval); return; }
            const job = await r.json();
            const pct = job.percent || 0;

            if(typeof forEachScanUi === 'function')
                forEachScanUi(inst => {
                    const f = $(inst.fill); if(f) f.style.width = pct+'%';
                    const p = $(inst.pct);  if(p) p.textContent = pct+'%';
                    const l = $(inst.label); if(l) l.textContent = job.current_tool || 'Processing';
                });

            if(typeof updateScanPhase === 'function') updateScanPhase(pct);
            updateTimer();
            if(typeof updateScanPopupProgress === 'function') updateScanPopupProgress(pct, job.current_tool);

            if(job.status === 'completed'){
                clearInterval(window.scanPollInterval);
                if(typeof forEachScanUi === 'function')
                    forEachScanUi(inst => {
                        const c = $(inst.card);
                        if(c){ c.classList.remove('is-active','is-failed'); c.classList.add('is-complete'); }
                        const f = $(inst.fill); if(f) f.style.width = '100%';
                        const p = $(inst.pct);  if(p) p.textContent = '100%';
                        const l = $(inst.label); if(l) l.textContent = `Scan complete — ${target}`;
                        const w = $(inst.phaseWrap);
                        if(w) w.innerHTML = '<i class="fas fa-check-circle" style="color:var(--green);"></i> <span style="color:var(--green);">Scan completed successfully</span>';
                    });
                if(typeof updateScanStepper === 'function') updateScanStepper(100);
                if(typeof renderResults === 'function') renderResults(job.results);
                resetBtns();
                if(typeof getStoragePref === 'function' && getStoragePref() === 'local'
                   && typeof addLocalHistoryEntry === 'function'){
                    addLocalHistoryEntry({ id: Date.now(), target, mode: modeUsed||'basic',
                        status:'completed', created_at: new Date().toISOString(), result: job.results });
                }
                if(typeof refreshOverview === 'function') refreshOverview();
                if(typeof showToast === 'function') showToast(`Scan completed for ${target}`);
                if(typeof clearPersistedScan === 'function') clearPersistedScan();
                if(typeof finishScanPopup === 'function') finishScanPopup(true, target);
                if(typeof maybeAutoOpenConsole === 'function') maybeAutoOpenConsole();
            }
            if(job.status === 'failed'){
                clearInterval(window.scanPollInterval);
                if(typeof forEachScanUi === 'function')
                    forEachScanUi(inst => {
                        const c = $(inst.card);
                        if(c){ c.classList.remove('is-active','is-complete'); c.classList.add('is-failed'); }
                        const l = $(inst.label); if(l) l.textContent = `Failed — ${job.error||'unknown error'}`;
                        const w = $(inst.phaseWrap);
                        if(w) w.innerHTML = '<i class="fas fa-times-circle" style="color:var(--red-500);"></i> <span style="color:var(--red-500);">Scan failed</span>';
                    });
                resetBtns();
                if(typeof showToast === 'function') showToast(`Scan failed: ${job.error||'unknown'}`,'error');
                if(typeof clearPersistedScan === 'function') clearPersistedScan();
                if(typeof finishScanPopup === 'function') finishScanPopup(false, target, job.error);
            }
        }catch(e){ clearInterval(window.scanPollInterval); }
    }, 800);
};

/* ─── FIX 2 : Network Traffic — single consolidated version ─── */
(function(){
    const LEN = 24;
    const outHist = new Array(LEN).fill(0);
    const inHist  = new Array(LEN).fill(0);
    let inHasData = false;

    function buildPaths(hist, W, H){
        const max = Math.max(1, ...hist);
        const step = W / (hist.length - 1);
        const pts = hist.map((v,i) => ({ x: i*step, y: H - 2 - (v/max)*(H-6) }));
        const line = pts.map((p,i) => `${i===0?'M':'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
        return { line, area: `${line} L${W},${H} L0,${H} Z`, pts };
    }
    function wireHover(el, unit){
        if(el.dataset.hoverWired) return;
        el.dataset.hoverWired = '1';
        const tip = document.createElement('div');
        tip.className = 'nt-tooltip'; tip.hidden = true;
        el.appendChild(tip);
        el.addEventListener('mouseover', e => {
            const hp = e.target.closest('.nt-hp'); if(!hp) return;
            tip.innerHTML = `<span class="ntt-v">${hp.dataset.v} ${unit}</span><span class="ntt-t">${hp.dataset.t||''}</span>`;
            tip.style.left = hp.style.left;
            tip.style.top  = hp.style.top;
            tip.hidden = false;
        });
        el.addEventListener('mouseout', e => { if(e.target.closest('.nt-hp')) tip.hidden = true; });
    }
    function render(id, hist, hasData, unit){
        const el = $(id); if(!el) return;
        wireHover(el, unit);
        const tip = el.querySelector('.nt-tooltip');
        if(!hasData){
            el.innerHTML = '<div class="nt-empty">Waiting for data…</div>';
            if(tip) el.appendChild(tip);
            return;
        }
        const W = 240, H = 44;
        const { line, area, pts } = buildPaths(hist, W, H);
        const hotspots = pts.map((p,i) => {
            const lp = (p.x/W)*100, tp = (p.y/H)*100;
            return `<span class="nt-hp" style="left:${lp.toFixed(2)}%;top:${tp.toFixed(2)}%" data-v="${hist[i]}"></span>`;
        }).join('');
        const last = pts[pts.length-1];
        el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
            <line class="nt-grid-line" x1="0" y1="${H-1}" x2="${W}" y2="${H-1}"></line>
            <path class="nt-area" d="${area}"></path>
            <path class="nt-line" d="${line}"></path>
            <circle class="nt-dot" cx="${last.x.toFixed(1)}" cy="${last.y.toFixed(1)}"></circle>
        </svg><div class="nt-hoverlayer">${hotspots}</div>`;
        if(tip) el.appendChild(tip);
    }

    window.refreshNetworkTraffic = async function(){
        const now = Date.now(), WINDOW = 60000, bucket = WINDOW/LEN;
        const buckets = new Array(LEN).fill(0);
        const log = window.outboundRequestLog || [];
        log.forEach(ts => {
            const age = now - ts;
            if(age < 0 || age > WINDOW) return;
            const i = Math.min(LEN-1, Math.floor(age/bucket));
            buckets[LEN-1-i]++;
        });
        for(let i=0;i<LEN;i++) outHist[i] = buckets[i];
        render('netOutboundSpark', outHist, true, 'req');

        const oV = $('netOutboundValue'); if(oV) oV.textContent = log.length;
        const oS = $('netOutboundSub');   if(oS) oS.textContent = `${log.length} req/min`;

        const iV = $('netInboundValue'); if(!iV) return;
        const iS = $('netInboundSub');
        try{
            const r = await fetch('/api/system/stats');
            const s = await r.json();
            const inb = s.network_in ?? s.inbound_requests ?? s.requests_in ?? s.inbound ?? null;
            if(inb !== null){
                iV.textContent = typeof inb === 'number' ? inb.toLocaleString() : String(inb);
                if(iS) iS.textContent = 'from server stats';
                inHasData = true;
                inHist.shift(); inHist.push(Number(inb)||0);
                render('netInboundSpark', inHist, true, 'req');
            }else{
                iV.textContent = '--';
                if(iS) iS.textContent = 'not reported by server';
                render('netInboundSpark', inHist, inHasData, 'req');
            }
        }catch(e){
            iV.textContent = '--';
            if(iS) iS.textContent = 'unavailable';
        }
    };
    setTimeout(() => { try{ window.refreshNetworkTraffic(); }catch(e){} }, 100);
    setInterval(() => {
        if($('section-overview')?.classList.contains('active')){
            try{ window.refreshNetworkTraffic(); }catch(e){}
        }
    }, 8000);
})();

/* ─── FIX 3 : Section-change accepts 'assets' OR 'history' ─── */
window.addEventListener('section-change', function(e){
    const sec = e.detail;
    if(sec === 'assets' || sec === 'history'){
        const inp = $('historySearch');
        if(typeof loadAssets === 'function') loadAssets(inp ? inp.value : '');
    }
});

/* ─── FIX 4 : Null-safe loadAssets ─────────────────────────── */
window.loadAssets = async function(filter){
    const grid = $('assetCardsGrid'); if(!grid) return;
    grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1"><i class="fas fa-spinner spin"></i> Loading scans…</div>';
    try{
        let data;
        if(window.getStoragePref && getStoragePref() === 'local') data = getLocalHistory();
        else { const r = await fetch('/api/history'); data = await r.json(); }
        window.allHistory = data;
        if(typeof renderAssets === 'function') renderAssets(data, filter || '');
    }catch(e){
        grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1">Could not load scan history.</div>';
    }
};

/* ─── FIX 5 : Null-safe renderCustomQmItems ────────────────── */
window.renderCustomQmItems = function(){
    const radial = $('qmRadial'); if(!radial) return;
    radial.querySelectorAll('.qm-custom-item').forEach(el => el.remove());
    const links = (typeof getCustomLinks === 'function') ? getCustomLinks() : [];
    const addBtn = radial.querySelector('.qm-add-item');
    links.forEach((link, i) => {
        const el = document.createElement('button');
        el.className = 'qm-item qm-custom-item';
        el.title = `${link.label} (long-press to remove)`;
        el.textContent = link.label.slice(0,2).toUpperCase();
        el.addEventListener('click', () => {
            if(typeof closeQuickMenuFromOutside === 'function') closeQuickMenuFromOutside();
            window.open(link.url, '_blank', 'noopener');
        });
        let t = null;
        el.addEventListener('pointerdown', () => { t = setTimeout(() => { if(typeof removeCustomLink === 'function') removeCustomLink(i); }, 650); });
        ['pointerup','pointerleave','pointercancel'].forEach(evt => el.addEventListener(evt, () => { if(t) clearTimeout(t); }));
        if(addBtn) radial.insertBefore(el, addBtn); else radial.appendChild(el);
    });
    radial.querySelectorAll('.qm-item').forEach((el, i) => el.style.setProperty('--i', i));
};

/* ─── FIX 6 : TDZ guard for currentApiKeyCount ─────────────── */
if(typeof window.currentApiKeyCount === 'undefined') window.currentApiKeyCount = 0;

/* ─── FIX 7 : Prevent double-binding of sidebar toggles ────── */
(function(){
    const sb = $('sidebar'), ov = $('sidebarOverlay'), cb = $('sidebarCloseBtn');
    if(!sb || !ov) return;
    sb.querySelectorAll('.nav-item[data-section]').forEach(b => {
        if(b.__mobileBound) return;
        b.__mobileBound = 1;
        b.addEventListener('click', () => {
            if(window.innerWidth <= 900){ sb.classList.remove('open','mobile-open'); ov.classList.remove('visible'); }
        });
    });
    if(cb && !cb.__bound){
        cb.__bound = 1;
        cb.addEventListener('click', () => { sb.classList.remove('open','mobile-open'); ov.classList.remove('visible'); });
    }
})();

/* ─── FIX 8 : Re-apply branding after DOM fully ready ──────── */
document.addEventListener('DOMContentLoaded', () => {
    try{ if(typeof applyLanguage === 'function') applyLanguage(); }catch(e){}
    try{ if(typeof initStorageChoice === 'function') initStorageChoice(); }catch(e){}
    try{ if(typeof renderTelegramSteps === 'function') renderTelegramSteps(); }catch(e){}
    try{ if(typeof renderRecentKeys === 'function') renderRecentKeys(); }catch(e){}
    try{
        const logo = typeof loadCustomLogo === 'function' ? loadCustomLogo() : null;
        if(logo && typeof applyCustomLogo === 'function') applyCustomLogo(logo);
    }catch(e){}
});

console.log('%c[Emergens] ✅ Bug-fix patch loaded successfully', 'color:#60a5fa;font-weight:bold;');
})();
