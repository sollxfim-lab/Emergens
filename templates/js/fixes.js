/* ═══════════════════════════════════════════════════════════════════════════
   EMERGENS — fixes.js v2.0.0
   ─────────────────────────────────────────────────────────────────────────
   Compatibility + repair patch that runs AFTER script.js, osint.js,
   mhddos.js, and exploit.js.

   Fixes in v2.0.0
     • Profile modal — rebind sidebar trigger + bottom nav, load user data,
       avatar, stats, session time, theme, storage
     • Prayer times — robust implementation with fallback cities, retries,
       segmented control, auto-refresh, next-prayer countdown
     • Tools Hub — every tool action button gets a working implementation:
         brat     · canvas-based offline renderer (no API needed)
         ipcheck  · ipwho.is  (public, CORS-friendly)
         wifi     · real browser NetworkInformation + Geolocation
         anime    · siputzx API with graceful fallback
         reels    · socialfetch.dev API with graceful fallback
         music    · siputzx Apple Music search with graceful fallback
         mctools  · MCPEDL search via siputzx
         downloader · TikTok / Pinterest via siputzx
     • Bottom-nav profile button → opens profile modal
     • Waktu Solat segmented control (MY / ID) works

   Load order in HTML:
     <script src="js/script.js" defer></script>
     <script src="js/osint.js"   defer></script>
     <script src="js/mhddos.js"  defer></script>
     <script src="js/exploit.js" defer></script>
     <script src="js/fixes.js"   defer></script>   ← THIS FILE
   ═══════════════════════════════════════════════════════════════════════════ */

(function () {
    'use strict';

    const LOG = '[fixes]';
    const log   = (...a) => console.log(LOG, ...a);
    const warn  = (...a) => console.warn(LOG, ...a);
    const err   = (...a) => console.error(LOG, ...a);

    const $  = (sel, root = document) => root.querySelector(sel);
    const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

    function onReady(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => setTimeout(fn, 0));
        } else {
            setTimeout(fn, 0);
        }
    }

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function fetchJSON(url, opts = {}, timeoutMs = 12000) {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), timeoutMs);
        return fetch(url, { ...opts, signal: ctrl.signal, credentials: 'same-origin' })
            .then(async (r) => {
                clearTimeout(t);
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
            .catch((e) => { clearTimeout(t); throw e; });
    }

    function toast(msg, type = 'success') {
        if (typeof window.showToast === 'function') {
            window.showToast(msg, type);
            return;
        }
        const c = document.getElementById('toastContainer');
        if (!c) { console.log(LOG, msg); return; }
        const d = document.createElement('div');
        d.className = 'toast ' + type;
        d.innerHTML = '<i class="fas fa-info-circle"></i><span></span>';
        d.querySelector('span').textContent = msg;
        c.appendChild(d);
        setTimeout(() => { d.classList.add('leaving'); setTimeout(() => d.remove(), 250); }, 3000);
    }

    /* ═══════════════════════════════════════════════════════════════════
     * 1. PROFILE MODAL — open + fill data
     * ═══════════════════════════════════════════════════════════════════ */
    function fixProfileModal() {
        const overlay = document.getElementById('profileModalOverlay');
        if (!overlay) { warn('profileModalOverlay missing'); return; }

        // Some browsers block events when parent has pointer-events:none
        overlay.style.pointerEvents = 'auto';

        async function fillProfile() {
            // Sidebar username as base
            const sidebarUser = (document.getElementById('sidebarUsername')?.textContent || '--').trim();
            const sidebarRole = (document.getElementById('sidebarRole')?.textContent || '--').trim();
            const initial = (sidebarUser && sidebarUser !== '--')
                ? sidebarUser.charAt(0).toUpperCase()
                : '?';

            // Try /api/me for freshest data
            let me = null;
            try {
                const r = await fetch('/api/me', { credentials: 'same-origin' });
                if (r.ok) me = await r.json();
            } catch (_) { /* silent */ }

            const username = (me?.username) || (sidebarUser !== '--' ? sidebarUser : '--');
            const role = (me?.role) || (sidebarRole !== '--' ? sidebarRole : '--');

            // Name + role
            const nameEl = document.getElementById('profileModalName');
            if (nameEl) nameEl.textContent = username;
            const roleEl = document.getElementById('profileModalRole');
            if (roleEl) roleEl.innerHTML = '<i class="fas fa-shield-halved"></i> ' + escapeHtml(role);

            // Avatar (image if set, else initial)
            const core = document.getElementById('profileAvatarInitial');
            if (core) {
                const avatarUrl = me?.avatar_url || null;
                if (avatarUrl) {
                    core.innerHTML = '<img src="' + escapeHtml(avatarUrl) + '" alt="">';
                } else {
                    core.textContent = initial;
                }
            }

            // Stats: try to gather
            const scanEl = document.getElementById('profileStatScans');
            const keysEl = document.getElementById('profileStatKeys');
            const chatsEl = document.getElementById('profileStatChats');

            const totalScansEl = document.getElementById('totalScansCount');
            if (scanEl) scanEl.textContent = totalScansEl?.textContent?.trim() || '0';

            try {
                const k = await fetchJSON('/api/settings/api-keys');
                const arr = Array.isArray(k) ? k : (k.keys || []);
                if (keysEl) keysEl.textContent = String(arr.length);
            } catch (_) { if (keysEl) keysEl.textContent = '0'; }

            if (chatsEl) chatsEl.textContent =
                document.getElementById('telegramChatCount')?.textContent || '0';

            // Session time (once, cached)
            const timeEl = document.getElementById('profileSessionTime');
            if (timeEl && !timeEl.dataset.filled) {
                timeEl.textContent = new Date().toLocaleTimeString();
                timeEl.dataset.filled = '1';
            }

            // Theme + storage
            const themeEl = document.getElementById('profileThemeValue');
            if (themeEl) {
                themeEl.textContent =
                    document.documentElement.getAttribute('data-theme') === 'light'
                        ? 'Light' : 'Dark';
            }
            const storageEl = document.getElementById('profileStorageValue');
            if (storageEl) {
                const pref = localStorage.getItem('emergens-storage-pref') || 'server';
                storageEl.textContent = pref === 'local' ? 'Local' : 'Server';
            }
        }

        function openProfile() {
            fillProfile();
            overlay.hidden = false;
            overlay.style.display = 'flex';
        }

        function closeProfile() {
            overlay.hidden = true;
            overlay.style.display = '';
        }

        // Rebind sidebar trigger
        const sidebar = document.getElementById('sidebarProfileTrigger');
        if (sidebar) {
            const fresh = sidebar.cloneNode(true);
            sidebar.parentNode.replaceChild(fresh, sidebar);
            fresh.addEventListener('click', openProfile);
            fresh.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openProfile(); }
            });
        }

        // Bottom-nav profile button
        const bnProfile = document.getElementById('bottomNavProfileBtn');
        if (bnProfile) {
            const fresh = bnProfile.cloneNode(true);
            bnProfile.parentNode.replaceChild(fresh, bnProfile);
            fresh.addEventListener('click', openProfile);
        }

        // Close buttons
        const close = document.getElementById('profileModalClose');
        if (close) {
            const fresh = close.cloneNode(true);
            close.parentNode.replaceChild(fresh, close);
            fresh.addEventListener('click', closeProfile);
        }

        // Backdrop
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) closeProfile();
        });

        // Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && !overlay.hidden) closeProfile();
        });

        // Signout
        const signout = document.getElementById('profileSignoutBtn');
        if (signout) {
            const fresh = signout.cloneNode(true);
            signout.parentNode.replaceChild(fresh, signout);
            fresh.addEventListener('click', () => {
                const logout = document.getElementById('logoutBtn');
                if (logout) logout.click();
                else window.location.href = '/login.html';
            });
        }

        log('Profile modal rebound');
    }

    /* ═══════════════════════════════════════════════════════════════════
     * 2. WAKTU SOLAT — robust
     * ═══════════════════════════════════════════════════════════════════ */
    function fixPrayerTimes() {
        const grid = document.getElementById('prayerTimesGrid');
        const citySel = document.getElementById('prayerCitySelect');
        const refreshBtn = document.getElementById('prayerRefreshBtn');
        const countryToggle = document.getElementById('prayerCountryToggle');
        const nextBanner = document.getElementById('prayerNextBanner');
        if (!grid) { warn('prayerTimesGrid missing'); return; }

        const PRAYER_CONFIG = {
            MY: {
                method: 17,               // JAKIM
                countryName: 'Malaysia',
                cities: ['Kuala Lumpur', 'Johor Bahru', 'George Town', 'Ipoh',
                          'Shah Alam', 'Kuching', 'Kota Kinabalu', 'Malacca City',
                          'Seremban', 'Kuantan', 'Alor Setar', 'Kota Bharu'],
            },
            ID: {
                method: 20,               // Kemenag
                countryName: 'Indonesia',
                cities: ['Jakarta', 'Surabaya', 'Bandung', 'Medan', 'Semarang',
                          'Makassar', 'Yogyakarta', 'Denpasar', 'Palembang',
                          'Balikpapan', 'Pontianak', 'Manado'],
            },
        };

        let currentCountry = 'MY';
        let lastFetchAt = 0;
        const CACHE_MS = 5 * 60 * 1000;

        function populateCities() {
            if (!citySel) return;
            const cfg = PRAYER_CONFIG[currentCountry];
            citySel.innerHTML = cfg.cities
                .map((c) => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`)
                .join('');
        }

        function renderLoading() {
            grid.innerHTML =
                '<div class="empty-state"><i class="fas fa-spinner spin"></i>' +
                ' <span>Loading times…</span></div>';
        }

        function renderError(msg) {
            grid.innerHTML =
                '<div class="prayer-error" style="grid-column:1/-1;text-align:center;' +
                'padding:18px;color:var(--text-muted);font-size:.82rem;">' +
                '<i class="fas fa-cloud-off" style="margin-right:6px;"></i>' +
                escapeHtml(msg) +
                '</div>';
            if (nextBanner) nextBanner.hidden = true;
        }

        function fmtTime(raw) {
            if (!raw) return '--';
            return String(raw).split(' ')[0];
        }

        function renderTimes(timings) {
            const order = ['Fajr', 'Dhuhr', 'Asr', 'Maghrib', 'Isha'];
            const now = new Date();
            const parsed = order.map((label) => {
                const raw = fmtTime(timings[label] || timings[label.toLowerCase()]);
                const [h, m] = raw.split(':').map(Number);
                const dt = new Date(now);
                dt.setHours(h || 0, m || 0, 0, 0);
                return { label, time: raw, dt };
            });

            const next = parsed.find((p) => p.dt.getTime() > now.getTime());

            grid.innerHTML = parsed.map((p) => `
                <div class="prayer-time-item ${next && p.label === next.label ? 'is-next' : ''}">
                    <div class="pt-name">${escapeHtml(p.label)}</div>
                    <div class="pt-time">${escapeHtml(p.time)}</div>
                </div>
            `).join('');

            if (next && nextBanner) {
                const mins = Math.max(0, Math.round((next.dt.getTime() - now.getTime()) / 60000));
                const hh = Math.floor(mins / 60);
                const mm = mins % 60;
                nextBanner.hidden = false;
                nextBanner.innerHTML =
                    '<i class="fas fa-mosque"></i> <span>' +
                    '<strong>' + escapeHtml(next.label) + '</strong> in ' +
                    (hh > 0 ? hh + 'h ' : '') + mm + 'm' +
                    '</span>';
            } else if (nextBanner) {
                nextBanner.hidden = true;
            }
        }

        async function loadTimes(force = false) {
            const cfg = PRAYER_CONFIG[currentCountry];
            const city = citySel?.value || cfg.cities[0];
            const now = Date.now();
            if (!force && now - lastFetchAt < CACHE_MS) return;

            renderLoading();

            const url = 'https://api.aladhan.com/v1/timingsByCity'
                + '?city=' + encodeURIComponent(city)
                + '&country=' + encodeURIComponent(cfg.countryName)
                + '&method=' + cfg.method;

            // Try with 2 attempts
            for (let attempt = 0; attempt < 2; attempt++) {
                try {
                    const ctrl = new AbortController();
                    const timeout = setTimeout(() => ctrl.abort(), 10000);
                    const r = await fetch(url, { signal: ctrl.signal });
                    clearTimeout(timeout);
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    const d = await r.json();
                    if (!d?.data?.timings) throw new Error('no timing data');
                    lastFetchAt = Date.now();
                    renderTimes(d.data.timings);
                    return;
                } catch (e) {
                    warn('Prayer fetch attempt ' + (attempt + 1) + ' failed:', e.message);
                    if (attempt === 0) await new Promise((r) => setTimeout(r, 1200));
                }
            }
            renderError('Could not load prayer times. Check your connection.');
        }

        // Populate cities immediately
        populateCities();

        // Rebind refresh button
        if (refreshBtn) {
            const fresh = refreshBtn.cloneNode(true);
            refreshBtn.parentNode.replaceChild(fresh, refreshBtn);
            fresh.addEventListener('click', () => {
                lastFetchAt = 0;
                loadTimes(true);
            });
        }

        // Rebind city select
        if (citySel) {
            const fresh = citySel.cloneNode(true);
            citySel.parentNode.replaceChild(fresh, citySel);
            fresh.addEventListener('change', () => {
                lastFetchAt = 0;
                loadTimes(true);
            });
        }

        // Rebind segmented control (Malaysia / Indonesia)
        if (countryToggle) {
            const fresh = countryToggle.cloneNode(true);
            countryToggle.parentNode.replaceChild(fresh, countryToggle);
            $$('.seg-btn', fresh).forEach((btn) => {
                btn.addEventListener('click', () => {
                    $$('.seg-btn', fresh).forEach((b) => b.classList.remove('active'));
                    btn.classList.add('active');
                    currentCountry = btn.dataset.country || 'MY';
                    populateCities();
                    lastFetchAt = 0;
                    loadTimes(true);
                });
            });
        }

        // Initial load
        loadTimes(true);

        // Auto-refresh every 5 min when Overview tab is active
        setInterval(() => {
            const section = document.getElementById('section-overview');
            if (section && section.classList.contains('active')) {
                loadTimes(false);
            }
        }, 60 * 1000);

        log('Prayer times rebound');
    }

    /* ═══════════════════════════════════════════════════════════════════
     * 3. TOOLS HUB — rebind all tool action buttons with working impls
     * ═══════════════════════════════════════════════════════════════════ */
    function fixToolsHubActions() {
        const modal = document.getElementById('toolsHubModal');
        if (!modal) { warn('toolsHubModal missing'); return; }

        // ─────────────────────────────────────────────────────────────
        // BRAT — canvas offline renderer
        // ─────────────────────────────────────────────────────────────
        function renderBratCanvas(text, bg) {
            const canvas = document.createElement('canvas');
            const SIZE = 640;
            canvas.width = SIZE; canvas.height = SIZE;
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = bg;
            ctx.fillRect(0, 0, SIZE, SIZE);

            const hex = bg.replace('#', '');
            const rr = parseInt(hex.substring(0, 2), 16);
            const gg = parseInt(hex.substring(2, 4), 16);
            const bb = parseInt(hex.substring(4, 6), 16);
            const lum = (0.299 * rr + 0.587 * gg + 0.114 * bb) / 255;
            ctx.fillStyle = lum > 0.6 ? '#111' : '#f5f5f5';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.filter = 'blur(1.1px)';

            const words = (text || 'brat').toLowerCase().split(/\s+/).filter(Boolean);
            let fontSize = Math.max(34, 92 - words.join(' ').length * 1.4);
            ctx.font = '700 ' + fontSize + 'px Helvetica Neue, Arial, sans-serif';
            const maxW = SIZE * 0.86;
            const lines = [];
            let cur = '';
            words.forEach((w) => {
                const test = cur ? cur + ' ' + w : w;
                if (ctx.measureText(test).width > maxW && cur) {
                    lines.push(cur); cur = w;
                } else { cur = test; }
            });
            if (cur) lines.push(cur);

            const lineH = fontSize * 0.98;
            let y = SIZE / 2 - (lineH * lines.length) / 2 + lineH / 2;
            lines.forEach((line) => { ctx.fillText(line, SIZE / 2, y); y += lineH; });
            ctx.filter = 'none';
            return canvas.toDataURL('image/png');
        }

        function bindBrat() {
            const btn = document.getElementById('bratGenerateBtn');
            const input = document.getElementById('bratTextInput');
            const colorInput = document.getElementById('bratBgColor');
            const area = document.getElementById('bratResultArea');
            if (!btn || !input || !area) return;

            const fresh = btn.cloneNode(true);
            btn.parentNode.replaceChild(fresh, btn);
            fresh.addEventListener('click', () => {
                const text = input.value.trim() || 'brat';
                const bg = (colorInput?.value) || '#8ace00';
                try {
                    const url = renderBratCanvas(text, bg);
                    area.innerHTML =
                        '<img src="' + url + '" class="tr-media-preview" alt="Brat cover">' +
                        '<a class="btn-secondary tr-download-btn" href="' + url +
                        '" download="brat.png"><i class="fas fa-download"></i> Download</a>';
                } catch (e) {
                    area.innerHTML = '<div class="tr-error">Render failed: ' +
                        escapeHtml(e.message) + '</div>';
                }
            });
        }

        // ─────────────────────────────────────────────────────────────
        // IP CHECK — ipwho.is (public, CORS-friendly)
        // ─────────────────────────────────────────────────────────────
        function bindIpCheck() {
            const btn = document.getElementById('ipCheckBtn');
            const mineBtn = document.getElementById('ipCheckMineBtn');
            const input = document.getElementById('ipCheckInput');
            const area = document.getElementById('ipCheckResultArea');
            if (!btn || !area) return;

            async function lookup(query) {
                area.innerHTML = '<div class="tr-loading"><i class="fas fa-spinner spin"></i> Looking up…</div>';
                try {
                    const r = await fetch('https://ipwho.is/' + encodeURIComponent(query));
                    const d = await r.json();
                    if (d.success === false) {
                        area.innerHTML = '<div class="tr-error"><i class="fas fa-circle-exclamation"></i> ' +
                            escapeHtml(d.message || 'Lookup failed') + '</div>';
                        return;
                    }
                    area.innerHTML = `
                        <div class="tr-card">
                            <div class="tr-row"><span class="tr-k">IP</span><span class="tr-v">${escapeHtml(d.ip || query)}</span></div>
                            <div class="tr-row"><span class="tr-k">Country</span><span class="tr-v">${escapeHtml(d.country || '--')} ${d.country_code ? '(' + escapeHtml(d.country_code) + ')' : ''}</span></div>
                            <div class="tr-row"><span class="tr-k">Region</span><span class="tr-v">${escapeHtml(d.region || '--')}</span></div>
                            <div class="tr-row"><span class="tr-k">City</span><span class="tr-v">${escapeHtml(d.city || '--')}</span></div>
                            <div class="tr-row"><span class="tr-k">ISP</span><span class="tr-v">${escapeHtml(d.connection?.isp || d.connection?.org || '--')}</span></div>
                            <div class="tr-row"><span class="tr-k">ASN</span><span class="tr-v">${escapeHtml(String(d.connection?.asn ?? '--'))}</span></div>
                            <div class="tr-row"><span class="tr-k">Timezone</span><span class="tr-v">${escapeHtml(d.timezone?.id || '--')}</span></div>
                        </div>`;
                } catch (e) {
                    area.innerHTML = '<div class="tr-error"><i class="fas fa-circle-exclamation"></i> ' +
                        escapeHtml(e.message) + '</div>';
                }
            }

            const fresh = btn.cloneNode(true);
            btn.parentNode.replaceChild(fresh, btn);
            fresh.addEventListener('click', () => {
                const q = input.value.trim();
                if (!q) { toast('Enter an IP or domain first', 'error'); return; }
                lookup(q);
            });

            if (mineBtn) {
                const fm = mineBtn.cloneNode(true);
                mineBtn.parentNode.replaceChild(fm, mineBtn);
                fm.addEventListener('click', async () => {
                    area.innerHTML = '<div class="tr-loading"><i class="fas fa-spinner spin"></i> Detecting…</div>';
                    try {
                        const r = await fetch('https://api.ipify.org?format=json');
                        const d = await r.json();
                        input.value = d.ip;
                        lookup(d.ip);
                    } catch (e) {
                        area.innerHTML = '<div class="tr-error">Could not detect IP</div>';
                    }
                });
            }
        }

        // ─────────────────────────────────────────────────────────────
        // WIFI — browser network info (honest implementation)
        // ─────────────────────────────────────────────────────────────
        function bindWifi() {
            const btn = document.getElementById('wifiRequestBtn');
            const area = document.getElementById('wifiResultArea');
            if (!btn || !area) return;

            const fresh = btn.cloneNode(true);
            btn.parentNode.replaceChild(fresh, btn);
            fresh.addEventListener('click', async () => {
                fresh.disabled = true;
                fresh.innerHTML = '<i class="fas fa-spinner spin"></i> Checking…';
                let html = '';

                const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
                if (conn) {
                    html += '<div class="tr-card">' +
                        '<div class="tr-row"><span class="tr-k">Type</span><span class="tr-v">' +
                        escapeHtml(conn.type || conn.effectiveType || 'unknown') + '</span></div>' +
                        (conn.downlink !== undefined ? '<div class="tr-row"><span class="tr-k">Downlink</span><span class="tr-v">' + conn.downlink + ' Mb/s</span></div>' : '') +
                        (conn.rtt !== undefined ? '<div class="tr-row"><span class="tr-k">RTT</span><span class="tr-v">' + conn.rtt + ' ms</span></div>' : '') +
                        '<div class="tr-row"><span class="tr-k">Online</span><span class="tr-v">' + (navigator.onLine ? 'Yes' : 'No') + '</span></div>' +
                        '</div>';
                } else {
                    html += '<div class="tr-card"><div class="tr-row"><span class="tr-k">Online</span>' +
                        '<span class="tr-v">' + (navigator.onLine ? 'Yes' : 'No') + '</span></div>' +
                        '<div class="tr-row"><span class="tr-k">Connection details</span><span class="tr-v">Not exposed</span></div></div>';
                }

                if (navigator.geolocation) {
                    try {
                        const pos = await new Promise((res, rej) => navigator.geolocation.getCurrentPosition(res, rej, { timeout: 8000 }));
                        html += '<div class="tr-card">' +
                            '<div class="tr-row"><span class="tr-k">Latitude</span><span class="tr-v">' + pos.coords.latitude.toFixed(5) + '</span></div>' +
                            '<div class="tr-row"><span class="tr-k">Longitude</span><span class="tr-v">' + pos.coords.longitude.toFixed(5) + '</span></div>' +
                            '<div class="tr-row"><span class="tr-k">Accuracy</span><span class="tr-v">±' + Math.round(pos.coords.accuracy) + ' m</span></div>' +
                            '</div>';
                    } catch (geoErr) {
                        html += '<div class="tr-card"><div class="tr-row"><span class="tr-k">Location</span>' +
                            '<span class="tr-v">' + (geoErr.code === 1 ? 'Permission denied' : 'Unavailable') + '</span></div></div>';
                    }
                }

                area.innerHTML = html;
                fresh.disabled = false;
                fresh.innerHTML = '<i class="fas fa-wifi"></i> Check Network Info';
            });
        }

        // ─────────────────────────────────────────────────────────────
        // GENERIC — siputzx API helpers
        // ─────────────────────────────────────────────────────────────
        async function siputzx(path, params = {}) {
            const qs = Object.entries(params)
                .map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v))
                .join('&');
            const url = 'https://api.siputzx.my.id' + path + (qs ? '?' + qs : '');
            const ctrl = new AbortController();
            const to = setTimeout(() => ctrl.abort(), 15000);
            try {
                const r = await fetch(url, { signal: ctrl.signal });
                clearTimeout(to);
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            } catch (e) { clearTimeout(to); throw e; }
        }

        // ─────────────────────────────────────────────────────────────
        // ANIME
        // ─────────────────────────────────────────────────────────────
        function bindAnime() {
            const btn = document.getElementById('animeSearchBtn');
            const input = document.getElementById('animeSearchInput');
            const area = document.getElementById('animeResultArea');
            if (!btn || !area) return;

            const fresh = btn.cloneNode(true);
            btn.parentNode.replaceChild(fresh, btn);
            fresh.addEventListener('click', async () => {
                const q = input.value.trim();
                if (!q) { toast('Type something to search', 'error'); return; }
                fresh.disabled = true;
                fresh.innerHTML = '<i class="fas fa-spinner spin"></i>';
                area.innerHTML = '<div class="tr-loading"><i class="fas fa-spinner spin"></i> Searching…</div>';
                try {
                    const d = await siputzx('/api/s/otakotaku', { q });
                    const payload = d.data || d;
                    const anime = payload.anime || [];
                    if (!anime.length) {
                        area.innerHTML = '<div class="empty-state">No results</div>';
                    } else {
                        area.innerHTML = '<div class="anime-result-grid">' + anime.slice(0, 24).map((a) => `
                            <div class="anime-card">
                                <div class="anime-card-thumb">${a.imageUrl ? '<img src="' + escapeHtml(a.imageUrl) + '" loading="lazy" alt="">' : '<i class="fas fa-clapperboard"></i>'}</div>
                                <div class="anime-card-title">${escapeHtml(a.title || 'Untitled')}</div>
                            </div>`).join('') + '</div>';
                    }
                } catch (e) {
                    area.innerHTML = '<div class="tr-error"><i class="fas fa-circle-exclamation"></i> ' +
                        escapeHtml(e.message) + '</div>';
                } finally {
                    fresh.disabled = false;
                    fresh.innerHTML = '<i class="fas fa-search"></i> Search';
                }
            });
        }

        // ─────────────────────────────────────────────────────────────
        // REELS (TikTok search)
        // ─────────────────────────────────────────────────────────────
        function bindReels() {
            const btn = document.getElementById('reelsSearchBtn');
            const input = document.getElementById('reelsSearchInput');
            const area = document.getElementById('reelsResultArea');
            if (!btn || !area) return;

            const fresh = btn.cloneNode(true);
            btn.parentNode.replaceChild(fresh, btn);
            fresh.addEventListener('click', async () => {
                const q = input.value.trim();
                if (!q) { toast('Type something', 'error'); return; }
                fresh.disabled = true;
                fresh.innerHTML = '<i class="fas fa-spinner spin"></i>';
                area.innerHTML = '<div class="tr-loading"><i class="fas fa-spinner spin"></i> Searching TikTok…</div>';
                try {
                    const r = await fetch('https://api.socialfetch.dev/v1/tiktok/search?query=' + encodeURIComponent(q));
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    const d = await r.json();
                    const list = d.data || d.results || d.videos || [];
                    if (!list.length) {
                        area.innerHTML = '<div class="empty-state">No videos found</div>';
                    } else {
                        area.innerHTML = '<div class="reels-grid">' + list.slice(0, 12).map((v) => {
                            const cover = v.cover || v.thumbnail || (v.video && v.video.cover) || '';
                            const link = v.share_url || v.link || '';
                            const desc = v.desc || v.title || '';
                            return '<div class="reel-card">' +
                                '<div class="reel-card-media">' +
                                (cover ? '<img src="' + escapeHtml(cover) + '" loading="lazy" alt="">' : '<i class="fas fa-film"></i>') +
                                '</div><div class="reel-card-body">' +
                                '<div class="reel-card-desc">' + escapeHtml(desc) + '</div>' +
                                (link ? '<a class="reel-card-open" href="' + escapeHtml(link) + '" target="_blank" rel="noopener">Open</a>' : '') +
                                '</div></div>';
                        }).join('') + '</div>';
                    }
                } catch (e) {
                    area.innerHTML = '<div class="tr-error"><i class="fas fa-circle-exclamation"></i> ' +
                        escapeHtml(e.message) + '</div>';
                } finally {
                    fresh.disabled = false;
                    fresh.innerHTML = '<i class="fas fa-search"></i> Search';
                }
            });
        }

        // ─────────────────────────────────────────────────────────────
        // MUSIC
        // ─────────────────────────────────────────────────────────────
        function bindMusic() {
            const btn = document.getElementById('musicFetchBtn');
            const input = document.getElementById('musicQueryInput');
            const area = document.getElementById('musicResultArea');
            if (!btn || !area) return;

            const fresh = btn.cloneNode(true);
            btn.parentNode.replaceChild(fresh, btn);
            fresh.addEventListener('click', async () => {
                const q = input.value.trim();
                if (!q) { toast('Enter a song name', 'error'); return; }
                fresh.disabled = true;
                fresh.innerHTML = '<i class="fas fa-spinner spin"></i>';
                area.innerHTML = '<div class="tr-loading"><i class="fas fa-spinner spin"></i> Searching…</div>';
                try {
                    const d = await siputzx('/api/s/applemusic', { q });
                    const items = (d.data || []).slice(0, 20);
                    if (!items.length) {
                        area.innerHTML = '<div class="empty-state">No results</div>';
                    } else {
                        area.innerHTML = '<div class="music-search-grid">' + items.map((it) => `
                            <a class="music-card" href="${escapeHtml(it.link || '#')}" target="_blank" rel="noopener">
                                <div class="music-card-art">${it.image ? '<img src="' + escapeHtml(it.image) + '" loading="lazy" alt="">' : '<i class="fas fa-music"></i>'}</div>
                                <div class="music-card-body">
                                    <div class="music-card-title">${escapeHtml(it.title || 'Untitled')}</div>
                                    <div class="music-card-artist">${escapeHtml((it.artist || '').replace(/Lyrics:.*/is, '').trim())}</div>
                                </div>
                            </a>`).join('') + '</div>';
                    }
                } catch (e) {
                    area.innerHTML = '<div class="tr-error"><i class="fas fa-circle-exclamation"></i> ' +
                        escapeHtml(e.message) + '</div>';
                } finally {
                    fresh.disabled = false;
                    fresh.innerHTML = '<i class="fas fa-search"></i> Search';
                }
            });
        }

        // ─────────────────────────────────────────────────────────────
        // DOWNLOADER (TikTok / Pinterest)
        // ─────────────────────────────────────────────────────────────
        function bindDownloader() {
            const platformToggle = document.getElementById('dlPlatformToggle');
            const btn = document.getElementById('dlFetchBtn');
            const input = document.getElementById('dlUrlInput');
            const area = document.getElementById('dlResultArea');
            if (!btn || !area) return;

            let platform = 'tiktok';
            if (platformToggle) {
                $$('.seg-btn', platformToggle).forEach((b) => {
                    b.addEventListener('click', () => {
                        $$('.seg-btn', platformToggle).forEach((x) => x.classList.remove('active'));
                        b.classList.add('active');
                        platform = b.dataset.platform || 'tiktok';
                        input.value = '';
                        input.placeholder = platform === 'pinterest'
                            ? 'Search Pinterest…'
                            : 'https://www.tiktok.com/@user/video/…';
                        area.innerHTML = '';
                    });
                });
            }

            const fresh = btn.cloneNode(true);
            btn.parentNode.replaceChild(fresh, btn);
            fresh.addEventListener('click', async () => {
                const v = input.value.trim();
                if (!v) { toast('Enter a value', 'error'); return; }
                fresh.disabled = true;
                fresh.innerHTML = '<i class="fas fa-spinner spin"></i>';
                area.innerHTML = '<div class="tr-loading"><i class="fas fa-spinner spin"></i> Working…</div>';
                try {
                    if (platform === 'tiktok') {
                        const d = await siputzx('/api/d/tiktok/v2', { url: v });
                        if (!d.data) throw new Error('No media returned');
                        const t = d.data;
                        const src = t.no_watermark_link_hd || t.no_watermark_link || t.watermark_link;
                        area.innerHTML = '<div class="tr-card">' +
                            (src ? '<video class="tr-media-preview" src="' + escapeHtml(src) + '" controls></video>' : '') +
                            '<div class="tr-row"><span class="tr-k">Author</span><span class="tr-v">' + escapeHtml(t.author_nickname || '--') + '</span></div>' +
                            '</div>';
                    } else {
                        const d = await siputzx('/api/s/pinterest', { q: v });
                        const raw = Array.isArray(d) ? d : (d.data || d.results || []);
                        if (!raw.length) throw new Error('No results');
                        area.innerHTML = '<div class="pin-grid">' + raw.slice(0, 24).map((it) => {
                            const img = typeof it === 'string' ? it : (it.image_url || it.image || it.url || '');
                            return '<a class="pin-card" href="' + escapeHtml(img) + '" target="_blank" rel="noopener"><img src="' + escapeHtml(img) + '" loading="lazy" alt=""></a>';
                        }).join('') + '</div>';
                    }
                } catch (e) {
                    area.innerHTML = '<div class="tr-error"><i class="fas fa-circle-exclamation"></i> ' +
                        escapeHtml(e.message) + '</div>';
                } finally {
                    fresh.disabled = false;
                    fresh.innerHTML = '<i class="fas fa-download"></i> Fetch';
                }
            });
        }

        // ─────────────────────────────────────────────────────────────
        // MCTOOLS
        // ─────────────────────────────────────────────────────────────
        function bindMcTools() {
            const btn = document.getElementById('mcSearchBtn');
            const input = document.getElementById('mcSearchInput');
            const area = document.getElementById('mcResultArea');
            if (!btn || !area) return;

            const fresh = btn.cloneNode(true);
            btn.parentNode.replaceChild(fresh, btn);
            fresh.addEventListener('click', async () => {
                const q = input.value.trim();
                if (!q) { toast('Type something', 'error'); return; }
                fresh.disabled = true;
                fresh.innerHTML = '<i class="fas fa-spinner spin"></i>';
                area.innerHTML = '<div class="mc-loading"><span class="mc-loading-text">Searching…</span></div>';
                try {
                    const d = await siputzx('/api/s/mcpedl', { q });
                    const items = d.data || [];
                    if (!items.length) {
                        area.innerHTML = '<div class="empty-state">No results</div>';
                    } else {
                        area.innerHTML = '<div class="mc-search-grid">' + items.slice(0, 20).map((it) => `
                            <a class="mc-card" href="${escapeHtml(it.link || '#')}" target="_blank" rel="noopener">
                                <div class="mc-card-thumb">${it.image ? '<img src="' + escapeHtml(it.image) + '" loading="lazy" alt="">' : '<i class="fas fa-cube"></i>'}</div>
                                <div class="mc-card-body">
                                    <div class="mc-card-title">${escapeHtml(it.title || 'Untitled')}</div>
                                </div>
                            </a>`).join('') + '</div>';
                    }
                } catch (e) {
                    area.innerHTML = '<div class="tr-error"><i class="fas fa-circle-exclamation"></i> ' +
                        escapeHtml(e.message) + '</div>';
                } finally {
                    fresh.disabled = false;
                    fresh.innerHTML = '<i class="fas fa-search"></i> Search';
                }
            });
        }

        // ─────────────────────────────────────────────────────────────
        // Bind everything
        // ─────────────────────────────────────────────────────────────
        try { bindBrat();       } catch (e) { warn('bindBrat failed:', e); }
        try { bindIpCheck();    } catch (e) { warn('bindIpCheck failed:', e); }
        try { bindWifi();       } catch (e) { warn('bindWifi failed:', e); }
        try { bindAnime();      } catch (e) { warn('bindAnime failed:', e); }
        try { bindReels();      } catch (e) { warn('bindReels failed:', e); }
        try { bindMusic();      } catch (e) { warn('bindMusic failed:', e); }
        try { bindDownloader(); } catch (e) { warn('bindDownloader failed:', e); }
        try { bindMcTools();    } catch (e) { warn('bindMcTools failed:', e); }

        log('Tools hub actions rebound');
    }

    /* ═══════════════════════════════════════════════════════════════════
     * 4. TOOLS HUB — nav trigger (existing patch)
     * ═══════════════════════════════════════════════════════════════════ */
    function fixToolsHubNav() {
        const oldBtn = document.getElementById('navToolsHub');
        const modal = document.getElementById('toolsHubModal');
        if (!oldBtn || !modal) { warn('navToolsHub or modal missing'); return; }

        const btn = oldBtn.cloneNode(true);
        oldBtn.parentNode.replaceChild(btn, oldBtn);
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const grid = document.getElementById('toolsGridView');
            if (grid) grid.hidden = false;
            $$('.tool-detail').forEach((d) => d.hidden = true);
            const backBtn = document.getElementById('toolsHubBackBtn');
            if (backBtn) backBtn.hidden = true;
            const title = document.getElementById('toolsHubHeaderTitle');
            if (title) title.innerHTML = '<i class="fas fa-grip" style="color:var(--red-400);margin-right:6px;"></i><span>Tools</span>';
            const card = modal.querySelector('.tools-hub-card');
            if (card) card.classList.remove('is-fullscreen');
            modal.hidden = false;
        });

        // Close
        const closeBtn = document.getElementById('closeToolsHubModal');
        if (closeBtn) {
            const fresh = closeBtn.cloneNode(true);
            closeBtn.parentNode.replaceChild(fresh, closeBtn);
            fresh.addEventListener('click', () => {
                modal.hidden = true;
                const card = modal.querySelector('.tools-hub-card');
                if (card) card.classList.remove('is-fullscreen');
            });
        }

        // Backdrop
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.hidden = true;
                const card = modal.querySelector('.tools-hub-card');
                if (card) card.classList.remove('is-fullscreen');
            }
        });

        // Tool box click → show detail
        $$('.tool-box[data-tool]').forEach((box) => {
            const fresh = box.cloneNode(true);
            box.parentNode.replaceChild(fresh, box);
            fresh.addEventListener('click', () => {
                const tool = fresh.dataset.tool;
                const grid = document.getElementById('toolsGridView');
                if (grid) grid.hidden = true;
                $$('.tool-detail').forEach((d) => d.hidden = (d.id !== 'toolDetail-' + tool));
                const backBtn = document.getElementById('toolsHubBackBtn');
                if (backBtn) backBtn.hidden = false;
                const titles = {
                    brat: 'Brat Generator', reels: 'Reels', osint: 'OSINT',
                    anime: 'Anime', wifi: 'Wifi Scanner', ipcheck: 'IP Check',
                    quickaccess: 'Quick Access', music: 'Music Downloader',
                    downloader: 'Downloader', mctools: 'MCTOOLS',
                };
                const title = document.getElementById('toolsHubHeaderTitle');
                if (title) title.textContent = titles[tool] || 'Tools';
                const card = modal.querySelector('.tools-hub-card');
                if (card) card.classList.add('is-fullscreen');
            });
        });

        // Back button
        const backBtn = document.getElementById('toolsHubBackBtn');
        if (backBtn) {
            const fresh = backBtn.cloneNode(true);
            backBtn.parentNode.replaceChild(fresh, backBtn);
            fresh.addEventListener('click', () => {
                const grid = document.getElementById('toolsGridView');
                if (grid) grid.hidden = false;
                $$('.tool-detail').forEach((d) => d.hidden = true);
                fresh.hidden = true;
                const title = document.getElementById('toolsHubHeaderTitle');
                if (title) title.innerHTML = '<i class="fas fa-grip" style="color:var(--red-400);margin-right:6px;"></i><span>Tools</span>';
                const card = modal.querySelector('.tools-hub-card');
                if (card) card.classList.remove('is-fullscreen');
            });
        }

        log('Tools hub nav rebound');
    }

    /* ═══════════════════════════════════════════════════════════════════
     * 5. BRIEFING (username + video)
     * ═══════════════════════════════════════════════════════════════════ */
    function fixBriefingUser() {
        const nameEl = document.getElementById('briefingUsername');
        const roleEl = document.getElementById('briefingRole');
        if (!nameEl) return;

        async function refresh() {
            try {
                const r = await fetch('/api/me', { credentials: 'same-origin' });
                if (r.ok) {
                    const d = await r.json();
                    if (d?.username) nameEl.textContent = d.username;
                    if (d?.role && roleEl) roleEl.innerHTML = '<i class="fas fa-shield-halved"></i> ' + escapeHtml(d.role);
                    return;
                }
            } catch (_) {}
            const sU = document.getElementById('sidebarUsername');
            const sR = document.getElementById('sidebarRole');
            if (sU?.textContent?.trim() && sU.textContent.trim() !== '--') nameEl.textContent = sU.textContent.trim();
            if (roleEl && sR?.textContent?.trim() && sR.textContent.trim() !== '--')
                roleEl.innerHTML = '<i class="fas fa-shield-halved"></i> ' + escapeHtml(sR.textContent.trim());
        }

        refresh();
        setTimeout(refresh, 500);
        setTimeout(refresh, 1500);
        window.addEventListener('section-change', (e) => {
            if (e.detail === 'testing') setTimeout(refresh, 100);
        });
    }

    function fixBriefingVideo() {
        const video = document.getElementById('briefingVideo');
        const placeholder = document.getElementById('briefingVideoPlaceholder');
        if (!video) return;

        const URL = 'https://cdn.pixabay.com/video/2023/03/28/156087-812319483_large.mp4';

        video.pause();
        video.removeAttribute('src');
        video.load();
        video.setAttribute('src', URL);
        video.muted = true;
        video.loop = true;
        video.autoplay = true;
        video.playsInline = true;
        video.preload = 'auto';
        video.hidden = false;
        if (placeholder) placeholder.hidden = true;

        function tryPlay() {
            const p = video.play();
            if (p && typeof p.catch === 'function') {
                p.catch(() => {
                    const kick = () => {
                        video.play().catch(() => {});
                        document.removeEventListener('click', kick);
                        document.removeEventListener('touchstart', kick);
                    };
                    document.addEventListener('click', kick, { once: true });
                    document.addEventListener('touchstart', kick, { once: true });
                });
            }
        }
        video.addEventListener('loadedmetadata', tryPlay, { once: true });
        video.addEventListener('canplay', tryPlay, { once: true });
        video.addEventListener('error', () => {
            video.hidden = true;
            if (placeholder) {
                placeholder.hidden = false;
                placeholder.innerHTML = '<i class="fas fa-video-slash"></i><span>Video unavailable</span>';
            }
        });
        tryPlay();
    }

    /* ═══════════════════════════════════════════════════════════════════
     * 6. QUICK MENU FAB
     * ═══════════════════════════════════════════════════════════════════ */
    function fixQuickMenu() {
        const fab = document.getElementById('quickMenuFab');
        const toggle = document.getElementById('qmToggle');
        if (!fab || !toggle) return;

        fab.style.display = 'block';
        fab.style.visibility = 'visible';
        fab.style.opacity = '1';
        fab.style.pointerEvents = 'auto';
        fab.style.zIndex = '150';

        const fresh = toggle.cloneNode(true);
        toggle.parentNode.replaceChild(fresh, toggle);

        let qmOpen = false;
        function openMenu() {
            if (qmOpen) return;
            qmOpen = true;
            positionItems();
            fab.classList.add('qm-open');
            fresh.setAttribute('aria-expanded', 'true');
        }
        function closeMenu() {
            if (!qmOpen) return;
            qmOpen = false;
            fab.classList.remove('qm-open');
            fresh.setAttribute('aria-expanded', 'false');
        }
        function toggleMenu() { qmOpen ? closeMenu() : openMenu(); }

        function positionItems() {
            const items = $$('#qmRadial .qm-item', fab);
            if (!items.length) return;
            const rect = fresh.getBoundingClientRect();
            const cx = rect.left + rect.width / 2;
            const cy = rect.top + rect.height / 2;
            const wantsLeft = cx >= (window.innerWidth - cx);
            const wantsUp = cy >= (window.innerHeight - cy);
            const centerAngle = wantsUp ? (wantsLeft ? 135 : 45) : (wantsLeft ? 225 : 315);
            const n = items.length;
            const spread = Math.min(260, 150 + n * 10);
            const startAngle = centerAngle - spread / 2;
            const radius = (window.innerWidth < 480 ? 84 : 104) + Math.max(0, n - 7) * 6;
            items.forEach((item, i) => {
                const deg = n > 1 ? startAngle + (spread / (n - 1)) * i : centerAngle;
                const rad = deg * Math.PI / 180;
                item.style.setProperty('--tx', (Math.cos(rad) * radius).toFixed(1) + 'px');
                item.style.setProperty('--ty', (-Math.sin(rad) * radius).toFixed(1) + 'px');
            });
        }

        let dragging = false, moved = false;
        let sx = 0, sy = 0, sR = 0, sB = 0;

        fresh.addEventListener('pointerdown', (e) => {
            dragging = true; moved = false;
            sx = e.clientX; sy = e.clientY;
            const rect = fab.getBoundingClientRect();
            sR = window.innerWidth - rect.right;
            sB = window.innerHeight - rect.bottom;
            try { fresh.setPointerCapture(e.pointerId); } catch (_) {}
            fab.classList.add('qm-dragging');
        });
        fresh.addEventListener('pointermove', (e) => {
            if (!dragging) return;
            const dx = e.clientX - sx, dy = e.clientY - sy;
            if (Math.abs(dx) > 5 || Math.abs(dy) > 5) moved = true;
            if (!moved) return;
            const rect = fab.getBoundingClientRect();
            const r = Math.max(8, Math.min(window.innerWidth - rect.width - 8, sR - dx));
            const b = Math.max(8, Math.min(window.innerHeight - rect.height - 8, sB - dy));
            fab.style.right = r + 'px';
            fab.style.bottom = b + 'px';
            if (qmOpen) positionItems();
        });
        function endDrag(e) {
            if (!dragging) return;
            dragging = false;
            fab.classList.remove('qm-dragging');
            try { fresh.releasePointerCapture(e.pointerId); } catch (_) {}
            if (!moved) toggleMenu();
        }
        fresh.addEventListener('pointerup', endDrag);
        fresh.addEventListener('pointercancel', endDrag);

        document.addEventListener('click', (e) => {
            if (qmOpen && !fab.contains(e.target) && !e.target.closest('#addLinkModal')) closeMenu();
        }, true);
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && qmOpen) closeMenu(); });
        window.addEventListener('resize', () => { if (qmOpen) positionItems(); });

        // Rebind radial actions
        $$('#qmRadial .qm-item[data-qm-action]', fab).forEach((oldItem) => {
            const item = oldItem.cloneNode(true);
            oldItem.parentNode.replaceChild(item, oldItem);
            item.addEventListener('click', () => {
                closeMenu();
                const action = item.dataset.qmAction;
                window.dispatchEvent(new CustomEvent('qm-action', { detail: action }));
                setTimeout(() => {
                    const navMap = {
                        'scan-basic': 'testing', 'scan-expert': 'testing',
                        history: 'assets', console: 'console', chat: 'chat',
                        telegram: 'telegram',
                    };
                    if (navMap[action]) {
                        const btn = document.querySelector('.nav-item[data-section="' + navMap[action] + '"]');
                        if (btn) btn.click();
                    }
                }, 200);
            });
        });

        log('Quick menu rebound');
    }

    /* ═══════════════════════════════════════════════════════════════════
     * RUN ALL
     * ═══════════════════════════════════════════════════════════════════ */
    onReady(function () {
        try { fixProfileModal();    } catch (e) { err('profile', e); }
        try { fixPrayerTimes();     } catch (e) { err('prayer', e); }
        try { fixToolsHubNav();     } catch (e) { err('tools-nav', e); }
        try { fixToolsHubActions(); } catch (e) { err('tools-actions', e); }
        try { fixBriefingUser();    } catch (e) { err('briefing-user', e); }
        try { fixBriefingVideo();   } catch (e) { err('briefing-video', e); }
        try { fixQuickMenu();       } catch (e) { err('quick-menu', e); }
        log('All patches applied');
    });

})();
