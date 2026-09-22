/* ═══════════════════════════════════════════════════════════════════════════
   EMERGENS — fixes.js v1.0.0
   ─────────────────────────────────────────────────────────────────────────
   Compatibility patch that runs AFTER script.js and re-binds every
   handler that might have failed due to an earlier JS error.

   Fixes
     1. Tools Hub modal not opening when clicking "Tools" nav button
     2. Security Testing briefing — username & role not appearing
     3. Security Testing briefing — video not playing (unreliable URL)
     4. Quick Menu FAB (floating bolt) not working / not responding

   Load order in HTML:
     <script src="script.js"></script>
     <script src="mhddos.js" defer></script>
     <script src="exploit.js" defer></script>
     <script src="fixes.js" defer></script>   ← ADD THIS
   ═══════════════════════════════════════════════════════════════════════════ */

(function () {
    'use strict';

    const LOG = '[fixes]';
    const log = (...a) => console.log(LOG, ...a);
    const warn = (...a) => console.warn(LOG, ...a);

    function onReady(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', fn);
        } else {
            // Yield to let other scripts finish
            setTimeout(fn, 0);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // 1. TOOLS HUB — clone & rebind the trigger button
    // ═══════════════════════════════════════════════════════════════════
    function fixToolsHub() {
        const oldBtn = document.getElementById('navToolsHub');
        const modal  = document.getElementById('toolsHubModal');

        if (!oldBtn) { warn('navToolsHub button missing'); return; }
        if (!modal)  { warn('toolsHubModal missing');     return; }

        // Replace button with a fresh clone so all previously attached
        // listeners are discarded and we get a clean slate.
        const btn = oldBtn.cloneNode(true);
        oldBtn.parentNode.replaceChild(btn, oldBtn);

        btn.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            openToolsHub();
        });

        function openToolsHub() {
            // Show the grid view (in case a previous detail view was left open)
            const grid = document.getElementById('toolsGridView');
            if (grid) grid.hidden = false;

            document.querySelectorAll('.tool-detail')
                      .forEach(d => d.hidden = true);

            const backBtn = document.getElementById('toolsHubBackBtn');
            if (backBtn) backBtn.hidden = true;

            const title = document.getElementById('toolsHubHeaderTitle');
            if (title) {
                title.innerHTML =
                    '<i class="fas fa-grip" style="color:var(--red-400);margin-right:6px;"></i>' +
                    '<span>Tools</span>';
            }

            const card = modal.querySelector('.tools-hub-card');
            if (card) card.classList.remove('is-fullscreen');

            modal.hidden = false;
            log('Tools hub opened');
        }

        // Close button
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

        // Click backdrop to close
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.hidden = true;
                const card = modal.querySelector('.tools-hub-card');
                if (card) card.classList.remove('is-fullscreen');
            }
        });

        // Re-bind every tool box click (they may not have been bound)
        document.querySelectorAll('.tool-box[data-tool]').forEach(box => {
            const fresh = box.cloneNode(true);
            box.parentNode.replaceChild(fresh, box);

            fresh.addEventListener('click', () => {
                const tool = fresh.dataset.tool;
                const grid  = document.getElementById('toolsGridView');
                if (grid) grid.hidden = true;

                document.querySelectorAll('.tool-detail')
                          .forEach(d => d.hidden = (d.id !== 'toolDetail-' + tool));

                const backBtn = document.getElementById('toolsHubBackBtn');
                if (backBtn) backBtn.hidden = false;

                const titleMap = {
                    brat: 'Brat Generator',
                    reels: 'Reels',
                    osint: 'OSINT',
                    anime: 'Anime',
                    wifi: 'Wifi Scanner',
                    ipcheck: 'IP Check',
                    quickaccess: 'Quick Access',
                    music: 'Music Downloader',
                    downloader: 'Downloader',
                    mctools: 'MCTOOLS',
                };
                const title = document.getElementById('toolsHubHeaderTitle');
                if (title) title.textContent = titleMap[tool] || 'Tools';

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
                document.querySelectorAll('.tool-detail')
                          .forEach(d => d.hidden = true);
                fresh.hidden = true;
                const card = modal.querySelector('.tools-hub-card');
                if (card) card.classList.remove('is-fullscreen');
            });
        }

        log('Tools hub rebound');
    }

    // ═══════════════════════════════════════════════════════════════════
    // 2. BRIEFING — username + role
    // ═══════════════════════════════════════════════════════════════════
    function fixBriefingUser() {
        const nameEl = document.getElementById('briefingUsername');
        const roleEl = document.getElementById('briefingRole');
        if (!nameEl) { warn('briefingUsername missing'); return; }

        async function refresh() {
            // Attempt 1: /api/me
            try {
                const r = await fetch('/api/me', { credentials: 'same-origin' });
                if (r.ok) {
                    const d = await r.json();
                    if (d && d.username) nameEl.textContent = d.username;
                    if (d && d.role && roleEl) {
                        roleEl.innerHTML =
                            '<i class="fas fa-shield-halved"></i> ' + d.role;
                    }
                    return;
                }
            } catch (_) { /* fall through */ }

            // Attempt 2: mirror from sidebar
            const sideUser = document.getElementById('sidebarUsername');
            const sideRole = document.getElementById('sidebarRole');
            if (sideUser && sideUser.textContent.trim() &&
                sideUser.textContent.trim() !== '--') {
                nameEl.textContent = sideUser.textContent.trim();
            }
            if (roleEl && sideRole && sideRole.textContent.trim() &&
                sideRole.textContent.trim() !== '--') {
                roleEl.innerHTML =
                    '<i class="fas fa-shield-halved"></i> ' +
                    sideRole.textContent.trim();
            }
        }

        // Initial + lazy retries
        refresh();
        setTimeout(refresh, 400);
        setTimeout(refresh, 1500);

        // Re-run every time user opens the Security Testing section
        window.addEventListener('section-change', (e) => {
            if (e.detail === 'testing') {
                setTimeout(refresh, 100);
            }
        });

        log('Briefing user rebound');
    }

    // ═══════════════════════════════════════════════════════════════════
    // 3. BRIEFING VIDEO — replace unreliable URL + robust autoplay
    // ═══════════════════════════════════════════════════════════════════
    function fixBriefingVideo() {
        const wrap        = document.getElementById('briefingVideoWrap');
        const video       = document.getElementById('briefingVideo');
        const placeholder = document.getElementById('briefingVideoPlaceholder');
        if (!wrap || !video) { warn('briefing video elements missing'); return; }

        // ── Replace the Pinterest URL with a stable, CORS-friendly MP4 ──
        // You can swap this for any MP4 hosted on your own CDN.
        const VIDEO_URL = 'https://cdn.pixabay.com/video/2023/03/28/156087-812319483_large.mp4';

        // Hard-reset the element so any stale <source> or listener is gone
        video.pause();
        video.removeAttribute('src');
        video.load();

        video.setAttribute('src', VIDEO_URL);
        video.muted = true;
        video.loop = true;
        video.autoplay = true;
        video.playsInline = true;
        video.preload = 'auto';
        video.hidden = false;
        if (placeholder) placeholder.hidden = true;

        // Try to play; fall back to muted-tap-to-play if blocked
        function tryPlay() {
            const p = video.play();
            if (p && typeof p.catch === 'function') {
                p.catch(err => {
                    warn('Autoplay blocked, will retry on first interaction:', err.message);
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
            warn('Briefing video failed to load — showing placeholder');
            video.hidden = true;
            if (placeholder) {
                placeholder.hidden = false;
                placeholder.innerHTML =
                    '<i class="fas fa-video-slash"></i>' +
                    '<span>Briefing video unavailable</span>';
            }
        });

        // Kick off immediately (covers cached video case)
        tryPlay();
        log('Briefing video rebound →', VIDEO_URL);
    }

    // ═══════════════════════════════════════════════════════════════════
    // 4. QUICK MENU FAB — force visibility + rebind toggle
    // ═══════════════════════════════════════════════════════════════════
    function fixQuickMenu() {
        const fab    = document.getElementById('quickMenuFab');
        const toggle = document.getElementById('qmToggle');
        if (!fab || !toggle) { warn('quick menu elements missing'); return; }

        // Some earlier script may have hidden the FAB — force it visible
        fab.style.display = 'block';
        fab.style.visibility = 'visible';
        fab.style.opacity = '1';
        fab.style.pointerEvents = 'auto';
        fab.style.zIndex = '150';

        // Replace the toggle with a fresh clone so any broken listeners
        // are discarded and we start clean.
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
            const items = fab.querySelectorAll('#qmRadial .qm-item');
            if (!items.length) return;
            const rect = fresh.getBoundingClientRect();
            const cx = rect.left + rect.width / 2;
            const cy = rect.top + rect.height / 2;
            const spaceUp = cy, spaceDown = window.innerHeight - cy;
            const spaceLeft = cx, spaceRight = window.innerWidth - cx;
            const wantsLeft = spaceLeft >= spaceRight;
            const wantsUp   = spaceUp  >= spaceDown;
            const centerAngle = wantsUp
                ? (wantsLeft ? 135 : 45)
                : (wantsLeft ? 225 : 315);
            const n = items.length;
            const spread = Math.min(260, 150 + n * 10);
            const startAngle = centerAngle - spread / 2;
            const radius = (window.innerWidth < 480 ? 84 : 104) +
                           Math.max(0, n - 7) * 6;
            items.forEach((item, i) => {
                const deg = n > 1 ? startAngle + (spread / (n - 1)) * i
                                  : centerAngle;
                const rad = deg * Math.PI / 180;
                item.style.setProperty('--tx', (Math.cos(rad) * radius).toFixed(1) + 'px');
                item.style.setProperty('--ty', (-Math.sin(rad) * radius).toFixed(1) + 'px');
            });
        }

        // Simple drag + click detection
        let dragging = false, moved = false;
        let startX = 0, startY = 0, startRight = 0, startBottom = 0;

        fresh.addEventListener('pointerdown', (e) => {
            dragging = true;
            moved = false;
            startX = e.clientX;
            startY = e.clientY;
            const rect = fab.getBoundingClientRect();
            startRight = window.innerWidth  - rect.right;
            startBottom = window.innerHeight - rect.bottom;
            try { fresh.setPointerCapture(e.pointerId); } catch (_) {}
            fab.classList.add('qm-dragging');
        });

        fresh.addEventListener('pointermove', (e) => {
            if (!dragging) return;
            const dx = e.clientX - startX;
            const dy = e.clientY - startY;
            if (Math.abs(dx) > 5 || Math.abs(dy) > 5) moved = true;
            if (!moved) return;
            const rect = fab.getBoundingClientRect();
            const newRight  = Math.max(8, Math.min(window.innerWidth  - rect.width  - 8, startRight  - dx));
            const newBottom = Math.max(8, Math.min(window.innerHeight - rect.height - 8, startBottom - dy));
            fab.style.right  = newRight  + 'px';
            fab.style.bottom = newBottom + 'px';
            if (qmOpen) positionItems();
        });

        function endDrag(e) {
            if (!dragging) return;
            dragging = false;
            fab.classList.remove('qm-dragging');
            try { fresh.releasePointerCapture(e.pointerId); } catch (_) {}
            if (!moved) {
                toggleMenu();
            } else {
                // Persist position
                try {
                    const rect = fab.getBoundingClientRect();
                    localStorage.setItem('emergens-quickmenu-pos',
                        JSON.stringify({
                            right: window.innerWidth  - rect.right,
                            bottom: window.innerHeight - rect.bottom,
                        }));
                } catch (_) {}
            }
        }

        fresh.addEventListener('pointerup', endDrag);
        fresh.addEventListener('pointercancel', endDrag);

        // Close on outside click
        document.addEventListener('click', (e) => {
            if (qmOpen && !fab.contains(e.target) &&
                !e.target.closest('#addLinkModal')) {
                closeMenu();
            }
        }, true);

        // Close on Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && qmOpen) closeMenu();
        });

        // Restore saved position
        try {
            const saved = JSON.parse(localStorage.getItem('emergens-quickmenu-pos') || 'null');
            if (saved && typeof saved.right === 'number' && typeof saved.bottom === 'number') {
                const rect = fab.getBoundingClientRect();
                fab.style.right  = Math.max(8, Math.min(window.innerWidth  - rect.width  - 8, saved.right))  + 'px';
                fab.style.bottom = Math.max(8, Math.min(window.innerHeight - rect.height - 8, saved.bottom)) + 'px';
            }
        } catch (_) {}

        // Rebind every radial item (they may be stale clones)
        fab.querySelectorAll('#qmRadial .qm-item[data-qm-action]').forEach(oldItem => {
            const item = oldItem.cloneNode(true);
            oldItem.parentNode.replaceChild(item, oldItem);
            item.addEventListener('click', () => {
                closeMenu();
                const action = item.dataset.qmAction;
                // Dispatch as a custom event so script.js handles the actual popup
                window.dispatchEvent(new CustomEvent('qm-action', { detail: action }));
                // Fallback: navigate to matching section if script.js didn't handle it
                setTimeout(() => {
                    const navMap = {
                        'scan-basic':  'testing',
                        'scan-expert': 'testing',
                        history:       'assets',
                        console:       'console',
                        chat:          'chat',
                        telegram:      'telegram',
                    };
                    if (navMap[action]) {
                        const btn = document.querySelector('.nav-item[data-section="' + navMap[action] + '"]');
                        if (btn) btn.click();
                    }
                }, 200);
            });
        });

        // Recompute layout on resize
        window.addEventListener('resize', () => { if (qmOpen) positionItems(); });

        log('Quick menu rebound');
    }

    // ═══════════════════════════════════════════════════════════════════
    // Run everything
    // ═══════════════════════════════════════════════════════════════════
    onReady(function () {
        try { fixToolsHub();       } catch (e) { warn('fixToolsHub failed:', e); }
        try { fixBriefingUser();   } catch (e) { warn('fixBriefingUser failed:', e); }
        try { fixBriefingVideo();  } catch (e) { warn('fixBriefingVideo failed:', e); }
        try { fixQuickMenu();      } catch (e) { warn('fixQuickMenu failed:', e); }
        log('All patches applied');
    });
})();
