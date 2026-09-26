/* ═══════════════════════════════════════════════════════════════════════════
   EMERGENS — LFI / RFI Renderer (v1.1.0)
   ─────────────────────────────────────────────────────────────────────────
   File         : templates/js/script2.js
   Load order   : after js/script.js, before js/app-*.js

   CHANGELOG
   ─────────
   v1.1.0
     • Redesigned card: compact KPI row, cleaner typography, tighter
       spacing, mobile-first layout.
     • Long payload / excerpt blocks now collapse by default with an
       inline "Show full" toggle — solves the case where a single
       Cloudflare-challenge quote dumps hundreds of characters into
       one line and stretches the card vertically.
     • Severity filter chips are now clickable to filter the finding
       list client-side (no refetch).
     • Removed every emoji; every glyph is a Font Awesome icon class.
     • Zero-result state redesigned to match the new layout.

   v1.0.1
     • Fixed duplicate render (extract LFI entries before delegating).

   Public API (window.LfiRfiRenderer):
       .render(toolResult)   -> string (HTML)
       .isResult(toolResult) -> boolean
       .selfCheck()          -> object
       .version              -> '1.1.0'

   Author : Yanxzyx
   ═══════════════════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  if (window.LfiRfiRenderer && window.LfiRfiRenderer.version) return;

  const VERSION = '1.1.0';

  /* ── 0. Escape helper ─────────────────────────────────────────────────── */
  const esc = (typeof window.escapeHtml === 'function')
    ? window.escapeHtml
    : function (v) {
        if (v === undefined || v === null) return '';
        return String(v)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#039;');
      };

  /* ── 1. Constants ─────────────────────────────────────────────────────── */
  const CSS_ID                 = 'lfi-rfi-renderer-styles';
  const PAYLOAD_PREVIEW_CHARS  = 140;
  const EXCERPT_PREVIEW_CHARS  = 180;
  const SEV_ORDER              = ['critical', 'high', 'medium', 'low', 'info'];

  /* ── 2. CSS ───────────────────────────────────────────────────────────── */

  const CSS_TEXT = `
/* ══════════════════════════════════════════════════════════════════════
   LFI / RFI RESULT CARD  (v1.1.0)
   Uses the theme's design tokens only — no hardcoded palette.
   ══════════════════════════════════════════════════════════════════════ */

.lfi-card{
    padding:0!important;
    overflow:hidden;
}

/* ── Header ────────────────────────────────────────────────────────── */
.lfi-header{
    display:flex;
    align-items:center;
    gap:10px;
    padding:14px 18px;
    border-bottom:1px solid var(--border-subtle);
    background:linear-gradient(180deg,
        color-mix(in srgb, var(--red-500) 6%, var(--bg-tertiary)),
        var(--bg-tertiary));
    flex-wrap:wrap;
}
.lfi-header-icon{
    width:30px;height:30px;
    border-radius:8px;
    display:flex;align-items:center;justify-content:center;
    background:var(--red-glow-soft);
    color:var(--red-400);
    font-size:.8rem;
    flex-shrink:0;
}
.lfi-header-title{
    font-size:.88rem;
    font-weight:700;
    color:var(--text-primary);
    letter-spacing:-.01em;
    flex:1;
    min-width:0;
    overflow:hidden;
    text-overflow:ellipsis;
    white-space:nowrap;
}
.lfi-header-meta{
    display:flex;
    align-items:center;
    gap:6px;
    flex-shrink:0;
}

/* ── Target strip ──────────────────────────────────────────────────── */
.lfi-target{
    display:flex;
    align-items:center;
    gap:8px;
    padding:9px 18px;
    background:var(--bg-secondary);
    border-bottom:1px solid var(--border-subtle);
    font-family:var(--font-mono);
    font-size:.72rem;
    color:var(--text-secondary);
    word-break:break-all;
    line-height:1.45;
}
.lfi-target-icon{color:var(--red-400);flex-shrink:0;font-size:.7rem}
.lfi-target-url{color:var(--text-primary);font-weight:600}

/* ── Verdict line ──────────────────────────────────────────────────── */
.lfi-verdict{
    display:flex;
    align-items:center;
    gap:9px;
    padding:10px 18px;
    font-size:.76rem;
    line-height:1.5;
    border-bottom:1px solid var(--border-subtle);
}
.lfi-verdict.is-vuln{
    background:color-mix(in srgb, var(--red-500) 8%, transparent);
    color:var(--red-400);
}
.lfi-verdict.is-clean{
    background:color-mix(in srgb, var(--green) 8%, transparent);
    color:var(--green);
}
.lfi-verdict-icon{flex-shrink:0;font-size:.82rem}
.lfi-verdict-body{flex:1;min-width:0}
.lfi-verdict-body strong{color:inherit;font-weight:700;margin-right:4px}

/* ── KPI row ──────────────────────────────────────────────────────── */
.lfi-kpi-row{
    display:grid;
    grid-template-columns:repeat(6, minmax(0, 1fr));
    gap:1px;
    background:var(--border-subtle);
    border-bottom:1px solid var(--border-subtle);
}
.lfi-kpi{
    background:var(--bg-secondary);
    padding:12px 8px;
    text-align:center;
    display:flex;
    flex-direction:column;
    justify-content:center;
    gap:3px;
    min-width:0;
    transition:background var(--transition-fast);
}
.lfi-kpi:hover{background:var(--bg-tertiary)}
.lfi-kpi-val{
    font-family:var(--font-display);
    font-size:1.05rem;
    font-weight:800;
    line-height:1.1;
    color:var(--text-primary);
    font-variant-numeric:tabular-nums;
    overflow:hidden;
    text-overflow:ellipsis;
    white-space:nowrap;
}
.lfi-kpi-label{
    font-size:.55rem;
    text-transform:uppercase;
    letter-spacing:.06em;
    font-weight:700;
    color:var(--text-muted);
    overflow:hidden;
    text-overflow:ellipsis;
    white-space:nowrap;
}
.lfi-kpi.is-accent .lfi-kpi-val{color:var(--red-500)}
.lfi-kpi.is-ok     .lfi-kpi-val{color:var(--green)}

@media (max-width:720px){
    .lfi-kpi-row{grid-template-columns:repeat(3, minmax(0, 1fr))}
}
@media (max-width:400px){
    .lfi-kpi-row{grid-template-columns:repeat(2, minmax(0, 1fr))}
}

/* ── Toolbar: filter chips + params toggle ─────────────────────────── */
.lfi-toolbar{
    display:flex;
    align-items:center;
    gap:8px;
    padding:11px 18px;
    background:var(--bg-secondary);
    border-bottom:1px solid var(--border-subtle);
    flex-wrap:wrap;
}
.lfi-toolbar-label{
    font-size:.6rem;
    text-transform:uppercase;
    letter-spacing:.08em;
    font-weight:700;
    color:var(--text-muted);
}
.lfi-filters{
    display:flex;
    flex-wrap:wrap;
    gap:5px;
    flex:1;
    min-width:0;
}

/* Filter / summary chip — dual purpose */
.lfi-chip{
    display:inline-flex;
    align-items:center;
    gap:6px;
    padding:4px 10px;
    border-radius:6px;
    border:1px solid var(--border-color);
    background:var(--bg-tertiary);
    color:var(--text-secondary);
    font-size:.66rem;
    font-weight:700;
    letter-spacing:.03em;
    text-transform:uppercase;
    cursor:pointer;
    transition:all var(--transition-fast);
    -webkit-user-select:none;
    user-select:none;
    font-family:inherit;
}
.lfi-chip:hover{border-color:var(--text-muted);color:var(--text-primary)}
.lfi-chip .lfi-chip-count{
    font-family:var(--font-display);
    font-size:.78rem;
    font-weight:800;
    letter-spacing:0;
    text-transform:none;
    color:var(--text-primary);
}
.lfi-chip.active{
    border-color:currentColor;
    background:color-mix(in srgb, currentColor 12%, transparent);
}
.lfi-chip[data-filter="critical"]{color:var(--red-500)}
.lfi-chip[data-filter="high"]    {color:#f97316}
.lfi-chip[data-filter="medium"]  {color:var(--amber)}
.lfi-chip[data-filter="low"]     {color:var(--steel)}
.lfi-chip[data-filter="info"]    {color:var(--text-muted)}
.lfi-chip[data-filter="all"]     {color:var(--text-secondary)}
.lfi-chip.is-empty{opacity:.4;cursor:not-allowed;pointer-events:none}

.lfi-params-toggle{
    display:inline-flex;
    align-items:center;
    gap:6px;
    padding:5px 11px;
    border-radius:6px;
    border:1px solid var(--border-color);
    background:var(--bg-tertiary);
    color:var(--text-secondary);
    font-size:.66rem;
    font-weight:700;
    letter-spacing:.03em;
    cursor:pointer;
    transition:all var(--transition-fast);
    font-family:inherit;
}
.lfi-params-toggle:hover{border-color:var(--red-500);color:var(--red-400)}
.lfi-params-toggle i{transition:transform var(--transition-fast)}
.lfi-params-toggle.is-open i.fas.fa-chevron-down{transform:rotate(180deg)}

/* ── Body ─────────────────────────────────────────────────────────── */
.lfi-body{
    padding:14px 18px 18px;
    display:flex;
    flex-direction:column;
    gap:10px;
}

/* ── Findings ─────────────────────────────────────────────────────── */
.lfi-findings{
    display:flex;
    flex-direction:column;
    gap:8px;
}
.lfi-finding{
    background:var(--bg-secondary);
    border:1px solid var(--border-color);
    border-left:3px solid var(--text-muted);
    border-radius:8px;
    padding:12px 14px;
    display:flex;
    flex-direction:column;
    gap:9px;
    transition:border-color var(--transition-fast),
               box-shadow var(--transition-fast);
    animation:fadeSlideUp .28s ease both;
}
.lfi-finding:hover{box-shadow:var(--shadow-sm)}
.lfi-finding.sev-critical{border-left-color:var(--red-500)}
.lfi-finding.sev-high    {border-left-color:#f97316}
.lfi-finding.sev-medium  {border-left-color:var(--amber)}
.lfi-finding.sev-low     {border-left-color:var(--steel)}
.lfi-finding.sev-info    {border-left-color:var(--text-muted)}

.lfi-finding-head{
    display:flex;
    align-items:center;
    gap:8px;
    flex-wrap:wrap;
    min-width:0;
}

.lfi-badge{
    display:inline-flex;
    align-items:center;
    gap:4px;
    padding:2px 8px;
    border-radius:5px;
    font-size:.58rem;
    font-weight:800;
    letter-spacing:.06em;
    text-transform:uppercase;
    border:1px solid;
    flex-shrink:0;
}
.lfi-badge.sev-critical{color:var(--red-500);border-color:var(--red-glow);
    background:var(--red-glow-soft)}
.lfi-badge.sev-high    {color:#f97316;border-color:rgba(249,115,22,.4);
    background:rgba(249,115,22,.14)}
.lfi-badge.sev-medium  {color:var(--amber);border-color:var(--amber-glow);
    background:var(--amber-glow)}
.lfi-badge.sev-low     {color:var(--steel);border-color:var(--steel-glow);
    background:var(--steel-glow)}
.lfi-badge.sev-info    {color:var(--text-muted);border-color:var(--border-color);
    background:var(--bg-tertiary)}

.lfi-param{
    font-family:var(--font-mono);
    font-size:.68rem;
    font-weight:700;
    color:var(--text-primary);
    background:var(--bg-tertiary);
    border:1px solid var(--border-subtle);
    padding:2px 7px;
    border-radius:5px;
    max-width:200px;
    overflow:hidden;
    text-overflow:ellipsis;
    white-space:nowrap;
}

.lfi-technique{
    font-family:var(--font-mono);
    font-size:.64rem;
    color:var(--steel);
    letter-spacing:.02em;
    max-width:200px;
    overflow:hidden;
    text-overflow:ellipsis;
    white-space:nowrap;
}

.lfi-confidence{
    margin-left:auto;
    display:inline-flex;
    align-items:center;
    gap:7px;
    flex-shrink:0;
}
.lfi-confidence-bar{
    position:relative;
    width:48px;
    height:5px;
    border-radius:999px;
    background:var(--bg-tertiary);
    border:1px solid var(--border-subtle);
    overflow:hidden;
}
.lfi-confidence-fill{
    position:absolute;
    top:0;bottom:0;left:0;
    border-radius:999px;
    background:linear-gradient(90deg, var(--steel), var(--red-400));
    transition:width .5s cubic-bezier(.16,1,.3,1);
}
.lfi-confidence-fill.val-high{
    background:linear-gradient(90deg, var(--amber), var(--red-500));
}
.lfi-confidence-fill.val-critical{
    background:linear-gradient(90deg, #f97316, var(--red-500));
}
.lfi-confidence-num{
    font-family:var(--font-mono);
    font-size:.66rem;
    font-weight:700;
    color:var(--text-secondary);
    font-variant-numeric:tabular-nums;
    min-width:32px;
    text-align:right;
}

/* Finding description line */
.lfi-finding-label{
    font-size:.76rem;
    color:var(--text-secondary);
    line-height:1.5;
    word-break:break-word;
    overflow-wrap:anywhere;
}

/* Payload / excerpt — collapsible blocks */
.lfi-block{
    position:relative;
    border-radius:6px;
    overflow:hidden;
    border:1px solid var(--border-subtle);
    background:var(--bg-tertiary);
}
.lfi-block-label{
    display:block;
    padding:5px 10px;
    background:var(--bg-secondary);
    border-bottom:1px solid var(--border-subtle);
    font-size:.55rem;
    font-weight:800;
    letter-spacing:.09em;
    text-transform:uppercase;
    color:var(--text-muted);
}
.lfi-block-content{
    padding:8px 11px;
    font-family:var(--font-mono);
    font-size:.68rem;
    line-height:1.55;
    color:var(--text-secondary);
    white-space:pre-wrap;
    word-break:break-all;
    overflow-wrap:anywhere;
    max-height:none;
    overflow-y:auto;
}
.lfi-block-content.is-collapsed{
    max-height:78px;
    overflow:hidden;
    -webkit-mask-image:linear-gradient(180deg,#000 60%,transparent 100%);
            mask-image:linear-gradient(180deg,#000 60%,transparent 100%);
}
.lfi-block-toggle{
    display:flex;
    align-items:center;
    justify-content:center;
    gap:6px;
    width:100%;
    padding:6px 10px;
    border:none;
    border-top:1px solid var(--border-subtle);
    background:var(--bg-secondary);
    color:var(--text-secondary);
    font-size:.62rem;
    font-weight:700;
    letter-spacing:.04em;
    text-transform:uppercase;
    cursor:pointer;
    font-family:inherit;
    transition:color var(--transition-fast),
               background var(--transition-fast);
}
.lfi-block-toggle:hover{color:var(--red-400);background:var(--bg-tertiary)}
.lfi-block-toggle i{font-size:.6rem}

/* Specific color tones */
.lfi-block.lfi-payload .lfi-block-label{color:var(--red-400)}
.lfi-block.lfi-payload .lfi-block-content{color:var(--red-400)}
.lfi-block.lfi-evidence .lfi-block-label{color:var(--steel)}
.lfi-block.lfi-evidence .lfi-block-content{color:var(--text-secondary)}

/* Evidence chips */
.lfi-evidence-chips{
    display:flex;
    flex-wrap:wrap;
    gap:5px;
}
.lfi-ev-chip{
    display:inline-flex;
    align-items:center;
    gap:4px;
    padding:2px 7px;
    border-radius:4px;
    font-family:var(--font-mono);
    font-size:.6rem;
    background:var(--bg-tertiary);
    border:1px solid var(--border-subtle);
    color:var(--text-muted);
}
.lfi-ev-chip i{font-size:.56rem}
.lfi-ev-chip.hit{
    color:var(--red-400);
    border-color:var(--red-glow);
    background:var(--red-glow-soft);
}
.lfi-ev-chip.ok{
    color:var(--green);
    border-color:var(--green-glow);
    background:var(--green-glow);
}

/* Finding meta footer */
.lfi-finding-meta{
    display:flex;
    flex-wrap:wrap;
    gap:12px;
    padding-top:8px;
    border-top:1px dashed var(--border-subtle);
    font-size:.64rem;
    color:var(--text-muted);
    font-family:var(--font-mono);
}
.lfi-finding-meta span{
    display:inline-flex;
    align-items:center;
    gap:5px;
    overflow:hidden;
    text-overflow:ellipsis;
    white-space:nowrap;
    max-width:100%;
}
.lfi-finding-meta i{color:var(--steel);font-size:.58rem;flex-shrink:0}

/* Params drawer */
.lfi-params-drawer{
    padding:12px 14px;
    background:var(--bg-tertiary);
    border:1px solid var(--border-subtle);
    border-radius:8px;
    animation:fadeSlideUp .22s ease both;
}
.lfi-params-title{
    font-size:.58rem;
    font-weight:800;
    letter-spacing:.08em;
    text-transform:uppercase;
    color:var(--text-muted);
    margin-bottom:8px;
}
.lfi-params-list{
    display:flex;
    flex-wrap:wrap;
    gap:5px;
}
.lfi-param-chip{
    font-family:var(--font-mono);
    font-size:.64rem;
    padding:3px 8px;
    border-radius:4px;
    background:var(--bg-secondary);
    border:1px solid var(--border-subtle);
    color:var(--text-secondary);
}

/* Empty state */
.lfi-empty{
    display:flex;
    align-items:center;
    gap:10px;
    padding:16px 18px;
    border-radius:8px;
    font-size:.8rem;
    line-height:1.5;
    background:color-mix(in srgb, var(--green) 8%, transparent);
    border:1px solid var(--green-glow);
    color:var(--green);
}
.lfi-empty i{flex-shrink:0;font-size:.95rem}

/* Filtering animation */
.lfi-finding[hidden]{display:none!important}

/* Mobile tightening */
@media (max-width:520px){
    .lfi-header{padding:12px 14px}
    .lfi-target{padding:8px 14px;font-size:.68rem}
    .lfi-verdict{padding:9px 14px;font-size:.72rem}
    .lfi-toolbar{padding:10px 14px}
    .lfi-body{padding:12px 14px 14px}
    .lfi-finding{padding:10px 12px;gap:7px}
    .lfi-confidence{flex-basis:100%;margin-left:0;order:2;width:100%}
    .lfi-param,.lfi-technique{max-width:100%}
    .lfi-block-content{font-size:.64rem;padding:7px 9px}
    .lfi-finding-meta{gap:8px;font-size:.6rem}
}
`;

  function injectCss() {
    if (document.getElementById(CSS_ID)) return;
    const el = document.createElement('style');
    el.id = CSS_ID;
    el.textContent = CSS_TEXT;
    document.head.appendChild(el);
  }

  /* ── 3. Utilities ─────────────────────────────────────────────────────── */

  function sevClass(sev) {
    const s = String(sev || '').toLowerCase();
    return SEV_ORDER.indexOf(s) >= 0 ? ('sev-' + s) : 'sev-info';
  }

  function fmtDuration(seconds) {
    const s = Number(seconds) || 0;
    if (s < 1) return Math.round(s * 1000) + 'ms';
    if (s < 60) return s.toFixed(2) + 's';
    const m = Math.floor(s / 60);
    const r = s - m * 60;
    return m + 'm ' + r.toFixed(1) + 's';
  }

  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(2) + ' MB';
  }

  function isLfiRfiResult(toolKey, toolResult) {
    const key = String(toolKey || '').toLowerCase();
    const KEY_ALIASES = ['lfi_rfi', 'lfi', 'rfi', 'lfi_scan', 'rfi_scan',
                          'scan_lfi', 'scan_rfi', 'lfi_rfi_check'];
    if (KEY_ALIASES.indexOf(key) >= 0) return true;

    const d = (toolResult && (toolResult.data || toolResult)) || {};
    return Array.isArray(d.findings) &&
           (typeof d.payloads_used === 'number' ||
            typeof d.tests_run === 'number');
  }

  /* ── 4. Block builder — collapsible code/pre blocks ──────────────────── */
  /**
   * Renders a labelled block that collapses if the content exceeds
   * `previewChars`. The toggle is wired via delegation on the results
   * grid, so this HTML stays inert and idempotent.
   */
  function buildBlock(kind, label, text, previewChars) {
    const raw = String(text == null ? '' : text);
    if (!raw) return '';
    const preview = raw.length > previewChars
                  ? raw.slice(0, previewChars)
                  : raw;
    const hasMore = raw.length > previewChars;
    const contentCls = hasMore ? 'lfi-block-content is-collapsed' : 'lfi-block-content';
    const fullHidden = hasMore
      ? `<span class="lfi-block-full" hidden>${esc(raw.slice(previewChars))}</span>`
      : '';
    const toggle = hasMore
      ? `<button type="button" class="lfi-block-toggle" data-state="collapsed"
                 aria-expanded="false">
           <i class="fas fa-chevron-down"></i>
           <span>Show full ${esc(kind)}</span>
         </button>`
      : '';
    return `<div class="lfi-block lfi-${esc(kind)}">
      <span class="lfi-block-label">${esc(label)}</span>
      <div class="${contentCls}">${esc(preview)}${fullHidden}</div>
      ${toggle}
    </div>`;
  }

  /* ── 5. Renderer ──────────────────────────────────────────────────────── */

  function buildKpiRow(d) {
    const findings  = Array.isArray(d.findings) ? d.findings : [];
    const params    = Array.isArray(d.params_tested) ? d.params_tested : [];
    const vuln      = d.vulnerable === true || findings.length > 0;

    const items = [
      { v: findings.length,        l: 'Findings', cls: vuln ? 'is-accent' : 'is-ok' },
      { v: params.length,          l: 'Params'   },
      { v: d.payloads_used || 0,   l: 'Payloads' },
      { v: d.tests_run || 0,       l: 'Tests'    },
      { v: d.requests_sent || 0,   l: 'Requests' },
      { v: fmtDuration(d.duration), l: 'Duration' },
    ];

    return `<div class="lfi-kpi-row">${items.map(it => `
      <div class="lfi-kpi ${it.cls || ''}">
        <div class="lfi-kpi-val">${esc(it.v)}</div>
        <div class="lfi-kpi-label">${esc(it.l)}</div>
      </div>`).join('')}</div>`;
  }

  function buildFilters(bySev) {
    const counts = bySev && typeof bySev === 'object' ? bySev : {};
    const total  = SEV_ORDER.reduce((s, k) => s + (Number(counts[k]) || 0), 0);

    const allChip = `<button type="button" class="lfi-chip active"
                              data-filter="all" data-count="${total}">
        <span>All</span><span class="lfi-chip-count">${total}</span>
      </button>`;

    const chips = SEV_ORDER.map(sev => {
      const n = Number(counts[sev]) || 0;
      const empty = n === 0 ? 'is-empty' : '';
      return `<button type="button" class="lfi-chip ${empty}"
                        data-filter="${sev}" data-count="${n}"
                        ${n === 0 ? 'disabled' : ''}>
        <span>${sev}</span><span class="lfi-chip-count">${n}</span>
      </button>`;
    }).join('');

    return allChip + chips;
  }

  function buildFinding(f, idx) {
    const sev      = String(f.severity || 'info').toLowerCase();
    const sevCls   = sevClass(sev);
    const conf     = Math.max(0, Math.min(100, Number(f.confidence) || 0));
    const confCls  = conf >= 85 ? 'val-critical' : (conf >= 70 ? 'val-high' : '');

    const param     = f.parameter || f.param || '?';
    const technique = f.technique || 'unknown';
    const label     = f.label || f.target_file || '';
    const payload   = f.payload || '';
    const excerpt   = f.excerpt || '';
    const status    = f.status_code !== undefined ? f.status_code : '?';
    const resLen    = Number(f.response_len) || 0;
    const baseLen   = Number(f.baseline_len) || 0;
    const ctype     = f.content_type || '';
    const ev        = f.evidence || {};

    /* Evidence chips */
    const chips = [];
    if (ev.base64_source === true) {
      chips.push('<span class="lfi-ev-chip hit"><i class="fas fa-check"></i>base64 source</span>');
    }
    if (ev.content_type_flip === true) {
      chips.push('<span class="lfi-ev-chip hit"><i class="fas fa-check"></i>content-type flip</span>');
    }
    const sigs = Array.isArray(ev.signature_hits) ? ev.signature_hits : [];
    if (sigs.length) {
      chips.push(`<span class="lfi-ev-chip hit"><i class="fas fa-crosshairs"></i>${sigs.length} signature hit(s)</span>`);
    }
    const errs = Array.isArray(ev.php_errors) ? ev.php_errors : [];
    if (errs.length) {
      chips.push(`<span class="lfi-ev-chip hit"><i class="fas fa-bug"></i>${errs.length} PHP error(s)</span>`);
    }
    if (!chips.length) {
      chips.push('<span class="lfi-ev-chip"><i class="fas fa-minus"></i>no direct signal</span>');
    }

    /* Payload + excerpt blocks */
    const payloadBlock  = payload  ? buildBlock('payload',  'Payload',  payload,  PAYLOAD_PREVIEW_CHARS)  : '';
    const excerptBlock  = excerpt  ? buildBlock('evidence', 'Excerpt',  excerpt,  EXCERPT_PREVIEW_CHARS)  : '';

    /* Meta footer */
    const metaParts = [
      `<span><i class="fas fa-signal"></i>HTTP ${esc(status)}</span>`,
      `<span><i class="fas fa-ruler-horizontal"></i>${esc(fmtBytes(resLen))} / base ${esc(fmtBytes(baseLen))}</span>`,
    ];
    if (ctype) {
      metaParts.push(`<span><i class="fas fa-file-code"></i>${esc(ctype)}</span>`);
    }
    if (f.confidence_label) {
      metaParts.push(`<span><i class="fas fa-gauge-simple"></i>${esc(f.confidence_label)}</span>`);
    }

    return `<div class="lfi-finding ${sevCls}"
                 data-severity="${esc(sev)}"
                 data-finding-index="${idx}">
      <div class="lfi-finding-head">
        <span class="lfi-badge ${sevCls}">${esc(sev)}</span>
        <span class="lfi-param" title="${esc(param)}">${esc(param)}</span>
        <span class="lfi-technique" title="${esc(technique)}">${esc(technique)}</span>
        <span class="lfi-confidence">
          <span class="lfi-confidence-bar"><span class="lfi-confidence-fill ${confCls}" style="width:${conf}%"></span></span>
          <span class="lfi-confidence-num">${conf}%</span>
        </span>
      </div>
      ${label ? `<div class="lfi-finding-label">${esc(label)}</div>` : ''}
      ${payloadBlock}
      ${excerptBlock}
      <div class="lfi-evidence-chips">${chips.join('')}</div>
      <div class="lfi-finding-meta">${metaParts.join('')}</div>
    </div>`;
  }

  function renderLfiRfiResult(toolResult) {
    const envelope = toolResult || {};
    const d = (envelope.data !== undefined ? envelope.data : envelope) || {};

    const findings  = Array.isArray(d.findings) ? d.findings : [];
    const vuln      = d.vulnerable === true || findings.length > 0;
    const url       = d.url || d.target_file || envelope.target || '--';
    const bySev     = (d.by_severity && typeof d.by_severity === 'object')
                    ? d.by_severity
                    : findings.reduce((acc, f) => {
                        const s = String(f.severity || 'info').toLowerCase();
                        acc[s] = (acc[s] || 0) + 1;
                        return acc;
                      }, {});
    const params    = Array.isArray(d.params_tested) ? d.params_tested : [];

    /* Header badge */
    const headerBadge = vuln
      ? `<span class="badge danger"><i class="fas fa-triangle-exclamation"></i>${findings.length} Finding${findings.length === 1 ? '' : 's'}</span>`
      : `<span class="badge success"><i class="fas fa-shield-halved"></i>Clean</span>`;

    /* Verdict */
    const verdict = vuln
      ? `<div class="lfi-verdict is-vuln">
           <i class="fas fa-triangle-exclamation lfi-verdict-icon"></i>
           <span class="lfi-verdict-body">
             <strong>File inclusion indicators confirmed.</strong>
             Review each finding against its confidence before reporting.
           </span>
         </div>`
      : `<div class="lfi-verdict is-clean">
           <i class="fas fa-shield-halved lfi-verdict-icon"></i>
           <span class="lfi-verdict-body">
             No LFI/RFI indicators triggered across the tested parameters.
           </span>
         </div>`;

    /* Findings — sorted by confidence desc, then severity rank */
    let findingsHtml;
    if (findings.length) {
      const rank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
      const sorted = findings.slice().sort((a, b) => {
        const ca = Number(a.confidence) || 0;
        const cb = Number(b.confidence) || 0;
        if (cb !== ca) return cb - ca;
        return (rank[String(b.severity).toLowerCase()] || 0) -
               (rank[String(a.severity).toLowerCase()] || 0);
      });
      findingsHtml = `<div class="lfi-findings" id="lfi-findings-list">${
        sorted.map(buildFinding).join('')
      }</div>`;
    } else {
      findingsHtml = `<div class="lfi-empty">
        <i class="fas fa-shield-halved"></i>
        <span>No LFI/RFI findings. The target resisted every payload in the
              <strong>${esc(d.mode || 'basic')}</strong> set.</span>
      </div>`;
    }

    /* Params drawer (hidden by default) */
    const paramsDrawer = params.length
      ? `<div class="lfi-params-drawer" id="lfi-params-drawer" hidden>
           <div class="lfi-params-title">Parameters tested (${params.length})</div>
           <div class="lfi-params-list">
             ${params.map(p => `<span class="lfi-param-chip">${esc(p)}</span>`).join('')}
           </div>
         </div>`
      : '';
    const paramsToggle = params.length
      ? `<button type="button" class="lfi-params-toggle" id="lfi-params-toggle"
                 aria-expanded="false">
           <i class="fas fa-chevron-down"></i>
           <span>Params (${params.length})</span>
         </button>`
      : '';

    /* Toolbar (filters + params toggle) */
    const toolbar = findings.length
      ? `<div class="lfi-toolbar">
           <span class="lfi-toolbar-label">Filter</span>
           <div class="lfi-filters" id="lfi-filters">${buildFilters(bySev)}</div>
           ${paramsToggle}
         </div>`
      : (paramsToggle
          ? `<div class="lfi-toolbar">
               <div class="lfi-filters"></div>
               ${paramsToggle}
             </div>`
          : '');

    /* Error block */
    const errBlock = envelope.error
      ? `<div class="tr-error" style="margin-top:6px;">
           <i class="fas fa-circle-exclamation"></i>${esc(envelope.error)}
         </div>`
      : '';

    /* Compose */
    return `<div class="result-card lfi-card" data-tool="lfi_rfi">
      <div class="lfi-header">
        <div class="lfi-header-icon"><i class="fas fa-folder-open"></i></div>
        <div class="lfi-header-title">LFI / RFI Scanner</div>
        <div class="lfi-header-meta">${headerBadge}</div>
      </div>
      <div class="lfi-target">
        <i class="fas fa-crosshairs lfi-target-icon"></i>
        <span class="lfi-target-url">${esc(url)}</span>
      </div>
      ${verdict}
      ${buildKpiRow(d)}
      ${toolbar}
      <div class="lfi-body">
        ${findingsHtml}
        ${paramsDrawer}
        ${errBlock}
      </div>
    </div>`;
  }

  /* ── 6. Interaction delegation ────────────────────────────────────────── */

  /**
   * All interactive bits inside our LFI card are wired via a single
   * delegated listener on the result grid, so re-rendering the grid
   * never leaves orphan handlers behind.
   */
  function installDelegatedHandlers() {
    const grid = document.getElementById('scanResultGrid');
    if (!grid || grid.dataset.lfiDelegated === '1') return;

    grid.addEventListener('click', function (e) {
      const card = e.target.closest('.lfi-card');
      if (!card) return;

      /* 6a. Collapsible payload / excerpt */
      const toggle = e.target.closest('.lfi-block-toggle');
      if (toggle) {
        const block  = toggle.closest('.lfi-block');
        const body   = block && block.querySelector('.lfi-block-content');
        if (!body) return;
        const full   = body.querySelector('.lfi-block-full');
        const isOpen = body.classList.toggle('is-collapsed') === false;
        toggle.dataset.state = isOpen ? 'expanded' : 'collapsed';
        toggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        const label = toggle.querySelector('span');
        if (label) {
          label.textContent = isOpen
            ? 'Show less'
            : ('Show full ' + (block.classList.contains('lfi-payload')
                               ? 'payload' : 'excerpt'));
        }
        const ico = toggle.querySelector('i');
        if (ico) {
          ico.className = isOpen
            ? 'fas fa-chevron-up'
            : 'fas fa-chevron-down';
        }
        // When collapsing, restore the mask; when expanding, hide the "…"
        if (full) full.hidden = !isOpen;
        return;
      }

      /* 6b. Params drawer */
      if (e.target.closest('#lfi-params-toggle')) {
        const btn    = card.querySelector('#lfi-params-toggle');
        const drawer = card.querySelector('#lfi-params-drawer');
        if (!btn || !drawer) return;
        const open   = drawer.hidden;
        drawer.hidden = !open;
        btn.classList.toggle('is-open', open);
        btn.setAttribute('aria-expanded', open ? 'true' : 'false');
        return;
      }

      /* 6c. Severity filter chips */
      const chip = e.target.closest('.lfi-chip');
      if (chip && !chip.disabled) {
        const filter = chip.dataset.filter || 'all';
        const list   = card.querySelector('#lfi-findings-list');
        if (!list) return;
        card.querySelectorAll('.lfi-chip').forEach(c =>
          c.classList.toggle('active', c === chip)
        );
        list.querySelectorAll('.lfi-finding').forEach(f => {
          const sev = f.dataset.severity;
          f.hidden = !(filter === 'all' || sev === filter);
        });
        return;
      }
    });

    grid.dataset.lfiDelegated = '1';
  }

  /* ── 7. Patch / fallback dispatch ─────────────────────────────────────── */

  const ORIGINAL_KEY = '__lfiRfiOrigRenderResults';
  const FLAG_KEY     = '__lfiRfiRenderResultsPatched';

  function patchRenderResults() {
    if (window[FLAG_KEY] === true) return true;
    if (typeof window.renderResults !== 'function') return false;

    const original = window.renderResults;
    window[ORIGINAL_KEY] = original;

    window.renderResults = function patchedRenderResults(results) {
      if (!results || typeof results !== 'object') {
        return original.apply(this, arguments);
      }

      /* Split LFI entries from the rest */
      const lfiEntries = [];
      const otherResults = {};
      for (const key of Object.keys(results)) {
        let isLfi = false;
        try {
          isLfi = isLfiRfiResult(key, results[key]);
        } catch (e) { /* silent */ }
        if (isLfi) lfiEntries.push([key, results[key]]);
        else otherResults[key] = results[key];
      }

      if (!lfiEntries.length) {
        return original.apply(this, arguments);
      }

      const grid = document.getElementById('scanResultGrid');
      if (!grid) return original.apply(this, arguments);

      /* Delegate to original for everything EXCEPT LFI */
      let originalHtml = '';
      if (Object.keys(otherResults).length > 0) {
        try {
          originalHtml = original.call(this, otherResults) || '';
        } catch (err) {
          if (window.console && console.error) {
            console.error('[LfiRfiRenderer] original renderResults threw:', err);
          }
        }
      } else {
        grid.innerHTML = '';
      }

      /* Post-render fixups */
      setTimeout(function () {
        try {
          /* Fix up "Modules Run" counter — includes LFI entries */
          const summaryBar  = grid.querySelector('.result-summary-bar');
          const firstStrong = summaryBar && summaryBar.querySelector('.rsb-item strong');
          if (firstStrong) {
            const cur = parseInt(firstStrong.textContent, 10) || 0;
            firstStrong.textContent = String(cur + lfiEntries.length);
          }

          /* Append styled LFI cards */
          lfiEntries.forEach(function (entry) {
            try {
              const html = renderLfiRfiResult(entry[1]);
              const wrap = document.createElement('div');
              wrap.innerHTML = html.trim();
              if (wrap.firstElementChild) grid.appendChild(wrap.firstElementChild);
            } catch (err) {
              if (window.console && console.warn) {
                console.warn('[LfiRfiRenderer] render failed for key',
                             entry[0], err);
              }
            }
          });

          /* Wire delegation once */
          installDelegatedHandlers();
        } catch (err) {
          if (window.console && console.warn) {
            console.warn('[LfiRfiRenderer] post-render fixup failed:', err);
          }
        }
      }, 0);

      return originalHtml;
    };

    window[FLAG_KEY] = true;
    return true;
  }

  function installFallbackDispatcher() {
    if (typeof window.renderResults === 'function') return false;
    if (!document.getElementById('scanResultGrid')) return false;

    window.renderResults = function fallbackRenderResults(results) {
      const grid = document.getElementById('scanResultGrid');
      if (!grid) return;
      grid.innerHTML = '';
      if (!results || typeof results !== 'object') {
        grid.innerHTML = '<div class="empty-state">No results returned.</div>';
        return;
      }
      for (const key of Object.keys(results)) {
        if (isLfiRfiResult(key, results[key])) {
          try {
            const wrap = document.createElement('div');
            wrap.innerHTML = renderLfiRfiResult(results[key]).trim();
            if (wrap.firstElementChild) grid.appendChild(wrap.firstElementChild);
          } catch (err) {
            if (window.console && console.warn) {
              console.warn('[LfiRfiRenderer] fallback render failed:', err);
            }
          }
        }
      }
      if (!grid.children.length) {
        grid.innerHTML = '<div class="empty-state">No LFI/RFI results in this scan.</div>';
      }
      installDelegatedHandlers();
    };

    return true;
  }

  /* ── 8. Boot ──────────────────────────────────────────────────────────── */

  function boot() {
    injectCss();

    if (patchRenderResults()) {
      installDelegatedHandlers();
      if (window.console && console.debug) {
        console.debug('[LfiRfiRenderer] patched existing renderResults()');
      }
      return;
    }

    let attempts = 0;
    const timer = setInterval(function () {
      attempts++;
      if (patchRenderResults()) {
        clearInterval(timer);
        installDelegatedHandlers();
        if (window.console && console.debug) {
          console.debug('[LfiRfiRenderer] patched after', attempts, 'attempt(s)');
        }
        return;
      }
      if (attempts >= 40) {
        clearInterval(timer);
        if (installFallbackDispatcher()) {
          if (window.console && console.debug) {
            console.debug('[LfiRfiRenderer] installed fallback dispatcher');
          }
        } else if (window.console && console.warn) {
          console.warn('[LfiRfiRenderer] could not find or patch renderResults()');
        }
      }
    }, 100);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  /* ── 9. Public API ────────────────────────────────────────────────────── */

  window.LfiRfiRenderer = {
    version: VERSION,
    render:  renderLfiRfiResult,
    isResult: isLfiRfiResult,
    injectCss: injectCss,
    selfCheck: function () {
      return {
        version: VERSION,
        cssInjected:             !!document.getElementById(CSS_ID),
        renderResultsPatched:    window[FLAG_KEY] === true,
        hasOriginalRenderResults: typeof window[ORIGINAL_KEY] === 'function',
        hasActiveRenderResults:  typeof window.renderResults === 'function',
        hasResultGrid:           !!document.getElementById('scanResultGrid'),
        hasDelegatedHandlers:    !!document.querySelector('#scanResultGrid[data-lfi-delegated="1"]'),
      };
    },
  };

})();