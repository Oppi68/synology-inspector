/**
 * app.js
 *
 * Main application bootstrap for Synology Inspector.
 *
 * State machine:
 *   'idle'    → file selected/dropped → 'loading'
 *   'loading' → parse success         → 'results'
 *   'loading' → parse error           → 'error'
 *   'idle'    → two files selected    → 'loading' → 'compare'
 *   'results' → reset button          → 'idle'
 *   'compare' → reset button          → 'idle'
 *   'error'   → reset button          → 'idle'
 *
 * Depends on (loaded before this file):
 *   i18n.js, xz-decompress.js, tar-parser.js, sqlite-reader.js,
 *   dss-pipeline.js, compliance-engine.js, compare.js, checks/*.js,
 *   compliance-view.js, bestpractices-view.js, compare-view.js
 */

const YOUTUBE_CHANNEL_URL = 'https://www.youtube.com/@navigio1';

// ── Utilities ─────────────────────────────────────────────────────────────────

function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatFileSize(bytes) {
    if (bytes < 1024)        return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// ── App state ─────────────────────────────────────────────────────────────────

let _appPhase     = 'idle';       // 'idle' | 'loading' | 'results' | 'compare' | 'error'
let _parseResult  = null;
let _compareResults = null;       // [parse result A, parse result B]
let _errorMessage = '';
let _errorKey     = '';           // translation key; rendered in the current language
let _activeTab    = 'security';   // 'security' | 'bestpractices'

// ── Main render ────────────────────────────────────────────────────────────────

function renderApp() {
    updateLangButtons();
    updateContextBar();

    const root = document.getElementById('app');
    if (!root) return;

    if (_appPhase === 'idle') {
        root.innerHTML = renderDropZone();
    } else if (_appPhase === 'loading') {
        root.innerHTML = renderLoadingView();
    } else if (_appPhase === 'results' && _parseResult) {
        const secFindings = runAllChecks(_parseResult.config, _parseResult.tlsProfile, _parseResult);
        const bpFindings  = runAllBestPracticesChecks(_parseResult.config, _parseResult.tlsProfile, _parseResult);
        // Reset view state on every render (covers language switches and tab switches)
        complianceState.severityFilter  = null;
        complianceState.frameworkFilter = null;
        complianceState.expandedIds.clear();
        bpState.expandedIds.clear();
        const isSecTab = _activeTab === 'security';
        root.innerHTML = `
            <div class="results-shell">
                <div class="tab-bar">
                    <button type="button" class="tab-btn ${isSecTab ? 'tab-btn--active' : ''}"
                            data-focus-key="tab-security" ${isSecTab ? 'aria-current="true"' : ''}
                            onclick="switchTab('security')">${t('tabSecurity')}</button>
                    <button type="button" class="tab-btn ${!isSecTab ? 'tab-btn--active' : ''}"
                            data-focus-key="tab-bestpractices" ${!isSecTab ? 'aria-current="true"' : ''}
                            onclick="switchTab('bestpractices')">${t('tabBestPractices')}</button>
                </div>
                ${isSecTab
                    ? `<div class="compliance-view" id="compliance-view-root">${renderComplianceView(secFindings)}</div>`
                    : `<div class="bestpractices-view" id="bestpractices-view-root">${renderBestPracticesView(bpFindings)}</div>`
                }
            </div>
        `;
    } else if (_appPhase === 'compare' && _compareResults) {
        root.innerHTML = `
            <div class="compare-view" id="compare-view-root">
                ${renderCompareView(_compareResults[0], _compareResults[1])}
            </div>
        `;
    } else if (_appPhase === 'error') {
        root.innerHTML = renderErrorView(errorText());
    }
}

// ── Context bar ────────────────────────────────────────────────────────────────

/** DSM version, model and hostname of a parse result, '—' where unknown. */
function describeBackup({ info, config }) {
    const version = info.dsm_majorversion
        ? `${info.dsm_majorversion}.${info.dsm_minorversion || '0'} (Build ${info.dsm_buildnumber || '?'})`
        : '—';
    const model   = info.unique
        ? info.unique.replace(/^synology_[^_]+_/, '').toUpperCase()
        : '—';
    let hostname = '—';
    try { hostname = JSON.parse(config?.get('NETWORK_GENERAL_config') || '{}')?.config?.server_name || '—'; } catch (_) {}
    return { version, model, hostname };
}

function updateContextBar() {
    const bar = document.getElementById('context-bar');
    if (!bar) return;

    if (_appPhase === 'results' && _parseResult) {
        const { fileName, fileSize } = _parseResult;
        const { version, model, hostname } = describeBackup(_parseResult);

        bar.className = 'context-bar';
        bar.setAttribute('aria-label', t('contextBarLabel'));
        bar.innerHTML = `
            <div class="context-item">
                <span class="context-label">${t('labelFileName')}</span>
                <span class="context-value">${escapeHtml(fileName)}</span>
            </div>
            <div class="context-item">
                <span class="context-label">${t('labelFileSize')}</span>
                <span class="context-value">${formatFileSize(fileSize)}</span>
            </div>
            <div class="context-item">
                <span class="context-label">${t('labelDSMVersion')}</span>
                <span class="context-value">${escapeHtml(version)}</span>
            </div>
            <div class="context-item">
                <span class="context-label">${t('labelModel')}</span>
                <span class="context-value">${escapeHtml(model)}</span>
            </div>
            <div class="context-item">
                <span class="context-label">${t('labelHostname')}</span>
                <span class="context-value">${escapeHtml(hostname)}</span>
            </div>
            <div class="context-actions">
                ${window.JKLP_PDF_EXPORT ? `
                <button type="button" class="fd-button fd-button--ghost pdf-export-btn"
                        onclick="${_activeTab === 'bestpractices' ? 'exportBPToPDF()' : 'exportToPDF()'}">
                    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                        <path d="M3 12h10M8 2v8M5 7l3 3 3-3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    ${t('btnExportPDF')}
                </button>` : ''}
                <button type="button" class="fd-button fd-button--ghost" onclick="resetApp()">
                    ${t('btnNewFile')}
                </button>
            </div>
        `;
    } else {
        bar.className = 'context-bar context-bar--hidden';
        bar.innerHTML = '';
    }
}

// ── Drop zone ─────────────────────────────────────────────────────────────────

function renderDropZone() {
    return `
        <div class="drop-zone-container"
             ondragover="onDragOver(event)"
             ondragleave="onDragLeave(event)"
             ondrop="onDrop(event)">
            <div class="drop-zone" id="drop-zone" onclick="openFilePicker()">
                <div class="drop-zone-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" aria-hidden="true"
                         fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="17 8 12 3 7 8"/>
                        <line x1="12" y1="3" x2="12" y2="15"/>
                    </svg>
                </div>
                <h2 class="drop-zone-title">${t('dropTitle')}</h2>
                <div class="drop-zone-or">${t('dropOr')}
                    <button type="button" class="drop-zone-browse" id="drop-zone-btn"
                            aria-describedby="drop-zone-formats"
                            onclick="event.stopPropagation();openFilePicker()">${t('dropBrowse')}</button>
                </div>
                <div class="drop-zone-formats" id="drop-zone-formats">${t('dropFormats')}</div>
                <div class="drop-zone-compare">${t('compareLead')}
                    <button type="button" class="drop-zone-browse" id="compare-btn"
                            onclick="event.stopPropagation();openComparePicker()">${t('compareBrowse')}</button>
                </div>
                <div class="drop-zone-privacy">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" aria-hidden="true"
                         fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                    ${t('dropPrivacy')}
                </div>
            </div>
            ${renderDisclaimer('drop-zone-disclaimer')}
            <button type="button" class="about-inline-btn" onclick="showAbout()">
                <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                    <circle cx="8" cy="8" r="7.25" stroke="currentColor" stroke-width="1.5"/>
                    <rect x="7.25" y="6.5" width="1.5" height="5" rx=".75" fill="currentColor"/>
                    <rect x="7.25" y="4" width="1.5" height="1.5" rx=".75" fill="currentColor"/>
                </svg>
                ${t('aboutBtn')}
            </button>
        </div>
        <input type="file" id="file-input" accept=".dss"
               style="display:none" onchange="onFileInputChange(event)">
        <input type="file" id="compare-input" accept=".dss" multiple
               style="display:none" onchange="onCompareInputChange(event)">
    `;
}

// ── Loading view ───────────────────────────────────────────────────────────────

function renderLoadingView() {
    return `
        <div class="loading-view">
            <div class="loading-spinner" aria-hidden="true"></div>
            <div class="loading-title">${t('loading')}</div>
            <div class="loading-hint">${t('loadingHint')}</div>
        </div>
    `;
}

// ── Error view ─────────────────────────────────────────────────────────────────

function renderErrorView(message) {
    return `
        <div class="error-view">
            <div class="error-icon" aria-hidden="true">⚠</div>
            <h2 class="error-title" tabindex="-1">${t('errUnknown')}</h2>
            <div class="error-message">${escapeHtml(message)}</div>
            <button class="fd-button fd-button--emphasized" onclick="resetApp()">
                ${t('btnNewFile')}
            </button>
        </div>
    `;
}

// ── File processing ────────────────────────────────────────────────────────────

function processFile(file) {
    if (!file) return;

    _appPhase = 'loading';
    renderApp();
    announce(t('loading'));

    parseDSSFile(file)
        .then(result => {
            _parseResult = result;
            _appPhase    = 'results';
            renderApp();
            document.getElementById('view-heading')?.focus();
            announce(t('announceLoaded', findingCountText(_complianceVisibleCount)));
        })
        .catch(showError);
}

function showError(err) {
    _errorMessage = err.message || String(err);
    _errorKey     = err.key || '';
    _appPhase     = 'error';
    renderApp();
    document.querySelector('.error-title')?.focus();
    // The focused heading already reads the error title
    announce(errorText());
}

function errorText() {
    return _errorKey ? t(_errorKey) : _errorMessage;
}

/** Parse two backups and show the comparison of their settings. */
function processComparison(files) {
    if (files.length !== 2) {
        showError({ key: 'errCompareCount' });
        return;
    }

    _appPhase = 'loading';
    renderApp();
    announce(t('loading'));

    Promise.all(files.map(parseDSSFile))
        .then(results => {
            _compareResults = results;
            compareState.showAll = false;
            _appPhase = 'compare';
            renderApp();
            document.getElementById('view-heading')?.focus();
            announce(t('announceCompared',
                compareFindingsSummaryText(compareFindings(results[0], results[1])),
                compareSummaryText(compareCounts(diffConfigMaps(results[0].config, results[1].config)))));
        })
        .catch(showError);
}

function resetApp() {
    _appPhase     = 'idle';
    _parseResult  = null;
    _compareResults = null;
    _errorMessage = '';
    _errorKey     = '';
    _activeTab    = 'security';
    renderApp();
    announce('');
    document.getElementById('drop-zone-btn')?.focus();
}

function switchTab(tab) {
    _activeTab = tab;
    rerenderKeepingFocus(renderApp);
}

function openFilePicker() {
    document.getElementById('file-input')?.click();
}

function openComparePicker() {
    document.getElementById('compare-input')?.click();
}

// ── Accessibility helpers ──────────────────────────────────────────────────────

let _announceTimer = null;

/**
 * Announce a message through the persistent live region in index.html.
 * An empty message clears the region. lang marks text in another language.
 */
function announce(message, lang) {
    const region = document.getElementById('app-status');
    if (!region) return;
    clearTimeout(_announceTimer);
    region.textContent = '';
    region.removeAttribute('lang');
    if (!message) return;
    // A short delay makes screen readers announce identical consecutive messages
    _announceTimer = setTimeout(() => {
        if (lang) region.lang = lang;
        region.textContent = message;
    }, 50);
}

/** "1 issue" / "3 issues" in the current language. */
function findingCountText(count) {
    return `${count} ${count === 1 ? t('findingSingular') : t('findingPlural')}`;
}

/**
 * Run a render function that replaces innerHTML and move focus back to the
 * element with the same data-focus-key. If that element is gone (e.g. the
 * "clear filters" button), focus the findings area instead of losing focus.
 */
function rerenderKeepingFocus(render) {
    const key = document.activeElement?.dataset?.focusKey;
    render();
    if (!key) return;
    const target = document.querySelector(`[data-focus-key="${CSS.escape(key)}"]`)
        || document.querySelector('.findings-scroll-area');
    target?.focus();
}

// ── Drag & drop event handlers ─────────────────────────────────────────────────

function onDragOver(event) {
    event.preventDefault();
    event.stopPropagation();
    document.getElementById('drop-zone')?.classList.add('drop-zone--active');
}

function onDragLeave(event) {
    event.preventDefault();
    // Only remove the class if we actually left the container (not a child element)
    if (!event.currentTarget.contains(event.relatedTarget)) {
        document.getElementById('drop-zone')?.classList.remove('drop-zone--active');
    }
}

function onDrop(event) {
    event.preventDefault();
    event.stopPropagation();
    document.getElementById('drop-zone')?.classList.remove('drop-zone--active');
    const files = [...(event.dataTransfer?.files ?? [])];
    if (files.length > 1) processComparison(files);
    else if (files.length === 1) processFile(files[0]);
}

function onFileInputChange(event) {
    const file = event.target?.files?.[0];
    if (file) processFile(file);
}

function onCompareInputChange(event) {
    const files = [...(event.target?.files ?? [])];
    if (files.length) processComparison(files);
}

// ── About ──────────────────────────────────────────────────────────────────────

function _renderAboutContent() {
    const ytIcon = `
        <svg class="about-yt-icon" width="32" height="22" viewBox="0 0 32 22" fill="none" aria-hidden="true">
            <rect width="32" height="22" rx="5" fill="#FF0000"/>
            <polygon points="13,6 13,16 22,11" fill="white"/>
        </svg>`;
    const arrowIcon = `
        <svg class="about-yt-arrow" width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>`;
    return `
        <div class="about-header">
            <img class="about-logo" src="img/logo-jklp.png" alt="JKLP Consulting">
            <div>
                <h2 class="about-tool-name" id="about-title">
                    Synology Inspector
                    <span class="about-tool-version">v1.1</span>
                </h2>
                <div class="about-maker">${t('aboutMaker')}</div>
            </div>
        </div>
        <p class="about-desc">${t('aboutDesc')}</p>
        <p class="about-sob-note">${t('aboutSoBNote')}</p>
        <a class="about-yt-link" href="${YOUTUBE_CHANNEL_URL}" target="_blank" rel="noopener noreferrer">
            ${ytIcon}
            <div class="about-yt-text">
                <span class="about-yt-name">${t('aboutChannelName')}</span>
                <span class="about-yt-sub">${t('aboutChannelDesc')}</span>
            </div>
            ${arrowIcon}
        </a>
        <a class="about-web-link" href="https://jklp.io" target="_blank" rel="noopener noreferrer">
            <svg class="about-web-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.6"/>
                <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" stroke="currentColor" stroke-width="1.6"/>
            </svg>
            <div class="about-yt-text">
                <span class="about-yt-name">${t('aboutWebsiteName')}</span>
                <span class="about-yt-sub">${t('aboutWebsiteDesc')}</span>
            </div>
            ${arrowIcon}
        </a>
        <div class="about-badges">
            <span class="about-badge">${t('aboutBadgeFree')}</span>
            <span class="about-badge">${t('aboutBadgeOS')}</span>
            <span class="about-badge">${t('aboutBadgePrivacy')}</span>
        </div>
    `;
}

let _aboutReturnFocus = null;

// Native <dialog>: showModal() traps focus and closes on Escape.
function showAbout() {
    const modal = document.getElementById('about-modal');
    const content = document.getElementById('about-modal-content');
    if (!modal || !content || modal.open) return;
    content.innerHTML = _renderAboutContent();
    _aboutReturnFocus = document.activeElement;
    modal.showModal();
}

function closeAbout() {
    document.getElementById('about-modal')?.close();
}

function _onAboutClosed() {
    _aboutReturnFocus?.focus?.();
    _aboutReturnFocus = null;
}

// ── Language button state ──────────────────────────────────────────────────────

function updateLangButtons() {
    const lang = getCurrentLanguage();
    document.querySelectorAll('.lang-btn').forEach(btn => {
        const active = btn.dataset.lang === lang;
        btn.classList.toggle('lang-btn--active', active);
        btn.setAttribute('aria-pressed', String(active));
    });
    // Static header/dialog labels live in index.html and are translated here
    const aboutLabel = document.getElementById('about-btn-label');
    if (aboutLabel) aboutLabel.textContent = t('aboutHeaderBtn');
    document.querySelector('.lang-toggle')?.setAttribute('aria-label', t('langGroupLabel'));
    document.querySelector('.about-modal-close')?.setAttribute('aria-label', t('closeLabel'));
    const subtitle = document.querySelector('.header-subtitle');
    if (subtitle) subtitle.textContent = t('appSubtitle');
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('about-modal')?.addEventListener('close', _onAboutClosed);
    renderApp();
});
