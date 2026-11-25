/**
 * compare-view.js
 *
 * Renders the comparison of two backups: their check results and their
 * system settings.
 *
 * Depends on: compare.js (diffConfigMaps, diffFindings), compliance-engine.js
 *             (runAllChecks, runAllBestPracticesChecks), i18n.js,
 *             app.js (escapeHtml, describeBackup, rerenderKeepingFocus, announce)
 */

const compareState = {
    showAll: false,   // false: only rows that are not "same"
};

const COMPARE_STATUS_TEXT = {
    changed: 'compareStatusChanged',
    same:    'compareStatusSame',
    onlyA:   'compareStatusOnlyA',
    onlyB:   'compareStatusOnlyB',
    unknown: 'compareStatusUnknown',
};

function toggleCompareShowAll() {
    compareState.showAll = !compareState.showAll;
    rerenderKeepingFocus(renderApp);
    const shown = document.querySelectorAll('.compare-row').length;
    announce(shown ? t('announceFiltered', shown) : t('compareNoDifferences'));
}

function compareCounts(entries) {
    const counts = { changed: 0, same: 0, onlyA: 0, onlyB: 0, unknown: 0 };
    for (const entry of entries) counts[entry.status]++;
    return counts;
}

function compareSummaryText(counts) {
    return t('compareSummary', counts.changed, counts.onlyA, counts.onlyB, counts.unknown);
}

/** Security and best-practice findings of one backup, each tagged with its kind. */
function compareRunChecks(result) {
    const tag = kind => f => ({ ...f, kind });
    return [
        ...runAllChecks(result.config, result.tlsProfile, result).map(tag('security')),
        ...runAllBestPracticesChecks(result.config, result.tlsProfile, result).map(tag('bestpractices')),
    ];
}

/** Checks run at render time so titles follow the current language. */
function compareFindings(resultA, resultB) {
    return diffFindings(compareRunChecks(resultA), compareRunChecks(resultB));
}

function compareFindingsSummaryText(diff) {
    return t('compareFindingsSummary', diff.onlyA.length, diff.onlyB.length, diff.itemsChanged.length);
}

function renderComparePill(f) {
    return f.status === 'unknown'
        ? `<span class="severity-pill severity-pill--unknown">${t('severityUnknown')}</span>`
        : `<span class="severity-pill severity-pill--${f.severity}">${t('severity' + f.severity.charAt(0).toUpperCase() + f.severity.slice(1))}</span>`;
}

/** One pill, or one per side when the two backups rate the finding differently. */
function renderComparePills(a, b) {
    const pillA = renderComparePill(a);
    const pillB = renderComparePill(b);
    if (pillA === pillB) return pillB;
    return `${t('compareSideA')}: ${pillA} ${t('compareSideB')}: ${pillB}`;
}

function renderCompareFinding(f, extra = '', pills = renderComparePill(f)) {
    const kind = t(f.kind === 'security' ? 'tabSecurity' : 'tabBestPractices');
    return `
        <li class="compare-finding">
            ${pills}
            <span>${escapeHtml(f.title)}</span>
            <span class="compare-finding-kind">(${kind})</span>
            ${extra}
        </li>`;
}

function renderCompareItems(change) {
    const parts = [];
    if (change.itemsOnlyA.length) parts.push(t('compareItemsOnlyA', change.itemsOnlyA.map(escapeHtml).join(', ')));
    if (change.itemsOnlyB.length) parts.push(t('compareItemsOnlyB', change.itemsOnlyB.map(escapeHtml).join(', ')));
    return `<span class="compare-finding-items">${parts.join('; ')}</span>`;
}

function renderCompareFindings(diff) {
    const group = (titleKey, html) => html ? `
        <h4 class="compare-group-title">${t(titleKey)}</h4>
        <ul class="compare-findings" role="list">${html}</ul>` : '';
    const body = group('compareFindingsOnlyA', diff.onlyA.map(f => renderCompareFinding(f)).join(''))
        + group('compareFindingsOnlyB', diff.onlyB.map(f => renderCompareFinding(f)).join(''))
        + group('compareFindingsItemsChanged',
            diff.itemsChanged.map(c => renderCompareFinding(c.b, renderCompareItems(c), renderComparePills(c.a, c.b))).join(''));
    return `
        <section class="compare-section" aria-labelledby="compare-findings-title">
            <h3 class="compare-section-title" id="compare-findings-title">${t('compareFindingsTitle')}</h3>
            <p class="compare-note">${t('compareFindingsNote')}</p>
            ${body || `<p class="compare-empty">${t('compareFindingsNone')}</p>`}
        </section>`;
}

/** Text for one side of a row; the diff only carries values that are safe to show. */
function renderCompareValue(config, key, shownValue) {
    if (!config.has(key))        return `<span class="compare-value--note">${t('compareValueMissing')}</span>`;
    if (config.get(key) === null) return `<span class="compare-value--note">${t('compareValueUnreadable')}</span>`;
    if (shownValue === null)     return `<span class="compare-value--note">${t('compareValueHidden')}</span>`;
    if (shownValue === '')       return `<span class="compare-value--note">${t('compareValueEmpty')}</span>`;
    return `<code>${escapeHtml(shownValue)}</code>`;
}

function renderCompareSide(label, parseResult) {
    const { version, model, hostname } = describeBackup(parseResult);
    return `
        <div>
            <h3 class="compare-side-title">${label}</h3>
            <dl class="compare-side-list">
                <dt>${t('labelFileName')}</dt><dd>${escapeHtml(parseResult.fileName)}</dd>
                <dt>${t('labelModel')}</dt><dd>${escapeHtml(model)}</dd>
                <dt>${t('labelDSMVersion')}</dt><dd>${escapeHtml(version)}</dd>
                <dt>${t('labelHostname')}</dt><dd>${escapeHtml(hostname)}</dd>
            </dl>
        </div>
    `;
}

function renderCompareRows(entries, configA, configB) {
    const groups = new Map();
    for (const entry of entries) {
        const group = entry.key.split('_')[0];
        if (!groups.has(group)) groups.set(group, []);
        groups.get(group).push(entry);
    }
    return [...groups].map(([group, rows]) => `
        <tbody>
            <tr><th scope="rowgroup" colspan="4" class="compare-group">${escapeHtml(group)}</th></tr>
            ${rows.map(entry => `
            <tr class="compare-row compare-row--${entry.status}">
                <th scope="row"><code>${escapeHtml(entry.key)}</code></th>
                <td>${renderCompareValue(configA, entry.key, entry.a)}</td>
                <td>${renderCompareValue(configB, entry.key, entry.b)}</td>
                <td class="compare-status">${t(COMPARE_STATUS_TEXT[entry.status])}</td>
            </tr>`).join('')}
        </tbody>
    `).join('');
}

/**
 * @param {Object} resultA  parse result of the first backup
 * @param {Object} resultB  parse result of the second backup
 * @returns {string} HTML
 */
function renderCompareView(resultA, resultB) {
    const entries  = diffConfigMaps(resultA.config, resultB.config);
    const counts   = compareCounts(entries);
    const visible  = compareState.showAll ? entries : entries.filter(e => e.status !== 'same');
    const findings = compareFindings(resultA, resultB);

    const table = visible.length
        ? `
                <table class="compare-table">
                    <thead>
                        <tr>
                            <th scope="col">${t('compareColSetting')}</th>
                            <th scope="col">${t('compareSideA')}</th>
                            <th scope="col">${t('compareSideB')}</th>
                            <th scope="col">${t('compareColResult')}</th>
                        </tr>
                    </thead>
                    ${renderCompareRows(visible, resultA.config, resultB.config)}
                </table>`
        : `<p class="compare-empty">${t('compareNoDifferences')}</p>`;

    return `
        <div class="compare-header">
            <div class="compare-header-top">
                <h2 class="bp-title" id="view-heading" tabindex="-1">${t('compareTitle')}</h2>
                <button type="button" class="fd-button fd-button--ghost" onclick="resetApp()">
                    ${t('compareBtnNew')}
                </button>
            </div>
            <div class="compare-sides">
                ${renderCompareSide(t('compareSideA'), resultA)}
                ${renderCompareSide(t('compareSideB'), resultB)}
            </div>
            <p class="compare-summary">${t('compareFindingsTitle')}: ${compareFindingsSummaryText(findings)}</p>
            <p class="compare-summary">${t('compareSettingsTitle')}: ${compareSummaryText(counts)}</p>
        </div>
        <div class="compare-scroll" tabindex="0" role="region" aria-label="${t('compareTitle')}">
            ${renderCompareFindings(findings)}
            <section class="compare-section" aria-labelledby="compare-settings-title">
                <h3 class="compare-section-title" id="compare-settings-title">${t('compareSettingsTitle')}</h3>
                <p class="compare-note">${t('compareScope')} ${t('compareHiddenNote')}</p>
                <button type="button" class="compare-toggle" data-focus-key="compare-show-all"
                        aria-pressed="${compareState.showAll}" onclick="toggleCompareShowAll()">
                    ${t('compareShowAll')}
                </button>
                ${table}
            </section>
        </div>
    `;
}
