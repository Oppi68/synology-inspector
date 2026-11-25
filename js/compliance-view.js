/**
 * compliance-view.js
 *
 * Renders the compliance report dashboard.
 *
 * Layout:
 *   ┌─ Score header: KPI number + grade + severity chips + framework chips ──────┐
 *   ├─ Status bar: finding count + active filters + clear button ────────────────┤
 *   └─ Findings grouped by category → passed checks section ─────────────────────┘
 *
 * Depends on: compliance-engine.js, i18n.js, app.js (escapeHtml)
 */

// ── Framework display metadata ────────────────────────────────────────────────

const FRAMEWORK_META = {
    CIS:  { label: 'CIS Controls v8',  color: '#a3380a' },
    NIST: { label: 'NIST SP 800-53',   color: '#1d4ed8' },
    ISO:  { label: 'ISO 27001:2022',   color: '#6d28d9' },
    NIS2: { label: 'NIS2 Directive',   color: '#036b4d' },
    PCI:  { label: 'PCI DSS v4',       color: '#9a3412' },
};

const FW_REF_DESCRIPTIONS = {
    'CIS 3.10':    { title: 'Encrypt Sensitive Data in Transit',            body: 'Encrypt sensitive data in transit using a secure protocol such as Transport Layer Security (TLS). Do not use older versions of TLS.' },
    'CIS 4.4':     { title: 'Implement and Manage a Firewall on Servers',     body: 'Implement and manage a firewall on servers, where supported, such as a virtual firewall, operating system firewall or third-party firewall agent.' },
    'CIS 4.6':     { title: 'Securely Manage Enterprise Assets and Software', body: 'Securely manage enterprise assets and software. Use encrypted protocols such as SSH rather than Telnet for remote management. Disable unnecessary services.' },
    'CIS 4.7':     { title: 'Manage Default Accounts',                        body: 'Manage default accounts on enterprise assets and software, such as root, administrator and other pre-configured vendor accounts. Disable default accounts or make them unusable.' },
    'CIS 4.8':     { title: 'Uninstall or Disable Unnecessary Services',    body: 'Uninstall or disable unnecessary services on enterprise assets and software, such as unused file sharing services, web application modules, or remote management services not required for business purposes.' },
    'CIS 4.10':    { title: 'Enforce Automatic Device Lockout',               body: 'Enforce automatic lockout following a predetermined threshold of failed authentication attempts, so that password guessing is slowed down or stopped.' },
    'CIS 5.2':     { title: 'Use Unique Passwords',                           body: 'Use unique passwords for all enterprise assets. Best practice implementation includes, at a minimum, an 8-character password for accounts using MFA and a 14-character password for accounts not using MFA.' },
    'CIS 5.4':     { title: 'Restrict Administrator Privileges to Dedicated Administrator Accounts', body: 'Restrict administrator privileges to dedicated administrator accounts. Conduct general computing activities from the user\'s primary, non-privileged account.' },
    'CIS 11.2':    { title: 'Perform Automated Backups',                      body: 'Perform automated backups of in-scope enterprise assets. Run backups weekly, or more frequently, based on the sensitivity of the data.' },
    'CIS 7.3':     { title: 'Perform Automated Operating System Patch Management', body: 'Perform operating system updates on enterprise assets through automated patch management on a monthly, or more frequent, basis.' },
    'CIS 9.2':     { title: 'Ensure Only Approved Ports and Services Are Listening', body: 'Ensure that only network ports, protocols, and services with validated business needs are listening on each enterprise asset.' },
    'CIS 9.4':     { title: 'Block Unnecessary File Sharing Services',       body: 'Block unnecessary file sharing services and protocols including SMBv1. Restrict access to file shares to authorised users only, using encrypted protocols.' },
    'CIS 9.5':     { title: 'Implement Application Layer Filtering',         body: 'Implement TLS on all services accessible from the internet. Ensure that HTTP traffic is redirected to HTTPS and that HSTS is configured.' },
    'NIST AC-2':   { title: 'Account Management',                             body: 'Define allowed account types, assign account managers, require approval for new accounts, and disable accounts that are no longer required, including shared and guest accounts.' },
    'NIST AC-6':   { title: 'Least Privilege',                                body: 'Allow only the authorized accesses for users and processes that are necessary to accomplish assigned tasks.' },
    'NIST AC-7':   { title: 'Unsuccessful Logon Attempts',                   body: 'Enforce a limit of consecutive invalid logon attempts. Automatically lock the account or delay further attempts when the limit is exceeded.' },
    'NIST CP-9':   { title: 'System Backup',                                  body: 'Conduct backups of system-level information, including system configuration, at a defined frequency and protect the confidentiality, integrity and availability of the backups.' },
    'NIST IA-5':   { title: 'Authenticator Management',                       body: 'Manage system authenticators such as passwords: establish minimum strength requirements, prohibit commonly used or compromised passwords, and protect authenticators from disclosure.' },
    'NIST SI-2':   { title: 'Flaw Remediation',                               body: 'Identify, report and correct system flaws; install security-relevant software and firmware updates within a defined time period of their release.' },
    'NIST CM-7':   { title: 'Least Functionality',                           body: 'Configure the system to provide only essential capabilities. Prohibit or restrict functions, ports, protocols, and services not required.' },
    'NIST IA-3':   { title: 'Device Identification and Authentication',       body: 'Uniquely identify and authenticate devices before establishing connections. Only use authentication protocols and algorithms that meet current security standards.' },
    'NIST SC-7':   { title: 'Boundary Protection',                           body: 'Monitor and control communications at the external boundary. Connect to external networks only through managed interfaces consisting of boundary protection devices.' },
    'NIST SC-8':   { title: 'Transmission Confidentiality and Integrity',    body: 'Implement cryptographic mechanisms to prevent unauthorized disclosure of information and detect changes during transmission.' },
    'ISO A.5.18':  { title: 'Access Rights',                                  body: 'Access rights to information and other associated assets shall be provisioned, reviewed, modified and removed in accordance with the topic-specific policy on access control.' },
    'ISO A.5.17':  { title: 'Authentication Information',                    body: 'Allocation and management of authentication information shall be controlled by a management process, including advising personnel on the appropriate handling of authentication information.' },
    'ISO A.8.13':  { title: 'Information Backup',                             body: 'Backup copies of information, software and systems shall be maintained and regularly tested in accordance with the agreed topic-specific policy on backup.' },
    'ISO A.8.8':   { title: 'Management of Technical Vulnerabilities',        body: 'Information about technical vulnerabilities of information systems in use shall be obtained, the exposure to such vulnerabilities evaluated and appropriate measures taken.' },
    'ISO A.8.2':   { title: 'Privileged Access Rights',                       body: 'The allocation and use of privileged access rights shall be restricted and managed.' },
    'ISO A.8.3':   { title: 'Information Access Restriction',                body: 'Access to information and application system functions shall be restricted in accordance with the access control policy. Anonymous or unauthenticated access shall be avoided.' },
    'ISO A.8.5':   { title: 'Secure Authentication',                         body: 'Secure authentication technologies and procedures shall be implemented based on information access restrictions and the access control policy, including account lockout for failed attempts.' },
    'ISO A.8.20':  { title: 'Networks Security',                             body: 'Networks and network devices shall be secured, managed and controlled to protect information in systems and applications. Unnecessary services and access paths shall be disabled.' },
    'ISO A.8.24':  { title: 'Use of Cryptography',                           body: 'Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented to protect confidentiality, authenticity and integrity.' },
    'NIS2 Art.21(b)': { title: 'Incident Handling',                          body: 'Entities must implement policies for handling cybersecurity incidents, including detection, reporting, and response. Limiting external attack surface reduces incident likelihood (NIS2 Art. 21 para. 2 lit. b).' },
    'NIS2 Art.21(h)': { title: 'Cryptography and Encryption',               body: 'Entities must implement policies regarding the use of cryptography and, where appropriate, encryption to protect information in transit (NIS2 Art. 21 para. 2 lit. h).' },
    'PCI Req.2.2.7': { title: 'All Non-Console Administrative Access Encrypted', body: 'All non-console administrative access must use strong cryptography. Telnet and other insecure protocols must be removed from all systems (PCI DSS v4.0, Requirement 2.2.7).' },
    'PCI Req.4.2.1': { title: 'Strong Cryptography for Transmitting PAN',   body: 'Strong cryptography is in use during transmission of PAN over open, public networks. Only trusted keys/certificates are accepted (PCI DSS v4.0, Requirement 4.2.1).' },
    'PCI Req.6.3.3': { title: 'Security Patches Are Installed',             body: 'All system components are protected from known vulnerabilities by installing applicable security patches and updates; critical patches within one month of release.' },
    'PCI Req.8.3.4': { title: 'Account Lockout',                            body: 'Invalid authentication attempts are limited. If a password-based authentication method is used, account lockout must be implemented for a defined number of failed attempts (PCI DSS v4.0, Requirement 8.3.4).' },
    'PCI Req.8.3.6': { title: 'Password Length and Complexity',             body: 'If passwords are used as authentication factors, they must have a minimum length of 12 characters and contain both numeric and alphabetic characters.' },
    'PCI Req.12.3.3': { title: 'Cryptographic Cipher Suite Review',         body: 'All cryptographic cipher suites and protocols in use are documented and reviewed at least once every 12 months. Insecure protocols and cipher suites must be removed (PCI DSS v4.0, Requirement 12.3.3).' },
};

// ── Severity metadata ──────────────────────────────────────────────────────────

const SEVERITY_COLOR = {
    critical: '#aa0808',
    high:     '#e76500',
    medium:   '#b44f00',
    low:      '#0064d9',
    info:     '#758ca4',
};

const SEVERITY_SORT_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ── View state ────────────────────────────────────────────────────────────────

const complianceState = {
    severityFilter:  null,   // 'critical' | 'high' | 'medium' | 'low' | null
    frameworkFilter: null,   // 'CIS' | 'NIST' | 'ISO' | 'NIS2' | 'PCI' | null
    expandedIds:     new Set(),
};

function setComplianceSeverityFilter(severity) {
    complianceState.severityFilter =
        complianceState.severityFilter === severity ? null : severity;
    rerenderCompliance(true);
}

function setComplianceFrameworkFilter(code) {
    complianceState.frameworkFilter =
        complianceState.frameworkFilter === code ? null : code;
    rerenderCompliance(true);
}

function clearAllComplianceFilters() {
    complianceState.severityFilter  = null;
    complianceState.frameworkFilter = null;
    rerenderCompliance(true);
}

function toggleFindingExpanded(id) {
    if (complianceState.expandedIds.has(id)) {
        complianceState.expandedIds.delete(id);
    } else {
        complianceState.expandedIds.add(id);
    }
    rerenderCompliance();
}

let _cachedFindings = null;
let _complianceVisibleCount = 0;

/** @param {boolean} [announceCount]  announce the number of visible findings (filter changes) */
function rerenderCompliance(announceCount = false) {
    if (!_cachedFindings) return;
    const el = document.getElementById('compliance-view-root');
    if (!el) return;
    // The popover anchor is replaced by the re-render
    closeFwRefPopover();
    const scrollArea = el.querySelector('.findings-scroll-area');
    const scrollTop  = scrollArea ? scrollArea.scrollTop : 0;
    rerenderKeepingFocus(() => {
        el.innerHTML    = renderComplianceView(_cachedFindings);
        const newScroll = el.querySelector('.findings-scroll-area');
        if (newScroll) newScroll.scrollTop = scrollTop;
    });
    if (announceCount) announce(t('announceFiltered', findingCountText(_complianceVisibleCount)));
}

// ── FW reference popover ──────────────────────────────────────────────────────

function showFwRefPopover(label, anchorEl) {
    closeFwRefPopover();
    const info = FW_REF_DESCRIPTIONS[label];
    if (!info) return;

    const pop = document.createElement('div');
    pop.id = 'fw-ref-popover';
    pop.className = 'fw-ref-popover';
    pop.setAttribute('role', 'tooltip');
    pop.lang = 'en';
    pop.innerHTML = `
        <div class="fw-ref-popover-label">${escapeHtml(label)}</div>
        <div class="fw-ref-popover-title">${escapeHtml(info.title)}</div>
        <div class="fw-ref-popover-body">${escapeHtml(info.body)}</div>
    `;
    document.body.appendChild(pop);

    const rect = anchorEl.getBoundingClientRect();
    const pw   = 320;
    let left = rect.left;
    let top  = rect.bottom + 6;
    if (left + pw > window.innerWidth - 12)  left = window.innerWidth - pw - 12;
    if (top + pop.offsetHeight > window.innerHeight - 12) top = rect.top - pop.offsetHeight - 6;
    pop.style.left = `${Math.max(12, left)}px`;
    pop.style.top  = `${Math.max(8, top)}px`;

    _fwRefAnchor = anchorEl;
    anchorEl.setAttribute('aria-describedby', pop.id);
    anchorEl.addEventListener('blur', closeFwRefPopover, { once: true });
    // Reference texts exist in English only
    announce(`${label}: ${info.title}. ${info.body}`, 'en');

    setTimeout(() => document.addEventListener('click', closeFwRefPopover, { once: true }), 0);
    document.addEventListener('keydown', _fwRefKeyHandler);
}

let _fwRefAnchor = null;

function closeFwRefPopover() {
    document.getElementById('fw-ref-popover')?.remove();
    _fwRefAnchor?.removeAttribute('aria-describedby');
    _fwRefAnchor?.removeEventListener('blur', closeFwRefPopover);
    _fwRefAnchor = null;
    document.removeEventListener('click', closeFwRefPopover);
    document.removeEventListener('keydown', _fwRefKeyHandler);
}

function _fwRefKeyHandler(e) {
    if (e.key === 'Escape') closeFwRefPopover();
}

// ── Top-level renderer ────────────────────────────────────────────────────────

/**
 * Render the full compliance dashboard into a string of HTML.
 * @param {Object[]} findings  All findings (fail + pass)
 * @returns {string}
 */
function renderComplianceView(findings) {
    _cachedFindings = findings;

    const failFindings = findings.filter(f => f.status === 'fail');
    const passFindings    = findings.filter(f => f.status === 'pass');
    const unknownFindings = findings.filter(f => f.status === 'unknown');
    const score           = calculateSecurityScore(findings);

    let visible = [...failFindings];
    if (complianceState.frameworkFilter) {
        visible = visible.filter(f =>
            f.frameworks.some(fw => fw.code === complianceState.frameworkFilter));
    }
    if (complianceState.severityFilter) {
        visible = visible.filter(f => f.severity === complianceState.severityFilter);
    }
    visible.sort((a, b) =>
        (SEVERITY_SORT_ORDER[a.severity] ?? 5) - (SEVERITY_SORT_ORDER[b.severity] ?? 5));
    _complianceVisibleCount = visible.length;

    return `
        <h2 class="visually-hidden" id="view-heading" tabindex="-1">${t('tabSecurity')}</h2>
        ${renderScoreHeader(findings, failFindings, score)}
        ${renderStatusBar(failFindings, visible)}
        <div class="findings-scroll-area" tabindex="0" role="region" aria-label="${t('findingsRegionLabel')}">
            ${renderFindingsByCategory(visible, unknownFindings.length)}
            ${renderUnknownSection(unknownFindings)}
            ${renderPassedSection(passFindings)}
            ${renderExcludedChecksSection()}
            ${renderDisclaimer()}
        </div>
    `;
}

// ── Score header ──────────────────────────────────────────────────────────────

function renderScoreHeader(allFindings, failFindings, score) {
    const grade   = scoreToGrade(score);
    const verdict = scoreToVerdict(score);
    const gradeColor = score >= 80 ? '#256f3a' : score >= 60 ? '#e76500' : '#aa0808';

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of failFindings) {
        if (counts[f.severity] !== undefined) counts[f.severity]++;
    }

    const kpiTiles = [
        { key: 'critical', labelKey: 'severityCritical', color: '#aa0808' },
        // Darker than SEVERITY_COLOR.high: the count needs 3:1 on the active tile tint
        { key: 'high',     labelKey: 'severityHigh',     color: '#d45d00' },
        { key: 'medium',   labelKey: 'severityMedium',   color: '#b44f00' },
        { key: 'low',      labelKey: 'severityLow',      color: '#0064d9' },
    ].map(({ key, labelKey, color }) => {
        const count    = counts[key] || 0;
        const isActive = complianceState.severityFilter === key;
        return `
            <button type="button" class="kpi-tile ${isActive ? 'kpi-tile--active' : ''} ${count === 0 ? 'kpi-tile--empty' : ''}"
                    style="--kpi-color: ${color}" data-focus-key="kpi-${key}"
                    ${count > 0
                        ? `aria-pressed="${isActive}" onclick="setComplianceSeverityFilter('${key}')"`
                        : 'aria-disabled="true"'}>
                <span class="kpi-number">${count}</span>
                <span class="kpi-label">${t(labelKey)}</span>
            </button>
        `;
    }).join('');

    const frameworkStats = {};
    for (const f of allFindings) {
        for (const fw of f.frameworks) {
            if (!frameworkStats[fw.code]) frameworkStats[fw.code] = { fail: 0, pass: 0, unknown: 0 };
            if (f.status === 'fail')         frameworkStats[fw.code].fail++;
            else if (f.status === 'pass')    frameworkStats[fw.code].pass++;
            else if (f.status === 'unknown') frameworkStats[fw.code].unknown++;
        }
    }

    const fwChips = Object.entries(FRAMEWORK_META).map(([code, meta]) => {
        const stats    = frameworkStats[code] || { fail: 0, pass: 0, unknown: 0 };
        const isActive = complianceState.frameworkFilter === code;
        const hasIssues = stats.fail > 0;
        // A framework is only "clean" when every one of its checks was evaluated
        const evaluated = stats.pass > 0 && stats.unknown === 0;
        return `
            <button type="button" class="fw-chip ${isActive ? 'fw-chip--active' : ''} ${hasIssues ? 'fw-chip--issues' : evaluated ? 'fw-chip--clean' : ''}"
                    style="--chip-color: ${meta.color}" data-focus-key="fw-${code}" aria-pressed="${isActive}"
                    onclick="setComplianceFrameworkFilter('${code}')"
                    title="${meta.label}">
                ${code}
                ${hasIssues
                    ? `<span class="fw-chip-count" aria-hidden="true">${stats.fail}</span><span class="visually-hidden">: ${findingCountText(stats.fail)}</span>`
                    : evaluated ? `<span class="fw-chip-clean" aria-hidden="true">✓</span><span class="visually-hidden">: ${t('fwChipClean')}</span>` : ''}
            </button>
        `;
    }).join('');

    const hasFilter = complianceState.severityFilter || complianceState.frameworkFilter;
    const clearBtn  = hasFilter
        ? `<button type="button" class="chip-clear-btn" data-focus-key="clear-filters" onclick="clearAllComplianceFilters()">${t('clearFiltersBtn')}</button>` : '';

    return `
        <div class="compliance-header">
            <div class="compliance-score-area">
                <div class="score-kpi-block">
                    <div class="score-kpi-number" style="color:${gradeColor}">
                        <span class="score-kpi-val">${score}</span><span class="score-kpi-denom">/100</span>
                    </div>
                    <div class="score-kpi-detail">
                        <div class="score-progress-bar" role="progressbar" aria-label="${t('scoreAriaLabel')}"
                             aria-valuenow="${score}" aria-valuemin="0" aria-valuemax="100">
                            <div class="score-progress-fill" style="width:${score}%;background:${gradeColor}"></div>
                        </div>
                        <div class="score-grade-row">
                            <span class="score-grade-letter" style="color:${gradeColor}">${grade}</span>
                            <span class="score-verdict">${verdict}</span>
                        </div>
                    </div>
                </div>
            </div>
            <div class="compliance-separator"></div>
            <div class="compliance-metrics-area">
                <div class="kpi-row">${kpiTiles}</div>
                <div class="fw-filter-row">
                    <span class="filter-row-label">${t('frameworksLabel')}</span>
                    ${fwChips}
                    ${clearBtn}
                </div>
            </div>
        </div>
    `;
}

// ── Status bar ────────────────────────────────────────────────────────────────

function renderStatusBar(allFail, visible) {
    const af = complianceState.frameworkFilter;
    const as = complianceState.severityFilter;
    const hasFilter = af || as;

    const labels = [];
    if (af) labels.push(FRAMEWORK_META[af]?.label || af);
    if (as) labels.push(t('severity' + as.charAt(0).toUpperCase() + as.slice(1)));

    return `
        <div class="compliance-status-bar">
            <span class="status-bar-count">${visible.length}</span>
            <span class="status-bar-label">
                ${visible.length !== 1 ? t('findingPlural') : t('findingSingular')}
                ${hasFilter
                    ? `<span class="status-bar-filter">· ${t('filteredBy')} ${escapeHtml(labels.join(', '))}</span>`
                    : `<span class="status-bar-total">(${t('ofTotal')} ${allFail.length})</span>`}
            </span>
            ${hasFilter
                ? `<button type="button" class="status-bar-clear" data-focus-key="clear-filters" onclick="clearAllComplianceFilters()">${t('clearAllFiltersBtn')}</button>`
                : ''}
        </div>
    `;
}

// ── Findings grouped by category ──────────────────────────────────────────────

function renderFindingsByCategory(findings, unknownCount = 0) {
    if (findings.length === 0 && (complianceState.severityFilter || complianceState.frameworkFilter)) {
        return `
            <div class="findings-empty-state">
                <div class="findings-empty-title">${t('noFilterMatchTitle')}</div>
                <div class="findings-empty-sub">${t('noFilterMatchSub')}</div>
            </div>
        `;
    }
    if (findings.length === 0) {
        return `
            <div class="findings-empty-state">
                <div class="findings-empty-icon" aria-hidden="true">✓</div>
                <div class="findings-empty-title">${t('noFindingsTitle')}</div>
                <div class="findings-empty-sub">${unknownCount ? t('noFindingsSubUnknown', unknownCount) : t('noFindingsSub')}</div>
            </div>
        `;
    }

    const order   = [];
    const grouped = {};
    for (const f of findings) {
        if (!grouped[f.category]) { grouped[f.category] = []; order.push(f.category); }
        grouped[f.category].push(f);
    }

    return order.map(cat => {
        const catF = grouped[cat];
        const n    = catF.length;
        const topColor = SEVERITY_COLOR[catF[0].severity] || SEVERITY_COLOR.info;
        const issueText = n === 1 ? t('issueCount') : t('issuesCount', n);
        return `
            <div class="category-group">
                <div class="category-header" style="--cat-color: ${topColor}">
                    <h3 class="category-header-name">${escapeHtml(cat)}</h3>
                    <span class="category-header-count">${issueText}</span>
                </div>
                <div class="category-findings">
                    ${catF.map(renderFindingCard).join('')}
                </div>
            </div>
        `;
    }).join('');
}

// ── Finding card ──────────────────────────────────────────────────────────────

function renderFindingCard(f) {
    const isExpanded   = complianceState.expandedIds.has(f.id);
    const stripeColor  = SEVERITY_COLOR[f.severity] || '#64748b';
    const sevLabel     = t('severity' + f.severity.charAt(0).toUpperCase() + f.severity.slice(1));

    const fwTags = f.frameworks.map(fw => {
        const meta    = FRAMEWORK_META[fw.code] || { color: '#6b7d93' };
        const hasInfo = !!FW_REF_DESCRIPTIONS[fw.label];
        const style   = `color:${meta.color};background:${meta.color}18;border-color:${meta.color}33`;
        // Only tags with a reference description are interactive
        return hasInfo
            ? `<button type="button" class="fw-tag fw-tag--clickable" style="${style}"
                       onclick="event.stopPropagation();showFwRefPopover('${fw.label}',this)">${fw.label}</button>`
            : `<span class="fw-tag" style="${style}">${fw.label}</span>`;
    }).join('');

    const titleId = `ftitle-${f.id}`;
    const bodyId  = `fbody-${f.id}`;
    const body = isExpanded ? `
        <div class="finding-body" id="${bodyId}">
            ${f.description ? `<p class="finding-description">${escapeHtml(f.description)}</p>` : ''}
            ${f.affectedItems.length > 0 ? `
                <div class="finding-section">
                    <div class="finding-section-title">${t('labelAffected')}</div>
                    <ul class="finding-affected-list">
                        ${f.affectedItems.map(i => `<li>${escapeHtml(i)}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            ${f.remediation ? `
                <div class="finding-section finding-section--remediation">
                    <div class="finding-section-title">${t('labelRemediation')}</div>
                    <p class="finding-remediation">${escapeHtml(f.remediation)}</p>
                </div>
            ` : ''}
        </div>
    ` : '';

    return `
        <div class="finding-card" style="--stripe-color: ${stripeColor}">
            <div class="finding-stripe"></div>
            <div class="finding-card-content">
                <div class="finding-header" onclick="toggleFindingExpanded('${f.id}')">
                    <div class="finding-header-main">
                        <span class="severity-pill severity-pill--${f.severity}">${sevLabel}</span>
                    </div>
                    <div class="finding-title" id="${titleId}">${escapeHtml(f.title)}</div>
                    <div class="finding-meta">
                        <div class="finding-fw-tags">${fwTags}</div>
                    </div>
                    <button type="button" class="finding-toggle ${isExpanded ? 'finding-toggle--open' : ''}"
                            aria-expanded="${isExpanded}" aria-labelledby="${titleId}"
                            ${isExpanded ? `aria-controls="${bodyId}"` : ''} data-focus-key="toggle-${f.id}"
                            onclick="event.stopPropagation();toggleFindingExpanded('${f.id}')"
                    ><span class="finding-toggle-icon" aria-hidden="true">▶</span></button>
                </div>
                ${body}
            </div>
        </div>
    `;
}

// ── Passed checks section ─────────────────────────────────────────────────────

function renderPassedSection(passFindings) {
    if (passFindings.length === 0) return '';

    const cards = passFindings.map(f => `
        <div class="finding-card finding-card--pass" style="--stripe-color: #34d399">
            <div class="finding-stripe"></div>
            <div class="finding-card-content">
                <div class="finding-header finding-header--pass">
                    <div class="finding-header-main">
                        <span class="severity-pill severity-pill--pass">${t('severityPass')}</span>
                        <span class="finding-category">${escapeHtml(f.category)}</span>
                    </div>
                    <div class="finding-title finding-title--pass">${escapeHtml(f.title)}</div>
                </div>
            </div>
        </div>
    `).join('');

    return `
        <div class="passed-section">
            <h3 class="passed-section-header">
                ${t('passedChecks')} <span class="passed-count">${passFindings.length}</span>
            </h3>
            <div class="passed-list">${cards}</div>
        </div>
    `;
}

// ── Checks that could not be evaluated ───────────────────────────────────────

function renderUnknownSection(unknownFindings) {
    if (unknownFindings.length === 0) return '';

    const cards = unknownFindings.map(f => `
        <div class="finding-card finding-card--unknown" style="--stripe-color: #94a3b8">
            <div class="finding-stripe"></div>
            <div class="finding-card-content">
                <div class="finding-header finding-header--pass">
                    <div class="finding-header-main">
                        <span class="severity-pill severity-pill--unknown">${t('severityUnknown')}</span>
                        <span class="finding-category">${escapeHtml(f.category)}</span>
                    </div>
                    <div class="finding-title finding-title--pass">${escapeHtml(f.title)}</div>
                </div>
                ${f.affectedItems?.length ? `
                <div class="unknown-detail">
                    ${f.description ? `<p>${escapeHtml(f.description)}</p>` : ''}
                    <ul>${f.affectedItems.map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul>
                    ${f.remediation ? `<p>${escapeHtml(f.remediation)}</p>` : ''}
                </div>` : ''}
            </div>
        </div>
    `).join('');

    return `
        <div class="passed-section unknown-section">
            <h3 class="passed-section-header unknown-section-header">
                ${t('unknownChecks')} <span class="passed-count unknown-count">${unknownFindings.length}</span>
            </h3>
            <p class="unknown-section-hint">${t('unknownDesc')}</p>
            <div class="passed-list">${cards}</div>
        </div>
    `;
}

// ── Excluded checks ───────────────────────────────────────────────────────────

function renderExcludedChecksSection() {
    const filterIcon = `<svg class="excluded-checks-icon" width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <path d="M2 3h12l-4.5 5.5V13l-3-1.5V8.5L2 3z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
    </svg>`;
    return `
        <details class="excluded-checks-section">
            <summary class="excluded-checks-summary">
                ${filterIcon}
                <span>${t('excludedChecksTitle')}</span>
                <span class="excluded-checks-toggle" aria-hidden="true">▶</span>
            </summary>
            <p class="excluded-checks-body">${t('excludedChecksDesc')}</p>
        </details>
    `;
}

// ── Disclaimer ────────────────────────────────────────────────────────────────

function renderDisclaimer() {
    const icon = `<svg class="disclaimer-icon" width="18" height="18" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <circle cx="8" cy="8" r="7.25" stroke="currentColor" stroke-width="1.5"/>
        <rect x="7.25" y="6.5" width="1.5" height="5" rx=".75" fill="currentColor"/>
        <rect x="7.25" y="4" width="1.5" height="1.5" rx=".75" fill="currentColor"/>
    </svg>`;
    return `
        <div class="disclaimer-box compliance-disclaimer">
            <div class="disclaimer-header">
                ${icon}
                <strong class="disclaimer-title">${t('disclaimerTitle')}</strong>
            </div>
            <ul class="disclaimer-list">
                <li>${t('disclaimerItem1')}</li>
                <li>${t('disclaimerItem2')}</li>
                <li>${t('disclaimerItem3')}</li>
                <li>${t('disclaimerItem4')}</li>
                <li>${t('disclaimerItem5')}</li>
            </ul>
            <p class="disclaimer-footer">${t('disclaimerFooter')}</p>
        </div>
    `;
}
