'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const vm     = require('node:vm');
const { loadApp, loadViews, runChecks } = require('./load-app.js');

function setup() {
    const app = loadViews(loadApp());
    const findings = runChecks(app, { CIFS_Min_Protocol: 'SMB1' });
    const smb1 = findings.find(f => f.id === 'syn-smb1-enabled');
    assert.ok(smb1, 'fixture must produce a failing SMBv1 finding');
    return { app, findings, smb1 };
}

test('collapsed finding card has a named toggle button with aria-expanded=false', () => {
    const { app, smb1 } = setup();
    const html = app.renderFindingCard(smb1);
    assert.match(html, /<button type="button" class="finding-toggle[^"]*"\s+aria-expanded="false" aria-labelledby="ftitle-syn-smb1-enabled"/);
    assert.match(html, /id="ftitle-syn-smb1-enabled"/);
    assert.doesNotMatch(html, /aria-controls=/);
    // The button sits inside the clickable header, which would toggle a second time
    assert.match(html, /onclick="event\.stopPropagation\(\);toggleFindingExpanded\('syn-smb1-enabled'\)"/);
});

test('expanded finding card points aria-controls at the rendered body', () => {
    const { app, smb1 } = setup();
    vm.runInContext("complianceState.expandedIds.add('syn-smb1-enabled')", app);
    const html = app.renderFindingCard(smb1);
    assert.match(html, /aria-expanded="true"/);
    assert.match(html, /aria-controls="fbody-syn-smb1-enabled"/);
    assert.match(html, /<div class="finding-body" id="fbody-syn-smb1-enabled">/);
});

test('filter controls expose their state instead of being disabled', () => {
    const { app, findings, smb1 } = setup();
    vm.runInContext("complianceState.severityFilter = 'critical'", app);
    const header = app.renderScoreHeader(findings, [smb1], 50);
    assert.doesNotMatch(header, /\sdisabled[\s>]/);
    assert.match(header, /data-focus-key="kpi-critical"\s+aria-pressed="true"/);
    assert.match(header, /data-focus-key="kpi-low"\s+aria-disabled="true"/);
    const html = app.renderComplianceView(findings);
    assert.match(html, /data-focus-key="fw-CIS" aria-pressed="false"/);
    assert.match(html, /role="progressbar" aria-label="Security score"/);
    assert.match(html, /class="findings-scroll-area" tabindex="0" role="region" aria-label="Findings"/);
    assert.match(html, /id="view-heading" tabindex="-1"/);
});

test('framework chips name their finding count for screen readers', () => {
    const app = loadViews(loadApp());
    const findings = runChecks(app, { CIFS_Min_Protocol: 'SMB1', w3_redirectHTTPS: 'no', w3_runsyshsts: 'no',
        Passwdstrength_isApplyPasswdRule: '0', CIFS_Enable_Server_Signing: '0' });
    const html = app.renderComplianceView(findings);
    assert.match(html, /<span class="fw-chip-count" aria-hidden="true">5<\/span><span class="visually-hidden">: 5 issues<\/span>/);
    assert.equal(app.findingCountText(1), '1 issue');
});

test('framework tags with a reference text open the popover', () => {
    const { app, smb1 } = setup();
    const html = app.renderFindingCard({ ...smb1, frameworks: [{ code: 'CIS', label: 'CIS 9.4' }] });
    assert.match(html, /<button type="button" class="fw-tag fw-tag--clickable"[^>]*\s+onclick="event\.stopPropagation\(\);showFwRefPopover\('CIS 9\.4',this\)">CIS 9\.4<\/button>/);
});

test('framework tags without a reference text are not buttons', () => {
    const { app, smb1 } = setup();
    const html = app.renderFindingCard({ ...smb1, frameworks: [{ code: 'CIS', label: 'CIS 0.0' }] });
    assert.match(html, /<span class="fw-tag" [^>]*>CIS 0\.0<\/span>/);
    assert.doesNotMatch(html, /<button[^>]*fw-tag/);
});

test('best practice cards have a toggle button with aria-expanded', () => {
    const { app } = setup();
    const card = app._renderBPFindingCard({
        id: 'bp-x', title: 'Example', severity: 'low', status: 'fail',
        category: 'Cat', description: '', affectedItems: [], remediation: '',
    });
    assert.match(card, /aria-expanded="false" aria-labelledby="bptitle-bp-x"/);
    assert.match(card, /onclick="event\.stopPropagation\(\);toggleBPExpanded\('bp-x'\)"/);
    assert.doesNotMatch(card, /aria-controls=/);
});

test('expanded best practice card points aria-controls at the rendered body', () => {
    const { app } = setup();
    vm.runInContext("bpState.expandedIds.add('bp-x')", app);
    const card = app._renderBPFindingCard({
        id: 'bp-x', title: 'Example', severity: 'low', status: 'fail',
        category: 'Cat', description: 'Text', affectedItems: [], remediation: '',
    });
    assert.match(card, /aria-expanded="true"/);
    assert.match(card, /aria-controls="bpbody-bp-x"/);
    assert.match(card, /<div class="finding-body" id="bpbody-bp-x">/);
});

test('a framework with unevaluated checks is not shown as clean', () => {
    const { app } = setup();
    const nis2 = [{ code: 'NIS2', label: 'NIS2 Art.21(b)' }];
    const findings = [
        { id: 'a', status: 'pass',    severity: 'info', frameworks: nis2 },
        { id: 'b', status: 'unknown', severity: 'info', frameworks: nis2 },
    ];
    const header = app.renderScoreHeader(findings, [], 100);
    const chip = header.match(/<button[^>]*data-focus-key="fw-NIS2"[\s\S]*?<\/button>/)[0];
    assert.doesNotMatch(chip, /fw-chip--clean/);
    assert.doesNotMatch(chip, /no issues/);
});

test('QuickConnect findings cite the same frameworks in every state', () => {
    const { app } = setup();
    const codes = cfg => {
        const f = runChecks(app, cfg).find(x => x.id.startsWith('syn-qc-'));
        return f.frameworks.map(fw => fw.label).join('|');
    };
    const on  = codes({ QUICKCONNECT_config: '{"quickconnect":{"enabled":true}}' });
    assert.equal(codes({ QUICKCONNECT_config: '{"quickconnect":{"enabled":false}}' }), on);
    assert.equal(codes({}), on);
});

test('status bar names the severity filter with its translated label', () => {
    const { app, smb1 } = setup();
    vm.runInContext("complianceState.severityFilter = 'critical'", app);
    const bar = app.renderStatusBar([smb1], [smb1]);
    assert.match(bar, /filtered by Critical/);
});

test('an empty filter result does not claim that all checks passed', () => {
    const { app } = setup();
    vm.runInContext("complianceState.severityFilter = 'low'", app);
    const html = app.renderFindingsByCategory([], 0);
    assert.doesNotMatch(html, /No Issues Found|All security checks passed/);
    assert.match(html, /No findings match the filter/);
});

function compareFixture(configA, configB) {
    const side = (fileName, config) => ({
        fileName,
        info: { unique: 'synology_x_ds220+', dsm_majorversion: '7', dsm_minorversion: '2', dsm_buildnumber: '1' },
        config: new Map(Object.entries(config)),
    });
    return [side('a.dss', configA), side('b.dss', configB)];
}

test('compare view lists differences with headers and never prints hidden values', () => {
    const app = loadViews(loadApp());
    const [a, b] = compareFixture(
        { FTP_isEnableFTP: '1', Ad_passwd: 'secret-a', FIREWALL_rules: 'r'.repeat(40), SNMP_isEnableSNMP: '0' },
        { FTP_isEnableFTP: '0', Ad_passwd: 'secret-b', FIREWALL_rules: 's'.repeat(40), SNMP_isEnableSNMP: '0' },
    );
    const html = app.renderCompareView(a, b);
    assert.match(html, /id="view-heading" tabindex="-1"/);
    assert.match(html, /data-focus-key="compare-show-all"\s+aria-pressed="false"/);
    assert.match(html, /class="compare-scroll" tabindex="0" role="region" aria-label="[^"]+"/);
    assert.match(html, /<th scope="rowgroup" colspan="4" class="compare-group">FTP<\/th>/);
    assert.match(html, /<th scope="row"><code>FTP_isEnableFTP<\/code><\/th>/);
    assert.doesNotMatch(html, /secret-a|secret-b|rrrr|ssss/);
    // Same values stay out until the toggle is pressed
    assert.doesNotMatch(html, /SNMP_isEnableSNMP/);
    vm.runInContext('compareState.showAll = true', app);
    assert.match(app.renderCompareView(a, b), /SNMP_isEnableSNMP/);
});

test('compare view says so when the backups do not differ', () => {
    const app = loadViews(loadApp());
    const [a, b] = compareFixture({ FTP_isEnableFTP: '1' }, { FTP_isEnableFTP: '1' });
    const html = app.renderCompareView(a, b);
    assert.match(html, /No differences in which checks are open or in their affected items\./);
    assert.match(html, /No differences in the system settings\./);
    assert.doesNotMatch(html, /<table/);
});

test('compare view lists check results that occur in one backup only', () => {
    const app = loadViews(loadApp());
    const [a, b] = compareFixture({ CIFS_Min_Protocol: 'SMB1' }, { CIFS_Min_Protocol: 'SMB2' });
    const html = app.renderCompareView(a, b);
    assert.match(html, /<h3 class="compare-section-title" id="compare-findings-title">Check results<\/h3>/);
    assert.match(html, /<h4 class="compare-group-title">Only in backup A<\/h4>\s*<ul class="compare-findings" role="list">/);
    assert.doesNotMatch(html, /Only in backup B/);
});

test('compare view shows check results even when the settings are equal', () => {
    const app = loadViews(loadApp());
    const [a, b] = compareFixture({ CIFS_Min_Protocol: 'SMB2' }, { CIFS_Min_Protocol: 'SMB2' });
    a.schedulerTasks = [{ app: 'SYNO.SDS.TaskScheduler.Recycle', state: 'enabled' }];
    b.schedulerTasks = [{ app: 'SYNO.SDS.Other', state: 'enabled' }];
    const html = app.renderCompareView(a, b);
    assert.match(html, /No differences in the system settings\./);
    assert.match(html, /Only in backup B/);
});

test('compare view shows each side in its own cell with the matching status', () => {
    const app = loadViews(loadApp());
    const [a, b] = compareFixture(
        { Terminal_SSHPort: '22', X_missing_in_b: '1', X_unreadable: null, X_empty: '' },
        { Terminal_SSHPort: '2222', X_unreadable: '1', X_empty: '1' },
    );
    const html = app.renderCompareView(a, b);
    const row = key => html.match(new RegExp(`<code>${key}</code></th>([\\s\\S]*?)</tr>`))[1];
    assert.match(row('Terminal_SSHPort'), /<td><code>22<\/code><\/td>\s*<td><code>2222<\/code><\/td>\s*<td class="compare-status">Different<\/td>/);
    assert.match(row('X_missing_in_b'), /<td><code>1<\/code><\/td>\s*<td>[^<]*<span[^>]*>not present<\/span><\/td>\s*<td class="compare-status">Only in A<\/td>/);
    assert.match(row('X_unreadable'), /not readable[\s\S]*<code>1<\/code>[\s\S]*Not comparable/);
    assert.match(row('X_empty'), /\(empty\)[\s\S]*<code>1<\/code>[\s\S]*Different/);
    // Headers name the right file per side
    assert.match(html, /Backup A<\/h3>[\s\S]*a\.dss[\s\S]*Backup B<\/h3>[\s\S]*b\.dss/);
});

test('compare view escapes markup from both backups', () => {
    const app = loadViews(loadApp());
    const [a, b] = compareFixture({ 'X_<b>key': '<i>a' }, { 'X_<b>key': '<i>b' });
    a.fileName = '<img src=x>.dss';
    const html = app.renderCompareView(a, b);
    assert.doesNotMatch(html, /<b>key|<i>a|<i>b|<img/);
    assert.match(html, /&lt;img src=x&gt;\.dss/);
    assert.match(html, /X_&lt;b&gt;key/);
});

test('compare toggle shows unchanged settings and reports its state', () => {
    const app = loadViews(loadApp());
    const [a, b] = compareFixture({ FTP_isEnableFTP: '1', SNMP_isEnableSNMP: '0' }, { FTP_isEnableFTP: '0', SNMP_isEnableSNMP: '0' });
    vm.runInContext('rerenderKeepingFocus = () => {}; announce = () => {};', app);
    const html = app.renderCompareView(a, b);
    assert.match(html, /aria-pressed="false" onclick="toggleCompareShowAll\(\)"/);
    app.toggleCompareShowAll();
    const shown = app.renderCompareView(a, b);
    assert.match(shown, /aria-pressed="true"/);
    assert.match(shown, /SNMP_isEnableSNMP/);
    app.toggleCompareShowAll();
    assert.match(app.renderCompareView(a, b), /aria-pressed="false"/);
});

test('compare view shows both severities when the backups rate a shared finding differently', () => {
    const app = loadViews(loadApp());
    const f = (severity, items) => ({ id: 'x', status: 'fail', severity, title: 'T', kind: 'security', affectedItems: items });
    const diff = app.diffFindings([f('high', ['a'])], [f('medium', ['b'])]);
    const html = app.renderCompareFindings(diff);
    assert.match(html, /Backup A: <span class="severity-pill severity-pill--high">[\s\S]*Backup B: <span class="severity-pill severity-pill--medium">/);
    assert.match(html, /only in A: a; only in B: b/);
    const same = app.renderCompareFindings(app.diffFindings([f('high', ['a'])], [f('high', ['b'])]));
    assert.doesNotMatch(same, /Backup A:/);
});

test('compare view escapes affected items on both sides', () => {
    const app = loadViews(loadApp());
    const f = items => [{ id: 'x', status: 'fail', severity: 'high', title: 'T', kind: 'security', affectedItems: items }];
    const html = app.renderCompareFindings(app.diffFindings(f(['<i>a']), f(['<i>b'])));
    assert.doesNotMatch(html, /<i>/);
    assert.match(html, /only in A: &lt;i&gt;a; only in B: &lt;i&gt;b/);
});

test('compare count error follows a language switch', () => {
    const app = loadViews(loadApp());
    const root = { innerHTML: '' };
    app.document.getElementById = id => (id === 'app' ? root : null);
    app.document.querySelector = () => null;
    app.processComparison([{}]);
    assert.match(root.innerHTML, /Select exactly two \.dss files to compare\./);
    app.setLanguage('de');
    assert.match(root.innerHTML, /Für den Vergleich genau zwei \.dss-Dateien auswählen\./);
});
