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
