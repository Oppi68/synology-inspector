'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const { loadApp } = require('./load-app.js');

// Values created inside the vm context have their own Array/Object prototypes.
const plain = v => JSON.parse(JSON.stringify(v));

function diff(a, b) {
    const app = loadApp();
    return plain(app.diffConfigMaps(new Map(Object.entries(a)), new Map(Object.entries(b))));
}

const byKey = entries => Object.fromEntries(entries.map(e => [e.key, e]));

test('classifies keys as only in A, only in B, changed or same', () => {
    const result = byKey(diff(
        { FTP_isEnableFTP: '1', SNMP_isEnableSNMP: '0', AFP_isEnableAFP: '0' },
        { FTP_isEnableFTP: '0', SNMP_isEnableSNMP: '0', NFS_isEnableNFS: '1' },
    ));
    assert.equal(result.FTP_isEnableFTP.status, 'changed');
    assert.equal(result.SNMP_isEnableSNMP.status, 'same');
    assert.equal(result.AFP_isEnableAFP.status, 'onlyA');
    assert.equal(result.NFS_isEnableNFS.status, 'onlyB');
});

test('returns entries sorted by key', () => {
    const keys = diff({ b: '1', a: '1' }, { c: '1' }).map(e => e.key);
    assert.deepEqual(keys, ['a', 'b', 'c']);
});

test('treats unreadable values as not comparable, never as equal', () => {
    const result = byKey(diff(
        { X_both_null: null, X_one_null: null, X_only_a_null: null, X_b_null: '1' },
        { X_both_null: null, X_one_null: '1', X_b_null: null },
    ));
    assert.equal(result.X_both_null.status, 'unknown');
    assert.equal(result.X_one_null.status, 'unknown');
    assert.equal(result.X_b_null.status, 'unknown');
    assert.equal(result.X_only_a_null.status, 'onlyA');
});

test('shows short values of harmless keys', () => {
    const [entry] = diff({ Terminal_SSHPort: '22' }, { Terminal_SSHPort: '2222' });
    assert.equal(entry.a, '22');
    assert.equal(entry.b, '2222');
});

test('never shows values of secret-like keys', () => {
    const secretKeys = ['Ad_passwd', 'LDAP_szPasswd', 'NOTIFY_smtpconf', 'retain_admin_pwd',
        'SOME_api_token', 'SOME_secret', 'SOME_prikey', 'NOTIFY_mailfrom', 'SOME_cert',
        'NetBKP_PairID', 'X_PrivateMaterial', 'NOTIFY_filter'];
    const a = Object.fromEntries(secretKeys.map(k => [k, 'x']));
    const b = Object.fromEntries(secretKeys.map(k => [k, 'y']));
    for (const entry of diff(a, b)) {
        assert.equal(entry.status, 'changed', entry.key);
        assert.equal(entry.a, null, entry.key);
        assert.equal(entry.b, null, entry.key);
    }
});

test('never shows long values, whatever the key', () => {
    const long = 'x'.repeat(33);
    const [entry] = diff({ FIREWALL_config: long }, { FIREWALL_config: long + 'y' });
    assert.equal(entry.status, 'changed');
    assert.equal(entry.a, null);
    assert.equal(entry.b, null);
});

test('shows values up to 32 characters and hides longer ones', () => {
    const result = byKey(diff(
        { X_shown: 'a'.repeat(32), X_hidden: 'a'.repeat(33) },
        { X_shown: 'b'.repeat(32), X_hidden: 'b'.repeat(33) },
    ));
    assert.equal(result.X_shown.a, 'a'.repeat(32));
    assert.equal(result.X_hidden.a, null);
    assert.equal(result.X_hidden.b, null);
});

test('hides a value on one side only when only that side is unsafe', () => {
    const [entry] = diff({ w3_server_header: 'nginx' }, { w3_server_header: 'y'.repeat(40) });
    assert.equal(entry.a, 'nginx');
    assert.equal(entry.b, null);
});

function diffChecks(configA, configB) {
    const app = loadApp();
    const { runChecks } = require('./load-app.js');
    return plain(app.diffFindings(runChecks(app, configA), runChecks(app, configB)));
}

const ids = list => list.map(f => (f.a ?? f).id);

test('lists failed checks that occur in one backup only', () => {
    const result = diffChecks({ CIFS_Min_Protocol: 'SMB1' }, { CIFS_Min_Protocol: 'SMB2' });
    assert.ok(ids(result.onlyA).includes('syn-smb1-enabled'));
    assert.ok(!ids(result.onlyB).includes('syn-smb1-enabled'));
    // Passed checks never count as a difference
    assert.ok(!ids(result.onlyB).some(id => id.startsWith('syn-smb1')));
});

test('shows a check that could not be evaluated instead of hiding it', () => {
    const result = diffChecks({ CIFS_Min_Protocol: 'SMB1' }, {});
    assert.ok(ids(result.onlyA).includes('syn-smb1-enabled'));
    const unknown = result.onlyB.find(f => f.id === 'syn-smb1-unknown');
    assert.ok(unknown, 'the unknown finding must appear on side B');
    assert.equal(unknown.status, 'unknown');
});

test('reports changed affected items for a check that fails in both', () => {
    const app = loadApp();
    const a = [{ id: 'x', status: 'fail', affectedItems: ['SSH 22', 'DSM HTTP 5000'] }];
    const b = [{ id: 'x', status: 'fail', affectedItems: ['DSM HTTP 5000', 'DSM HTTPS 5001'] }];
    const result = plain(app.diffFindings(a, b));
    assert.deepEqual(result.onlyA, []);
    assert.deepEqual(result.onlyB, []);
    assert.equal(result.itemsChanged.length, 1);
    assert.deepEqual(result.itemsChanged[0].itemsOnlyA, ['SSH 22']);
    assert.deepEqual(result.itemsChanged[0].itemsOnlyB, ['DSM HTTPS 5001']);
    assert.equal(plain(app.diffFindings(a, a)).itemsChanged.length, 0);
});

test('reports affected items that were only added or only removed', () => {
    const app = loadApp();
    const f = items => [{ id: 'x', status: 'fail', affectedItems: items }];
    const added = plain(app.diffFindings(f(['a']), f(['a', 'b'])));
    assert.deepEqual(added.itemsChanged[0].itemsOnlyA, []);
    assert.deepEqual(added.itemsChanged[0].itemsOnlyB, ['b']);
    const removed = plain(app.diffFindings(f(['a', 'b']), f(['a'])));
    assert.deepEqual(removed.itemsChanged[0].itemsOnlyA, ['b']);
    assert.deepEqual(removed.itemsChanged[0].itemsOnlyB, []);
});

test('translation placeholders insert values literally', () => {
    const app = loadApp();
    assert.equal(app.t('compareItemsOnlyA', 'R$&D'), 'only in A: R$&D');
    assert.equal(app.t('compareFindingsSummary', '{1}', 2, 3), '{1} only in A, 2 only in B, 3 with different affected items');
});
