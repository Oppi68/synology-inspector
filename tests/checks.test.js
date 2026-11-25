'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('node:fs');
const path   = require('node:path');
const { loadApp, runChecks, ROOT } = require('./load-app.js');

const DAY = 86400000;
const today = () => Math.floor(Date.now() / DAY);

function byId(findings, id) {
    return findings.find(f => f.id === id);
}

function ids(findings) {
    return findings.map(f => f.id);
}

test('isAccountActive interprets the expire column', () => {
    const app = loadApp();
    assert.equal(app.isAccountActive({ expire: -1 }), true);
    assert.equal(app.isAccountActive({ expire: 1 }), false);
    assert.equal(app.isAccountActive({ expire: today() + 30 }), true);
    assert.equal(app.isAccountActive({ expire: today() - 30 }), false);
    for (const expire of [0, -2, null, undefined, NaN, 1.5]) {
        assert.equal(app.isAccountActive({ expire }), null, String(expire));
    }
});

test('account with an unrecognized expire value is unknown, not active', () => {
    const app = loadApp();
    const odd = runChecks(app, {}, { users: [
        { name: 'admin', uid: 1024, expire: 0 },
        { name: 'guest', uid: 1025, expire: null },
        { name: 'alice', uid: 1026, expire: -1 },
    ], adminMembers: ['admin', 'alice'] });
    for (const id of ['syn-admin-unknown', 'syn-guest-unknown', 'syn-admins-unknown']) assert.ok(ids(odd).includes(id), id);

    const users = ['a', 'b', 'c'].map((name, i) => ({ name, uid: 1030 + i, expire: -1 }));
    users.push({ name: 'd', uid: 1040, expire: 0 });
    const many = runChecks(app, {}, { users, adminMembers: ['a', 'b', 'c', 'd'] });
    assert.equal(byId(many, 'syn-admins-many').status, 'fail');
});

test('missing data is reported as unknown, never as passed', () => {
    const app = loadApp();
    const findings = runChecks(app, {}, { autoBackupConfigured: null });
    const unknown = [...findings.filter(f => f.status === 'unknown').map(f => f.id)].sort();
    assert.deepEqual(unknown, [
        'syn-account-protection-unknown', 'syn-admin-unknown', 'syn-admins-unknown', 'syn-advisories-unknown', 'syn-autoblock-unknown', 'syn-config-backup-unknown', 'syn-csrf-unknown',
        'syn-dos-unknown', 'syn-firewall-unknown', 'syn-guest-unknown', 'syn-hsts-unknown', 'syn-https-redirect-unknown',
        'syn-iframe-unknown', 'syn-ip-check-unknown', 'syn-notify-unknown', 'syn-ntlmv1-unknown', 'syn-pwd-policy-unknown',
        'syn-qc-unknown', 'syn-security-updates-unknown', 'syn-services-unknown', 'syn-smb-signing-unknown',
        'syn-smb1-unknown', 'syn-ssh-unknown', 'syn-telnet-unknown', 'syn-tls-unknown',
    ]);
});

test('settings verified in real backups pass only with their explicit value', () => {
    const app = loadApp();
    const passes = runChecks(app, {}, { autoBackupConfigured: null }).filter(f => f.status === 'pass').map(f => f.id);
    for (const id of ['syn-ssh-disabled', 'syn-telnet-disabled', 'syn-ntlmv1-disabled', 'syn-guest-disabled', 'syn-admins-ok']) {
        assert.ok(!passes.includes(id), `${id} must not pass without data`);
    }
    const off = runChecks(app, { Terminal_isEnableSSH: '0', Terminal_isEnableTelnet: '0', CIFS_Enable_NTLMv1_Auth: '0' });
    for (const id of ['syn-ssh-disabled', 'syn-telnet-disabled', 'syn-ntlmv1-disabled']) assert.ok(ids(off).includes(id), id);
});

test('missing guest row or no active administrator is unknown', () => {
    const app = loadApp();
    const users = [{ name: 'alice', uid: 1026, expire: -1 }];
    assert.ok(ids(runChecks(app, {}, { users })).includes('syn-guest-unknown'));
    const inactive = runChecks(app, {}, { users: [{ name: 'admin', uid: 1024, expire: 1 }], adminMembers: ['admin'] });
    assert.ok(ids(inactive).includes('syn-admins-unknown'));
});

test('unknown findings do not change the score', () => {
    const app = loadApp();
    const fail = { id: 'x', status: 'fail', severity: 'high' };
    const unknown = { id: 'y', status: 'unknown', severity: 'info' };
    assert.equal(app.calculateSecurityScore([fail, unknown]), app.calculateSecurityScore([fail]));
});

test('active default admin fails, deactivated admin passes', () => {
    const app = loadApp();
    const active = runChecks(app, {}, { users: [{ name: 'admin', uid: 1024, expire: -1 }] });
    assert.equal(byId(active, 'syn-admin-active').status, 'fail');
    const off = runChecks(app, {}, { users: [{ name: 'admin', uid: 1024, expire: 1 }] });
    assert.equal(byId(off, 'syn-admin-disabled').status, 'pass');
    assert.ok(!ids(off).includes('syn-admin-active'));
});

test('active guest account fails, with shares raising the severity', () => {
    const app = loadApp();
    const users = [{ name: 'guest', uid: 1025, expire: -1 }];
    const noShares = byId(runChecks(app, {}, { users }), 'syn-guest-active');
    assert.equal(noShares.severity, 'medium');

    const sharePrivileges = [
        { share: 'public', type: 'user', name: 'guest', privilege: 'RW' },
        { share: 'media',  type: 'user', name: 'guest', privilege: 'Deny' },
        { share: 'docs',   type: 'user', name: 'bob',   privilege: 'RO' },
    ];
    const withShares = byId(runChecks(app, {}, { users, sharePrivileges }), 'syn-guest-active');
    assert.equal(withShares.severity, 'high');
    assert.deepEqual([...withShares.affectedItems], ['public (RW)']);

    const disabled = runChecks(app, {}, { users: [{ name: 'guest', uid: 1025, expire: 1 }], sharePrivileges });
    assert.equal(byId(disabled, 'syn-guest-disabled').status, 'pass');
});

test('more than two active administrators fail; inactive and service members are skipped', () => {
    const app = loadApp();
    const users = [
        { name: 'admin', uid: 1024, expire: 1 },
        { name: 'alice', uid: 1026, expire: -1 },
        { name: 'bob',   uid: 1027, expire: -1 },
        { name: 'carol', uid: 1028, expire: today() - 1 },
    ];
    const ok = runChecks(app, {}, { users, adminMembers: ['admin', 'alice', 'bob', 'carol', 'SomePackage'] });
    assert.equal(byId(ok, 'syn-admins-ok').status, 'pass');

    users.push({ name: 'dave', uid: 1029, expire: -1 });
    const many = byId(runChecks(app, {}, { users, adminMembers: ['alice', 'bob', 'dave'] }), 'syn-admins-many');
    assert.equal(many.status, 'fail');
    assert.deepEqual([...many.affectedItems], ['alice', 'bob', 'dave']);
});

test('firewall status is read from FIREWALL_config', () => {
    const app = loadApp();
    const cfg = status => ({ FIREWALL_config: JSON.stringify({ config_firewall_settings: { profile: 'custom', status } }) });
    assert.ok(ids(runChecks(app, cfg(false))).includes('syn-firewall-off'));
    assert.ok(ids(runChecks(app, cfg(true))).includes('syn-firewall-on'));
    assert.ok(ids(runChecks(app, { FIREWALL_config: 'not json' })).includes('syn-firewall-unknown'));
});

test('TLS check flags outdated protocols and ignores temp copies', () => {
    const app = loadApp();
    const conf = protocols => `ssl_protocols               ${protocols};\nssl_ciphers X;\n`;
    const weak = runChecks(app, {}, { tlsConfigs: [
        { name: 'ConfigBkp/tls_profile/config/dsm.conf', text: conf('TLSv1 TLSv1.1 TLSv1.2') },
        { name: 'ConfigBkp/tls_profile/config/system_quickconnect.conf', text: conf('TLSv1.2 TLSv1.3') },
        { name: 'ConfigBkp/tls_profile/config/temp-dsm.conf.Ab12Cd', text: conf('SSLv3') },
    ] });
    assert.deepEqual([...byId(weak, 'syn-tls-weak').affectedItems], ['dsm (TLSv1, TLSv1.1)']);

    const strong = runChecks(app, {}, { tlsConfigs: [
        { name: 'ConfigBkp/tls_profile/config/dsm.conf', text: conf('TLSv1.2 TLSv1.3') },
        { name: 'ConfigBkp/tls_profile/config/temp-dsm.conf.Ab12Cd', text: conf('TLSv1') },
    ] });
    assert.ok(ids(strong).includes('syn-tls-ok'));

    const twoServers = runChecks(app, {}, { tlsConfigs: [
        { name: 'ConfigBkp/tls_profile/config/dsm.conf', text: conf('TLSv1.2') + conf('TLSv1 TLSv1.2') },
    ] });
    assert.deepEqual([...byId(twoServers, 'syn-tls-weak').affectedItems], ['dsm (TLSv1)']);

    const noDirective = runChecks(app, {}, { tlsConfigs: [
        { name: 'ConfigBkp/tls_profile/config/LogCenter.conf', text: 'ssl_certificate x;\n' },
    ] });
    assert.ok(ids(noDirective).includes('syn-tls-unknown'));
});

test('update settings: security check and best practice agree on hotfix-security', () => {
    const app = loadApp();
    const run = type => {
        const config = new Map([['UPDATE_setting_v4', JSON.stringify({ autoupdate_type: type })]]);
        const pr = { config, users: [], adminMembers: [], schedulerTasks: [], autoBackupConfigured: true, hasBtrfs: false };
        return [...app.runAllChecks(config, null, pr), ...app.runAllBestPracticesChecks(config, null, pr)]
            .filter(f => f.id.includes('update'))
            .map(f => `${f.id}:${f.status}`)
            .sort();
    };
    assert.deepEqual(run('notify'), ['bp-update-notify-ok:pass', 'syn-security-updates-manual:fail']);
    assert.deepEqual(run('hotfix-security'), ['bp-update-notify-ok:pass', 'syn-security-updates-auto:pass']);
    // The value for "install all updates" is not verified: unknown, no best practice finding
    assert.deepEqual(run('all'), ['syn-security-updates-unknown:unknown']);
    assert.deepEqual(run('auto'), ['syn-security-updates-unknown:unknown']);
});

test('non-string update type is unknown, not a pass', () => {
    const app = loadApp();
    const findings = runChecks(app, { UPDATE_setting_v4: JSON.stringify({ autoupdate_type: true }) });
    assert.ok(ids(findings).includes('syn-security-updates-unknown'));
});

test('unrecognized SMB minimum protocol is unknown, not a pass', () => {
    const app = loadApp();
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'typo' })).includes('syn-smb1-unknown'));
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'SMB2' })).includes('syn-smb1-disabled'));
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'NT1' })).includes('syn-smb1-enabled'));
});

test('anonymous FTP is only reported while FTP is enabled', () => {
    const app = loadApp();
    const anonId = f => f.filter(x => x.id.includes('ftp-anon') && x.status === 'fail');
    assert.equal(anonId(runChecks(app, { FTP_isEnableFTP: '0', FTP_isEnableAnon: '1' })).length, 0);
    assert.equal(anonId(runChecks(app, { FTP_isEnableFTP: '1', FTP_isEnableAnon: '1' })).length, 1);
});

test('password checks reference password controls, not lockout controls', () => {
    const app = loadApp();
    const findings = runChecks(app, {});
    const labels = findings.filter(f => f.id.startsWith('syn-pwd')).flatMap(f => f.frameworks.map(r => r.label));
    assert.ok(labels.length > 0);
    for (const lockout of ['CIS 4.10', 'NIST AC-7', 'PCI Req.8.3.4']) {
        assert.ok(!labels.includes(lockout), `${lockout} must not be used for password checks`);
    }
});

test('every i18n key exists in English and German', () => {
    const src = fs.readFileSync(path.join(ROOT, 'js/i18n.js'), 'utf8');
    const [enPart, dePart] = src.split(/\n {8}de: \{/);
    const keys = part => new Set([...part.matchAll(/^ {12}(\w+):/gm)].map(m => m[1]));
    const en = keys(enPart);
    const de = keys(dePart);
    assert.deepEqual([...en].filter(k => !de.has(k)), []);
    assert.deepEqual([...de].filter(k => !en.has(k)), []);
});

test('every translation key used by the checks and views is defined', () => {
    const app = loadApp('de');
    const dir = path.join(ROOT, 'js/checks');
    const files = [...fs.readdirSync(dir).map(f => path.join(dir, f)),
        ...['compliance-engine.js', 'compliance-view.js', 'bestpractices-view.js',
            'compare-view.js', 'app.js']
            .map(f => path.join(ROOT, 'js', f))];
    const used = new Set();
    for (const file of files) {
        const src = fs.readFileSync(file, 'utf8');
        for (const m of src.matchAll(/\bt\('(\w+)'\s*[,)]/g)) used.add(m[1]);
    }
    assert.deepEqual([...used].filter(k => app.t(k) === k), []);
});

test('advisory status follows the fixed releases per DSM branch', () => {
    const app = loadApp();
    const adv = { fixes: [
        { build: 69057, update: null, version: null },
        { build: 86009, update: 6, version: '7.3.2-86009-6' },
        { build: 90080, update: 2, version: '7.4.1-90080-2' },
    ] };
    const status = build => app.dsmAdvisoryStatus(build, adv).status;
    assert.equal(status(42962), 'unknown');      // branch not listed
    assert.equal(status(69057), 'vulnerable');   // no fix for this branch
    assert.equal(status(72806), 'vulnerable');   // between listed branches
    assert.equal(status(86003), 'vulnerable');
    assert.equal(app.dsmAdvisoryStatus(86003, adv).version, '7.3.2-86009-6');
    assert.equal(status(86009), 'unknown');      // fixed by an update of the same build
    assert.equal(status(90081), 'fixed');        // newer than every fix
    assert.equal(app.dsmAdvisoryStatus(90075, { fixes: [{ build: 90075, update: 0, version: '7.4-90075' }] }).status, 'fixed');
});

test('advisory check: vulnerable build fails, own build with pending update is unknown', () => {
    const app = loadApp();
    const run = (build, cfg = {}) => runChecks(app, cfg, { info: { dsm_buildnumber: String(build) } });
    const old = byId(run(86003, { w3_runHTTP2: 'yes' }), 'syn-advisories-vulnerable');
    assert.equal(old.severity, 'critical');
    assert.ok(old.affectedItems.some(i => i.startsWith('SA-26:20') && i.includes('HTTP/2')));
    const current = byId(run(90080), 'syn-advisories-unknown');
    assert.equal(current.status, 'unknown');
    assert.deepEqual([...current.affectedItems].map(i => i.split(' ')[0]), ['SA-26:21', 'SA-26:20', 'SA-26:19']);
    assert.ok(ids(run(90100)).includes('syn-advisories-ok'));
});

test('advisory check keeps unverifiable advisories next to vulnerable ones', () => {
    const app = loadApp();
    const findings = runChecks(app, {}, { info: { dsm_buildnumber: '69057' } });
    const vuln = byId(findings, 'syn-advisories-vulnerable');
    const unk  = byId(findings, 'syn-advisories-unknown');
    assert.deepEqual([...vuln.affectedItems].map(i => i.split(' ')[0]), ['SA-26:21', 'SA-26:20']);
    assert.ok(unk, 'unknown advisories must not be dropped');
    assert.deepEqual([...unk.affectedItems].map(i => i.split(' ')[0]), ['SA-26:19', 'SA-26:13']);
});

test('advisory check rejects build numbers beyond the safe integer range', () => {
    const app = loadApp();
    const findings = runChecks(app, {}, { info: { dsm_buildnumber: '99999999999999999999' } });
    assert.ok(ids(findings).includes('syn-advisories-unknown'));
});

test('advisory check rejects build numbers with trailing garbage', () => {
    const app = loadApp();
    const f = byId(runChecks(app, {}, { info: { dsm_buildnumber: '90100-invalid' } }), 'syn-advisories-unknown');
    assert.ok(f);
    assert.equal(f.affectedItems.length, 0);
});

test('session IP binding needs an explicit boolean', () => {
    const app = loadApp();
    const sec = data => ({ SECURITY_: JSON.stringify([{ api: 'SYNO.Core.Security.DSM', result: { data } }]) });
    assert.ok(ids(runChecks(app, sec({ skip_ip_checking: false }))).includes('syn-ip-check-on'));
    assert.ok(ids(runChecks(app, sec({ skip_ip_checking: true }))).includes('syn-ip-check-off'));
    assert.ok(ids(runChecks(app, sec({}))).includes('syn-ip-check-unknown'));
    assert.ok(ids(runChecks(app, sec({ skip_ip_checking: 'false' }))).includes('syn-ip-check-unknown'));
});

test('a non-numeric minimum password length is unknown, not a pass', () => {
    const app = loadApp();
    const cfg = len => ({ Passwdstrength_isApplyPasswdRule: '1', Passwdstrength_isEnableMinLength: '1', Passwdstrength_minLength: len });
    assert.ok(ids(runChecks(app, cfg('abc'))).includes('syn-pwd-length-unknown'));
    assert.ok(ids(runChecks(app, cfg(undefined))).includes('syn-pwd-length-unknown'));
    assert.ok(ids(runChecks(app, cfg('12'))).includes('syn-pwd-length-ok'));
    assert.ok(ids(runChecks(app, cfg('8'))).includes('syn-pwd-length-weak'));
    assert.ok(ids(runChecks(app, cfg('12abc'))).includes('syn-pwd-length-unknown'));
    assert.ok(ids(runChecks(app, cfg('9'.repeat(310)))).includes('syn-pwd-length-unknown'));
});

test('DoS protection reads only an active directive per interface', () => {
    const app = loadApp();
    const dos = ini => ({ DOS_config: JSON.stringify({ '/etc/fw_security/eth0.conf': ini }) });
    assert.ok(ids(runChecks(app, dos('\n[SETTINGS]\ndos_protect_enable=yes\n'))).includes('syn-dos-protected'));
    assert.ok(ids(runChecks(app, dos('[SETTINGS]\n#dos_protect_enable=yes\ndos_protect_enable=no\n'))).includes('syn-dos-incomplete'));
    assert.ok(ids(runChecks(app, dos('[SETTINGS]\n# dos_protect_enable=yes\n'))).includes('syn-dos-incomplete'));
    assert.ok(ids(runChecks(app, dos('[SETTINGS]\ndos_protect_enable="yes"\n'))).includes('syn-dos-protected'));
    for (const unclear of ['dos_protect_enable=yesterday', 'dos_protect_enable="yes', 'dos_protect_enable=yes\ndos_protect_enable=no # off']) {
        assert.ok(ids(runChecks(app, dos(`[SETTINGS]\n${unclear}\n`))).includes('syn-dos-unknown'), unclear);
    }
    // An unprotected interface fails even when another one is unclear
    const mixed = { DOS_config: JSON.stringify({
        '/etc/fw_security/eth0.conf': 'dos_protect_enable=maybe', '/etc/fw_security/eth1.conf': 'dos_protect_enable=no' }) };
    assert.ok(ids(runChecks(app, mixed)).includes('syn-dos-incomplete'));
});

test('auto block needs numeric attempt and period values', () => {
    const app = loadApp();
    const cfg = (attempts, min) => ({ AutoBlock_attempts: attempts, AutoBlock_attemptMin: min });
    assert.ok(ids(runChecks(app, cfg('10', '5'))).includes('syn-autoblock-on'));
    assert.ok(ids(runChecks(app, cfg('0', '5'))).includes('syn-autoblock-off'));
    assert.ok(ids(runChecks(app, cfg('5x', '5'))).includes('syn-autoblock-unknown'));
    assert.ok(ids(runChecks(app, cfg('10', undefined))).includes('syn-autoblock-unknown'));
});

test('TLS snippets with unrecognized protocol names are not a pass', () => {
    const app = loadApp();
    const conf = protocols => `ssl_protocols ${protocols};\n`;
    const run = text => runChecks(app, {}, { tlsConfigs: [
        { name: 'ConfigBkp/tls_profile/config/dsm.conf', text: conf('TLSv1.2 TLSv1.3') },
        { name: 'ConfigBkp/tls_profile/config/webdav.conf', text },
    ] });
    assert.ok(ids(run(conf('UNKNOWN'))).includes('syn-tls-unknown'));
    assert.ok(ids(run(conf('UNKNOWN TLSv1'))).includes('syn-tls-weak'));
    assert.ok(ids(run(conf('TLSv1.2'))).includes('syn-tls-ok'));
    // A weak service is reported even when another file is unclear
    const weakAndUnclear = runChecks(app, {}, { tlsConfigs: [
        { name: 'ConfigBkp/tls_profile/config/dsm.conf', text: conf('TLSv1') },
        { name: 'ConfigBkp/tls_profile/config/webdav.conf', text: conf('UNKNOWN') },
    ] });
    assert.ok(ids(weakAndUnclear).includes('syn-tls-weak'));
});

test('SMB minimum protocol accepts only real SMB2/SMB3 dialect names', () => {
    const app = loadApp();
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'SMB2_10' })).includes('syn-smb1-disabled'));
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'SMB3_11' })).includes('syn-smb1-disabled'));
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'SMB3' })).includes('syn-smb1-disabled'));
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'SMB2-invalid' })).includes('syn-smb1-unknown'));
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'SMB3_999' })).includes('syn-smb1-unknown'));
});

test('optional services: enabled ones fail, all explicitly off passes', () => {
    const app = loadApp();
    const on = byId(runChecks(app, { NetBKP_isEnableNetBkp: '1', NFS_isEnableNFS: '1', SNMP_isEnableSNMP: '0' }), 'syn-services-enabled');
    assert.deepEqual([...on.affectedItems], ['rsync', 'NFS']);
    assert.ok(ids(runChecks(app, { NetBKP_isEnableNetBkp: '0', NFS_isEnableNFS: '0', SNMP_isEnableSNMP: '0' })).includes('syn-services-disabled'));
    assert.ok(ids(runChecks(app, { NetBKP_isEnableNetBkp: '0', NFS_isEnableNFS: '0' })).includes('syn-services-unknown'));
});

test('default ports best practice only counts SSH while it is enabled', () => {
    const app = loadApp();
    const bp = cfg => app.runAllBestPracticesChecks(new Map(Object.entries(cfg)), null, { schedulerTasks: [] });
    const fail = byId(bp({ w3_admin_port: '5000', w3_secure_admin_port: '5001', Terminal_isEnableSSH: '1', Terminal_SSHPort: '22' }), 'bp-default-ports');
    assert.deepEqual([...fail.affectedItems], ['DSM HTTP 5000', 'DSM HTTPS 5001', 'SSH 22']);
    assert.ok(ids(bp({ w3_admin_port: '5009', w3_secure_admin_port: '5010', Terminal_isEnableSSH: '0', Terminal_SSHPort: '22' })).includes('bp-custom-ports'));
});

test('notifications: one enabled channel passes, all off fails, a configured webhook is unknown', () => {
    const app = loadApp();
    const off = { NOTIFY_smtp_mail_enabled: '0', NOTIFY_pushservice_mail_enabled: '0',
        NOTIFY_pushservice_mobile_enabled: '0', NOTIFY_sms_enable: '0' };
    const find = cfg => [...runChecks(app, cfg)].filter(f => f.id.startsWith('syn-notify-')).map(f => `${f.id}:${f.status}`);
    assert.deepEqual(find(off), ['syn-notify-off:fail']);
    assert.deepEqual(find({ ...off, NOTIFY_webhookconf: 'null' }), ['syn-notify-off:fail']);
    assert.deepEqual(find({ ...off, NOTIFY_pushservice_mobile_enabled: '1' }), ['syn-notify-ok:pass']);
    assert.deepEqual(find({ NOTIFY_smtp_mail_enabled: '1' }), ['syn-notify-ok:pass']);
    assert.deepEqual(find({ ...off, NOTIFY_pushservice_mail_enabled: '1' }), ['syn-notify-ok:pass']);
    assert.deepEqual(find({ ...off, NOTIFY_sms_enable: 'yes' }), ['syn-notify-unknown:unknown']);
    assert.deepEqual(find({ ...off, NOTIFY_webhookconf: '{"hooks":[{}]}' }), ['syn-notify-unknown:unknown']);
    assert.equal(byId(runChecks(app, off), 'syn-notify-off').severity, 'low');
});

test('account protection: enabled passes, disabled fails, missing is unknown', () => {
    const app = loadApp();
    const find = enabled => [...runChecks(app, {}, { accountProtectionEnabled: enabled })]
        .filter(f => f.id.startsWith('syn-account-protection-')).map(f => `${f.id}:${f.status}:${f.severity}`);
    assert.deepEqual(find(true), ['syn-account-protection-on:pass:info']);
    assert.deepEqual(find(false), ['syn-account-protection-off:fail:low']);
    assert.deepEqual(find(null), ['syn-account-protection-unknown:unknown:info']);
});

test('unknown findings cite every framework their pass and fail findings cite', () => {
    const app = loadApp();
    const sec = data => JSON.stringify([{ api: 'SYNO.Core.Security.DSM', result: { data } }]);
    const embed = data => JSON.stringify([{ api: 'SYNO.Core.Security.DSM.Embed', result: { data } }]);
    const admin = expire => ({ users: [{ name: 'admin', uid: 1024, expire }] });
    // unknown id -> configs that produce its siblings
    const cases = {
        'syn-admin-unknown':          [[{}, admin(-1)], [{}, admin(1)]],
        'syn-autoblock-unknown':      [[{ AutoBlock_attempts: '10', AutoBlock_attemptMin: '5' }], [{ AutoBlock_attempts: '0', AutoBlock_attemptMin: '5' }]],
        'syn-ssh-unknown':            [[{ Terminal_isEnableSSH: '1' }], [{ Terminal_isEnableSSH: '0' }]],
        'syn-telnet-unknown':         [[{ Terminal_isEnableTelnet: '1' }], [{ Terminal_isEnableTelnet: '0' }]],
        'syn-smb1-unknown':           [[{ CIFS_Min_Protocol: 'NT1' }], [{ CIFS_Min_Protocol: 'SMB2' }]],
        'syn-ntlmv1-unknown':         [[{ CIFS_Enable_NTLMv1_Auth: '1' }], [{ CIFS_Enable_NTLMv1_Auth: '0' }]],
        'syn-dos-unknown':            [[{ DOS_config: JSON.stringify({ e: 'dos_protect_enable=yes' }) }], [{ DOS_config: JSON.stringify({ e: 'dos_protect_enable=no' }) }]],
        'syn-csrf-unknown':           [[{ SECURITY_: sec({ enable_csrf_protection: true }) }], [{ SECURITY_: sec({ enable_csrf_protection: false }) }]],
        'syn-iframe-unknown':         [[{ SECURITY_: embed({ enable_block: true }) }], [{ SECURITY_: embed({ enable_block: false }) }]],
        'syn-https-redirect-unknown': [[{ w3_redirectHTTPS: 'yes' }], [{ w3_redirectHTTPS: 'no' }]],
        'syn-hsts-unknown':           [[{ w3_runsyshsts: 'yes' }], [{ w3_runsyshsts: 'no' }]],
        'syn-pwd-policy-unknown':     [[{ Passwdstrength_isApplyPasswdRule: '0' }]],
        'syn-smb-signing-unknown':    [[{ CIFS_Enable_Server_Signing: '2' }], [{ CIFS_Enable_Server_Signing: '0' }]],
        'syn-ftp-tls-unknown':        [[{ FTP_isEnableFTP: '1', FTP_isEnableSSL: '2' }], [{ FTP_isEnableFTP: '1', FTP_isEnableSSL: '1' }]],
    };
    const unknownConfigs = { 'syn-ftp-tls-unknown': { FTP_isEnableFTP: '1' } };
    const siblingPattern = { 'syn-smb-signing-unknown': /^syn-smb-(no-)?signing/, 'syn-ftp-tls-unknown': /^syn-ftp-(no-tls|tls-on)$/ };
    const isSibling = (id, f) => f.status !== 'unknown'
        && (siblingPattern[id] ? siblingPattern[id].test(f.id) : f.id.startsWith(id.replace(/-unknown$/, '-')));
    for (const [id, siblings] of Object.entries(cases)) {
        const unknown = byId(runChecks(app, unknownConfigs[id] || {}, { autoBackupConfigured: null }), id);
        assert.ok(unknown, `${id} must be produced without data`);
        const cited = new Set(unknown.frameworks.map(r => r.label));
        for (const [cfg, extras] of siblings) {
            const sibling = runChecks(app, cfg, extras).find(f => isSibling(id, f));
            assert.ok(sibling, `${id}: sibling for ${JSON.stringify(cfg)}`);
            for (const r of sibling.frameworks) assert.ok(cited.has(r.label), `${id} must cite ${r.label} (from ${sibling.id})`);
        }
    }
});

test('HTTPS redirect, HSTS, password rules, SMB signing: only explicit values decide', () => {
    const app = loadApp();
    const status = (cfg, idPrefix) => [...runChecks(app, cfg)].filter(f => f.id.startsWith(idPrefix)).map(f => `${f.id}:${f.status}`);
    assert.deepEqual(status({ w3_redirectHTTPS: 'maybe' }, 'syn-https-redirect'), ['syn-https-redirect-unknown:unknown']);
    assert.deepEqual(status({ w3_runsyshsts: '1' }, 'syn-hsts'), ['syn-hsts-unknown:unknown']);
    assert.equal(status({ w3_redirectHTTPS: 'no' }, 'syn-https-redirect')[0].endsWith(':fail'), true);
    assert.equal(status({ w3_runsyshsts: 'yes' }, 'syn-hsts')[0].endsWith(':pass'), true);
    assert.deepEqual(status({ Passwdstrength_isApplyPasswdRule: 'yes' }, 'syn-pwd'), ['syn-pwd-policy-unknown:unknown']);
    assert.deepEqual(status({ Passwdstrength_isApplyPasswdRule: '0' }, 'syn-pwd'), ['syn-pwd-policy-disabled:fail']);
    assert.deepEqual(status({ CIFS_Enable_Server_Signing: '3' }, 'syn-smb-signing'), ['syn-smb-signing-unknown:unknown']);
    assert.deepEqual(status({ CIFS_Enable_Server_Signing: '1' }, 'syn-smb-no-signing'), ['syn-smb-no-signing:fail']);
    assert.equal(status({ CIFS_Enable_Server_Signing: '2' }, 'syn-smb-signing')[0].endsWith(':pass'), true);
});

test('FTP passes only with required TLS; an unknown TLS value is unknown', () => {
    const app = loadApp();
    const ftp = ssl => [...runChecks(app, { FTP_isEnableFTP: '1', FTP_isEnableSSL: ssl })]
        .filter(f => /^syn-ftp-(no-tls|tls-)/.test(f.id)).map(f => f.status);
    assert.deepEqual(ftp('2'), ['pass']);
    assert.deepEqual(ftp('1'), ['fail']);
    assert.deepEqual(ftp('0'), ['fail']);
    assert.deepEqual(ftp('x'), ['unknown']);
    assert.deepEqual(ftp(undefined), ['unknown']);
    assert.ok(!ids(runChecks(app, { FTP_isEnableFTP: '0' })).includes('syn-ftp-tls-unknown'));
    const noTls = ssl => [...runChecks(app, { FTP_isEnableFTP: '1', FTP_isEnableSSL: ssl })]
        .find(f => f.id === 'syn-ftp-no-tls');
    assert.equal(noTls('1').title, app.t('checkFTPTLSOptionalFailTitle'));
    assert.deepEqual([...noTls('1').affectedItems], ['FTP (TLS optional)']);
    assert.equal(noTls('0').title, app.t('checkFTPTLSFailTitle'));
    assert.deepEqual([...noTls('0').affectedItems], ['FTP (unencrypted)']);
});

test('DoS config that is not an object of INI texts is unknown', () => {
    const app = loadApp();
    for (const raw of ['[]', '["dos_protect_enable=yes"]', JSON.stringify({ e: 1 }), '{not json']) {
        assert.ok(ids(runChecks(app, { DOS_config: raw })).includes('syn-dos-unknown'), raw);
    }
    // A non-text entry does not hide an unprotected interface listed after it
    const later = JSON.stringify({ eth0: 1, eth1: 'dos_protect_enable=no' });
    assert.ok(ids(runChecks(app, { DOS_config: later })).includes('syn-dos-incomplete'));
});

test('TLS directives are read after comments, also inline, and need a semicolon', () => {
    const app = loadApp();
    const run = text => ids(runChecks(app, {}, { tlsConfigs: [{ name: 'ConfigBkp/tls_profile/config/dsm.conf', text }] }));
    assert.ok(run('server { ssl_protocols TLSv1.2 TLSv1.3; }\n').includes('syn-tls-ok'));
    assert.ok(run('listen 443; ssl_protocols TLSv1;\n').includes('syn-tls-weak'));
    assert.ok(run('# ssl_protocols TLSv1;\nssl_protocols TLSv1.2;\n').includes('syn-tls-ok'));
    assert.ok(run('ssl_protocols TLSv1.2\n').includes('syn-tls-unknown'));
    assert.ok(run('ssl_protocols TLSv1.2; ssl_protocols TLSv1.3\n').includes('syn-tls-unknown'));
});

test('a stored webhook value that is not text is unknown, not off', () => {
    const app = loadApp();
    const off = { NOTIFY_smtp_mail_enabled: '0', NOTIFY_pushservice_mail_enabled: '0',
        NOTIFY_pushservice_mobile_enabled: '0', NOTIFY_sms_enable: '0' };
    assert.ok(ids(runChecks(app, { ...off, NOTIFY_webhookconf: new Uint8Array([1]) })).includes('syn-notify-unknown'));
    assert.ok(ids(runChecks(app, { ...off, NOTIFY_webhookconf: null })).includes('syn-notify-unknown'));
});

test('CSRF and iframe settings need a boolean', () => {
    const app = loadApp();
    const sec = data => ({ SECURITY_: JSON.stringify([{ api: 'SYNO.Core.Security.DSM', result: { data } },
        { api: 'SYNO.Core.Security.DSM.Embed', result: { data } }]) });
    const found = ids(runChecks(app, sec({ enable_csrf_protection: 'true', enable_block: 1 })));
    assert.ok(found.includes('syn-csrf-unknown'));
    assert.ok(found.includes('syn-iframe-unknown'));
});

test('best practices give no finding when a setting was not read', () => {
    const app = loadApp();
    const bp = (cfg, extras = {}) => [...app.runAllBestPracticesChecks(new Map(Object.entries(cfg)), null,
        { schedulerTasks: [{ app: 'other', state: 'enabled' }], hasBtrfs: true, ...extras })]
        .map(f => `${f.id}:${f.status}`).sort();
    assert.deepEqual(bp({}), ['bp-no-recycle-task:fail']);
    const off = { CIFS_Enable_Transfer_Log: '0', CIFS_Strict_Allocate: '0', CIFS_Enable_AIO_Read: '0',
        CIFS_Enable_Multichannel: '0', CIFS_Widelinks: '0', AFP_isEnableAFP: '0', ADV_isEnableReflinkCopy: '0' };
    assert.deepEqual(bp(off), [
        'bp-afp-disabled:pass', 'bp-no-fast-clone:fail', 'bp-no-recycle-task:fail', 'bp-smb-cross-share-symlinks-ok:pass',
        'bp-smb-no-aio:fail', 'bp-smb-no-multichannel:fail', 'bp-smb-no-strict-allocate:fail', 'bp-smb-transfer-log-off:pass',
    ].sort());
    const on = Object.fromEntries(Object.keys(off).map(k => [k, '1']));
    assert.deepEqual(bp(on), [
        'bp-afp-enabled:fail', 'bp-fast-clone-ok:pass', 'bp-no-recycle-task:fail', 'bp-smb-aio-ok:pass',
        'bp-smb-cross-share-symlinks:fail', 'bp-smb-multichannel-ok:pass', 'bp-smb-strict-allocate-ok:pass',
        'bp-smb-transfer-log-on:fail',
    ].sort());
    const garbage = Object.fromEntries(Object.keys(off).map(k => [k, 'x']));
    assert.deepEqual(bp(garbage), ['bp-no-recycle-task:fail']);
});

test('recycle task best practice needs a readable, non-empty task list', () => {
    const app = loadApp();
    const run = tasks => [...app.runAllBestPracticesChecks(new Map(), null, { schedulerTasks: tasks })]
        .filter(f => f.id.includes('recycle')).map(f => `${f.id}:${f.status}`);
    assert.deepEqual(run([]), []);
    assert.deepEqual(run(null), []);
    assert.deepEqual(run(undefined), []);
    assert.deepEqual(run([{ app: 'other', state: 'enabled' }]), ['bp-no-recycle-task:fail']);
    assert.deepEqual(run([{ app: 'SYNO.SDS.TaskScheduler.Recycle', state: 'enabled' }]), ['bp-recycle-task-ok:pass']);
});

test('custom ports pass only when every relevant port was read', () => {
    const app = loadApp();
    const bp = cfg => ids([...app.runAllBestPracticesChecks(new Map(Object.entries(cfg)), null, { schedulerTasks: [] })]);
    const dsm = { w3_admin_port: '5009', w3_secure_admin_port: '5010' };
    assert.ok(!bp({ ...dsm, Terminal_isEnableSSH: '1' }).includes('bp-custom-ports'));
    assert.ok(!bp(dsm).includes('bp-custom-ports'));
    assert.ok(!bp({ w3_admin_port: '5009', Terminal_isEnableSSH: '0' }).includes('bp-custom-ports'));
    assert.ok(bp({ ...dsm, Terminal_isEnableSSH: '1', Terminal_SSHPort: '2222' }).includes('bp-custom-ports'));
    assert.ok(bp({ ...dsm, Terminal_isEnableSSH: '0' }).includes('bp-custom-ports'));
});
