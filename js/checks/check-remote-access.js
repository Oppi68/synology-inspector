/**
 * check-remote-access.js
 *
 * Remote access checks:
 *   1. QuickConnect enabled  (high)
 *   2. SSH enabled           (medium)
 *   3. Telnet enabled        (critical)
 */

function checkRemoteAccess(config, _tlsProfile) {
    const findings = [];

    // ── QuickConnect ─────────────────────────────────────────────────────────
    const qcFw    = [fwRef('CIS', '4.8'), fwRef('NIST', 'SC-7'), fwRef('ISO', 'A.8.20'), fwRef('NIS2', 'Art.21(b)')];
    const qcRaw   = config.get('QUICKCONNECT_config');
    let qcEnabled = null;
    if (qcRaw) {
        try {
            const enabled = JSON.parse(qcRaw)?.quickconnect?.enabled;
            if (typeof enabled === 'boolean') qcEnabled = enabled;
        } catch (_) {}
    }

    if (qcEnabled === null) {
        findings.push(unknownFinding('syn-qc-unknown', t('checkNameQC'), t('catRemoteAccess'), qcFw));
    } else {
        if (qcEnabled) {
            findings.push({
                id:          'syn-qc-enabled',
                title:       t('checkQCFailTitle'),
                description: t('checkQCDesc'),
                severity:    'high',
                status:      'fail',
                category:    t('catRemoteAccess'),
                frameworks:  qcFw,
                affectedItems: ['QuickConnect'],
                remediation: t('checkQCRemediation'),
            });
        } else {
            findings.push({
                id:          'syn-qc-disabled',
                title:       t('checkQCPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catRemoteAccess'),
                frameworks:  qcFw,
                affectedItems: [],
                remediation: '',
            });
        }
    }

    // ── SSH ───────────────────────────────────────────────────────────────────
    // Terminal_isEnableSSH: '1' = enabled. We check presence, not port number.
    const sshVal = config.get('Terminal_isEnableSSH');

    if (sshVal !== '0' && sshVal !== '1') {
        findings.push(unknownFinding('syn-ssh-unknown', t('checkNameSSH'), t('catRemoteAccess'),
            [fwRef('CIS', '4.6'), fwRef('NIST', 'CM-7'), fwRef('ISO', 'A.8.20')]));
    } else if (sshVal === '1') {
        findings.push({
            id:          'syn-ssh-enabled',
            title:       t('checkSSHFailTitle'),
            description: t('checkSSHDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catRemoteAccess'),
            frameworks:  [fwRef('CIS', '4.6'), fwRef('NIST', 'CM-7'), fwRef('ISO', 'A.8.20')],
            affectedItems: ['SSH'],
            remediation: t('checkSSHRemediation'),
        });
    } else {
        findings.push({
            id:          'syn-ssh-disabled',
            title:       t('checkSSHPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catRemoteAccess'),
            frameworks:  [fwRef('CIS', '4.6'), fwRef('NIST', 'CM-7')],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── Telnet ───────────────────────────────────────────────────────────────
    const telnetVal = config.get('Terminal_isEnableTelnet');
    if (telnetVal !== '0' && telnetVal !== '1') {
        findings.push(unknownFinding('syn-telnet-unknown', t('checkNameTelnet'), t('catRemoteAccess'),
            [fwRef('CIS', '4.6'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.20'), fwRef('PCI', 'Req.2.2.7')]));
    } else if (telnetVal === '1') {
        findings.push({
            id:          'syn-telnet-enabled',
            title:       t('checkTelnetFailTitle'),
            description: t('checkTelnetDesc'),
            severity:    'critical',
            status:      'fail',
            category:    t('catRemoteAccess'),
            frameworks:  [fwRef('CIS', '4.6'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.20'), fwRef('PCI', 'Req.2.2.7')],
            affectedItems: ['Telnet'],
            remediation: t('checkTelnetRemediation'),
        });
    } else {
        findings.push({
            id:          'syn-telnet-disabled',
            title:       t('checkTelnetPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catRemoteAccess'),
            frameworks:  [fwRef('CIS', '4.6'), fwRef('NIST', 'SC-8')],
            affectedItems: [],
            remediation: '',
        });
    }


    return findings;
}

COMPLIANCE_CHECKS.push(checkRemoteAccess);
