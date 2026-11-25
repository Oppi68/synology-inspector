/**
 * check-protocols.js
 *
 * Network protocol security checks:
 *   1. SMBv1 enabled       (critical)
 *   2. NTLMv1 auth enabled (high)
 *   3. FTP anonymous access enabled (high)
 *   4. FTP without TLS enabled      (medium)
 *   5. TLS 1.0/1.1 allowed on web services (medium)
 *   6. Optional services rsync, NFS, SNMP enabled (low)
 */

const WEAK_TLS_PROTOCOLS  = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'];
const KNOWN_TLS_PROTOCOLS = [...WEAK_TLS_PROTOCOLS, 'TLSv1.2', 'TLSv1.3'];

/**
 * Find services whose nginx TLS snippet still allows outdated protocols.
 * Only files named <service>.conf are evaluated; DSM leaves temp-* copies behind.
 * A file listing protocol names the check does not know is counted as unclear.
 *
 * @param {Array<{name: string, text: string}>} tlsConfigs
 * @returns {{ evaluated: number, weak: string[], unclear: number }}
 */
function findWeakTlsServices(tlsConfigs) {
    let evaluated = 0;
    let unclear = 0;
    const weak = [];
    for (const { name, text } of tlsConfigs || []) {
        const base = name.split('/').pop();
        if (!base.endsWith('.conf') || base.startsWith('temp-')) continue;
        // nginx allows several directives per line; comments run to the end of the line
        const active = text.replace(/#.*$/gm, '');
        const mentions = active.match(/\bssl_protocols\b/g) || [];
        if (!mentions.length) continue;
        evaluated++;
        const directives = [...active.matchAll(/(?:^|[;{}\s])ssl_protocols\s+([^;{}]+);/g)];
        const protocols = directives.flatMap(m => m[1].trim().split(/\s+/));
        const bad = [...new Set(protocols.filter(p => WEAK_TLS_PROTOCOLS.includes(p)))];
        if (bad.length) weak.push(`${base.slice(0, -5)} (${bad.join(', ')})`);
        // A directive the regex could not read (e.g. no closing semicolon) is unclear
        else if (directives.length !== mentions.length
            || protocols.some(p => !KNOWN_TLS_PROTOCOLS.includes(p))) unclear++;
    }
    return { evaluated, weak, unclear };
}

function checkProtocols(config, _tlsProfile, parseResult) {
    const findings = [];

    // ── SMBv1 ────────────────────────────────────────────────────────────────
    // CIFS_Min_Protocol: 'SMB1' / 'NT1' = SMBv1 allowed; 'SMB2' / 'SMB3' = secure
    const minProto  = (config.get('CIFS_Min_Protocol') || '').toUpperCase();
    const smb1On    = (minProto === 'SMB1' || minProto === 'NT1');
    // Dialect names Samba accepts for 'server min protocol'
    const smb2Plus  = ['SMB2', 'SMB2_02', 'SMB2_10', 'SMB2_22', 'SMB2_24',
                       'SMB3', 'SMB3_00', 'SMB3_02', 'SMB3_10', 'SMB3_11'].includes(minProto);

    if (!smb1On && !smb2Plus) {
        findings.push(unknownFinding('syn-smb1-unknown', t('checkNameSMBMinProto'), t('catProtocols'),
            [fwRef('CIS', '9.4'), fwRef('NIST', 'CM-7'), fwRef('ISO', 'A.8.20'), fwRef('PCI', 'Req.12.3.3')]));
    } else if (smb1On) {
        findings.push({
            id:          'syn-smb1-enabled',
            title:       t('checkSMB1FailTitle'),
            description: t('checkSMB1Desc'),
            severity:    'critical',
            status:      'fail',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.4'), fwRef('NIST', 'CM-7'), fwRef('ISO', 'A.8.20'), fwRef('PCI', 'Req.12.3.3')],
            affectedItems: ['SMBv1 / CIFS'],
            remediation: t('checkSMB1Remediation'),
        });
    } else {
        findings.push({
            id:          'syn-smb1-disabled',
            title:       t('checkSMB1PassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.4'), fwRef('NIST', 'CM-7')],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── NTLMv1 authentication ─────────────────────────────────────────────────
    const ntlmv1Val = config.get('CIFS_Enable_NTLMv1_Auth');
    if (ntlmv1Val !== '0' && ntlmv1Val !== '1') {
        findings.push(unknownFinding('syn-ntlmv1-unknown', t('checkNameNTLMv1'), t('catProtocols'),
            [fwRef('CIS', '9.4'), fwRef('NIST', 'IA-3'), fwRef('ISO', 'A.8.20'), fwRef('PCI', 'Req.12.3.3')]));
    } else if (ntlmv1Val === '1') {
        findings.push({
            id:          'syn-ntlmv1-enabled',
            title:       t('checkNTLMv1FailTitle'),
            description: t('checkNTLMv1Desc'),
            severity:    'high',
            status:      'fail',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.4'), fwRef('NIST', 'IA-3'), fwRef('ISO', 'A.8.20'), fwRef('PCI', 'Req.12.3.3')],
            affectedItems: ['NTLMv1 authentication'],
            remediation: t('checkNTLMv1Remediation'),
        });
    } else {
        findings.push({
            id:          'syn-ntlmv1-disabled',
            title:       t('checkNTLMv1PassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.4'), fwRef('NIST', 'IA-3')],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── FTP anonymous access ──────────────────────────────────────────────────
    const ftpOn     = config.get('FTP_isEnableFTP') === '1';
    const ftpAnonOn = config.get('FTP_isEnableAnon') === '1';

    if (ftpOn && ftpAnonOn) {
        findings.push({
            id:          'syn-ftp-anon',
            title:       t('checkFTPAnonFailTitle'),
            description: t('checkFTPAnonDesc'),
            severity:    'high',
            status:      'fail',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.2'), fwRef('NIST', 'CM-7'), fwRef('ISO', 'A.8.3'), fwRef('PCI', 'Req.2.2.7')],
            affectedItems: ['FTP anonymous login'],
            remediation: t('checkFTPAnonRemediation'),
        });
    }

    // ── FTP without TLS ───────────────────────────────────────────────────────
    // FTP_isEnableSSL: '0' = disabled, '1' = optional, '2' = required.
    // Optional TLS still lets clients log in unencrypted, so only '2' passes.
    const ftpFw     = [fwRef('CIS', '9.2'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24')];
    const ftpSslVal = config.get('FTP_isEnableSSL');

    if (ftpOn && !['0', '1', '2'].includes(ftpSslVal)) {
        findings.push(unknownFinding('syn-ftp-tls-unknown', t('checkNameFTPTLS'), t('catProtocols'), ftpFw));
    } else if (ftpOn && ftpSslVal !== '2') {
        const optional = ftpSslVal === '1';
        findings.push({
            id:          'syn-ftp-no-tls',
            title:       t(optional ? 'checkFTPTLSOptionalFailTitle' : 'checkFTPTLSFailTitle'),
            description: t(optional ? 'checkFTPTLSOptionalDesc' : 'checkFTPTLSDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catProtocols'),
            frameworks:  ftpFw,
            affectedItems: [optional ? 'FTP (TLS optional)' : 'FTP (unencrypted)'],
            remediation: t(optional ? 'checkFTPTLSOptionalRemediation' : 'checkFTPTLSRemediation'),
        });
    } else if (ftpOn) {
        findings.push({
            id:          'syn-ftp-tls-on',
            title:       t('checkFTPTLSPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catProtocols'),
            frameworks:  ftpFw,
            affectedItems: [],
            remediation: '',
        });
    }

    // ── Optional services ─────────────────────────────────────────────────────
    // '1' = enabled, '0' = disabled (confirmed on DSM 7.4 backups).
    const OPTIONAL_SERVICES = [
        ['rsync', 'NetBKP_isEnableNetBkp'],
        ['NFS',   'NFS_isEnableNFS'],
        ['SNMP',  'SNMP_isEnableSNMP'],
    ];
    const servicesFw = [fwRef('CIS', '4.8'), fwRef('NIST', 'CM-7'), fwRef('ISO', 'A.8.20')];
    const serviceValues = OPTIONAL_SERVICES.map(([name, key]) => [name, config.get(key)]);
    const enabledServices = serviceValues.filter(([, v]) => v === '1').map(([name]) => name);
    const allKnown = serviceValues.every(([, v]) => v === '0' || v === '1');

    if (enabledServices.length) {
        findings.push({
            id:          'syn-services-enabled',
            title:       t('checkServicesFailTitle'),
            description: t('checkServicesDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catProtocols'),
            frameworks:  servicesFw,
            affectedItems: enabledServices,
            remediation: t('checkServicesRemediation'),
        });
    } else if (!allKnown) {
        findings.push(unknownFinding('syn-services-unknown', t('checkNameServices'), t('catProtocols'), servicesFw));
    } else {
        findings.push({
            id:          'syn-services-disabled',
            title:       t('checkServicesPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catProtocols'),
            frameworks:  servicesFw,
            affectedItems: [],
            remediation: '',
        });
    }

    // ── Outdated TLS versions ─────────────────────────────────────────────────
    const tlsFw = [fwRef('CIS', '3.10'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24'), fwRef('PCI', 'Req.4.2.1')];
    const tls   = findWeakTlsServices(parseResult?.tlsConfigs);
    if (tls.weak.length === 0 && (tls.evaluated === 0 || tls.unclear > 0)) {
        findings.push(unknownFinding('syn-tls-unknown', t('checkNameTLS'), t('catProtocols'), tlsFw));
    } else if (tls.weak.length) {
        findings.push({
            id:          'syn-tls-weak',
            title:       t('checkTLSFailTitle'),
            description: t('checkTLSDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catProtocols'),
            frameworks:  tlsFw,
            affectedItems: tls.weak,
            remediation: t('checkTLSRemediation'),
        });
    } else {
        findings.push({
            id:          'syn-tls-ok',
            title:       t('checkTLSPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catProtocols'),
            frameworks:  tlsFw,
            affectedItems: [],
            remediation: '',
        });
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkProtocols);
