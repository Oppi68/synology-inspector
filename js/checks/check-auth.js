/**
 * check-auth.js
 *
 * Authentication and access hardening checks:
 *   1. Auto-block not configured   (medium)
 *   2. HTTPS redirect disabled     (medium)
 *   3. HSTS not enabled            (low)
 *   4. Account protection disabled (low)
 */

function checkAuth(config, _tlsProfile, parseResult) {
    const findings = [];

    // ── Auto-block ────────────────────────────────────────────────────────────
    // AutoBlock_attempts > 0 means the feature is configured with an attempt limit.
    // A value of 0 means auto-block is effectively off; a missing or non-numeric
    // value cannot be evaluated.
    const autoBlockRaw      = [config.get('AutoBlock_attempts'), config.get('AutoBlock_attemptMin')];
    const [autoBlockAttempts, autoBlockMinutes] = autoBlockRaw.map(v => parseInt(v, 10));

    if (!autoBlockRaw.every(v => /^\d{1,6}$/.test(v ?? ''))) {
        findings.push(unknownFinding('syn-autoblock-unknown', t('checkNameAutoBlock'), t('catAuth'),
            [fwRef('CIS', '4.10'), fwRef('NIST', 'AC-7'), fwRef('ISO', 'A.8.5'), fwRef('PCI', 'Req.8.3.4')]));
    } else if (autoBlockAttempts > 0 && autoBlockMinutes > 0) {
        findings.push({
            id:          'syn-autoblock-on',
            title:       t('checkAutoBlockPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catAuth'),
            frameworks:  [fwRef('CIS', '4.10'), fwRef('NIST', 'AC-7'), fwRef('ISO', 'A.8.5')],
            affectedItems: [],
            remediation: '',
        });
    } else {
        findings.push({
            id:          'syn-autoblock-off',
            title:       t('checkAutoBlockFailTitle'),
            description: t('checkAutoBlockDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catAuth'),
            frameworks:  [fwRef('CIS', '4.10'), fwRef('NIST', 'AC-7'), fwRef('ISO', 'A.8.5'), fwRef('PCI', 'Req.8.3.4')],
            affectedItems: [t('checkAutoBlockAffected')],
            remediation: t('checkAutoBlockRemediation'),
        });
    }

    // ── HTTPS redirect ────────────────────────────────────────────────────────
    // w3_redirectHTTPS = 'yes' means DSM automatically redirects HTTP → HTTPS,
    // 'no' means it does not; any other value cannot be evaluated.
    const httpsRedirect = config.get('w3_redirectHTTPS');

    if (httpsRedirect !== 'yes' && httpsRedirect !== 'no') {
        findings.push(unknownFinding('syn-https-redirect-unknown', t('checkNameHTTPSRedirect'), t('catAuth'),
            [fwRef('CIS', '9.5'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24'), fwRef('PCI', 'Req.4.2.1')]));
    } else if (httpsRedirect === 'yes') {
        findings.push({
            id:          'syn-https-redirect-on',
            title:       t('checkHTTPSRedirectPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catAuth'),
            frameworks:  [fwRef('CIS', '9.5'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24')],
            affectedItems: [],
            remediation: '',
        });
    } else {
        findings.push({
            id:          'syn-https-redirect-off',
            title:       t('checkHTTPSRedirectFailTitle'),
            description: t('checkHTTPSRedirectDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catAuth'),
            frameworks:  [fwRef('CIS', '9.5'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24'), fwRef('PCI', 'Req.4.2.1')],
            affectedItems: [t('checkHTTPSRedirectAffected')],
            remediation: t('checkHTTPSRedirectRemediation'),
        });
    }

    // ── HSTS ─────────────────────────────────────────────────────────────────
    // w3_runsyshsts = 'yes' means HTTP Strict Transport Security is active, 'no' that it is off.
    const hsts = config.get('w3_runsyshsts');

    if (hsts !== 'yes' && hsts !== 'no') {
        findings.push(unknownFinding('syn-hsts-unknown', t('checkNameHSTS'), t('catAuth'),
            [fwRef('CIS', '9.5'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24')]));
    } else if (hsts === 'yes') {
        findings.push({
            id:          'syn-hsts-on',
            title:       t('checkHSTSPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catAuth'),
            frameworks:  [fwRef('CIS', '9.5'), fwRef('NIST', 'SC-8')],
            affectedItems: [],
            remediation: '',
        });
    } else {
        findings.push({
            id:          'syn-hsts-off',
            title:       t('checkHSTSFailTitle'),
            description: t('checkHSTSDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catAuth'),
            frameworks:  [fwRef('CIS', '9.5'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24')],
            affectedItems: [t('checkHSTSAffected')],
            remediation: t('checkHSTSRemediation'),
        });
    }

    // ── Account protection ────────────────────────────────────────────────────
    // Blocks an account after repeated failed logins from untrusted clients.
    // Unlike auto-block it counts per account, so it also catches attacks
    // spread over many source IPs.
    const protectionFw = [fwRef('CIS', '4.10'), fwRef('NIST', 'AC-7'), fwRef('ISO', 'A.8.5')];
    const protectionEnabled = parseResult?.accountProtectionEnabled ?? null;

    if (protectionEnabled === null) {
        findings.push(unknownFinding('syn-account-protection-unknown', t('checkNameAccountProtection'),
            t('catAuth'), protectionFw));
    } else if (protectionEnabled) {
        findings.push({
            id:          'syn-account-protection-on',
            title:       t('checkAccountProtectionPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catAuth'),
            frameworks:  protectionFw,
            affectedItems: [],
            remediation: '',
        });
    } else {
        findings.push({
            id:          'syn-account-protection-off',
            title:       t('checkAccountProtectionFailTitle'),
            description: t('checkAccountProtectionDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catAuth'),
            frameworks:  protectionFw,
            affectedItems: [],
            remediation: t('checkAccountProtectionRemediation'),
        });
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkAuth);
