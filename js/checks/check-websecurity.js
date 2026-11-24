/**
 * check-websecurity.js
 *
 * DSM web interface hardening checks:
 *   1. CSRF protection disabled          (medium)
 *   2. iFrame embedding not blocked      (medium)
 *   3. Session IP binding disabled       (medium)
 *
 * All three settings live in the SECURITY_ config key —
 * a JSON array of SYNO.Core.Security.* API response objects.
 */

/**
 * Extract the two relevant DSM security data objects from the SECURITY_ blob.
 *
 * @param {Map<string,string>} config
 * @returns {{ dsmSecurity: Object|null, dsmEmbedSecurity: Object|null }}
 */
function parseDsmSecurityBlob(config) {
    const securityRaw = config.get('SECURITY_');
    let dsmSecurity      = null;
    let dsmEmbedSecurity = null;

    if (!securityRaw) return { dsmSecurity, dsmEmbedSecurity };

    try {
        const apiResponses = JSON.parse(securityRaw);
        for (const apiResponse of Array.isArray(apiResponses) ? apiResponses : []) {
            if (apiResponse.api === 'SYNO.Core.Security.DSM') {
                dsmSecurity = apiResponse.result?.data ?? null;
            } else if (apiResponse.api === 'SYNO.Core.Security.DSM.Embed') {
                dsmEmbedSecurity = apiResponse.result?.data ?? null;
            }
        }
    } catch (_) {}

    return { dsmSecurity, dsmEmbedSecurity };
}

function checkWebSecurity(config, _tlsProfile) {
    const findings = [];
    const { dsmSecurity, dsmEmbedSecurity } = parseDsmSecurityBlob(config);

    // ── CSRF protection ───────────────────────────────────────────────────────
    const csrfEnabled = dsmSecurity?.enable_csrf_protection;
    if (typeof csrfEnabled !== 'boolean') {
        findings.push(unknownFinding('syn-csrf-unknown', t('checkNameCSRF'), t('catAuth'),
            [fwRef('CIS', '16.6'), fwRef('NIST', 'SI-10'), fwRef('ISO', 'A.8.26')]));
    } else {
        if (csrfEnabled) {
            findings.push({
                id:          'syn-csrf-on',
                title:       t('checkCSRFPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catAuth'),
                frameworks:  [fwRef('CIS', '16.6'), fwRef('NIST', 'SI-10'), fwRef('ISO', 'A.8.26')],
                affectedItems: [],
                remediation: '',
            });
        } else {
            findings.push({
                id:          'syn-csrf-off',
                title:       t('checkCSRFFailTitle'),
                description: t('checkCSRFDesc'),
                severity:    'medium',
                status:      'fail',
                category:    t('catAuth'),
                frameworks:  [fwRef('CIS', '16.6'), fwRef('NIST', 'SI-10'), fwRef('ISO', 'A.8.26')],
                affectedItems: [t('checkCSRFAffected')],
                remediation: t('checkCSRFRemediation'),
            });
        }
    }

    // ── iFrame embedding ──────────────────────────────────────────────────────
    const iframeBlocked = dsmEmbedSecurity?.enable_block;
    if (typeof iframeBlocked !== 'boolean') {
        findings.push(unknownFinding('syn-iframe-unknown', t('checkNameIFrame'), t('catAuth'),
            [fwRef('CIS', '16.6'), fwRef('NIST', 'SI-10'), fwRef('ISO', 'A.8.26')]));
    } else {
        if (iframeBlocked) {
            findings.push({
                id:          'syn-iframe-blocked',
                title:       t('checkIFramePassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catAuth'),
                frameworks:  [fwRef('CIS', '16.6'), fwRef('NIST', 'SI-10'), fwRef('ISO', 'A.8.26')],
                affectedItems: [],
                remediation: '',
            });
        } else {
            findings.push({
                id:          'syn-iframe-allowed',
                title:       t('checkIFrameFailTitle'),
                description: t('checkIFrameDesc'),
                severity:    'medium',
                status:      'fail',
                category:    t('catAuth'),
                frameworks:  [fwRef('CIS', '16.6'), fwRef('NIST', 'SI-10'), fwRef('ISO', 'A.8.26')],
                affectedItems: [t('checkIFrameAffected')],
                remediation: t('checkIFrameRemediation'),
            });
        }
    }

    // ── Session IP binding ────────────────────────────────────────────────────
    // skip_ip_checking = true means DSM no longer verifies that requests in a
    // session come from the same IP as the login → session hijacking is easier.
    const skipIp = dsmSecurity?.skip_ip_checking;
    if (typeof skipIp !== 'boolean') {
        findings.push(unknownFinding('syn-ip-check-unknown', t('checkNameIPCheck'), t('catAuth'),
            [fwRef('NIST', 'AC-17'), fwRef('ISO', 'A.8.5')]));
    } else {
        if (!skipIp) {
            findings.push({
                id:          'syn-ip-check-on',
                title:       t('checkIPCheckPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catAuth'),
                frameworks:  [fwRef('NIST', 'AC-17'), fwRef('ISO', 'A.8.5')],
                affectedItems: [],
                remediation: '',
            });
        } else {
            findings.push({
                id:          'syn-ip-check-off',
                title:       t('checkIPCheckFailTitle'),
                description: t('checkIPCheckDesc'),
                severity:    'medium',
                status:      'fail',
                category:    t('catAuth'),
                frameworks:  [fwRef('NIST', 'AC-17'), fwRef('ISO', 'A.8.5')],
                affectedItems: [t('checkIPCheckAffected')],
                remediation: t('checkIPCheckRemediation'),
            });
        }
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkWebSecurity);
