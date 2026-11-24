/**
 * check-users.js
 *
 * User account security checks:
 *   1. Default admin account active                (high)
 *   2. Password policy not enforced                (high)
 *   3. Password minimum length below 12            (medium)
 *   4. Password special characters not required    (low)
 *   5. Common password check disabled              (low)
 *   6. Guest account active                        (medium, high with share access)
 *   7. More than two active administrators         (low)
 */

function checkUsers(config, _tlsProfile, parseResult) {
    const findings = [];
    const users    = parseResult?.users || [];

    // ── Default admin account disabled ────────────────────────────────────────
    const adminUser   = users.find(u => u.name === 'admin' || u.uid === 1024);
    const adminActive = adminUser ? isAccountActive(adminUser) : null;

    if (adminActive === null) {
        findings.push(unknownFinding('syn-admin-unknown', t('checkNameAdmin'), t('catUsers'),
            [fwRef('CIS', '4.7'), fwRef('NIST', 'AC-2'), fwRef('ISO', 'A.8.3')]));
    } else if (adminActive) {
        findings.push({
            id:          'syn-admin-active',
            title:       t('checkAdminActiveFailTitle'),
            description: t('checkAdminActiveDesc'),
            severity:    'high',
            status:      'fail',
            category:    t('catUsers'),
            frameworks:  [fwRef('CIS', '4.7'), fwRef('NIST', 'AC-2'), fwRef('ISO', 'A.8.3')],
            affectedItems: ['admin'],
            remediation: t('checkAdminActiveRemediation'),
        });
    } else {
        findings.push({
            id:          'syn-admin-disabled',
            title:       t('checkAdminActivePassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catUsers'),
            frameworks:  [fwRef('CIS', '4.7'), fwRef('NIST', 'AC-2')],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── Password policy ───────────────────────────────────────────────────────
    // '1' = strength rules applied, '0' = not applied; anything else cannot be evaluated
    const policyValue = config.get('Passwdstrength_isApplyPasswdRule');

    if (policyValue !== '0' && policyValue !== '1') {
        findings.push(unknownFinding('syn-pwd-policy-unknown', t('checkNamePwdPolicy'), t('catUsers'),
            [fwRef('CIS', '5.2'), fwRef('NIST', 'IA-5'), fwRef('ISO', 'A.5.17'), fwRef('PCI', 'Req.8.3.6')]));
    } else if (policyValue === '0') {
        findings.push({
            id:          'syn-pwd-policy-disabled',
            title:       t('checkPwdPolicyDisabledFailTitle'),
            description: t('checkPwdPolicyDisabledDesc'),
            severity:    'high',
            status:      'fail',
            category:    t('catUsers'),
            frameworks:  [fwRef('CIS', '5.2'), fwRef('NIST', 'IA-5'), fwRef('ISO', 'A.5.17'), fwRef('PCI', 'Req.8.3.6')],
            affectedItems: [],
            remediation: t('checkPwdPolicyDisabledRemediation'),
        });
    } else {
        // Min length
        const minLengthEnabled = config.get('Passwdstrength_isEnableMinLength') === '1';
        const minLengthRaw     = config.get('Passwdstrength_minLength') ?? '';
        const minLength        = minLengthEnabled ? parseInt(minLengthRaw, 10) : 0;

        if (minLengthEnabled && !/^\d{1,3}$/.test(minLengthRaw)) {
            findings.push(unknownFinding('syn-pwd-length-unknown', t('checkNamePwdLength'), t('catUsers'),
                [fwRef('CIS', '5.2'), fwRef('ISO', 'A.5.17'), fwRef('PCI', 'Req.8.3.6')]));
        } else if (!minLengthEnabled || minLength < 12) {
            findings.push({
                id:          'syn-pwd-length-weak',
                title:       t('checkPwdLengthFailTitle'),
                description: t('checkPwdLengthDesc', minLength || 0),
                severity:    'medium',
                status:      'fail',
                category:    t('catUsers'),
                frameworks:  [fwRef('CIS', '5.2'), fwRef('ISO', 'A.5.17'), fwRef('PCI', 'Req.8.3.6')],
                affectedItems: [],
                remediation: t('checkPwdLengthRemediation'),
            });
        } else {
            findings.push({
                id:          'syn-pwd-length-ok',
                title:       t('checkPwdLengthPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catUsers'),
                frameworks:  [fwRef('CIS', '5.2'), fwRef('ISO', 'A.5.17')],
                affectedItems: [],
                remediation: '',
            });
        }

        // Special characters
        if (config.get('Passwdstrength_isIncludeSpecialChar') !== '1') {
            findings.push({
                id:          'syn-pwd-no-special',
                title:       t('checkPwdSpecialFailTitle'),
                description: t('checkPwdSpecialDesc'),
                severity:    'low',
                status:      'fail',
                category:    t('catUsers'),
                frameworks:  [fwRef('NIST', 'IA-5'), fwRef('ISO', 'A.5.17')],
                affectedItems: [],
                remediation: t('checkPwdSpecialRemediation'),
            });
        } else {
            findings.push({
                id:          'syn-pwd-special-ok',
                title:       t('checkPwdSpecialPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catUsers'),
                frameworks:  [fwRef('ISO', 'A.5.17')],
                affectedItems: [],
                remediation: '',
            });
        }

        // Common password check
        if (config.get('Passwdstrength_isExcloudCommon') !== '1') {
            findings.push({
                id:          'syn-pwd-no-common-check',
                title:       t('checkPwdCommonFailTitle'),
                description: t('checkPwdCommonDesc'),
                severity:    'low',
                status:      'fail',
                category:    t('catUsers'),
                frameworks:  [fwRef('NIST', 'IA-5'), fwRef('ISO', 'A.5.17')],
                affectedItems: [],
                remediation: t('checkPwdCommonRemediation'),
            });
        } else {
            findings.push({
                id:          'syn-pwd-common-ok',
                title:       t('checkPwdCommonPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catUsers'),
                frameworks:  [fwRef('ISO', 'A.5.17')],
                affectedItems: [],
                remediation: '',
            });
        }
    }

    // ── Guest account ─────────────────────────────────────────────────────────
    const guestFw = [fwRef('CIS', '4.7'), fwRef('NIST', 'AC-2'), fwRef('ISO', 'A.5.18')];
    const guest = users.find(u => u.name === 'guest');
    const guestActive = guest ? isAccountActive(guest) : null;
    if (guestActive === null) {
        findings.push(unknownFinding('syn-guest-unknown', t('checkNameGuest'), t('catUsers'), guestFw));
    } else {
        if (guestActive) {
            const guestShares = (parseResult?.sharePrivileges || [])
                .filter(p => p.type === 'user' && p.name === 'guest' && (p.privilege === 'RW' || p.privilege === 'RO'))
                .map(p => `${p.share} (${p.privilege})`);
            findings.push({
                id:          'syn-guest-active',
                title:       t('checkGuestFailTitle'),
                description: t('checkGuestDesc'),
                severity:    guestShares.length ? 'high' : 'medium',
                status:      'fail',
                category:    t('catUsers'),
                frameworks:  guestFw,
                affectedItems: guestShares,
                remediation: t('checkGuestRemediation'),
            });
        } else {
            findings.push({
                id:          'syn-guest-disabled',
                title:       t('checkGuestPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catUsers'),
                frameworks:  guestFw,
                affectedItems: [],
                remediation: '',
            });
        }
    }

    // ── Number of active administrators ───────────────────────────────────────
    // Members without a local account (e.g. package service users) are skipped.
    const MAX_ADMINS   = 2;
    const adminFw      = [fwRef('CIS', '5.4'), fwRef('NIST', 'AC-6'), fwRef('ISO', 'A.8.2')];
    const adminMembers = parseResult?.adminMembers || [];
    if (users.length === 0 || adminMembers.length === 0) {
        findings.push(unknownFinding('syn-admins-unknown', t('checkNameAdmins'), t('catUsers'), adminFw));
    } else {
        const adminStates = adminMembers
            .map(name => users.find(x => x.name === name))
            .filter(Boolean)
            .map(u => [u.name, isAccountActive(u)]);
        const activeAdmins = adminStates.filter(([, active]) => active === true).map(([name]) => name);
        const undetermined = adminStates.some(([, active]) => active === null);
        if (activeAdmins.length === 0 || (undetermined && activeAdmins.length <= MAX_ADMINS)) {
            findings.push(unknownFinding('syn-admins-unknown', t('checkNameAdmins'), t('catUsers'), adminFw));
        } else if (activeAdmins.length > MAX_ADMINS) {
            findings.push({
                id:          'syn-admins-many',
                title:       t('checkAdminsFailTitle', activeAdmins.length),
                description: t('checkAdminsDesc', MAX_ADMINS),
                severity:    'low',
                status:      'fail',
                category:    t('catUsers'),
                frameworks:  adminFw,
                affectedItems: activeAdmins,
                remediation: t('checkAdminsRemediation'),
            });
        } else {
            findings.push({
                id:          'syn-admins-ok',
                title:       t('checkAdminsPassTitle', activeAdmins.length),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catUsers'),
                frameworks:  adminFw,
                affectedItems: [],
                remediation: '',
            });
        }
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkUsers);
