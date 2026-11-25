/**
 * check-network.js
 *
 * Network perimeter security checks:
 *   1. DoS protection not enabled on all interfaces  (medium)
 *   2. Firewall disabled                             (medium)
 */

function checkNetwork(config, _tlsProfile) {
    const findings = [];

    // ── DoS protection ────────────────────────────────────────────────────────
    // DOS_config: JSON object mapping /etc/fw_security/<iface>.conf → INI content.
    // Each INI block contains dos_protect_enable=yes|no.
    const dosConfigRaw = config.get('DOS_config');
    const unprotectedInterfaces = [];
    let dosUnclear = false;
    let dosConfigAvailable = false;

    if (dosConfigRaw) {
        try {
            const dosConfig = JSON.parse(dosConfigRaw);
            dosConfigAvailable = dosConfig !== null && typeof dosConfig === 'object'
                && !Array.isArray(dosConfig) && Object.keys(dosConfig).length > 0;
            for (const [confFilePath, iniContent] of dosConfigAvailable ? Object.entries(dosConfig) : []) {
                // Each value is the text of one INI file
                if (typeof iniContent !== 'string') { dosUnclear = true; continue; }
                const interfaceName = confFilePath
                    .replace('/etc/fw_security/', '')
                    .replace('.conf', '');
                // The last active (uncommented) directive counts. Only a bare or
                // fully quoted yes/no is understood; anything else is unclear.
                const last = [...iniContent.matchAll(/^[ \t]*dos_protect_enable[ \t]*=(.*)$/gim)].at(-1);
                const value = last ? last[1].trim().match(/^("?)(yes|no)\1$/i)?.[2].toLowerCase() : 'no';
                if (value === 'no') unprotectedInterfaces.push(interfaceName);
                else if (value !== 'yes') dosUnclear = true;
            }
        } catch (_) {
            dosUnclear = true;
        }
    }

    if (!dosConfigAvailable || (dosUnclear && unprotectedInterfaces.length === 0)) {
        findings.push(unknownFinding('syn-dos-unknown', t('checkNameDoS'), t('catNetwork'),
            [fwRef('NIST', 'SC-5'), fwRef('ISO', 'A.8.20'), fwRef('NIS2', 'Art.21(e)')]));
    } else {
        if (unprotectedInterfaces.length === 0) {
            findings.push({
                id:          'syn-dos-protected',
                title:       t('checkDoSPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catNetwork'),
                frameworks:  [fwRef('NIST', 'SC-5'), fwRef('ISO', 'A.8.20'), fwRef('NIS2', 'Art.21(e)')],
                affectedItems: [],
                remediation: '',
            });
        } else {
            findings.push({
                id:          'syn-dos-incomplete',
                title:       t('checkDoSFailTitle'),
                description: t('checkDoSDesc'),
                severity:    'medium',
                status:      'fail',
                category:    t('catNetwork'),
                frameworks:  [fwRef('NIST', 'SC-5'), fwRef('ISO', 'A.8.20'), fwRef('NIS2', 'Art.21(e)')],
                affectedItems: unprotectedInterfaces,
                remediation: t('checkDoSRemediation'),
            });
        }
    }

    // ── Firewall ──────────────────────────────────────────────────────────────
    // FIREWALL_config is JSON: { config_firewall_settings: { profile, status } }
    const fwFw = [fwRef('CIS', '4.4'), fwRef('NIST', 'SC-7'), fwRef('ISO', 'A.8.20')];
    let firewallOn = null;
    try {
        const raw = config.get('FIREWALL_config');
        const status = raw ? JSON.parse(raw)?.config_firewall_settings?.status : undefined;
        if (typeof status === 'boolean') firewallOn = status;
    } catch (_) {}

    if (firewallOn === null) {
        findings.push(unknownFinding('syn-firewall-unknown', t('checkNameFirewall'), t('catNetwork'), fwFw));
    } else if (!firewallOn) {
        findings.push({
            id:          'syn-firewall-off',
            title:       t('checkFirewallFailTitle'),
            description: t('checkFirewallDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catNetwork'),
            frameworks:  fwFw,
            affectedItems: [],
            remediation: t('checkFirewallRemediation'),
        });
    } else {
        findings.push({
            id:          'syn-firewall-on',
            title:       t('checkFirewallPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catNetwork'),
            frameworks:  fwFw,
            affectedItems: [],
            remediation: '',
        });
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkNetwork);
