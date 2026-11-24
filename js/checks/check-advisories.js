/**
 * check-advisories.js
 *
 * Compares the DSM build from config_info with the fixed releases of critical
 * Synology security advisories.
 *
 * config_info only contains the build number (e.g. 90080), not the installed
 * update (the "-2" in 7.4.1-90080-2). If an advisory is fixed by an update of
 * the device's own build, the result is therefore unknown.
 */

/**
 * Critical DSM advisories. One entry per DSM branch listed in the advisory:
 *   build   — base build of the branch
 *   update  — first fixed update of that build (0 = the build itself),
 *             null = no fix released yet ("Ongoing")
 *   version — fixed release as written in the advisory
 * Source: https://www.synology.com/security/advisory (read 2026-11-23).
 */
const DSM_ADVISORIES = [
    {
        id: 'SA-26:21', cves: ['CVE-2026-120382'],
        fixes: [
            { build: 42962, update: null, version: null },
            { build: 69057, update: null, version: null },
            { build: 72806, update: null, version: null },
            { build: 86009, update: 6, version: '7.3.2-86009-6' },
            { build: 90080, update: 2, version: '7.4.1-90080-2' },
        ],
    },
    {
        id: 'SA-26:20', cves: ['CVE-2026-123007'], http2: true,
        fixes: [
            { build: 42962, update: null, version: null },
            { build: 69057, update: null, version: null },
            { build: 72806, update: null, version: null },
            { build: 86009, update: 6, version: '7.3.2-86009-6' },
            { build: 90080, update: 2, version: '7.4.1-90080-2' },
        ],
    },
    {
        id: 'SA-26:19', cves: ['CVE-2026-76954', 'CVE-2026-85101'],
        fixes: [
            { build: 69057, update: 13, version: '7.2.1-69057-13' },
            { build: 72806, update: 10, version: '7.2.2-72806-10' },
            { build: 86009, update: 5,  version: '7.3.2-86009-5' },
            { build: 90080, update: 1,  version: '7.4.1-90080-1' },
        ],
    },
    {
        id: 'SA-26:13', cves: ['CVE-2026-13684', 'CVE-2026-13639'],
        fixes: [
            { build: 69057, update: 12, version: '7.2.1-69057-12' },
            { build: 72806, update: 9,  version: '7.2.2-72806-9' },
            { build: 86009, update: 4,  version: '7.3.2-86009-4' },
            { build: 90075, update: 0,  version: '7.4-90075' },
        ],
    },
];

/**
 * Status of one advisory for a DSM build. Build numbers grow across all DSM
 * branches, so a build newer than every listed fix contains the fix.
 *
 * @param {number} build
 * @param {{fixes: Array<{build: number, update: ?number, version: ?string}>}} advisory
 * @returns {{ status: 'fixed'|'vulnerable'|'unknown', version: ?string }}
 */
function dsmAdvisoryStatus(build, advisory) {
    const fixes = advisory.fixes;
    const last  = fixes[fixes.length - 1];
    if (build < fixes[0].build) return { status: 'unknown', version: null };   // branch not listed
    if (build > last.build) {
        return { status: last.update === null ? 'unknown' : 'fixed', version: null };
    }
    const same = fixes.find(f => f.build === build);
    if (same) {
        if (same.update === null) return { status: 'vulnerable', version: null };
        return { status: same.update === 0 ? 'fixed' : 'unknown', version: same.version };
    }
    const next = fixes.find(f => f.build > build && f.update !== null);
    return { status: 'vulnerable', version: next ? next.version : null };
}

function checkAdvisories(config, _tlsProfile, parseResult) {
    const fw    = [fwRef('CIS', '7.3'), fwRef('NIST', 'SI-2'), fwRef('ISO', 'A.8.8'), fwRef('PCI', 'Req.6.3.3')];
    const raw   = String(parseResult?.info?.dsm_buildnumber ?? '').trim();
    const build = /^\d+$/.test(raw) ? parseInt(raw, 10) : NaN;
    if (!Number.isSafeInteger(build) || build <= 0) {
        return [unknownFinding('syn-advisories-unknown', t('checkNameAdvisories'), t('catMaintenance'), fw)];
    }

    const http2On    = config.get('w3_runHTTP2') === 'yes';
    const vulnerable = [];
    const unknown    = [];
    for (const adv of DSM_ADVISORIES) {
        const { status, version } = dsmAdvisoryStatus(build, adv);
        if (status === 'fixed') continue;
        let item = `${adv.id} (${adv.cves.join(', ')}): `
            + (version ? t('checkAdvisoryFixedIn', version) : t('checkAdvisoryNoFix'));
        if (adv.http2 && http2On) item += ` – ${t('checkAdvisoryHttp2On')}`;
        (status === 'vulnerable' ? vulnerable : unknown).push(item);
    }

    const findings = [];
    if (vulnerable.length) {
        findings.push({
            id:          'syn-advisories-vulnerable',
            title:       t('checkAdvisoriesFailTitle', build),
            description: t('checkAdvisoriesDesc'),
            severity:    'critical',
            status:      'fail',
            category:    t('catMaintenance'),
            frameworks:  fw,
            affectedItems: vulnerable,
            remediation: t('checkAdvisoriesRemediation'),
        });
    }
    if (unknown.length) {
        findings.push({
            ...unknownFinding('syn-advisories-unknown', t('checkNameAdvisories'), t('catMaintenance'), fw),
            title:         t('checkAdvisoriesUnknownTitle', build),
            description:   t('checkAdvisoriesUnknownDesc'),
            affectedItems: unknown,
            remediation:   t('checkAdvisoriesRemediation'),
        });
    }
    if (findings.length) return findings;
    return [{
        id:          'syn-advisories-ok',
        title:       t('checkAdvisoriesPassTitle', build),
        description: '',
        severity:    'info',
        status:      'pass',
        category:    t('catMaintenance'),
        frameworks:  fw,
        affectedItems: [],
        remediation: '',
    }];
}

COMPLIANCE_CHECKS.push(checkAdvisories);
