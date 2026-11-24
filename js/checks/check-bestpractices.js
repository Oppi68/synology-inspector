/**
 * check-bestpractices.js
 *
 * Operational best-practice checks (non-security, do NOT affect security score):
 *   SMB:      Transfer Log off, Strict Allocate on, AIO Read on, Multichannel on,
 *             Cross-share symlinks off
 *   Services: AFP deprecated
 *   Storage:  Fast Clone (btrfs only)
 *   Updates:  Notify-only setting
 *   Scheduler: Recycle Bin cleanup task
 *   Network:  Default ports for DSM and SSH
 */

function checkBestPractices(config, _tlsProfile, parseResult) {
    const findings       = [];
    const schedulerTasks = parseResult?.schedulerTasks ?? null;
    const hasBtrfs       = parseResult?.hasBtrfs       ?? false;

    // ── Network: default ports ─────────────────────────────────────────────────
    // A changed port does not stop targeted attacks, but cuts noise from scanners.
    const sshFlag      = config.get('Terminal_isEnableSSH');
    const defaultPorts = [];
    if (config.get('w3_admin_port') === '5000')        defaultPorts.push('DSM HTTP 5000');
    if (config.get('w3_secure_admin_port') === '5001') defaultPorts.push('DSM HTTPS 5001');
    if (sshFlag === '1' && config.get('Terminal_SSHPort') === '22') defaultPorts.push('SSH 22');
    // A pass needs every port in question: both DSM ports, plus the SSH port if SSH is on
    const allPortsRead = config.has('w3_admin_port') && config.has('w3_secure_admin_port')
        && (sshFlag === '0' || (sshFlag === '1' && config.has('Terminal_SSHPort')));
    if (defaultPorts.length) {
        findings.push({
            id:          'bp-default-ports',
            title:       t('bpCheckPortsFailTitle'),
            description: t('bpCheckPortsDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPNetwork'),
            frameworks:  [],
            affectedItems: defaultPorts,
            remediation: t('bpCheckPortsRemediation'),
        });
    } else if (allPortsRead) {
        findings.push({
            id:          'bp-custom-ports',
            title:       t('bpCheckPortsPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPNetwork'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── SMB: Transfer Log ─────────────────────────────────────────────────────
    // Transfer log should be OFF (0) for performance; ON (1) = FAIL.
    // Other or missing values produce no finding (also for the SMB, AFP and
    // Fast Clone checks below).
    const transferLog = config.get('CIFS_Enable_Transfer_Log');
    if (transferLog === '1') {
        findings.push({
            id:          'bp-smb-transfer-log-on',
            title:       t('bpCheckTransferLogFailTitle'),
            description: t('bpCheckTransferLogDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: ['CIFS_Enable_Transfer_Log'],
            remediation: t('bpCheckTransferLogRemediation'),
        });
    } else if (transferLog === '0') {
        findings.push({
            id:          'bp-smb-transfer-log-off',
            title:       t('bpCheckTransferLogPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── SMB: Strict Allocate ──────────────────────────────────────────────────
    // Should be ON (1) = "do not reserve disk space" = better performance
    if (config.get('CIFS_Strict_Allocate') === '0') {
        findings.push({
            id:          'bp-smb-no-strict-allocate',
            title:       t('bpCheckStrictAllocateFailTitle'),
            description: t('bpCheckStrictAllocateDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: t('bpCheckStrictAllocateRemediation'),
        });
    } else if (config.get('CIFS_Strict_Allocate') === '1') {
        findings.push({
            id:          'bp-smb-strict-allocate-ok',
            title:       t('bpCheckStrictAllocatePassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── SMB: Asynchronous Read ────────────────────────────────────────────────
    if (config.get('CIFS_Enable_AIO_Read') === '0') {
        findings.push({
            id:          'bp-smb-no-aio',
            title:       t('bpCheckAIOReadFailTitle'),
            description: t('bpCheckAIOReadDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: t('bpCheckAIOReadRemediation'),
        });
    } else if (config.get('CIFS_Enable_AIO_Read') === '1') {
        findings.push({
            id:          'bp-smb-aio-ok',
            title:       t('bpCheckAIOReadPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── SMB: Multichannel ─────────────────────────────────────────────────────
    if (config.get('CIFS_Enable_Multichannel') === '0') {
        findings.push({
            id:          'bp-smb-no-multichannel',
            title:       t('bpCheckMultichannelFailTitle'),
            description: t('bpCheckMultichannelDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: t('bpCheckMultichannelRemediation'),
        });
    } else if (config.get('CIFS_Enable_Multichannel') === '1') {
        findings.push({
            id:          'bp-smb-multichannel-ok',
            title:       t('bpCheckMultichannelPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── SMB: Cross-share symlinks ─────────────────────────────────────────────
    // CIFS_Widelinks: '1' = symlinks may cross share boundaries (path traversal risk)
    //                 '0' = constrained within share (safe)
    // CIFS_Symlinks controls symlinks *within* a share (normal, not a risk).
    if (config.get('CIFS_Widelinks') === '1') {
        findings.push({
            id:          'bp-smb-cross-share-symlinks',
            title:       t('bpCheckSymlinksFailTitle'),
            description: t('bpCheckSymlinksDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: t('bpCheckSymlinksRemediation'),
        });
    } else if (config.get('CIFS_Widelinks') === '0') {
        findings.push({
            id:          'bp-smb-cross-share-symlinks-ok',
            title:       t('bpCheckSymlinksPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── AFP: deprecated service ───────────────────────────────────────────────
    if (config.get('AFP_isEnableAFP') === '1') {
        findings.push({
            id:          'bp-afp-enabled',
            title:       t('bpCheckAFPFailTitle'),
            description: t('bpCheckAFPDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catBPStorage'),
            frameworks:  [],
            affectedItems: ['AFP'],
            remediation: t('bpCheckAFPRemediation'),
        });
    } else if (config.get('AFP_isEnableAFP') === '0') {
        findings.push({
            id:          'bp-afp-disabled',
            title:       t('bpCheckAFPPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPStorage'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── Fast Clone — only relevant when btrfs is in use ───────────────────────
    if (hasBtrfs) {
        if (config.get('ADV_isEnableReflinkCopy') === '0') {
            findings.push({
                id:          'bp-no-fast-clone',
                title:       t('bpCheckFastCloneFailTitle'),
                description: t('bpCheckFastCloneDesc'),
                severity:    'medium',
                status:      'fail',
                category:    t('catBPStorage'),
                frameworks:  [],
                affectedItems: [],
                remediation: t('bpCheckFastCloneRemediation'),
            });
        } else if (config.get('ADV_isEnableReflinkCopy') === '1') {
            findings.push({
                id:          'bp-fast-clone-ok',
                title:       t('bpCheckFastClonePassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catBPStorage'),
                frameworks:  [],
                affectedItems: [],
                remediation: '',
            });
        }
    }

    // ── DSM update setting: no fully automatic updates ────────────────────────
    // 'notify' and 'hotfix-security' (security fixes only) both keep feature
    // updates under manual control. The value DSM stores for "install all
    // updates" is not verified, so other values produce no finding here; the
    // security check reports them as unknown.
    let updateType = null;
    try {
        const raw = config.get('UPDATE_setting_v4');
        const type = raw ? JSON.parse(raw)?.autoupdate_type : undefined;
        if (typeof type === 'string' && type !== '') updateType = type;
    } catch (_) {}

    if (updateType === 'notify' || updateType === 'hotfix-security') {
        findings.push({
            id:          'bp-update-notify-ok',
            title:       t('bpCheckUpdateNotifyPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPUpdates'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── Recycle Bin cleanup task ──────────────────────────────────────────────
    // An empty or partly unreadable task list cannot show that the task is missing
    const hasRecycleTask = schedulerTasks?.some(
        task => task.app === 'SYNO.SDS.TaskScheduler.Recycle' && task.state === 'enabled'
    );

    if (schedulerTasks?.length && !hasRecycleTask) {
        findings.push({
            id:          'bp-no-recycle-task',
            title:       t('bpCheckRecycleTaskFailTitle'),
            description: t('bpCheckRecycleTaskDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPScheduler'),
            frameworks:  [],
            affectedItems: [],
            remediation: t('bpCheckRecycleTaskRemediation'),
        });
    } else if (hasRecycleTask) {
        findings.push({
            id:          'bp-recycle-task-ok',
            title:       t('bpCheckRecycleTaskPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPScheduler'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    return findings;
}

BEST_PRACTICES_CHECKS.push(checkBestPractices);
