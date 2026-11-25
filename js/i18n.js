/**
 * i18n.js — internationalisation for Synology Inspector
 *
 * Usage:
 *   t('key')           — returns the translated string for the active language
 *   setLanguage('de')  — switches to German (persisted in localStorage)
 *
 * Languages: 'en' (default), 'de'
 */

(function () {
    'use strict';

    const STRINGS = {
        en: {
            // ── UI chrome ────────────────────────────────────────────────────
            appTitle:        'Synology Inspector',
            appVersion:      'v1.1',
            appSubtitle:     'JKLP CONSULTING · SECURITY AUDIT',

            // ── Drop zone ────────────────────────────────────────────────────
            dropTitle:       'Drop your Synology .dss backup here',
            dropOr:          'or',
            dropBrowse:      'browse for file',
            dropFormats:     'Supported: Synology configuration backup (.dss) — DSM 7+',
            dropPrivacy:     'This file is processed entirely in your browser. Nothing is sent to any server.',

            // ── States ────────────────────────────────────────────────────────
            loading:         'Analysing backup…',
            loadingHint:     'Decompressing and parsing — this may take a few seconds.',
            btnNewFile:      'Analyse another file',
            btnExportPDF:    'Export PDF',
            pdfReportTitle:  'Security Assessment Report',
            pdfAnalysedOn:   'Analysed on',
            pdfIssues:       'Findings',

            // ── Errors ────────────────────────────────────────────────────────
            errFileRead:     'Could not read file',
            errDecompress:   'Failed to decompress backup (is this a valid .dss file?)',
            errNoDb:         'No configuration database found in backup',
            errParse:        'Failed to parse backup',
            errUnknown:      'An unexpected error occurred',

            // ── Context bar ────────────────────────────────────────────────────
            labelFileName:   'File',
            labelFileSize:   'Size',
            labelDSMVersion: 'DSM',
            labelModel:      'Model',
            labelHostname:   'Hostname',

            // ── Compliance view ────────────────────────────────────────────────
            complianceTitle:     'Security Assessment',
            filterAll:           'All',
            filterFailed:        'Issues only',
            labelFindings:       'Findings',
            labelAffected:       'Affected',
            labelRemediation:    'Remediation',
            labelFrameworks:     'References',
            labelNoFindings:     'No issues found.',

            // ── Severity labels ────────────────────────────────────────────────
            severityCritical:    'Critical',
            severityHigh:        'High',
            severityMedium:      'Medium',
            severityLow:         'Low',
            severityInfo:        'Info',

            // ── Verdicts ──────────────────────────────────────────────────────
            verdictStrong:       'Strong Security Posture',
            verdictGood:         'Good Security Posture',
            verdictAcceptable:   'Acceptable — Improvements Recommended',
            verdictImprove:      'Needs Improvement',
            verdictExposure:     'Significant Exposure',
            verdictCritical:     'Critical — Immediate Action Required',

            // ── Tab bar ───────────────────────────────────────────────────────
            tabSecurity:         'Security Check',
            tabBestPractices:    'Best Practices',

            // ── Best Practices view ───────────────────────────────────────────
            bpViewTitle:         'Best Practices Assessment',
            bpNoIssuesTitle:     'All Best-Practice Checks Passed',
            bpNoIssuesSub:       'Your configuration follows all recommended best practices.',

            // ── Categories ────────────────────────────────────────────────────
            catRemoteAccess:     'Remote Access',
            catProtocols:        'Protocols',
            catAuth:             'Authentication',
            catUsers:            'User Accounts',
            catMaintenance:      'Maintenance',
            catNetwork:          'Network Security',
            catBPSMB:            'SMB Performance',
            catBPStorage:        'File Services & Storage',
            catBPUpdates:        'Update Management',
            catBPScheduler:      'Task Scheduler',
            catBPNetwork:        'Network',

            // ── check-remote-access.js ─────────────────────────────────────────
            checkQCFailTitle:    'QuickConnect Is Enabled',
            checkQCPassTitle:    'QuickConnect Is Disabled',
            checkQCDesc:         'QuickConnect routes connections through Synology\'s relay servers, creating a permanent inbound pathway into the NAS that bypasses your network perimeter. Even with port forwarding disabled, QuickConnect exposes management interfaces to the internet.',
            checkQCRemediation:  'Disable QuickConnect in Control Panel › External Access › QuickConnect.',

            checkSSHFailTitle:    'SSH Is Enabled',
            checkSSHPassTitle:    'SSH Is Disabled',
            checkSSHDesc:         'SSH exposes a remote shell to the NAS over the network. If not actively required, SSH should be disabled to minimise attack surface. If SSH is needed, restrict access to trusted source addresses using the DSM firewall and enforce key-based authentication.',
            checkSSHRemediation:  'Disable SSH if not required: Control Panel › Terminal & SNMP › Terminal. If SSH is needed, restrict access via the firewall: Control Panel › Security › Firewall.',

            checkTelnetFailTitle: 'Telnet Is Enabled',
            checkTelnetPassTitle: 'Telnet Is Disabled',
            checkTelnetDesc:      'Telnet transmits all data — including credentials — in plain text. Any network observer or man-in-the-middle can intercept passwords and session content. Telnet has been superseded by SSH for all remote shell access.',
            checkTelnetRemediation: 'Disable Telnet in Control Panel › Terminal & SNMP › Terminal.',

            // ── check-network.js ───────────────────────────────────────────────
            checkDoSFailTitle:       'DoS Protection Is Not Enabled on All Interfaces',
            checkDoSPassTitle:       'DoS Protection Is Active on All Interfaces',
            checkDoSDesc:            'DoS (Denial of Service) protection drops malformed and flood packets before they can exhaust system resources. Without it, even simple network floods can degrade NAS responsiveness for legitimate users.',
            checkDoSRemediation:     'Enable DoS protection: Control Panel › Security › Protection › Enable DoS Protection.',
            checkFirewallFailTitle:  'Firewall Is Disabled',
            checkFirewallPassTitle:  'Firewall Is Enabled',
            checkFirewallDesc:       'The DSM firewall is switched off, so every service listening on the NAS is reachable from any address that can route to it. A router in front of the NAS does not protect against devices inside the same network.',
            checkFirewallRemediation: 'Enable the firewall and allow only required services and source networks: Control Panel › Security › Firewall › Enable firewall.',

            // ── check-protocols.js ─────────────────────────────────────────────
            checkSMB1FailTitle:  'SMBv1 Is Allowed',
            checkSMB1PassTitle:  'SMBv1 Is Disabled',
            checkSMB1Desc:       'SMBv1 is a 1980s-era protocol with no encryption, no integrity checking, and no modern authentication. It is the vector for EternalBlue (WannaCry, NotPetya) and numerous other critical exploits. All modern clients support SMB2 or SMB3.',
            checkSMB1Remediation: 'Set the minimum SMB protocol to SMB2 or higher in Control Panel › File Services › SMB.',

            checkNTLMv1FailTitle: 'NTLMv1 Authentication Is Enabled',
            checkNTLMv1PassTitle: 'NTLMv1 Authentication Is Disabled',
            checkNTLMv1Desc:      'NTLMv1 is a cryptographically weak authentication protocol vulnerable to Pass-the-Hash attacks and NTLM relay attacks. NTLMv2 should be the minimum, and Kerberos preferred where possible.',
            checkNTLMv1Remediation: 'Disable NTLMv1 in Control Panel › File Services › SMB › Advanced Settings.',

            checkFTPAnonFailTitle: 'FTP Anonymous Access Is Enabled',
            checkFTPAnonDesc:      'Anonymous FTP allows any user to connect without credentials. This exposes shared files to the internet without authentication and can be abused for data exfiltration.',
            checkFTPAnonRemediation: 'Disable anonymous FTP access in Control Panel › File Services › FTP › FTP service.',

            checkFTPTLSFailTitle: 'FTP Is Operating Without TLS',
            checkFTPTLSPassTitle: 'FTP Is Using TLS Encryption',
            checkFTPTLSDesc:      'Plain FTP transmits credentials and file content in clear text. Anyone on the network path can intercept passwords and data. Use FTPS (FTP over TLS) or switch to SFTP (SSH File Transfer Protocol) instead.',
            checkFTPTLSRemediation: 'Enable FTPS in Control Panel › File Services › FTP › Enable FTP SSL/TLS encryption.',
            checkFTPTLSOptionalFailTitle: 'FTP Does Not Require TLS',
            checkFTPTLSOptionalDesc:      'FTPS is offered but not required. Clients can still connect without encryption and send credentials and file content in clear text. Accept only encrypted FTP connections or switch to SFTP (SSH File Transfer Protocol).',
            checkFTPTLSOptionalRemediation: 'Configure the FTP service to accept only SSL/TLS connections in Control Panel › File Services › FTP, or use SFTP instead.',
            checkTLSFailTitle:      'Outdated TLS Versions Are Allowed',
            checkTLSPassTitle:      'Web Services Allow Only TLS 1.2 or Newer',
            checkTLSDesc:           'TLS 1.0 and 1.1 have been deprecated since 2021 (RFC 8996) and are not permitted by PCI DSS. Services that still accept them let clients fall back to weak cipher suites. The check covers the nginx-based services of the TLS profile (DSM, QuickConnect, reverse proxy, application portal).',
            checkTLSRemediation:    'Raise the TLS profile to "Intermediate compatibility" or "Modern compatibility": Control Panel › Security › Advanced › TLS / SSL Profile Level, for the system default and every listed service.',

            // ── check-auth.js ──────────────────────────────────────────────────
            checkAutoBlockFailTitle: 'Automatic Account Blocking Is Not Configured',
            checkAutoBlockPassTitle: 'Automatic Account Blocking Is Active',
            checkAutoBlockDesc:      'Without account blocking, attackers can attempt unlimited password combinations against DSM and all enabled services. Even a modest rate of attempts can eventually succeed against weak passwords.',
            checkAutoBlockAffected:  'All DSM login services',
            checkAutoBlockRemediation: 'Enable auto block in Control Panel › Security › Account › Enable auto block. Configure a low attempt count (e.g., 5 attempts in 2 minutes).',
            checkAccountProtectionFailTitle: 'Account Protection Is Disabled',
            checkAccountProtectionPassTitle: 'Account Protection Is Enabled',
            checkAccountProtectionDesc:      'Auto block counts failed logins per IP address. An attacker who spreads guesses over many addresses never reaches that limit. Account protection counts per account and locks it for untrusted clients after repeated failures.',
            checkAccountProtectionRemediation: 'Enable account protection: Control Panel › Security › Account › Account Protection.',

            checkHTTPSRedirectFailTitle: 'HTTP Does Not Redirect to HTTPS',
            checkHTTPSRedirectPassTitle: 'HTTP Automatically Redirects to HTTPS',
            checkHTTPSRedirectDesc:      'Without HTTPS redirect, the DSM web interface and any reverse-proxied applications can be accessed over unencrypted HTTP. This exposes credentials and session tokens to network eavesdropping.',
            checkHTTPSRedirectAffected:  'DSM web interface (HTTP port)',
            checkHTTPSRedirectRemediation: 'Enable HTTPS redirect in Control Panel › Login Portal › DSM › Enable HTTPS redirect.',

            checkHSTSFailTitle: 'HTTP Strict Transport Security (HSTS) Is Not Enabled',
            checkHSTSPassTitle: 'HTTP Strict Transport Security (HSTS) Is Active',
            checkHSTSDesc:      'Without HSTS, browsers may allow users to bypass TLS certificate warnings or accept downgrade attacks. HSTS instructs browsers to always connect via HTTPS for a defined period. Note: in DSM, the HSTS option may be greyed out if no valid certificate with a custom domain is configured. If you access DSM exclusively via IP address, this finding may not be applicable.',
            checkHSTSAffected:  'DSM web interface',
            checkHSTSRemediation: 'Control Panel › Login Portal › DSM tab › Enable HTTP Strict Transport Security (HSTS). If the option is greyed out, a valid certificate with a custom domain must be configured first (Control Panel › Security › Certificate).',

            // ── check-websecurity.js ───────────────────────────────────────────
            checkCSRFFailTitle:  'CSRF Protection Is Not Enabled',
            checkCSRFPassTitle:  'CSRF Protection Is Active',
            checkCSRFDesc:       'Cross-Site Request Forgery (CSRF) attacks trick authenticated users into unknowingly executing actions in DSM. Without CSRF protection, an attacker can craft a malicious web page that silently performs administrative actions inside the victim\'s active DSM session.',
            checkCSRFAffected:   'DSM web interface',
            checkCSRFRemediation: 'Enable CSRF protection: Control Panel › Security › Security › Improve protection against Cross-Site Request Forgery attacks.',

            checkIFrameFailTitle: 'DSM Can Be Embedded in iFrames',
            checkIFramePassTitle: 'DSM iFrame Embedding Is Blocked',
            checkIFrameDesc:      'If DSM can be embedded in an iFrame on a third-party website, attackers can use clickjacking — overlaying an invisible DSM frame to trick users into clicking UI elements without their knowledge.',
            checkIFrameAffected:  'DSM web interface',
            checkIFrameRemediation: 'Block iFrame embedding: Control Panel › Security › Security › Do not allow DSM to be embedded in iFrames.',

            checkIPCheckFailTitle: 'Session IP Binding Is Disabled',
            checkIPCheckPassTitle: 'Session IP Binding Is Active',
            checkIPCheckDesc:      'When IP binding is disabled, DSM no longer verifies that requests within a session originate from the same IP address as the login. This makes it easier for an attacker who obtains a valid session token to reuse it from a different machine.',
            checkIPCheckAffected:  'DSM session management',
            checkIPCheckRemediation: 'Re-enable IP binding: Control Panel › Security › Security › uncheck "Improve browser compatibility by skipping IP checking".',

            // ── check-users.js ─────────────────────────────────────────────────
            checkAdminActiveFailTitle:  'Default Admin Account Is Active',
            checkAdminActivePassTitle:  'Default Admin Account Is Disabled',
            checkAdminActiveDesc:       'The built-in "admin" account is active. Synology recommends disabling it and using a named personal account for administration. The default admin name is a predictable brute-force target.',
            checkAdminActiveRemediation: 'Disable the admin account: Control Panel › User & Group › select "admin" › Edit › Deactivate this account.',
            checkGuestFailTitle:        'Guest Account Is Active',
            checkGuestPassTitle:        'Guest Account Is Disabled',
            checkGuestDesc:             'The built-in guest account allows access without a password. Every shared folder that grants guest read or write permission is open to anyone who can reach the NAS. Listed items are shared folders with explicit guest access.',
            checkGuestRemediation:      'Disable the guest account: Control Panel › User & Group › select "guest" › Edit › Disable this account. Then remove guest permissions from shared folders.',
            checkAdminsFailTitle:       '{0} Active Accounts Have Administrator Rights',
            checkAdminsPassTitle:       '{0} Active Account(s) With Administrator Rights',
            checkAdminsDesc:            'Every administrator account is a full takeover path if its password leaks. Keep administrator rights to at most {0} personal accounts and use regular accounts for daily work and for service or backup users.',
            checkAdminsRemediation:     'Review the administrators group: Control Panel › User & Group › Group › administrators › Edit › Members. Remove accounts that do not need full administrative access.',

            checkPwdPolicyDisabledFailTitle: 'Password Policy Is Not Enforced',
            checkPwdPolicyDisabledDesc:      'No password strength rules are applied. Users can set arbitrarily simple passwords, making all accounts highly vulnerable to brute-force and credential-stuffing attacks.',
            checkPwdPolicyDisabledRemediation: 'Enable password strength rules: Control Panel › User & Group › Advanced › Password Settings › Apply password strength rules.',

            checkPwdLengthFailTitle:    'Minimum Password Length Is Below Recommended Threshold',
            checkPwdLengthPassTitle:    'Minimum Password Length Meets Recommended Threshold',
            checkPwdLengthDesc:         'The current minimum password length ({0} characters) is below the recommended minimum of 12. Short passwords are significantly easier to crack by brute-force or dictionary attacks.',
            checkPwdLengthRemediation:  'Increase the minimum password length to at least 12 characters: Control Panel › User & Group › Advanced › Password Settings.',

            checkPwdSpecialFailTitle:   'Password Policy Does Not Require Special Characters',
            checkPwdSpecialPassTitle:   'Password Policy Requires Special Characters',
            checkPwdSpecialDesc:        'Requiring at least one special character significantly increases password entropy and resistance to dictionary attacks.',
            checkPwdSpecialRemediation: 'Enable "Include special characters" in the password strength settings: Control Panel › User & Group › Advanced › Password Settings.',

            checkPwdCommonFailTitle:    'Common Password Check Is Not Enabled',
            checkPwdCommonPassTitle:    'Common Password Check Is Active',
            checkPwdCommonDesc:         'Without a common password check, users may set easily-guessable passwords such as "Password1!" that technically meet complexity rules but offer minimal real-world security.',
            checkPwdCommonRemediation:  'Control Panel › User & Group › Advanced › Password Settings › enable "Exclude common passwords".',

            // ── check-maintenance.js ───────────────────────────────────────────
            checkConfigBackupFailTitle: 'Automatic Configuration Backup Is Not Configured',
            checkConfigBackupPassTitle: 'Automatic Configuration Backup Is Configured',
            checkConfigBackupDesc:      'Without a scheduled configuration backup, a hardware failure, ransomware attack, or misconfiguration could make recovery difficult or impossible. Synology DSM supports automated backups to a local share.',
            checkConfigBackupRemediation: 'Configure automatic configuration backup: Control Panel › Update & Restore › Configuration Backup › Back Up Configuration.',
            checkSecurityUpdatesFailTitle: 'Security Updates Are Not Installed Automatically',
            checkSecurityUpdatesPassTitle: 'Security Updates Are Installed Automatically',
            checkSecurityUpdatesDesc:      'DSM is set to notify only. Security fixes stay uninstalled until someone applies them manually, which leaves known vulnerabilities open in the meantime. Synology regularly patches remotely exploitable flaws in DSM.',
            checkSecurityUpdatesRemediation: 'Allow DSM to install important updates automatically: Control Panel › Update & Restore › DSM Update › Update Settings.',
            checkNotifyFailTitle:       'No Notifications Are Enabled',
            checkNotifyPassTitle:       'Notifications Are Enabled',
            checkNotifyDesc:            'Email, push and SMS notifications are all off. DSM then reports blocked login attempts, failing drives or a degraded volume to nobody; problems only show up when someone logs in and looks.',
            checkNotifyRemediation:     'Turn on email or push notifications: Control Panel › Notification › Email or Push Service.',

            checkSMBSigningFailTitle:   'SMB Server Signing Not Enforced',
            checkSMBSigningPassTitle:   'SMB Server Signing Enforced (Force)',
            checkSMBSigningDesc:        'SMB signing ensures that packets cannot be tampered with in transit. "Disable SMB1 signing on" (the default) only auto-negotiates signing — a man-in-the-middle can strip it. Only "Force" actively requires all clients to sign, protecting against NTLM relay attacks. Note: if the NAS is domain-joined, the AD DC must also enforce signing.',
            checkSMBSigningRemediation: 'Control Panel › File Services › SMB › Advanced Settings › General tab › Server signing status → "Force".',

            // ── check-bestpractices.js ─────────────────────────────────────────
            bpCheckTransferLogPassTitle:        'SMB Transfer Log Is Disabled',
            bpCheckTransferLogFailTitle:        'SMB Transfer Log Is Enabled',
            bpCheckTransferLogDesc:             'Logging every SMB file operation generates significant I/O overhead and disk usage on production servers. Disable transfer logging unless actively required for compliance or troubleshooting.',
            bpCheckTransferLogRemediation:      'Disable transfer log: Control Panel › File Services › SMB › Advanced Settings › Enable transfer log.',

            bpCheckStrictAllocatePassTitle:     'File Space Pre-allocation Is Disabled',
            bpCheckStrictAllocateFailTitle:     'File Space Pre-allocation Is Enabled',
            bpCheckStrictAllocateDesc:          '"Do not reserve disk space when creating files" improves write performance by using sparse file allocation instead of pre-allocating the full file size on disk. Pre-allocation can significantly slow write-heavy workloads.',
            bpCheckStrictAllocateRemediation:   'Disable strict allocation: Control Panel › File Services › SMB › Advanced Settings › Do not reserve disk space when creating files.',

            bpCheckAIOReadPassTitle:            'Asynchronous SMB Read Is Enabled',
            bpCheckAIOReadFailTitle:            'Asynchronous SMB Read Is Disabled',
            bpCheckAIOReadDesc:                 'Asynchronous read (AIO) allows the server to process multiple SMB read requests concurrently, significantly improving throughput for multi-client workloads.',
            bpCheckAIOReadRemediation:          'Enable async read: Control Panel › File Services › SMB › Advanced Settings › Enable asynchronous read.',

            bpCheckMultichannelPassTitle:       'SMB Multichannel Is Enabled',
            bpCheckMultichannelFailTitle:       'SMB Multichannel Is Disabled',
            bpCheckMultichannelDesc:            'SMB3 Multichannel allows clients with multiple network adapters to aggregate all available interfaces simultaneously, dramatically increasing throughput and providing automatic network failover.',
            bpCheckMultichannelRemediation:     'Enable SMB Multichannel: Control Panel › File Services › SMB › Advanced Settings › Enable SMB3 Multichannel.',

            bpCheckAFPPassTitle:                'AFP Service Is Disabled',
            bpCheckAFPFailTitle:                'AFP Service Is Enabled',
            bpCheckAFPDesc:                     'Apple Filing Protocol (AFP) is deprecated and has been removed from macOS Ventura and later. Modern Macs connect via SMB3. Running AFP adds unnecessary attack surface and maintenance overhead without benefit for current Apple clients.',
            bpCheckAFPRemediation:              'Disable AFP: Control Panel › File Services › AFP › uncheck "Enable AFP service".',

            bpCheckFastClonePassTitle:          'File Fast Clone (Reflink) Is Enabled',
            bpCheckFastCloneFailTitle:          'File Fast Clone (Reflink) Is Disabled',
            bpCheckFastCloneDesc:               'Fast Clone uses btrfs reflinks to create instant, space-efficient file copies without duplicating data on disk. This is a major performance feature for virtual machine storage, Docker volumes, and backup workflows.',
            bpCheckFastCloneRemediation:        'Enable File Fast Clone: Control Panel › File Services › Advanced › Enable file fast clone.',

            bpCheckUpdateNotifyPassTitle:       'DSM Feature Updates Are Not Installed Automatically',

            bpCheckRecycleTaskPassTitle:        'Recycle Bin Cleanup Task Is Configured',
            bpCheckRecycleTaskFailTitle:        'No Recycle Bin Cleanup Task Found',
            bpCheckRecycleTaskDesc:             'Without a scheduled recycle bin cleanup, deleted files accumulate indefinitely. This silently consumes disk space and can trigger unexpected storage alerts on production NAS systems.',
            bpCheckRecycleTaskRemediation:      'Create a scheduled task to empty the recycle bin: Control Panel › Task Scheduler › Create › Scheduled Task › Recycle Bin.',

            bpCheckSymlinksPassTitle:           'Cross-Share Symlinks Are Disabled',
            bpCheckSymlinksFailTitle:           'Cross-Share Symlinks Are Enabled',
            bpCheckSymlinksDesc:                'When cross-share symlinks are enabled, a symbolic link inside one shared folder can point to files in another share — potentially giving SMB users access to data outside their intended scope. Disabling this constrains symlinks to their own share.',
            bpCheckSymlinksRemediation:         'Disable cross-share symlinks: Control Panel › File Services › SMB › Advanced Settings › Others tab › uncheck "Allow symbolic links across shared folders".',

            // ── Compliance view UI ─────────────────────────────────────────────
            frameworksLabel:         'Frameworks',
            clearFiltersBtn:         'Clear',
            clearAllFiltersBtn:      'Clear all filters',
            findingPlural:           'issues',
            findingSingular:         'issue',
            filteredBy:              'filtered by',
            ofTotal:                 'of',
            noFindingsTitle:         'No Issues Found',
            noFindingsSub:           'All security checks passed.',
            noFilterMatchTitle:      'No findings match the filter',
            noFilterMatchSub:        'Clear the filters to see all failed checks.',
            noFindingsSubUnknown:    'No failed checks, but {0} could not be evaluated (see below).',
            issueCount:              '1 issue',
            issuesCount:             '{0} issues',
            severityPass:            'Pass',
            passedChecks:            'Passed checks',
            severityUnknown:         'Not checked',
            unknownChecks:           'Checks that could not be evaluated',
            unknownTitle:            'Could not evaluate: {0}',
            unknownDesc:             'The setting is missing from the backup or could not be read. It is not counted in the score. Verify it manually in DSM.',
            checkNameQC:             'QuickConnect',
            checkNameAdvisories:     'Known critical DSM vulnerabilities',
            checkNameServices:       'Optional services (rsync, NFS, SNMP)',
            checkAdvisoriesFailTitle:   'DSM Build {0} Is Affected by Known Critical Vulnerabilities',
            checkAdvisoriesPassTitle:   'No Known Critical Vulnerabilities for DSM Build {0}',
            checkAdvisoriesUnknownTitle: 'Update Level of DSM Build {0} Cannot Be Determined',
            checkAdvisoriesDesc:        'Synology lists this DSM build as affected by critical vulnerabilities, some of which can be exploited without signing in. The result reflects the state at the time of the backup.',
            checkAdvisoriesUnknownDesc: 'The backup contains the build number but not the installed update. These advisories are fixed by an update of this build:',
            checkAdvisoriesRemediation: 'Install the latest DSM update under Control Panel › Update & Restore and check the version there. Until a fix is installed: deactivate the OAuth Service package (SA-26:21) and disable HTTP/2 under Control Panel › Network › Connectivity (SA-26:20).',
            checkAdvisoryFixedIn:       'fixed in {0}',
            checkAdvisoryNoFix:         'no fix released yet',
            checkAdvisoryHttp2On:       'HTTP/2 is enabled',
            checkServicesFailTitle:     'Optional Network Services Are Enabled',
            checkServicesPassTitle:     'rsync, NFS and SNMP Are Disabled',
            checkServicesDesc:          'Every enabled service is additional attack surface. In November 2026 Synology fixed vulnerabilities in rsync (CVE-2026-85101), the NFS server (CVE-2026-18633) and the SNMP API (CVE-2026-86343).',
            checkServicesRemediation:   'Disable services that are not needed: rsync under Control Panel › File Services › rsync, NFS under File Services › NFS, SNMP under Terminal & SNMP › SNMP.',
            bpCheckPortsFailTitle:      'DSM or SSH Uses the Default Port',
            bpCheckPortsPassTitle:      'DSM Uses Custom Ports',
            bpCheckPortsDesc:           'Automated scanners try the default ports first. A changed port does not stop a targeted attack, but it reduces login attempts in the logs.',
            bpCheckPortsRemediation:    'Change the DSM ports under Control Panel › Login Portal › DSM and the SSH port under Control Panel › Terminal & SNMP.',
            checkNameSSH:            'SSH',
            checkNameTelnet:         'Telnet',
            checkNameNTLMv1:         'NTLMv1',
            checkNameDoS:            'DoS protection',
            checkNameCSRF:           'CSRF protection',
            checkNameIFrame:         'iFrame embedding',
            checkNameIPCheck:        'Session IP binding',
            checkNamePwdLength:      'Minimum password length',
            checkNameSMBMinProto:    'SMB minimum protocol',
            checkNameAdmin:          'Default admin account',
            checkNameGuest:          'Guest account',
            checkNameAdmins:         'Number of administrators',
            checkNameFirewall:       'Firewall',
            checkNameTLS:            'TLS versions of web services',
            checkNameConfigBackup:   'Automatic configuration backup',
            checkNameSecurityUpdates: 'Automatic security updates',
            checkNameNotify:          'Notifications',
            checkNameAccountProtection: 'Account protection',
            checkNameAutoBlock:      'Auto block',
            checkNameHTTPSRedirect:  'HTTPS redirect',
            checkNameHSTS:           'HSTS',
            checkNamePwdPolicy:      'Password strength rules',
            checkNameSMBSigning:     'SMB signing',
            checkNameFTPTLS:         'FTP encryption',
            affectedItems:           'Affected items',
            howToFix:                'How to fix',

            // ── About ──────────────────────────────────────────────────────────
            aboutBtn:         'About this tool',
            aboutHeaderBtn:   'About',
            closeLabel:       'Close',
            langGroupLabel:   'Language',
            scoreAriaLabel:   'Security score',
            findingsRegionLabel: 'Findings',
            contextBarLabel: 'Backup details',
            fwChipClean: 'no issues',
            announceLoaded:   'Backup analysed: {0}.',
            announceFiltered: '{0} shown.',
            announceCompared: 'Backups compared. Check results: {0}. Settings: {1}.',
            compareLead:      'Two NAS or two points in time?',
            compareBrowse:    'Compare two backups',
            errCompareCount:  'Select exactly two .dss files to compare.',
            compareTitle:     'Backup comparison',
            compareBtnNew:    'Start over',
            compareSideA:     'Backup A',
            compareSideB:     'Backup B',
            compareColSetting: 'Setting',
            compareColResult: 'Result',
            compareStatusChanged: 'Different',
            compareStatusSame:    'Same',
            compareStatusOnlyA:   'Only in A',
            compareStatusOnlyB:   'Only in B',
            compareStatusUnknown: 'Not comparable',
            compareValueMissing:    'not present',
            compareValueUnreadable: 'not readable',
            compareValueHidden:     'hidden',
            compareValueEmpty:      '(empty)',
            compareSummary:   '{0} different, {1} only in A, {2} only in B, {3} not comparable',
            compareScope:     'Compares the system settings such as SMB, FTP, NFS, ports and password rules. Users, shares and scheduled tasks only count through the check results.',
            compareHiddenNote: 'Values of settings whose names point to passwords, keys, certificates or mail, and values longer than 32 characters, are compared but not shown. Shorter values such as IP addresses or host names are shown.',
            compareShowAll:   'Show unchanged settings',
            compareNoDifferences: 'No differences in the system settings.',
            compareSettingsTitle: 'System settings',
            compareFindingsTitle: 'Check results',
            compareFindingsNote:  'Failed checks and checks that could not be evaluated, from both the security and the best practice checks. Passed checks are not listed.',
            compareFindingsSummary: '{0} only in A, {1} only in B, {2} with different affected items',
            compareFindingsOnlyA: 'Only in backup A',
            compareFindingsOnlyB: 'Only in backup B',
            compareFindingsItemsChanged: 'In both, with different affected items',
            compareFindingsNone:  'No differences in which checks are open or in their affected items.',
            compareItemsOnlyA:    'only in A: {0}',
            compareItemsOnlyB:    'only in B: {0}',
            aboutMaker:       'JKLP CONSULTING · SECURITY AUDIT',
            aboutDesc:        'Synology Inspector analyses Synology DSM configuration backups (.dss) directly in your browser — no data is ever uploaded. It checks your NAS configuration against security best practices and common compliance frameworks.',
            aboutChannelName: 'JKLP Consulting',
            aboutChannelDesc: 'Security audits, NAS hardening guides, and IT security for SMEs.',
            aboutWebsiteName: 'jklp.io',
            aboutWebsiteDesc: 'Book a security consultation',
            aboutBadgeFree:   'Free for personal use',
            aboutBadgeOS:     'Source available',
            aboutBadgePrivacy:'No data leaves your browser',

            // ── Excluded checks section ────────────────────────────────────────
            excludedChecksTitle: 'Deliberately Excluded Checks',
            excludedChecksDesc:  'Inspector intentionally omits recommendations to move services to non-standard port numbers — such as changing SSH away from port 22 or the DSM web interface away from its default ports. This is Security by Obscurity: it does not reduce the attack surface, adds operational overhead, and creates a false sense of security. Any port scanner finds a service regardless of which port it runs on.',

            // ── About SbO note ─────────────────────────────────────────────────
            aboutSoBNote: 'Inspector deliberately excludes "Security by Obscurity" checks — such as recommendations to change default port numbers. These add operational overhead without providing real security.',

            // ── Disclaimer ─────────────────────────────────────────────────────
            disclaimerTitle:  'Important Notice',
            disclaimerItem1:  'This tool provides automated analysis as technical guidance only and does not replace a professional security audit.',
            disclaimerItem2:  'It makes no claim to completeness or correctness.',
            disclaimerItem3:  'Results serve as technical orientation only and do not constitute professional security advice.',
            disclaimerItem4:  'The mapping to compliance frameworks is for technical orientation only and does not constitute certification or legal assessment.',
            disclaimerItem5:  'The tool analyses backups in read-only mode and makes no changes to your Synology NAS.',
            disclaimerFooter: 'Use at your own risk.',
        },

        de: {
            // ── Compliance view UI ─────────────────────────────────────────────
            frameworksLabel:         'Frameworks',
            clearFiltersBtn:         'Zurücksetzen',
            clearAllFiltersBtn:      'Alle Filter zurücksetzen',
            findingPlural:           'Befunde',
            findingSingular:         'Befund',
            filteredBy:              'gefiltert nach',
            ofTotal:                 'von',
            noFindingsTitle:         'Keine Befunde',
            noFindingsSub:           'Alle Sicherheitsprüfungen bestanden.',
            noFilterMatchTitle:      'Keine Befunde für diesen Filter',
            noFilterMatchSub:        'Filter zurücksetzen, um alle fehlgeschlagenen Prüfungen zu sehen.',
            noFindingsSubUnknown:    'Keine fehlgeschlagenen Prüfungen, aber {0} nicht auswertbar (siehe unten).',
            issueCount:              '1 Befund',
            issuesCount:             '{0} Befunde',
            severityPass:            'OK',
            passedChecks:            'Bestandene Prüfungen',
            severityUnknown:         'Nicht geprüft',
            unknownChecks:           'Nicht auswertbare Prüfungen',
            unknownTitle:            'Nicht auswertbar: {0}',
            unknownDesc:             'Die Einstellung fehlt im Backup oder konnte nicht gelesen werden. Sie fließt nicht in die Bewertung ein. Bitte manuell in DSM prüfen.',
            checkNameQC:             'QuickConnect',
            checkNameAdvisories:     'Bekannte kritische DSM-Sicherheitslücken',
            checkNameServices:       'Optionale Dienste (rsync, NFS, SNMP)',
            checkAdvisoriesFailTitle:   'DSM-Build {0} ist von bekannten kritischen Sicherheitslücken betroffen',
            checkAdvisoriesPassTitle:   'Keine bekannten kritischen Sicherheitslücken für DSM-Build {0}',
            checkAdvisoriesUnknownTitle: 'Update-Stand von DSM-Build {0} nicht bestimmbar',
            checkAdvisoriesDesc:        'Synology führt diesen DSM-Build als betroffen von kritischen Sicherheitslücken, die teils ohne Anmeldung ausnutzbar sind. Das Ergebnis gibt den Stand zum Zeitpunkt des Backups wieder.',
            checkAdvisoriesUnknownDesc: 'Das Backup enthält die Build-Nummer, aber nicht das installierte Update. Diese Advisories werden durch ein Update dieses Builds behoben:',
            checkAdvisoriesRemediation: 'Das neueste DSM-Update unter Systemsteuerung › Aktualisieren & Wiederherstellen installieren und die Version dort prüfen. Bis dahin: das Paket OAuth Service deaktivieren (SA-26:21) und HTTP/2 unter Systemsteuerung › Netzwerk › Konnektivität abschalten (SA-26:20).',
            checkAdvisoryFixedIn:       'behoben in {0}',
            checkAdvisoryNoFix:         'noch kein Fix verfügbar',
            checkAdvisoryHttp2On:       'HTTP/2 ist aktiv',
            checkServicesFailTitle:     'Optionale Netzwerkdienste sind aktiv',
            checkServicesPassTitle:     'rsync, NFS und SNMP sind deaktiviert',
            checkServicesDesc:          'Jeder aktive Dienst vergrößert die Angriffsfläche. Im November 2026 hat Synology Lücken in rsync (CVE-2026-85101), im NFS-Server (CVE-2026-18633) und in der SNMP-API (CVE-2026-86343) behoben.',
            checkServicesRemediation:   'Nicht benötigte Dienste abschalten: rsync unter Systemsteuerung › Dateidienste › rsync, NFS unter Dateidienste › NFS, SNMP unter Terminal & SNMP › SNMP.',
            bpCheckPortsFailTitle:      'DSM oder SSH nutzt den Standard-Port',
            bpCheckPortsPassTitle:      'DSM nutzt eigene Ports',
            bpCheckPortsDesc:           'Automatische Scanner probieren zuerst die Standard-Ports. Ein geänderter Port stoppt keinen gezielten Angriff, verringert aber die Anmeldeversuche im Log.',
            bpCheckPortsRemediation:    'DSM-Ports unter Systemsteuerung › Anmeldeportal › DSM ändern, den SSH-Port unter Systemsteuerung › Terminal & SNMP.',
            checkNameSSH:            'SSH',
            checkNameTelnet:         'Telnet',
            checkNameNTLMv1:         'NTLMv1',
            checkNameDoS:            'DoS-Schutz',
            checkNameCSRF:           'CSRF-Schutz',
            checkNameIFrame:         'iFrame-Einbettung',
            checkNameIPCheck:        'IP-Bindung der Sitzung',
            checkNamePwdLength:      'Mindestlänge für Passwörter',
            checkNameSMBMinProto:    'SMB-Mindestprotokoll',
            checkNameAdmin:          'Standard-Admin-Konto',
            checkNameGuest:          'Gastkonto',
            checkNameAdmins:         'Anzahl der Administratoren',
            checkNameFirewall:       'Firewall',
            checkNameTLS:            'TLS-Versionen der Webdienste',
            checkNameConfigBackup:   'Automatische Konfigurationssicherung',
            checkNameSecurityUpdates: 'Automatische Sicherheitsupdates',
            checkNameNotify:          'Benachrichtigungen',
            checkNameAccountProtection: 'Kontoschutz',
            checkNameAutoBlock:      'Automatische Kontosperrung',
            checkNameHTTPSRedirect:  'HTTPS-Weiterleitung',
            checkNameHSTS:           'HSTS',
            checkNamePwdPolicy:      'Regeln für Passwortstärke',
            checkNameSMBSigning:     'SMB-Signierung',
            checkNameFTPTLS:         'FTP-Verschlüsselung',
            affectedItems:           'Betroffene Elemente',
            howToFix:                'So beheben',

            // ── About ──────────────────────────────────────────────────────────
            aboutBtn:         'Über dieses Tool',
            aboutHeaderBtn:   'Über',
            closeLabel:       'Schließen',
            langGroupLabel:   'Sprache',
            scoreAriaLabel:   'Sicherheitsbewertung',
            findingsRegionLabel: 'Befunde',
            contextBarLabel: 'Details der Sicherung',
            fwChipClean: 'keine Befunde',
            announceLoaded:   'Sicherung analysiert: {0}.',
            announceFiltered: '{0} angezeigt.',
            announceCompared: 'Sicherungen verglichen. Prüfergebnisse: {0}. Einstellungen: {1}.',
            compareLead:      'Zwei NAS oder zwei Zeitpunkte?',
            compareBrowse:    'Zwei Sicherungen vergleichen',
            errCompareCount:  'Für den Vergleich genau zwei .dss-Dateien auswählen.',
            compareTitle:     'Vergleich der Sicherungen',
            compareBtnNew:    'Neu beginnen',
            compareSideA:     'Sicherung A',
            compareSideB:     'Sicherung B',
            compareColSetting: 'Einstellung',
            compareColResult: 'Ergebnis',
            compareStatusChanged: 'Unterschiedlich',
            compareStatusSame:    'Gleich',
            compareStatusOnlyA:   'Nur in A',
            compareStatusOnlyB:   'Nur in B',
            compareStatusUnknown: 'Nicht vergleichbar',
            compareValueMissing:    'nicht vorhanden',
            compareValueUnreadable: 'nicht lesbar',
            compareValueHidden:     'verborgen',
            compareValueEmpty:      '(leer)',
            compareSummary:   '{0} unterschiedlich, {1} nur in A, {2} nur in B, {3} nicht vergleichbar',
            compareScope:     'Verglichen werden die Systemeinstellungen wie SMB, FTP, NFS, Ports und Passwortregeln. Benutzer, Freigaben und geplante Aufgaben fließen nur über die Prüfergebnisse ein.',
            compareHiddenNote: 'Werte von Einstellungen, deren Namen auf Passwörter, Schlüssel, Zertifikate oder E-Mail hindeuten, und Werte über 32 Zeichen werden verglichen, aber nicht angezeigt. Kürzere Werte wie IP-Adressen oder Hostnamen sind sichtbar.',
            compareShowAll:   'Unveränderte Einstellungen anzeigen',
            compareNoDifferences: 'Keine Unterschiede in den Systemeinstellungen.',
            compareSettingsTitle: 'Systemeinstellungen',
            compareFindingsTitle: 'Prüfergebnisse',
            compareFindingsNote:  'Fehlgeschlagene Sicherheits- und Best-Practice-Prüfungen sowie Prüfungen, die nicht ausgewertet werden konnten. Bestandene Prüfungen werden nicht aufgeführt.',
            compareFindingsSummary: '{0} nur in A, {1} nur in B, {2} mit anderen betroffenen Einträgen',
            compareFindingsOnlyA: 'Nur in Sicherung A',
            compareFindingsOnlyB: 'Nur in Sicherung B',
            compareFindingsItemsChanged: 'In beiden, mit anderen betroffenen Einträgen',
            compareFindingsNone:  'Keine Unterschiede bei den offenen Prüfungen und ihren betroffenen Einträgen.',
            compareItemsOnlyA:    'nur in A: {0}',
            compareItemsOnlyB:    'nur in B: {0}',
            aboutMaker:       'JKLP CONSULTING · SICHERHEITSAUDIT',
            aboutDesc:        'Synology Inspector analysiert Synology DSM-Konfigurationssicherungen (.dss) direkt im Browser – ohne Datenübertragung. Er prüft die NAS-Konfiguration gegen Sicherheits-Best-Practices und gängige Compliance-Frameworks.',
            aboutChannelName: 'JKLP Consulting',
            aboutChannelDesc: 'Security-Audits, NAS-Hardening-Guides und IT-Sicherheit für KMU.',
            aboutWebsiteName: 'jklp.io',
            aboutWebsiteDesc: 'Beratungsgespräch buchen',
            aboutBadgeFree:   'Kostenlos für Privatnutzung',
            aboutBadgeOS:     'Quellcode einsehbar',
            aboutBadgePrivacy:'Keine Daten verlassen Ihren Browser',

            // ── Excluded checks section ────────────────────────────────────────
            excludedChecksTitle: 'Bewusst ausgeschlossene Prüfungen',
            excludedChecksDesc:  'Inspector verzichtet bewusst auf Empfehlungen, Dienste auf nicht-standardmäßige Portnummern zu verlegen — z. B. SSH von Port 22 wegzuverlegen oder die DSM-Weboberfläche von ihren Standard-Ports zu ändern. Dies ist Security by Obscurity: Es reduziert die Angriffsfläche nicht, erhöht den Betriebsaufwand und vermittelt ein falsches Sicherheitsgefühl. Jeder Portscanner findet einen Dienst unabhängig davon, auf welchem Port er läuft.',

            // ── About SbO note ─────────────────────────────────────────────────
            aboutSoBNote: 'Inspector schließt „Security by Obscurity"-Prüfungen bewusst aus — z. B. Empfehlungen, Standard-Portnummern zu ändern. Diese erhöhen den Betriebsaufwand, ohne echten Sicherheitsgewinn zu bringen.',

            // ── Disclaimer ─────────────────────────────────────────────────────
            disclaimerTitle:  'Wichtiger Hinweis',
            disclaimerItem1:  'Dieses Tool bietet eine automatisierte Analyse als technische Orientierungshilfe und ersetzt kein professionelles Security Audit.',
            disclaimerItem2:  'Es erhebt keinen Anspruch auf Vollständigkeit oder Korrektheit.',
            disclaimerItem3:  'Ergebnisse liefern technische Anhaltspunkte, ersetzen jedoch keine professionelle Sicherheitsberatung.',
            disclaimerItem4:  'Die Zuordnung zu Compliance-Frameworks dient ausschließlich der technischen Orientierung und stellt keine Zertifizierung oder rechtliche Bewertung dar.',
            disclaimerItem5:  'Das Tool analysiert Backups ausschließlich lesend und nimmt keine Änderungen an Ihrem Synology NAS vor.',
            disclaimerFooter: 'Benutzung auf eigene Gefahr.',

            // ── UI chrome ────────────────────────────────────────────────────
            appTitle:        'Synology Inspector',
            appVersion:      'v1.1',
            appSubtitle:     'JKLP CONSULTING · SICHERHEITSAUDIT',

            // ── Drop zone ────────────────────────────────────────────────────
            dropTitle:       'Synology .dss-Backup hier ablegen',
            dropOr:          'oder',
            dropBrowse:      'Datei auswählen',
            dropFormats:     'Unterstützt: Synology Konfigurationssicherung (.dss) – DSM 7+',
            dropPrivacy:     'Die Datei wird ausschließlich im Browser verarbeitet. Es werden keine Daten an einen Server übertragen.',

            // ── States ────────────────────────────────────────────────────────
            loading:         'Backup wird analysiert…',
            loadingHint:     'Dekomprimierung und Analyse — dies kann einige Sekunden dauern.',
            btnNewFile:      'Weitere Datei analysieren',
            btnExportPDF:    'PDF exportieren',
            pdfReportTitle:  'Sicherheitsbericht',
            pdfAnalysedOn:   'Analysiert am',
            pdfIssues:       'Befunde',

            // ── Errors ────────────────────────────────────────────────────────
            errFileRead:     'Datei konnte nicht gelesen werden',
            errDecompress:   'Dekomprimierung fehlgeschlagen (ist dies eine gültige .dss-Datei?)',
            errNoDb:         'Keine Konfigurationsdatenbank im Backup gefunden',
            errParse:        'Backup konnte nicht analysiert werden',
            errUnknown:      'Ein unerwarteter Fehler ist aufgetreten',

            // ── Context bar ────────────────────────────────────────────────────
            labelFileName:   'Datei',
            labelFileSize:   'Größe',
            labelDSMVersion: 'DSM',
            labelModel:      'Modell',
            labelHostname:   'Hostname',

            // ── Compliance view ────────────────────────────────────────────────
            complianceTitle:     'Sicherheitsbewertung',
            filterAll:           'Alle',
            filterFailed:        'Nur Befunde',
            labelFindings:       'Befunde',
            labelAffected:       'Betroffen',
            labelRemediation:    'Behebung',
            labelFrameworks:     'Referenzen',
            labelNoFindings:     'Keine Befunde.',

            // ── Severity labels ────────────────────────────────────────────────
            severityCritical:    'Kritisch',
            severityHigh:        'Hoch',
            severityMedium:      'Mittel',
            severityLow:         'Niedrig',
            severityInfo:        'Info',

            // ── Verdicts ──────────────────────────────────────────────────────
            verdictStrong:       'Starke Sicherheitslage',
            verdictGood:         'Gute Sicherheitslage',
            verdictAcceptable:   'Akzeptabel – Verbesserungen empfohlen',
            verdictImprove:      'Verbesserungsbedarf',
            verdictExposure:     'Erhebliches Risiko',
            verdictCritical:     'Kritisch – Sofortiger Handlungsbedarf',

            // ── Tab bar ───────────────────────────────────────────────────────
            tabSecurity:         'Sicherheitsprüfung',
            tabBestPractices:    'Best Practices',

            // ── Best Practices view ───────────────────────────────────────────
            bpViewTitle:         'Best-Practices-Bewertung',
            bpNoIssuesTitle:     'Alle Best-Practice-Prüfungen bestanden',
            bpNoIssuesSub:       'Ihre Konfiguration entspricht allen empfohlenen Best Practices.',

            // ── Categories ────────────────────────────────────────────────────
            catRemoteAccess:     'Fernzugriff',
            catProtocols:        'Protokolle',
            catAuth:             'Authentifizierung',
            catUsers:            'Benutzerkonten',
            catMaintenance:      'Wartung',
            catNetwork:          'Netzwerksicherheit',
            catBPSMB:            'SMB-Performance',
            catBPStorage:        'Dateidienste & Speicher',
            catBPUpdates:        'Update-Verwaltung',
            catBPScheduler:      'Aufgabenplaner',
            catBPNetwork:        'Netzwerk',

            // ── check-remote-access.js ─────────────────────────────────────────
            checkQCFailTitle:    'QuickConnect ist aktiviert',
            checkQCPassTitle:    'QuickConnect ist deaktiviert',
            checkQCDesc:         'QuickConnect leitet Verbindungen über die Relay-Server von Synology, wodurch ein dauerhafter eingehender Pfad zum NAS entsteht, der Ihr Netzwerkperimeter umgeht. Auch ohne Port-Weiterleitungen werden Verwaltungsschnittstellen dem Internet zugänglich gemacht.',
            checkQCRemediation:  'QuickConnect deaktivieren: Systemsteuerung › Externer Zugriff › QuickConnect.',

            checkSSHFailTitle:    'SSH ist aktiviert',
            checkSSHPassTitle:    'SSH ist deaktiviert',
            checkSSHDesc:         'SSH stellt eine Remote-Kommandozeilenschnittstelle zum NAS bereit. Falls SSH nicht aktiv benötigt wird, sollte es deaktiviert werden, um die Angriffsfläche zu minimieren. Falls SSH erforderlich ist, sollte der Zugriff per Firewall auf vertrauenswürdige Quelladressen beschränkt und schlüsselbasierte Authentifizierung erzwungen werden.',
            checkSSHRemediation:  'SSH deaktivieren, wenn nicht benötigt: Systemsteuerung › Terminal & SNMP › Terminal. Falls SSH erforderlich ist, Zugriff einschränken: Systemsteuerung › Sicherheit › Firewall.',

            checkTelnetFailTitle: 'Telnet ist aktiviert',
            checkTelnetPassTitle: 'Telnet ist deaktiviert',
            checkTelnetDesc:      'Telnet überträgt alle Daten einschließlich Anmeldedaten im Klartext. Jeder Netzwerkbeobachter kann Passwörter und Sitzungsinhalte mitlesen. SSH ist der sichere Ersatz für alle Remote-Shell-Zugriffe.',
            checkTelnetRemediation: 'Telnet deaktivieren: Systemsteuerung › Terminal & SNMP › Terminal.',

            // ── check-network.js ───────────────────────────────────────────────
            checkDoSFailTitle:       'DoS-Schutz ist nicht auf allen Schnittstellen aktiviert',
            checkDoSPassTitle:       'DoS-Schutz ist auf allen Schnittstellen aktiv',
            checkDoSDesc:            'DoS-Schutz (Denial of Service) verwirft fehlerhafte und Flood-Pakete, bevor sie Systemressourcen erschöpfen können. Ohne diesen Schutz können selbst einfache Netzwerkfluten die NAS-Reaktionsfähigkeit für legitime Benutzer beeinträchtigen.',
            checkDoSRemediation:     'DoS-Schutz aktivieren: Systemsteuerung › Sicherheit › Schutz › DoS-Schutz aktivieren.',
            checkFirewallFailTitle:  'Firewall ist deaktiviert',
            checkFirewallPassTitle:  'Firewall ist aktiviert',
            checkFirewallDesc:       'Die DSM-Firewall ist ausgeschaltet. Jeder Dienst auf dem NAS ist damit von jeder Adresse erreichbar, die das NAS routen kann. Ein vorgeschalteter Router schützt nicht vor Geräten im selben Netz.',
            checkFirewallRemediation: 'Firewall aktivieren und nur benötigte Dienste und Quellnetze zulassen: Systemsteuerung › Sicherheit › Firewall › Firewall aktivieren.',

            // ── check-protocols.js ─────────────────────────────────────────────
            checkSMB1FailTitle:  'SMBv1 ist erlaubt',
            checkSMB1PassTitle:  'SMBv1 ist deaktiviert',
            checkSMB1Desc:       'SMBv1 ist ein veraltetes Protokoll aus den 1980er Jahren ohne Verschlüsselung oder Integritätsprüfung. Es ist der Angriffsvektor für EternalBlue (WannaCry, NotPetya). Alle modernen Clients unterstützen SMB2 oder SMB3.',
            checkSMB1Remediation: 'Mindest-SMB-Version auf SMB2 oder höher setzen: Systemsteuerung › Dateidienste › SMB.',

            checkNTLMv1FailTitle: 'NTLMv1-Authentifizierung ist aktiviert',
            checkNTLMv1PassTitle: 'NTLMv1-Authentifizierung ist deaktiviert',
            checkNTLMv1Desc:      'NTLMv1 ist ein kryptografisch schwaches Authentifizierungsprotokoll, das für Pass-the-Hash- und NTLM-Relay-Angriffe anfällig ist. NTLMv2 ist das Minimum, Kerberos wird bevorzugt.',
            checkNTLMv1Remediation: 'NTLMv1 deaktivieren: Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen.',

            checkFTPAnonFailTitle: 'FTP-Anonymzugriff ist aktiviert',
            checkFTPAnonDesc:      'Anonymer FTP-Zugriff erlaubt Verbindungen ohne Anmeldedaten. Dies macht freigegebene Dateien ohne Authentifizierung zugänglich und kann zur Datenexfiltration missbraucht werden.',
            checkFTPAnonRemediation: 'Anonymen FTP-Zugriff deaktivieren: Systemsteuerung › Dateidienste › FTP.',

            checkFTPTLSFailTitle: 'FTP läuft ohne TLS',
            checkFTPTLSPassTitle: 'FTP verwendet TLS-Verschlüsselung',
            checkFTPTLSDesc:      'FTP ohne TLS überträgt Anmeldedaten und Dateiinhalte im Klartext. Jeder auf dem Netzwerkpfad kann Passwörter und Daten mitlesen. FTPS oder SFTP sollte stattdessen verwendet werden.',
            checkFTPTLSRemediation: 'FTPS aktivieren: Systemsteuerung › Dateidienste › FTP › FTP SSL/TLS-Verschlüsselung aktivieren.',
            checkFTPTLSOptionalFailTitle: 'FTP erzwingt kein TLS',
            checkFTPTLSOptionalDesc:      'FTPS wird angeboten, aber nicht erzwungen. Clients können sich weiterhin unverschlüsselt verbinden und Anmeldedaten sowie Dateiinhalte im Klartext senden. Nur verschlüsselte FTP-Verbindungen zulassen oder auf SFTP (SSH File Transfer Protocol) umsteigen.',
            checkFTPTLSOptionalRemediation: 'Den FTP-Dienst unter Systemsteuerung › Dateidienste › FTP so einstellen, dass nur SSL/TLS-Verbindungen angenommen werden, oder stattdessen SFTP nutzen.',
            checkTLSFailTitle:      'Veraltete TLS-Versionen sind erlaubt',
            checkTLSPassTitle:      'Webdienste erlauben nur TLS 1.2 oder neuer',
            checkTLSDesc:           'TLS 1.0 und 1.1 sind seit 2021 abgekündigt (RFC 8996) und unter PCI DSS nicht zulässig. Dienste, die sie noch annehmen, lassen Clients auf schwache Cipher-Suites ausweichen. Geprüft werden die nginx-basierten Dienste des TLS-Profils (DSM, QuickConnect, Reverse Proxy, Anwendungsportal).',
            checkTLSRemediation:    'TLS-Profil auf „Mittlere Kompatibilität“ oder „Moderne Kompatibilität“ anheben: Systemsteuerung › Sicherheit › Erweitert › TLS-/SSL-Profilebene, für den Systemstandard und jeden aufgeführten Dienst.',

            // ── check-auth.js ──────────────────────────────────────────────────
            checkAutoBlockFailTitle: 'Automatische Kontosperrung ist nicht konfiguriert',
            checkAutoBlockPassTitle: 'Automatische Kontosperrung ist aktiv',
            checkAutoBlockDesc:      'Ohne Kontosperrung können Angreifer unbegrenzte Passwortversuche gegen DSM und alle aktivierten Dienste starten. Bereits eine moderate Versuchsrate kann bei schwachen Passwörtern erfolgreich sein.',
            checkAutoBlockAffected:  'Alle DSM-Anmeldedienste',
            checkAutoBlockRemediation: 'Automatische Sperrung aktivieren: Systemsteuerung › Sicherheit › Konto › Automatische Sperrung aktivieren. Niedrige Schwellenwerte konfigurieren (z. B. 5 Versuche in 2 Minuten).',
            checkAccountProtectionFailTitle: 'Kontoschutz ist deaktiviert',
            checkAccountProtectionPassTitle: 'Kontoschutz ist aktiviert',
            checkAccountProtectionDesc:      'Die automatische Blockierung zählt Fehlversuche je IP-Adresse. Wer seine Versuche auf viele Adressen verteilt, erreicht dieses Limit nie. Der Kontoschutz zählt je Konto und sperrt es nach wiederholten Fehlversuchen für nicht vertrauenswürdige Clients.',
            checkAccountProtectionRemediation: 'Kontoschutz aktivieren: Systemsteuerung › Sicherheit › Konto › Kontoschutz.',

            checkHTTPSRedirectFailTitle: 'HTTP leitet nicht auf HTTPS um',
            checkHTTPSRedirectPassTitle: 'HTTP leitet automatisch auf HTTPS um',
            checkHTTPSRedirectDesc:      'Ohne HTTPS-Weiterleitung kann die DSM-Weboberfläche unverschlüsselt über HTTP aufgerufen werden. Dies ermöglicht das Abfangen von Anmeldedaten und Sitzungstoken.',
            checkHTTPSRedirectAffected:  'DSM-Weboberfläche (HTTP-Port)',
            checkHTTPSRedirectRemediation: 'HTTPS-Weiterleitung aktivieren: Systemsteuerung › Anmeldeportal › DSM › HTTPS-Weiterleitung aktivieren.',

            checkHSTSFailTitle: 'HTTP Strict Transport Security (HSTS) ist nicht aktiviert',
            checkHSTSPassTitle: 'HTTP Strict Transport Security (HSTS) ist aktiv',
            checkHSTSDesc:      'Ohne HSTS können Browser TLS-Zertifikatswarnungen umgehen oder Downgrade-Angriffe akzeptieren. HSTS weist Browser an, für einen definierten Zeitraum ausschließlich HTTPS zu verwenden. Hinweis: Die HSTS-Option ist in DSM ausgegraut, solange kein gültiges Zertifikat mit benutzerdefinierter Domain eingerichtet ist. Bei reinem IP-Zugriff auf das NAS ist dieser Befund möglicherweise nicht anwendbar.',
            checkHSTSAffected:  'DSM-Weboberfläche',
            checkHSTSRemediation: 'Systemsteuerung › Anmeldeportal › DSM-Tab › HTTP Strict Transport Security (HSTS) aktivieren. Ist die Option ausgegraut, muss zunächst ein gültiges Zertifikat mit benutzerdefinierter Domain eingerichtet werden (Systemsteuerung › Sicherheit › Zertifikat).',

            // ── check-websecurity.js ───────────────────────────────────────────
            checkCSRFFailTitle:  'CSRF-Schutz ist nicht aktiviert',
            checkCSRFPassTitle:  'CSRF-Schutz ist aktiv',
            checkCSRFDesc:       'Cross-Site-Request-Forgery-Angriffe (CSRF) verleiten authentifizierte Benutzer dazu, unwissentlich Aktionen in DSM auszuführen. Ohne CSRF-Schutz kann ein Angreifer eine bösartige Webseite erstellen, die still administrative Aktionen in einer aktiven DSM-Sitzung des Opfers ausführt.',
            checkCSRFAffected:   'DSM-Weboberfläche',
            checkCSRFRemediation: 'CSRF-Schutz aktivieren: Systemsteuerung › Sicherheit › Sicherheit › Schutz gegen Cross-Site-Request-Forgery-Attacken verbessern.',

            checkIFrameFailTitle: 'DSM kann in iFrames eingebettet werden',
            checkIFramePassTitle: 'DSM-iFrame-Einbettung ist blockiert',
            checkIFrameDesc:      'Wenn DSM auf einer fremden Webseite in einem iFrame eingebettet werden kann, können Angreifer Clickjacking einsetzen — ein unsichtbarer DSM-Frame überlagert die Seite und verleitet Benutzer dazu, unwissentlich UI-Elemente zu klicken.',
            checkIFrameAffected:  'DSM-Weboberfläche',
            checkIFrameRemediation: 'iFrame-Einbettung blockieren: Systemsteuerung › Sicherheit › Sicherheit › Nicht zulassen, dass DSM in iFrame eingebettet wird.',

            checkIPCheckFailTitle: 'Sitzungs-IP-Bindung ist deaktiviert',
            checkIPCheckPassTitle: 'Sitzungs-IP-Bindung ist aktiv',
            checkIPCheckDesc:      'Wenn die IP-Bindung deaktiviert ist, prüft DSM nicht mehr, ob Anfragen innerhalb einer Sitzung von derselben IP-Adresse wie die Anmeldung stammen. Dies erleichtert es einem Angreifer, der ein gültiges Sitzungstoken erlangt, es von einem anderen Gerät zu verwenden.',
            checkIPCheckAffected:  'DSM-Sitzungsverwaltung',
            checkIPCheckRemediation: 'IP-Bindung reaktivieren: Systemsteuerung › Sicherheit › Sicherheit › "Browserkompatibilität durch Verzicht auf IP-Prüfung verbessern" deaktivieren.',

            // ── check-users.js ─────────────────────────────────────────────────
            checkAdminActiveFailTitle:  'Standard-Admin-Konto ist aktiv',
            checkAdminActivePassTitle:  'Standard-Admin-Konto ist deaktiviert',
            checkAdminActiveDesc:       'Das integrierte "admin"-Konto ist aktiv. Synology empfiehlt, es zu deaktivieren und stattdessen ein persönliches benanntes Konto für die Administration zu verwenden. Der standardisierte Kontoname ist ein vorhersehbares Ziel für Brute-Force-Angriffe.',
            checkAdminActiveRemediation: 'Admin-Konto deaktivieren: Systemsteuerung › Benutzer & Gruppe › "admin" auswählen › Bearbeiten › Dieses Konto deaktivieren.',
            checkGuestFailTitle:        'Gastkonto ist aktiv',
            checkGuestPassTitle:        'Gastkonto ist deaktiviert',
            checkGuestDesc:             'Das eingebaute Gastkonto erlaubt Zugriff ohne Passwort. Jeder freigegebene Ordner mit Lese- oder Schreibrecht für guest steht damit allen offen, die das NAS erreichen. Aufgeführt sind freigegebene Ordner mit ausdrücklichem Gastzugriff.',
            checkGuestRemediation:      'Gastkonto deaktivieren: Systemsteuerung › Benutzer & Gruppe › "guest" auswählen › Bearbeiten › Dieses Konto deaktivieren. Anschließend Gastrechte von freigegebenen Ordnern entfernen.',
            checkAdminsFailTitle:       '{0} aktive Konten haben Administratorrechte',
            checkAdminsPassTitle:       '{0} aktive(s) Konto/Konten mit Administratorrechten',
            checkAdminsDesc:            'Jedes Administratorkonto ist ein vollständiger Übernahmeweg, falls sein Passwort abhandenkommt. Administratorrechte auf höchstens {0} persönliche Konten beschränken; für die tägliche Arbeit sowie für Dienst- und Backup-Benutzer normale Konten verwenden.',
            checkAdminsRemediation:     'Gruppe administrators prüfen: Systemsteuerung › Benutzer & Gruppe › Gruppe › administrators › Bearbeiten › Mitglieder. Konten ohne Bedarf an vollem Administratorzugriff entfernen.',

            checkPwdPolicyDisabledFailTitle: 'Kennwortrichtlinie ist nicht aktiviert',
            checkPwdPolicyDisabledDesc:      'Es werden keine Kennwortstärkeregeln angewendet. Benutzer können beliebig einfache Kennwörter setzen, was alle Konten für Brute-Force- und Credential-Stuffing-Angriffe anfällig macht.',
            checkPwdPolicyDisabledRemediation: 'Kennwortstärkeregeln aktivieren: Systemsteuerung › Benutzer & Gruppe › Erweitert › Kennworteinstellungen › Kennwortstärkeregeln anwenden.',

            checkPwdLengthFailTitle:    'Minimale Kennwortlänge liegt unter dem empfohlenen Schwellenwert',
            checkPwdLengthPassTitle:    'Minimale Kennwortlänge entspricht dem empfohlenen Schwellenwert',
            checkPwdLengthDesc:         'Die aktuelle Mindestkennwortlänge ({0} Zeichen) liegt unter dem empfohlenen Minimum von 12. Kurze Kennwörter sind deutlich einfacher durch Brute-Force- oder Wörterbuchangriffe zu knacken.',
            checkPwdLengthRemediation:  'Mindestkennwortlänge auf mindestens 12 Zeichen erhöhen: Systemsteuerung › Benutzer & Gruppe › Erweitert › Kennworteinstellungen.',

            checkPwdSpecialFailTitle:   'Kennwortrichtlinie erfordert keine Sonderzeichen',
            checkPwdSpecialPassTitle:   'Kennwortrichtlinie erfordert Sonderzeichen',
            checkPwdSpecialDesc:        'Die Anforderung mindestens eines Sonderzeichens erhöht die Kennwort-Entropie und die Resistenz gegen Wörterbuchangriffe erheblich.',
            checkPwdSpecialRemediation: '"Sonderzeichen einschließen" in den Kennwortstärkeeinstellungen aktivieren: Systemsteuerung › Benutzer & Gruppe › Erweitert › Kennworteinstellungen.',

            checkPwdCommonFailTitle:    'Prüfung auf gängige Kennwörter ist nicht aktiviert',
            checkPwdCommonPassTitle:    'Prüfung auf gängige Kennwörter ist aktiv',
            checkPwdCommonDesc:         'Ohne Prüfung auf gängige Kennwörter können Benutzer leicht erratbare Kennwörter wie "Passwort1!" setzen, die technisch die Komplexitätsregeln erfüllen, aber in der Praxis kaum Sicherheit bieten.',
            checkPwdCommonRemediation:  'Systemsteuerung › Benutzer und Gruppe › Erweitert › Passwort-Einstellungen › „Schwache Kennwörter ausschließen" aktivieren.',

            // ── check-maintenance.js ───────────────────────────────────────────
            checkConfigBackupFailTitle: 'Automatische Konfigurationssicherung ist nicht konfiguriert',
            checkConfigBackupPassTitle: 'Automatische Konfigurationssicherung ist konfiguriert',
            checkConfigBackupDesc:      'Ohne geplante Konfigurationssicherung kann ein Hardwareausfall, Ransomware-Angriff oder eine Fehlkonfiguration die Wiederherstellung erheblich erschweren oder unmöglich machen. DSM unterstützt automatische Sicherungen auf einer lokalen Freigabe.',
            checkConfigBackupRemediation: 'Automatische Konfigurationssicherung einrichten: Systemsteuerung › Aktualisierung & Wiederherstellung › Konfigurationssicherung.',
            checkSecurityUpdatesFailTitle: 'Sicherheitsupdates werden nicht automatisch installiert',
            checkSecurityUpdatesPassTitle: 'Sicherheitsupdates werden automatisch installiert',
            checkSecurityUpdatesDesc:      'DSM ist auf „Nur benachrichtigen“ eingestellt. Sicherheitskorrekturen bleiben uninstalliert, bis jemand sie von Hand einspielt; bekannte Schwachstellen bleiben so lange offen. Synology schließt in DSM regelmäßig Lücken, die aus der Ferne ausnutzbar sind.',
            checkSecurityUpdatesRemediation: 'DSM wichtige Updates automatisch installieren lassen: Systemsteuerung › Aktualisierung & Wiederherstellung › DSM-Aktualisierung › Update-Einstellungen.',
            checkNotifyFailTitle:       'Keine Benachrichtigungen aktiviert',
            checkNotifyPassTitle:       'Benachrichtigungen sind aktiviert',
            checkNotifyDesc:            'E-Mail-, Push- und SMS-Benachrichtigungen sind alle aus. DSM meldet dann niemandem blockierte Anmeldeversuche, ausfallende Laufwerke oder ein beeinträchtigtes Volume; Probleme fallen erst auf, wenn sich jemand anmeldet und nachsieht.',
            checkNotifyRemediation:     'E-Mail- oder Push-Benachrichtigungen einschalten: Systemsteuerung › Benachrichtigung › E-Mail bzw. Push-Dienst.',

            checkSMBSigningFailTitle:   'SMB-Serversignatur nicht erzwungen',
            checkSMBSigningPassTitle:   'SMB-Serversignatur erzwungen (Force)',
            checkSMBSigningDesc:        'SMB-Signierung verhindert die Manipulation von Paketen während der Übertragung. Die Option „SMB1-Signierung deaktivieren ein" (Standard) verhandelt Signierung nur automatisch — ein Angreifer kann sie wegstreichen. Nur „Erzwingen" schreibt Signierung für alle Clients vor und schützt so vor NTLM-Relay-Angriffen. Hinweis: Bei domänengebundenem NAS muss auch der AD DC Signierung erzwingen.',
            checkSMBSigningRemediation: 'Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen › Reiter Allgemein › Server-Signierstatus → „Erzwingen".',

            // ── check-bestpractices.js ─────────────────────────────────────────
            bpCheckTransferLogPassTitle:        'SMB Transfer-Log ist deaktiviert',
            bpCheckTransferLogFailTitle:        'SMB Transfer-Log ist aktiviert',
            bpCheckTransferLogDesc:             'Das Protokollieren jeder SMB-Dateioperation erzeugt erheblichen I/O-Overhead und Festplattenverbrauch auf Produktionsservern. Deaktivieren Sie Transfer-Logging, sofern es nicht für Compliance oder Fehleranalyse benötigt wird.',
            bpCheckTransferLogRemediation:      'Transfer-Log deaktivieren: Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen › Transfer-Log aktivieren.',

            bpCheckStrictAllocatePassTitle:     'Speicherplatzvorreservierung ist deaktiviert',
            bpCheckStrictAllocateFailTitle:     'Speicherplatzvorreservierung ist aktiviert',
            bpCheckStrictAllocateDesc:          '"Keinen Speicherplatz beim Erstellen von Dateien reservieren" verbessert die Schreibleistung durch Verwendung von Sparse-File-Zuweisung statt Vorab-Allokation der vollen Dateigröße. Vorab-Allokation kann schreibintensive Workloads erheblich verlangsamen.',
            bpCheckStrictAllocateRemediation:   'Strikte Allokation deaktivieren: Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen › Keinen Speicherplatz beim Erstellen von Dateien reservieren.',

            bpCheckAIOReadPassTitle:            'Asynchrones SMB-Lesen ist aktiviert',
            bpCheckAIOReadFailTitle:            'Asynchrones SMB-Lesen ist deaktiviert',
            bpCheckAIOReadDesc:                 'Asynchrones Lesen (AIO) ermöglicht es dem Server, mehrere SMB-Leseanfragen gleichzeitig zu verarbeiten, was den Durchsatz bei Multi-Client-Workloads erheblich verbessert.',
            bpCheckAIOReadRemediation:          'Asynchrones Lesen aktivieren: Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen › Asynchrones Lesen aktivieren.',

            bpCheckMultichannelPassTitle:       'SMB Multichannel ist aktiviert',
            bpCheckMultichannelFailTitle:       'SMB Multichannel ist deaktiviert',
            bpCheckMultichannelDesc:            'SMB3 Multichannel ermöglicht Clients mit mehreren Netzwerkadaptern, alle verfügbaren Schnittstellen gleichzeitig zu nutzen, was den Durchsatz erheblich steigert und automatisches Netzwerk-Failover bietet.',
            bpCheckMultichannelRemediation:     'SMB Multichannel aktivieren: Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen › SMB3 Multichannel aktivieren.',

            bpCheckAFPPassTitle:                'AFP-Dienst ist deaktiviert',
            bpCheckAFPFailTitle:                'AFP-Dienst ist aktiviert',
            bpCheckAFPDesc:                     'Apple Filing Protocol (AFP) ist veraltet und wurde ab macOS Ventura entfernt. Moderne Macs verbinden sich über SMB3. Das Ausführen von AFP erzeugt unnötige Angriffsfläche und Wartungsaufwand ohne Nutzen für aktuelle Apple-Clients.',
            bpCheckAFPRemediation:              'AFP deaktivieren: Systemsteuerung › Dateidienste › AFP › "AFP-Dienst aktivieren" deaktivieren.',

            bpCheckFastClonePassTitle:          'File Fast Clone (Reflink) ist aktiviert',
            bpCheckFastCloneFailTitle:          'File Fast Clone (Reflink) ist deaktiviert',
            bpCheckFastCloneDesc:               'Fast Clone nutzt btrfs-Reflinks, um sofortige, platzsparende Dateikopien ohne Datenduplizierung zu erstellen. Dies ist ein entscheidendes Performance-Feature für VM-Storage, Docker-Volumes und Backup-Workflows.',
            bpCheckFastCloneRemediation:        'File Fast Clone aktivieren: Systemsteuerung › Dateidienste › Erweitert › Datei-Fast-Clone aktivieren.',

            bpCheckUpdateNotifyPassTitle:       'DSM-Funktionsupdates werden nicht automatisch installiert',

            bpCheckRecycleTaskPassTitle:        'Papierkorb-Bereinigungsaufgabe ist konfiguriert',
            bpCheckRecycleTaskFailTitle:        'Keine Papierkorb-Bereinigungsaufgabe gefunden',
            bpCheckRecycleTaskDesc:             'Ohne geplante Papierkorbleerung häufen sich gelöschte Dateien unbegrenzt an. Dies verbraucht stillschweigend Festplattenplatz und kann zu unerwarteten Speicheralarmen auf Produktionssystemen führen.',
            bpCheckRecycleTaskRemediation:      'Geplante Aufgabe zur Papierkorbleerung erstellen: Systemsteuerung › Aufgabenplaner › Erstellen › Geplante Aufgabe › Papierkorb.',

            bpCheckSymlinksPassTitle:           'Freigaben-übergreifende Symlinks sind deaktiviert',
            bpCheckSymlinksFailTitle:           'Freigaben-übergreifende Symlinks sind aktiviert',
            bpCheckSymlinksDesc:                'Wenn freigaben-übergreifende Symlinks aktiviert sind, kann ein symbolischer Link in einer Freigabe auf Dateien in einer anderen Freigabe zeigen — und SMB-Benutzern damit Zugriff auf Daten außerhalb ihres vorgesehenen Bereichs ermöglichen. Das Deaktivieren beschränkt Symlinks auf ihre eigene Freigabe.',
            bpCheckSymlinksRemediation:         'Freigaben-übergreifende Symlinks deaktivieren: Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen › Reiter „Sonstiges" › Häkchen bei „Symbolische Links für freigegebene Ordner zulassen" entfernen.',

        },
    };

    // ── Runtime ────────────────────────────────────────────────────────────────

    // Storage access throws when the browser blocks site data (e.g. file:// in
    // some privacy modes); the app must still work without a stored language.
    let _lang = 'en';
    try { _lang = localStorage.getItem('syno-inspector-lang') || 'en'; } catch (_) {}
    if (!STRINGS[_lang]) _lang = 'en';
    document.documentElement.lang = _lang;

    window.t = function (key, ...args) {
        let str = (STRINGS[_lang] && STRINGS[_lang][key]) ||
                  (STRINGS['en']  && STRINGS['en'][key])  ||
                  key;
        // One pass with a replacer function: a value that contains "$&" or
        // "{1}" is inserted literally instead of being expanded again
        str = str.replace(/\{(\d+)\}/g, (match, i) => (i < args.length ? String(args[i]) : match));
        return str;
    };

    window.setLanguage = function (lang) {
        if (!STRINGS[lang]) return;
        _lang = lang;
        try { localStorage.setItem('syno-inspector-lang', lang); } catch (_) {}
        document.documentElement.lang = lang;
        // Update active button state
        document.querySelectorAll('.lang-btn').forEach(btn => {
            btn.classList.toggle('lang-btn--active', btn.dataset.lang === lang);
        });
        if (typeof renderApp === 'function') renderApp();
    };

    window.getCurrentLanguage = function () { return _lang; };
}());
