# Synology Inspector

**Browser-based security audit tool for Synology DSM configuration backups.**

Synology Inspector analyses `.dss` backup files exported from Synology DiskStation Manager (DSM 7+) and checks your NAS configuration against security best practices and common compliance frameworks — entirely in your browser, with no data ever leaving your device.

---

## Features

- **Security checks** across Remote Access, Network, Protocols, Authentication, User Accounts, and Maintenance
- **Best Practices checks** for SMB performance, file services, updates, and task scheduler
- **Framework references** — CIS Controls, NIST SP 800-53, ISO 27001, NIS2, PCI DSS
- **Security score** with letter grade (A–F) and verdict
- **Filter by severity** — Critical, High, Medium, Low
- **EN / DE** — full English and German UI
- **100% client-side** — no server, no telemetry, no internet connection required
- **Source available** — every line of code is open to inspection before use

## Members

YouTube channel members receive an extended version with **PDF export** — a branded, print-ready security assessment report.

→ [youtube.com/@navigio1](https://www.youtube.com/@navigio1)

---

## How to Use

1. **Download** the latest release ZIP and unpack it
2. **Open** `index.html` in your browser (works from `file://` — no web server needed)
3. **Drop** your `.dss` backup file onto the upload area
4. **Review** the findings

### Exporting a Synology DSM backup

In DSM: **Control Panel → Update & Restore → Configuration Backup → Back Up Configuration**

The exported file has a `.dss` extension.

---

## Privacy

Your backup file is processed entirely within your browser using client-side JavaScript and WebAssembly. No data is transmitted to any server — not even anonymised telemetry. The tool works fully offline.

You are encouraged to review the source code before use.

---

## Supported DSM Versions

DSM 7.0 and later. DSM 6.x is not supported.

---

## Security Checks

| Category | Check | Severity |
|---|---|---|
| Remote Access | QuickConnect enabled | High |
| Remote Access | SSH enabled | Medium |
| Remote Access | Telnet enabled | Critical |
| Network Security | DoS protection not enabled on all interfaces | Medium |
| Network Security | Firewall disabled | Medium |
| Protocols | SMBv1 allowed | Critical |
| Protocols | NTLMv1 authentication enabled | High |
| Protocols | FTP anonymous access enabled | High |
| Protocols | FTP without TLS | Medium |
| Protocols | TLS 1.0/1.1 allowed on web services (DSM, QuickConnect, reverse proxy) | Medium |
| Protocols | SMB signing not enforced | Medium |
| Protocols | Optional services enabled (rsync, NFS, SNMP) | Low |
| Authentication | Automatic account blocking not configured | Medium |
| Authentication | Account protection disabled | Low |
| Authentication | HTTP does not redirect to HTTPS | Medium |
| Authentication | HSTS not enabled | Low |
| Authentication | CSRF protection not enabled | Medium |
| Authentication | DSM can be embedded in iFrames | Medium |
| Authentication | Session IP binding disabled | Medium |
| User Accounts | Default admin account active | High |
| User Accounts | Password policy not enforced | High |
| User Accounts | Minimum password length below 12 | Medium |
| User Accounts | Special characters not required | Low |
| User Accounts | Common password check disabled | Low |
| User Accounts | Guest account active (High if shared folders grant guest access) | Medium |
| User Accounts | More than two active administrator accounts | Low |
| Maintenance | Automatic configuration backup not configured | Medium |
| Maintenance | Security updates not installed automatically | Medium |
| Maintenance | No notification channel enabled (email, push, SMS) | Low |
| Maintenance | DSM build affected by a critical Synology security advisory | Critical |

If the backup does not contain the data a check needs, the check is listed as "could not evaluate" instead of passed. Such checks do not affect the score.

The advisory check compares the DSM build number with the fixed releases listed in `DSM_ADVISORIES` (`js/checks/check-advisories.js`). The backup does not record the installed update (the `-2` in `7.4.1-90080-2`), so an advisory fixed by an update of the device's own build is reported as "could not evaluate". When Synology publishes a new critical DSM advisory, add it to that table.

## Best Practice Checks

| Category | Check |
|---|---|
| SMB Performance | Transfer log enabled |
| SMB Performance | File space pre-allocation enabled |
| SMB Performance | Asynchronous SMB read disabled |
| SMB Performance | SMB Multichannel disabled |
| SMB Performance | Cross-share symlinks enabled |
| File Services & Storage | AFP service enabled (deprecated) |
| File Services & Storage | File Fast Clone disabled (btrfs only) |
| Update Management | DSM installs all updates automatically (security-only or notify-only is fine) |
| Task Scheduler | No recycle bin cleanup task configured |
| Network | DSM or SSH on a default port (5000, 5001, 22) |

---

## Development

The checks run in Node.js for testing, without a build step or dependencies (Node.js 22.13 or newer):

```sh
node --test tests/*.test.js
```

---

## License

Source Available — free for personal, non-commercial use.  
Commercial use requires written permission. See [LICENSE](LICENSE) for details.

© 2025–2026 Jürgen Barth, JKLP Consulting

---

## About

**JKLP Consulting** provides security audits, NAS hardening, and IT security advisory for small and medium-sized businesses.

- Website: [jklp.io](https://jklp.io)
- YouTube: [@navigio1](https://www.youtube.com/@navigio1)
- Contact: [contact@jklp.io](mailto:contact@jklp.io)
