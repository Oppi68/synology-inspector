/**
 * dss-pipeline.js
 *
 * Parses a Synology .dss configuration backup file and returns the structured
 * data needed by the compliance checks.
 *
 * .dss format:
 *   XZ-compressed TAR archive
 *   └── ConfigBkp/
 *       ├── _Syno_ConfBkp.db          — SQLite key-value store (main config)
 *       ├── config_info                — plain text: OS version, model
 *       └── tls_profile/
 *           └── datastore.json         — TLS level per service
 *
 * Dependencies (must be loaded before this file):
 *   xz-decompress.js  → window['xz-decompress'].XzReadableStream
 *   tar-parser.js     → parseTar()
 *   sqlite-reader.js  → buildSynoConfigMap(), buildSynoExtras()
 *
 * Returns a Promise<ParseResult> where ParseResult is:
 * {
 *   config:               Map<string, string>   key-value pairs from SQLite
 *   tlsProfile:           Object | null         parsed tls_profile/datastore.json
 *   tlsConfigs:           Array                 nginx TLS snippets { name, text } from tls_profile/config/*.conf
 *   info:                 Object                DSM version, model, etc.
 *   fileName:             string
 *   fileSize:             number
 *   users:                Array                 local user accounts { name, uid, expire }
 *   adminMembers:         string[]              members of the administrators group
 *   sharePrivileges:      Array                 explicit share permissions { share, type, name, privilege }
 *   schedulerTasks:       Array | null          scheduler tasks { app, state, name },
 *                                               null if a task row cannot be read
 *   autoBackupConfigured: boolean | null        true if auto config backup is configured,
 *                                               null if the backup does not contain the state
 *   accountProtectionEnabled: boolean | null    DSM account protection switch, null if unknown
 *   hasBtrfs:             boolean               true if any volume uses btrfs
 * }
 */

/**
 * Parse the config_info plain-text file.
 * Format: key="value"\n per line (shell variable syntax).
 *
 * @param {Uint8Array} data
 * @returns {Object}
 */
function parseConfigInfo(data) {
    const text   = new TextDecoder('utf-8', { fatal: false }).decode(data);
    const result = {};
    for (const line of text.split('\n')) {
        const m = line.match(/^(\w+)="([^"]*)"/);
        if (m) result[m[1]] = m[2];
    }
    return result;
}

/**
 * Decompress an XZ-compressed Uint8Array using XzReadableStream (xz-decompress).
 *
 * @param {Uint8Array} compressed
 * @returns {Promise<Uint8Array>}
 */
// Config backups are a few MB; anything far beyond that is not a DSM backup
// and would exhaust the browser's memory (decompression bomb).
const DSS_MAX_TAR_BYTES = 256 * 1024 * 1024;

async function decompressXZ(compressed, maxBytes = DSS_MAX_TAR_BYTES) {
    const XzReadableStream = window['xz-decompress']?.XzReadableStream;
    if (!XzReadableStream) {
        throw new Error('xz-decompress not loaded');
    }

    const inputStream = new ReadableStream({
        start(controller) {
            controller.enqueue(compressed);
            controller.close();
        }
    });

    const xzStream = new XzReadableStream(inputStream);
    const reader   = xzStream.getReader();
    const chunks   = [];
    let totalLen   = 0;

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        totalLen += value.length;
        if (totalLen > maxBytes) {
            await reader.cancel();
            throw new Error(`decompressed data too large (over ${Math.round(maxBytes / 1048576)} MB)`);
        }
        chunks.push(value);
    }

    const result   = new Uint8Array(totalLen);
    let offset     = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
    return result;
}

/**
 * Main entry point.  Reads a File (or Blob) and resolves with a ParseResult.
 *
 * @param {File} file
 * @returns {Promise<ParseResult>}
 */
function parseDSSFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onerror = () => reject(new Error(t('errFileRead')));

        reader.onload = async (event) => {
            const rawBytes = new Uint8Array(event.target.result);

            let tarBytes;
            try {
                // Step 1: XZ decompression
                tarBytes = await decompressXZ(rawBytes);
            } catch (err) {
                return reject(new Error(t('errDecompress') + ': ' + err.message));
            }

            try {
                // Step 2: TAR parsing
                const tarEntries = parseTar(tarBytes);

                // Step 3: locate required files
                const dbEntry      = findTarEntry(tarEntries, '_Syno_ConfBkp.db');
                const infoEntry    = findTarEntry(tarEntries, 'config_info');
                const tlsJsonEntry = findTarEntry(tarEntries, 'tls_profile/datastore.json');
                const tlsConfigEntries = tarEntries.filter(e => /(^|\/)tls_profile\/config\/[^/]+\.conf$/.test(e.name));

                if (!dbEntry) {
                    return reject(new Error(t('errNoDb')));
                }

                // Step 4: parse SQLite config + supplementary data
                const config = buildSynoConfigMap(dbEntry.data);
                const extras = buildSynoExtras(dbEntry.data);

                // Step 5: parse config_info
                const info = infoEntry ? parseConfigInfo(infoEntry.data) : {};

                // Step 6: parse TLS profile
                let tlsProfile = null;
                if (tlsJsonEntry) {
                    try {
                        const json = new TextDecoder('utf-8').decode(tlsJsonEntry.data);
                        tlsProfile = JSON.parse(json);
                    } catch (_) { /* not critical */ }
                }

                const tlsConfigs = tlsConfigEntries.map(e => ({
                    name: e.name,
                    text: new TextDecoder('utf-8').decode(e.data),
                }));

                resolve({
                    config,
                    tlsProfile,
                    tlsConfigs,
                    info,
                    fileName: file.name,
                    fileSize: file.size,
                    users:                extras.users,
                    adminMembers:         extras.adminMembers,
                    sharePrivileges:      extras.sharePrivileges,
                    schedulerTasks:       extras.schedulerTasks,
                    autoBackupConfigured: extras.autoBackupConfigured,
                    accountProtectionEnabled: extras.accountProtectionEnabled,
                    hasBtrfs:             extras.hasBtrfs,
                });
            } catch (err) {
                reject(new Error(t('errParse') + ': ' + err.message));
            }
        };

        reader.readAsArrayBuffer(file);
    });
}
