/**
 * tar-parser.js
 *
 * Parse a POSIX/UStar TAR archive from a Uint8Array.
 * Returns an array of { name: string, data: Uint8Array } for all regular files.
 *
 * TAR header layout (512 bytes per block):
 *   Offset  Size  Field
 *     0     100   Filename (null-terminated UTF-8)
 *   124      12   File size in octal ASCII (null/space terminated)
 *   148       8   Header checksum in octal ASCII
 *   156       1   Type flag: '0'/NUL = regular file, '5' = directory, 'L' = long name
 *   257       6   UStar magic: "ustar\0" or "ustar "
 *   345     155   Filename prefix for paths > 100 bytes (UStar only)
 *
 * The data immediately follows the header block, padded up to the next
 * 512-byte boundary.  End-of-archive is two consecutive all-zero blocks.
 */

/**
 * Read a NUL/space terminated octal field; returns null if it is not plain octal.
 */
function tarReadOctal(bytes, offset, length) {
    let text = '';
    for (let i = offset; i < offset + length && bytes[i] !== 0; i++) text += String.fromCharCode(bytes[i]);
    text = text.trim();
    return /^[0-7]+$/.test(text) ? parseInt(text, 8) : null;
}

/**
 * Header checksum: sum of all 512 header bytes, the checksum field counted as spaces.
 */
function tarHeaderChecksum(bytes, offset) {
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += (i >= 148 && i < 156) ? 0x20 : bytes[offset + i];
    return sum;
}

/**
 * Parse a TAR archive and return all regular file entries.
 *
 * @param {Uint8Array|ArrayBuffer} buffer  Raw TAR bytes (uncompressed)
 * @returns {Array<{name: string, data: Uint8Array}>}
 * @throws  {Error} On a damaged header or a member cut off by the end of the archive
 */
function parseTar(buffer) {
    const bytes  = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const entries = [];
    const BLOCK   = 512;
    const decoder = new TextDecoder('utf-8', { fatal: false });
    let   offset  = 0;

    while (offset + BLOCK <= bytes.length) {
        // End-of-archive: two consecutive zero blocks
        let allZero = true;
        for (let i = 0; i < BLOCK; i++) {
            if (bytes[offset + i] !== 0) { allZero = false; break; }
        }
        if (allZero) break;

        // ── Filename (offset 0, 100 bytes) ───────────────────────────────────
        const nameSlice = bytes.subarray(offset, offset + 100);
        const nameNull  = nameSlice.indexOf(0);
        const name      = decoder.decode(nameSlice.subarray(0, nameNull === -1 ? 100 : nameNull));

        // ── UStar prefix (offset 345, 155 bytes) — only if magic present ─────
        let fullName = name;
        const magic = decoder.decode(bytes.subarray(offset + 257, offset + 263));
        if (magic.startsWith('ustar')) {
            const prefixSlice = bytes.subarray(offset + 345, offset + 500);
            const prefixNull  = prefixSlice.indexOf(0);
            const prefix      = decoder.decode(prefixSlice.subarray(0, prefixNull === -1 ? 155 : prefixNull));
            if (prefix.length > 0) fullName = `${prefix}/${name}`;
        }

        // ── Checksum (offset 148) and file size (offset 124, 12 bytes) ───────
        // A damaged header would misplace every following member
        if (tarReadOctal(bytes, offset + 148, 8) !== tarHeaderChecksum(bytes, offset)) {
            throw new Error(`Damaged archive header at offset ${offset}`);
        }
        const fileSize = tarReadOctal(bytes, offset + 124, 12);
        if (fileSize === null) throw new Error(`Invalid member size at offset ${offset}`);

        // ── Type flag (offset 156) ────────────────────────────────────────────
        const typeFlag      = bytes[offset + 156];
        const isRegularFile = (typeFlag === 0x30 || typeFlag === 0x00); // '0' or NUL

        offset += BLOCK; // advance past the header

        // A member whose data runs past the end means the archive was cut off
        if (offset + fileSize > bytes.length) throw new Error('Archive is truncated');

        if (isRegularFile && fileSize > 0 && fullName.length > 0) {
            // slice() creates an independent copy — safe to hold after parsing
            const data = bytes.slice(offset, offset + fileSize);
            entries.push({ name: fullName, data });
        }

        // Advance past data blocks (padded to 512-byte boundary)
        if (fileSize > 0) {
            offset += Math.ceil(fileSize / BLOCK) * BLOCK;
        }
    }

    return entries;
}

/**
 * Find the archive member at `path`, allowing any leading directories
 * (e.g. "ConfigBkp/" or "./ConfigBkp/") but no partial file names.
 *
 * @param {Array<{name: string}>} entries
 * @param {string}                path  e.g. "config_info" or "tls_profile/datastore.json"
 * @returns {{name: string, data: Uint8Array}|undefined}
 */
function findTarEntry(entries, path) {
    return entries.find(e => e.name === path || e.name.endsWith('/' + path));
}
