#!/usr/bin/env python3
"""Normalize a ditto-produced zip for deterministic packaging.

Usage: normalize_zip.py <archive.zip>

Applied in-place to the release archive after `ditto -c -k --keepParent`:

1. Normalize every 0x5855 (UT) extra subfield in both the local file
   headers and the central directory. The central shape is 8 bytes
   (atime mtime); the local shape is 12 bytes (atime mtime uid gid).
   APFS can advance atimes while ditto reads the tree (cache- and
   size-dependent), and ditto records the atime here; setting the atime
   word to the mtime word renders the archive independent of atime drift.
   The mtime word is trusted because `touch -t` pins mtime and reading
   never moves it. The local uid/gid word is zeroed: the staging user is
   a machine-state input whose values must not reach the published
   archive.

2. Remove AppleDouble `._*` sidecar entries. The com.apple.provenance xattr
   cannot be removed, so ditto emits a constant sidecar for every entry; the
   v0.5.0 archive layout excludes them. Removal rebuilds the central
   directory with updated local-header offsets.

The zip signature constants are built with bytes((...)) rather than backslash
escapes so the source is immune to backslash-doubling in text round-trips.

Safety: entries are located via the central directory (exact record stride)
and the per-entry local header offset; the raw byte stream is never scanned
for PK signatures (deflate payloads could contain false-positive signatures
and would corrupt content if the walk desynchronized). Every entry's data
region is size- and CRC-32-verified (decompressing for deflate entries),
unsupported methods, unexpected 0x5855 shapes, and any 0x5835 (XAttr)
subfield are rejected, and the rebuilt archive is re-parsed before being
written.
"""
import os
import struct
import sys
import zlib

# Zip record signatures (built without backslash escapes on purpose).
LOCAL_MAGIC = b"PK" + bytes((3, 4))   # local file header
CD_MAGIC = b"PK" + bytes((1, 2))      # central directory header
EOCD_MAGIC = b"PK" + bytes((5, 6))    # end of central directory

CD_FIELDS = "<" + "H" * 6 + "I" * 3 + "H" * 5 + "I" * 2
# ver_made ver flags method time date crc csize usize
# nlen elen clen disk iattr eattr lhref
LOCAL_FIELDS = "<" + "H" * 5 + "I" * 3 + "H" * 2
# ver flags method time date crc csize usize nlen elen


def die(path, message):
    raise SystemExit(f"{os.path.basename(path)}: {message}")


def patch_ut(extra, path):
    """Normalize every 0x5855 subfield in place and count the words written.

    The 8-byte shape (central directory) is atime mtime: the atime word is
    set to the mtime word. The 12-byte shape (local header) is atime mtime
    uid gid: do that, and zero the uid/gid word so the archive does not
    record the staging machine's owner. Any other size is not a shape this
    tool can interpret and is rejected.
    """
    rewritten = 0
    i = 0
    while i + 4 <= len(extra):
        tag, slen = struct.unpack_from("<HH", extra, i)
        if tag == 0x5855:
            if slen not in (8, 12):
                die(path, f"unexpected 0x5855 subfield shape len={slen}")
            mtime = struct.unpack_from("<I", extra, i + 8)[0]
            for w in range(2):
                off = i + 4 + 4 * w
                if struct.unpack_from("<I", extra, off)[0] != mtime:
                    struct.pack_into("<I", extra, off, mtime)
                    rewritten += 1
            if slen == 12 and struct.unpack_from("<I", extra, i + 12)[0] != 0:
                struct.pack_into("<I", extra, i + 12, 0)
                rewritten += 1
        elif tag == 0x5835:
            die(path, f"unexpected 0x5835 (XAttr) subfield len={slen}")
        i += 4 + slen
    return rewritten


def walk_central(blob, path):
    eocd = blob.rfind(EOCD_MAGIC)
    if eocd < 0:
        die(path, "not a zip (no end-of-central-directory record)")
    count = struct.unpack_from("<H", blob, eocd + 10)[0]
    cd_off = struct.unpack_from("<I", blob, eocd + 16)[0]
    cd_size = struct.unpack_from("<I", blob, eocd + 12)[0]
    if blob[cd_off:cd_off + 4] != CD_MAGIC or cd_off + cd_size != eocd:
        die(path, "malformed central directory")
    entries = []
    pos = cd_off
    for _ in range(count):
        if blob[pos:pos + 4] != CD_MAGIC:
            die(path, "central directory walk out of sync")
        fields = struct.unpack_from(CD_FIELDS, blob, pos + 4)
        name = bytes(blob[pos + 46:pos + 46 + fields[9]])
        entries.append((pos, fields, name))
        pos += 46 + fields[9] + fields[10] + fields[11]
    if pos != eocd:
        die(path, "central directory walk does not end at EOCD")
    comment = bytes(blob[eocd + 22:])
    return entries, comment, cd_off


def sanity(blob, path):
    entries, _, _ = walk_central(bytes(blob), path)
    for _, fields, name in entries:
        if blob[fields[15]:fields[15] + 4] != LOCAL_MAGIC:
            die(path, f"rebuilt archive: lhref invalid for {name!r}")
    return len(entries)


def main():
    path = sys.argv[1]
    with open(path, "rb") as fh:
        data = bytearray(fh.read())

    entries, comment, cd_off = walk_central(data, path)
    patched = 0
    dropped = 0
    for pos, fields, name in entries:
        c_start = pos + 46 + fields[9]
        c_extra = bytearray(data[c_start:c_start + fields[10]])
        patched += patch_ut(c_extra, path)
        data[c_start:c_start + fields[10]] = c_extra

        lhref = fields[15]
        if data[lhref:lhref + 4] != LOCAL_MAGIC:
            die(path, f"lhref {lhref} is not a local file header")
        lfields = struct.unpack_from(LOCAL_FIELDS, data, lhref + 4)
        l_start = lhref + 30 + lfields[8]
        l_extra = bytearray(data[l_start:l_start + lfields[9]])
        patched += patch_ut(l_extra, path)
        data[l_start:l_start + lfields[9]] = l_extra

        body = data[l_start + lfields[9]:l_start + lfields[9] + fields[7]]
        if fields[3] == 0:
            raw = body
        elif fields[3] == 8:
            decompressor = zlib.decompressobj(-15)  # raw deflate
            raw = decompressor.decompress(body)
            if decompressor.unused_data:
                die(path, f"trailing bytes after deflate stream for {name!r}")
            raw += decompressor.flush()
        else:
            die(path, f"unsupported compression method {fields[3]} for {name!r}")
        if len(raw) != fields[8]:
            die(path, f"uncompressed size mismatch for {name!r}")
        if zlib.crc32(raw) != fields[6]:
            die(path, f"CRC-32 mismatch for {name!r}")

        if b"__MACOSX/" in name:
            die(path, f"unexpected __MACOSX entry {name!r}")
        if name.split(b"/")[-1].startswith(b"._"):
            dropped += 1

    # Rebuild the archive from the kept entries. Each entry's raw region is
    # bounded by the *next entry in the full list* (kept or dropped), so a
    # run of trailing sidecars is not folded into the last kept entry and no
    # orphan bytes survive into the output.
    out = bytearray()
    cd_out = bytearray()
    total = len(entries)
    kept = 0
    for i, (pos, fields, name) in enumerate(entries):
        if name.split(b"/")[-1].startswith(b"._"):
            continue
        start = fields[15]
        end = entries[i + 1][1][15] if i + 1 < total else cd_off
        if end <= start:
            die(path, f"invalid entry range for {name!r}")
        new_off = len(out)
        out += data[start:end]
        record = bytearray(
            data[pos:pos + 46 + fields[9] + fields[10] + fields[11]])
        struct.pack_into("<I", record, 42, new_off)
        cd_out += record
        kept += 1

    out += cd_out
    cd_offset = len(out) - len(cd_out)
    # EOCD: signature, this-disk, cd-disk, entries-on-disk, total-entries,
    # cd-size, cd-offset, comment-length, then the comment bytes.
    out += EOCD_MAGIC
    out += struct.pack("<HHHHIIH", 0, 0, kept, kept,
                       len(cd_out), cd_offset, len(comment))
    out += comment

    sanity(out, path)
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(out)
    os.replace(tmp, path)
    print(f"{os.path.basename(path)}: {len(entries)} entries, "
          f"{dropped} AppleDouble sidecars removed, "
          f"{patched} 0x5855 words normalized")


if __name__ == "__main__":
    main()
