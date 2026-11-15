#!/usr/bin/env python3
"""Normalize a ditto-produced zip for deterministic packaging.

Usage: normalize_zip.py <archive.zip>

Applied in-place to the release archive after `ditto -c -k --keepParent`:

1. Normalize every 0x5855 (Info-ZIP "UX", original Unix) extra subfield
   in both the local file headers and the central directory. The central
   shape is 8 bytes (atime mtime); the local shape is 12 bytes (atime
   mtime uid gid).
   APFS can advance atimes while ditto reads the tree (cache- and
   size-dependent), and ditto records the atime here; setting the atime
   word to the mtime word renders the archive independent of atime drift.
   The mtime word is trusted because `touch -t` pins mtime and reading
   never moves it. The local 12-byte shape is rewritten to the 8-byte
   shape (the documented minimal UX): the uid/gid word is removed, so
   the archive records no owner at all -- a zeroed word would record
   root:root, and the staging user is a machine-state input whose values
   must not reach the published archive either. 0x5855 is the only
   subfield ditto writes, and every other subfield is rejected rather
   than parsed: an owner (0x7855, 0x7875, 0x000d, 0x756e), extended
   attributes (0x5835) or a timestamp (0x5455) cannot reach the archive
   through one either.

2. Remove AppleDouble `._*` sidecar entries. The com.apple.provenance xattr
   cannot be removed, so ditto emits a constant sidecar for every entry; the
   v0.5.0 archive layout excludes them. Because the UX rewrite and the
   removal change record sizes, the local file records and the central
   directory are rebuilt from their verified parts with updated lengths
   and offsets.

The zip signature constants are built with bytes((...)) rather than backslash
escapes so the source is immune to backslash-doubling in text round-trips.

Safety: entries are located via the central directory (exact record stride)
and the per-entry local header offset; the raw byte stream is never scanned
for PK signatures (deflate payloads could contain false-positive signatures
and would corrupt content if the walk desynchronized). Every entry's data
region is size- and CRC-32-verified (decompressing for deflate entries) and
must not overrun the next entry, unsupported methods, malformed extra
fields, 0x5855 subfields whose size is not accepted at their location (8
bytes central; 8 or 12 bytes local), and any other subfield are rejected,
and the rebuilt archive is re-parsed, with every extra field required to
be already normalized, before being written.
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

# Names for the rejection message. Every subfield other than 0x5855 is
# rejected; these are the ones that carry machine state (extended
# attributes, an owner, or a drifting timestamp).
TAG_NAMES = {
    0x000D: "PKWARE Unix",
    0x5455: "extended timestamp",
    0x5835: "XAttr",
    0x756E: "ASi Unix",
    0x7855: "Info-ZIP Unix Ux",
    0x7875: "Info-ZIP Unix ux",
}


def die(path, message):
    raise SystemExit(f"{os.path.basename(path)}: {message}")


def is_sidecar(name):
    """True for an AppleDouble `._*` entry, which the rebuild drops."""
    return name.split(b"/")[-1].startswith(b"._")


def subfields(extra, path):
    """Yield (offset, tag, slen) for each extra subfield, in order.

    A subfield that overruns the extra field, and trailing bytes too short
    to be a subfield header, are rejected.
    """
    i = 0
    while i + 4 <= len(extra):
        tag, slen = struct.unpack_from("<HH", extra, i)
        if i + 4 + slen > len(extra):
            die(path, f"extra subfield 0x{tag:04x} len={slen} overruns "
                      f"the extra field")
        yield i, tag, slen
        i += 4 + slen
    if i != len(extra):
        die(path, f"{len(extra) - i} trailing bytes in extra field")


def patch_ux(extra, local, path):
    """Normalize every 0x5855 subfield, returning (new_extra, rewritten).

    The normalized shape is 8 bytes, atime mtime, in both locations: the
    atime word is set to the mtime word. In a local header (local true) the
    input may also be the 12-byte shape, atime mtime uid gid; the uid/gid
    word is dropped, so the archive records no owner at all -- a zeroed word
    would record root:root, and the staging user is a machine-state input
    whose values must not reach the published archive either. In the central
    directory (local false) only the 8-byte shape is accepted. A subfield of
    any other size, a subfield that overruns the extra field, trailing
    bytes, and any other subfield are not shapes this tool can interpret and
    are rejected. `rewritten` counts the words not already in their
    normalized form: the atime word when it differed from the mtime word,
    plus the uid/gid word when the 12-byte shape was dropped.
    """
    new_extra = bytearray()
    rewritten = 0
    for i, tag, slen in subfields(extra, path):
        if tag != 0x5855:
            die(path, f"unexpected 0x{tag:04x} "
                      f"({TAG_NAMES.get(tag, 'not written by ditto')}) "
                      f"subfield len={slen}")
        payload = extra[i + 4:i + 4 + slen]
        atime = struct.unpack_from("<I", payload, 0)[0]
        mtime = struct.unpack_from("<I", payload, 4)[0]
        if local and slen == 12:
            if atime != mtime:
                rewritten += 1
            rewritten += 1  # the uid/gid word is dropped
        elif slen == 8:
            if atime != mtime:
                rewritten += 1
        else:
            die(path, f"unexpected 0x5855 subfield shape len={slen}")
        new_extra += struct.pack("<HH", 0x5855, 8)
        new_extra += struct.pack("<II", mtime, mtime)
    return bytes(new_extra), rewritten


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
    for pos, fields, name in entries:
        lhref = fields[15]
        if blob[lhref:lhref + 4] != LOCAL_MAGIC:
            die(path, f"rebuilt archive: lhref invalid for {name!r}")
        lfields = struct.unpack_from(LOCAL_FIELDS, blob, lhref + 4)
        c_start = pos + 46 + fields[9]
        l_start = lhref + 30 + lfields[8]
        for extra, local in (
                (blob[c_start:c_start + fields[10]], False),
                (blob[l_start:l_start + lfields[9]], True)):
            try:
                _new_extra, rewritten = patch_ux(bytearray(extra), local, path)
            except SystemExit as exc:
                reason = str(exc).split(": ", 1)[1]
                die(path, f"rebuilt archive: {reason} for {name!r}")
            if rewritten:
                die(path, f"rebuilt archive: extra field not normalized "
                          f"for {name!r}")
    return len(entries)


def main():
    path = sys.argv[1]
    with open(path, "rb") as fh:
        data = bytearray(fh.read())

    entries, comment, cd_off = walk_central(data, path)
    # Sidecars are dropped by the rebuild, so their extra fields are
    # neither normalized nor checked: nothing in them reaches the output.
    drop = [is_sidecar(name) for _, _, name in entries]
    # The local UX rewrite changes the record size, so the rewritten local
    # extras are kept here and re-emitted by the rebuild.
    new_local_extras = [None] * len(entries)
    patched = 0
    for i, ((pos, fields, name), sidecar) in enumerate(zip(entries, drop)):
        lhref = fields[15]
        if data[lhref:lhref + 4] != LOCAL_MAGIC:
            die(path, f"lhref {lhref} is not a local file header")
        lfields = struct.unpack_from(LOCAL_FIELDS, data, lhref + 4)
        l_start = lhref + 30 + lfields[8]
        if not sidecar:
            c_start = pos + 46 + fields[9]
            c_extra, c_words = patch_ux(
                bytearray(data[c_start:c_start + fields[10]]), False, path)
            data[c_start:c_start + fields[10]] = c_extra
            patched += c_words

            l_extra, l_words = patch_ux(
                bytearray(data[l_start:l_start + lfields[9]]), True, path)
            new_local_extras[i] = l_extra
            patched += l_words

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

    # Rebuild the archive from the kept entries. Each local record is
    # re-emitted from its verified parts -- the header (with the updated
    # extra length), the name, the rewritten extra, and the payload (the
    # compressed data and, where the local header's bit 3 is set, the data
    # descriptor that follows it) -- rather than copied as a raw region,
    # because the UX rewrite changes the record size. The payload runs to the
    # next entry's local header, so no run of dropped sidecars is folded into
    # a kept entry and no orphan bytes survive into the output.
    out = bytearray()
    cd_out = bytearray()
    total = len(entries)
    kept = 0
    for i, (pos, fields, name) in enumerate(entries):
        if drop[i]:
            continue
        lhref = fields[15]
        next_lhref = entries[i + 1][1][15] if i + 1 < total else cd_off
        if next_lhref <= lhref:
            die(path, f"invalid entry range for {name!r}")
        lfields = struct.unpack_from(LOCAL_FIELDS, data, lhref + 4)
        nlen = lfields[8]
        elen = lfields[9]
        l_start = lhref + 30 + nlen
        if l_start + elen + fields[7] > next_lhref:
            die(path, f"local record for {name!r} overruns the next entry")
        # The payload is the data plus, when bit 3 is set, the 16-byte data
        # descriptor that follows it; together they run to the next record.
        expected = fields[7] + (16 if (lfields[1] >> 3) & 1 else 0)
        if next_lhref - (l_start + elen) != expected:
            die(path, f"local record payload for {name!r} is "
                      f"{next_lhref - l_start - elen} bytes, expected {expected}")
        header = bytearray(data[lhref:lhref + 30])
        struct.pack_into("<H", header, 28, len(new_local_extras[i]))
        new_off = len(out)
        out += (header + data[lhref + 30:l_start] + new_local_extras[i]
                + data[l_start + elen:next_lhref])
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
          f"{sum(drop)} AppleDouble sidecars removed, "
          f"{patched} 0x5855 words normalized")


if __name__ == "__main__":
    main()
