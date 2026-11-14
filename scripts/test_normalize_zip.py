"""Tests for scripts/normalize_zip.py.

The normalizer rewrites the 0x5855 (Info-ZIP "UX") extra subfields of a ditto-produced
zip so the release archive does not depend on filesystem or machine state:
the atime word is aligned with the pinned mtime word, and the local-header
uid/gid word is zeroed. `ditto` only exists on macOS, so the fixtures are
synthetic zips built from raw records that mirror ditto's layout (12-byte
local UX, 8-byte central UX, AppleDouble sidecar); the package script's
in-run double-ditto self-test then covers the real machine on a macOS
runner.

Run with: python3 -m unittest discover -s scripts -p 'test_*.py'
"""
import datetime
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)
import normalize_zip  # noqa: E402

NORMALIZER = os.path.join(SCRIPTS_DIR, "normalize_zip.py")

# The pinned mtime the release packaging stamps (2026-01-01 00:00:00 UTC),
# and the machine-state inputs the normalizer must remove from the archive.
MTIME = 1767225600
ATIME = MTIME + 3600  # APFS advances atimes while ditto reads the tree
STAGING_UID = 501
STAGING_GID = 20

LOCAL_MAGIC = normalize_zip.LOCAL_MAGIC
CD_MAGIC = normalize_zip.CD_MAGIC
EOCD_MAGIC = normalize_zip.EOCD_MAGIC

# A subfield ditto does not write, which the normalizer must reject even
# though it carries no machine state: 0x6375, Info-ZIP Unicode Comment
# (version, CRC-32 of the header comment, UTF-8 comment).
COMMENT_EXTRA_PAYLOAD = b"\x01" + struct.pack("<I", zlib.crc32(b"")) + b"ok"
COMMENT_EXTRA = struct.pack(
    "<HH", 0x6375, len(COMMENT_EXTRA_PAYLOAD)) + COMMENT_EXTRA_PAYLOAD
# An xattr-bearing subfield the normalizer must reject (machine state).
XATTR_EXTRA = struct.pack("<HH", 0x5835, 3) + b"\x00" + b"p\x00"
# 0x5455 "UT" extended timestamp (flags, mtime, atime), which would carry
# the drifting atime.
UT_EXTRA = struct.pack("<HHBII", 0x5455, 9, 3, MTIME, ATIME)
# The other Unix ownership subfields, which carry the staging uid/gid and
# must be rejected: 0x000d PKWARE Unix (atime mtime, 16-bit uid gid),
# 0x756e ASi Unix (CRC-32, mode, sizdev, 16-bit uid gid), 0x7855 "Ux"
# (local: uid gid as 16-bit words) and 0x7875 "ux" (version, uid size,
# uid, gid size, gid).
PKWARE_UNIX_EXTRA = struct.pack("<HHIIHH", 0x000D, 12, ATIME, MTIME,
                                STAGING_UID, STAGING_GID)
ASI_UNIX_EXTRA = struct.pack("<HHIHIHH", 0x756E, 14, 0, 0o100644, 0,
                             STAGING_UID, STAGING_GID)
UX_NEW_EXTRA = struct.pack("<HHHH", 0x7855, 4, STAGING_UID, STAGING_GID)
UX3_EXTRA = struct.pack("<HHBBIBI", 0x7875, 11, 1, 4, STAGING_UID,
                        4, STAGING_GID)
COMMENT = b"determinism-fixture"

README = b"AppAuth-Rust packaging fixture\n"
SIDECAR = b"\x00\x05\x16\x07" + b"apple-double"


def _dos(ts):
    """The DOS time/date fields for a Unix timestamp, derived the way
    `ditto` derives them from the stamped mtime."""
    dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    time = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    return time, date


def _ux(words):
    """A 0x5855 subfield built from 32-bit words (8 or 12 bytes)."""
    return struct.pack("<HH", 0x5855, 4 * len(words)) + b"".join(
        struct.pack("<I", word) for word in words)


def _local(name, data, extra):
    crc = zlib.crc32(data)
    time, date = _dos(MTIME)
    header = LOCAL_MAGIC + struct.pack(
        "<5H3I2H", 20, 0, 0, time, date, crc, len(data), len(data),
        len(name), len(extra))
    return header + name + extra + data


def _central(name, data, extra, local_off):
    crc = zlib.crc32(data)
    time, date = _dos(MTIME)
    header = CD_MAGIC + struct.pack(
        "<6H3I5H2I", 20, 20, 0, 0, time, date, crc, len(data), len(data),
        len(name), len(extra), 0, 0, 0, 0, local_off)
    return header + name + extra


def _build(entries, comment):
    """Build a zip from (name, data, local_extra, central_extra) entries.

    Local records are written in order, then the central directory, then
    the EOCD, with every offset consistent the way a real zip is.
    """
    local_blob = b""
    local_offsets = []
    for name, data, local_extra, _central_extra in entries:
        local_offsets.append(len(local_blob))
        local_blob += _local(name, data, local_extra)
    cd_off = len(local_blob)
    records = [
        _central(name, data, central_extra, local_off)
        for (name, data, _local_extra, central_extra), local_off
        in zip(entries, local_offsets)
    ]
    eocd = EOCD_MAGIC + struct.pack(
        "<HHHHIIH", 0, 0, len(entries), len(entries), sum(
            len(record) for record in records), cd_off, len(comment)) + comment
    return local_blob + b"".join(records) + eocd


def _subfields(extra):
    """Return the (tag, payload) pairs of every extra subfield, rejecting a
    malformed extra field the way the normalizer does."""
    return [(tag, bytes(extra[i + 4:i + 4 + slen]))
            for i, tag, slen in normalize_zip.subfields(extra, "archive.zip")]


def _ux_words(extra):
    """Return the word tuples of every 0x5855 subfield in extra."""
    words = []
    for tag, payload in _subfields(extra):
        if tag == 0x5855:
            words.append(struct.unpack("<" + "I" * (len(payload) // 4),
                                       payload))
    return words


def _archive_entries(blob):
    """Return [(name, local_extra, central_extra)] in archive order."""
    entries = []
    walked, _, _ = normalize_zip.walk_central(blob, "archive.zip")
    for pos, fields, name in walked:
        c_start = pos + 46 + fields[9]
        lfields = struct.unpack_from(normalize_zip.LOCAL_FIELDS,
                                     blob, fields[15] + 4)
        l_start = fields[15] + 30 + lfields[8]
        entries.append((name, blob[l_start:l_start + lfields[9]],
                        blob[c_start:c_start + fields[10]]))
    return entries


def _drifted_ux_local():
    return _ux([ATIME, MTIME, (STAGING_GID << 16) | STAGING_UID])


def _drifted_ux_central():
    return _ux([ATIME, MTIME])


INPUT_ENTRIES = [
    (b"pkg/", b"", _drifted_ux_local(), _drifted_ux_central()),
    (b"pkg/readme.txt", README, _drifted_ux_local(), _drifted_ux_central()),
    (b"pkg/._readme.txt", SIDECAR, _drifted_ux_local(),
     _drifted_ux_central()),
]

# What the normalizer must produce: the sidecar dropped, every atime word
# aligned with the mtime word, every local uid/gid word zeroed, the
# archive comment untouched.
EXPECTED_ENTRIES = [
    (b"pkg/", b"", _ux([MTIME, MTIME, 0]), _ux([MTIME, MTIME])),
    (b"pkg/readme.txt", README,
     _ux([MTIME, MTIME, 0]), _ux([MTIME, MTIME])),
]


class NormalizeZipTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="normalize-zip-test-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.path = os.path.join(self.tmpdir, "archive.zip")
        with open(self.path, "wb") as handle:
            handle.write(_build(INPUT_ENTRIES, COMMENT))
        self.expected = _build(EXPECTED_ENTRIES, COMMENT)

    def _run(self):
        return subprocess.run(
            [sys.executable, NORMALIZER, self.path],
            capture_output=True, text=True)

    def _read(self):
        with open(self.path, "rb") as handle:
            return handle.read()

    def test_normalized_bytes(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self._read(), self.expected)

    def test_uid_gid_zeroed_and_atime_aligned(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        entries = _archive_entries(self._read())
        self.assertEqual([name for name, _, _ in entries],
                         [b"pkg/", b"pkg/readme.txt"])
        for _name, local_extra, central_extra in entries:
            local_words = _ux_words(local_extra)
            central_words = _ux_words(central_extra)
            self.assertEqual(len(local_words), 1)
            self.assertEqual(len(central_words), 1)
            self.assertEqual(local_words[0][:2], (MTIME, MTIME))
            self.assertEqual(central_words[0], (MTIME, MTIME))
            uid, gid = struct.unpack("<HH", struct.pack("<I",
                                                        local_words[0][2]))
            self.assertEqual((uid, gid), (0, 0))

    def test_summary_line(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            "archive.zip: 3 entries, 1 AppleDouble sidecars removed, "
            "6 0x5855 words normalized",
            proc.stdout)

    def test_normalized_output_is_idempotent(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        first = self._read()
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self._read(), first)

    def _assert_refused(self, local_extra, central_extra, message):
        with open(self.path, "wb") as handle:
            handle.write(_build(
                [(b"pkg/f.txt", b"x", local_extra, central_extra)], COMMENT))
        before = self._read()
        proc = self._run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(message, proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertEqual(self._read(), before)

    def test_unexpected_ux_shape_is_refused(self):
        self._assert_refused(_ux([ATIME, MTIME, 1, 2]), _drifted_ux_central(),
                             "unexpected 0x5855 subfield shape len=16")

    def test_local_shape_in_central_directory_is_refused(self):
        self._assert_refused(_drifted_ux_local(), _drifted_ux_local(),
                             "unexpected 0x5855 subfield shape len=12")

    def test_central_shape_in_local_header_is_refused(self):
        self._assert_refused(_drifted_ux_central(), _drifted_ux_central(),
                             "unexpected 0x5855 subfield shape len=8")

    def test_xattr_subfield_is_refused(self):
        self._assert_refused(_drifted_ux_local() + XATTR_EXTRA,
                             _drifted_ux_central(),
                             "unexpected 0x5835 (XAttr) subfield len=3")

    def test_xattr_subfield_in_central_directory_is_refused(self):
        self._assert_refused(_drifted_ux_local(),
                             _drifted_ux_central() + XATTR_EXTRA,
                             "unexpected 0x5835 (XAttr) subfield len=3")

    def test_extended_timestamp_subfield_is_refused(self):
        self._assert_refused(_drifted_ux_local() + UT_EXTRA,
                             _drifted_ux_central(),
                             "unexpected 0x5455 (extended timestamp) "
                             "subfield len=9")

    def test_unknown_subfield_is_refused(self):
        self._assert_refused(_drifted_ux_local(),
                             _drifted_ux_central() + COMMENT_EXTRA,
                             "unexpected 0x6375 (not written by ditto) "
                             "subfield len=7")

    def test_pkware_unix_subfield_is_refused(self):
        self._assert_refused(_drifted_ux_local() + PKWARE_UNIX_EXTRA,
                             _drifted_ux_central(),
                             "unexpected 0x000d (PKWARE Unix) subfield")

    def test_asi_unix_subfield_is_refused(self):
        self._assert_refused(_drifted_ux_local() + ASI_UNIX_EXTRA,
                             _drifted_ux_central(),
                             "unexpected 0x756e (ASi Unix) subfield")

    def test_unix_ux_subfield_is_refused(self):
        self._assert_refused(_drifted_ux_local() + UX_NEW_EXTRA,
                             _drifted_ux_central(),
                             "unexpected 0x7855 (Info-ZIP Unix Ux) subfield")

    def test_unix3_ux_subfield_is_refused(self):
        self._assert_refused(_drifted_ux_local() + UX3_EXTRA,
                             _drifted_ux_central(),
                             "unexpected 0x7875 (Info-ZIP Unix ux) subfield")

    def test_sidecar_extra_is_not_checked(self):
        with open(self.path, "wb") as handle:
            handle.write(_build(
                [(b"pkg/f.txt", b"x", _drifted_ux_local(),
                  _drifted_ux_central()),
                 (b"pkg/._f.txt", SIDECAR, _drifted_ux_local() + XATTR_EXTRA,
                  _drifted_ux_local())],
                COMMENT))
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            [name for name, _, _ in _archive_entries(self._read())],
            [b"pkg/f.txt"])

    def test_truncated_subfield_is_refused(self):
        self._assert_refused(_drifted_ux_local()[:-6], _drifted_ux_central(),
                             "extra subfield 0x5855 len=12 overruns")

    def test_trailing_extra_bytes_are_refused(self):
        self._assert_refused(_drifted_ux_local() + b"\x00\x00",
                             _drifted_ux_central(),
                             "2 trailing bytes in extra field")


class SanityTestCase(unittest.TestCase):
    def test_accepts_normalized_archive(self):
        blob = _build(EXPECTED_ENTRIES, COMMENT)
        self.assertEqual(normalize_zip.sanity(blob, "archive.zip"), 2)

    def test_rejects_unnormalized_extra(self):
        blob = _build(INPUT_ENTRIES, COMMENT)
        with self.assertRaises(SystemExit) as raised:
            normalize_zip.sanity(blob, "archive.zip")
        self.assertIn("rebuilt archive: extra field not normalized",
                      str(raised.exception))


class WalkCentralTestCase(unittest.TestCase):
    def test_returns_cd_offset(self):
        blob = _build(INPUT_ENTRIES, COMMENT)
        entries, comment, cd_off = normalize_zip.walk_central(
            blob, "fixture")
        self.assertEqual(len(entries), 3)
        self.assertEqual(comment, COMMENT)
        self.assertEqual(cd_off, blob.index(CD_MAGIC))


if __name__ == "__main__":
    unittest.main()
