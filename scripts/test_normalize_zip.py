"""Tests for scripts/normalize_zip.py.

The normalizer rewrites the 0x5855 (UT) extra subfields of a ditto-produced
zip so the release archive does not depend on filesystem or machine state:
the atime word is aligned with the pinned mtime word, and the local-header
uid/gid word is zeroed. `ditto` only exists on macOS, so the fixtures are
synthetic zips built from raw records that mirror ditto's layout (12-byte
local UT, 8-byte central UT, AppleDouble sidecar); the package script's
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

LOCAL_MAGIC = b"PK" + bytes((3, 4))
CD_MAGIC = b"PK" + bytes((1, 2))
EOCD_MAGIC = b"PK" + bytes((5, 6))

# A non-UT subfield (0x6375, Unix3) that the normalizer must leave alone.
UNIX_EXTRA = struct.pack(
    "<HH", 0x6375, 8) + struct.pack(
    "<HHHH", STAGING_UID, STAGING_GID, 0, 0)
# An xattr-bearing subfield the normalizer must reject (machine state).
XATTR_EXTRA = struct.pack("<HH", 0x5835, 5) + b"\x00" + b"p\x00"
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


def _ut(words):
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
    """Return the (tag, payload) pairs of every extra subfield."""
    fields = []
    i = 0
    while i + 4 <= len(extra):
        tag, slen = struct.unpack_from("<HH", extra, i)
        fields.append((tag, bytes(extra[i + 4:i + 4 + slen])))
        i += 4 + slen
    return fields


def _ut_words(extra):
    """Return the word tuples of every 0x5855 subfield in extra."""
    words = []
    for tag, payload in _subfields(extra):
        if tag == 0x5855:
            words.append(struct.unpack("<" + "I" * (len(payload) // 4),
                                       payload))
    return words


def _archive_entries(blob):
    """Walk the central directory; return [(name, local_extra,
    central_extra)] in archive order."""
    eocd = blob.rfind(EOCD_MAGIC)
    assert eocd >= 0
    count = struct.unpack_from("<H", blob, eocd + 10)[0]
    entries = []
    pos = struct.unpack_from("<I", blob, eocd + 16)[0]
    for _ in range(count):
        fields = struct.unpack_from(normalize_zip.CD_FIELDS, blob, pos + 4)
        name = bytes(blob[pos + 46:pos + 46 + fields[9]])
        central_extra = blob[pos + 46 + fields[9]:
                             pos + 46 + fields[9] + fields[10]]
        lfields = struct.unpack_from(normalize_zip.LOCAL_FIELDS,
                                     blob, fields[15] + 4)
        local_extra = blob[fields[15] + 30 + lfields[8]:
                         fields[15] + 30 + lfields[8] + lfields[9]]
        entries.append((name, local_extra, central_extra))
        pos += 46 + fields[9] + fields[10] + fields[11]
    return entries


def _drifted_ut_local():
    return _ut([ATIME, MTIME, (STAGING_GID << 16) | STAGING_UID])


def _drifted_ut_central():
    return _ut([ATIME, MTIME])


INPUT_ENTRIES = [
    (b"pkg/", b"", _drifted_ut_local(), _drifted_ut_central()),
    (b"pkg/readme.txt", README,
     _drifted_ut_local() + UNIX_EXTRA, _drifted_ut_central() + UNIX_EXTRA),
    (b"pkg/._readme.txt", SIDECAR, _drifted_ut_local(),
     _drifted_ut_central()),
]

# What the normalizer must produce: the sidecar dropped, every atime word
# aligned with the mtime word, every local uid/gid word zeroed, the
# 0x6375 subfield and the comment untouched.
EXPECTED_ENTRIES = [
    (b"pkg/", b"", _ut([MTIME, MTIME, 0]), _ut([MTIME, MTIME])),
    (b"pkg/readme.txt", README,
     _ut([MTIME, MTIME, 0]) + UNIX_EXTRA, _ut([MTIME, MTIME]) + UNIX_EXTRA),
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
            ["python3", NORMALIZER, self.path],
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
            local_words = _ut_words(local_extra)
            central_words = _ut_words(central_extra)
            self.assertEqual(len(local_words), 1)
            self.assertEqual(len(central_words), 1)
            self.assertEqual(local_words[0][:2], (MTIME, MTIME))
            self.assertEqual(central_words[0], (MTIME, MTIME))
            uid, gid = struct.unpack("<HH", struct.pack("<I",
                                                        local_words[0][2]))
            self.assertEqual((uid, gid), (0, 0))

    def test_non_ut_subfield_untouched(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        entries = _archive_entries(self._read())
        for extra in (entries[1][1], entries[1][2]):
            self.assertIn((0x6375, UNIX_EXTRA[4:]), _subfields(extra))

    def test_summary_line(self):
        proc = self._run()
        self.assertIn(
            "archive.zip: 3 entries, 1 AppleDouble sidecars removed, "
            "9 0x5855 words normalized",
            proc.stdout)

    def test_normalized_output_is_idempotent(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        first = self._read()
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self._read(), first)

    def test_unexpected_ut_shape_is_refused(self):
        with open(self.path, "wb") as handle:
            handle.write(_build(
                [(b"pkg/f.txt", b"x", _ut([ATIME, MTIME, 1, 2]),
                  _drifted_ut_central())],
                COMMENT))
        before = self._read()
        proc = self._run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unexpected 0x5855 subfield shape len=16",
                      proc.stderr)
        self.assertEqual(self._read(), before)

    def test_xattr_subfield_is_refused(self):
        with open(self.path, "wb") as handle:
            handle.write(_build(
                [(b"pkg/f.txt", b"x",
                  _drifted_ut_local() + XATTR_EXTRA,
                  _drifted_ut_central())],
                COMMENT))
        before = self._read()
        proc = self._run()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unexpected 0x5835 (XAttr) subfield", proc.stderr)
        self.assertEqual(self._read(), before)


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
