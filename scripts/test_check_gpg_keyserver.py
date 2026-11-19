"""Tests for scripts/check-gpg-keyserver.sh.

The check derives the fingerprint of every primary key in GPG_PRIVATE_KEY
and requires each to resolve at the key server's by-fingerprint endpoint,
verifying that the returned key block actually carries the key asked for
(Issue #152; the key server was the point of failure for v0.6.0, #131).
The key server is a local mock; the key material is:

  * the version 4 Ed25519 key from RFC 9580 appendix A.1, both as a public
    key and as a secret key packet (the secret packet embeds the public
    part, section 5.5.3, and must yield the same RFC-fixed fingerprint
    C959BDBAFA32A2F89A153B678CFDE12197965A9A whether or not it is
    passphrase-protected);
  * a pgpy-generated version 4 RSA secret key (unprotected) and its public
    twin: a real armor shape with a CRC24 footer and a 2-octet packet
    length, cross-validated against the library's own fingerprint;
  * the RSA primary + subkey key that keys.openpgp.org serves for the
    t-saito@project-flora.net uid, as a real armor shape with Comment
    headers and a CRC24 footer (only the public part; the subkey exercises
    the "subkeys are not checked directly" path);
  * the version 6 certificate from RFC 9580 appendix A.3 (no CRC footer,
    76-character lines), which the check must reject with a
    manual-verification notice because it supports v4 keys only.
"""
import base64
import http.server
import os
import shutil
import subprocess
import tempfile
import threading
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "check-gpg-keyserver.sh")

# RFC 9580 appendix A.1: a version 4 Ed25519 key. The fingerprint is fixed
# by the RFC text, so any parser regression changes it.
RFC_ED25519_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku
Q+47JAY=
-----END PGP PUBLIC KEY BLOCK-----
"""
RFC_ED25519_FPR = "C959BDBAFA32A2F89A153B678CFDE12197965A9A"

# A version 4 RSA primary key with a subkey, as keys.openpgp.org serves it
# (public part; Comment headers and the RFC 9580 6.1 CRC24 footer included).
RSA_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: FD27 0193 59F4 7316 C1A9  ECF1 3675 5799 29C4 4B54
Comment: SAITO Tomomi <t-saito@project-flora.net>

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
R8nEa2vSH44LRS6BlNyyEg==
=ZQe9
-----END PGP PUBLIC KEY BLOCK-----
"""
RSA_FPR = "FD27019359F47316C1A9ECF13675579929C44B54"

# RFC 9580 appendix A.3: a version 6 certificate. The check supports v4
# keys only and must fail it with a manual-verification notice.
RFC_V6_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----
"""
RFC_V6_FPR = "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"


# The same RFC 9580 appendix A.1 key as a version 4 *secret* key packet
# (type 5): the RFC-fixed public part, followed by the secret key fields of
# section 5.5.3. The fingerprint of a secret key packet is that of its
# embedded public part, so it must be the RFC-fixed C959... either way.
#
#   public part (section 5.5.2.2, 51 octets):
#     04 53f35f0b 16 [09 2b06010401da470f0101] [0107 40 32-octet q]
#     (EdDSA: 1-octet curve OID length + OID, then the point MPI)
A1_PUBLIC_PART = bytes.fromhex(
    "0453f35f0b16092b06010401da470f0101"
    "07403f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406")
# RFC A.1: "The secret key used for this example is: D: 1a8b1ff0..."
A1_SECRET_D = bytes.fromhex(
    "1a8b1ff05ded48e18bf50166c664ab023ea70003d78d9e41f5758a91d850f8d2")


def _a1_secret_packet(tail):
    body = A1_PUBLIC_PART + tail
    return b"\xc5" + bytes([len(body)]) + body  # new format, tag 5, 1-octet length


def _a1_tail_unprotected():
    # S2K usage 0: [secret MPI][2-octet checksum of the secret material].
    # D starts with 0x1a, so its minimal bit count is 253.
    mpi = b"\x00\xfd" + A1_SECRET_D
    return b"\x00" + mpi + bytes((sum(mpi) % 65536).to_bytes(2, "big"))


def _a1_tail_protected():
    # S2K usage 255 (MalleableCFB): [cipher AES-256][S2K type 3
    # iterated+salted][8-octet salt][count code][16-octet IV][CFB data]
    return b"\xff\x09\x03" + bytes(range(8)) + b"\x0e" + \
        bytes(range(16, 32)) + bytes((i * 37 + 11) % 256 for i in range(64))


def _a1_tail_corrupted():
    # A bit flipped in the secret material leaves the checksum stale.
    d = bytearray(A1_SECRET_D)
    d[5] ^= 1
    mpi = b"\x00\xfd" + bytes(d)
    good = b"\x00\xfd" + A1_SECRET_D
    return b"\x00" + mpi + bytes((sum(good) % 65536).to_bytes(2, "big"))


def _secret_armor(packet):
    b64 = base64.b64encode(packet).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN PGP SECRET KEY BLOCK-----\n\n%s\n"
            "-----END PGP SECRET KEY BLOCK-----\n" % "\n".join(lines))


A1_SECRET_KEY = _secret_armor(_a1_secret_packet(_a1_tail_unprotected()))
A1_SECRET_KEY_PROTECTED = _secret_armor(_a1_secret_packet(_a1_tail_protected()))
A1_SECRET_KEY_CORRUPTED = _secret_armor(_a1_secret_packet(_a1_tail_corrupted()))
# The public part recast as a secret *subkey* packet (tag 7): its fingerprint
# is noted but never checked, and a key server lookup by the primary
# fingerprint returns it.
A1_SECRET_SUBKEY = _secret_armor(
    b"\xc7" + bytes([len(A1_PUBLIC_PART) + len(_a1_tail_unprotected())])
    + A1_PUBLIC_PART + _a1_tail_unprotected())

# A pgpy-generated version 4 RSA secret key (unprotected) and its public
# twin. The fingerprint AEBD... is pgpy's own for this key.
PGPY_RSA_FPR = "AEBD6A4F75879B7918B541DB2B43D0EE520CF7F5"
PGPY_RSA_PUBLIC_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xsBNBGr+k/IBCACyYF8Zu1d64vWaqKo/srYiuvGGnGHP/vVHKpxVf6/HrxQNhTi+
HhfYslVRg7Z9zAk3MkT8ym0iywF3AxeX9VxSgUpFkNEPh4kvan2JwNnOms20tQFh
qxUnE0lVso+lgCjk4KKMxJ8lY7bYolzO5iBB1WeYN9rbwlA+Mye0Y6CKqxth18oO
CCJ+5Lk8QrLSVyX6Kn0XLcOH5jjUQil6cxjrtZC4k3kKEP8VrPFA8TEk9cqsby/c
FmnybHLVkTMos6qqbzxDmXuHFji5yHTv3XykktQYBKux1WdhQ0x0qHhDSUEPtZhw
D6CtbuJhSl6Fz+VzyeExDp3ce1g9maLz1liLABEBAAE=
=xcov
-----END PGP PUBLIC KEY BLOCK-----
"""
PGPY_RSA_SECRET_KEY = """-----BEGIN PGP PRIVATE KEY BLOCK-----

xcLYBGr+k/IBCACyYF8Zu1d64vWaqKo/srYiuvGGnGHP/vVHKpxVf6/HrxQNhTi+
HhfYslVRg7Z9zAk3MkT8ym0iywF3AxeX9VxSgUpFkNEPh4kvan2JwNnOms20tQFh
qxUnE0lVso+lgCjk4KKMxJ8lY7bYolzO5iBB1WeYN9rbwlA+Mye0Y6CKqxth18oO
CCJ+5Lk8QrLSVyX6Kn0XLcOH5jjUQil6cxjrtZC4k3kKEP8VrPFA8TEk9cqsby/c
FmnybHLVkTMos6qqbzxDmXuHFji5yHTv3XykktQYBKux1WdhQ0x0qHhDSUEPtZhw
D6CtbuJhSl6Fz+VzyeExDp3ce1g9maLz1liLABEBAAEAB/oDLG/Et26RAyS3gbS1
uWpAJ+9QI8whtTmL8JgjdUgdV2IV837U8xgdhN67uooupsirMLvFe5yBd/cotOdg
jr77wM0fe7ocep7YNx7Qqpu1b0+lnWrO4ApaTZ+KZMjleug/WjfKJV1nfuSr6geY
rsN4KGHVdXjxW/2tfZ+BOByNGwKJUWvnRdY+YI1z9YVWQiXm6EhsIuqZQUXr+8Of
7OHFONnw31wWE7TBAYncuddsPNjYtpzHiOKSCLBhGy2s/1LeGt+3Jo1ld5BdxQXF
kQAyz8FEF2vUqSp+GyJxF1yO+Dm3/q/xOjnEptiMvHIdhxZGsqb6/Yrcf9uKnL9W
nTQRBAD5z9wWMWePIx7N94XNQjQAwqg6ZoxU9bUf22/mR6DwKZIaS3EIZ6E4lrzN
U7EguPWi2gSFa7kAWaEg3PrcNahFU7lYadVNwCqFqfHRBIonJNc2mubZrN488l04
abPwBUSD6kjSMVxsJ00IbUPLdZ+5iX/qhlF54IbFU7rPuxCCRQQAtsuD/zxo6kFA
d6u2514xKWBOJ1+Kb9nLZ7xLGm39QjQrjOGm1xIEAu+5gBTVxHBVGr7GjPyDl4Bd
5D0vaquwh7bukwyk4c6dIr3cAqMkZqpWKgl67apKV9I4EjyeGtTmSg0vUCTBeiZF
mC3E9d5OEu7qTwGRQybUgpA6nAjKhI8D/3bk7EURndoB54RHXN9N4jsbb9dC2vZE
ZeWuMx+S69PcNCSdzUKjk79N4uuyOKxeQRgc7gPcw3EqP7K2oOuyNZwBfQAkk/WZ
hQmueFJFvXzuRbQWkQ1k27NHsmQ7g0XUtAEd2nxPo6IlbjfzRx+0TjseEqOEAxZz
vXJ5AqcJtgd7Q8Q=
=qYDd
-----END PGP PRIVATE KEY BLOCK-----
"""


class FastHTTPServer(http.server.ThreadingHTTPServer):
    def server_bind(self):
        import socketserver

        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class KeyserverHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # self.server.routes maps path -> (status, body or None), or a
        # list of (status, body or None) replayed per request (the last
        # entry repeats) so retry behavior can be tested.
        entry = self.server.routes.get(self.path, (404, None))
        self.server.requests.append(self.path)
        if isinstance(entry, list):
            count = self.server.counts.get(self.path, 0)
            self.server.counts[self.path] = count + 1
            entry = entry[min(count, len(entry) - 1)]
        status, body = entry
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.end_headers()

    def log_message(self, format, *args):  # silence request logging
        pass


def route(fpr):
    return "/vks/v1/by-fingerprint/%s" % fpr


def block(armor):
    return (200, armor.encode())


class KeyserverCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = FastHTTPServer(("127.0.0.1", 0), KeyserverHandler)
        cls.server.routes = {}
        cls.server.requests = []
        cls.server.counts = {}
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def run_script(self, routes, key=RFC_ED25519_KEY, attempts="3", delay="0",
                   with_secret=True, summary=None):
        self.server.routes = routes
        self.server.requests.clear()
        self.server.counts.clear()
        env = dict(os.environ)
        env.update({
            "KEYSERVER_BASE_URL": self.base,
            "KEYSERVER_ATTEMPTS": attempts,
            "KEYSERVER_RETRY_DELAY": delay,
            "KEYSERVER_TIMEOUT": "5",
        })
        env.pop("GPG_PRIVATE_KEY", None)
        if with_secret:
            env["GPG_PRIVATE_KEY"] = key
        env.pop("GITHUB_STEP_SUMMARY", None)
        if summary is not None:
            env["GITHUB_STEP_SUMMARY"] = summary
        return subprocess.run(
            ["bash", SCRIPT], env=env,
            capture_output=True, text=True, timeout=60)

    def test_resolved(self):
        summary = os.path.join(tempfile.gettempdir(),
                               "step-summary-%d" % os.getpid())
        try:
            r = self.run_script({route(RFC_ED25519_FPR): block(RFC_ED25519_KEY)},
                                summary=summary)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("Checking %s" % RFC_ED25519_FPR, r.stdout)
            self.assertIn("Resolved %s" % RFC_ED25519_FPR, r.stdout)
            self.assertIn("Every signing key", r.stdout)
            self.assertEqual(self.server.requests, [route(RFC_ED25519_FPR)])
            with open(summary) as f:
                self.assertIn(RFC_ED25519_FPR, f.read())
        finally:
            if os.path.exists(summary):
                os.unlink(summary)

    def test_not_resolved(self):
        r = self.run_script({route(RFC_ED25519_FPR): (404, None)})
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("does not resolve", r.stderr)
        self.assertIn(RFC_ED25519_FPR, r.stderr)
        self.assertIn("keys.openpgp.org/upload", r.stderr)
        self.assertIn("Re-dispatch the release run", r.stderr)
        # The retry loop ran; the remediation names the key, so the
        # maintainer can act on it without reading the logs.
        self.assertEqual(len(self.server.requests), 3)
        self.assertEqual(self.server.requests[0], route(RFC_ED25519_FPR))

    def test_retry_then_resolves(self):
        # Propagation lag: 404 twice, then the pool catches up.
        routes = {route(RFC_ED25519_FPR):
                  [(404, None), (404, None), block(RFC_ED25519_KEY)]}
        r = self.run_script(routes)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertIn("Resolved %s" % RFC_ED25519_FPR, r.stdout)
        self.assertEqual(len(self.server.requests), 3)

    def test_resolves_but_wrong_key(self):
        # A 200 whose block does not carry the queried fingerprint is a
        # definitive failure (no retry): the key server answered, but not
        # with our key.
        r = self.run_script({route(RFC_ED25519_FPR): block(RSA_KEY)})
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("answered 200 but its key block is not %s" % RFC_ED25519_FPR,
                      r.stderr)
        self.assertEqual(self.server.requests, [route(RFC_ED25519_FPR)])

    def test_missing_secret(self):
        r = self.run_script({}, with_secret=False)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("GPG_PRIVATE_KEY is not set", r.stderr)
        self.assertEqual(self.server.requests, [])

    def test_multiple_keys_all_resolved(self):
        key = RFC_ED25519_KEY + "\n" + RSA_KEY
        routes = {
            route(RFC_ED25519_FPR): block(RFC_ED25519_KEY),
            route(RSA_FPR): block(RSA_KEY),
        }
        r = self.run_script(routes, key=key)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertIn("Resolved %s" % RFC_ED25519_FPR, r.stdout)
        self.assertIn("Resolved %s" % RSA_FPR, r.stdout)
        # The subkey is never queried: only the primaries are checked.
        self.assertEqual(sorted(self.server.requests),
                         sorted([route(RFC_ED25519_FPR), route(RSA_FPR)]))

    def test_multiple_keys_one_missing(self):
        key = RFC_ED25519_KEY + "\n" + RSA_KEY
        routes = {
            route(RFC_ED25519_FPR): block(RFC_ED25519_KEY),
            route(RSA_FPR): (404, None),
        }
        r = self.run_script(routes, key=key)
        self.assertEqual(r.returncode, 1, r.stdout)
        # The resolvable key passes; the missing one fails with its own
        # fingerprint in the remediation.
        self.assertIn("Resolved %s" % RFC_ED25519_FPR, r.stdout)
        self.assertIn("does not resolve", r.stderr)
        self.assertIn(RSA_FPR, r.stderr)
        self.assertNotIn(RFC_ED25519_FPR, r.stderr)

    def test_unsupported_key_version(self):
        # v6 fingerprints are SHA-256 based; this check supports v4 only and
        # must fail with a manual-verification notice rather than guess.
        r = self.run_script({route(RFC_V6_FPR): (404, None)}, key=RFC_V6_KEY)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("version 6", r.stderr)
        self.assertEqual(self.server.requests, [])

    def test_secret_key_unprotected(self):
        # The secret key packet (type 5) embeds the public part; the
        # fingerprint must be the RFC-fixed one of the public key.
        routes = {route(RFC_ED25519_FPR): block(RFC_ED25519_KEY)}
        r = self.run_script(routes, key=A1_SECRET_KEY)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertIn("Resolved %s" % RFC_ED25519_FPR, r.stdout)
        self.assertEqual(self.server.requests, [route(RFC_ED25519_FPR)])

    def test_secret_key_protected(self):
        # A passphrase-protected secret key (S2K usage 255) must yield the
        # same fingerprint: the public part is not encrypted.
        routes = {route(RFC_ED25519_FPR): block(RFC_ED25519_KEY)}
        r = self.run_script(routes, key=A1_SECRET_KEY_PROTECTED)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertIn("Resolved %s" % RFC_ED25519_FPR, r.stdout)
        self.assertEqual(self.server.requests, [route(RFC_ED25519_FPR)])

    def test_secret_key_rsa(self):
        # A real library-generated RSA secret key (2-octet packet length,
        # CRC24 footer, unprotected).
        routes = {route(PGPY_RSA_FPR): block(PGPY_RSA_PUBLIC_KEY)}
        r = self.run_script(routes, key=PGPY_RSA_SECRET_KEY)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertIn("Resolved %s" % PGPY_RSA_FPR, r.stdout)
        self.assertEqual(self.server.requests, [route(PGPY_RSA_FPR)])

    def test_secret_key_corrupted(self):
        # A flipped bit in the unprotected secret material fails its
        # checksum: the key must be reported malformed, not resolved with
        # a wrong fingerprint.
        routes = {route(RFC_ED25519_FPR): block(RFC_ED25519_KEY)}
        r = self.run_script(routes, key=A1_SECRET_KEY_CORRUPTED)
        self.assertEqual(r.returncode, 1, (r.stdout, r.stderr))
        self.assertIn("malformed", r.stderr)
        self.assertEqual(self.server.requests, [])

    def test_secret_key_and_secret_subkey(self):
        # A secret primary plus a secret subkey: the primary is checked,
        # the subkey is only noted.
        key = A1_SECRET_KEY + "\n" + A1_SECRET_SUBKEY
        routes = {route(RFC_ED25519_FPR): block(RFC_ED25519_KEY)}
        r = self.run_script(routes, key=key)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertIn("subkey %s is not checked directly" % RFC_ED25519_FPR,
                      r.stderr)
        self.assertEqual(self.server.requests, [route(RFC_ED25519_FPR)])

    @unittest.skipUnless(shutil.which("gpg"), "GnuPG is not installed")
    def test_gpg_generated_key(self):
        # Cross-validate the parser against a real GnuPG-generated key,
        # including its subkey layout (the GitHub runner ships GnuPG; a
        # machine without it skips this test).
        home = tempfile.mkdtemp()
        try:
            env = dict(os.environ, GNUPGHOME=home)
            gpg = lambda *args: subprocess.run(
                ["gpg", "--batch", "--no-protection", *args], env=env,
                capture_output=True, text=True, check=True, timeout=60)
            gpg("--quick-generate-key",
                "Keyserver Check Test <test@example.invalid>", "ed25519")
            listing = gpg("--with-colons", "--list-secret-keys").stdout
            fpr = [line.split(":", 10)[9] for line in listing.splitlines()
                   if line.startswith("fpr:")][0]
            armor = gpg("--armor", "--export-secret-keys", fpr).stdout
            public = gpg("--armor", "--export", fpr).stdout
            r = self.run_script({route(fpr): block(public)}, key=armor)
            self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
            self.assertIn("Resolved %s" % fpr, r.stdout)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    @unittest.skipUnless(shutil.which("gpg"), "GnuPG is not installed")
    def test_gpg_generated_key_protected(self):
        # The protected form (a passphrase-protected secret key, S2K usage
        # 254/255 with an IV and CFB-encrypted secret material) is what a
        # key exported from a real keyring looks like; it must yield the
        # same fingerprint as the public part.
        home = tempfile.mkdtemp()
        try:
            env = dict(os.environ, GNUPGHOME=home)
            gpg = lambda *args: subprocess.run(
                ["gpg", "--batch", "--pinentry-mode", "loopback",
                 "--passphrase", "test", *args], env=env,
                capture_output=True, text=True, check=True, timeout=60)
            gpg("--quick-generate-key",
                "Keyserver Check Test <test@example.invalid>", "ed25519")
            listing = gpg("--with-colons", "--list-secret-keys").stdout
            fpr = [line.split(":", 10)[9] for line in listing.splitlines()
                   if line.startswith("fpr:")][0]
            armor = gpg("--armor", "--export-secret-keys", fpr).stdout
            public = gpg("--armor", "--export", fpr).stdout
            r = self.run_script({route(fpr): block(public)}, key=armor)
            self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
            self.assertIn("Resolved %s" % fpr, r.stdout)
        finally:
            shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
