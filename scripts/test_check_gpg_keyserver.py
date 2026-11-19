"""Tests for scripts/check-gpg-keyserver.sh.

The check derives the fingerprint of every primary key in GPG_PRIVATE_KEY
and requires each to resolve at the key server's by-fingerprint endpoint,
verifying that the returned key block actually carries the key asked for
(Issue #152; the key server was the point of failure for v0.6.0, #131).
The key server is a local mock; the key material is:

  * the version 4 Ed25519 key from RFC 9580 appendix A.1 (a public key;
    its fingerprint C959BDBAFA32A2F89A153B678CFDE12197965A9A is fixed by
    the RFC, so the parser is regression-tested against a known vector);
  * the RSA primary + subkey key that keys.openpgp.org serves for the
    t-saito@project-flora.net uid, as a real armor shape with Comment
    headers and a CRC24 footer (only the public part; the subkey exercises
    the "subkeys are not checked directly" path);
  * the version 6 certificate from RFC 9580 appendix A.3 (no CRC footer,
    76-character lines), which the check must reject with a
    manual-verification notice because it supports v4 keys only.
"""
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


if __name__ == "__main__":
    unittest.main()
