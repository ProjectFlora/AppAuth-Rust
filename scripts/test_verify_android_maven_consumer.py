"""Tests for scripts/verify-android-maven-consumer.sh.

The verify script's stage machine (Issue #137): an HTTP availability gate on
the canonical Maven Central POM and AAR URLs, a strict Gradle resolution
preflight (checkDebugAarMetadata), and the full consumer smoke. The tests
run the script in a sandbox that replaces the Gradle wrapper with a fake
recording its invocations, and point the availability gate at a local mock
of Maven Central, so no network, SDK or real Gradle is needed:

    test A  gate 404/404            -> fails after the budget, Gradle never runs
    test B  gate 200/200            -> preflight + smoke, success
    test C  gate 200/200, strict x  -> fails with the preflight diagnosis
    test D  gate 200/200, smoke x   -> fails with the full-check diagnosis
    test E  gate 200/404 (partial)  -> treated as not yet visible

Run with: python3 -m unittest discover -s scripts -p 'test_*.py'
"""
import http.server
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
VERIFY_SCRIPT = os.path.join(SCRIPTS_DIR, "verify-android-maven-consumer.sh")
CONSUMER_SCRIPT = os.path.join(SCRIPTS_DIR, "check-android-maven-consumer.sh")
VERSION = "1.2.3"
# The artifact URL paths exactly as the verify script constructs them.
POM_PATH = "/maven2/net/project-flora/appauth/appauth-rust-android/%s/appauth-rust-android-%s.pom" % (VERSION, VERSION)
AAR_PATH = "/maven2/net/project-flora/appauth/appauth-rust-android/%s/appauth-rust-android-%s.aar" % (VERSION, VERSION)

FAKE_GRADLEW = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FAKE_GRADLE_LOG:?FAKE_GRADLE_LOG unset}"
case "$*" in
    *checkDebugAarMetadata*) exit "${FAKE_STRICT_EXIT:-0}" ;;
    *connectedDebugAndroidTest*) exit "${FAKE_FULL_EXIT:-0}" ;;
    *) exit 0 ;;
esac
"""


class FastHTTPServer(http.server.HTTPServer):
    """Skip HTTPServer.server_bind's socket.getfqdn reverse lookup.

    The reverse DNS lookup can stall (observed: ~35s on first call in a
    sandboxed network) for no value in a test; the server only ever serves
    127.0.0.1.
    """

    def server_bind(self):
        import socketserver

        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class CentralHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.server.requests.append(self.path)
        status = self.server.routes.get(self.path, 404)
        self.send_response(status)
        self.end_headers()

    def log_message(self, format, *args):  # silence request logging
        pass


class VerifyScriptSandbox:
    """A repo tree with the real scripts and a fake Gradle wrapper."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="verify-maven-")
        os.makedirs(os.path.join(self.root, "scripts"))
        os.makedirs(os.path.join(self.root, "native", "android"))
        os.makedirs(os.path.join(self.root, "native", "consumer-smoke", "android"))
        for name in ("verify-android-maven-consumer.sh",
                     "check-android-maven-consumer.sh"):
            shutil.copy(os.path.join(SCRIPTS_DIR, name),
                        os.path.join(self.root, "scripts", name))
        gradlew = os.path.join(self.root, "native", "android", "gradlew")
        with open(gradlew, "w") as f:
            f.write(FAKE_GRADLEW)
        os.chmod(gradlew, os.stat(gradlew).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        self.log_path = os.path.join(self.root, "gradlew-invocations.log")

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run(self, strict_exit="0", full_exit="0", retries="2"):
        env = dict(os.environ)
        env.update({
            "MAVEN_CENTRAL_BASE_URL": "http://127.0.0.1:%d/maven2" % self.server_port,
            "VERIFY_MAX_RETRIES": retries,
            "VERIFY_RETRY_INTERVAL": "0",
            "FAKE_GRADLE_LOG": self.log_path,
            "FAKE_STRICT_EXIT": strict_exit,
            "FAKE_FULL_EXIT": full_exit,
        })
        for var in ("SKIP_PUBLICATION_CHECK",):
            env.pop(var, None)
        return subprocess.run(
            ["bash", os.path.join(self.root, "scripts",
                                  "verify-android-maven-consumer.sh"), VERSION],
            env=env, cwd=self.root, capture_output=True, text=True, timeout=120)

    def gradlew_calls(self):
        if not os.path.exists(self.log_path):
            return []
        with open(self.log_path) as f:
            return [line.rstrip("\n") for line in f if line.strip()]


class VerifyAndroidMavenConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = FastHTTPServer(("127.0.0.1", 0), CentralHandler)
        cls.server.routes = {}
        cls.server.requests = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def run_scenario(self, routes, strict_exit="0", full_exit="0", retries="2"):
        self.server.routes = routes
        self.server.requests.clear()
        sandbox = VerifyScriptSandbox()
        sandbox.server_port = self.port
        try:
            result = sandbox.run(strict_exit=strict_exit,
                                 full_exit=full_exit, retries=retries)
            # Capture the Gradle invocations before the sandbox tree (and its
            # log file) is removed.
            return result, sandbox.gradlew_calls()
        finally:
            sandbox.close()

    def test_gate_404_fails_without_running_gradle(self):
        r, calls = self.run_scenario({POM_PATH: 404, AAR_PATH: 404})
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("not yet visible on Maven Central", r.stderr)
        self.assertIn("failed after 2 attempts", r.stderr)
        self.assertIn("POM 404", r.stderr)
        self.assertEqual(calls, [])

    def test_gate_200_preflight_and_smoke_succeed(self):
        r, calls = self.run_scenario({POM_PATH: 200, AAR_PATH: 200})
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertIn("verification succeeded", r.stdout)
        self.assertTrue(any("checkDebugAarMetadata" in c for c in calls), calls)
        self.assertTrue(any("connectedDebugAndroidTest" in c for c in calls), calls)
        # The full check also passes --refresh-dependencies to the wrapper.
        self.assertTrue(all("--refresh-dependencies" in c for c in calls), calls)

    def test_strict_preflight_failure(self):
        r, calls = self.run_scenario({POM_PATH: 200, AAR_PATH: 200},
                                     strict_exit="1")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("Strict preflight failed", r.stderr)
        self.assertTrue(any("checkDebugAarMetadata" in c for c in calls), calls)
        self.assertFalse(any("connectedDebugAndroidTest" in c for c in calls), calls)

    def test_full_check_failure(self):
        r, calls = self.run_scenario({POM_PATH: 200, AAR_PATH: 200},
                                     full_exit="1")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("Full check failed", r.stderr)
        self.assertTrue(any("connectedDebugAndroidTest" in c for c in calls), calls)

    def test_gate_partial_404_is_not_visible(self):
        # The AAR is what the full check consumes; a 200 POM with a 404 AAR
        # must be treated as "not yet visible", not as a preflight attempt.
        r, calls = self.run_scenario({POM_PATH: 200, AAR_PATH: 404})
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("not yet visible on Maven Central", r.stderr)
        self.assertEqual(calls, [])

    def test_retry_budget_is_exhausted_not_waited(self):
        # With a zero interval the loop must still perform exactly MAX_RETRIES
        # gate attempts before failing (and not sleep a final interval).
        r, sandbox = self.run_scenario({POM_PATH: 404, AAR_PATH: 404},
                                       retries="3")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.server.requests.count(POM_PATH), 3)
        self.assertEqual(self.server.requests.count(AAR_PATH), 3)


if __name__ == "__main__":
    unittest.main()
