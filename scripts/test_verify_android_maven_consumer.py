"""Tests for scripts/verify-android-maven-consumer.sh.

The verify script's stage machine (Issue #137): an HTTP availability gate
on the full Maven Central publication -- every file the release publishes,
the AAR, the POM, the Gradle module metadata, the sources and javadoc jars,
and the signature of each (Issue #131) -- a strict Gradle resolution
preflight (checkDebugAarMetadata), and the full consumer smoke. The tests
run the script in a sandbox that replaces the Gradle wrapper with a fake
recording its invocations, and point the availability gate at a local mock
of Maven Central, so no network, SDK or real Gradle is needed:

    test A  gate all 404            -> fails after the budget, Gradle never runs
    test B  gate all 200            -> preflight + smoke, success
    test C  gate all 200, strict x  -> fails with the preflight diagnosis
    test D  gate all 200, smoke x   -> fails with the full-check diagnosis
    test E  gate partially visible  -> treated as not yet visible

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


def gate_paths():
    """The availability-gate URL paths, exactly as the verify script
    constructs them from MAVEN_CENTRAL_BASE_URL: the full publication."""
    base = ("/maven2/net/project-flora/appauth/appauth-rust-android/%s/"
            "appauth-rust-android-%s") % (VERSION, VERSION)
    return [base + ext for ext in (
        ".aar", ".pom", ".module",
        "-sources.jar", "-javadoc.jar",
        ".aar.asc", ".pom.asc", ".module.asc",
        "-sources.jar.asc", "-javadoc.jar.asc",
    )]


def gate_routes(status, **overrides):
    """Gate routes with every file answering `status`; `overrides` maps a
    file name (the path's final component) to a different status, for the
    partial-visibility scenarios."""
    paths = gate_paths()
    routes = {path: status for path in paths}
    for path in paths:
        name = path.rsplit("/", 1)[1]
        if name in overrides:
            routes[path] = overrides[name]
    return routes

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
        r, calls = self.run_scenario(gate_routes(404))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("not yet visible on Maven Central", r.stderr)
        self.assertIn("failed after 2 attempts", r.stderr)
        self.assertIn("appauth-rust-android-%s.pom 404" % VERSION, r.stderr)
        # The missing files are separated by ", " in publication order:
        # the first two entries of the summary, joined correctly
        # (separator-placement regression, Copilot review of #143).
        self.assertIn(
            "appauth-rust-android-%s.aar 404, "
            "appauth-rust-android-%s.pom 404" % (VERSION, VERSION),
            r.stderr)
        # No trailing separator before the closing parenthesis.
        self.assertNotIn(", )", r.stderr)
        self.assertEqual(calls, [])

    def test_gate_200_preflight_and_smoke_succeed(self):
        r, calls = self.run_scenario(gate_routes(200))
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        self.assertIn("verification succeeded", r.stdout)
        self.assertTrue(any("checkDebugAarMetadata" in c for c in calls), calls)
        self.assertTrue(any("connectedDebugAndroidTest" in c for c in calls), calls)
        # The full check also passes --refresh-dependencies to the wrapper.
        self.assertTrue(all("--refresh-dependencies" in c for c in calls), calls)

    def test_strict_preflight_failure(self):
        r, calls = self.run_scenario(gate_routes(200),
                                     strict_exit="1")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("Strict preflight failed", r.stderr)
        self.assertTrue(any("checkDebugAarMetadata" in c for c in calls), calls)
        self.assertFalse(any("connectedDebugAndroidTest" in c for c in calls), calls)

    def test_full_check_failure(self):
        r, calls = self.run_scenario(gate_routes(200),
                                     full_exit="1")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("Full check failed", r.stderr)
        self.assertTrue(any("connectedDebugAndroidTest" in c for c in calls), calls)

    def test_gate_partial_404_is_not_visible(self):
        # A publication missing any single file -- the AAR the full check
        # consumes, the POM, the module metadata, a jar, or one of the
        # signatures -- is incomplete: it must be treated as "not yet
        # visible", never as a preflight attempt. The case is run for every
        # publication file so a gate that HEADs the ten files but only
        # checks some of their statuses (the pre-#131 POM/AAR behavior)
        # cannot regress (Copilot review of #143).
        for missing in gate_paths():
            name = missing.rsplit("/", 1)[1]
            with self.subTest(missing=name):
                r, calls = self.run_scenario(
                    gate_routes(200, **{name: 404}))
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertIn("not yet visible on Maven Central", r.stderr)
                # The diagnosis names the file that is not 200.
                self.assertIn(name, r.stderr)
                self.assertEqual(calls, [])

    def test_retry_budget_is_exhausted_not_waited(self):
        # With a zero interval the loop must still perform exactly
        # MAX_RETRIES gate attempts -- over every publication file -- before
        # failing (and not sleep a final interval).
        r, sandbox = self.run_scenario(gate_routes(404), retries="3")
        self.assertEqual(r.returncode, 1)
        for path in gate_paths():
            self.assertEqual(self.server.requests.count(path), 3, path)


if __name__ == "__main__":
    unittest.main()
