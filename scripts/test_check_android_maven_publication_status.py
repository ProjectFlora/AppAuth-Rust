"""Tests for scripts/check-android-maven-publication-status.sh.

The check distinguishes a version that was never published to Maven Central
(released before publish_maven existed in release.yml, or never released at
all) from one that is published but still syncing, which the verify script's
retry loop absorbs (Issue #137). It does so through the contents API, so
the tests run the script against a local mock of that API:

    GET /repos/<repo>/git/refs/tags/v<version>
    GET /repos/<repo>/contents/.github/workflows/release.yml?ref=v<version>

Run with: python3 -m unittest discover -s scripts -p 'test_*.py'
"""
import base64
import http.server
import json
import os
import subprocess
import threading
import unittest

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(SCRIPTS_DIR, "check-android-maven-publication-status.sh")
REPO = "test/repo"

# A release.yml without the publish_maven job, as at tag v0.5.0 (the release
# predates #132, which added the job).
RELEASE_YML_WITHOUT_MAVEN = (
    "jobs:\n"
    "  validate_version:\n"
    "  android:\n"
    "  publish:\n"
    "    if: ${{ inputs.publish }}\n"
)
RELEASE_YML_WITH_MAVEN = RELEASE_YML_WITHOUT_MAVEN + (
    "  publish_maven:\n"
    "    if: ${{ inputs.publish }}\n"
    "    name: Publish Android library to Maven Central\n"
)


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


class ApiHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # self.server.routes maps "<path>?<query>" -> (status, body or None)
        status, body = self.server.routes.get(self.path, (404, None))
        self.server.requests.append(self.path)
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.end_headers()

    def log_message(self, format, *args):  # silence request logging
        pass


def yml_response(yml_text):
    return (200, json.dumps(
        {"name": "release.yml", "encoding": "base64",
         "content": base64.b64encode(yml_text.encode()).decode(),
         "size": len(yml_text)}).encode())


class PublicationStatusCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = FastHTTPServer(("127.0.0.1", 0), ApiHandler)
        cls.server.routes = {}
        cls.server.requests = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def run_script(self, version, routes, skip=False):
        self.server.routes = routes
        self.server.requests.clear()
        env = dict(os.environ)
        env.update({
            "GITHUB_API_BASE": self.base,
            "GITHUB_REPOSITORY": REPO,
            "GH_TOKEN": "",  # never hit the real API from a test
        })
        if skip:
            env["SKIP_PUBLICATION_CHECK"] = "1"
        else:
            env.pop("SKIP_PUBLICATION_CHECK", None)
        return subprocess.run(
            ["bash", SCRIPT, version], env=env,
            capture_output=True, text=True, timeout=60)

    def tag(self, status, body=None):
        self.server.routes.setdefault(
            "/repos/%s/git/refs/tags/v" % REPO, (status, body))

    def test_never_released_no_tag(self):
        r = self.run_script("1.2.3", {
            "/repos/%s/git/refs/tags/v1.2.3" % REPO: (404, None),
        })
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("was never released", r.stderr)
        self.assertIn("v1.2.3", r.stderr)
        # The contents endpoint must not even be queried.
        self.assertEqual(self.server.requests,
                         ["/repos/%s/git/refs/tags/v1.2.3" % REPO])

    def test_released_before_maven_publication(self):
        r = self.run_script("1.2.3", {
            "/repos/%s/git/refs/tags/v1.2.3" % REPO: (200, b"{}"),
            "/repos/%s/contents/.github/workflows/release.yml?ref=v1.2.3" % REPO:
                yml_response(RELEASE_YML_WITHOUT_MAVEN),
        })
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("never published to Maven Central", r.stderr)
        self.assertIn("publish_maven", r.stderr)
        self.assertIn(
            "https://repo.maven.apache.org/maven2/net/project-flora/appauth/"
            "appauth-rust-android/1.2.3/appauth-rust-android-1.2.3.pom",
            r.stderr)

    def test_published(self):
        r = self.run_script("1.2.3", {
            "/repos/%s/git/refs/tags/v1.2.3" % REPO: (200, b"{}"),
            "/repos/%s/contents/.github/workflows/release.yml?ref=v1.2.3" % REPO:
                yml_response(RELEASE_YML_WITH_MAVEN),
        })
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("published to Maven Central", r.stdout)

    def test_api_error_degrades_to_retry_loop(self):
        # A 500 (or a rate-limited 403) is not a definitive "never published":
        # the script must let the verify script's retry loop take over.
        for status in (500, 403):
            r = self.run_script("1.2.3", {
                "/repos/%s/git/refs/tags/v1.2.3" % REPO: (status, b"{}"),
            })
            self.assertEqual(r.returncode, 0, (status, r.stderr))
            self.assertIn("WARN", r.stderr)

    def test_skip(self):
        r = self.run_script("1.2.3", {}, skip=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.server.requests, [])

    def test_invalid_version(self):
        r = self.run_script("1.2", {})
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("not a MAJOR.MINOR.PATCH", r.stderr)
        self.assertEqual(self.server.requests, [])

    def test_usage(self):
        r = subprocess.run(["bash", SCRIPT], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("Usage", r.stderr)


if __name__ == "__main__":
    unittest.main()
