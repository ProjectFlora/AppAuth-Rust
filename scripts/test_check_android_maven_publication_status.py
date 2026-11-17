"""Tests for scripts/check-android-maven-publication-status.sh.

The check distinguishes a version that was never published to Maven Central
(released before publish_maven existed in release.yml, or never released at
all) from one whose publication is still propagating, which the verify
script's retry loop absorbs (Issue #137). It makes three queries the tests
mock locally:

    1. GET /repos/<repo>/git/refs/tags/v<version>
    2. GET /repos/<repo>/contents/.github/workflows/release.yml?ref=v<version>
    3. (best effort, the publication outcome)
       GET /repos/<repo>/git/tags/<tag object sha>        (annotated tags)
       GET /repos/<repo>/git/commits/<commit sha>
       GET /repos/<repo>/actions/workflows
       GET /repos/<repo>/actions/workflows/<id>/runs?per_page=100&page=<n>
       GET /repos/<repo>/actions/runs/<id>/jobs?per_page=100&attempt=<n>

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
VERSION = "1.2.3"
TAG_SHA = "a" * 40
COMMIT_SHA = "b" * 40
BASE_SHA = "c" * 40
RUN_ID = 777
WORKFLOW_ID = 42
RUN_URL = "https://github.com/%s/actions/runs/%d" % (REPO, RUN_ID)

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
        # self.server.routes maps "path?query" -> (status, body or None)
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


def route(path):
    """A mock-API route key, relative to the mock base URL."""
    return "/repos/%s%s" % (REPO, path)


def json_body(status, payload):
    return (status, json.dumps(payload).encode())


def yml_response(yml_text):
    return (200, json.dumps(
        {"name": "release.yml", "encoding": "base64",
         "content": base64.b64encode(yml_text.encode()).decode(),
         "size": len(yml_text)}).encode())


def annotated_tag_response():
    return json_body(
        200,
        {"ref": "refs/tags/v%s" % VERSION,
         "object": {"sha": TAG_SHA, "type": "tag", "url": ""}})


def tag_object_response():
    # The annotated tag object points at the release commit.
    return json_body(
        200,
        {"tag": "v%s" % VERSION,
         "object": {"sha": COMMIT_SHA, "type": "commit", "url": ""}})


def commit_response():
    # The release commit's parent is the commit the Release run was
    # dispatched on (the run's head commit).
    return json_body(
        200,
        {"sha": COMMIT_SHA,
         "parents": [{"sha": BASE_SHA}]})


def workflows_response():
    return json_body(
        200,
        {"total_count": 1,
         "workflows": [{"id": WORKFLOW_ID, "name": "Release",
                        "path": ".github/workflows/release.yml"}]})


def runs_response(job_status=None, job_conclusion=None):
    # The /actions/workflows/{id}/runs response lists its runs under the
    # "workflow_runs" key (verified against the live API).
    status = "completed" if job_conclusion is not None else job_status
    return json_body(
        200,
        {"total_count": 1,
         "workflow_runs": [{"id": RUN_ID, "run_attempt": 1,
                            "head_sha": BASE_SHA, "status": status,
                            "conclusion": job_conclusion,
                            "html_url": RUN_URL}]})


def jobs_response(job_status, job_conclusion):
    return json_body(
        200,
        {"total_count": 2,
         "jobs": [{"id": 1, "name": "Publish GitHub Release",
                   "status": "completed", "conclusion": "success"},
                  {"id": 2, "name": "Publish Android library to Maven Central",
                   "status": job_status, "conclusion": job_conclusion}]})


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

    def test_usage(self):
        r = subprocess.run(["bash", SCRIPT], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("Usage", r.stderr)

    def test_invalid_version(self):
        r = self.run_script("1.2", {})
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("not a MAJOR.MINOR.PATCH", r.stderr)
        self.assertEqual(self.server.requests, [])

    def test_skip(self):
        r = self.run_script(VERSION, {}, skip=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.server.requests, [])

    def test_never_released_no_tag(self):
        r = self.run_script(VERSION, {
            route("/git/refs/tags/v" + VERSION): (404, None),
        })
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("was never released", r.stderr)
        self.assertIn("v%s" % VERSION, r.stderr)
        # The contents endpoint must not even be queried.
        self.assertEqual(
            self.server.requests,
            [route("/git/refs/tags/v" + VERSION)])

    def test_api_error_degrades_to_retry_loop(self):
        # A 500 (or a rate-limited 403) is not a definitive "never published":
        # the script must let the verify script's retry loop take over.
        for status in (500, 403):
            r = self.run_script(VERSION, {
                route("/git/refs/tags/v" + VERSION): (status, b"{}"),
            })
            self.assertEqual(r.returncode, 0, (status, r.stderr))
            self.assertIn("WARN", r.stderr)

    def test_released_before_maven_publication(self):
        r = self.run_script(VERSION, {
            route("/git/refs/tags/v" + VERSION): annotated_tag_response(),
            route("/contents/.github/workflows/release.yml?ref=v" + VERSION):
                yml_response(RELEASE_YML_WITHOUT_MAVEN),
        })
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("never published to Maven Central", r.stderr)
        self.assertIn("publish_maven", r.stderr)
        self.assertIn(
            "https://repo.maven.apache.org/maven2/net/project-flora/appauth/"
            "appauth-rust-android/%s/appauth-rust-android-%s.pom"
            % (VERSION, VERSION),
            r.stderr)

    def published_routes(self):
        """The tag + release.yml routes common to the step-3 scenarios."""
        return {
            route("/git/refs/tags/v" + VERSION): annotated_tag_response(),
            route("/contents/.github/workflows/release.yml?ref=v" + VERSION):
                yml_response(RELEASE_YML_WITH_MAVEN),
        }

    def test_published_maven_job_succeeded(self):
        routes = self.published_routes()
        routes[route("/git/tags/%s" % TAG_SHA)] = tag_object_response()
        routes[route("/git/commits/%s" % COMMIT_SHA)] = commit_response()
        routes[route("/actions/workflows")] = workflows_response()
        routes[route("/actions/workflows/%d/runs?per_page=100&page=1"
                     % WORKFLOW_ID)] = runs_response("completed", "success")
        routes[route("/actions/runs/%d/jobs?per_page=100&attempt=1" % RUN_ID)] = \
            jobs_response("completed", "success")
        r = self.run_script(VERSION, routes)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("was published to Maven Central", r.stdout)
        self.assertIn("Confirmed", r.stdout)

    def test_published_maven_job_failed(self):
        routes = self.published_routes()
        routes[route("/git/tags/%s" % TAG_SHA)] = tag_object_response()
        routes[route("/git/commits/%s" % COMMIT_SHA)] = commit_response()
        routes[route("/actions/workflows")] = workflows_response()
        routes[route("/actions/workflows/%d/runs?per_page=100&page=1"
                     % WORKFLOW_ID)] = runs_response("completed", "failure")
        routes[route("/actions/runs/%d/jobs?per_page=100&attempt=1" % RUN_ID)] = \
            jobs_response("completed", "failure")
        r = self.run_script(VERSION, routes)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("Maven publication did not complete", r.stderr)
        self.assertIn("Re-run failed jobs", r.stderr)
        # The tag-removal remedy for a run whose tag push did not complete.
        self.assertIn("remove the tag first", r.stderr)
        self.assertIn(RUN_URL, r.stderr)

    def test_published_maven_job_running(self):
        # The publication is still in flight: not a failure, but the outcome
        # is unconfirmed and the retry loop must be allowed to take over.
        routes = self.published_routes()
        routes[route("/git/tags/%s" % TAG_SHA)] = tag_object_response()
        routes[route("/git/commits/%s" % COMMIT_SHA)] = commit_response()
        routes[route("/actions/workflows")] = workflows_response()
        routes[route("/actions/workflows/%d/runs?per_page=100&page=1"
                     % WORKFLOW_ID)] = runs_response("in_progress", None)
        routes[route("/actions/runs/%d/jobs?per_page=100&attempt=1" % RUN_ID)] = \
            jobs_response("in_progress", None)
        r = self.run_script(VERSION, routes)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("was published to Maven Central", r.stdout)
        self.assertIn("unconfirmed", r.stdout)
        self.assertIn("still running", r.stdout)

    def test_published_outcome_unconfirmed_api_error(self):
        # A failure of the outcome queries is not a publication failure:
        # report unconfirmed and let the retry loop observe Central directly.
        routes = self.published_routes()
        routes[route("/git/tags/%s" % TAG_SHA)] = (500, b"{}")
        r = self.run_script(VERSION, routes)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("unconfirmed", r.stdout)
        # The failure must stop the chain before the commits query.
        self.assertEqual(
            self.server.requests,
            [route("/git/refs/tags/v" + VERSION),
             route("/contents/.github/workflows/release.yml?ref=v" + VERSION),
             route("/git/tags/%s" % TAG_SHA)])

    def test_published_unparseable_tag_body(self):
        # A tag body without the object payload cannot be attributed to a
        # run; the check must degrade to unconfirmed without further calls.
        routes = self.published_routes()
        routes[route("/git/refs/tags/v" + VERSION)] = (200, b"{}")
        r = self.run_script(VERSION, routes)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("unconfirmed", r.stdout)
        self.assertEqual(
            self.server.requests,
            [route("/git/refs/tags/v" + VERSION),
             route("/contents/.github/workflows/release.yml?ref=v" + VERSION)])

    def test_published_lightweight_tag(self):
        # A lightweight tag points at the commit directly: no tag object
        # dereference, but the same run attribution.
        routes = self.published_routes()
        routes[route("/git/refs/tags/v" + VERSION)] = json_body(
            200,
            {"ref": "refs/tags/v%s" % VERSION,
             "object": {"sha": COMMIT_SHA, "type": "commit", "url": ""}})
        routes[route("/git/commits/%s" % COMMIT_SHA)] = commit_response()
        routes[route("/actions/workflows")] = workflows_response()
        routes[route("/actions/workflows/%d/runs?per_page=100&page=1"
                     % WORKFLOW_ID)] = runs_response("completed", "success")
        routes[route("/actions/runs/%d/jobs?per_page=100&attempt=1" % RUN_ID)] = \
            jobs_response("completed", "success")
        r = self.run_script(VERSION, routes)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Confirmed", r.stdout)
        self.assertNotIn(route("/git/tags/%s" % TAG_SHA),
                         self.server.requests)


if __name__ == "__main__":
    unittest.main()
