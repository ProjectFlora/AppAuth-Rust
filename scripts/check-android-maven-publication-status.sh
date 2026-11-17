#!/usr/bin/env bash
# Checks whether a release version was ever published to Maven Central.
#
# The consumer validation workflow (release-consumer.yml, android_maven job)
# runs this before it sets up the SDK and boots the emulator: a version that
# was never published to Central -- for example v0.5.0, which was released
# 2026-11-14, before the publish_maven job landed in #132 (2026-11-16) -- can
# never appear there, and the verify script would otherwise burn its entire
# retry budget waiting for a Central sync that will never happen (Issue #137).
#
# The check uses only the contents API (the `contents: read` permission the
# workflow already has). A version is on its way to Central only if a release
# run created its tag and the release workflow at that tag contains the
# publish_maven job -- the job that uploads the artifact to the Central
# Portal. The GitHub REST API does not expose a run's workflow_dispatch
# inputs, so the tag is the only stable way to attribute a release to a
# version.
#
# Exit codes:
#   0  the version was published to Maven Central, or the check could not
#      decide (API error), or SKIP_PUBLICATION_CHECK=1 -- proceed to the
#      verify script's retry loop, which absorbs the Central sync delay
#   1  the version was definitively never published -- fail fast
#   2  usage error
#
# Environment:
#   GH_TOKEN                  GitHub token (set in CI); unauthenticated otherwise
#   GITHUB_REPOSITORY         defaults to ProjectFlora/AppAuth-Rust
#   GITHUB_API_BASE           defaults to https://api.github.com (tests)
#   SKIP_PUBLICATION_CHECK=1  skip the check (offline local use)

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version>" >&2
    exit 2
fi

version="$1"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: $version is not a MAJOR.MINOR.PATCH release version; it was never released (release.yml enforces this form) and was never published to Maven Central." >&2
    exit 1
fi

if [[ "${SKIP_PUBLICATION_CHECK:-}" == "1" ]]; then
    exit 0
fi

api_base="${GITHUB_API_BASE:-https://api.github.com}"
repo="${GITHUB_REPOSITORY:-ProjectFlora/AppAuth-Rust}"
pom_url="https://repo.maven.apache.org/maven2/net/project-flora/appauth/appauth-rust-android/${version}/appauth-rust-android-${version}.pom"

# GET a REST endpoint, writing the body to $2 and printing the HTTP status
# code. Returns non-zero on transport failure (network error, timeout).
curl_api() {
    local args=(-sS --max-time 30 -H "Accept: application/vnd.github+json" -o "$2" -w "%{http_code}")
    if [[ -n "${GH_TOKEN:-}" ]]; then
        args+=(-H "Authorization: Bearer ${GH_TOKEN}")
    fi
    curl "${args[@]}" "${api_base}${1}"
}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

# 1. Was this version released? A release run with publish: true creates the
#    v$version tag; candidate runs and unpublished versions create none.
code=$(curl_api "/repos/${repo}/git/refs/tags/v${version}" "$tmp") || {
    echo "WARN: could not query the GitHub API for tag v${version} (network error); continuing without the publication check." >&2
    exit 0
}
if [[ "$code" == "404" ]]; then
    echo "ERROR: v${version} was never released: tag v${version} does not exist in ${repo}." >&2
    echo "       A tag is created only by a release run with publish: true, so nothing was published to Maven Central for this version." >&2
    exit 1
fi
if [[ ! "$code" =~ ^2[0-9][0-9]$ ]]; then
    echo "WARN: GitHub API returned HTTP ${code} for tag v${version}; continuing without the publication check." >&2
    exit 0
fi

# 2. Did the release workflow at that tag publish to Maven Central?
code=$(curl_api "/repos/${repo}/contents/.github/workflows/release.yml?ref=v${version}" "$tmp") || {
    echo "WARN: could not fetch release.yml at v${version} (network error); continuing without the publication check." >&2
    exit 0
}
if [[ ! "$code" =~ ^2[0-9][0-9]$ ]]; then
    echo "WARN: GitHub API returned HTTP ${code} for release.yml at v${version}; continuing without the publication check." >&2
    exit 0
fi

has_maven_job=$(python3 - "$tmp" <<'PY'
import base64
import json
import re
import sys

with open(sys.argv[1]) as f:
    data = json.load(f)
content = base64.b64decode(data["content"]).decode()
print("1" if re.search(r"^[ \t]+publish_maven:", content, re.M) else "0")
PY
) || {
    echo "WARN: could not parse release.yml at v${version}; continuing without the publication check." >&2
    exit 0
}

if [[ "$has_maven_job" != "1" ]]; then
    echo "ERROR: v${version} was never published to Maven Central." >&2
    echo "       Tag v${version} exists, but the release workflow at that tag has no publish_maven job:" >&2
    echo "       Maven Central publication was added to release.yml on 2026-11-16 (#132), so releases made before that date (v0.5.0 and earlier) were GitHub Releases only." >&2
    echo "       Expected artifact (not found): ${pom_url}" >&2
    echo "       Dispatch a version released after that date, or dispatch the release workflow again with publish: true." >&2
    exit 1
fi

echo "v${version} was published to Maven Central (the release workflow at tag v${version} has the publish_maven job)."
exit 0
