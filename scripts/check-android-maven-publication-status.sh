#!/usr/bin/env bash
# Checks whether a release version was published to Maven Central.
#
# The consumer validation workflow (release-consumer.yml, android_maven job)
# runs this before it sets up the SDK and boots the emulator: a version that
# was never published to Central -- for example v0.5.0, which was released
# 2026-11-14, before the publish_maven job landed in #132 (2026-11-16) -- can
# never appear there, and the verify script would otherwise burn its entire
# retry budget waiting for a Central sync that will never happen (Issue #137).
#
# Three checks, in order of certainty:
#
#   1. Does the v<version> tag exist? A release run with publish: true
#      creates it; candidate runs and unpublished versions create none.
#      A missing tag is a definitive "never released".
#   2. Does the release workflow at that tag have the publish_maven job?
#      (Contents API only; the workflow's `contents: read` permission
#      suffices.) A tag whose release.yml predates #132 (v0.5.0 and
#      earlier) is a definitive "never published".
#   3. Best effort: did the release run actually complete publish_maven?
#      release.yml pushes the tag in the `publish` job *before* the
#      dependent publish_maven job runs, so the evidence above proves
#      publication was *configured* for this release, not that it
#      succeeded: a failed or cancelled publish_maven leaves the tag in
#      place, and the artifact never reaches Central. Step 3 resolves the
#      tag to the release commit (dereferencing the annotated tag object
#      release.yml creates), takes that commit's parent -- the commit the
#      run was dispatched on -- as the run's head commit, lists the
#      Release workflow runs for it (the GitHub API does not expose a
#      run's workflow_dispatch inputs, so the tag is the only stable
#      attribution), and classifies each run's publish_maven job:
#
#      - success -> confirmed;
#      - in progress -> unconfirmed (the retry loop decides);
#      - failed, cancelled, or skipped because the tag-pushing publish
#        job failed or was cancelled (the run never published) ->
#        checked against Maven Central: a visible artifact is confirmed,
#        a partially visible or unreachable Central is unconfirmed, and
#        an absent artifact is a definitive failure;
#      - skipped for another reason (a candidate run) -> ignored.
#
#      A run whose jobs could not be read or parsed is "incomplete", and
#      a definitive failure is reported only when no matching run is
#      incomplete, still running, or confirmed: an unreadable run may
#      still succeed or still be publishing. Incomplete or missing
#      evidence reports the outcome as unconfirmed and leaves the
#      decision to the verify script's retry loop, which observes Maven
#      Central directly (the pre-#137 behavior).
#
# Exit codes:
#   0  published, or not definitively ruled out (publication in progress,
#      the artifact visible or syncing on Central, incomplete or missing
#      run data, or API error), or SKIP_PUBLICATION_CHECK=1 -- proceed to
#      the verify script, whose retry loop absorbs the Central sync delay
#   1  definitively never published (no tag; no publish_maven job; or the
#      publication did not complete and the artifact is absent from
#      Central) -- fail fast
#   2  usage error
#
# Environment:
#   GH_TOKEN                  GitHub token (set in CI); unauthenticated otherwise
#   GITHUB_REPOSITORY         defaults to ProjectFlora/AppAuth-Rust
#   GITHUB_API_BASE           defaults to https://api.github.com (tests)
#   MAVEN_CENTRAL_BASE_URL    defaults to https://repo.maven.apache.org/maven2
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
central_base="${MAVEN_CENTRAL_BASE_URL:-https://repo.maven.apache.org/maven2}"
base_path="net/project-flora/appauth/appauth-rust-android/${version}"
pom_url="${central_base}/${base_path}/appauth-rust-android-${version}.pom"
# The full publication, the same file set scripts/verify-android-maven-consumer.sh
# gates on (Issue #131).
artifact_files=(
    "appauth-rust-android-${version}.aar"
    "appauth-rust-android-${version}.pom"
    "appauth-rust-android-${version}.module"
    "appauth-rust-android-${version}-sources.jar"
    "appauth-rust-android-${version}-javadoc.jar"
    "appauth-rust-android-${version}.aar.asc"
    "appauth-rust-android-${version}.pom.asc"
    "appauth-rust-android-${version}.module.asc"
    "appauth-rust-android-${version}-sources.jar.asc"
    "appauth-rust-android-${version}-javadoc.jar.asc"
)

# GET a REST endpoint, writing the body to $2 and printing the HTTP status
# code. Returns non-zero on transport failure (network error, timeout).
curl_api() {
    local args=(-sS --max-time 30 -H "Accept: application/vnd.github+json" -o "$2" -w "%{http_code}")
    if [[ -n "${GH_TOKEN:-}" ]]; then
        args+=(-H "Authorization: Bearer ${GH_TOKEN}")
    fi
    curl "${args[@]}" "${api_base}${1}"
}

# The HTTP status of a HEAD request, or 000 on a transport failure.
http_head() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -I --max-time 30 "$1") || code="000"
    printf '%s' "${code:-000}"
}

# Classify the artifact's visibility on Maven Central over the full
# publication (the file set above):
#   visible  every file answers 200
#   syncing  some but not all do (the portal -> Central sync is
#            propagating, so the deployment was released)
#   absent   Central answers, but no file is there
#   unknown  some file could not be reached at all
central_check() {
    local f status complete=0 any200=0 any000=0
    for f in "${artifact_files[@]}"; do
        status=$(http_head "${central_base}/${base_path}/${f}")
        echo "    ${f}: HTTP ${status}" >&2
        if [[ "${status}" == "200" ]]; then
            complete=$((complete + 1))
            any200=1
        elif [[ "${status}" == "000" ]]; then
            any000=1
        fi
    done
    if [[ ${any000} -eq 1 ]]; then
        printf 'unknown\n'
    elif [[ ${complete} -eq ${#artifact_files[@]} ]]; then
        printf 'visible\n'
    elif [[ ${any200} -eq 1 ]]; then
        printf 'syncing\n'
    else
        printf 'absent\n'
    fi
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

# The tag's object type and SHA, for the run attribution in check 3 (both
# empty when the body cannot be parsed; check 3 then degrades to
# "unconfirmed" without further queries).
tag_type=""
tag_sha=""
tag_meta=$(python3 -c 'import json,sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    obj = data["object"]
    print("%s\t%s" % (obj["type"], obj["sha"]))
except Exception:
    pass' "$tmp" 2>/dev/null) || tag_meta=""
if [[ -n "${tag_meta:-}" ]]; then
    tag_type=${tag_meta%%$'\t'*}
    tag_sha=${tag_meta#*$'\t'}
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

# 3. Best effort: did the release run actually complete the publication?
#
# Check 2 is definition-only evidence: the tag exists and the workflow at the
# tag can publish, but release.yml pushes the tag in the `publish` job
# *before* the dependent publish_maven job runs, so a failed or cancelled
# publish_maven leaves the tag in place while the artifact never reaches
# Central -- and the retry loop below would wait 10 minutes for a sync that
# will not occur.
#
# Attribution: the run's head commit is the tagged release commit's parent
# (the release run was dispatched on that commit, and the publish job
# committed the Package.swift update on top of it). Find the Release
# workflow runs for that commit and read their publish_maven results.
#
# Every failure in this check degrades to "unconfirmed" (exit 0): the verify
# script then observes Maven Central directly and its retry loop decides.
echo "Checking the release run for v${version} for a completed Maven publication..."

any_success=0
any_running=0
any_failed=0
any_incomplete=0
failed_reason=""
failed_run_url=""

# commit_sha of the tag: the ref object for an annotated tag points at the
# tag object, which must be dereferenced; a lightweight tag points at the
# commit directly.
commit_sha=""
if [[ "${tag_type}" == "tag" ]]; then
    code=$(curl_api "/repos/${repo}/git/tags/${tag_sha}" "$tmp") || code=""
    if [[ "$code" =~ ^2[0-9][0-9]$ ]]; then
        commit_sha=$(python3 -c 'import json,sys
try:
    with open(sys.argv[1]) as f:
        print(json.load(f)["object"]["sha"])
except Exception:
    pass' "$tmp" 2>/dev/null) || commit_sha=""
    fi
elif [[ "${tag_type}" == "commit" ]]; then
    commit_sha="${tag_sha}"
fi

# The Release workflow ran with the tagged commit as its head commit; its
# parent is the commit the run was dispatched on.
run_commit=""
if [[ -n "${commit_sha:-}" ]]; then
    code=$(curl_api "/repos/${repo}/git/commits/${commit_sha}" "$tmp") || code=""
    if [[ "$code" =~ ^2[0-9][0-9]$ ]]; then
        run_commit=$(python3 -c 'import json,sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    parents = data.get("parents") or []
    print(parents[0]["sha"] if parents else "")
except Exception:
    pass' "$tmp" 2>/dev/null) || run_commit=""
    fi
fi

workflow_id=""
if [[ -n "${run_commit:-}" ]]; then
    code=$(curl_api "/repos/${repo}/actions/workflows" "$tmp") || code=""
    if [[ "$code" =~ ^2[0-9][0-9]$ ]]; then
        workflow_id=$(python3 -c 'import json,sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    for workflow in data.get("workflows", []):
        if workflow.get("path") == ".github/workflows/release.yml":
            print(workflow["id"])
            break
except Exception:
    pass' "$tmp" 2>/dev/null) || workflow_id=""
    fi
fi

if [[ -n "${workflow_id:-}" ]]; then
    # List the Release workflow runs, newest first, and inspect the
    # publish_maven result of each run dispatched on the tag's commit.
    page=1
    while [[ ${page} -le 5 ]]; do
        code=$(curl_api "/repos/${repo}/actions/workflows/${workflow_id}/runs?per_page=100&page=${page}" "$tmp") || code=""
        [[ "$code" == "200" ]] || break
        page_done=0
        page_out=$(python3 - "$tmp" "${run_commit}" <<'PY' 2>/dev/null || true
import json
import sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    sys.exit(0)
target = sys.argv[2]
for run in data.get("workflow_runs", []):
    if run.get("head_sha") == target:
        print("run\t%s\t%s\t%s" % (run["id"], run.get("run_attempt", 1), run.get("html_url", "")))
print("total\t%s" % data.get("total_count", 0))
PY
)
        while IFS=$'\t' read -r kind run_id run_attempt run_url; do
            [[ -n "${kind:-}" ]] || continue
            if [[ "${kind}" == "total" ]]; then
                # Fewer than a full page: nothing older remains.
                if [[ "${run_id:-0}" -lt 100 ]]; then
                    page_done=1
                fi
                continue
            fi
            [[ "${kind}" == "run" ]] || continue
            code=$(curl_api "/repos/${repo}/actions/runs/${run_id}/jobs?per_page=100&attempt=${run_attempt:-1}" "$tmp") || code=""
            if [[ "${code:-}" != "200" ]]; then
                # The run's jobs could not be read: its publication outcome
                # is unknown, which must not count as a failure.
                any_incomplete=1
                continue
            fi
            # Classify this run's publication outcome in one place: the
            # publish_maven job is the only Release workflow job with
            # "Maven" in its name, and a skipped publish_maven is only a
            # real non-publication when the tag-pushing publish job failed
            # (a candidate run skips both jobs on purpose).
            job_class=$(python3 - "$tmp" <<'PY' 2>/dev/null
import json
import sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    sys.exit(3)  # unparseable body: the outcome is unknown, not failed

jobs = data.get("jobs", [])
maven = [j for j in jobs if "Maven" in (j.get("name") or "")]
publish = [j for j in jobs if (j.get("name") or "") == "Publish GitHub Release"]

def outcome(job):
    # A completed job's conclusion is its final result; an in-flight job
    # has no conclusion yet and is reported by its status.
    return job.get("conclusion") or job.get("status", "")

def inflight(job):
    return not job.get("conclusion") and job.get("status") in (
        "in_progress", "queued", "waiting")

if any(outcome(j) == "success" for j in maven):
    print("confirmed")
elif any(inflight(j) for j in maven):
    print("running")
elif any(outcome(j) in ("failure", "cancelled") for j in maven):
    print("failed")
elif any(outcome(j) == "skipped" for j in maven):
    if any(outcome(j) in ("failure", "cancelled") for j in publish):
        print("prereq_failed")
    else:
        print("ignored")
else:
    # No publish_maven job in this run (for example, a run built from a
    # release.yml predating #132): it contributes no publication evidence.
    print("ignored")
PY
) && job_rc=0 || job_rc=$?
            if [[ ${job_rc} -ne 0 ]]; then
                any_incomplete=1
                continue
            fi
            case "${job_class}" in
                confirmed) any_success=1 ;;
                running) any_running=1 ;;
                failed | prereq_failed)
                    any_failed=1
                    failed_reason="${job_class}"
                    failed_run_url="${run_url:-}"
                    ;;
            esac
        done <<< "${page_out:-}"
        if [[ "${page_done}" == "1" ]]; then
            break
        fi
        page=$((page + 1))
    done
fi

if [[ ${any_success} -eq 1 ]]; then
    echo "v${version} was published to Maven Central."
    echo "       Confirmed: the Release run for this version completed its Maven publication job successfully."
    exit 0
fi
if [[ ${any_running} -eq 1 ]]; then
    echo "v${version} was published to Maven Central (the release workflow at tag v${version} has the publish_maven job)."
    echo "       The Maven publication is still running, so its outcome is unconfirmed; proceeding to the verify script, whose retry loop observes Maven Central directly."
    exit 0
fi
# A definitive failure requires complete evidence: if any matching run's
# results could not be read, that run may still succeed or still be
# publishing, so the outcome is reported as unconfirmed instead and the
# verify script's retry loop, which observes Maven Central directly,
# decides.
if [[ ${any_failed} -eq 1 && ${any_incomplete} -eq 0 ]]; then
    # A failed, cancelled, or prerequisite-blocked publication is checked
    # against Maven Central before being rejected: publish_maven can fail
    # or be cancelled *after* the Central Portal deployment was released,
    # in which case the artifact is already on its way and republishing
    # an immutable version would be the wrong remedy.
    central_state=$(central_check)
    if [[ "${central_state}" == "visible" ]]; then
        echo "v${version} was published to Maven Central (the release workflow at tag v${version} has the publish_maven job)."
        echo "       The release run's Maven publication job${failed_run_url:+ (${failed_run_url})} did not complete, but the artifact is already visible on Maven Central: the Central Portal deployment was released. Proceeding to the verify script."
        exit 0
    fi
    if [[ "${central_state}" == "syncing" ]]; then
        echo "v${version} was published to Maven Central (the release workflow at tag v${version} has the publish_maven job)."
        echo "       The publication outcome is unconfirmed: the artifact is partially visible on Maven Central, so the Central sync is still propagating. Proceeding to the verify script, whose retry loop observes Maven Central directly."
        exit 0
    fi
    if [[ "${central_state}" == "unknown" ]]; then
        echo "v${version} was published to Maven Central (the release workflow at tag v${version} has the publish_maven job)."
        echo "       The publication outcome is unconfirmed: Maven Central could not be reached. Proceeding to the verify script, whose retry loop observes Maven Central directly."
        exit 0
    fi
    echo "ERROR: v${version} was released, but its Maven publication did not complete, and the artifact is not on Maven Central." >&2
    if [[ "${failed_reason}" == "prereq_failed" ]]; then
        echo "       The Release run${failed_run_url:+ (${failed_run_url})} has its Maven publication job skipped: the tag-pushing publish job failed or was cancelled, so the run never attempted a publication." >&2
        echo "       Remove the tag first (git push origin :refs/tags/v${version} -- see docs/releasing.md), then use \"Re-run failed jobs\" on that run, and dispatch the consumer validation again." >&2
    else
        echo "       The Release run${failed_run_url:+ (${failed_run_url})} has its Maven publication job failed or cancelled." >&2
        echo "       Check the run's logs for the Central Portal deployment: if it was *not* released, fix the cause (for example, credentials or the signing key) and use \"Re-run failed jobs\" -- it re-runs only the failed or cancelled jobs, so an already-pushed tag is not re-pushed." >&2
        echo "       If the deployment *was* released, the sync completes on its own: wait, then dispatch the consumer validation again. A version already on Central cannot be republished; if it never appears, fix forward with a new patch version." >&2
    fi
    exit 1
fi
echo "v${version} was published to Maven Central (the release workflow at tag v${version} has the publish_maven job)."
if [[ ${any_failed} -eq 1 ]]; then
    echo "       At least one release run's Maven publication job failed or was cancelled, but at least one matching run's results could not be read, so the outcome is unconfirmed; proceeding to the verify script, whose retry loop observes Maven Central directly."
else
    echo "       The publication outcome is unconfirmed (the release run data could not be queried, or the runs carried no Maven publication job); proceeding to the verify script, whose retry loop observes Maven Central directly."
fi
exit 0
