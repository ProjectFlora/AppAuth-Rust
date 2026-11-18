#!/usr/bin/env bash
# Verifies that a published release's Android library can be consumed from
# Maven Central, exactly the way a foreign Gradle consumer would.
#
# The stages, run in a retry loop that absorbs the Central sync delay (the
# portal -> Central propagation that starts when publish_maven finishes:
# typically minutes, occasionally up to an hour):
#
#   1. Availability gate: a direct HTTP HEAD on every file of the
#      publication -- the AAR, the POM, the Gradle module metadata, the
#      sources and javadoc jars, and the GPG signature of each: exactly the
#      file set the local pre-publication check verifies (Issue #131). This
#      replaces the old light check -- `gradle dependencies` is a lenient
#      report: it renders unresolvable dependencies as FAILED nodes and exits
#      0, so it "passed" for an artifact that 404s on Central (Issue #137)
#      -- and every file answering 200 is the deterministic "complete
#      publication on Central" signal the later stages rely on: a deployment
#      that is only partially synced is retried, and one that is missing its
#      signatures cannot pass the gate.
#   2. Strict resolution preflight: checkDebugAarMetadata resolves the POM
#      and downloads the AAR and the transitive dependencies.
#      --refresh-dependencies re-verifies against Central rather than
#      trusting the local module cache, where a 404 from an earlier retry
#      would otherwise sit as a 24h negative entry. It fails the build on a
#      missing or malformed artifact, before the expensive emulator test.
#   3. Full consumer smoke: check-android-maven-consumer.sh (assemble +
#      connectedDebugAndroidTest on the emulator).
#
# In CI, release-consumer.yml runs scripts/check-android-maven-publication-status.sh
# first, which fails a version that was never published to Central before
# the emulator boots; run that script locally for the same fail-fast.
#
# Environment (defaults in parentheses, overridable for tests):
#   MAVEN_CENTRAL_BASE_URL  (https://repo.maven.apache.org/maven2)
#   VERIFY_MAX_RETRIES      (10)
#   VERIFY_RETRY_INTERVAL   (60 seconds)

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version>" >&2
    exit 2
fi

VERSION="$1"
MAX_RETRIES="${VERIFY_MAX_RETRIES:-10}"
RETRY_INTERVAL="${VERIFY_RETRY_INTERVAL:-60}"

central_base="${MAVEN_CENTRAL_BASE_URL:-https://repo.maven.apache.org/maven2}"
# The group's Maven path (native/android/build.gradle.kts) and the full
# publication, the file set scripts/check-android-maven-publication.sh
# verifies locally before the upload (Issue #131).
base_path="net/project-flora/nativeoidc/native-oidc-android/${VERSION}"
artifact_files=(
    "native-oidc-android-${VERSION}.aar"
    "native-oidc-android-${VERSION}.pom"
    "native-oidc-android-${VERSION}.module"
    "native-oidc-android-${VERSION}-sources.jar"
    "native-oidc-android-${VERSION}-javadoc.jar"
    "native-oidc-android-${VERSION}.aar.asc"
    "native-oidc-android-${VERSION}.pom.asc"
    "native-oidc-android-${VERSION}.module.asc"
    "native-oidc-android-${VERSION}-sources.jar.asc"
    "native-oidc-android-${VERSION}-javadoc.jar.asc"
)

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
fixture="$repo_root/native/consumer-smoke/android"

# Stage 1: HTTP availability gate (see header). Anything other than 200 --
# 404 while the sync is still propagating, 410 for a withdrawn version, 000
# for a transport failure -- means the publication is not (yet) complete;
# the retry loop absorbs it.
http_status() {
    curl -s -o /dev/null -w "%{http_code}" -I --max-time 30 "$1" || printf '000'
}

# "<file> <status>" for the most recent gate attempt.
last_gate=()

gate() {
    local f status incomplete=0
    last_gate=()
    for f in "${artifact_files[@]}"; do
        status=$(http_status "${central_base}/${base_path}/${f}")
        last_gate+=("${f} ${status}")
        echo "    ${f}: HTTP ${status}"
        [[ "$status" == "200" ]] || incomplete=1
    done
    [[ "$incomplete" -eq 0 ]]
}

# The non-200 files of the most recent gate attempt, for the diagnostic
# messages; a complete gate means the failure came from a later stage.
gate_summary() {
    local entry summary=""
    for entry in "${last_gate[@]}"; do
        # The conditional separator precedes the entry it separates;
        # appending it after would join entries and leave a trailing comma.
        [[ "${entry#* }" == "200" ]] || summary+="${summary:+, }${entry}"
    done
    if [[ -z "$summary" ]]; then
        printf 'all %d files visible' "${#artifact_files[@]}"
    else
        printf '%s' "$summary"
    fi
}

# Stage 2: strict resolution preflight (see header).
strict_check() {
    "$repo_root/native/android/gradlew" -p "$fixture" -PnativeOidcVersion="$VERSION" \
        --refresh-dependencies checkDebugAarMetadata
}

for i in $(seq 1 "$MAX_RETRIES"); do
    echo "Retry ${i}/${MAX_RETRIES}: Maven Central availability gate..."
    if gate; then
        echo "Complete publication visible on Maven Central. Running strict resolution preflight..."
        if strict_check; then
            echo "Strict preflight passed. Running full consumer smoke test..."
            if "$repo_root/scripts/check-android-maven-consumer.sh" "$VERSION"; then
                echo "Maven Central verification succeeded!"
                exit 0
            fi
            echo "Full check failed." >&2
        else
            echo "Strict preflight failed: the POM or AAR is missing or malformed (a transient Central glitch, or a bad publication)." >&2
        fi
    else
        echo "Artifact not yet visible on Maven Central (last gate: $(gate_summary))." >&2
        echo "If this version was just published, this is the portal -> Central sync delay; if it was published long ago, the artifact may have been withdrawn." >&2
    fi
    if [[ "$i" -lt "$MAX_RETRIES" ]]; then
        echo "Waiting ${RETRY_INTERVAL}s before the next retry..."
        sleep "$RETRY_INTERVAL"
    fi
done

echo "Maven Central verification failed after ${MAX_RETRIES} attempts (last gate: $(gate_summary))." >&2
echo "If the release run's publish_maven job succeeded but the artifact never becomes visible, check the Central portal deployment for the version; once the sync completes, dispatch the workflow again." >&2
exit 1
