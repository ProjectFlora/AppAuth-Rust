#!/usr/bin/env bash
# Verifies that a published release's Android library can be consumed from
# Maven Central, exactly the way a foreign Gradle consumer would.
#
# The stages, run in a retry loop that absorbs the Central sync delay (the
# portal -> Central propagation that starts when publish_maven finishes:
# typically minutes, occasionally up to an hour):
#
#   1. Availability gate: a direct HTTP HEAD on the canonical POM and AAR
#      URLs. This replaces the old light check -- `gradle dependencies` is a
#      lenient report: it renders unresolvable dependencies as FAILED nodes
#      and exits 0, so it "passed" for an artifact that 404s on Central
#      (Issue #137). Both URLs returning 200 is the deterministic
#      "visible on Central" signal the later stages rely on.
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
# The group's Maven path and the artifact name (native/android/build.gradle.kts)
pom_url="${central_base}/net/project-flora/appauth/appauth-rust-android/${VERSION}/appauth-rust-android-${VERSION}.pom"
aar_url="${central_base}/net/project-flora/appauth/appauth-rust-android/${VERSION}/appauth-rust-android-${VERSION}.aar"

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
fixture="$repo_root/native/consumer-smoke/android"

# Stage 1: HTTP availability gate. Anything other than 200 -- 404 while the
# sync is still propagating, 410 for a withdrawn version, 000 for a transport
# failure -- means "not (yet) visible"; the retry loop absorbs it.
http_status() {
    curl -s -o /dev/null -w "%{http_code}" -I --max-time 30 "$1" || printf '000'
}

last_pom=""
last_aar=""

gate() {
    last_pom=$(http_status "$pom_url")
    last_aar=$(http_status "$aar_url")
    echo "    POM: HTTP ${last_pom}  ${pom_url}"
    echo "    AAR: HTTP ${last_aar}  ${aar_url}"
    [[ "$last_pom" == "200" && "$last_aar" == "200" ]]
}

# Stage 2: strict resolution preflight (see header).
strict_check() {
    "$repo_root/native/android/gradlew" -p "$fixture" -PappauthVersion="$VERSION" \
        --refresh-dependencies checkDebugAarMetadata
}

for i in $(seq 1 "$MAX_RETRIES"); do
    echo "Retry ${i}/${MAX_RETRIES}: Maven Central availability gate..."
    if gate; then
        echo "Artifact visible on Maven Central. Running strict resolution preflight..."
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
        echo "Artifact not yet visible on Maven Central (last status: POM ${last_pom}, AAR ${last_aar})." >&2
        echo "If this version was just published, this is the portal -> Central sync delay; if it was published long ago, the artifact may have been withdrawn." >&2
    fi
    if [[ "$i" -lt "$MAX_RETRIES" ]]; then
        echo "Waiting ${RETRY_INTERVAL}s before the next retry..."
        sleep "$RETRY_INTERVAL"
    fi
done

echo "Maven Central verification failed after ${MAX_RETRIES} attempts (last gate: POM ${last_pom}, AAR ${last_aar})." >&2
echo "If the release run's publish_maven job succeeded but the artifact never becomes visible, check the Central portal deployment for the version; once the sync completes, dispatch the workflow again." >&2
exit 1
