#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version>" >&2
    exit 2
fi

VERSION="$1"
MAX_RETRIES=10
RETRY_INTERVAL=60 # seconds

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
fixture="$repo_root/native/consumer-smoke/android"

for i in $(seq 1 $MAX_RETRIES); do
    echo "Retry $i/$MAX_RETRIES: Checking Maven Central artifact availability..."

    # Light check: Validate that dependencies can be resolved from Maven Central
    if ! "$repo_root/native/android/gradlew" -p "$fixture" -PappauthVersion="$VERSION" --refresh-dependencies dependencies > /dev/null 2>&1; then
        echo "Light check failed: Artifact not yet available or POM error. Waiting $RETRY_INTERVAL seconds..."
        sleep "$RETRY_INTERVAL"
        continue
    fi

    echo "Light check passed. Running full consumer smoke test..."
    if "$repo_root/scripts/check-android-maven-consumer.sh" "$VERSION"; then
        echo "Maven Central verification succeeded!"
        exit 0
    fi

    echo "Full check failed. Waiting $RETRY_INTERVAL seconds..."
    sleep "$RETRY_INTERVAL"
done

echo "Maven Central verification failed after $MAX_RETRIES retries."
exit 1
