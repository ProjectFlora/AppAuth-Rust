#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version>" >&2
    exit 2
fi

VERSION="$1"
MAX_RETRIES=10
RETRY_INTERVAL=60 # seconds

for i in $(seq 1 $MAX_RETRIES); do
    if scripts/check-android-maven-consumer.sh "$VERSION"; then
        echo "Maven Central verification succeeded!"
        exit 0
    fi
    echo "Retry $i/$MAX_RETRIES: Maven Central artifact might not be available yet. Waiting $RETRY_INTERVAL seconds..."
    sleep "$RETRY_INTERVAL"
done

echo "Maven Central verification failed after $MAX_RETRIES retries."
exit 1
