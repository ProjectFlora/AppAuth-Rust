#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version>" >&2
    exit 2
fi

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
fixture="$repo_root/native/consumer-smoke/android"

"$repo_root/native/android/gradlew" -p "$fixture" -PnativeOidcVersion="$1" --refresh-dependencies connectedDebugAndroidTest
