#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <appauth-rust-android-<version>.aar>" >&2
    exit 2
fi

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
archive=$(cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")
fixture="$repo_root/native/consumer-smoke/android"
library="$fixture/app/libs/appauth-rust.aar"

mkdir -p "$(dirname -- "$library")"
trap 'rm -f "$library"' EXIT
cp "$archive" "$library"
"$repo_root/native/android/gradlew" -p "$fixture" connectedDebugAndroidTest
