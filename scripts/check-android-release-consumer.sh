#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <native-oidc-android-<version>.aar>" >&2
    exit 2
fi

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
archive=$(cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")
fixture="$repo_root/native/consumer-smoke/android"
library="$fixture/app/libs/native-oidc.aar"

notices=(META-INF/native-oidc/LICENSE META-INF/native-oidc/THIRD_PARTY_LICENSES.txt)
classes_jar=$(mktemp)

mkdir -p "$(dirname -- "$library")"
trap 'rm -f "$library" "$classes_jar"' EXIT

# The AAR carries the license notices as java resources in classes.jar...
unzip -p "$archive" classes.jar > "$classes_jar"
for notice in "${notices[@]}"; do
    unzip -Z1 "$classes_jar" | grep -Fx "$notice"
done

cp "$archive" "$library"
"$repo_root/native/android/gradlew" -p "$fixture" connectedDebugAndroidTest

# ...and an app built against it keeps them under their own path.
apk="$fixture/app/build/outputs/apk/debug/app-debug.apk"
for notice in "${notices[@]}"; do
    unzip -Z1 "$apk" | grep -Fx "$notice"
done
