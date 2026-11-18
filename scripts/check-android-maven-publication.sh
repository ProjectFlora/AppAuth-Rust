#!/usr/bin/env bash
# Publishes the Android library to a throwaway local Maven repository and
# checks the files Maven Central requires: the AAR with both Rust ABIs, a POM
# with complete metadata and the transitive dependencies, and the sources and
# javadoc jars. Signatures are checked when signing is configured.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version>" >&2
    exit 2
fi

version=$1
repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
local_repo=$(mktemp -d)
trap 'rm -rf "$local_repo"' EXIT

"$repo_root/native/android/gradlew" -p "$repo_root/native/android" \
    publishToMavenLocal -PreleaseVersion="$version" -Dmaven.repo.local="$local_repo"

dir="$local_repo/net/project-flora/nativeoidc/native-oidc-android/$version"
base="$dir/native-oidc-android-$version"
for file in "$base.aar" "$base.pom" "$base.module" "$base-sources.jar" "$base-javadoc.jar"; do
    test -s "$file" || { echo "missing $file" >&2; ls -l "$dir" >&2; exit 1; }
done

unzip -Z1 "$base.aar" | grep -Fx jni/arm64-v8a/libnative_oidc.so
unzip -Z1 "$base.aar" | grep -Fx jni/x86_64/libnative_oidc.so
# The license notices are java resources, so they live in classes.jar.
unzip -p "$base.aar" classes.jar > "$local_repo/classes.jar"
unzip -Z1 "$local_repo/classes.jar" | grep -Fx META-INF/native-oidc/LICENSE
unzip -Z1 "$local_repo/classes.jar" | grep -Fx META-INF/native-oidc/THIRD_PARTY_LICENSES.txt
unzip -Z1 "$local_repo/classes.jar" | grep -Fx META-INF/native-oidc/RUST_STANDARD_LIBRARY_COPYRIGHT.html
unzip -Z1 "$base-sources.jar" | grep -E '(^|/)uniffi/native_oidc/native_oidc\.kt$'
unzip -Z1 "$base-sources.jar" | grep -E '(^|/)net/projectflora/nativeoidc/AndroidAuthorizationAdapter\.kt$'

pom="$base.pom"
grep -F '<groupId>net.project-flora.nativeoidc</groupId>' "$pom"
grep -F "<version>$version</version>" "$pom"
grep -F '<packaging>aar</packaging>' "$pom"
for element in name description url licenses developers scm; do
    grep -q "<$element>" "$pom" || { echo "POM lacks <$element>" >&2; exit 1; }
done
# jna must stay an AAR-typed dependency so consumers get its native libraries.
grep -A4 -F '<artifactId>jna</artifactId>' "$pom" | grep -F '<type>aar</type>'
grep -F '<artifactId>kotlinx-coroutines-android</artifactId>' "$pom"
grep -F '<artifactId>browser</artifactId>' "$pom"

if [[ -n "${ORG_GRADLE_PROJECT_signingInMemoryKey:-}" ]]; then
    for file in "$base.aar" "$base.pom" "$base.module" "$base-sources.jar" "$base-javadoc.jar"; do
        test -s "$file.asc" || { echo "missing signature $file.asc" >&2; exit 1; }
    done
fi

echo "Maven publication for $version is complete"
