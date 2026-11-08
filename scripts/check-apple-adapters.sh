#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

output_dir=target/uniffi
scripts/generate-bindings.sh "$output_dir"
xcrun swift-format lint --strict \
    native/apple/IOSAuthorizationAdapter.swift \
    native/apple/MacOSAuthorizationAdapter.swift \
    native/apple/URLSessionNativeHttpTransport.swift \
    native/apple/MacOSLoopbackListenerSmoke.swift

swift_file="$output_dir/swift/appauth_rust.swift"
module_map="$output_dir/swift/appauth_rustFFI.modulemap"
swiftc \
    -target arm64-apple-ios18.0 \
    -sdk "$(xcrun --sdk iphoneos --show-sdk-path)" \
    -Xcc "-fmodule-map-file=$module_map" \
    -typecheck \
    "$swift_file" \
    native/apple/IOSAuthorizationAdapter.swift \
    native/apple/MacOSAuthorizationAdapter.swift \
    native/apple/URLSessionNativeHttpTransport.swift

swiftc \
    -target arm64-apple-macosx15.0 \
    -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
    -Xcc "-fmodule-map-file=$module_map" \
    -typecheck \
    "$swift_file" \
    native/apple/IOSAuthorizationAdapter.swift \
    native/apple/MacOSAuthorizationAdapter.swift \
    native/apple/URLSessionNativeHttpTransport.swift

mkdir -p target/apple
case "$(uname -m)" in
    arm64) host_macos_target=arm64-apple-macosx15.0 ;;
    x86_64) host_macos_target=x86_64-apple-macosx15.0 ;;
    *)
        echo "unsupported macOS architecture for loopback smoke test" >&2
        exit 1
        ;;
esac

swiftc \
    -parse-as-library \
    -target "$host_macos_target" \
    -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
    -Xcc "-fmodule-map-file=$module_map" \
    -L target/debug \
    -lappauth_rust \
    -Xlinker -rpath \
    -Xlinker "$repo_root/target/debug" \
    -o target/apple/mac-loopback-smoke \
    "$swift_file" \
    native/apple/MacOSAuthorizationAdapter.swift \
    native/apple/URLSessionNativeHttpTransport.swift \
    native/apple/MacOSLoopbackListenerSmoke.swift
target/apple/mac-loopback-smoke
