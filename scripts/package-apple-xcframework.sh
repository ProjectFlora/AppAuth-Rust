#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if [[ "$(uname -s)" != Darwin ]]; then
    echo "Apple XCFramework packaging requires macOS and Xcode" >&2
    exit 1
fi

version=${1:-0.0.0-ci}
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$ ]]; then
    echo "Usage: $0 [version]" >&2
    exit 2
fi

case "$(uname -m)" in
    arm64) host_macos_target=arm64-apple-macosx15.0 ;;
    x86_64) host_macos_target=x86_64-apple-macosx15.0 ;;
    *)
        echo "unsupported macOS architecture for package smoke test" >&2
        exit 1
        ;;
esac

output_root="$repo_root/target/apple/release-package"
package_root="$output_root/AppAuthRust-Apple"
xcframework="$package_root/AppAuthRust.xcframework"
generated="$repo_root/target/uniffi"
headers="$output_root/headers"
macos_library="$repo_root/target/apple/libappauth_rust_macos.a"

if [[ -e "$package_root" ]]; then
    echo "Package output already exists: $package_root" >&2
    exit 1
fi

export IPHONEOS_DEPLOYMENT_TARGET=18.0
export MACOSX_DEPLOYMENT_TARGET=15.0

scripts/generate-bindings.sh "$generated"

for target in \
    aarch64-apple-ios \
    aarch64-apple-ios-sim \
    aarch64-apple-darwin \
    x86_64-apple-darwin; do
    rustup target add "$target"
    cargo build --locked --release --lib --target "$target"
done

mkdir -p "$repo_root/target/apple" "$package_root/Swift" "$headers"
# The Swift package sources (the UniFFI-generated API plus the platform
# adapters) ship in the archive so manual Xcode users get the same content as
# the Swift Package Manager target. The generated file is copied from the
# freshly generated output, which the SPM bindings check verifies matches the
# checked-in copy.
cp "$generated/swift/appauth_rust.swift" "$package_root/Swift/"
cp "$repo_root"/Sources/AppAuthRust/IOSAuthorizationAdapter.swift \
    "$repo_root"/Sources/AppAuthRust/MacOSAuthorizationAdapter.swift \
    "$repo_root"/Sources/AppAuthRust/URLSessionNativeHttpTransport.swift \
    "$package_root/Swift/"
cp "$repo_root/LICENSE" "$package_root/"
cp "$repo_root/docs/swift-xcframework.md" "$package_root/README.md"
cp "$generated/swift/appauth_rustFFI.h" "$headers/"
cp "$generated/swift/appauth_rustFFI.modulemap" "$headers/module.modulemap"

xcrun lipo -create \
    target/aarch64-apple-darwin/release/libappauth_rust.a \
    target/x86_64-apple-darwin/release/libappauth_rust.a \
    -output "$macos_library"

xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libappauth_rust.a \
    -headers "$headers" \
    -library target/aarch64-apple-ios-sim/release/libappauth_rust.a \
    -headers "$headers" \
    -library "$macos_library" \
    -headers "$headers" \
    -output "$xcframework"

python3 - "$xcframework/Info.plist" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as info_file:
    libraries = plistlib.load(info_file)["AvailableLibraries"]

actual = {
    (
        library["SupportedPlatform"],
        library.get("SupportedPlatformVariant"),
        tuple(sorted(library["SupportedArchitectures"])),
    )
    for library in libraries
}
expected = {
    ("ios", None, ("arm64",)),
    ("ios", "simulator", ("arm64",)),
    ("macos", None, ("arm64", "x86_64")),
}
if actual != expected:
    raise SystemExit(f"unexpected XCFramework slices: {actual!r}")
PY

xcrun swiftc \
    -parse-as-library \
    -target "$host_macos_target" \
    -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
    -Xcc "-fmodule-map-file=$headers/module.modulemap" \
    -L "$repo_root/target/apple" \
    -lappauth_rust_macos \
    -o "$repo_root/target/apple/mac-authorization-flow-smoke-static" \
    "$generated/swift/appauth_rust.swift" \
    "$repo_root/native/apple/MacOSMockOAuthProvider.swift" \
    "$repo_root/Sources/AppAuthRust/MacOSAuthorizationAdapter.swift" \
    "$repo_root/Sources/AppAuthRust/URLSessionNativeHttpTransport.swift" \
    "$repo_root/native/apple/MacOSAuthorizationFlowSmoke.swift"
"$repo_root/target/apple/mac-authorization-flow-smoke-static"
scripts/check-ios-authorization-flow.sh

ditto -c -k --sequesterRsrc --keepParent \
    "$package_root" \
    "$output_root/AppAuthRust-Apple-$version.zip"
