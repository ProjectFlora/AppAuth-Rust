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

# The slice inputs are shared by both create-xcframework calls below; the
# xcframework names derive from the libraries, so only -output differs.
xcframework_args=(
    -library target/aarch64-apple-ios/release/libappauth_rust.a
    -headers "$headers"
    -library target/aarch64-apple-ios-sim/release/libappauth_rust.a
    -headers "$headers"
    -library "$macos_library"
    -headers "$headers"
)

xcodebuild -create-xcframework \
    "${xcframework_args[@]}" \
    -output "$xcframework"

# xcodebuild writes AvailableLibraries in a run-varying order (its internal
# slice enumeration, not the input order), so the same package yields a
# different Info.plist — and therefore a different release archive — from
# run to run. The in-run determinism self-test below therefore creates the
# framework a second time, canonicalizes both plists
# (scripts/normalize_xcframework_plist.py: validate the slice set, sort the
# array and each architecture list, rewrite in a fixed format), and requires
# identical bytes before the archive embeds the framework.
scratch_xcframework="$output_root/AppAuthRust-Apple-scratch.xcframework"
xcodebuild -create-xcframework \
    "${xcframework_args[@]}" \
    -output "$scratch_xcframework"

python3 "$repo_root/scripts/normalize_xcframework_plist.py" \
    "$xcframework/Info.plist"
python3 "$repo_root/scripts/normalize_xcframework_plist.py" \
    "$scratch_xcframework/Info.plist"
if ! cmp -s "$xcframework/Info.plist" "$scratch_xcframework/Info.plist"; then
    echo "XCFramework Info.plist is not stable across create-xcframework runs (run-varying order survived canonicalization)" >&2
    exit 1
fi
rm -rf "$scratch_xcframework"

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

# The archive bytes must not depend on the build machine or on the file
# states `ditto` reads: the in-run determinism self-test below packages the
# same tree a second time and requires an identical SHA-256. Three layers
# enforce that:
#
# 1. Fixed timestamps. `ditto` records each file's modification time in the
#    zip DOS time fields and as atime + mtime words in the 0x5855 (UT)
#    extra field; unpinned build outputs would carry their build time.
#    `touch -t` pins both to 2026-01-01 00:00:00.
# 2. Empty attribute sets. `xattr -cr` drops extended attributes so `ditto`
#    does not embed build-machine metadata in the archive.
# 3. Post-zip normalization (scripts/normalize_zip.py). Two things escape
#    filesystem-level pinning. APFS advances atimes when `ditto` reads the
#    tree, so the UT atime word drifts between zips even though the files
#    were pinned; the normalizer rewrites every 0x5855 word to the pinned
#    mtime word. And the `com.apple.provenance` attribute cannot be removed
#    (`xattr -d` is a silent no-op), so `ditto` always emits a constant
#    `._*` AppleDouble sidecar per entry; the normalizer strips them.
#    `--sequesterRsrc` is deliberately omitted: the `__MACOSX/` shadow tree
#    it creates inside the archive is stamped with the zip run time.
#
# The timezone is fixed for the metadata and zip steps: `touch -t` interprets
# the pin in the local timezone and `ditto` derives the DOS time fields from
# it, so the same wall-clock pin would otherwise yield different archive
# bytes on machines in different time zones.
export TZ=UTC
xattr -cr "$package_root"
find "$package_root" -print0 | xargs -0 touch -t 202601010000.00

archive="$output_root/AppAuthRust-Apple-$version.zip"
ditto -c -k --keepParent "$package_root" "$archive"
python3 "$repo_root/scripts/normalize_zip.py" "$archive"

# The in-run determinism self-test: zip the same package a second time,
# normalize both, and demand identical hashes.
# (The raw double-ditto hashes would differ: the first zip's read of the
# tree advances file atimes, which the second zip records in the UT extra
# field; the normalizer is what makes the comparison meaningful.)
recheck="$output_root/AppAuthRust-Apple-$version-determinism.zip"
ditto -c -k --keepParent "$package_root" "$recheck"
python3 "$repo_root/scripts/normalize_zip.py" "$recheck"
first_hash=$(shasum -a 256 "$archive" | awk '{print $1}')
second_hash=$(shasum -a 256 "$recheck" | awk '{print $1}')
rm "$recheck"
if [[ "$first_hash" != "$second_hash" ]]; then
    echo "Apple release archive packaging is not deterministic: $first_hash != $second_hash" >&2
    exit 1
fi
echo "Apple release archive packaging is deterministic ($first_hash)"
