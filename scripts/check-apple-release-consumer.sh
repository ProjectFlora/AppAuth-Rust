#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <AppAuthRust-Apple-<version>.zip>" >&2
    exit 2
fi

if [[ "$(uname -s)" != Darwin ]]; then
    echo "Apple release consumer validation requires macOS and Xcode" >&2
    exit 1
fi

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
archive=$(cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")
fixture="$repo_root/native/consumer-smoke/apple"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

unzip -q "$archive" -d "$work_dir"
# ditto may include a parallel __MACOSX resource-fork tree with the same name.
# Only the actual package contains bindings and libraries.
package_root=$(find "$work_dir" -path "$work_dir/__MACOSX" -prune -o -type d -name AppAuthRust-Apple -print -quit)
if [[ -z "$package_root" ]]; then
    echo "Apple release archive does not contain AppAuthRust-Apple/" >&2
    exit 1
fi

framework_root="$package_root"
bindings="$package_root/Swift/appauth_rust.swift"
xcframework="$framework_root/AppAuthRust.xcframework"
if [[ ! -d "$xcframework" || ! -f "$bindings" ]]; then
    echo "Apple release archive is missing its XCFramework or Swift bindings" >&2
    exit 1
fi

case "$(uname -m)" in
    arm64) macos_target=arm64-apple-macosx15.0 ;;
    x86_64) macos_target=x86_64-apple-macosx15.0 ;;
    *) echo "unsupported macOS architecture: $(uname -m)" >&2; exit 1 ;;
esac

macos_slice=$(find "$xcframework" -maxdepth 1 -type d -name 'macos-*' -print -quit)
ios_simulator_slice=$(find "$xcframework" -maxdepth 1 -type d -name 'ios-*-simulator' -print -quit)
if [[ -z "$macos_slice" || -z "$ios_simulator_slice" ]]; then
    echo "Apple release XCFramework is missing macOS or iOS simulator slices" >&2
    exit 1
fi
macos_library=$(find "$macos_slice" -maxdepth 1 -name '*.a' -print -quit)
ios_simulator_library=$(find "$ios_simulator_slice" -maxdepth 1 -name '*.a' -print -quit)
if [[ -z "$macos_library" || -z "$ios_simulator_library" ]]; then
    echo "Apple release XCFramework is missing a static library" >&2
    exit 1
fi

xcrun swiftc \
    -target "$macos_target" \
    -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
    -Xcc "-fmodule-map-file=$macos_slice/Headers/module.modulemap" \
    "$bindings" "$fixture/ReleaseConsumerSmoke.swift" "$macos_library" \
    -o "$work_dir/apple-release-consumer"
"$work_dir/apple-release-consumer"

xcrun swiftc \
    -target arm64-apple-ios18.0-simulator \
    -sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" \
    -Xcc "-fmodule-map-file=$ios_simulator_slice/Headers/module.modulemap" \
    -emit-library \
    "$bindings" "$fixture/ReleaseConsumerLibrary.swift" "$ios_simulator_library" \
    -o "$work_dir/libAppleReleaseConsumer.dylib"
