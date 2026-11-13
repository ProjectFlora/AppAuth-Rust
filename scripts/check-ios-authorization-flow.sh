#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

bundle_id=com.projectflora.appauth-rust.ios-flow-smoke
app_bundle="$repo_root/target/apple/ios-authorization-flow-smoke.app"
executable=AppAuthRustIOSFlowSmoke
generated="$repo_root/target/uniffi/swift"
xcframework="$repo_root/target/apple/release-package/AppAuthRust-Apple/AppAuthRust.xcframework"
simulator_slice="$xcframework/ios-arm64-simulator"
simulator_sdk=$(xcrun --sdk iphonesimulator --show-sdk-path)
provider_port_file="$repo_root/target/apple/ios-mock-provider.port"
provider_log="$repo_root/target/apple/ios-mock-provider.log"
provider_pid=""
booted_by_script=false

if [[ "$(uname -m)" != arm64 ]]; then
    echo "iOS simulator smoke test requires an arm64 Apple host" >&2
    exit 1
fi

if [[ ! -f "$simulator_slice/libappauth_rust.a" ]]; then
    echo "iOS simulator library is missing: $simulator_slice/libappauth_rust.a" >&2
    exit 1
fi

rm -rf "$app_bundle"
mkdir -p "$app_bundle"
cp native/apple/IOSAuthorizationFlowSmoke-Info.plist "$app_bundle/Info.plist"

xcrun --sdk iphonesimulator swiftc \
    -parse-as-library \
    -target arm64-apple-ios18.0-simulator \
    -sdk "$simulator_sdk" \
    -Xcc "-fmodule-map-file=$simulator_slice/Headers/module.modulemap" \
    -L "$simulator_slice" \
    -lappauth_rust \
    -framework AuthenticationServices \
    -framework Network \
    -framework Security \
    -framework UIKit \
    -o "$app_bundle/$executable" \
    "$generated/appauth_rust.swift" \
    Sources/AppAuthRust/IOSAuthorizationAdapter.swift \
    native/apple/IOSAuthorizationFlowSmoke.swift \
    Sources/AppAuthRust/URLSessionNativeHttpTransport.swift

codesign --force --sign - --timestamp=none "$app_bundle"

simulator_selection=$(
    xcrun simctl list devices available -j |
        python3 scripts/select_ios_simulator.py "${IOS_SIMULATOR_MAJOR_VERSION:-}"
)
IFS=$'\t' read -r simulator_id simulator_state simulator_runtime <<< "$simulator_selection"
echo "iOS flow simulator: $simulator_id ($simulator_runtime; $simulator_state)"
sw_vers
xcodebuild -version
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    echo "iOS authorization: $simulator_runtime on $(uname -m), simulator $simulator_id" >> "$GITHUB_STEP_SUMMARY"
fi
if [[ "$simulator_state" != Booted ]]; then
    xcrun simctl boot "$simulator_id"
    booted_by_script=true
fi

cleanup() {
    xcrun simctl terminate "$simulator_id" "$bundle_id" >/dev/null 2>&1 || true
    if [[ -n "$provider_pid" ]]; then
        kill "$provider_pid" >/dev/null 2>&1 || true
        wait "$provider_pid" 2>/dev/null || true
    fi
    if [[ "$booted_by_script" == true ]]; then
        xcrun simctl shutdown "$simulator_id" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

xcrun simctl bootstatus "$simulator_id" -b
xcrun simctl uninstall "$simulator_id" "$bundle_id" >/dev/null 2>&1 || true
rm -f "$provider_port_file"
python3 scripts/ios-mock-oauth-provider.py --port-file "$provider_port_file" \
    > "$provider_log" 2>&1 &
provider_pid=$!
for ((attempt = 0; attempt < 600; attempt++)); do
    if [[ -s "$provider_port_file" ]]; then
        break
    fi
    if ! kill -0 "$provider_pid" 2>/dev/null; then
        cat "$provider_log" >&2
        echo "mock OAuth provider exited before becoming ready" >&2
        exit 1
    fi
    sleep 0.1
done
if [[ ! -s "$provider_port_file" ]]; then
    cat "$provider_log" >&2
    echo "mock OAuth provider did not start" >&2
    exit 1
fi
provider_port=$(<"$provider_port_file")
xcrun simctl install "$simulator_id" "$app_bundle"
xcrun simctl launch "$simulator_id" "$bundle_id" --oauth-provider-port "$provider_port"

data_container=$(xcrun simctl get_app_container "$simulator_id" "$bundle_id" data)
result_file="$data_container/Documents/authorization-flow-result"
for ((attempt = 0; attempt < 90; attempt++)); do
    if [[ -f "$result_file" ]]; then
        result=$(<"$result_file")
        if [[ "$result" == success ]]; then
            echo "iOS ASWebAuthenticationSession mock-provider flow passed"
            exit 0
        fi
        echo "iOS authorization flow failed: $result" >&2
        exit 1
    fi
    sleep 2
done

xcrun simctl spawn "$simulator_id" log show \
    --last 3m \
    --style compact \
    --predicate "process == \"$executable\"" |
    tail -n 40 || true
cat "$provider_log" >&2
echo "timed out waiting for iOS authorization flow result" >&2
exit 1
