#!/usr/bin/env bash
set -euo pipefail

# Install an iOS simulator runtime the hosted image does not ship, and make
# sure an available iPhone simulator exists for it. The release workflow
# builds with Xcode 26.x on macos-26, whose image ships only iOS 26.x
# runtimes, but still runs the iOS authorization flow on the iOS 18
# deployment minimum (Issue #135). Installing a runtime does not guarantee
# that CoreSimulator creates devices for it, so the script creates one from
# the runtime's own supported iPhone device types when none is available.
#
# Usage: scripts/install-ios-simulator-runtime.sh <iOS version, e.g. 18.6>

if [[ $# -ne 1 || ! "$1" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "Usage: $0 <iOS major.minor version, e.g. 18.6>" >&2
    exit 2
fi
version=$1

# Prints the identifier of the available iOS runtime for $version, then, when
# the runtime has no available iPhone, the identifier of a supported iPhone
# device type to create one with.
inspect_runtime() {
    python3 - "$version" \
        <(xcrun simctl list runtimes available -j) \
        <(xcrun simctl list devices available -j) <<'PY'
import json
import re
import sys

version, runtimes_path, devices_path = sys.argv[1:]
with open(runtimes_path) as runtimes_file:
    runtimes = json.load(runtimes_file)["runtimes"]
with open(devices_path) as devices_file:
    devices = json.load(devices_file)["devices"]
# Only generic runtimes, as in scripts/select_ios_simulator.py: device-specific
# ones (e.g. iOS-27-2-iPhone19-4) are not candidates for the iOS flow.
matches = [
    runtime for runtime in runtimes
    if re.fullmatch(r"com\.apple\.CoreSimulator\.SimRuntime\.iOS-\d+(?:-\d+)*",
                    runtime["identifier"])
    and (runtime["version"] == version or runtime["version"].startswith(version + "."))
]
if not matches:
    sys.exit(1)
runtime = matches[0]
print(runtime["identifier"])
if not any(device["name"].startswith("iPhone")
           for device in devices.get(runtime["identifier"], [])):
    iphones = [device_type for device_type in runtime.get("supportedDeviceTypes", [])
               if device_type.get("productFamily") == "iPhone"]
    if not iphones:
        sys.exit(f"iOS {version} runtime supports no iPhone device type")
    print(iphones[-1]["identifier"])
PY
}

if ! inspect_runtime > /dev/null; then
    echo "Installing iOS $version simulator runtime"
    # The download comes from Apple's CDN and can fail transiently.
    for attempt in 1 2 3; do
        if xcodebuild -downloadPlatform iOS -buildVersion "$version"; then
            break
        fi
        if [[ $attempt -eq 3 ]]; then
            echo "Failed to download the iOS $version simulator runtime" >&2
            exit 1
        fi
        sleep 30
    done
fi

if ! inspection=$(inspect_runtime); then
    echo "iOS $version simulator runtime is not available after installation" >&2
    xcrun simctl list runtimes >&2
    exit 1
fi
{ read -r runtime_id; read -r device_type || device_type=; } <<< "$inspection"
if [[ -n "$device_type" ]]; then
    echo "Creating an iPhone simulator ($device_type) for $runtime_id"
    xcrun simctl create "iPhone (iOS $version)" "$device_type" "$runtime_id"
fi
echo "iOS $version simulator runtime: $runtime_id"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    echo "Installed iOS simulator runtime: $runtime_id" >> "$GITHUB_STEP_SUMMARY"
fi
