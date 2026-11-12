#!/usr/bin/env python3
"""Select an available iPhone for an iOS major or the latest installed runtime."""

import json
import re
import sys


def select_device(devices, major):
    latest = major == "latest"
    if major and not latest:
        if not major.isascii() or not major.isdecimal() or int(major) < 1:
            raise ValueError("IOS_SIMULATOR_MAJOR_VERSION must be a positive integer or latest")
    candidates = []
    for runtime, entries in devices.items():
        match = re.fullmatch(r"com\.apple\.CoreSimulator\.SimRuntime\.iOS-(\d+(?:-\d+)*)", runtime)
        if not match:
            continue
        version = tuple(int(part) for part in match[1].split("-"))
        if major and not latest and version[0] != int(major):
            continue
        for device in entries:
            if device.get("isAvailable") and device["name"].startswith("iPhone"):
                candidates.append((version, device["state"] != "Booted", device["name"],
                                   device["udid"], device["state"], runtime))
    if not candidates:
        raise ValueError(f"no available iPhone simulator for iOS {major or 'any'}")
    if latest:
        newest = max(candidate[0] for candidate in candidates)
        candidates = [candidate for candidate in candidates if candidate[0] == newest]
    # A fixed generation uses its oldest available runtime; latest uses its newest.
    _, _, _, udid, state, runtime = min(candidates)
    return udid, state, runtime


if __name__ == "__main__":
    try:
        print("\t".join(select_device(json.load(sys.stdin)["devices"], sys.argv[1])))
    except (ValueError, KeyError, IndexError) as error:
        sys.exit(str(error))
