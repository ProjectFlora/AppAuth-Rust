#!/usr/bin/env python3
"""Canonicalize an xcframework's Info.plist for deterministic packaging.

xcodebuild -create-xcframework writes AvailableLibraries in an order that
varies between runs (it follows its internal enumeration of the slices,
not the -input order), so the same package yields a different plist — and
therefore a different release archive — from run to run. The packaging
self-test in scripts/package-apple-xcframework.sh re-creates the framework
and requires identical canonicalized plists, so rewrite the plist
deterministically: the slice array is sorted by LibraryIdentifier and each
slice's architecture list is sorted, after validating that the slice set is
exactly the expected one.

Usage: scripts/normalize_xcframework_plist.py <xcframework/Info.plist>
"""
import plistlib
import sys

if len(sys.argv) != 2:
    sys.exit(f"usage: {sys.argv[0]} <xcframework/Info.plist>")

info_path = sys.argv[1]
with open(info_path, "rb") as info_file:
    info = plistlib.load(info_file)
libraries = info["AvailableLibraries"]

libraries.sort(key=lambda library: library["LibraryIdentifier"])
for library in libraries:
    library["SupportedArchitectures"] = sorted(
        library["SupportedArchitectures"]
    )

actual = {
    (
        library["SupportedPlatform"],
        library.get("SupportedPlatformVariant"),
        tuple(library["SupportedArchitectures"]),
    )
    for library in libraries
}
expected = {
    ("ios", None, ("arm64",)),
    ("ios", "simulator", ("arm64",)),
    ("macos", None, ("arm64", "x86_64")),
}
if actual != expected:
    sys.exit(f"unexpected XCFramework slices: {actual!r}")

with open(info_path, "wb") as info_file:
    plistlib.dump(info, info_file, fmt=plistlib.FMT_XML)
