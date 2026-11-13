#!/usr/bin/env bash
set -euo pipefail

# Validate the in-tree Swift package against a locally built release archive.
# The committed manifest's binary target points at a published GitHub Release
# zip; for validation this script rewrites it to the supplied local path (a
# path-based binary target needs no checksum), then builds the package for the
# macOS host, runs its tests, and builds it for the iOS simulator
# destination. The original manifest is restored when the script exits.
#
# Usage: scripts/check-spm-package.sh <AppAuthRust-Apple-<version>.zip>

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <AppAuthRust-Apple-<version>.zip>" >&2
    exit 2
fi

if [[ "$(uname -s)" != Darwin ]]; then
    echo "Swift package validation requires macOS and Xcode" >&2
    exit 1
fi

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

archive=$(cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")
manifest=Package.swift

if [[ ! -f "$archive" ]]; then
    echo "Release archive not found: $archive" >&2
    exit 1
fi

# SPM requires a local binary target path relative to the package root.
case "$archive" in
    "$repo_root"/*) rel_archive=${archive#"$repo_root"/} ;;
    *)
        echo "Archive must be inside the package root: $archive" >&2
        exit 1
        ;;
esac

cp "$manifest" "$manifest.orig"
trap 'mv -f "$manifest.orig" "$manifest"' EXIT

# Swap the binary target's release URL and checksum for the local archive.
python3 - "$rel_archive" "$manifest" <<'PY'
import pathlib
import re
import sys

archive, manifest = sys.argv[1], sys.argv[2]
text = pathlib.Path(manifest).read_text()
needle = 'name: "AppAuthRustBinary",'
if needle not in text:
    sys.exit(f"refusing to rewrite unrecognized manifest: {manifest}")
binary_block = text.split(needle, 1)[1].split(")", 1)[0]
if "url:" not in binary_block or "path:" in binary_block:
    sys.exit(f"refusing to rewrite unrecognized manifest: {manifest}")
# Strip the url/checksum lines only inside this binary target block, so any
# other remote binary target in the manifest is left untouched.
block = re.sub(r'\n[ \t]+url: "[^"]+",', "", binary_block)
block = re.sub(r'\n[ \t]+checksum: "[^"]+"', "", block)
text = text.replace(
    needle + binary_block,
    f'{needle}\n            path: "{archive}"' + block,
    1)
pathlib.Path(manifest).write_text(text)
PY

# Prove the rewrite produced a well-formed path-based binary target.
swift package dump-package | grep -qF "$(basename "$archive")"

echo "Building Swift package for the macOS host"
swift build

echo "Running Swift package tests"
swift test

echo "Building Swift package for the iOS simulator destination"
xcodebuild \
    -scheme AppAuthRust \
    -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath target/apple/spm-derived \
    build

echo "Swift package validation passed"
