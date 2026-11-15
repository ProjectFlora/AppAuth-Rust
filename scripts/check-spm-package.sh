#!/usr/bin/env bash
set -euo pipefail

# Validate the in-tree Swift package against a locally built release archive.
# The committed manifest's binary target points at a published GitHub Release
# zip; a path-based binary target needs no checksum, so for validation the
# script copies the package to a temporary directory, rewrites that copy's
# binary target to the supplied local archive, then builds the copy for the
# macOS host, runs its tests, and builds it for the iOS simulator
# destination. Nothing inside the repository is written, so an unclean exit
# (SIGKILL, crash, power loss) cannot leave a modified Package.swift or a
# backup file behind in the working tree (Issue #102).
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

if [[ ! -f "$archive" ]]; then
    echo "Release archive not found: $archive" >&2
    exit 1
fi

# SPM requires a local binary target path inside the package root, and the
# committed manifest must never be rewritten in place: an unclean exit would
# strand a path-based Package.swift and a .orig backup in the working tree.
# The manifest, the source and test trees, and the archive are therefore
# copied to a temporary package, which is validated and removed on exit. A
# SIGKILL can leave the temporary directory behind in the system temporary
# directory, but never anything in the repository.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp Package.swift "$work/"
cp -R Sources "$work/"
cp -R SwiftTests "$work/"
cp "$archive" "$work/$(basename -- "$archive")"
cd "$work"

# Swap the binary target's release URL and checksum for the local archive.
# The archive was copied to the package root, so its path is its basename.
python3 - "$(basename -- "$archive")" Package.swift <<'PY'
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
swift package dump-package | grep -qF "$(basename -- "$archive")"

echo "Building Swift package for the macOS host"
swift build

echo "Running Swift package tests"
swift test

echo "Building Swift package for the iOS simulator destination"
xcodebuild \
    -scheme AppAuthRust \
    -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath .derived \
    build

echo "Swift package validation passed"
