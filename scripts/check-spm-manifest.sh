#!/usr/bin/env bash
set -euo pipefail

# Check that the committed Swift package manifest is consistent with the
# release state. At a version tag, the release workflow's spm_manifest job
# writes the binary target's URL and SHA-256 checksum
# (scripts/update-package-swift.py); on main the target is whatever was last
# committed there and the workflow never rewrites it. This check catches
# malformed or leading targets in pull requests.
#
# The release commit carries only Package.swift and is pushed as the version
# tag, never to main (see docs/releasing.md: "Why CI creates the tag"). Main
# therefore keeps the binary target last committed to it by hand
# while the Cargo version moves forward with every release preparation pull
# request, so the lag grows by one per release. The manifest version may lag
# the Cargo version by any number of releases but must never lead it (a
# leading URL would point at a release that does not exist yet).
#
# Usage: scripts/check-spm-manifest.sh

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if [[ ! -f Package.swift ]]; then
    echo "Package.swift not found: $repo_root" >&2
    exit 1
fi

# Canonical repository URL for the release asset: CI provides the
# repository; local runs fall back to the origin remote.
if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    repo_url="https://github.com/$GITHUB_REPOSITORY"
else
    remote_url=$(git remote get-url origin)
    case "$remote_url" in
        https://github.com/*) repo_url="${remote_url%.git}" ;;
        *)
            echo "Cannot derive the repository URL from origin remote: $remote_url" >&2
            exit 1
            ;;
    esac
fi

REPO_URL="$repo_url" python3 - <<'PY'
import os
import pathlib
import re
import sys

repo_url = os.environ["REPO_URL"]
manifest = pathlib.Path("Package.swift").read_text()
cargo_toml = pathlib.Path("Cargo.toml").read_text()


def semver(triple):
    return tuple(int(part) for part in triple.split("."))


package_match = re.search(
    r'(?m)^version = "([^"]+)"\s*$', cargo_toml.split("[dependencies]", 1)[0]
)
if not package_match:
    sys.exit("cannot locate the [package] version line in Cargo.toml")
cargo_version = package_match.group(1)
if not re.fullmatch(r"\d+\.\d+\.\d+", cargo_version):
    sys.exit(f"Cargo package version is not MAJOR.MINOR.PATCH: {cargo_version!r}")

needle = 'name: "AppAuthRustBinary",'
if needle not in manifest:
    sys.exit("Package.swift is missing the AppAuthRustBinary binary target")
binary_block = manifest.split(needle, 1)[1].split(")", 1)[0]
url_match = re.search(r'(?m)^[ \t]+url: "([^"]+)",', binary_block)
checksum_match = re.search(r'(?m)^[ \t]+checksum: "([^"]+)"', binary_block)
if not url_match or not checksum_match:
    sys.exit("Package.swift binary target is missing its url or checksum line")

url = url_match.group(1)
checksum = checksum_match.group(1)
if not re.fullmatch(r"[0-9a-f]{64}", checksum):
    sys.exit(f"Package.swift binary target checksum is not a SHA-256: {checksum}")

# The URL encodes the release the binary target points at: it must be the
# canonical asset name for that release of this repository.
url_match = re.fullmatch(
    rf"{re.escape(repo_url)}/releases/download/v(\d+\.\d+\.\d+)"
    rf"/AppAuthRust-Apple-(\d+\.\d+\.\d+)\.zip",
    url,
)
if not url_match:
    sys.exit(
        f"Package.swift binary target URL is not a canonical release asset: "
        f"{url!r} (expected {repo_url!r}/releases/download/v<version>/"
        f"AppAuthRust-Apple-<version>.zip; restore the binary target from "
        f"main instead of editing it by hand)"
    )
manifest_version = url_match.group(1)
if manifest_version != url_match.group(2):
    sys.exit(
        f"Package.swift binary target URL version {manifest_version!r} does not "
        f"match its asset name version {url_match.group(2)!r}"
    )
if semver(manifest_version) > semver(cargo_version):
    sys.exit(
        f"Package.swift binary target points at release {manifest_version} but "
        f"the Cargo version is {cargo_version}; the manifest may lag the Cargo "
        f"version (the release workflow never updates main's binary "
        f"target) but must not lead it"
    )

lag = (
    ""
    if manifest_version == cargo_version
    else f", lagging Cargo version {cargo_version} as expected on main"
)
print(
    f"Swift package manifest is consistent (binary target "
    f"AppAuthRust-Apple-{manifest_version}.zip, checksum {checksum}{lag})"
)
PY
