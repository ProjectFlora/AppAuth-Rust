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
# therefore keeps the binary target last committed to it by hand while the
# Cargo version moves forward with every release preparation pull request,
# so the manifest falls further behind with each release unless updated.
# The manifest version may lag the Cargo version by any number of releases
# but must never lead it (a leading URL would point at a release that does
# not exist yet).
#
# Releases up to 0.6.0 were published while the repository was named
# ProjectFlora/AppAuth-Rust and their Apple archives AppAuthRust-Apple-*.zip
# (Issue #146). Their assets keep that URL, which GitHub redirects after the
# rename, so the check also accepts it for those releases whatever the
# current repository name is, and expects the former archive name for them.
#
# On main the binary target is updated manually in release preparation PRs.
# Once main catches up to a prior release (e.g., v0.6.x), these legacy URL
# acceptances will no longer be needed but are retained for safety until then.
# Usage: scripts/check-spm-manifest.sh

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if [[ ! -f Package.swift ]]; then
    echo "Package.swift not found: $repo_root" >&2
    exit 1
fi

# Canonical repository URL for the release asset: CI provides the
# repository; local runs fall back to the origin remote. The remote may
# use any form git accepts for this repository — https, scp-style SSH
# (git@github.com:OWNER/REPO) or ssh:// — with or without a .git suffix;
# the two SSH forms normalize to the https form CI derives.
if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    repo_url="https://github.com/$GITHUB_REPOSITORY"
else
    remote_url=$(git remote get-url origin)
    case "$remote_url" in
        https://github.com/*)
            repo_url="${remote_url%.git}"
            ;;
        git@github.com:*)
            repo_url="https://github.com/${remote_url#git@github.com:}"
            repo_url="${repo_url%.git}"
            ;;
        ssh://git@github.com/*)
            repo_url="https://github.com/${remote_url#ssh://git@github.com/}"
            repo_url="${repo_url%.git}"
            ;;
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

needle = 'name: "NativeOIDCBinary",'
if needle not in manifest:
    sys.exit("Package.swift is missing the NativeOIDCBinary binary target")
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
# canonical asset name for that release of this repository, or the URL a
# release published under the former repository name was given.
LEGACY_REPO_URL = "https://github.com/ProjectFlora/AppAuth-Rust"
LEGACY_LAST_VERSION = "0.6.0"


def asset_prefix(version):
    if semver(version) <= semver(LEGACY_LAST_VERSION):
        return "AppAuthRust-Apple"
    return "NativeOIDC-Apple"


def match_release_url(base):
    return re.fullmatch(
        rf"{re.escape(base)}/releases/download/v(\d+\.\d+\.\d+)"
        rf"/(AppAuthRust-Apple|NativeOIDC-Apple)-(\d+\.\d+\.\d+)\.zip",
        url,
    )


url_match = match_release_url(repo_url)
if not url_match:
    url_match = match_release_url(LEGACY_REPO_URL)
    if url_match and semver(url_match.group(1)) > semver(LEGACY_LAST_VERSION):
        sys.exit(
            f"Package.swift binary target URL uses the former repository name "
            f"for release {url_match.group(1)}, but only releases up to "
            f"{LEGACY_LAST_VERSION} were published under it: {url!r} (expected "
            f"{repo_url!r}/releases/download/v<version>/...)"
        )
if not url_match:
    sys.exit(
        f"Package.swift binary target URL is not a canonical release asset: "
        f"{url!r} (expected {repo_url!r}/releases/download/v<version>/"
        f"NativeOIDC-Apple-<version>.zip; revert the binary target to its last "
        f"canonical value; a release writes new ones only at its tag)"
    )
manifest_version = url_match.group(1)
if manifest_version != url_match.group(3):
    sys.exit(
        f"Package.swift binary target URL version {manifest_version!r} does not "
        f"match its asset name version {url_match.group(3)!r}"
    )
if url_match.group(2) != asset_prefix(manifest_version):
    sys.exit(
        f"Package.swift binary target URL names release {manifest_version}'s "
        f"archive {url_match.group(2)}-{manifest_version}.zip, but that "
        f"release's archive is {asset_prefix(manifest_version)}-"
        f"{manifest_version}.zip"
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
    f"{url_match.group(2)}-{manifest_version}.zip, checksum {checksum}{lag})"
)
PY
