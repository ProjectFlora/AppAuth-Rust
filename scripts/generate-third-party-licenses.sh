#!/usr/bin/env bash
# Writes THIRD_PARTY_LICENSES.txt, the license notices for the crates linked
# into the release libraries, from Cargo.lock with cargo-about (about.toml,
# about.hbs). Every release package ships it next to LICENSE.
#
# The cargo-about version is pinned so the same Cargo.lock always gives the
# same file; CI installs exactly this version. The run is offline, so the
# license texts come only from the crates in Cargo.lock, never from the
# network.
set -euo pipefail

cargo_about_version=0.9.3

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

output=${1:-target/licenses/THIRD_PARTY_LICENSES.txt}

if ! installed=$(cargo about --version 2>/dev/null); then
    echo "cargo-about is not installed; install it with:" >&2
    echo "  cargo install --locked --features cli cargo-about@$cargo_about_version" >&2
    exit 1
fi
if [[ "$installed" != "cargo-about $cargo_about_version" ]]; then
    echo "cargo-about $cargo_about_version is required, found: $installed" >&2
    exit 1
fi

mkdir -p "$(dirname -- "$output")"
cargo fetch --locked
cargo about generate --locked --offline --fail -c about.toml -o "$output" about.hbs
