#!/usr/bin/env bash
# Writes THIRD_PARTY_LICENSES.txt, the license notices for the code linked
# into the release libraries, and RUST_STANDARD_LIBRARY_COPYRIGHT.html next
# to it. Every release package ships both next to LICENSE.
#
# - The crates in Cargo.lock come from cargo-about (about.toml, about.hbs).
#   The cargo-about version is pinned so the same Cargo.lock always gives
#   the same list; CI installs exactly this version. The run is offline, so
#   the license texts come only from the crates in Cargo.lock.
# - The Rust standard library is not in Cargo.lock. Its notices come from
#   the active Rust toolchain, which must be the one that builds the
#   package: the license files of compiler-builtins and libm (the parts not
#   under MIT OR Apache-2.0) from its rust-src component, appended to the
#   text file, and its COPYRIGHT-library.html, copied as the HTML file.
set -euo pipefail

cargo_about_version=0.9.3

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

output=${1:-target/licenses/THIRD_PARTY_LICENSES.txt}
output_dir=$(dirname -- "$output")

if ! installed=$(cargo about --version 2>/dev/null); then
    echo "cargo-about is not installed; install it with:" >&2
    echo "  cargo install --locked --features cli cargo-about@$cargo_about_version" >&2
    exit 1
fi
if [[ "$installed" != "cargo-about $cargo_about_version" ]]; then
    echo "cargo-about $cargo_about_version is required, found: $installed" >&2
    exit 1
fi

rustup component add rust-src
# Forward slashes, so Git Bash on Windows reads the path too.
sysroot=$(rustc --print sysroot | tr '\\' '/')
std_copyright="$sysroot/share/doc/rust/COPYRIGHT-library.html"
std_sources="$sysroot/lib/rustlib/src/rust/library"
std_licenses=(compiler-builtins/LICENSE.txt compiler-builtins/libm/LICENSE.txt)
for file in "$std_copyright" "${std_licenses[@]/#/$std_sources/}"; do
    if [[ ! -s "$file" ]]; then
        echo "The Rust toolchain lacks $file" >&2
        exit 1
    fi
done

mkdir -p "$output_dir"
cargo fetch --locked
cargo about generate --locked --offline --fail -c about.toml -o "$output" about.hbs

rule=================================================================================
{
    printf '\n%s\nRust standard library: %s\n' "$rule" "$(rustc --version)"
    for file in "${std_licenses[@]}"; do
        printf '\n%s\nlibrary/%s\n\n' "$rule" "$file"
        cat "$std_sources/$file"
    done
} >> "$output"
cp "$std_copyright" "$output_dir/RUST_STANDARD_LIBRARY_COPYRIGHT.html"
