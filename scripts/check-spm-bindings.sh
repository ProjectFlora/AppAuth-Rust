#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

# The SPM package ships the UniFFI-generated Swift API as a checked-in source
# file (SPM source targets must live inside the package checkout). Regenerate
# the bindings and require the checked-in copy to match the generated output
# byte for byte, so the file cannot drift from the Rust API it wraps.
# Binding generation is host-independent, so this check runs on any CI host.
output_dir=target/uniffi
checked_in=Sources/AppAuthRust/appauth_rust.swift

if [[ ! -f "$checked_in" ]]; then
    echo "Missing checked-in Swift bindings: $checked_in" >&2
    exit 1
fi

scripts/generate-bindings.sh "$output_dir"

generated="$output_dir/swift/appauth_rust.swift"
if ! diff -u "$generated" "$checked_in"; then
    cat >&2 <<EOF
Checked-in Swift bindings differ from the generated bindings.
Regenerate them with:
  scripts/generate-bindings.sh "$output_dir"
  cp "$generated" "$checked_in"
EOF
    exit 1
fi

echo "Checked-in Swift bindings match the generated output"
