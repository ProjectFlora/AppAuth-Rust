#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

output_dir=${1:-target/uniffi}
force=${2:-}

case "$(uname -s)" in
    Darwin) library=target/debug/libnative_oidc.dylib ;;
    Linux) library=target/debug/libnative_oidc.so ;;
    MINGW*|MSYS*|CYGWIN*) library=target/debug/native_oidc.dll ;;
    *)
        echo "unsupported host for UniFFI metadata extraction" >&2
        exit 1
        ;;
esac

# The generated bindings are a pure function of the inputs below, so a run
# recorded under the same fingerprint produced identical output and can be
# reused instead of rebuilt:
#   - the Rust sources (the UniFFI API surface behind uniffi::setup_scaffolding!)
#   - Cargo.lock (pins the uniffi version and every dependency)
#   - the rustc version
# This lets scripts that run earlier in the same job (check-apple-adapters.sh)
# and later (package-apple-xcframework.sh) share one generation: the first
# call builds, the second reuses, instead of each rebuilding the host library
# and re-running uniffi-bindgen (Issue #176).
compute_fingerprint() {
    {
        find src -name '*.rs' -type f | LC_ALL=C sort | while IFS= read -r f; do
            shasum -a 256 "$f"
        done
        shasum -a 256 Cargo.lock
        rustc -vV
    } | shasum -a 256 | awk '{print $1}'
}

fingerprint_file="$output_dir/.uniffi-fingerprint"
fingerprint="$(compute_fingerprint)"

# Reuse is explicit, not silent: it only applies when a prior run was recorded
# under the current fingerprint and the files that run must have produced are
# actually present. A changed checkout (Rust source), Cargo.lock (uniffi
# version) or rustc changes the fingerprint, so stale generated output from an
# earlier toolchain or checkout is never reused silently -- it is regenerated.
up_to_date() {
    [[ -f "$fingerprint_file" ]] || return 1
    [[ "$(cat "$fingerprint_file")" == "$fingerprint" ]] || return 1
    [[ -f "$output_dir/swift/native_oidc.swift" ]] || return 1
    [[ -f "$output_dir/swift/native_oidcFFI.modulemap" ]] || return 1
    return 0
}

regenerate() {
    cargo build --locked --lib
    # The swift/ and kotlin/ subdirectories hold only generated bindings. Clear
    # them so files generated for an earlier module name (such as
    # uniffi/appauth_rust/ before the NativeOIDC rename) never survive alongside
    # the new ones: Gradle compiles the whole kotlin/ tree.
    rm -rf "$output_dir/swift" "$output_dir/kotlin"
    cargo run --locked --features uniffi-cli --bin uniffi-bindgen -- \
        generate --library "$library" --language swift --out-dir "$output_dir/swift"
    cargo run --locked --features uniffi-cli --bin uniffi-bindgen -- \
        generate --library "$library" --language kotlin --out-dir "$output_dir/kotlin"
    # Record the input fingerprint so a later run with identical inputs can
    # reuse the bindings instead of rebuilding.
    mkdir -p "$output_dir"
    printf '%s\n' "$fingerprint" > "$fingerprint_file"
}

if [[ "$force" == "--force" || "$force" == "--regenerate" ]]; then
    echo "UniFFI bindings: forcing regeneration into $output_dir (fingerprint $fingerprint)"
    regenerate
elif up_to_date; then
    echo "UniFFI bindings: reusing existing output in $output_dir (fingerprint $fingerprint matches; skipping rebuild)"
else
    echo "UniFFI bindings: generating into $output_dir (fingerprint $fingerprint)"
    regenerate
fi
