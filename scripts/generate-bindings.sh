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
#   - Cargo.toml (the uniffi version, the uniffi-cli feature, the bin target)
#   - Cargo.lock (pins the uniffi version and every dependency)
#   - uniffi-bindgen.rs (the generator entry point)
#   - this script (its generation options: languages and output layout)
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
        shasum -a 256 Cargo.toml Cargo.lock uniffi-bindgen.rs scripts/generate-bindings.sh
        rustc -vV
    } | shasum -a 256 | awk '{print $1}'
}

fingerprint_file="$output_dir/.uniffi-fingerprint"
fingerprint="$(compute_fingerprint)"

# Every output a consumer expects must be present before reuse may skip a
# generation. If any of these was deleted (Kotlin binding, Swift FFI header,
# or the host library that the Apple smoke test links against), the fingerprint
# alone would wrongly allow reuse, so each is checked explicitly.
up_to_date() {
    [[ -f "$fingerprint_file" ]] || return 1
    [[ "$(cat "$fingerprint_file")" == "$fingerprint" ]] || return 1
    local f
    for f in \
        "$output_dir/swift/native_oidc.swift" \
        "$output_dir/swift/native_oidcFFI.h" \
        "$output_dir/swift/native_oidcFFI.modulemap"; do
        [[ -f "$f" ]] || return 1
    done
    # The Kotlin tree's file names are uniffi's to choose, so require the tree
    # to contain at least one generated source rather than a fixed name.
    [[ -n "$(find "$output_dir/kotlin" -name '*.kt' -print -quit 2>/dev/null)" ]] || return 1
    # The host library: check-apple-adapters.sh links its smoke test against it.
    [[ -f "$library" ]] || return 1
    return 0
}

regenerate() {
    # Drop the marker before touching the outputs: a regeneration that fails
    # partway (say the Kotlin pass after the Swift one) must not leave a stale
    # fingerprint that a later run would accept along with partial outputs. The
    # marker is recreated only after every generation step has succeeded.
    rm -f "$fingerprint_file"
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
    mkdir -p "$output_dir"
    printf '%s\n' "$fingerprint" > "$fingerprint_file"
}

if [[ "$force" == "--force" || "$force" == "--regenerate" ]]; then
    echo "UniFFI bindings: forcing regeneration into $output_dir (fingerprint $fingerprint)"
    regenerate
elif up_to_date; then
    echo "UniFFI bindings: reusing existing output in $output_dir (fingerprint $fingerprint matches; all outputs present; skipping rebuild)"
else
    echo "UniFFI bindings: generating into $output_dir (fingerprint $fingerprint)"
    regenerate
fi
