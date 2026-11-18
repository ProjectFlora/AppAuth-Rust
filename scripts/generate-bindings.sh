#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

output_dir=${1:-target/uniffi}

case "$(uname -s)" in
    Darwin) library=target/debug/libnative_oidc.dylib ;;
    Linux) library=target/debug/libnative_oidc.so ;;
    MINGW*|MSYS*|CYGWIN*) library=target/debug/native_oidc.dll ;;
    *)
        echo "unsupported host for UniFFI metadata extraction" >&2
        exit 1
        ;;
esac

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
