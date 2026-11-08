#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

output_dir=${1:-target/uniffi}

case "$(uname -s)" in
    Darwin) library=target/debug/libappauth_rust.dylib ;;
    Linux) library=target/debug/libappauth_rust.so ;;
    MINGW*|MSYS*|CYGWIN*) library=target/debug/appauth_rust.dll ;;
    *)
        echo "unsupported host for UniFFI metadata extraction" >&2
        exit 1
        ;;
esac

cargo build --locked --lib
cargo run --locked --features uniffi-cli --bin uniffi-bindgen -- \
    generate --library "$library" --language swift --out-dir "$output_dir/swift"
cargo run --locked --features uniffi-cli --bin uniffi-bindgen -- \
    generate --library "$library" --language kotlin --out-dir "$output_dir/kotlin"
