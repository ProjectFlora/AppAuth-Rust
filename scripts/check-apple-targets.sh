#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

export IPHONEOS_DEPLOYMENT_TARGET=18.0
export MACOSX_DEPLOYMENT_TARGET=15.0

for target in \
    aarch64-apple-ios \
    aarch64-apple-ios-sim \
    aarch64-apple-darwin \
    x86_64-apple-darwin; do
    rustup target add "$target"
    cargo build --locked --lib --target "$target"
done
