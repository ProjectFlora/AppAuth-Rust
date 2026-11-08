#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

ndk_home=${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to the Android NDK directory}
api_level=${ANDROID_API_LEVEL:-34}
toolchain="$ndk_home/toolchains/llvm/prebuilt/linux-x86_64/bin"

if [[ ! "$api_level" =~ ^[1-9][0-9]*$ ]]; then
    echo "ANDROID_API_LEVEL must be a positive integer" >&2
    exit 2
fi

if [[ ! -x "$toolchain/llvm-ar" ]]; then
    echo "Android NDK archiver not found or not executable: $toolchain/llvm-ar" >&2
    exit 1
fi

for target in aarch64-linux-android x86_64-linux-android; do
    case "$target" in
        aarch64-linux-android)
            linker="$toolchain/aarch64-linux-android${api_level}-clang"
            export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$linker"
            export CC_aarch64_linux_android="$linker"
            export AR_aarch64_linux_android="$toolchain/llvm-ar"
            ;;
        x86_64-linux-android)
            linker="$toolchain/x86_64-linux-android${api_level}-clang"
            export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$linker"
            export CC_x86_64_linux_android="$linker"
            export AR_x86_64_linux_android="$toolchain/llvm-ar"
            ;;
    esac

    if [[ ! -x "$linker" ]]; then
        echo "Android NDK linker not found or not executable: $linker" >&2
        exit 1
    fi

    rustup target add "$target"
    cargo build --locked --lib --target "$target"
done
