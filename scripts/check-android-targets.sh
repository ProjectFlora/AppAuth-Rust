#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if (( $# > 1 )); then
    echo "Usage: $0 [jniLibs output directory]" >&2
    exit 2
fi

ndk_home=${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to the Android NDK directory}
api_level=${ANDROID_API_LEVEL:-34}
output_dir=${1:-}

if [[ ! "$api_level" =~ ^[1-9][0-9]*$ ]]; then
    echo "ANDROID_API_LEVEL must be a positive integer" >&2
    exit 2
fi

case "$(uname -s)" in
    Linux) host_tag=linux-x86_64 ;;
    Darwin)
        if [[ -d "$ndk_home/toolchains/llvm/prebuilt/darwin-arm64" ]]; then
            host_tag=darwin-arm64
        elif [[ -d "$ndk_home/toolchains/llvm/prebuilt/darwin-x86_64" ]]; then
            host_tag=darwin-x86_64
        else
            echo "Android NDK does not include a supported macOS host toolchain" >&2
            exit 1
        fi
        ;;
    *)
        echo "Android NDK builds are supported on Linux x86_64 and macOS" >&2
        exit 1
        ;;
esac

toolchain="$ndk_home/toolchains/llvm/prebuilt/$host_tag/bin"

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
    cargo build --locked --release --lib --target "$target"

    if [[ -n "$output_dir" ]]; then
        case "$target" in
            aarch64-linux-android) abi=arm64-v8a ;;
            x86_64-linux-android) abi=x86_64 ;;
        esac
        abi_dir="$output_dir/$abi"
        mkdir -p "$abi_dir"
        cp "target/$target/release/libappauth_rust.so" "$abi_dir/libappauth_rust.so"
    fi
done
