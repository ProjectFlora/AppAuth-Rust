#!/usr/bin/env python3
"""Point Package.swift's AppAuthRustBinary target at a published release archive.

The release workflow runs this after building and validating the Apple
archive, then commits the result as the release commit that the version tag
points to, so the tagged manifest carries the archive's URL and checksum.

Usage: update-package-swift.py --repository OWNER/NAME [--manifest PATH] VERSION CHECKSUM
"""
import argparse
import pathlib
import re
import sys

BINARY_TARGET = re.compile(
    r'(\.binaryTarget\(\s*name:\s*"AppAuthRustBinary",\s*url:\s*")[^"]+'
    r'("\s*,\s*checksum:\s*")[0-9a-f]+(")'
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent.parent / "Package.swift",
    )
    parser.add_argument("--repository", required=True, help="OWNER/NAME")
    parser.add_argument("version", help="MAJOR.MINOR.PATCH (no leading v)")
    parser.add_argument("checksum", help="SHA-256 of the Apple release archive")
    args = parser.parse_args()

    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        sys.exit(f"invalid version: {args.version!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", args.checksum):
        sys.exit(f"invalid SHA-256 checksum: {args.checksum!r}")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", args.repository):
        sys.exit(f"invalid repository: {args.repository!r}")

    url = (
        f"https://github.com/{args.repository}/releases/download/"
        f"v{args.version}/AppAuthRust-Apple-{args.version}.zip"
    )
    content = args.manifest.read_text(encoding="utf-8")
    updated, count = BINARY_TARGET.subn(
        lambda m: f"{m[1]}{url}{m[2]}{args.checksum}{m[3]}", content
    )
    if count != 1:
        sys.exit(
            f"expected one AppAuthRustBinary target in {args.manifest}, found {count}"
        )

    args.manifest.write_text(updated, encoding="utf-8")
    print(f"{args.manifest}: {url} ({args.checksum})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
