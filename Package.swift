// swift-tools-version: 6.0
import PackageDescription

// The binary target downloads the static XCFramework from a GitHub Release
// asset. At a version tag, the release pipeline has written the URL and
// SHA-256 checksum of that release's archive. On main the pipeline never
// updates them, so main points at an older release whose binary may not
// match the newer Swift sources; depend on a release tag, not on main
// (see docs/releasing.md: "Why CI creates the tag"). The source target
// carries the UniFFI-generated Swift API (do not edit; CI verifies it
// matches the current Rust source) and the platform adapters. The generated
// API is not Swift 6 strict-concurrency clean, so the target is pinned to
// Swift 5 language mode.
let package = Package(
    name: "NativeOIDC",
    platforms: [
        .iOS(.v18),
        .macOS(.v15),
    ],
    products: [
        .library(
            name: "NativeOIDC",
            targets: ["NativeOIDC"]
        ),
    ],
    targets: [
        .binaryTarget(
            name: "NativeOIDCBinary",
            url: "https://github.com/ProjectFlora/NativeOIDC/releases/download/v0.7.0/NativeOIDC-Apple-0.7.0.zip",
            checksum: "185e099716ea5a7f74c91d7f82e2036d6ade0d33f759c079b15635d49777d127"
        ),
        .target(
            name: "NativeOIDC",
            dependencies: ["NativeOIDCBinary"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // The repository root's `tests/` directory belongs to the Rust
        // integration tests, so the Swift tests live in `SwiftTests/` to
        // avoid a case-insensitive path collision.
        .testTarget(
            name: "NativeOIDCTests",
            dependencies: ["NativeOIDC"],
            path: "SwiftTests/NativeOIDCTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
