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
            url: "https://github.com/ProjectFlora/NativeOIDC/releases/download/v0.7.1/NativeOIDC-Apple-0.7.1.zip",
            checksum: "6dc979ff61e855e632fba6e57c7f6aa4fa5cad76ab07e207088393fec130f46d"
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
