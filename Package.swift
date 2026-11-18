// swift-tools-version: 6.0
import PackageDescription

// The binary target downloads the static XCFramework from a GitHub Release
// asset. At a version tag, the release pipeline has written the URL and
// SHA-256 checksum of that release's archive. On main the pipeline never
// updates them, so main points at an older release whose binary may not
// match the newer Swift sources; depend on a release tag, not on main
// (see docs/releasing.md: "Why CI creates the tag"). Until the first
// NativeOIDC release, main still points at an AppAuth-Rust archive, whose
// module is appauth_rustFFI, so main does not build through SPM.
// The source target carries the UniFFI-generated Swift API (do not edit;
// CI verifies it matches the current Rust source) and the platform
// adapters. The generated API is not Swift 6 strict-concurrency clean, so
// the target is pinned to Swift 5 language mode.
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
            url: "https://github.com/ProjectFlora/AppAuth-Rust/releases/download/v0.4.0/AppAuthRust-Apple-0.4.0.zip",
            checksum: "a298fca36ea9c06f515dc6aa69cd366dd905607d06aac8b29f22abf7df352d95"
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
