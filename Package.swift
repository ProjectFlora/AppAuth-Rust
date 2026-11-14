// swift-tools-version: 6.0
import PackageDescription

// The binary target downloads the static XCFramework from the GitHub Release
// asset for the release this tag was published from; the release pipeline
// keeps its URL and SHA-256 checksum in sync with the published archive.
// The source target carries the UniFFI-generated Swift API (do not edit;
// CI verifies it matches the current Rust source) and the platform
// adapters. The generated API is not Swift 6 strict-concurrency clean, so
// the target is pinned to Swift 5 language mode.
let package = Package(
    name: "AppAuthRust",
    platforms: [
        .iOS(.v18),
        .macOS(.v15),
    ],
    products: [
        .library(
            name: "AppAuthRust",
            targets: ["AppAuthRust"]
        ),
    ],
    targets: [
        .binaryTarget(
            name: "AppAuthRustBinary",
            url: "https://github.com/ProjectFlora/AppAuth-Rust/releases/download/v0.5.0/AppAuthRust-Apple-0.5.0.zip",
            checksum: "31d5984f3fd641bd58805b74218f0f605fdae3a9a7f07ae3f425094aa9a24ef5"
        ),
        .target(
            name: "AppAuthRust",
            dependencies: ["AppAuthRustBinary"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // The repository root's `tests/` directory belongs to the Rust
        // integration tests, so the Swift tests live in `SwiftTests/` to
        // avoid a case-insensitive path collision.
        .testTarget(
            name: "AppAuthRustTests",
            dependencies: ["AppAuthRust"],
            path: "SwiftTests/AppAuthRustTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
