# Native distribution channels

This document records the evaluation of package distribution channels for the
native bindings, per [issue #44](https://github.com/ProjectFlora/AppAuth-Rust/issues/44).
It compares Maven Central, Swift Package Manager, Carthage, and the current
GitHub Releases channel, and records the per-platform decision with rationale.
Publishing and channel implementation are intentionally out of scope here and
are tracked as follow-up issues.

## Current state: GitHub Releases

All three native packages ship exclusively as versioned GitHub Release assets
with SHA-256 checksums, validated against minimal consumer fixtures before
publication (see [README.md](../README.md)). The release pipeline stops at
publication: published assets are immutable per release version and can be
re-validated on demand by manually running the "Published release consumer
validation" workflow against a published version.

Consumer onboarding is manual on every platform:

- **Apple:** add `AppAuthRust.xcframework` to the Xcode project with
  **Do Not Embed**, add the generated `Swift/appauth_rust.swift` file with
  target membership, set the minimum deployment version (iOS/iPadOS 18 or
  macOS 15), and verify the archive checksum. See
  [swift-xcframework.md](swift-xcframework.md).
- **Android:** declare the AAR as a local file dependency and separately
  declare its three transitive dependencies (`net.java.dev.jna:jna:5.12.0@aar`,
  `org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2`,
  `androidx.browser:browser:1.8.0`), then verify the checksum.
- **Windows:** extract the release zip and place the C ABI header, import
  library, and DLL by hand.

The Android case is the sharpest friction: a package manager consumer expects
one dependency line to bring the whole transitive closure, and the manual
file-based AAR defeats both version resolution and update workflows.

## Evaluation axes

The axes from issue #44:

1. **Public trust, signing, and versioning** — how a channel vouches for an
   artifact, and what its versioning rules are.
2. **Dependency resolution** — whether transitive dependencies arrive
   automatically and how consumers pin or override versions.
3. **Release automation** — work to add to the existing release pipeline
   (build, consumer validation, publication, checksums).
4. **Maintenance cost** — ongoing upkeep per release and over time.
5. **Consumer onboarding** — steps a new user takes to start using the library.

## Candidates

### Maven Central (Android)

Maven Central is the default repository for Gradle and Maven. Relevant
properties of the current (2026) Central Portal:

- A free account and a **namespace registration** tied to the source project
  (DNS TXT record or source-repository claim) are required before the first
  publication; registration has lead time.
- **Every published file must be GPG-signed**, and md5/sha1 checksums are
  required alongside.
- A complete POM is required: name, description, URL, license, developers,
  and source-control metadata.
- `packaging` `aar` is a valid packaging type.
- **Published versions are immutable.** A bad artifact cannot be replaced in
  place; the remedies are deprecating or retiring the version and publishing a
  new one.
- Versions must be plain SemVer-style identifiers; `-SNAPSHOT` builds are not
  accepted, which matches the release workflow's tag-only publication.

The main consumer win is dependency resolution: a hand-written or
`maven-publish`-generated POM declares `jna` (as an AAR-typed dependency),
`kotlinx-coroutines-android`, and `androidx.browser`, so a consumer writes a
single `implementation("com.projectflora.appauth:appauth-rust-android:0.4.0")`
line and the transitive closure arrives automatically. Version pinning,
upgrades, and overrides use ordinary Gradle mechanisms.

### Swift Package Manager (Apple)

SPM is the default package manager for Swift. For a prebuilt binary, the
supported shape is a **binary target** (a zip containing the XCFramework)
plus a **source target** containing the generated Swift bindings, which import
the FFI module declared in the XCFramework's module map. The binary target can
reference a URL (any hosted zip) with a SHA-256 checksum, or a local path.

The open technical questions — whether a static, unsigned XCFramework links
through a binary target, whether the generated Swift compiles against it, and
whether the existing release zip layout is accepted — were answered by
Spike A below. In short: yes, and the existing release zip is usable as-is.

### Carthage (Apple)

Carthage's latest release is 0.40.0 (September 2025) and its maintenance cadence
has slowed. Two integration routes exist for a prebuilt binary:

- **Source builds** compile the package on every consumer machine. For this
  repository that means a Rust toolchain, the correct target triples, and the
  Android NDK per developer machine — not a realistic expectation.
- **Binary specs** (since 0.38) map a version to a zip URL, so a prebuilt
  GitHub Release zip could be referenced without local Rust builds. Carthage
  compares Swift compiler versions between build and use and can reject
  prebuilt binaries it considers stale, which adds a failure mode to every
  Xcode upgrade.

The Carthage audience overlaps almost entirely with the SPM audience; a binary
spec adds a second Apple channel that serves users SPM already reaches, at a
per-release maintenance cost and with a declining tool.

### Continue GitHub Releases (all platforms)

The current channel costs zero additional infrastructure: the release pipeline
already builds, consumer-validates, and publishes the assets with checksums,
and the artifacts are immutable per version. It remains the primary channel
for Windows, where no native package manager applies to a C ABI package, and a
sensible fallback where a consumer cannot use a package manager.

## Technical spikes

Both spikes were run on 2026-11-13 in a scratch directory outside the
repository against the published **v0.4.0** assets (checksum-verified from
SHA256SUMS), with Swift 6.4.2 / Xcode 27.2, Gradle 8.13, and AGP 8.13.0.
Neither spike modified this repository.

### Spike A: SPM binary target with the static XCFramework

A minimal SPM package declared a binary target pointing at the release zip
plus a source target containing the generated `Swift/appauth_rust.swift`, and
an executable target that round-trips `FfiAuthenticationState` through the
FFI (`fromJson` / `toJson`) — a live FFI call with no network activity.
Five manifest/platform variants were built:

| Variant | Manifest | Result |
| --- | --- | --- |
| Slim zip (single XCFramework at zip root) via `path:`, macOS, tools 5.9 | zip extracted, slice selected, FFI module imported, static library linked; smoke ran and round-tripped | pass |
| Same, iOS simulator build | correct simulator slice linked into the executable | pass |
| Current release zip (wrapper directory + LICENSE/README/Swift extras) via `path:`, macOS | SPM accepts the layout; build and smoke run | pass |
| tools 6.0, no language-mode pin, macOS | build **fails**: the generated bindings are not Swift 6 strict-concurrency clean (`SendingClosureRisksDataRace` in the `rustCall` helpers) | fail |
| tools 6.0 + `.swiftLanguageMode(.v5)` on the source target | build and smoke run | pass |

Conclusions for the SPM channel:

- The static, unsigned XCFramework works through a binary target on both
  macOS and the iOS simulator; the FFI Clang module resolves from the
  module map inside the XCFramework, and the Rust static library links into
  the consumer binary.
- **The existing release zip needs no repackaging.** SPM tolerates a single
  wrapper directory at the zip root and ignores non-XCFramework entries, so a
  binary target can point directly at the current
  `AppAuthRust-Apple-<version>.zip` asset. A slimmer zip remains an optional
  optimization.
- The release binary's minimum OS versions are **iOS 18 / macOS 15**, both
  explicitly pinned in `scripts/package-apple-xcframework.sh` (`export
  IPHONEOS_DEPLOYMENT_TARGET=18.0` / `MACOSX_DEPLOYMENT_TARGET=15.0` before
  the `cargo build` calls). The v0.4.0 release slices confirm the pins
  (device 18.0, simulator 18.0, macOS 15.0); the Rust toolchain's implicit
  defaults (10.0 / 14.0 on the current MSRV toolchain) fall below the
  documented floor, so the explicit pins are load-bearing. The SPM manifest
  must declare platform minimums at least as high, matching the documented
  support range.
- The v0.4.0 generated Swift is not Swift 6 strict-concurrency clean. A
  production manifest pinned to Swift 5 language mode
  (`swiftLanguageMode(.v5)`) compiles correctly for consumers on any tools
  version; regenerating the bindings until they are Swift 6 clean is a
  follow-up item that the SPM issue must track.
- The manifest's binary target uses `url:` pointing at the immutable GitHub
  Release asset plus the SHA-256 checksum, so SPM performs no re-hosting of
  the binary; the checksum is already published in `SHA256SUMS`.

### Spike B: Maven POM with a minimal Gradle consumer

A hand-written POM — mirroring what `maven-publish` would generate from
`native/android/build.gradle.kts` — declared the release AAR with `aar`
packaging, the three api dependencies (`jna:5.12.0` with `aar` type,
`kotlinx-coroutines-android:1.10.2`, `androidx.browser:1.8.0`), and the
metadata fields Central requires (name, description, URL, license,
developers, SCM). It was published into a local file Maven repository next to
the v0.4.0 release AAR, and consumed by a minimal application whose only
relevant line is
`implementation("com.projectflora.appauth:appauth-rust-android:0.4.0")`, with
one Kotlin file importing `AndroidAuthorizationAdapter`.

Result: **pass.** `assembleDebug` completed end to end — manifest merge,
resource link, Kotlin compilation against the library, dexing, and packaging.
The built APK contains the AAR's `libappauth_rust.so` (arm64-v8a, x86_64)
alongside JNA's `libjnidispatch.so` for all seven ABIs the jna AAR ships.
The resolved runtime classpath confirms the whole transitive closure arriving
from that single declared dependency:

```text
+--- com.projectflora.appauth:appauth-rust-android:0.4.0
     +--- net.java.dev.jna:jna:5.12.0
     +--- org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2
     |    \--- kotlinx-coroutines-core → core-jvm 1.10.2 (stdlib 2.1.0 → 2.1.20)
     \--- androidx.browser:browser:1.8.0
          \--- androidx annotation / collection / core / interpolator /
              versionedparcelable / concurrent-futures
```

Findings:

- **`jna` must be declared with `aar` type.** Central publishes `jna` as both
  a JAR and an AAR. The JAR embeds desktop natives (Linux/Windows/macOS) for
  JNA's runtime extraction but no Android ABIs; the AAR carries the `jni/`
  tree with `libjnidispatch.so` for all Android ABIs, which the consumer APK
  packages. The library's `@aar` notation is therefore load-bearing, not
  cosmetic.
- **The AAR's manifest `minSdkVersion` binds the consumer.** The v0.4.0
  release AAR declares `minSdkVersion 34` (it was built before the floor was
  lowered to 28 in `5c1b865`), and AGP's manifest merger rejects a consumer
  app whose `minSdk` is lower. Consumers must set `minSdk` at least as high
  as the library's declared floor — ordinary Android packaging behavior, but
  the Android README section must state the current floor.
- **Local environment workarounds** (not channel facts): the consumer used
  AGP 8.13.0 / Kotlin 2.1.20 — the versions present in the local Gradle cache —
  instead of the repository's 8.11.1 / 2.2.20, and a locally patched SDK
  layout, because the installed SDK ships a versioned platform
  (`android-36.1`) that AGP 8.13 does not discover.
- **Offline mirror of upstream artifacts.** This environment's network
  dropped connections mid-build, so the transitive artifacts (and AGP's
  aapt2 tool jar) were resolved from a local Maven-layout mirror of the exact
  `dl.google.com` / Maven Central files, every artifact verified against its
  upstream `.sha1`. Production consumers resolve the same dependency line
  from `mavenCentral()` and `google()`.

## Comparison

| Axis | Maven Central | SPM | Carthage | GitHub Releases (status quo) |
| --- | --- | --- | --- | --- |
| Trust, signing, versioning | GPG-signed artifacts, checksums, source-tied namespace; immutable SemVer versions | SHA-256 checksum in manifest; unsigned static binary signed only as part of the consuming app; version follows repository tags | No mandatory signing; binary spec JSON per version; immutable assets underneath | SHA-256 checksums published and manually verified; immutable assets |
| Dependency resolution | Automatic: POM carries `jna` (aar), coroutines, browser | Automatic within the package: binary target + generated source target; no further transitive deps | None for prebuilt specs; source builds would require the Rust toolchain per machine | None: manual files, manual transitive declarations |
| Release automation | Add GPG signing + portal publication to the existing pipeline after one-time namespace setup | Add per-release manifest assembly pointing at the existing zip asset | Add binary spec JSON per release | None: existing pipeline unchanged |
| Maintenance cost | Low after first publication; immutable versions mean fixes ship as new versions | Low: the release zip already exists | Moderate: compiler-version drift, declining ecosystem | None |
| Consumer onboarding | One Gradle dependency line | One SPM dependency (or local package reference) | Cartfile entry plus prebuilt download, with compiler-version rejection risk | Multi-step manual integration per platform |

## Decisions

- **Android — adopt Maven Central.** It removes the single largest onboarding
  friction (three hand-declared transitive dependencies next to a file AAR)
  and matches where Android developers resolve dependencies. The GitHub
  Release AAR continues in parallel as the fallback channel. Follow-up:
  [#81](https://github.com/ProjectFlora/AppAuth-Rust/issues/81).
- **Apple — adopt Swift Package Manager.** Spike A confirms the binary-target
  mechanism works with the existing release artifacts, and SPM is the native
  default for the supported platforms. The GitHub Release zip continues as
  the fallback channel and as the binary source for the SPM target.
  Follow-up: [#82](https://github.com/ProjectFlora/AppAuth-Rust/issues/82).
- **Carthage — decline for now, revisit later.** The binary-spec route is
  technically possible, but the audience is covered by SPM, the tool's
  maintenance has slowed, and the compiler-version comparison adds a
  recurring failure mode. Revisit only if a concrete Carthage-only consumer
  need emerges.
- **Windows — continue GitHub Releases.** No package manager fits a C ABI
  package; the manual-channel friction is inherent to the target.
- **Adjacent channels — not evaluated here.** Publishing the Rust core to
  crates.io and the .NET wrapper to NuGet were named in issue #44 but are
  separate platform decisions; they are intentionally not evaluated or
  scheduled by this document.

## Follow-up work

The adopted channels are implemented in separate issues that reference this
document:

- **Publish the Android AAR to Maven Central** ([#81](https://github.com/ProjectFlora/AppAuth-Rust/issues/81)) — planned for v0.6.0. Central Portal account and
  `com.projectflora` namespace registration (lead-time item), GPG key and
  signing setup, POM generation for the library module with the three
  transitive dependencies (jna as `aar` type, per Spike B), publication step
  in the release workflow, and consumer documentation updates.
- **Distribute the Apple package through SPM** ([#82](https://github.com/ProjectFlora/AppAuth-Rust/issues/82)) — the package
  landed as `Package.swift` at the repository root: a subdirectory manifest
  is not an option because SPM resolves only a root manifest for remote git
  dependencies (the upstream feature request remains unimplemented), and a
  dedicated repository would split version tags and the release pipeline.
  Its source target carries the checked-in UniFFI-generated Swift API (a
  CI check verifies it matches the Rust source) plus the platform adapters,
  and its binary target references the release zip by URL with a per-release
  checksum. The checksum is only known after the build: the archive is a
  build output, and the in-run self-test proves only that its packaging
  step is deterministic, not that a rebuild would be byte-identical. The
  release workflow (dispatched from `main`) therefore writes the URL and
  checksum into `Package.swift`, validates the rewritten manifest against
  the archive, commits it as a release commit on top of the dispatched
  `main` commit, and creates the version tag there; the published release
  consumer workflow resolves the tag by URL (see
  [Releasing](releasing.md)). The first SPM release is v0.5.0.
