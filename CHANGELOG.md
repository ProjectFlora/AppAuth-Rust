# Changelog

Notable changes to NativeOIDC (named AppAuth-Rust up to v0.6.0) are
documented here. The 0.x series is pre-1.0: releases may be published while
interoperability testing and support policies are still evolving. Each release records its known limitations.

## [Unreleased]

### Changed

- Explicitly configured token revocation endpoints now accept loopback HTTP
  (`127.0.0.0/8`, `::1`, `localhost`), matching the authorization and token
  endpoints, so a local test provider can serve revocation. The issuer,
  discovered endpoints, and the end-session, registration and JWKS endpoints
  still require HTTPS
  ([#165](https://github.com/ProjectFlora/NativeOIDC/issues/165)).

## [0.7.1] - 2026-11-20

### Changed

- The Release workflow checks the signing key at the key server before any
  package is built: a new `keyserver` job, which runs on every release
  dispatch (candidate and publish), derives the fingerprint of every primary
  key in the `GPG_PRIVATE_KEY` secret and requires each to resolve at
  `keys.openpgp.org` by fingerprint, retrying to absorb key-server
  propagation lag. The parser handles both a secret and a public key block
  (a secret key packet embeds the public key, RFC 9580 section 5.5.3, and
  the check derives the fingerprint from that embedded public part), but
  material without secret key packets fails: it cannot sign, so the run
  would break only at the Maven signing step. A public key absent from the
  key server failed v0.6.0's
  Maven Central sync validation, which is why v0.6.0 was never published
  there ([#131](https://github.com/ProjectFlora/NativeOIDC/issues/131),
  [#152](https://github.com/ProjectFlora/NativeOIDC/issues/152)).
- Add a former-URL SPM consumer job to the release consumer validation
  workflow: a clean macOS runner resolves `v0.6.0` from
  `ProjectFlora/AppAuth-Rust`, downloads the binary artifact through
  GitHub's repository redirect, runs the host-side FFI smoke, and builds
  for the iOS simulator
  ([#154](https://github.com/ProjectFlora/NativeOIDC/issues/154)). The
  renamed repository's tags are immutable, so this job is the only check
  of that redirect path: it runs on every dispatch, so the redirect keeps
  being exercised as new releases are validated.

### Fixed

- Ship license notices in every release package. The Apple and Windows
  zips and the Android AAR (on GitHub Releases and Maven Central) now
  contain `LICENSE`, `THIRD_PARTY_LICENSES.txt` (the notices for the Rust
  crates in `Cargo.lock`, generated with cargo-about, and for the standard
  library's compiler-builtins and libm) and
  `RUST_STANDARD_LIBRARY_COPYRIGHT.html` (the Rust toolchain's notice file
  for the standard library); the Windows zip previously had no `LICENSE`
  either. The release workflow builds every package with the same pinned
  Rust version. In the AAR they are in `classes.jar` under
  `META-INF/native-oidc/`. CI checks the dependency licenses with
  cargo-deny (`deny.toml`), and the consumer checks require the notice
  files. v0.1.0 through v0.7.0 shipped without the notices: their GitHub
  Releases now carry the notice files, and Maven
  Central users of v0.7.0 should move to this release
  ([#161](https://github.com/ProjectFlora/NativeOIDC/issues/161)).
- Start each release's generated notes at the previous release. Release
  commits are tagged off `main`, so GitHub started the notes of every
  release since v0.5.0 at `v0.4.0`, the last release tagged on `main`; the
  notes of v0.6.0 and v0.7.0 have been corrected
  ([#151](https://github.com/ProjectFlora/NativeOIDC/issues/151)).

### Documentation

- State that the public API targets Swift and Kotlin only, that Objective-C
  and Java applications should use an app-side wrapper (for example a Swift
  `@objc` class with completion handlers, or a Kotlin function returning a
  `CompletableFuture` or accepting a callback), in the README, the feature
  matrix, the shared user guide, the documentation index, and the API
  coverage matrix. Record the decision and rationale in
  [ROADMAP.md](ROADMAP.md)
  ([#144](https://github.com/ProjectFlora/NativeOIDC/issues/144)).
- Record in the migration section that SPM consumers pinning a release up
  to v0.6.0 on the former URL continue to work: the redirect covers both
  the git dependency and the release asset that those manifests download
  their XCFramework from ([#154](https://github.com/ProjectFlora/NativeOIDC/issues/154)).

### Distribution

- Published as a regular GitHub Release while remaining a pre-1.0 version,
  with the Apple XCFramework, Android AAR, Windows DLL/C ABI package, API
  documentation, and SHA-256 checksums. Each package now carries `LICENSE`,
  `THIRD_PARTY_LICENSES.txt`, and `RUST_STANDARD_LIBRARY_COPYRIGHT.html`.
- The Android library is published to Maven Central as
  `net.project-flora.nativeoidc:native-oidc-android:0.7.1`. Swift Package
  Manager remains available through release tags.
- The public API, behavior, and serialized authentication state are
  unchanged from 0.7.0.

### Known limitations

- Live identity-provider interoperability has not been validated, including
  token revocation.
- macOS and Windows tests do not automate the real system-browser flow.
- Release consumer fixtures exercise refresh and end-session error paths in
  the Windows C++ and .NET hosts and token revocation in the Windows .NET
  host only; the Android and Apple XCFramework fixtures only construct the
  configuration object, and the SPM consumer runs a host-side smoke of the
  generated API without an authorization flow.
- The ASCII armor of the Maven Central signature files carries a
  `Version: BCPG v@RELEASE_NAME@` header, as in 0.7.0. The header is a
  comment and the signatures verify
  ([#169](https://github.com/ProjectFlora/NativeOIDC/issues/169)).
- SPM is supported only through release tags; depending on the `main`
  branch is not supported.

## [0.7.0] - 2026-11-18

### Changed

- Rename the project from AppAuth-Rust to NativeOIDC
  ([#146](https://github.com/ProjectFlora/NativeOIDC/issues/146)). The
  repository moves to `ProjectFlora/NativeOIDC`, and every consumer-facing
  identifier changes: the SPM package, product, and Swift module
  (`NativeOIDC`); the Android Maven coordinates
  (`net.project-flora.nativeoidc:native-oidc-android`) and Kotlin packages
  (`net.projectflora.nativeoidc`, `uniffi.native_oidc`); the Windows DLL
  (`native_oidc.dll`), C header (`native_oidc_windows.h`) and identifiers
  (`native_oidc_windows_*`, `NATIVE_OIDC_WINDOWS_*`, `NativeOidcWindows*`), and
  .NET wrapper (`ProjectFlora.NativeOidc.NativeOidcWindows`); the release
  asset names; and the Rust crate (`native-oidc`). The API, behavior, and
  serialized authentication state are unchanged. Releases v0.1.0 through
  v0.6.0 keep their former names, and the former Maven coordinates are never
  published. See
  [Migrating from AppAuth-Rust](README.md#migrating-from-appauth-rust) for the
  full mapping.
- `scripts/check-spm-manifest.sh` accepts the original asset URLs of releases
  up to 0.6.0, published under the former repository name, and expects
  `AppAuthRust-Apple-*.zip` archives up to 0.6.0 and `NativeOIDC-Apple-*.zip`
  archives from 0.7.0. Binding generation and Android library staging clear
  their generated-only output directories first, so outputs from a build
  under the former name are not packaged.

### Documentation

- State that AppAuth-Rust is an independent project, not affiliated with the
  OpenID Foundation or the AppAuth projects, in the README, the documentation
  index, the Apple and Windows release-asset READMEs, and the Maven POM, and
  describe AppAuth-iOS and AppAuth-Android as reference implementations
  ([#145](https://github.com/ProjectFlora/NativeOIDC/issues/145)). Record
  the decision to rename the project to NativeOIDC in v0.7.0.
- Add `authors`, `description`, `license`, and `repository` to `Cargo.toml`,
  and set `publish = false` while crates.io publication is deferred.
- Correct the v0.6.0 notes: its Maven Central upload failed Maven Central's
  signature validation because the signing key's public key was not on a key
  server Maven Central checks, so v0.6.0 was never published there
  ([#131](https://github.com/ProjectFlora/NativeOIDC/issues/131)). It will not
  be republished under the former coordinates.

### Distribution

- Published as a regular GitHub Release while remaining a pre-1.0 version.
  Release assets include Apple XCFramework, Android AAR, Windows DLL/C ABI
  package, API documentation, and SHA-256 checksums, under the NativeOIDC
  names.
- First release published to Maven Central: the Android library is
  available as `net.project-flora.nativeoidc:native-oidc-android:0.7.0`
  ([#81](https://github.com/ProjectFlora/NativeOIDC/issues/81),
  [#131](https://github.com/ProjectFlora/NativeOIDC/issues/131)). Swift
  Package Manager remains available through release tags, now from
  `https://github.com/ProjectFlora/NativeOIDC`.

### Known limitations

- Live identity-provider interoperability has not been validated, including
  token revocation.
- macOS and Windows tests do not automate the real system-browser flow.
- Release consumer fixtures exercise refresh and end-session error paths in
  the Windows C++ and .NET hosts and token revocation in the Windows .NET
  host only; the Android and Apple XCFramework fixtures only construct the
  configuration object, and the SPM consumer runs a host-side smoke of the
  generated API without an authorization flow.
- SPM is supported only through release tags; depending on the `main`
  branch is not supported.
- `release-consumer.yml` validates releases from v0.7.0 only; releases up to
  v0.6.0 used the former names.
- Platform minimums and provider interoperability policies remain subject to
  the 1.0.0 readiness criteria in `ROADMAP.md`.

## [0.6.0] - 2026-11-17

### Added

- Publish the Android library to Maven Central as
  `net.project-flora.appauth:appauth-rust-android`
  ([#81](https://github.com/ProjectFlora/AppAuth-Rust/issues/81)). A
  publishing release run builds the library from the release tag, signs it,
  and uploads it through the Central Portal after the GitHub Release is
  created. The POM declares jna (as an AAR), kotlinx-coroutines-android, and
  androidx.browser, so consumers need a single dependency line. The
  publication ships sources and javadoc jars. Pull request CI and release
  candidate runs check the publication contents with
  `scripts/check-android-maven-publication.sh`.
- Validate the published Android library from Maven Central in the release
  consumer workflow ([#131](https://github.com/ProjectFlora/AppAuth-Rust/issues/131)).
  The `android_maven` job of `release-consumer.yml` resolves
  `net.project-flora.appauth:appauth-rust-android:X.Y.Z` from
  `mavenCentral()` with a single dependency line -- the consumer fixture
  forces verification of the POM's transitive dependencies -- and runs the
  full consumer smoke on an emulator. A fail-fast publication-status check
  rejects a version that was never published to Central before the emulator
  boots, and a retry loop over the full publication (the AAR, the POM, the
  module metadata, the sources and javadoc jars, and their signatures)
  absorbs the portal -> Central sync delay
  ([#137](https://github.com/ProjectFlora/AppAuth-Rust/issues/137)).

### Documentation

- Correct how the v0.5.0 notes describe the Apple release archive. The
  release builds the archive once and computes the manifest checksum from
  that build. The packaging script's in-run self-test re-zips the staged
  tree and re-runs `create-xcframework` for the Info.plist, so it shows
  only that those steps repeat byte-identically within one run on one
  machine, not that a rebuild or a build on another machine reproduces the
  archive. Pinning the toolchain records which toolchain built the archive;
  it does not keep rebuilt bytes from drifting. Main's `Package.swift` is
  never rewritten by the release workflow: the pipeline maintains the
  manifest only in the release commit at each tag, and main keeps the binary
  target last committed to it by hand, not the previous release's. See
  [Releasing](docs/releasing.md#what-the-packaging-self-test-checks).

### Changed

- Build and validate the Apple release archive with Xcode 26.6
  ([#135](https://github.com/ProjectFlora/AppAuth-Rust/issues/135)).
  App Store Connect requires apps built with Xcode 26 or later, but the
  release `apple` job was pinned to Xcode 16.4 on `macos-15`, and the
  release and published-release consumer checks used that image's default
  Xcode 16.4, so the distributed XCFramework was never validated with an
  Xcode that App Store Connect accepts. All Apple jobs of `release.yml`
  and `release-consumer.yml` now run on `macos-26` and select the same
  Xcode through `XCODE_VERSION`; every job records `xcodebuild` and Swift
  versions in its step summary. The `macos-26` image ships no iOS 18
  simulator runtime, so the release `apple` job installs iOS 18.6 with the
  new `scripts/install-ios-simulator-runtime.sh` and keeps running the iOS
  authorization flow on the iOS 18 deployment minimum. The published SPM
  consumer no longer tracks the image's default toolchain (the
  #107 policy below); it uses the release Xcode, and a newer Swift reaches
  it only when `XCODE_VERSION` is bumped. Regular CI's `macos-15` and
  `xcode-27` lanes are unchanged.
- Make the published SPM consumer's Swift language mode explicit
  ([#107](https://github.com/ProjectFlora/AppAuth-Rust/issues/107)). The
  `spm` job of `release-consumer.yml` generates a consumer package with
  `swift-tools-version: 6.0`, so the consumer already built in the Swift 6
  language mode while the published library pins its source target to
  Swift 5, and the job pinned no Xcode version; neither choice was
  documented, so a future failure of the job could not be attributed to a
  language-mode or toolchain decision. The workflow now records the
  `xcodebuild` and Swift versions in its step summary before building, and
  comments in the workflow, a comment in the generated consumer manifest,
  and a new "Swift language mode" section in
  [docs/distribution-channels.md](docs/distribution-channels.md) record
  the policy: the consumer deliberately builds in the Swift 6 language
  mode and tracks the current toolchain, the library's Swift 5 pin is a
  fact about the generated API tracked for removal in
  [#133](https://github.com/ProjectFlora/AppAuth-Rust/issues/133), and a
  toolchain upgrade that fails the post-publication audit is triaged with
  the recorded versions, fixed with a fixture pull request, or routed to
  #133 when it reflects an API shape a real Swift 6 consumer would hit.
  The consumer package's manifest is otherwise unchanged.
- Require the whole Apple packaging output directory to be absent.
  `scripts/package-apple-xcframework.sh` refused to start only when the
  staged package directory existed, while the CI workflows remove the whole
  `target/apple/release-package` output directory before each run; the
  guard and the CI operating model disagreed on what a clean state is. The
  guard now checks the whole output directory — an existing one, even an
  empty one, stops the run with a message naming that directory and the
  removal command — matching the CI wipe. Re-running after a failure, or
  to repackage a version, therefore requires
  `rm -rf target/apple/release-package`, which also removes archives of
  earlier runs; move any archive you keep elsewhere first. The self-test
  outputs are no longer pre-removed before they are created: with the guard
  guaranteeing an absent output directory, there is nothing from an earlier
  run to remove. The EXIT trap that removes them on every exit stays, so
  the run never leaves its self-test outputs behind. The in-run self-tests
  and the release archive are unchanged.
- Accept SSH origin remotes in the SPM manifest check.
  `scripts/check-spm-manifest.sh` derived the repository URL for local
  runs from the origin remote and accepted only `https://github.com`
  URLs, so a repository cloned with an SSH remote — `git@github.com:OWNER/REPO`
  or `ssh://git@github.com/OWNER/REPO`, with or without a `.git` suffix —
  failed with "Cannot derive the repository URL from origin remote" before
  it inspected the manifest. The check now normalizes all three remote
  forms to the canonical `https://github.com/OWNER/REPO` URL it derives in
  CI from `GITHUB_REPOSITORY`, so the manifest check runs from an https or
  an SSH clone alike.
- Report missing keys in the Apple Info.plist normalizer as a validation
  error. `scripts/normalize_xcframework_plist.py` read the keys it sorts
  and compares by before validating the slice set, so a plist missing
  `AvailableLibraries`, or a slice missing `LibraryIdentifier`,
  `SupportedPlatform`, or `SupportedArchitectures` — the shape a future
  Xcode might write if it renamed or dropped a key — stopped the release
  run with a Python traceback instead of a rejection message. The
  normalizer now checks those keys before rewriting: a missing key is
  reported as a message naming the plist, the library (or its index when
  the identifier itself is missing) and the key, and the plist is left
  untouched. Valid plists canonicalize exactly as before, so the release
  archive is unchanged.
- Clean up the Apple packaging self-test's scratch outputs on every exit.
  An EXIT trap now removes the scratch XCFramework, and the determinism
  zip, whenever the script exits any other way. Previously the scratch was
  removed only when its Info.plist comparison succeeded, so a failed
  comparison or an interruption stranded it in
  `target/apple/release-package`, outside the package directory the guard
  then checked; the next run then failed in `create-xcframework`, which
  refuses an existing output path, even after the user removed the package
  directory as the guard's message then directed.
- Record no owner in the Apple release archive. The zip normalizer
  rewrites the 12-byte local-header 0x5855 (Info-ZIP "UX") subfield to
  the 8-byte shape, dropping the uid/gid word, so the archive records no
  owner at all: a zeroed word would record root:root, and the staging
  user's uid/gid is a machine-state input that must not reach the
  published archive. The normalizer accepts only the extra subfield
  `ditto` writes, a 0x5855 subfield of 8 bytes in the central directory
  or 8 or 12 bytes in a local header (the 12-byte shape is rewritten to
  8 bytes), and rejects every other subfield: no owner (such as 0x7855
  "Ux" or 0x7875 "ux"), extended attribute (0x5835 XAttr, a rejection the
  code documented but never implemented) or timestamp (0x5455) can reach
  the published archive. It also rejects extra fields whose subfields
  overrun or leave trailing bytes, and checks that every extra field in
  the rebuilt archive is already normalized. It also verifies each entry's
  record before reading the data: the payload — the compressed data plus,
  for bit-3 entries, the 16-byte data descriptor that follows it — must
  run exactly to the next record, so a malformed record is reported as a
  range problem, not a data error; a bit-3 entry's data descriptor must
  carry the `PK\x07\x08` signature and the central directory's crc,
  compressed-size, and uncompressed-size words. The extra fields of the
  removed AppleDouble sidecars are no longer normalized or checked, and the
  normalizer's summary line no longer counts their words; their records
  are still range-, data-descriptor- and CRC-checked, and a macOS-only test
  confirms that the sidecars real `ditto` writes pass those checks. The
  published archive's bytes, and the manifest checksum computed from them,
  change; the in-run determinism self-test is unchanged.
- Parse the end-of-central-directory record once in the zip normalizer:
  the central directory walk returns the central directory offset, so the
  main path no longer rescans the archive for it. The normalized archive
  bytes are unchanged.

### Distribution

- Published as a regular GitHub Release while remaining a pre-1.0 version.
  Release assets include Apple XCFramework, Android AAR, Windows DLL/C ABI
  package, API documentation, and SHA-256 checksums.
- First release published to Maven Central: the Android library is
  available as `net.project-flora.appauth:appauth-rust-android:0.6.0`
  ([#81](https://github.com/ProjectFlora/AppAuth-Rust/issues/81)). The
  publication is signed and uploaded through the Central Portal after the
  GitHub Release is created, so a version that reaches Central always has a
  GitHub Release to cross-check against. Swift Package Manager remains
  available from 0.5.0 through release tags.

### Known limitations

- Live identity-provider interoperability has not been validated, including
  token revocation.
- macOS and Windows tests do not automate the real system-browser flow.
- Release consumer fixtures exercise refresh and end-session error paths in
  the Windows C++ and .NET hosts and token revocation in the Windows .NET
  host only; the Android and Apple XCFramework fixtures only construct the
  configuration object, and the SPM consumer runs a host-side smoke of the
  generated API without an authorization flow.
- SPM is supported only through release tags; depending on the `main`
  branch is not supported.
- Platform minimums and provider interoperability policies remain subject to
  the 1.0.0 readiness criteria in `ROADMAP.md`.

## [0.5.0] - 2026-11-14

### Security

- Complete iOS browser waits directly on cancellation and accept only one
  completion for the active operation. Exercise duplicate/stale completion,
  dismissal/start errors, cancellation and reuse in the simulator smoke flow.
- Cancel native refresh while it waits for authentication-state access; cover
  reserved/duplicate parameters through native refresh and package consumers.
- Validate current Apple/Android/Windows package consumers in PR CI, including
  Android callback-activity edge cases. Exclude Apple ZIP resource forks when
  locating packages and fail Windows consumer validation on native nonzero exits.

- Process Windows loopback connections concurrently (up to 32, with per-client
  time limits), so incomplete requests do not serially block callbacks. Abort
  and drain active connection tasks when the operation completes or is cancelled.
- Route malformed matching Android callbacks to core validation instead of
  silently leaving the operation pending.
- Disable native Apple/Android HTTP caching so Rust controls JWKS freshness.
  Avoid delayed iOS cancellation affecting a newer operation, and reject
  starting an already-cancelled macOS listener or iOS browser request.

- Reject duplicate or conflicting token/revocation error objects and preserve
  their HTTP status instead of interpreting an ambiguous error. Require HTTP
  200 for token issuance and revocation success; retain unexpected/retryable
  status codes, including 429/503, even with OAuth-shaped bodies. Valid OAuth
  error objects on 400/401 remain authorization-server errors.
- Reject reserved revocation endpoint query parameters and propagate core
  cancellation even when an HTTP transport ignores its cancellation handle.

- Reject malformed percent escapes and invalid UTF-8 in authorization/logout
  callback queries, empty authorization errors, and ambiguous configured
  callback queries. Reject reserved parameters in token endpoint queries before
  code exchange or refresh sends a request.

- Serialize JWKS retrieval across configuration clones and recheck the cache
  after waiting, avoiding duplicate successful refreshes and stale overwrites.
  Preserve valid cached keys on refresh failure, reject expired-key fallback,
  and allow independent cancellation while waiting or fetching.
- Honor all JWKS Cache-Control fields, subtract Age from freshness, and disable
  caching for ambiguous or malformed freshness directives and unsupported
  Expires-only policies.

- Validate ID Token exp, iat and optional nbf against one clock reading, with
  deterministic coverage of the inclusive 60-second skew boundary. Reject
  malformed non-null nbf values and use overflow-safe time comparisons.

- Reject token success responses containing duplicate top-level JSON member
  names or an `error` member, preventing ambiguous responses from being
  accepted during code exchange or refresh.

### Changed

- Support Swift Package Manager as an Apple distribution channel: the
  release workflow computes the release archive's SHA-256 checksum, writes
  it and the archive URL into `Package.swift` as a release commit, and
  creates the version tag on top of it, so the manifest is maintained by
  the pipeline instead of by hand. The release preparation pull request
  (version, changelog, docs) is the only manual step before dispatch; see
  [Releasing](docs/releasing.md).
- Make the Apple release archive reproducible: the packaging step pins
  entry timestamps and metadata, normalizes the zip and the xcframework
  Info.plist, and requires a second in-run build to be byte-identical, so
  the checksum recorded in the manifest is stable and verifiable.
- Pin the release apple job to exact Rust and Xcode toolchain versions and
  record them in the run summary, so the archive's bytes — and the manifest
  checksum computed from them — cannot drift with a stable release or a
  runner image update.
- Published release consumer validation covers the SPM channel: an external
  consumer package resolves the release tag as a remote dependency, runs a
  host-side smoke of the generated API, and builds for the iOS simulator
  (the arm64 slice the release xcframework ships).
- CI now checks that the committed `Package.swift` binary target stays
  consistent: a canonical asset URL, a SHA-256 checksum, and a release
  version that never leads the Cargo version (main intentionally keeps the
  previous release's binary target).

### Distribution

- Published as a regular GitHub Release while remaining a pre-1.0 version.
  Release assets include Apple XCFramework, Android AAR, Windows DLL/C ABI
  package, API documentation, and SHA-256 checksums.
- First release available through Swift Package Manager: depend on
  `https://github.com/ProjectFlora/AppAuth-Rust` from `0.5.0` and use the
  `AppAuthRust` library product.

### Known limitations

- Maven Central publication of the Android AAR is not included; it is
  planned for 0.6.0 (#81). Install the AAR from the GitHub Release assets.
- SPM is supported only through release tags; depending on the `main`
  branch is not supported.
- Live identity-provider interoperability has not been validated, including
  token revocation.
- macOS and Windows tests do not automate the real system-browser flow.
- Release consumer fixtures exercise refresh and end-session error paths in
  the Windows C++ and .NET hosts and token revocation in the Windows .NET
  host only; the Android and Apple XCFramework fixtures only construct the
  configuration object, and the SPM consumer runs a host-side smoke of the
  generated API without an authorization flow.
- Platform minimums and provider interoperability policies remain subject to
  the 1.0.0 readiness criteria in `ROADMAP.md`.

## [0.4.0] - 2026-11-12

### Added

- Token refresh through the Windows C ABI `appauth_windows_refresh` and the
  .NET `AppAuthWindows.RefreshAsync` wrapper. A successful result returns the
  updated serialized authentication state, which the host must persist.
- OIDC end-session (RP-Initiated Logout) through the Windows C ABI
  `appauth_windows_end_session` and the .NET `AppAuthWindows.EndSessionAsync`
  wrapper. This brings the Windows C ABI to parity with the UniFFI operation
  surface: authorization, refresh, end-session, and revocation.

### Distribution

- Published as a regular GitHub Release while remaining a pre-1.0 version.
  Release assets include Apple XCFramework, Android AAR, Windows DLL/C ABI
  package, API documentation, and SHA-256 checksums.

### Known limitations

- Live identity-provider interoperability has not been validated, including
  token revocation.
- macOS and Windows tests do not automate the real system-browser flow.
- The Windows C ABI exposes authorization, refresh, end-session, and token
  revocation, matching the UniFFI operation surface.
- Release consumer fixtures exercise refresh and end-session error paths in
  the Windows C++ and .NET hosts and token revocation in the Windows .NET
  host only; the Apple and Android fixtures only construct the configuration
  object.
- Platform minimums and provider interoperability policies remain subject to
  the 1.0.0 readiness criteria in `ROADMAP.md`.

## [0.3.0] - 2026-11-12

### Added

- OAuth 2.0 Token Revocation (RFC 7009) through discovered or explicitly
  configured HTTPS endpoints for Rust, UniFFI, and Windows C ABI public-client
  APIs.

### Documentation

- Align distribution documentation with the published v0.3.0 assets, including
  download links, checksum verification, and the distinction between persistent
  release assets and temporary CI validation artifacts.

### Distribution

- Published as a regular GitHub Release while remaining a pre-1.0 version.
  Release assets include Apple XCFramework, Android AAR, Windows DLL/C ABI
  package, API documentation, and SHA-256 checksums.

### Known limitations

- Live identity-provider interoperability has not been validated, including
  token revocation.
- macOS and Windows tests do not automate the real system-browser flow.
- The Windows C ABI exposes authorization and token revocation, but not
  refresh or end-session.
- Release consumer fixtures exercise token revocation only in the Windows .NET
  host; the Apple and Android fixtures do not.
- Platform minimums and provider interoperability policies remain subject to
  the 1.0.0 readiness criteria in `ROADMAP.md`.

## [0.2.0] - 2026-11-10

### Added

- Windows desktop authorization through the system browser and loopback
  callback, with a cancellable C ABI and C++/.NET interop.
- Windows DLL/C ABI package generation and Windows adapter tests in CI.

### Validation

- iOS simulator and Android emulator authorization flows use local mock
  providers; macOS loopback and Windows adapter flows have mock/test coverage.

### Distribution

- Published as a regular GitHub Release while remaining a pre-1.0 version.
  Release assets include Apple XCFramework, Android AAR, Windows DLL/C ABI
  package, API documentation, and SHA-256 checksums.

### Known limitations

- Live identity-provider interoperability has not been validated.
- macOS and Windows tests do not automate the real system-browser flow.
- Platform minimums and provider interoperability policies remain subject to
  the 1.0.0 readiness criteria in `ROADMAP.md`.

## [0.1.0] - 2026-11-09

### Added

- Initial OAuth 2.0 Authorization Code + PKCE and OpenID Connect core,
  including discovery, refreshable serializable authentication state, ID Token
  validation, end-session, and public-client dynamic registration.
- UniFFI-generated Swift and Kotlin APIs and native authorization adapters for
  iOS/iPadOS, macOS, and Android.
- Initial Apple XCFramework, Android AAR, API documentation, and checksums.

### Security

- Native public clients do not embed client secrets. Authorization uses
  external browsers rather than embedded WebViews.
- ID Tokens accept RS256 and ES256 only and are checked against issuer JWKS,
  required claims, and the request nonce.
