# Changelog

Notable changes to AppAuth-Rust are documented here. The 0.x series is
pre-1.0: releases may be published while interoperability testing and support
policies are still evolving. Each release records its known limitations.

## [Unreleased]

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
  The scratch XCFramework is now removed before it is created, which makes
  a re-run possible after any earlier failed or interrupted run, including
  exits a trap cannot observe (SIGKILL, power loss); an EXIT trap removes
  it, and the determinism zip, whenever the script exits any other way, and
  the determinism zip is pre-removed before its second `ditto`. Previously
  the scratch was removed only when its Info.plist comparison succeeded, so
  a failed comparison or an interruption stranded it in
  `target/apple/release-package`, outside the package directory the guard
  checks; the next run then failed in `create-xcframework`, which refuses
  an existing output path, even after the user removed the package
  directory as the guard's message directs.
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
