# Roadmap

This roadmap tracks work remaining for the initial scope in
[README.md](README.md). Items marked as open are decisions, not commitments.

## Confirmed decisions

- **OIDC scope:** Include ID Token validation in the initial release, including
  signature verification and validation of required claims such as issuer,
  audience, expiration, and nonce.
- **OIDC algorithms and JWKS:** Accept RS256 and ES256 only; cache JWKS for up
  to 300 seconds, respect stricter server cache directives, and refresh once
  when a cached set does not contain the presented key ID.
- **Authentication state:** The Rust core models serializable authentication
  state; persistence and encryption are the host application's responsibility.
- **Native API surface:** Expose the Rust core through thin Swift adapters for
  Apple platforms, a thin Kotlin adapter for Android, and a Windows C ABI for
  C++ and .NET hosts; keep browser and redirect lifecycle handling in adapters.
- **Binding mechanism:** Define the native-facing Rust API with UniFFI
  proc-macros, keeping protocol implementation behind that interface. Pin the
  UniFFI runtime and binding generator to 0.32.2; generate bindings
  reproducibly and do not hand-edit generated files. Implement explicit
  cancellation separately from UniFFI.
- **Initial binding distribution:** Pin UniFFI generation to 0.32.2, matching
  the validated spike, and generate bindings reproducibly from the Rust
  interface. Publish versioned Apple XCFramework, Android AAR, and Windows
  DLL/C ABI packages with checksums through GitHub Releases; keep compiled
  binaries out of the source repository. Evaluate Maven Central, Swift Package
  Manager, and Carthage as later distribution channels.
- **HTTP architecture:** Use an asynchronous transport abstraction, with a
  Rust `reqwest` implementation by default and native transport overrides
  available to mobile adapters.
- **Runtime ownership:** Rust callers provide the Tokio runtime used by the
  default `reqwest` transport; native mobile adapters may use their own HTTP
  clients.
- **Redirect policy:** Prefer verified HTTPS links on iOS/iPadOS and Android,
  with custom URI scheme fallbacks; use loopback redirects on macOS and Windows.
- **Windows scope:** Include Windows desktop browser and redirect integration
  in v1, using the external browser and loopback redirects. Initially target
  `x86_64-pc-windows-msvc`; support Windows client versions currently supported
  by Microsoft and review the supported versions at each release rather than
  pinning a fixed minimum OS version.
- **Authorization callback lifecycle:** Native adapters prepare the callback
  handler or loopback listener before browser launch and stop it after the first
  callback for the registered redirect. Unrelated callbacks are ignored
  (loopback requests to another path receive 404); malformed matching
  callbacks and state mismatches terminate with an invalid-response error, and
  matching OAuth errors remain authorization-server errors. Explicit
  cancellation and platform-reported user dismissal return `Cancelled` and
  clean up listeners and active work. There is no implicit timeout; the host
  owns timeout policy.
- **Cancellation contract:** Expose an explicit, idempotent operation
  cancellation handle and a distinct cancellation result; propagate
  cancellation to active work where supported.
- **Rust support:** Set Rust 1.99.1 as the MSRV to match the version currently
  used by CI and test it there. Support the documented initial-release target
  triples in [README.md](README.md); Linux is for development and CI only.
  Keep one Rust core crate and add a workspace only if separate Rust crates
  become necessary.
- **Initial support matrix:** As checked on 2026-11-08, set iOS/iPadOS minimum
  to 18 and macOS minimum to 15 based on Apple's current security-updated
  generations. Set Android API 34 as a provisional minimum based on current
  AOSP Security Bulletin coverage; reassess it before release using the current
  bulletin and available Google Play Console Reach and devices data. For
  Windows, support Microsoft-supported Windows client versions and review the
  support matrix at each release.
- **Provider-specific behavior:** Do not add provider detection, defaults, or
  protocol branches in the initial release. Keep provider parameters caller
  supplied and expose unrecognized response parameters to callers as raw
  additional values, without interpreting them; future additions require an
  explicit scope decision and interoperability evidence.

## Open decisions

- **Long-term package distribution:** Evaluate Maven Central, Swift Package
  Manager, and Carthage after the initial GitHub Release artifacts are
  available.
- **Android 1.0 release floor:** Reassess provisional API 34 against current
  security bulletins, device reach data, and the final native dependency set
  before 1.0.0.

## Pre-1.0 release policy

- 0.x releases are usable development releases, not a promise that the initial
  feature set or compatibility guarantees are complete. They may be published
  as regular GitHub Releases while known gaps remain; release notes must state
  the status and limitations.
- v0.2.0 is the current implementation snapshot. It adds the Windows desktop
  adapter and release package to the previously published v0.1.0 assets.
- Do not declare 1.0.0 ready until all of these conditions are met:
  - Reassess and settle provisional platform minimums, including Android API
    level, Apple security-supported OS generations, and the Windows support
    matrix.
  - Validate authorization against live identity providers on supported
    platforms, including real browser launch and callback behavior where
    applicable.
  - Complete security-focused protocol and platform edge-case coverage, and
    ensure CI is green for all declared targets and packages.
  - Validate installation and use of each release artifact, publish complete
    API/user documentation, and record the final support matrix.

## Work phases

1. **Finalize the initial feature boundary (complete):** Review the proposed
   initial, later, and out-of-scope features in [FEATURE_MATRIX.md](FEATURE_MATRIX.md)
   and confirm the feature boundary. Remaining 1.0.0 policy decisions are
   tracked above.
2. **Establish the Rust foundation (complete):** Maintain the documented
   single-crate core boundary, select core dependencies, define public types
   and error behavior, implement the pinned UniFFI proc-macro interface and
   reproducible binding generation, and verify the planned Apple, Android, and
   Windows build targets.
3. **Implement the shared authorization core (complete):** Provide endpoint
   configuration and discovery, Authorization Code + PKCE request construction,
   callback validation, code exchange, token response handling, refresh behavior,
   OIDC ID Token signature and claim validation, end-session, and dynamic client
   registration for public clients. Enforce exact redirect and state checks,
   with explicit cancellation for in-flight operations.
4. **Integrate initial native platforms (complete):** Add external-browser
   and redirect integrations for iOS/iPadOS, macOS, and Android while keeping
   UI and OS lifecycle concerns outside the shared protocol core.
5. **Add Windows desktop integration (complete; v1 target):** Provide the
   Windows C ABI, system-browser launch, loopback redirect handling, and
   cancellation for `x86_64-pc-windows-msvc`. At each release, review
   Microsoft's supported Windows client versions and update the documented
   support matrix and validation targets accordingly.
6. **Continue pre-1.0 validation and release preparation (in progress):**
   Publish 0.x development releases as milestones. Close the 1.0.0 readiness
   criteria above before making compatibility and support commitments.

The Rust core provides endpoint configuration and discovery, Authorization
Code + PKCE, callback validation, cancellable HTTP, code exchange and token
parsing, explicit refresh with serializable authentication state, additional
token parameters, RP-Initiated Logout, public-client dynamic registration, and
OIDC ID Token validation. The UniFFI facade and reproducible binding generation
are in place. Initial iOS/iPadOS and macOS authorization adapters are
implemented and covered by SDK type-checking. CI exercises iOS simulator
authorization against a local mock provider and runs a macOS loopback
authorization flow against a local mock provider. The Android authorization
adapter is implemented with App Links/custom-scheme selection, unit-tested
redirect handling, and an API 34 emulator test that exercises authorization
through a Custom Tab, callback activity, and code exchange against a local mock
provider. The Windows C ABI implements system-browser launch, loopback
authorization, and cancellation; unit tests exercise the flow with a simulated
browser callback, and CI builds/tests the Windows target and builds the .NET
wrapper. CI also packages an Apple XCFramework and verifies Rust libraries are
packaged in the Android release AAR. Live identity-provider interoperability
and release validation remain.

## Initial validation checkpoints

- PKCE verifier/challenge, state, and nonce generation and handling.
- Discovery and authorization-server error handling.
- Redirect URI and authorization response validation.
- Token exchange, refresh, expiration, and refresh failure behavior.
- ID Token signature, issuer, audience, expiration, and nonce validation.
- No embedded WebView flow; no client secret embedded in a native public
  client.
- Cross-platform builds and platform callback behavior at the declared minimum
  OS versions.
