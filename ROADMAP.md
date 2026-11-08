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
  Apple platforms and a thin Kotlin adapter for Android; keep browser and
  redirect lifecycle handling in those adapters.
- **Binding mechanism:** Define the native-facing Rust API with UniFFI
  proc-macros, keeping protocol implementation behind that interface. Pin the
  UniFFI runtime and binding generator to 0.32.2; generate bindings
  reproducibly and do not hand-edit generated files. Implement explicit
  cancellation separately from UniFFI.
- **Initial binding distribution:** Pin UniFFI generation to 0.32.2, matching
  the validated spike, and generate bindings reproducibly from the Rust
  interface. Publish versioned Apple XCFramework and Android AAR artifacts with
  checksums through GitHub Releases; keep compiled binaries out of the source
  repository. Evaluate Maven Central, Swift Package Manager, and Carthage as
  later distribution channels.
- **HTTP architecture:** Use an asynchronous transport abstraction, with a
  Rust `reqwest` implementation by default and native transport overrides
  available to mobile adapters.
- **Runtime ownership:** Rust callers provide the Tokio runtime used by the
  default `reqwest` transport; native mobile adapters may use their own HTTP
  clients.
- **Redirect policy:** Prefer verified HTTPS links on iOS/iPadOS and Android,
  with custom URI scheme fallbacks; use loopback redirects on macOS.
- **Windows scope:** Include the shared Rust core for `x86_64-pc-windows-msvc`
  in the initial release. Defer Windows browser and redirect integration, and
  its minimum OS decision, to a later phase; it is not an initial-release
  requirement.
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
- **Rust support:** Set Rust 1.88 as the MSRV based on the currently locked
  dependency set and test it in CI. Support the documented initial-release
  target triples in [README.md](README.md); Linux is for development and CI
  only. Keep one Rust core crate and add a workspace only if separate Rust
  crates become necessary.
- **Initial support matrix:** As checked on 2026-11-08, set iOS/iPadOS minimum
  to 18 and macOS minimum to 15 based on Apple's current security-updated
  generations. Set Android API 34 as a provisional minimum based on current
  AOSP Security Bulletin coverage; reassess it before release using the current
  bulletin and available Google Play Console Reach and devices data. Windows
  desktop OS minimum remains deferred because only the shared core is in the
  initial release.
- **Provider-specific behavior:** Do not add provider detection, defaults, or
  protocol branches in the initial release. Keep provider parameters caller
  supplied and expose unrecognized response parameters to callers as raw
  additional values, without interpreting them; future additions require an
  explicit scope decision and interoperability evidence.

## Open decisions

- **Long-term package distribution:** Evaluate Maven Central, Swift Package
  Manager, and Carthage after the initial GitHub Release artifacts are
  available.
- **Android release floor:** Reassess provisional API 34 against current
  security bulletins, device reach data, and the final native dependency set
  before the release candidate.

## Work phases

1. **Finalize the initial feature boundary (complete):** Review the proposed
   initial, later, and out-of-scope features in [FEATURE_MATRIX.md](FEATURE_MATRIX.md),
   confirm the feature boundary, and resolve the remaining open decisions above.
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
5. **Add Windows desktop integration (later phase):** This is not required for
   the initial release. When scheduled, add external-browser launch and
   redirect handling, then define and document the minimum Windows version.
6. **Validate and prepare a release:** Add unit and protocol integration tests,
   platform build/flow tests, security-focused edge-case coverage, examples,
   API documentation, and a release/support matrix.

The Rust core provides endpoint configuration and discovery, Authorization
Code + PKCE, callback validation, cancellable HTTP, code exchange and token
parsing, explicit refresh with serializable authentication state, additional
token parameters, RP-Initiated Logout, public-client dynamic registration, and
OIDC ID Token validation. The UniFFI facade and reproducible binding generation
are in place. Initial iOS/iPadOS and macOS authorization adapters are
implemented and covered by SDK type-checking and a macOS loopback smoke test.
The Android authorization adapter is implemented with App Links/custom-scheme
selection, unit-tested redirect handling, and emulator-tested callback
activity routing. CI cross-compiles all documented Apple, Android, and Windows
Rust targets, packages an Apple XCFramework, and verifies Rust libraries are
packaged in the Android release AAR. Full authorization through external
browsers and live identity providers, and release validation, remain.

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
