# Roadmap

This roadmap tracks work remaining for the initial scope in
[README.md](README.md). Items marked as open are decisions, not commitments.

## Confirmed decisions

- **OIDC scope:** Include ID Token validation in the initial release, including
  signature verification and validation of required claims such as issuer,
  audience, expiration, and nonce.
- **OIDC algorithms and JWKS:** Accept RS256 and ES256 only; cache JWKS for up
  to 300 seconds, respect stricter server cache directives, and refresh once
  when a cached set does not contain the presented key ID. Serialize retrieval
  across configuration clones and reuse newly cached results after waiting;
  uncached results and failed retrievals may require separate attempts.
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
  binaries out of the source repository. Maven Central, Swift Package
  Manager, and Carthage were subsequently evaluated; the per-platform
  decisions and rationale are recorded in
  [docs/distribution-channels.md](docs/distribution-channels.md).
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
- **Initial support matrix:** Re-evaluated 2026-11-12. Set iOS/iPadOS minimum
  to 18 and macOS minimum to 15, based on the Apple security-update
  generations current on that date. Set the Android minimum to API 28
  (Android 9): the November 2026 AOSP Security Bulletin still patches 14 and
  later, so a security-based floor would stay at API 34, but the 1.0.0 reach
  target (at least 90% of active devices, 95% preferred) only holds at API
  28 or lower — 97.1% in Google's October 2026 distribution data, versus
  56.4% for API 34. Manufacturer-dependent updates for older devices are
  accepted and documented in the README support policy. For Windows, support
  Microsoft-supported Windows client versions (25H2 and newer as of the check
  date) and review the support matrix at each release. Re-evaluate all three
  against the then-current security data and device reach immediately before
  the 1.0.0 tag.
- **Provider-specific behavior:** Do not add provider detection, defaults, or
  protocol branches in the initial release. Keep provider parameters caller
  supplied and expose unrecognized response parameters to callers as raw
  additional values, without interpreting them; future additions require an
  explicit scope decision and interoperability evidence.
- **Live identity-provider interoperability:** Do not operate dedicated IdP,
  Keycloak, or mobile callback-domain infrastructure solely for the initial
  release. Record the resulting unverified provider and real-device coverage
  in [docs/live-idp-interoperability.md](docs/live-idp-interoperability.md);
  ordinary pull-request CI remains limited to local mock providers.
- **Long-term package distribution:** Re-evaluated 2026-11-13
  ([#44](https://github.com/ProjectFlora/AppAuth-Rust/issues/44)). Adopt
  Maven Central for the Android AAR and Swift Package Manager for the Apple
  package, each running alongside the existing GitHub Release assets. Decline
  Carthage for now: its maintenance has slowed and SPM covers the same
  audience. Windows stays on GitHub Releases. The evaluation, technical
  spike evidence, comparison matrix, and follow-up issues are recorded in
  [docs/distribution-channels.md](docs/distribution-channels.md).
- **Crates.io publication:** Deferred 2026-11-13
  ([#64](https://github.com/ProjectFlora/AppAuth-Rust/issues/64)). Do not
  publish the Rust core to crates.io for the initial release: the primary
  consumers are the native bindings, publishing requires package metadata,
  docs.rs, and `cargo publish` validation work, and the version policy relative
  to the Maven Central and SPM packages is not yet settled. Re-evaluate after
  1.0.0 or when a concrete pure-Rust consumer need emerges.

## Open decisions

None.

## Pre-1.0 release policy

- 0.x releases are usable development releases, not a promise that the initial
  feature set or compatibility guarantees are complete. They may be published
  as regular GitHub Releases while known gaps remain; release notes must state
  the status and limitations.
- v0.5.0 is the current implementation snapshot. It adds Swift Package
  Manager distribution for the Apple package on top of the previously
  published v0.4.0 assets, which include token refresh and OIDC end-session
  in the Windows C ABI and .NET wrapper.
  Maven Central publication of the Android AAR is planned for v0.6.0
  ([#81](https://github.com/ProjectFlora/AppAuth-Rust/issues/81)).
- Do not declare 1.0.0 ready until all of these conditions are met:
  - Re-evaluate the support matrix against the then-current Apple security
    updates, Android Security Bulletin and device distribution, and
    Microsoft-supported Windows client versions immediately before the 1.0.0
    tag (1.0.0 is planned for 2026 Q4 to 2027 H1), and record the settled
    values in the support policy in [README.md](README.md).
  - Keep live identity-provider and real-device interoperability explicitly
    documented as unverified; do not represent those integrations as validated
    compatibility guarantees.
  - Complete security-focused protocol and platform edge-case coverage, and
    ensure CI is green for all declared targets and packages.
  - Validate installation and use of each release artifact, publish complete
    API/user documentation, and record the final support matrix.
    [Issue #60](https://github.com/ProjectFlora/AppAuth-Rust/issues/60) tracks
    the [matrix and verification procedure](docs/support-matrix.md).
    Release-candidate asset inspection is tracked in
    [#77](https://github.com/ProjectFlora/AppAuth-Rust/issues/77), and the
    pre-tag lifecycle recheck and final OS record in
    [#78](https://github.com/ProjectFlora/AppAuth-Rust/issues/78).
    Both remain 1.0.0 readiness gates after #60 is complete. Record actual
    CI runtimes and explicitly resolve or accept execution gaps in #77.

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
redirect handling, and an API 28 emulator test that exercises authorization
through a Custom Tab, callback activity, and code exchange against a local mock
provider. The Windows C ABI implements system-browser launch, loopback
authorization, and cancellation; unit tests exercise the flow with a simulated
browser callback, and CI builds/tests the Windows target and builds the .NET
wrapper. CI also packages an Apple XCFramework and verifies Rust libraries are
packaged in the Android release AAR. Live identity-provider interoperability
remains explicitly unverified.

Security edge-case audit progress and remaining gaps are tracked in
[the audit ledger](docs/security-edge-case-audit.md) ([#62](https://github.com/ProjectFlora/AppAuth-Rust/issues/62)).

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
