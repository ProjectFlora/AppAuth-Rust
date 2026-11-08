# Roadmap

This roadmap tracks work remaining for the initial scope in
[README.md](README.md). Items marked as open are decisions, not commitments.

## Confirmed decisions

- **OIDC scope:** Include ID Token validation in the initial release, including
  signature verification and validation of required claims such as issuer,
  audience, expiration, and nonce.

## Open decisions

- **Authorization state and storage:** Decide which session state the library
  models and serializes, and leave secure storage to the host application or
  provide platform-specific storage integrations.
- **Async and HTTP design:** Choose an async/runtime strategy and decide how
  callers configure or replace HTTP transport.
- **Redirect support:** Specify supported redirect types and callback
  lifecycle per platform, including cancellation and malformed or unexpected
  responses.
- **Rust and packaging support:** Set the Rust MSRV, target architectures,
  crate boundaries, and distribution/integration mechanisms.
- **Feature boundary:** Record whether logout/end-session, device authorization,
  dynamic client registration, and provider-specific extensions are in or out
  of the initial release.

## Work phases

1. **Finalize the feature matrix:** Compare AppAuth-iOS and AppAuth-Android
   behavior, mark each feature as initial, later, or out of scope, and resolve
   the open decisions above.
2. **Establish the Rust foundation:** Create the crate/workspace structure,
   select core dependencies, define public types and error behavior, and verify
   the planned Apple, Android, and Windows build targets.
3. **Implement the shared authorization core:** Add endpoint configuration
   and discovery, Authorization Code + PKCE request construction, callback
   validation, code exchange, token response handling, refresh behavior, and
   OIDC ID Token signature and claim validation.
4. **Integrate initial native platforms:** Add external-browser and redirect
   integrations for iOS/iPadOS, macOS, and Android while keeping UI and OS
   lifecycle concerns outside the shared protocol core.
5. **Complete Windows desktop integration:** Add external-browser launch and
   redirect handling, then define and document the minimum Windows version.
6. **Validate and prepare a release:** Add unit and protocol integration tests,
   platform build/flow tests, security-focused edge-case coverage, examples,
   API documentation, and a release/support matrix.

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
