# Roadmap

This roadmap tracks work remaining for the initial scope in
[README.md](README.md). Items marked as open are decisions, not commitments.

## Confirmed decisions

- **OIDC scope:** Include ID Token validation in the initial release, including
  signature verification and validation of required claims such as issuer,
  audience, expiration, and nonce.
- **Authentication state:** The Rust core models serializable authentication
  state; persistence and encryption are the host application's responsibility.
- **Native API surface:** Expose the Rust core through thin Swift adapters for
  Apple platforms and a thin Kotlin adapter for Android; keep browser and
  redirect lifecycle handling in those adapters.
- **Binding mechanism:** Use UniFFI to generate Swift and Kotlin bindings.
  Define explicit cancellation behavior and platform packaging separately.

## Open decisions

- **Async and HTTP design:** Choose an async/runtime strategy and decide how
  callers configure or replace HTTP transport.
- **Redirect support:** Specify supported redirect types and callback
  lifecycle per platform, including cancellation and malformed or unexpected
  responses.
- **Rust and packaging support:** Set the Rust MSRV, target architectures,
  crate boundaries, and distribution mechanisms for UniFFI-generated bindings.
- **Cancellation behavior:** Design how a native caller cancels an in-flight
  authorization, network, or refresh operation across the UniFFI boundary.
- **Remaining feature boundary:** Decide how to expose unrecognized response
  parameters and provider-specific extensions; review the remaining proposals
  in [FEATURE_MATRIX.md](FEATURE_MATRIX.md).

## Work phases

1. **Finalize the feature matrix:** Review the proposed initial, later, and
   out-of-scope features in [FEATURE_MATRIX.md](FEATURE_MATRIX.md), confirm the
   feature boundary, and resolve the remaining open decisions above.
2. **Establish the Rust foundation:** Create the crate/workspace structure,
   select core dependencies, define public types and error behavior, choose the
   UniFFI packaging approach, and verify the planned Apple, Android, and
   Windows build targets.
3. **Implement the shared authorization core:** Add endpoint configuration
   and discovery, Authorization Code + PKCE request construction, callback
   validation, code exchange, token response handling, refresh behavior, OIDC
   ID Token signature and claim validation, end-session, and dynamic client
   registration for public clients.
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
