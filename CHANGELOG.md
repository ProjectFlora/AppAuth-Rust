# Changelog

Notable changes to AppAuth-Rust are documented here. Until the first release,
changes remain under `Unreleased`.

## [Unreleased]

### Added

- Shared OAuth 2.0 Authorization Code + PKCE core with OIDC discovery,
  cancellable transport, refreshable serializable authentication state, and
  preservation of additional response parameters.
- OpenID Connect ID Token signature and claim validation, end-session requests,
  and public-client dynamic registration.
- UniFFI-generated Swift and Kotlin APIs, with external-browser authorization
  adapters for iOS/iPadOS, macOS, and Android.
- Cross-target CI for Apple, Android, and Windows core targets; Android release
  AAR packaging and callback-routing instrumentation checks.

### Security

- Native public clients do not embed client secrets. Authorization uses
  external browsers rather than embedded WebViews.
- ID Tokens accept RS256 and ES256 only and are checked against issuer JWKS,
  required claims, and the request nonce.

### Distribution

- The initial distribution plan is versioned GitHub Release assets containing
  an Apple XCFramework and Android AAR. These release packages and checksums
  have not yet been published.
