# Changelog

Notable changes to AppAuth-Rust are documented here. The 0.x series is
pre-1.0: releases may be published while interoperability testing and support
policies are still evolving. Each release records its known limitations.

## [Unreleased]

## [0.3.0] - 2026-11-11

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
