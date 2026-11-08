# AppAuth-Rust

Rust client library for OAuth 2.0 and OpenID Connect, informed by
[AppAuth-iOS](https://github.com/openid/AppAuth-iOS) and
[AppAuth-Android](https://github.com/openid/AppAuth-Android).

## Initial scope

- Implement a shared Rust core for native applications.
- Expose the core to iOS/iPadOS and macOS through thin Swift adapters, and to
  Android through a thin Kotlin adapter generated with UniFFI. Keep browser
  launch and redirect lifecycle in these adapters.
- Start with Authorization Code + PKCE, authorization server discovery or
  explicit endpoint configuration, authorization code exchange, and token
  refresh.
- Include OpenID Connect ID Token validation in the initial release.
- Include OIDC end-session and dynamic client registration for public clients.
- Allow additional authorization and token request parameters.
- Model authentication state in the Rust core and make it serializable; host
  applications are responsible for persistence and encryption.
- Use the external browser for authorization; do not embed the flow in a
  WebView.
- Keep OAuth/OIDC protocol handling in the shared Rust core.

## Platform plan

| Platform | Initial scope |
| --- | --- |
| iOS / iPadOS | Shared core and native authorization integration |
| macOS | Shared core and native authorization integration |
| Android | Shared core and native authorization integration |
| Windows | First compile and use the shared core; add desktop browser and redirect integration in a later phase |
| tvOS | Deferred |

## Minimum OS support policy

- **iOS / iPadOS and macOS:** At each release, support the latest, previous,
  and second-previous major OS generations when Apple still provides security
  updates for them. Assess each platform independently. If the second-previous
  generation is no longer receiving security updates, raise the minimum to the
  oldest generation that is still supported.
- **Android:** Use API 23 (Android 6.0) as the initial technical baseline for
  App Links. The eventual minimum may be higher if required by dependencies or
  the target user base.
- **Windows:** Set the minimum Windows version when the desktop browser and
  redirect integration is designed. The initial shared-core phase does not
  establish a Windows OS minimum.

The OS versions actually supported by a release must be checked and recorded
at release time; these policies do not promise fixed version numbers.

See [FEATURE_MATRIX.md](FEATURE_MATRIX.md) for the feature-scope proposal and
[ROADMAP.md](ROADMAP.md) for remaining design decisions and work phases.
