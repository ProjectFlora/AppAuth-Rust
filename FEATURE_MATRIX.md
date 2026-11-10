# Feature matrix

This draft compares the documented features of
[AppAuth-iOS](https://github.com/openid/AppAuth-iOS) and
[AppAuth-Android](https://github.com/openid/AppAuth-Android) with the proposed
Rust scope. “Agreed” reflects decisions already made; “Proposed” still needs
confirmation.

| Feature | AppAuth-iOS | AppAuth-Android | Rust scope |
| --- | --- | --- | --- |
| Authorization Code + PKCE | Supported | Supported | Initial — agreed |
| Authorization server configuration and OIDC discovery | Supported | Supported | Initial — agreed |
| External browser authorization | System authentication session; WebViews unsupported | Custom Tabs preferred; WebViews unsupported | Initial — agreed; platform adapters handle browser/UI |
| Redirect capture and authorization response | iOS HTTPS redirects or custom scheme; macOS loopback or custom scheme | Custom scheme or HTTPS App Links | Initial — agreed: iOS HTTPS preferred/custom fallback; Android App Links preferred/custom fallback; macOS/Windows loopback |
| Code exchange, token responses, and refresh | Supported | Supported | Initial — agreed |
| Authorization state and fresh-token convenience | `OIDAuthState` tracks requests/responses and supports refresh | `AuthState` supports JSON persistence and fresh-token action | Initial — agreed; serialize state in core, host app owns persistence and encryption |
| Operation cancellation | Platform/browser cancellation is represented in flow results | Completion and cancellation use separate intents | Initial — agreed; expose explicit cancel handle and distinct cancellation result |
| OIDC ID Token | Parses claims; explicitly does not verify JWT signatures | Validates selected claims; does not verify JWT signatures | Initial — agreed; RS256/ES256 signatures, required claims, and JWKS rotation |
| Additional authorization and token request parameters | Supported | Supported | Initial — agreed; constrain reserved/security-sensitive parameters |
| Additional response parameters | Exposed by token response models | Exposed by token response models | Initial — agreed; preserve unrecognized values opaquely without interpreting them |
| OIDC end-session / logout | Supported | Supported | Initial — agreed |
| Dynamic client registration | Supported | Supported | Initial — agreed for public clients; do not embed client secrets |
| Browser selection/custom user agent | Custom external user agents | Browser matching and custom-tab selection | Later — platform-specific |
| Native application API | Native Objective-C/Swift APIs | Native Java/Kotlin APIs | Initial — agreed; thin Swift/Kotlin adapters and a Windows C ABI around the Rust core |
| Rust-to-native bindings | N/A | N/A | Initial — agreed; UniFFI generates Swift/Kotlin bindings; a C ABI serves Windows C++ and .NET hosts |
| HTTP transport | Customizable URL session provider | Custom connection builder | Initial — agreed; async abstraction, caller-runtime reqwest default, native override available |
| Device Authorization Grant | Separate AppAuthTV implementation | Not part of the documented core flow | Deferred with tvOS |
| Static client secret in a native app | API can accept a client secret | Supported, but upstream warns against static secrets | Out of scope — native clients are public clients |
| Resource Owner Password / Implicit flows | Not part of the documented recommended flow | Not part of the documented recommended flow | Out of scope — use Authorization Code + PKCE |
| UserInfo and application API calls | Caller makes API calls with tokens | Caller makes API calls with tokens | Out of scope — return tokens; callers use them with their APIs |
| Windows browser and redirect integration | Not applicable | Not applicable | Initial — agreed for v1: external browser and loopback redirect; support Microsoft-supported Windows client versions and review at each release |

## Important parity difference

The Rust client is intended to provide stronger ID Token validation than the
upstream SDKs. AppAuth-iOS documents that it parses claims but does not verify
the JWT signature. AppAuth-Android validates selected claims, but its
implementation also relies on TLS to the token endpoint instead of verifying
the JWT signature. Rust validation must therefore define trusted key discovery,
allowed signing algorithms, required claim checks, and key-rotation behavior.

Dynamic registration is scoped to native public clients. A registration flow
that requires a confidential client secret is not supported in the native app.

## Provider-specific behavior

The initial release will not detect providers or add provider-specific defaults
or protocol branches. Callers can supply additional authorization and token
request parameters, subject to the core's reserved-parameter checks, and
unrecognized response parameters are exposed through the token response's
`additional_parameters` map as raw JSON values; the SDK does not interpret
them. Any later provider-specific behavior requires an explicit scope decision
and interoperability evidence.

## Binding spike notes

UniFFI 0.32.2 successfully compiled a minimal Rust API containing a record,
typed error, synchronous function, and async function. It generated both Swift
and Kotlin bindings; the Swift output type-checked with Swift 6.4, and the
generated Kotlin output compiled with Kotlin 2.4.21, JNA 5.12.0, and
`kotlinx-coroutines-core` 1.6.4. Async calls were exposed as Swift `async` and
Kotlin `suspend`.

The documented limitations to account for are that cancellation is not
built-in, UniFFI does not package the platform library, and Swift 6 support is
partial (including known `Sendable` limitations for async code). The spike did
not validate runtime cancellation or Apple/Android packaging. Since then,
platform cancellation has been implemented, and CI builds an Apple XCFramework
and an Android AAR and checks the packaged Rust libraries. CI also exercises
iOS simulator authorization, macOS loopback authorization, and Android Custom
Tab authorization flows against local mock providers. These checks do not
replace live identity-provider interoperability testing. The CI validation
artifacts expire after 14 days; versioned GitHub Release assets are the
persistent distribution channel. UniFFI is adopted for the initial
Swift/Kotlin binding approach.

Generation is pinned to UniFFI 0.32.2 and uses proc macros to define the
native-facing Rust API. The published
[v0.1.0 release](https://github.com/ProjectFlora/AppAuth-Rust/releases/tag/v0.1.0)
contains the Apple XCFramework, Android AAR, Rust API reference, and
`SHA256SUMS`, without a Windows package. The published
[v0.2.0 release](https://github.com/ProjectFlora/AppAuth-Rust/releases/tag/v0.2.0)
includes those assets and adds the Windows DLL/C ABI package. See
[Download and verify v0.2.0](README.md#download-and-verify-v020) for exact asset
names, download links, and checksum verification using the same release's
`SHA256SUMS`. The XCFramework contains the generated Swift API and Rust
library; the AAR contains the generated Kotlin API and Android Rust libraries;
the Windows package contains the DLL, import library, C header, and .NET
wrapper. Compiled binaries stay out of the source repository. Maven Central,
Swift Package Manager, and Carthage remain candidates for later evaluation.

## References

- [AppAuth-iOS README](https://github.com/openid/AppAuth-iOS/blob/master/README.md)
- [AppAuth-Android README](https://github.com/openid/AppAuth-Android/blob/master/README.md)
- [AppAuth-iOS `OIDIDToken.h`](https://github.com/openid/AppAuth-iOS/blob/master/Sources/AppAuthCore/OIDIDToken.h)
- [AppAuth-iOS `OIDTokenResponse.h`](https://github.com/openid/AppAuth-iOS/blob/master/Sources/AppAuthCore/OIDTokenResponse.h)
- [AppAuth-Android `IdToken.java`](https://github.com/openid/AppAuth-Android/blob/master/library/java/net/openid/appauth/IdToken.java)
- [Apple security releases](https://support.apple.com/en-us/100100)
- [Android Security Bulletin, November 2026](https://source.android.com/docs/security/bulletin/2026/2026-11-01)
- [Google Pixel software update policy](https://support.google.com/pixelphone/answer/4457705?hl=en)
- [Google Play Android device dashboard](https://developer.android.com/about/dashboards)
- [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252)
- [RFC 6749: Authorization Response](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2)
- [RFC 7591: OAuth 2.0 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)
- [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [UniFFI documentation](https://mozilla.github.io/uniffi-rs/latest/)
- [UniFFI async/Future support](https://mozilla.github.io/uniffi-rs/latest/futures.html)
- [UniFFI Swift bindings](https://mozilla.github.io/uniffi-rs/latest/swift/overview.html)
- [UniFFI async API client example](https://github.com/mozilla/uniffi-rs/tree/main/examples/async-api-client)
