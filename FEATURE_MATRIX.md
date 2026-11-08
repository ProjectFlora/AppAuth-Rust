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
| Redirect capture and authorization response | iOS URI redirects; macOS loopback or custom scheme | Custom scheme or HTTPS App Links | Initial — agreed at high level; exact redirect modes remain open |
| Code exchange, token responses, and refresh | Supported | Supported | Initial — agreed |
| Authorization state and fresh-token convenience | `OIDAuthState` tracks requests/responses and supports refresh | `AuthState` supports JSON persistence and fresh-token action | Initial — agreed; serialize state in core, host app owns persistence and encryption |
| OIDC ID Token | Parses claims; explicitly does not verify JWT signatures | Validates selected claims; does not verify JWT signatures | Initial — agreed; verify signatures and required claims |
| Additional authorization and token request parameters | Supported | Supported | Initial — agreed; constrain reserved/security-sensitive parameters |
| Additional response parameters | Exposed by token response models | Exposed by token response models | Open — decide whether to preserve unrecognized response fields |
| OIDC end-session / logout | Supported | Supported | Initial — agreed |
| Dynamic client registration | Supported | Supported | Initial — agreed for public clients; do not embed client secrets |
| Browser selection/custom user agent | Custom external user agents | Browser matching and custom-tab selection | Later — platform-specific |
| Native application API | Native Objective-C/Swift APIs | Native Java/Kotlin APIs | Initial — agreed; thin Swift and Kotlin adapters around the Rust core |
| Rust-to-native bindings | N/A | N/A | Initial — agreed; UniFFI generates the Swift/Kotlin bindings |
| Custom HTTP transport | Customizable URL session provider | Custom connection builder | Open — choose runtime/transport design before committing API |
| Device Authorization Grant | Separate AppAuthTV implementation | Not part of the documented core flow | Deferred with tvOS |
| Static client secret in a native app | API can accept a client secret | Supported, but upstream warns against static secrets | Out of scope — native clients are public clients |
| Resource Owner Password / Implicit flows | Not part of the documented recommended flow | Not part of the documented recommended flow | Out of scope — use Authorization Code + PKCE |
| UserInfo and application API calls | Caller makes API calls with tokens | Caller makes API calls with tokens | Out of scope — return tokens; callers use them with their APIs |
| Windows browser and redirect integration | Not applicable | Not applicable | Later — agreed; shared Rust core comes first |

## Important parity difference

The Rust client is intended to provide stronger ID Token validation than the
upstream SDKs. AppAuth-iOS documents that it parses claims but does not verify
the JWT signature. AppAuth-Android validates selected claims, but its
implementation also relies on TLS to the token endpoint instead of verifying
the JWT signature. Rust validation must therefore define trusted key discovery,
allowed signing algorithms, required claim checks, and key-rotation behavior.

Dynamic registration is scoped to native public clients. A registration flow
that requires a confidential client secret is not supported in the native app.

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
not validate runtime cancellation behavior or Apple/Android packaging; these
remain open implementation tasks. UniFFI is adopted for the initial
Swift/Kotlin binding approach.

## References

- [AppAuth-iOS README](https://github.com/openid/AppAuth-iOS/blob/master/README.md)
- [AppAuth-Android README](https://github.com/openid/AppAuth-Android/blob/master/README.md)
- [AppAuth-iOS `OIDIDToken.h`](https://github.com/openid/AppAuth-iOS/blob/master/Sources/AppAuthCore/OIDIDToken.h)
- [AppAuth-iOS `OIDTokenResponse.h`](https://github.com/openid/AppAuth-iOS/blob/master/Sources/AppAuthCore/OIDTokenResponse.h)
- [AppAuth-Android `IdToken.java`](https://github.com/openid/AppAuth-Android/blob/master/library/java/net/openid/appauth/IdToken.java)
- [UniFFI documentation](https://mozilla.github.io/uniffi-rs/latest/)
- [UniFFI async/Future support](https://mozilla.github.io/uniffi-rs/latest/futures.html)
- [UniFFI Swift bindings](https://mozilla.github.io/uniffi-rs/latest/swift/overview.html)
