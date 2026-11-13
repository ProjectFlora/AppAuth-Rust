# Public API coverage

Return to the [documentation index](README.md). Initial source inventory:
`d0e4aa37acd801bb367bd533841616bd2a5ed775`. This document accompanies the source
revision being read; it is not evidence that all examples were executed.
Update the inventory when a public operation, record, error or adapter changes.

## Operations by language

UniFFI names below are the Rust source names from [ffi.rs](../src/ffi.rs).
Swift and Kotlin bindings use generated language spellings. Windows C++ uses
the [ABI reference](windows-api.md); .NET uses `AppAuthWindows` methods.
“Host” means application work is required; “not exposed” is a binding limit.

| Operation | Rust core | Swift / Kotlin (UniFFI) | Windows C++ | Windows .NET |
| --- | --- | --- | --- | --- |
| Discovery | `ServiceConfiguration::discover` | `FfiServiceConfiguration::discover` | `issuer` in operation JSON; no standalone call | Same JSON via operation methods |
| Explicit endpoints / OIDC | `ServiceConfiguration::new`, `with_oidc_validation_endpoints` | Same methods on `FfiServiceConfiguration` | Operation JSON endpoint fields | Same JSON |
| Optional endpoints | `with_end_session_endpoint`, `with_revocation_endpoint`, `with_registration_endpoint` | Same methods on `FfiServiceConfiguration` | End-session/revocation endpoint fields; registration not exposed | Same JSON; registration not exposed |
| Configuration inspection | Seven endpoint/issuer getters | Five getters: authorization/token/revocation endpoint, issuer, JWKS | Not exposed | Not exposed |
| Prepare authorization | `AuthorizationRequest::new`, `begin` | `begin_authorization`, `FfiAuthorizationOptions` | Integrated in `appauth_windows_authorize` | `AuthorizeAsync` |
| Additional request parameters | `with_additional_parameter`, `with_additional_token_parameter` | Options' `additional_parameters`, `additional_token_parameters` | Same authorize JSON arrays | Same JSON |
| Authorization URL / nonce | `AuthorizationSession::authorization_url`, `nonce` | Same methods on `FfiAuthorizationSession` | Managed internally, not exposed separately | Same |
| Browser and callback lifecycle | Host | `IOSAuthorizationAdapter`, `MacOSAuthorizationAdapter`, `AndroidAuthorizationAdapter` | Integrated authorize browser/loopback | Via `AuthorizeAsync` |
| Callback validation / exchange | `parse_redirect`, `exchange_code` | Same session methods; exchange returns state | Integrated authorize | Integrated authorize |
| Response inspection | `AuthorizationResponse::{code,state,additional_parameters}` | Same getters on `FfiAuthorizationResponse` | State JSON only | State JSON only |
| Create state after exchange | `AuthorizationSession::authentication_state` | Exchange returns `FfiAuthenticationState` | Authorize returns state JSON | Authorize returns state JSON |
| Other state construction | `AuthenticationState::{new,new_with_oidc_nonce}` | Only `from_json`; no token-based constructor | No separate constructor | No separate constructor |
| Token / expiry / expiry check | `AuthenticationState::{token_response,expires_at,is_expired_at}` | Same methods on `FfiAuthenticationState` | Host reads JSON / compares timestamp | Host reads JSON / compares timestamp |
| Serialize / restore | Serde on `AuthenticationState` | `to_json`, `from_json` | Returned JSON / refresh `state` object | Same JSON |
| Secure persistence | Host | Host | Host | Host |
| Refresh / extra parameters | `refresh`, `refresh_with_additional_parameters` | `FfiAuthenticationState::refresh` with parameters | `appauth_windows_refresh`, JSON parameters | `RefreshAsync` |
| Prepare end-session | `EndSessionRequest::{new,with_id_token_hint,with_post_logout_redirect_uri,begin}` | `begin_end_session`, `FfiEndSessionOptions` | `appauth_windows_end_session` | `EndSessionAsync` |
| Logout URL / callback | `EndSessionSession::{end_session_url,parse_redirect}` | Same methods on `FfiEndSessionSession` | Integrated browser/loopback | Integrated browser/loopback |
| Logout browser lifecycle | Host | Host; authorization adapters have no logout method | Integrated | Integrated |
| Logout response | `EndSessionResponse::{state,additional_parameters}` | `FfiEndSessionResponse` record | Result JSON | Result JSON |
| Token revocation | `revoke_token`, `RevocationTokenType` | `revoke`, string type hint | `appauth_windows_revoke` | `RevokeAsync` |
| Public-client registration | `ClientRegistrationRequest::{new,with_client_name,with_initial_access_token,register}`, response `client_id` | `register_public_client`, `FfiRegistrationOptions`, response `client_id` | Not exposed | Not exposed |
| Cancellation signal | `CancellationHandle::{new,cancel,is_cancelled,cancelled}` | Same methods on `FfiCancellationHandle`; adapter `cancel` | `appauth_windows_cancellation_{new,cancel,free}` | `CancellationToken` |
| HTTP transport | `HttpTransport::execute`, `ReqwestTransport::new` | `NativeHttpTransport::execute`; supplied native implementations | Internal | Internal |
| Error handling | `AuthError`, `Result` | `FfiError` and adapter errors | Result status/value/free | Exceptions from wrapper |
| Local sign-out | Host | Host | Host | Host |

## Public data and support types

The operation table includes all public constructors and methods in the core
and UniFFI facade. These records and enums form their input/output contracts:

- Core `TokenResponse`: access token, type, optional lifetime/refresh token/
  scope/ID Token, and additional JSON-valued parameters. `RevocationTokenType`:
  `AccessToken` or `RefreshToken`. `AuthenticationState` implements Serde.
- Core `HttpRequest` and `HttpResponse`: method/URL or status, headers and body;
  `HttpTransport` and `ReqwestTransport` define execution. `CancellationHandle`
  is cloneable and has a default constructor.
- UniFFI HTTP records: `FfiHttpHeader` (name/value bytes), `FfiHttpRequest`
  (method/URL/headers/body), `FfiHttpResponse` (status/headers/body).
- UniFFI parameter records: `FfiParameter` (name/value strings),
  `FfiJsonParameter` (name/value_json). `FfiTokenResponse` mirrors token fields,
  with additional JSON values represented by `FfiJsonParameter`.
- UniFFI options: `FfiAuthorizationOptions` (client, redirect, scopes, both
  parameter arrays), `FfiRegistrationOptions` (redirects, optional client name
  and initial access token), `FfiEndSessionOptions` (client, optional ID Token
  hint and redirect). `FfiClientRegistrationResponse` exposes `client_id`;
  `FfiEndSessionResponse` exposes state and additional parameters.
- Errors: [core enum](../src/error.rs), [UniFFI enum](../src/ffi.rs), and
  [cross-language error categories](user-guide.md#cancellation-timeouts-and-errors).
- Native adapters: Swift authorization initializers, `authorize` and `cancel`,
  iOS presentation context and ephemeral-session option, macOS browser-opening
  closure, Android redirect configuration, adapter exceptions and callback activity. See
  [Apple source](../native/apple/IOSAuthorizationAdapter.swift),
  [macOS source](../native/apple/MacOSAuthorizationAdapter.swift),
  [Android source](../native/android/src/main/kotlin/com/projectflora/appauth/AndroidAuthorizationAdapter.kt)
  and [internal redirect selection implementation](../native/android/src/main/kotlin/com/projectflora/appauth/AndroidRedirectSelector.kt)
  (the selector is not public API).
- All Windows handles, aliases, status constants, ten exported functions and
  four wrapper methods are listed in the [Windows reference](windows-api.md).

## Documentation, examples and verification

The following is a source-to-check map, not a report of successful runs.
Run the affected commands and record the commit/run URL when updating a guide.

| Operation group | Explanation / existing example | Verification source | Remaining documentation |
| --- | --- | --- | --- |
| Configuration, authorize, callback, exchange, nonce | [Shared guide](user-guide.md), [Rust example](../examples/manual_authorization.rs), [native notes](../README.md#native-bindings) | [Protocol integration](../tests/protocol_integration.rs), core/FFI unit tests, native flow scripts below | Complete Swift/Kotlin/C++/.NET examples: #85–#88 |
| Tokens, expiry, save/restore, refresh | [State lifecycle](user-guide.md#save-restore-and-refresh), [Windows JSON example](../native/windows/README.md#token-refresh) | Core/FFI state and refresh unit tests; Windows consumer fixtures | Platform secure-storage and refresh examples: #85–#88 |
| End-session, revoke, local deletion | [Logout policy](user-guide.md#logout-revocation-and-local-deletion), [Windows examples](../native/windows/README.md#end-session) | Core/FFI and Windows unit tests; Windows consumer fixtures | Swift/Kotlin browser/callback examples; complete language examples: #85–#88 |
| Registration and additional parameters | [API reference entry points](README.md#api-reference), core/FFI source | Protocol integration and core/FFI unit tests | Swift/Kotlin examples: #85/#86; Windows limit: #87/#88 |
| Cancellation, errors, transport | [Shared error guide](user-guide.md#cancellation-timeouts-and-errors), [Windows contract](windows-api.md) | Core/FFI unit tests, native lifecycle/transport tests | Direct-operation cancellation and language error examples: #85–#88 |
| Installation and public binding calls | [Language entry points](README.md) | [Consumer fixtures](../native/consumer-smoke), release consumer scripts | Full guide and API coverage is broader than consumer smoke; packaging: #89 |

Repository checks:

```sh
cargo doc --locked --no-deps
cargo test --locked --doc
cargo check --locked --example manual_authorization
cargo test --locked --workspace --all-targets --all-features
```

Platform checks require their host SDKs and tools:

- Apple: `scripts/check-apple-adapters.sh`,
  `scripts/check-ios-authorization-flow.sh`,
  `scripts/check-apple-release-consumer.sh <archive>`.
- Android: `./native/android/gradlew -p native/android testDebugUnitTest`,
  `./native/android/gradlew -p native/android connectedDebugAndroidTest`,
  `scripts/check-android-release-consumer.sh <aar>`.
- Windows: `scripts/check-windows-release-consumer.ps1 -Package <archive>`;
  C++ and .NET use the same packaged DLL. Windows unit tests additionally
  exercise mock callback and protocol behavior.

Consumer fixtures check only their implemented scenarios. They do not prove
every operation in this table, mobile real-device execution, or live IdP
interoperability. See [support limits](support-matrix.md) and
[interoperability status](live-idp-interoperability.md). Language-guide work
must add checks for its new examples where existing fixtures do not cover them.
