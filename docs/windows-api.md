# Windows ABI and .NET reference

Return to the [documentation index](README.md). This reference supplements
the release's Linux-generated rustdoc, which excludes the Windows module.
Use the [Windows user guide](../native/windows/README.md) for JSON examples
and the [public header](../native/windows/include/appauth_windows.h) for
declarations. This describes the source revision being read, not a new ABI.

## C ABI

All exported calls use the C calling convention. Operation input is a
NUL-terminated UTF-8 JSON object. Operations block: call them from a worker
thread, keeping input and handles alive until return. Supported distribution
architecture is `x86_64-pc-windows-msvc`.

| Function | Contract |
| --- | --- |
| `appauth_windows_cancellation_new` | Returns an owned opaque cancellation handle |
| `appauth_windows_cancellation_cancel` | Signals cancellation; may be called from another thread; null is ignored |
| `appauth_windows_cancellation_free` | Releases the handle after all calls using it return; null is allowed |
| `appauth_windows_authorize` | Opens browser, validates loopback callback, exchanges code; returns authentication-state JSON on success |
| `appauth_windows_refresh` | Refreshes the supplied state; returns replacement authentication-state JSON on success |
| `appauth_windows_end_session` | Opens browser; with redirect waits for validated loopback callback and returns response JSON; otherwise returns an empty success value |
| `appauth_windows_revoke` | Revokes the supplied token; returns an empty success value |
| `appauth_windows_authorization_result_status` | Reads status from any operation result |
| `appauth_windows_authorization_result_value` | Borrows a UTF-8 string owned by the result; copy it before freeing the result |
| `appauth_windows_authorization_result_free` | Releases any operation result; do not use its pointers afterward |

`AppAuthWindowsCancellationHandle` and `AppAuthWindowsAuthorizationResult`
are opaque. `AppAuthWindowsRefreshResult`, `AppAuthWindowsEndSessionResult`
and `AppAuthWindowsRevocationResult` alias the authorization result type;
the same result accessors and free function apply to all four operations.

| Status constant | Value | Result value |
| --- | --- | --- |
| `APPAUTH_WINDOWS_AUTHORIZATION_SUCCESS` | 0 | Operation-specific value above |
| `APPAUTH_WINDOWS_AUTHORIZATION_ERROR` | 1 | Diagnostic error text |
| `APPAUTH_WINDOWS_AUTHORIZATION_CANCELLED` | 2 | Cancellation message |

Errors flatten configuration, validation, provider, HTTP, transport and
platform failures into text. There is no structured error-code/status API
beyond the three statuses; do not parse diagnostic strings as stable fields.

## Request and response fields

Each operation discovers configuration from `issuer`, or uses both
`authorization_endpoint` and `token_endpoint`. One explicit endpoint alone
is invalid. With explicit endpoints, authorize/refresh need both `issuer`
and `jwks_uri` when validating ID Tokens. Revocation/end-session require
their operation endpoint with explicit configuration; a supplied operation
endpoint overrides the discovered one. Endpoint URLs use HTTPS.

| Operation | Required operation fields | Optional fields |
| --- | --- | --- |
| Authorize | `client_id`, `redirect_uri`, `scopes` | `additional_parameters`, `additional_token_parameters` |
| Refresh | `client_id`, `state` (JSON object, not a JSON-encoded string) | `additional_parameters` |
| End-session | `client_id` | `end_session_endpoint`, `id_token_hint`, `post_logout_redirect_uri` |
| Revoke | `client_id`, `token` | `revocation_endpoint`, `token_type_hint` (`access_token` or `refresh_token`) |

Parameter arrays contain `{ "name": "...", "value": "..." }` objects.
Duplicate names and reserved token-request parameters are rejected.
Authorize's redirect and end-session's optional post-logout redirect must
be portless `http://127.0.0.1/...` templates. The adapter substitutes a free
port, binds to loopback and checks the callback against that operation.
End-session callback success returns `state` and `additional_parameters`.
No redirect means browser launch success, not confirmed provider logout.

Authentication-state JSON contains `token_response`, optional `expires_at`
(absolute Unix seconds), and optional `oidc_nonce`. Token response contains
`access_token`, `token_type`, optional `expires_in`, `refresh_token`, `scope`,
`id_token`, and preserved additional response fields. Persist the complete
returned JSON unchanged so expiry and nonce survive restoration. The host
may inspect it with its JSON library; the ABI has no separate token or expiry
accessors. See the [state lifecycle](user-guide.md#save-restore-and-refresh).

The ABI has no standalone discovery, dynamic registration, manual
authorization-session, or expiry-predicate functions. These shared-core
features must not be presented as Windows ABI operations.

## .NET wrapper

The [wrapper](../native/windows/dotnet/AppAuthWindows.cs) in namespace
`ProjectFlora.AppAuthRust` targets .NET Standard 2.1 and loads
`appauth_rust.dll` using P/Invoke with UTF-8 strings and Cdecl.

| Method | Return |
| --- | --- |
| `AppAuthWindows.AuthorizeAsync(requestJson, cancellationToken)` | `Task<string>`: state JSON |
| `AppAuthWindows.RefreshAsync(requestJson, cancellationToken)` | `Task<string>`: updated state JSON |
| `AppAuthWindows.EndSessionAsync(requestJson, cancellationToken)` | `Task<string>`: callback JSON or empty string |
| `AppAuthWindows.RevokeAsync(requestJson, cancellationToken)` | `Task`: no value |

All methods accept a string and optional `CancellationToken`. They run the
blocking call on a worker, register cancellation and release native handles.
Null input throws `ArgumentNullException`; native cancellation becomes
`OperationCanceledException`; other native errors or unusable native results
become `InvalidOperationException`. Deployment/loading errors can also surface
from P/Invoke. There are no additional typed discovery, state, registration
or expiry APIs in the wrapper. Installation and complete C# examples are
tracked by [#88](https://github.com/ProjectFlora/AppAuth-Rust/issues/88).
