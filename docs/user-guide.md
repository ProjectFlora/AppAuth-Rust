# Shared user guide

Return to the [documentation index](README.md). Language-specific entry points
and the [API coverage matrix](api-coverage.md) identify the concrete APIs.

## Configure a native public client

Register a native public client and the exact redirect URIs with your provider.
Do not embed a client secret. Discover configuration from an HTTPS issuer, or
provide explicit HTTPS endpoints. For explicit OIDC configuration, include
both issuer and JWKS URI. Requests with the `openid` scope require OIDC
validation configuration; returned ID Tokens are verified before exposure.
Optional end-session, revocation, and registration endpoints must be supported
by the provider and discovered or explicitly configured before use.

Rust callers supply an async transport and, for `ReqwestTransport`, a Tokio
runtime. Swift and Kotlin callers supply `NativeHttpTransport`; the supplied
URLSession and URLConnection implementations can be used. A custom transport
must return HTTP redirects without following them and propagate cancellation.
The supplied native transports disable platform HTTP caching; the core owns
JWKS freshness. Windows operations use their internal runtime and transport.

## Authorize and retain state

Start the platform callback handler or loopback listener before opening the
external browser. The adapters manage this for authorization. Use verified
HTTPS callbacks on mobile where configured, with registered custom schemes
as fallback; desktop adapters use a dynamically allocated IPv4 loopback port.
The core validates the complete callback and state before code exchange.

Rust callers use `AuthorizationSession::authentication_state` after exchange
to retain the authorization nonce. UniFFI exchange and the platform adapters
already return authentication state; Windows returns its JSON serialization.
Do not reconstruct state from only an access token: expiry, refresh token,
and OIDC nonce are needed for later operations.

Read token values from state to call the resource server. Access-token expiry
is an optional Unix timestamp in seconds. An unknown expiry is not proof that
a token is valid indefinitely. The library does not automatically refresh
tokens or retry resource-server calls. ID Tokens are identity assertions;
use the access token for resource-server authorization.

## Save, restore, and refresh

Serialize the complete state using Serde in Rust or `to_json` in UniFFI;
Windows authorization and refresh already return JSON. Persist it using
host-managed secure storage and encryption. Keep tokens, nonce, and state
JSON out of logs. Restore the full JSON using Serde, UniFFI `from_json`, or
the Windows refresh request's `state` object. Restoration does not contact
the provider or prove that previously issued tokens are still accepted.

The host associates stored state with the correct issuer, client ID, and
configuration; state JSON does not contain that complete configuration.
Retain the original absolute expiry instead of recalculating it from
`expires_in` on each application launch.

Refresh requires a non-empty refresh token. Rust and UniFFI update state only
after a successful response and any returned ID Token validation. Windows
returns a replacement state JSON. Persist the updated complete state after
every success, including refresh-token rotation. A missing refresh token,
scope, or ID Token in a successful refresh response retains the old value.

On failure or cancellation, the local previous state is unchanged. This does
not guarantee that the server still accepts its tokens: a refresh may reach
the server before the response is lost. The host decides retry or
reauthentication policy, including how to handle `invalid_grant`. Serialize
refresh and logout at the application level so a late refresh cannot restore
state after local logout. Protect the write to persistent storage as well as
the in-memory update.

## Logout, revocation, and local deletion

| Action | Effect | Host responsibility |
| --- | --- | --- |
| OIDC end-session | Opens the provider's RP-Initiated Logout URL; optionally validates a post-logout callback | Manage browser/callback lifecycle where no logout adapter exists; delete local state separately |
| OAuth token revocation | Requests invalidation of the supplied access or refresh token | Choose the token and optional type hint; own retries; delete local state even on failure or cancellation |
| Local state deletion | Removes the application's stored credentials | Clear stored and in-memory state; prevent concurrent operations from writing it back |

End-session requires an HTTPS end-session endpoint. An ID Token hint and
post-logout redirect are optional. With a redirect, retain the prepared logout
session and validate the callback/state. Without one, opening the browser is
not confirmation that the provider completed logout. Swift/Kotlin expose URL
construction and callback validation, but their existing authorization
adapters do not provide a logout method. Rust similarly leaves browser work
to the host. Windows handles the browser and optional loopback callback.

Revocation requires an HTTPS revocation endpoint. HTTP 200 completes the
operation even for an already-invalid token; it does not delete local state.
Failure does not confirm remote invalidation. The library does not retry
automatically or expose Retry-After. If logout policy attempts network cleanup,
retain only the values needed for that attempt, and ensure local deletion
runs even if cleanup fails or is cancelled. Do not make local sign-out depend
on provider availability.

## Cancellation, timeouts, and errors

Cancellation handles are shared signals. Calling `cancel` is idempotent; a
cancelled handle stays cancelled, so use a new handle for a new operation.
The host owns authorization timeout policy. Cancellation stops active work
where supported, but cannot undo a request already processed by the provider.
macOS and Windows cannot dismiss the external browser; Android does not
promise to close the Custom Tab. iOS cancels its authentication session.
Swift Task and Kotlin coroutine cancellation are connected by the supplied
authorization adapters; direct core/UniFFI operations use their explicit
handle. Follow each language guide for lifecycle integration.

| Failure category | Rust / UniFFI | Windows / .NET |
| --- | --- | --- |
| Caller configuration | `InvalidConfiguration` / `InvalidRequest` | Error status / `InvalidOperationException` |
| Invalid protocol response or ID Token | Specific validation errors / `InvalidResponse` | Error status / `InvalidOperationException` |
| Provider rejection | `AuthorizationServer`, `ClientRegistrationServer` with code and optional description | Error message; no structured OAuth fields |
| HTTP or network | `HttpStatus`, `Transport`, `TransportFailure` | Error message; no structured HTTP fields |
| Cancellation | `Cancelled` | Cancelled status / `OperationCanceledException` |
| Platform/browser/listener | Adapter-specific errors | Error status / `InvalidOperationException` |

Rust also exposes clock/randomness failures; UniFFI exposes clock/randomness
and internal failures. Rust's error enum is non-exhaustive. Preserve cancellation
as a distinct result, avoid parsing Windows error text into a protocol contract,
and present provider descriptions as untrusted diagnostic text. Apply host retry
policy to transient failures; validation errors need investigation rather than
blind retries. See the [Windows contract](windows-api.md) for exact statuses.

## Structure for the language guides

The follow-up guides use this common sequence, with concrete imports, request
construction, and compilable examples for their language:

1. Supported versions, download/checksum, dependencies, installation and build.
2. Provider configuration, transport, callback registration and platform setup.
3. Authorization, token access and expiry.
4. Secure state persistence and restoration.
5. Explicit refresh and persistence of updated state.
6. End-session, revocation and local sign-out.
7. Dynamic registration and additional parameters where exposed.
8. Cancellation, timeout policy, errors and platform lifecycle constraints.
9. Example verification commands, evidence and known limits.

Common behavior is documented here; platform-specific setup and executable
examples remain in #85–#88. Sample storage abstractions must say which work
the application still needs to implement.
