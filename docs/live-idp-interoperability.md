# Live identity-provider interoperability status

This document records live identity-provider interoperability that is
explicitly unverified for the 1.0.0 release. It complements the local
mock-provider checks in CI; it does not introduce provider-specific behavior
into the library.

## Scope and recording policy

The project does not operate dedicated IdP tenants, Keycloak hosting, or
mobile callback-domain infrastructure solely for library validation.
Consequently, no live provider or real-device result is required for 1.0.0,
and the matrix below remains **not verified**.

If a future release explicitly scopes a live interoperability effort, validate
these providers:

| Provider | Purpose |
| --- | --- |
| Keycloak | Controlled OIDC baseline and reproducible negative cases |
| Microsoft Entra ID | Enterprise SaaS OIDC interoperability |
| Auth0 | SaaS OIDC interoperability with a distinct implementation |

For each applicable provider and platform, a result is acceptable only when an
authorization code flow completes through the real system browser and the
library completes its documented validation. Record the provider tenant or
realm only by a non-sensitive label; never record a token, credential, client
secret, or test user's identifying information.

Any future result must include the date, AppAuth-Rust revision or release
candidate, OS and browser version, redirect type, ID Token signing algorithm,
and a status of **passed**, **limited**, **failed**, or **not verified**. A
limited or failed result must link to an issue that explains the constraint or
fix.

## Prerequisites for future live validation

The following requirements apply only if the project resumes live
interoperability validation:

- Create isolated test tenants or realms and native **public** clients for
  each provider. Do not configure a client secret.
- Create non-production test users. Keep their credentials in the team's
  approved secret store, not in this repository, GitHub Issues, workflow
  variables, or test output.
- Use a publicly trusted HTTPS Keycloak deployment for OIDC validation. The
  Rust `ReqwestTransport` uses the WebPKI root set and does not trust a
  self-signed or locally generated certificate by default.
- Provision a dedicated HTTPS test domain before testing iOS/iPadOS and
  Android verified links. Follow the [HTTPS callback domain
  procedure](https-callback-domain.md); it includes association-file templates
  and required DNS, TLS, and static-hosting ownership records. The domain is
  currently **not yet selected**.
- Register each provider redirect URI according to its native-app registration
  policy. Confirm that its loopback registration permits the adapter's
  dynamically assigned port; a provider that requires a fixed port is a
  compatibility result, not a reason to weaken the loopback implementation.
- Use separate clients when a provider cannot register all required redirect
  URIs on one public client. Record the non-sensitive client label only.

### Local Keycloak baseline

The repository includes a local Keycloak configuration at
`tests/live-idp/keycloak`. It imports the `appauth-rust-live` realm and its
`appauth-rust-desktop` public client. That client permits loopback redirects
on `127.0.0.1` and requires S256 PKCE. This service is HTTP-only and is for
client-registration and redirect-configuration development only. It must not
be used to mark discovery, ID Token, or JWKS validation as passed: OIDC
discovery and JWKS endpoints require HTTPS.

1. Copy `tests/live-idp/keycloak/.env.example` to
   `tests/live-idp/keycloak/.env` and replace the administrator password with
   a local-only value. The `.env` file is ignored by Git.
2. Start the service:

   ```sh
   docker compose --env-file tests/live-idp/keycloak/.env \
     -f tests/live-idp/keycloak/docker-compose.yml up -d
   ```

3. Open `http://127.0.0.1:8080`, create a non-production test user in the
   `appauth-rust-live` realm, and give it a local-only password.
4. Verify the non-sensitive client and redirect configuration. Run the
   acceptance cases only against a Keycloak deployment with a publicly trusted
   HTTPS endpoint, then record the result in the matrix below.

Stop and remove the local service when finished:

```sh
docker compose --env-file tests/live-idp/keycloak/.env \
  -f tests/live-idp/keycloak/docker-compose.yml down
```

## Cases for future live validation

| ID | Flow | Expected result |
| --- | --- | --- |
| LIP-01 | Discovery | The issuer discovery document supplies usable authorization, token, issuer, and JWKS endpoints. |
| LIP-02 | Authorization Code + PKCE | A real browser authorization returns a code; S256 PKCE, exact redirect, and state validation succeed. |
| LIP-03 | OIDC ID Token | An `openid` request returns an ID Token whose issuer, audience, nonce, time claims, and JWKS signature validation succeed. Record the issued signing algorithm. |
| LIP-04 | Refresh | Where the provider issues a refresh token to the public client, refresh succeeds and a returned ID Token is validated. Otherwise record the provider policy and mark this case limited. |
| LIP-05 | Cancellation and denial | User cancellation and consent denial are reported as the documented cancellation or authorization-server error; no token state is persisted. |
| LIP-06 | Callback routing | A callback for a different path, redirect URI, or state does not complete the active operation. |

The existing mock-provider tests remain the required coverage for generated
negative cases and algorithms that no selected live provider issues. Live
testing verifies actual discovery metadata, key material, browser behavior,
and callback delivery.

## CI boundary

Ordinary pull-request CI uses local mock providers only. It must not depend on
live IdP availability or access live-tenant credentials.

No live IdP workflow is part of the current release scope. Do not add one
without an explicit decision to operate the required environments and to
define credential ownership, rotation, and log-safety controls.

GitHub-hosted simulator and emulator jobs are regression checks; they do not
establish real-device verified-link or App Link interoperability.

## Platform redirect coverage

| Platform | Expected redirect validation if live testing resumes |
| --- | --- |
| iOS / iPadOS | Verified HTTPS callback with the associated domain on a real device; custom URI scheme fallback. |
| Android | Verified App Link with the release-signing certificate on a real device; custom URI scheme fallback. |
| macOS | Loopback callback with a dynamically allocated port in the system browser. |
| Windows | Loopback callback with a dynamically allocated port in the system browser. |

Simulator and emulator checks remain useful regression tests but do not
replace the real-device verified-link results above.

## Unverified interoperability matrix

The project does not claim live-provider interoperability for these rows.
They must not be represented as passed or as a supported integration without
recorded validation evidence.

| Provider | Platform | Redirect | Cases | Status | Evidence / limitation |
| --- | --- | --- | --- | --- | --- |
| Keycloak | iOS / iPadOS | HTTPS verified link | LIP-01–06 | not verified | Dedicated IdP and callback-domain infrastructure is not operated |
| Keycloak | Android | App Link | LIP-01–06 | not verified | Dedicated IdP and callback-domain infrastructure is not operated |
| Keycloak | macOS | Loopback | LIP-01–06 | not verified | Dedicated IdP infrastructure is not operated |
| Keycloak | Windows | Loopback | LIP-01–06 | not verified | Dedicated IdP infrastructure is not operated |
| Microsoft Entra ID | iOS / iPadOS | HTTPS verified link | LIP-01–06 | not verified | Dedicated IdP and callback-domain infrastructure is not operated |
| Microsoft Entra ID | Android | App Link | LIP-01–06 | not verified | Dedicated IdP and callback-domain infrastructure is not operated |
| Microsoft Entra ID | macOS | Loopback | LIP-01–06 | not verified | Dedicated IdP test tenant is not operated |
| Microsoft Entra ID | Windows | Loopback | LIP-01–06 | not verified | Dedicated IdP test tenant is not operated |
| Auth0 | iOS / iPadOS | HTTPS verified link | LIP-01–06 | not verified | Dedicated IdP and callback-domain infrastructure is not operated |
| Auth0 | Android | App Link | LIP-01–06 | not verified | Dedicated IdP and callback-domain infrastructure is not operated |
| Auth0 | macOS | Loopback | LIP-01–06 | not verified | Dedicated IdP test tenant is not operated |
| Auth0 | Windows | Loopback | LIP-01–06 | not verified | Dedicated IdP test tenant is not operated |

## Release status

Live identity-provider interoperability is not a 1.0.0 release gate. The
unverified matrix is a documented limitation, not evidence of compatibility.
If the project resumes live validation, record its evidence and limitations in
this document before representing a provider or platform integration as
validated.
