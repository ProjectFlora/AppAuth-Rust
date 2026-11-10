# HTTPS callback domain for mobile validation

This directory prepares the static association files required by issue #50.
It is not a deployed callback domain. Do not publish either file while it
contains a value enclosed in `<` and `>`.

## Required configuration

Choose a dedicated non-production subdomain, such as
`auth-callback-test.example.org`, and use this callback path for both mobile
platforms:

```text
https://auth-callback-test.example.org/oauth/callback
```

The domain must be controlled by the project, serve a publicly trusted TLS
certificate, and be kept separate from production authentication endpoints.
Record the selected domain and operational ownership in the table below before
registering redirect URIs with any identity provider.

| Item | Required record |
| --- | --- |
| Callback domain | Fully qualified domain name |
| DNS owner | Team or role responsible for DNS changes |
| TLS certificate owner | Team or role responsible for renewal and expiry alerts |
| Static hosting owner | Team or role responsible for association-file deployment |
| Review cadence | At least before every release candidate and before certificate expiry |

## Publish the association files

1. Replace every placeholder in
   `docs/https-callback-domain/.well-known/apple-app-site-association`:
   - `<APPLE_TEAM_ID>` is the Apple Developer Team ID.
   - `<IOS_BUNDLE_ID>` is the bundle ID of the physical-device validation app.
2. Replace every placeholder in
   `docs/https-callback-domain/.well-known/assetlinks.json`:
   - `<ANDROID_APPLICATION_ID>` is the application ID of the physical-device
     validation app.
   - `<ANDROID_RELEASE_SIGNING_CERTIFICATE_SHA256>` is the SHA-256 fingerprint
     of the certificate used to sign that app's release build. Do not use a
     debug or upload-key fingerprint unless that is the certificate installed
     on the device.
3. Publish the files unchanged in name at these exact HTTPS URLs:

   ```text
   https://<callback-domain>/.well-known/apple-app-site-association
   https://<callback-domain>/.well-known/assetlinks.json
   ```

   The URLs must return `200 OK`, use `Content-Type: application/json`, and
   not redirect. Do not require authentication or set a browser download
   disposition.
4. Configure the iOS/iPadOS validation app with the associated-domain
   entitlement `webcredentials:<callback-domain>`. Its HTTPS callback must be
   `https://<callback-domain>/oauth/callback`.
5. Configure the Android validation app with an exported
   `AndroidAuthorizationCallbackActivity` intent filter for the same host and
   path, including `android:autoVerify="true"`. Its HTTPS callback must be
   `https://<callback-domain>/oauth/callback`.
6. Register that exact callback URI for each public client in Keycloak,
   Microsoft Entra ID, and Auth0. Keep client labels and redirect URIs
   non-sensitive; never add credentials, tokens, or client secrets here.

## Verify before live testing

Run the following checks after deployment, replacing `<callback-domain>`:

```sh
curl --fail --silent --show-error --location --max-redirs 0 \
  -D - "https://<callback-domain>/.well-known/apple-app-site-association" -o /dev/null
curl --fail --silent --show-error --location --max-redirs 0 \
  -D - "https://<callback-domain>/.well-known/assetlinks.json" -o /dev/null
```

Confirm both responses are `200`, have `Content-Type: application/json`, and
contain no placeholder values. On real devices, confirm iOS/iPadOS accepts the
associated domain and Android reports the host as verified before running the
mobile rows in [live identity-provider interoperability validation](live-idp-interoperability.md).

Record the selected domain, callback path, association-file URLs, and the
owners from the table in issue #41's results table. The iOS/iPadOS and Android
rows remain **not tested** until those real-device checks and LIP-01 through
LIP-06 complete.
