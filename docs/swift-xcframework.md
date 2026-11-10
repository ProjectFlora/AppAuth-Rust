# Swift XCFramework installation

The Apple release asset contains a static `AppAuthRust.xcframework` for iOS
device, iOS simulator, and macOS, plus the generated Swift bindings. It
supports iOS/iPadOS 18 and later and macOS 15 and later. Mac Catalyst and
other Apple platforms are not included.

## Download and verify

Download `AppAuthRust-Apple-<version>.zip` and `SHA256SUMS` from the same
[GitHub Release](https://github.com/ProjectFlora/AppAuth-Rust/releases/tag/v0.2.0). From the directory containing both files, verify the archive:

```sh
VERSION=0.2.0
grep -F "AppAuthRust-Apple-$VERSION.zip" SHA256SUMS | shasum -a 256 -c
unzip "AppAuthRust-Apple-$VERSION.zip"
```

Replace `0.2.0` with the release version you downloaded. The archive extracts
to `AppAuthRust-Apple/`.

## Add the package to Xcode

For each iOS/iPadOS or macOS app target:

1. Add `AppAuthRust-Apple/AppAuthRust.xcframework` to the Xcode project and
   select the app target. In **Frameworks, Libraries, and Embedded Content**,
   set it to **Do Not Embed**; it contains static libraries.
2. Add `AppAuthRust-Apple/Swift/appauth_rust.swift` to the project and make
   sure the app target is selected under **Target Membership**. The generated
   Swift bindings and XCFramework must come from the same release archive.
3. Set the target's minimum deployment version to iOS/iPadOS 18 or macOS 15,
   as appropriate.

The XCFramework includes the FFI header and module map; do not add them
separately. The package does not include Mac Catalyst, tvOS, or watchOS
libraries.

## Configure authorization callbacks

- On iOS/iPadOS, use `IOSAuthorizationAdapter` with an
  `ASWebAuthenticationPresentationContextProviding` implementation. For an
  HTTPS redirect, configure the `webcredentials:<host>` associated domain and
  the matching server association; for a custom-scheme fallback, register the
  scheme in the app target and with the authorization server.
- On macOS, configure a loopback redirect such as
  `http://127.0.0.1/oauth/callback`. The adapter binds an ephemeral port on
  IPv4 loopback and launches the authorization URL in the external browser.

Authorization uses the external browser, not a WebView. The host app remains
responsible for securely persisting and encrypting authentication state. See
the [Apple adapter notes](https://github.com/ProjectFlora/AppAuth-Rust#apple-adapters)
for callback behavior, cancellation, and native HTTP transport requirements.
