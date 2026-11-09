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
- Preserve unrecognized response parameters as opaque values without
  interpreting provider-specific semantics.
- Model authentication state in the Rust core and make it serializable; host
  applications are responsible for persistence and encryption.
- Expose explicit cancellation for in-flight operations, distinguish it from
  authorization-server errors, and propagate it to active work where the
  platform and transport allow.
- Use an asynchronous HTTP transport abstraction, with a Rust `reqwest`
  implementation by default and the option for native adapters to provide
  their own transport. Rust callers provide the Tokio runtime used by the
  default transport.
- Use the external browser for authorization; do not embed the flow in a
  WebView.
- Keep OAuth/OIDC protocol handling in the shared Rust core.

## Support baseline

| Platform | Minimum | Initial-release support |
| --- | --- | --- |
| iOS / iPadOS | 18 | Rust core and native authorization adapter |
| macOS | 15 | Rust core and native authorization adapter |
| Android | API 34 (Android 14) | Rust core and native authorization adapter |
| Windows | Microsoft-supported Windows client versions; reviewed each release | Rust core and desktop authorization adapter |
| tvOS | Not applicable | Deferred |

The Apple minimums follow the security-update generations reviewed on
2026-11-08. Android API 34 is provisional. Recheck both the supported OS
versions and Android device reach immediately before release.

## Redirect policy

- **iOS / iPadOS:** Prefer verified HTTPS redirects; allow a custom URI scheme
  fallback. AppAuth-iOS requires iOS 17.4+ and `webcredentials` domain
  association for HTTPS redirects.
- **Android:** Prefer verified Android App Links; allow a custom URI scheme
  fallback. App Links require API 23+ and domain association.
- **macOS:** Use an HTTP loopback redirect on a dynamically allocated port,
  bound only to the loopback interface.
- **Windows:** Use the external browser and an HTTP loopback redirect, bound
  only to the loopback interface.

## Authorization callback lifecycle

- Native adapters own browser launch and callback delivery. Register the
  callback handler or start the loopback listener before launching the external
  browser. A loopback listener is per authorization operation and binds only
  to the loopback interface.
- Ignore callbacks that do not target the active operation's registered
  redirect. For loopback requests to an unexpected path, return 404 and keep
  waiting.
- A callback to the registered redirect is terminal for the listener. Validate
  the exact redirect and state; malformed or duplicate parameters, a missing
  or mismatched state, conflicting `code` and `error`, or neither result is an
  invalid authorization response. A matching OAuth error is returned as an
  authorization-server error. Stop the listener before code exchange; ignore
  any later callback.
- Explicit cancellation and user dismissal of the authorization session
  return the distinct `Cancelled` result when reported by the platform.
  Cancellation is idempotent, stops listeners and active work, and dismisses
  the browser session where the platform permits. Platform launch or listener
  failures are surfaced as platform errors, not authorization-server errors.
- Do not impose an implicit authorization timeout. The host application owns
  timeout policy and cancels through the operation's cancellation handle.

## End-session / logout

- Use the discovered `end_session_endpoint` or configure one explicitly; it
  must use HTTPS. Providers without an end-session endpoint cannot use this
  flow.
- Build an RP-Initiated Logout URL with the client ID, optional ID Token hint,
  and optional post-logout redirect URI. When a redirect URI is supplied, the
  core generates state and validates the registered callback URI and returned
  state.
- The host application launches the external browser and handles its lifecycle.

## Dynamic client registration

- Use the discovered `registration_endpoint` or configure one explicitly; it
  must use HTTPS. The request registers a native public client with Authorization
  Code and refresh-token grants and `token_endpoint_auth_method=none`.
- A host may provide an initial access token for a protected registration
  endpoint per request; the library does not embed one.
- The response exposes only the client ID. Responses containing a client secret
  or specifying a non-native/confidential client are rejected.

## OpenID Connect ID Token validation

- Authorization requests containing `openid` require an issuer and `jwks_uri`
  from discovery or `with_oidc_validation_endpoints`. The code exchange rejects
  missing ID Tokens and verifies any returned ID Token before exposing it.
- Only RS256 and ES256 signatures are accepted. Issuer, audience, subject,
  expiry, issued-at time, authorized party, and the request nonce are checked;
  time checks allow 60 seconds of clock skew.
- JWKS responses follow their `Cache-Control` directives with a maximum
  300-second cache lifetime. An unknown `kid` triggers one JWKS refresh when a
  cached set was used. Refresh responses that include a new ID Token are also
  verified before authentication state is updated.
- Create state with `AuthorizationSession::authentication_state` after code
  exchange so the request nonce is persisted and checked on refresh. The
  returned serializable state contains tokens and nonce; the host application
  remains responsible for secure storage and encryption.

## Native bindings

- The UniFFI 0.32.2 API is exposed through `appauth_rust::ffi`. Generate Swift
  and Kotlin source with `scripts/generate-bindings.sh`; generated sources go
  under `target/uniffi` by default and should not be hand-edited.
- Native callers provide a `NativeHttpTransport` implementation. It must not
  follow redirects and receives the shared cancellation handle for every
  request. The Rust `ReqwestTransport` remains available to Rust callers that
  provide a Tokio runtime.
- Windows desktop applications use the C ABI in `native/windows/include` to
  run authorization in the system browser and receive a loopback callback.
  The ABI is callable from C++ and from .NET through P/Invoke; see
  [`native/windows/README.md`](native/windows/README.md).
- Generate the public Rust API reference locally with
  `cargo doc --locked --no-deps`; the HTML output is written to
  `target/doc/appauth_rust/index.html`.
- `examples/manual_authorization.rs` shows the shared Rust-core flow. It prints
  the authorization URL and asks the caller to paste the redirect URL; native
  applications should use the platform adapters for browser launch and
  callback delivery. Check the example with
  `cargo check --locked --example manual_authorization`.

The project is not yet published on crates.io, Swift Package Manager, Maven
Central, or Carthage. The initial native distribution decision is versioned
GitHub Release assets: an Apple XCFramework, Android AAR, and Windows DLL
package with C/C++ and .NET interop files. Those versioned packages and
checksums are not published yet.
The release workflow accepts only SemVer tags that point to `main` and match
the crate version. It publishes the Apple XCFramework, Android AAR, Windows
package, Rust API reference, and SHA-256 checksums. Do not tag v0.1.0 until the
remaining release-candidate checks are complete.

## Apple adapters

- `native/apple/IOSAuthorizationAdapter.swift` runs authorization in
  `ASWebAuthenticationSession`; HTTPS callbacks use Apple's verified callback
  matcher, and custom URI schemes are supported as a fallback. The host app
  must configure a `webcredentials:<host>` associated domain or register its
  custom URL scheme, and provide an
  `ASWebAuthenticationPresentationContextProviding` implementation.
- `native/apple/MacOSAuthorizationAdapter.swift` accepts a redirect template
  such as `http://127.0.0.1/oauth/callback`, replaces its port with a
  dynamically allocated port, and binds the listener only to IPv4 loopback.
  Unexpected paths receive 404 while the adapter continues waiting.
- Cancelling the iOS adapter or Swift task dismisses its authentication
  session; iOS-reported browser dismissal maps to `FfiError.Cancelled`.
  Cancellation on either adapter stops its callback wait and cancels
  in-flight core work. The macOS adapter cannot dismiss the external browser.
  `URLSessionNativeHttpTransport` refuses HTTP redirects and forwards
  cancellation to `URLSession`.
- Run `scripts/check-apple-adapters.sh` to regenerate the bindings, type-check
  the adapters against the iOS and macOS SDKs, and smoke-test the macOS
  loopback listener.

## Apple binary package

- Build a package for a specific version with
  `scripts/package-apple-xcframework.sh 0.1.0`. It creates
  `target/apple/release-package/AppAuthRust-Apple-0.1.0.zip`, containing an
  `AppAuthRust.xcframework` with static Rust libraries for iOS device,
  iOS simulator, and universal macOS, the generated Swift API source, and an
  installation guide. See [Swift XCFramework installation](docs/swift-xcframework.md).
  The CI `apple-xcframework` artifact is for validation and expires after
  14 days. Versioned GitHub Release assets and checksums remain pending.

## Android adapter

- `native/android` launches authorization in a Custom Tab. It uses the HTTPS
  App Link redirect only when Android reports the host as verified and the
  configured callback activity resolves for that URI; otherwise it selects
  the registered custom-scheme fallback.
- Declare both registered redirect URIs with the authorization server. The
  host app must register
  `com.projectflora.appauth.AndroidAuthorizationCallbackActivity` with
  `android:exported="true"` and browsable intent filters for those URIs. Set
  `android:autoVerify="true"` on the HTTPS filter and host the matching
  `assetlinks.json` file. The adapter ignores callbacks that do not match the
  active redirect's scheme, host, port, and path; the Rust core validates the
  complete callback and state.
- For example, add these filters to the callback activity in the host app's
  manifest, replacing the sample host and scheme with the registered values:

  ```xml
  <activity
      android:name="com.projectflora.appauth.AndroidAuthorizationCallbackActivity"
      android:exported="true"
      android:noHistory="true">
      <intent-filter android:autoVerify="true">
          <action android:name="android.intent.action.VIEW" />
          <category android:name="android.intent.category.DEFAULT" />
          <category android:name="android.intent.category.BROWSABLE" />
          <data
              android:scheme="https"
              android:host="login.example.com"
              android:path="/oauth/callback" />
      </intent-filter>
      <intent-filter>
          <action android:name="android.intent.action.VIEW" />
          <category android:name="android.intent.category.DEFAULT" />
          <category android:name="android.intent.category.BROWSABLE" />
          <data
              android:scheme="com.example.app"
              android:path="/oauth/callback" />
      </intent-filter>
  </activity>
  ```

- Pass both URIs in `AndroidRedirectConfiguration`; the adapter selects the
  verified HTTPS App Link when available and otherwise uses the custom scheme.
  Supply a native transport when authorizing:

  ```kotlin
  val adapter = AndroidAuthorizationAdapter(activity)
  val state = adapter.authorize(
      configuration,
      options,
      AndroidRedirectConfiguration(
          appLinkUri = "https://login.example.com/oauth/callback",
          customSchemeUri = "com.example.app:/oauth/callback",
      ),
      UrlConnectionNativeHttpTransport(),
  )
  ```

- `UrlConnectionNativeHttpTransport` does not follow HTTP redirects and
  disconnects active requests when its cancellation handle is cancelled.
  `AndroidAuthorizationAdapter.cancel()` stops the callback wait and cancels
  core work; the host remains responsible for authorization timeout policy.
- Build and run the adapter unit tests with
  `./native/android/gradlew -p native/android testDebugUnitTest`. The module
  targets the documented Android API 34 minimum and regenerates UniFFI Kotlin
  bindings under its build directory.
- Build the release AAR with
  `ANDROID_NDK_HOME=/path/to/ndk ./native/android/gradlew -p native/android assembleRelease`.
  The AAR includes Rust shared libraries for `arm64-v8a` and `x86_64`; CI
  verifies both entries and uploads the AAR as a workflow artifact. The
  current output is
  `native/android/build/outputs/aar/appauth-rust-android-release.aar`.
- The CI `android-aar` artifact can be copied into an Android app's `libs`
  directory and consumed with `implementation(files("libs/appauth-rust-android-release.aar"))`.
  Because a raw AAR has no dependency metadata, also declare the runtime
  dependencies used by this module:

  ```kotlin
  dependencies {
      implementation(files("libs/appauth-rust-android-release.aar"))
      implementation("net.java.dev.jna:jna:5.12.0@aar")
      implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
      implementation("androidx.browser:browser:1.8.0")
  }
  ```

- This workflow artifact is for CI validation and expires after 14 days.
  Versioned GitHub Release packages and checksums are still pending.
- Android callback activity routing is exercised on an API 34 emulator.
  Complete authorization through an external browser and a live identity
  provider is not yet tested end-to-end.

## Windows adapter

- `native/windows` provides a blocking C ABI for C++ and .NET hosts. It
  discovers provider configuration, starts a loopback listener on
  `127.0.0.1`, opens the external browser, validates the callback through the
  shared Rust core, and exchanges the authorization code.
- The C# `AuthorizeAsync` wrapper in `native/windows/dotnet` runs the blocking
  ABI on a worker and connects .NET cancellation to the native cancellation
  handle. C++ and VB.NET hosts can call the C ABI directly.
- Call authorization from a worker thread. A C-compatible cancellation handle
  cancels the callback wait and in-flight HTTP operations. Successful results
  contain serialized token state and must be stored securely.
- Build the Windows shared library and run its adapter tests with:

  ```powershell
  cargo build --locked --lib --target x86_64-pc-windows-msvc
  cargo test --locked --lib --target x86_64-pc-windows-msvc
  ```

- The adapter targets `x86_64-pc-windows-msvc`. Review Microsoft's supported
  Windows client versions at each release and update the support matrix and
  validation targets.

## Platform plan

| Platform | Initial scope |
| --- | --- |
| iOS / iPadOS | Shared core and native authorization integration |
| macOS | Shared core and native authorization integration |
| Android | Shared core and native authorization integration |
| Windows | Shared core and desktop browser/redirect integration (v1 target) |
| tvOS | Deferred |

## Rust support

- **MSRV:** Rust 1.99.1, matching the version currently used by CI. CI tests
  both this version and stable; dependency updates must preserve this baseline
  or deliberately raise it.
- **Supported targets:**
  - iOS / iPadOS: `aarch64-apple-ios` (device),
    `aarch64-apple-ios-sim` (simulator)
  - macOS: `aarch64-apple-darwin`, `x86_64-apple-darwin`
  - Android: `aarch64-linux-android`, `x86_64-linux-android`
  - Windows: `x86_64-pc-windows-msvc`
  - Linux: `x86_64-unknown-linux-gnu` for development and CI only; Linux is
    not an initial-release platform commitment.
- **Cross-target CI:** Build the Rust core for every documented Apple, Android,
  and Windows release target. These checks do not package release artifacts or
  exercise authorization flows on devices.
- **Crate boundary:** Keep the protocol implementation in the single
  `appauth-rust` Rust crate. Swift and Kotlin adapters are native-language
  packages; introduce a Cargo workspace only if a separate Rust crate is
  needed for bindings or distribution.

## Native bindings and initial distribution

- Define the native-facing Rust API with UniFFI proc macros, keeping the
  protocol implementation behind that API. Pin both the UniFFI runtime and
  binding generator to 0.32.2, matching the validated binding spike. Generate
  Swift and Kotlin bindings reproducibly; do not hand-edit generated files.
- For the initial release, publish a versioned Apple XCFramework archive,
  Android AAR, and Windows DLL/C ABI package as GitHub Release assets. The
  XCFramework contains the generated
  Swift API and Rust library for the documented Apple targets; the AAR contains
  the generated Kotlin API and Rust libraries for Android `arm64-v8a` and
  `x86_64`. Include checksums and instructions for adding the XCFramework in
  Xcode, the AAR as a local Gradle dependency, and the Windows DLL/import
  library in C++ or .NET applications. Keep compiled platform binaries out of
  the source repository.
- Evaluate Maven Central, Swift Package Manager, and Carthage as later
  distribution channels; they are not initial-release requirements.

## Minimum OS support policy

| Platform | Initial minimum / support | Basis checked 2026-11-08 |
| --- | --- | --- |
| iOS / iPadOS | 18 | Apple listed security updates for 27.2, 26.7.2, and 18.7.11 on 2026-10-26; minimum follows the oldest security-updated major generation. |
| macOS | 15 (Sequoia) | Apple listed security updates for 27.2 (Golden Gate), 26.7.2 (Tahoe), and 15.8.2 (Sequoia) on 2026-10-26. |
| Android | API 34 (Android 14), provisional | The November 2026 Android Security Bulletin lists AOSP versions 14–17. Re-evaluate against current security bulletins and Google Play Console Reach and devices data before release. |
| Windows | Microsoft-supported Windows client versions (x64), reviewed at each release | Track Microsoft's product lifecycle; no fixed minimum OS version. |

The Apple versions above are a dated snapshot, not fixed promises. At release,
recheck Apple's security updates and record the actual supported versions.
Android API 34 is a provisional SDK floor, not a guarantee that a device is
receiving security patches: updates depend on the device manufacturer and model.
Reassess the floor before release using the then-current Android Security
Bulletin and available Play Console data. Android App Links require API 23, but
the provisional security-based floor is higher. For Windows, review Microsoft's
supported Windows client versions at each release and update the support matrix
and validation targets; the v1 target is currently `x86_64-pc-windows-msvc`.

See [FEATURE_MATRIX.md](FEATURE_MATRIX.md) for the feature-scope proposal and
[ROADMAP.md](ROADMAP.md) for remaining design decisions and work phases.
