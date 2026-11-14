# AppAuth-Rust

Rust client library for OAuth 2.0 and OpenID Connect, informed by
[AppAuth-iOS](https://github.com/openid/AppAuth-iOS) and
[AppAuth-Android](https://github.com/openid/AppAuth-Android).

See the [documentation index](docs/README.md) for platform installation guides,
the shared authentication-state lifecycle, and public API coverage by language.

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
- Support optional OAuth 2.0 Token Revocation endpoints for public clients.
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
  default transport. The supplied Swift/Kotlin HTTP transports disable platform
  HTTP caching; JWKS caching and freshness are handled by the Rust core.
- Use the external browser for authorization; do not embed the flow in a
  WebView.
- Keep OAuth/OIDC protocol handling in the shared Rust core.

## Support baseline

| Platform | Minimum | Initial-release support |
| --- | --- | --- |
| iOS / iPadOS | 18 | Rust core and native authorization adapter |
| macOS | 15 | Rust core and native authorization adapter |
| Android | API 28 (Android 9) | Rust core and native authorization adapter |
| Windows | Microsoft-supported Windows client versions; reviewed each release | Rust core and desktop authorization adapter |
| tvOS | Not applicable | Deferred |

The Apple minimums follow the security-update generations reviewed on
2026-11-12. Android API 28 is the settled 1.0.0 minimum: it is the highest
floor that still reaches at least 95% of active devices in Google's October
2026 distribution data (97.1%; API 34 reaches only 56.4%). Recheck the
supported OS versions, Android device reach, and the Windows support list
before the 1.0.0 tag; the pre-1.0 release policy in
[ROADMAP.md](ROADMAP.md) makes this a release gate.

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

## Token revocation

- Use the discovered `revocation_endpoint` or configure one explicitly; it
  must use HTTPS. Providers without this optional endpoint cannot use
  revocation.
- Call `revoke_token` explicitly with an access or refresh token and the
  public client ID. The request never includes a client secret; callers may
  provide the optional `access_token` or `refresh_token` type hint.
- HTTP 200 completes the operation, including for an already-invalid token;
  its body is ignored as required by RFC 7009. Other status codes do not confirm
  revocation. Valid OAuth error objects on HTTP 400/401 are returned as
  authorization-server errors; malformed/ambiguous bodies and other statuses
  remain HTTP errors. HTTP 503 remains observable even with an OAuth-shaped
  body. Transport failures and explicit cancellation are also returned without
  changing local authentication state. The API does not expose Retry-After or
  retry automatically; the host owns retry policy.
- Revocation is distinct from RP-Initiated Logout and local state deletion.
  The host application must delete its local authentication state regardless
  of a revocation request's success, failure, or cancellation. It owns retry
  policy for transient failures.
- Swift and Kotlin receive this operation through the UniFFI API. The Windows
  C ABI exposes token revocation through a blocking worker-thread API.

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
- Windows desktop applications use the C ABI in `native/windows/include` for
  authorization, token refresh, OIDC end-session, and token revocation. The ABI
  is callable from C++ and from .NET through P/Invoke; see
  [`native/windows/README.md`](native/windows/README.md).
- Generate the public Rust API reference locally with
  `cargo doc --locked --no-deps`; the HTML output is written to
  `target/doc/appauth_rust/index.html`.
- `examples/manual_authorization.rs` shows the shared Rust-core flow. It prints
  the authorization URL and asks the caller to paste the redirect URL; native
  applications should use the platform adapters for browser launch and
  callback delivery. Check the example with
  `cargo check --locked --example manual_authorization`.

The crate is not published on crates.io. Binary distribution uses versioned
GitHub Releases on all platforms. The package-channel evaluation recorded in
[docs/distribution-channels.md](docs/distribution-channels.md) (issue #44)
adopts Maven Central for Android and Swift Package Manager for Apple, with the
GitHub Release assets remaining the fallback channel; those channels are not
published yet and are implemented in [#81](https://github.com/ProjectFlora/AppAuth-Rust/issues/81)
and [#82](https://github.com/ProjectFlora/AppAuth-Rust/issues/82). Carthage
was evaluated and declined. The published [v0.1.0 release](https://github.com/ProjectFlora/AppAuth-Rust/releases/tag/v0.1.0) contains the
Apple XCFramework, Android AAR, API reference, and checksums; it predates the
Windows adapter. The published [v0.2.0 release](https://github.com/ProjectFlora/AppAuth-Rust/releases/tag/v0.2.0) adds the Windows DLL/C ABI package with
C/C++ and .NET interop files. The published [v0.3.0 release](https://github.com/ProjectFlora/AppAuth-Rust/releases/tag/v0.3.0)
adds token revocation to the Rust, UniFFI, and Windows C ABI public-client
APIs. The published [v0.4.0 release](https://github.com/ProjectFlora/AppAuth-Rust/releases/tag/v0.4.0)
adds token refresh and OIDC end-session to the Windows C ABI and .NET
wrapper.
The release workflow accepts only SemVer tags that point to `main` and match
the crate version. A manual workflow run validates and packages a release
candidate without publishing; pushing its matching version tag publishes the
assets and SHA-256 checksums. Releases before 1.0.0 are pre-1.0 and may have
documented interoperability or support-policy gaps; see `CHANGELOG.md` and
`ROADMAP.md`.

## Download and verify v0.4.0

The following versioned assets are available from GitHub Releases, independently
of the temporary CI validation artifacts:

| Asset | Download |
| --- | --- |
| Apple XCFramework and generated Swift API | [AppAuthRust-Apple-0.4.0.zip](https://github.com/ProjectFlora/AppAuth-Rust/releases/download/v0.4.0/AppAuthRust-Apple-0.4.0.zip) |
| Android AAR | [appauth-rust-android-0.4.0.aar](https://github.com/ProjectFlora/AppAuth-Rust/releases/download/v0.4.0/appauth-rust-android-0.4.0.aar) |
| Windows DLL/C ABI and C++/.NET interop files | [appauth-rust-windows-0.4.0.zip](https://github.com/ProjectFlora/AppAuth-Rust/releases/download/v0.4.0/appauth-rust-windows-0.4.0.zip) |
| Rust API reference | [AppAuthRust-API-Docs-0.4.0.zip](https://github.com/ProjectFlora/AppAuth-Rust/releases/download/v0.4.0/AppAuthRust-API-Docs-0.4.0.zip) |
| SHA-256 checksums for all four assets | [SHA256SUMS](https://github.com/ProjectFlora/AppAuth-Rust/releases/download/v0.4.0/SHA256SUMS) |

Download the desired asset and `SHA256SUMS` from the same release. For example,
from the directory containing the Android AAR and checksum file:

```sh
grep -F '  appauth-rust-android-0.4.0.aar' SHA256SUMS | shasum -a 256 -c -
```

Use the exact downloaded asset name when verifying another package. GitHub
Release assets are the persistent distribution channel; the CI validation
artifacts expire after 14 days.

## Release consumer validation

Each release candidate is installed into minimal consumer fixtures before it
can be published. These fixtures use only the generated release archive, not
the repository's native build output:

- Apple compiles and runs a macOS Swift host, then links the same generated
  Swift API and XCFramework for the iOS simulator.
- Android installs the AAR as a local Gradle dependency and calls its Kotlin
  API on an x86_64 API 28 emulator. The release job separately verifies that
  the AAR contains both `arm64-v8a` and `x86_64` libraries.
- Windows builds and runs a C++ host linked with the import library, plus a
  .NET host that compiles the packaged P/Invoke wrapper and loads the DLL.

For a downloaded candidate, verify its SHA-256 entry before using it, then run
the corresponding consumer check on its host platform:

```sh
grep -F '  AppAuthRust-Apple-<version>.zip' SHA256SUMS | shasum -a 256 -c -
scripts/check-apple-release-consumer.sh AppAuthRust-Apple-<version>.zip
```

```sh
grep -F '  appauth-rust-android-<version>.aar' SHA256SUMS | shasum -a 256 -c -
scripts/check-android-release-consumer.sh appauth-rust-android-<version>.aar
```

```powershell
$expected = ((Select-String SHA256SUMS -Pattern '  appauth-rust-windows-<version>\.zip$').Line -split '\s+')[0]
$actual = (Get-FileHash appauth-rust-windows-<version>.zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'SHA-256 mismatch' }
scripts/check-windows-release-consumer.ps1 -Package appauth-rust-windows-<version>.zip
```

The PowerShell verification parses the portable `shasum`-format checksum file
and fails before running the consumer check when the value differs.

Run the **Published release consumer validation** workflow with a published
version to repeat these checks against the immutable GitHub Release assets.

## Apple adapters

- `Sources/AppAuthRust/IOSAuthorizationAdapter.swift` runs authorization in
  `ASWebAuthenticationSession`; HTTPS callbacks use Apple's verified callback
  matcher, and custom URI schemes are supported as a fallback. The host app
  must configure a `webcredentials:<host>` associated domain or register its
  custom URL scheme, and provide an
  `ASWebAuthenticationPresentationContextProviding` implementation.
- `Sources/AppAuthRust/MacOSAuthorizationAdapter.swift` accepts a redirect
  template such as `http://127.0.0.1/oauth/callback`, replaces its port with a
  dynamically allocated port, and binds the listener only to IPv4 loopback.
  Unexpected paths receive 404 while the adapter continues waiting.
- Cancelling the iOS adapter or Swift task dismisses its authentication
  session; iOS-reported browser dismissal maps to `FfiError.Cancelled`.
  Cancellation on either adapter stops its callback wait and cancels
  in-flight core work. The macOS adapter cannot dismiss the external browser.
  `URLSessionNativeHttpTransport` refuses HTTP redirects and forwards
  cancellation to `URLSession`.
- Run `scripts/check-apple-adapters.sh` to regenerate the bindings, type-check
  the adapters against the iOS and macOS SDKs, and run a macOS loopback
  authorization flow against a local mock provider. CI also runs
  `scripts/check-ios-authorization-flow.sh` on an arm64 Apple host to exercise
  the iOS simulator adapter against a local mock provider.

## Apple binary package

- Build a package for a specific version with
  `scripts/package-apple-xcframework.sh 0.4.0`. It creates
  `target/apple/release-package/AppAuthRust-Apple-0.4.0.zip`, containing an
  `AppAuthRust.xcframework` with static Rust libraries for iOS device,
  iOS simulator, and universal macOS, the generated Swift API source, the
  platform adapters (the same sources the Swift package target compiles),
  and an installation guide.
  See [Swift XCFramework installation](docs/swift-xcframework.md).
  The CI `apple-xcframework` artifact is for validation and expires after
  14 days. Use the published Apple archive and `SHA256SUMS` linked in
  [Download and verify v0.4.0](#download-and-verify-v040) for distribution.

## Apple Swift Package Manager (SPM)

Starting with v0.5.0, the Apple package is also available through Swift
Package Manager. SPM is the recommended installation method; it resolves the
same XCFramework published in the GitHub Release and compiles the generated
Swift API and the platform adapters as part of the `AppAuthRust` library
product. The package supports iOS/iPadOS 18 and later and macOS 15 and later.

In Xcode, choose **File > Add Package Dependencies...**, enter
`https://github.com/ProjectFlora/AppAuth-Rust`, set **Dependency Rule** to
**Up to Next Minor Version** from `0.5.0`, and add the `AppAuthRust` library
to your app target.

In a `Package.swift` manifest, add the package dependency and the
`AppAuthRust` product to your target:

```swift
dependencies: [
    .package(
        url: "https://github.com/ProjectFlora/AppAuth-Rust",
        .upToNextMinor(from: "0.5.0")
    ),
],
targets: [
    .target(
        name: "MyApp",
        dependencies: [
            .product(name: "AppAuthRust", package: "AppAuth-Rust"),
        ]
    ),
],
```

Pin to a minor version while the project is pre-1.0: 0.x minor releases may
contain breaking API changes (see the
[pre-1.0 release policy](ROADMAP.md#pre-10-release-policy)). Then
`import AppAuthRust` in your Swift code. With SPM, skip the manual XCFramework
and Swift source steps in
[Swift XCFramework installation](docs/swift-xcframework.md); its callback
configuration still applies.

### Advantages of using SPM
By using SPM, the library automatically handles the inclusion of the
Swift API and platform adapters. This eliminates the need to manually
check in or copy generated source files into the repository, ensuring that
the distributed package always matches the latest released binary. This
approach avoids "double management" of versioned artifacts and source code,
as the `Package.swift` is dynamically updated during the release process to
point to the correct SHA-256 checksum of the published archive.

By using SPM, the library automatically handles the inclusion of the
Swift API and platform adapters. This eliminates the need to manually
check in or copy generated source files into the repository, ensuring that
the distributed package always matches the latest released binary.

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
  targets the documented Android API 28 minimum and regenerates UniFFI Kotlin
  bindings under its build directory.
- Build the release AAR with
  `ANDROID_NDK_HOME=/path/to/ndk ./native/android/gradlew -p native/android assembleRelease`.
  The AAR includes Rust shared libraries for `arm64-v8a` and `x86_64`; CI
  verifies both entries and uploads the AAR as a workflow artifact. The
  current output is
  `native/android/build/outputs/aar/appauth-rust-android-release.aar`.
- Download `appauth-rust-android-0.4.0.aar` from the
  [published release](#download-and-verify-v040), verify its checksum, and copy
  it into the Android app's `libs` directory.
  Because a raw AAR has no dependency metadata, also declare the runtime
  dependencies used by this module:

  ```kotlin
  dependencies {
      implementation(files("libs/appauth-rust-android-0.4.0.aar"))
      implementation("net.java.dev.jna:jna:5.12.0@aar")
      implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
      implementation("androidx.browser:browser:1.8.0")
  }
  ```

- The CI `android-aar` artifact uses the build output name
  `appauth-rust-android-release.aar` and expires after 14 days. The versioned
  GitHub Release AAR and `SHA256SUMS` are the persistent distribution artifacts.
- Android authorization through a Custom Tab, callback activity, and code
  exchange is exercised against a local mock provider on an API 28 emulator.
  Live identity-provider interoperability is not yet tested end-to-end.

## Windows adapter

- `native/windows` provides a blocking C ABI for C++ and .NET hosts. It
  discovers provider configuration, starts a loopback listener on
  `127.0.0.1`, opens the external browser, and validates callbacks through the
  shared Rust core. It exposes authorization, token refresh, OIDC end-session,
  and token revocation.
- The C# wrappers in `native/windows/dotnet` (`AuthorizeAsync`,
  `RefreshAsync`, `EndSessionAsync`, and `RevokeAsync`) run the blocking ABI on
  a worker and connect .NET cancellation to the native cancellation handle.
  C++ and VB.NET hosts can call the C ABI directly.
- Call each operation from a worker thread. A C-compatible cancellation handle
  cancels the callback wait and in-flight HTTP operations. Successful
  authorization and refresh results contain serialized token state and must be
  stored securely.
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
- v0.4.0 publishes a versioned Apple XCFramework archive, Android AAR,
  Windows DLL/C ABI package, API reference, and `SHA256SUMS` as
  [GitHub Release assets](#download-and-verify-v040). The
  XCFramework contains the generated
  Swift API and Rust library for the documented Apple targets; the AAR contains
  the generated Kotlin API and Rust libraries for Android `arm64-v8a` and
  `x86_64`. Installation instructions cover adding the XCFramework in
  Xcode, the AAR as a local Gradle dependency, and the Windows DLL/import
  library in C++ or .NET applications. Compiled platform binaries stay out of
  the source repository.
- Maven Central, Swift Package Manager, and Carthage were evaluated as later
  distribution channels in
  [docs/distribution-channels.md](docs/distribution-channels.md): Maven
  Central (Android) and Swift Package Manager (Apple) are adopted, Carthage
  was declined; none are initial-release requirements.

## Minimum OS support policy

The [release support matrix](docs/support-matrix.md) maps these OS decisions
to package targets and CI coverage, records verification limits, and tracks
the final 1.0.0 release evidence. Its source review does not replace the
release-time lifecycle check below.

| Platform | Initial minimum / support | Basis checked 2026-11-12 |
| --- | --- | --- |
| iOS / iPadOS | 18 | Apple listed security updates for 27.2.1, 26.7.3, and 18.7.12 on 2026-11-09; the minimum follows the oldest security-updated major generation. |
| macOS | 15 (Sequoia) | Apple listed security updates for 27.2.1 (Golden Gate), 26.7.3 (Tahoe), and 15.8.3 (Sequoia) on 2026-11-09. Sequoia is in its final security-support year; see the re-evaluation policy below. |
| Android | API 28 (Android 9) | Google's October 2026 device distribution (Android Studio data, active devices contacting the Play Store) puts API 28+ on 97.1% of devices, meeting the 95% reach target; API 34+ reaches only 56.4%. |
| Windows | Microsoft-supported Windows client versions (x64), reviewed at each release | As of 2026-11-12 Microsoft supports Windows 11 client editions 25H2, 26H1, and 26H2 (Home/Pro); 24H2 consumer support ended 2026-10-13 and 23H2 ended 2026-11-10. No fixed minimum OS version. |

The Apple versions above are a dated snapshot, not fixed promises. Before
the 1.0.0 tag, recheck Apple's security updates and record the actual
supported versions. macOS 15 (Sequoia) is expected to leave Apple's
security updates around autumn 2027, and 1.0.0 is planned for 2026 Q4 to
2027 H1; a release that slips past the Sequoia end of support must raise the
macOS floor and re-verify the affected targets.

Android API 28 is a device-reach floor, not a security-patch guarantee. The
November 2026 Android Security Bulletin patches AOSP 14 and later, so
devices below that level depend on their manufacturer for updates; this
floor accepts that trade-off to meet the reach target, and the Rust core has
no Android-specific dependencies that would block it. Android App Links
require API 23, which every supported device meets. Reassess the floor
before release using the then-current Android Security Bulletin, the latest
Google device distribution (Play Console Reach and devices data where
available), and the final native dependency set.

For Windows, review Microsoft's supported client versions at each release
and update the support matrix and validation targets; the v1 target is
currently `x86_64-pc-windows-msvc`. CI builds and tests that target on
GitHub's hosted Windows runners (a Windows Server release), which is not one
of the supported client editions. Regular CI additionally runs the x64
C++/.NET package consumers on a `windows-11-arm` client runner under x64
emulation and records the actual OS/build. Native x64 client-hardware execution
and real system-browser interaction remain unverified. See the
[release support matrix](docs/support-matrix.md) for coverage limits and
[live identity-provider coverage](docs/live-idp-interoperability.md).

See [FEATURE_MATRIX.md](FEATURE_MATRIX.md) for the feature-scope proposal and
[ROADMAP.md](ROADMAP.md) for remaining design decisions and work phases.
