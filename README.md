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

## Redirect policy

- **iOS / iPadOS:** Prefer verified HTTPS redirects; allow a custom URI scheme
  fallback. AppAuth-iOS requires iOS 17.4+ and `webcredentials` domain
  association for HTTPS redirects.
- **Android:** Prefer verified Android App Links; allow a custom URI scheme
  fallback. App Links require API 23+ and domain association.
- **macOS:** Use an HTTP loopback redirect on a dynamically allocated port,
  bound only to the loopback interface.
- **Windows:** Loopback browser and redirect integration is deferred beyond
  the initial release.

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

## Platform plan

| Platform | Initial scope |
| --- | --- |
| iOS / iPadOS | Shared core and native authorization integration |
| macOS | Shared core and native authorization integration |
| Android | Shared core and native authorization integration |
| Windows | Shared Rust core only; desktop browser and redirect integration are not required for the initial release |
| tvOS | Deferred |

## Rust support

- **MSRV:** Rust 1.88, the minimum required by the currently locked dependency
  set. CI tests both this version and stable; dependency updates must preserve
  the MSRV or deliberately raise it.
- **Supported targets:**
  - iOS / iPadOS: `aarch64-apple-ios` (device),
    `aarch64-apple-ios-sim` (simulator)
  - macOS: `aarch64-apple-darwin`, `x86_64-apple-darwin`
  - Android: `aarch64-linux-android`, `x86_64-linux-android`
  - Windows shared core: `x86_64-pc-windows-msvc`
  - Linux: `x86_64-unknown-linux-gnu` for development and CI only; Linux is
    not an initial-release platform commitment.
- **Crate boundary:** Keep the protocol implementation in the single
  `appauth-rust` Rust crate. Swift and Kotlin adapters are native-language
  packages; introduce a Cargo workspace only if a separate Rust crate is
  needed for bindings or distribution.

## Native bindings and initial distribution

- Define the native-facing Rust API with UniFFI proc macros, keeping the
  protocol implementation behind that API. Pin both the UniFFI runtime and
  binding generator to 0.32.2, matching the validated binding spike. Generate
  Swift and Kotlin bindings reproducibly; do not hand-edit generated files.
- For the initial release, publish a versioned Apple XCFramework archive and
  Android AAR as GitHub Release assets. The XCFramework contains the generated
  Swift API and Rust library for the documented Apple targets; the AAR contains
  the generated Kotlin API and Rust libraries for Android `arm64-v8a` and
  `x86_64`. Include checksums and instructions for adding the XCFramework in
  Xcode or the AAR as a local Gradle dependency. Keep compiled platform
  binaries out of the source repository.
- Evaluate Maven Central, Swift Package Manager, and Carthage as later
  distribution channels; they are not initial-release requirements.

## Minimum OS support policy

| Platform | Initial minimum / support | Basis checked 2026-11-08 |
| --- | --- | --- |
| iOS / iPadOS | 18 | Apple listed security updates for 27.2, 26.7.2, and 18.7.11 on 2026-10-26; minimum follows the oldest security-updated major generation. |
| macOS | 15 (Sequoia) | Apple listed security updates for 27.2 (Golden Gate), 26.7.2 (Tahoe), and 15.8.2 (Sequoia) on 2026-10-26. |
| Android | API 34 (Android 14), provisional | The November 2026 Android Security Bulletin lists AOSP versions 14–17. Re-evaluate against current security bulletins and Google Play Console Reach and devices data before release. |
| Windows | No desktop OS minimum for the initial release | Only the shared Rust core is included; desktop browser and redirect integration are deferred. |

The Apple versions above are a dated snapshot, not fixed promises. At release,
recheck Apple's security updates and record the actual supported versions.
Android API 34 is a provisional SDK floor, not a guarantee that a device is
receiving security patches: updates depend on the device manufacturer and model.
Reassess the floor before release using the then-current Android Security
Bulletin and available Play Console data. Android App Links require API 23, but
the provisional security-based floor is higher. Windows desktop support and
its minimum OS version will be decided when that integration is scheduled.

See [FEATURE_MATRIX.md](FEATURE_MATRIX.md) for the feature-scope proposal and
[ROADMAP.md](ROADMAP.md) for remaining design decisions and work phases.
