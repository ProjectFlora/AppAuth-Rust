# Documentation

Start with the [shared user guide](user-guide.md) for the authentication-state
lifecycle, storage, cancellation, errors, and logout policy. The
[public API coverage matrix](api-coverage.md) identifies the operations exposed
by each language and the examples and checks available today.

| Audience | Installation and current usage | Remaining guide work |
| --- | --- | --- |
| Swift: iOS/iPadOS and macOS | [XCFramework installation](swift-xcframework.md), [Apple adapters](../README.md#apple-adapters) | [#85](https://github.com/ProjectFlora/AppAuth-Rust/issues/85) |
| Kotlin: Android | [Android installation and adapter](../README.md#android-adapter) | [#86](https://github.com/ProjectFlora/AppAuth-Rust/issues/86) |
| C++: Windows | [Windows usage](../native/windows/README.md), [ABI reference](windows-api.md) | [#87](https://github.com/ProjectFlora/AppAuth-Rust/issues/87) |
| .NET: Windows | [Windows usage](../native/windows/README.md#net-interop), [wrapper contract](windows-api.md#net-wrapper) | [#88](https://github.com/ProjectFlora/AppAuth-Rust/issues/88) |
| Rust | [Manual authorization example](../examples/manual_authorization.rs), API reference below | [Coverage matrix](api-coverage.md) |

These are the current entry points, not a claim that all language guides are
complete. [#63](https://github.com/ProjectFlora/AppAuth-Rust/issues/63) tracks
completion; [#89](https://github.com/ProjectFlora/AppAuth-Rust/issues/89) tracks
distribution of the complete, version-matched documentation set.

## API reference

Run `cargo doc --locked --no-deps --open` from the repository. The crate index
is `target/doc/appauth_rust/index.html`; its `ffi` module documents the UniFFI
types and functions used by Swift and Kotlin. The source API names in that
reference are Rust names; use the generated bindings from the same release
for Swift/Kotlin spelling and signatures.

The existing `AppAuthRust-API-Docs-<version>.zip` release asset contains Rust
HTML documentation. It is built on Linux, so it excludes the Windows module.
The [Windows ABI and .NET reference](windows-api.md), the
[C header](../native/windows/include/appauth_windows.h), and the
[C# wrapper](../native/windows/dotnet/AppAuthWindows.cs) cover that public
surface without requiring Windows rustdoc. A local Windows `cargo doc` also
includes the Windows Rust module. Full user-guide packaging remains #89.

## Version and verification policy

Repository documentation describes the source revision being read. Use the
matching tag when installing a published release: current main's OS minimums,
API additions, and packaging fixes may postdate that release. See the
[support matrix](support-matrix.md) and [release downloads](../README.md#download-and-verify-v050).
Swift Package Manager is available from v0.5.0
([#82](https://github.com/ProjectFlora/AppAuth-Rust/issues/82)). Maven Central
publication is planned for v0.6.0
([#81](https://github.com/ProjectFlora/AppAuth-Rust/issues/81)); until then, use
the documented GitHub Release installation for Android.

Maintainers publishing a version follow the [release procedure](releasing.md).

Build checks, mock-provider tests, and real-provider/device verification are
different kinds of evidence. Consult the [coverage matrix](api-coverage.md)
and [interoperability limits](live-idp-interoperability.md) before treating an
example or CI fixture as a compatibility guarantee.
