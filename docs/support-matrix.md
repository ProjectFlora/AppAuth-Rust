# Release support matrix

Tracking: [#60](https://github.com/ProjectFlora/AppAuth-Rust/issues/60).
OS decisions: [#43](https://github.com/ProjectFlora/AppAuth-Rust/issues/43),
implemented by [PR #76](https://github.com/ProjectFlora/AppAuth-Rust/pull/76).

## Status and evidence

Source configuration reviewed on 2026-11-13, based on
`d320722930c179c046f7c2051701389155556d89` (main after PR #76), with the
iOS 18/latest selection and Windows client CI additions accompanying this document.
The OS decision date is 2026-11-12; this source review does not renew the
external lifecycle or device-reach evidence. The dated rationale is in
[Minimum OS support policy](../README.md#minimum-os-support-policy).

This records the settled development baseline and the procedure for the final
1.0.0 record. Final release verification is pending. Published v0.4.0 assets
predate PR #76; their Android minimum must not be inferred from current main.
This document records CI configuration; successful execution evidence belongs
to the accompanying PR checks, not to the source review itself.

#60 covers this baseline, CI mapping, limitations, and verification procedure.
The release-dependent work is tracked separately:

- [#77: candidate artifact verification](https://github.com/ProjectFlora/AppAuth-Rust/issues/77).
- [#78: pre-tag OS support recheck and final decisions](https://github.com/ProjectFlora/AppAuth-Rust/issues/78).

Completing #60 does not satisfy those remaining 1.0.0 readiness gates.

## OS, distribution, and CI mapping

| Platform | Settled minimum / policy | Release targets and package | CI validation and limits |
| --- | --- | --- | --- |
| iOS / iPadOS | 18; recheck Apple's security-update generations before 1.0.0 | `aarch64-apple-ios` device and `aarch64-apple-ios-sim` simulator; XCFramework; deployment target 18.0 | Build both targets and type-check adapters. Regular CI runs two configurations: oldest available iOS 18.x iPhone runtime on `macos-15`, and latest available iOS iPhone runtime on `xcode-27` with the newest installed stable Xcode. Release builds use 18.x on `macos-15`. Missing requested runtimes fail; actual runtimes are logged. Latest means the newest available runtime on the hosted image, which can lag Apple's release. Package consumer links an iOS simulator library and runs on macOS, not on iOS. No exact 18.0, iPad, or physical-device execution claim. |
| macOS | 15; recheck Apple's security-update generations before 1.0.0 | `aarch64-apple-darwin` and `x86_64-apple-darwin`; universal XCFramework slice; deployment target 15.0 | `macos-15` host; build both architectures, run mock loopback flow and package consumer on the host architecture. Building the other architecture does not verify execution on it; real system-browser flow is not automated. |
| Android | API 28 (Android 9); device-reach decision, not a security-patch guarantee; reassess reach, security bulletin, and dependencies before 1.0.0 | `aarch64-linux-android` / `arm64-v8a` and `x86_64-linux-android` / `x86_64`; AAR; Gradle minSdk and NDK API level 28 | Ubuntu host; API 28 x86_64 `google_apis_playstore` emulator for adapter and package-consumer tests; verify both native libraries in AAR. arm64 device execution is unverified. compileSdk 35 is a build requirement, not the runtime minimum. |
| Windows | Microsoft-supported client versions, reviewed each release; concrete edition/version list in README's dated policy | `x86_64-pc-windows-msvc`; DLL, import library, C header, and .NET wrapper ZIP | `windows-latest` Server runner builds/tests and runs C++/.NET consumers. Regular CI also transfers the same package to `windows-11-arm` and runs x64 C++/.NET consumers under emulation, verifying a Windows 11 client host and logging OS/build/image. This adds neither a native ARM64 distribution target nor native x64 client-hardware coverage. Browser callbacks remain simulated; real system-browser flow is unverified. |

Linux is a development/CI host, not a supported distribution platform. tvOS is
deferred. Unverified provider and real-device coverage remains documented in
[live IdP interoperability](live-idp-interoperability.md).

Configuration evidence:

- Hosted Apple images: [Xcode 27 image](https://github.com/actions/runner-images/blob/main/images/macos/xcode-27-arm64-Readme.md)
  and [macOS 15 image](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-arm64-Readme.md).
  The latest lane uses the Xcode 27 image because `macos-latest` currently
  supplies the previous iOS generation. Revisit that label as GitHub's images
  advance. The Xcode 27 hosted image is currently a public preview; failures
  remain visible and are not ignored.
- Apple targets and deployment settings:
  [target builds](../scripts/check-apple-targets.sh),
  [XCFramework packaging and slice assertions](../scripts/package-apple-xcframework.sh),
  [simulator selection](../scripts/check-ios-authorization-flow.sh).
- Android minimums: [library Gradle configuration](../native/android/build.gradle.kts),
  [consumer Gradle configuration](../native/consumer-smoke/android/app/build.gradle.kts),
  [NDK target builds](../scripts/check-android-targets.sh).
- CI and package checks: [regular CI](../.github/workflows/ci.yml),
  [release candidate build and consumers](../.github/workflows/release.yml),
  [published release consumers](../.github/workflows/release-consumer.yml).

Alignment means that every declared distribution target is built and packaged,
runtime minimums agree across documentation and build configuration, and tests
and limitations are accurately recorded. It does not imply execution on every
supported OS, device, or architecture. Any decision to accept an execution gap
must be explicit in the final release record; an unrecorded gap is not a pass.

## Final 1.0.0 verification

Before tagging 1.0.0, complete this record against one release-candidate commit:

1. Recheck official Apple security releases, Android security bulletins and
   device-reach data, and Microsoft client lifecycles. Record source links,
   access dates, Windows editions/versions, rationale, and the next review
   trigger in README's support policy. Use the primary sources referenced by
   [FEATURE_MATRIX.md](../FEATURE_MATRIX.md#references) as starting points;
   an earlier PR's findings alone do not constitute a new lifecycle check.
2. Compare the matrix with the candidate's build scripts, both Android minSdk
   values, NDK API level, and all three workflows. Correct any drift and run
   affected checks. Record actual Apple simulator/runtime, host OS and
   architecture, Android emulator API/ABI, and Windows runner image/version.
   Resolve execution gaps by adding coverage or explicitly recording their
   accepted limits; do not describe deployment-target compilation as an
   execution test of the minimum OS.
3. Run regular CI and the release workflow in `workflow_dispatch` mode for
   the candidate version. Inspect the produced XCFramework slice metadata
   and deployment minimums, AAR manifest minimum and native ABI entries, and
   Windows binary architecture/package contents against this table. Record
   the exact asset names and SHA-256 digests, commit SHA, and successful run
   URLs. Do not substitute existing v0.4.0 assets for candidate artifacts.
4. Update README and ROADMAP to reference the completed record and settled
   release-time values. Keep historical changelog entries unchanged. Complete
   #78 after the lifecycle recheck, and record the candidate evidence and
   explicit dispositions for remaining verification limits under #77.
5. After publication, verify checksums and run the published-release consumer
   workflow for that version. Attach its run URL and confirm that the
   published assets match the candidate record; investigate any difference
   before closing #77.

| Final release record | Status |
| --- | --- |
| Candidate version and full commit SHA | Pending (#77) |
| Lifecycle/reach sources, checked date, and final OS decisions | Pending (#78) |
| Actual CI host/runtime versions and successful regular CI run | Pending for release candidate (#77) |
| Candidate release workflow run and consumer results | Pending (#77) |
| Inspected asset names, SHA-256 digests, targets, and minimums | Pending (#77) |
| Execution gaps and explicit release-time dispositions | Pending (#77) |
| Final confirmation date and next review trigger | Pending (#78) |
| Published release checksums and consumer workflow run | Pending publication (#77) |

Recheck Windows client support at every release. Recheck the whole matrix
immediately before 1.0.0, and whenever a lifecycle change, native dependency,
toolchain, or runner change may invalidate a minimum or its verification.
