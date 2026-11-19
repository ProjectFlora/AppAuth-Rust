# Releasing

This is the maintainer procedure for publishing a version of NativeOIDC.
Every release is produced by the [Release workflow](../.github/workflows/release.yml),
which is dispatched manually. Do not push version tags by hand: the workflow
creates the tag itself (see [Why CI creates the tag](#why-ci-creates-the-tag)).

## Overview

| Step | Where | Result |
| --- | --- | --- |
| 1. Prepare | Pull request to `main` | Version, changelog, and docs updated |
| 2. Candidate run | Release workflow, `publish: false` | All packages built and consumer-validated; nothing published |
| 3. Publish run | Release workflow from `main`, `publish: true` | Release commit, `vX.Y.Z` tag, GitHub Release with assets and `SHA256SUMS`, and the Android library on Maven Central |
| 4. Verify | Published release consumer validation workflow | Published assets and the Swift package resolve and build |

## 1. Prepare the release

In a pull request to `main`:

- Set `version` in `Cargo.toml` to the release version and update
  `Cargo.lock` (`cargo update -p native-oidc`). The workflow rejects any
  version that does not match the crate version.
- Move the `CHANGELOG.md` `[Unreleased]` entries under the new version.
- Update README's download section, the SPM installation version (the
  `from:` version and Xcode dependency rule), the Maven Central
  dependency version, and any version-specific notes.
- If dependencies changed, check that `THIRD_PARTY_LICENSES.txt` still
  reads correctly (CI uploads it as the `third-party-licenses` artifact;
  see [License notices](#license-notices)).
- Recheck Windows client support as required by the
  [support matrix](support-matrix.md). For 1.0.0, complete the
  [final verification record](support-matrix.md#final-100-verification).

Do not edit the `NativeOIDCBinary` URL or checksum in `Package.swift`; the
release workflow writes them into the release commit at the version tag.
`main`'s copy is not updated by a release (see
[Why CI creates the tag](#why-ci-creates-the-tag)).

Merge the pull request once CI passes.

## 2. Run a release candidate

A candidate run builds and validates every package without publishing
anything. Candidate runs can be dispatched from any branch, so release
pipeline changes can be checked before they merge.

```sh
gh workflow run release.yml --ref main -f version=X.Y.Z -f publish=false
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
```

Or, in GitHub: **Actions > Release > Run workflow**, choose the branch, enter
the version, and leave **publish** unchecked.

Confirm that every job succeeds, including **Prepare and validate release
Package.swift** (`spm_manifest`). That job's log shows the rewritten
`Package.swift` diff: the URL must be
`https://github.com/ProjectFlora/NativeOIDC/releases/download/vX.Y.Z/NativeOIDC-Apple-X.Y.Z.zip`.
The **Validate release version** step summary names the release the
generated notes will start from and links the comparison; it must be the
previous release (see [Release notes range](#release-notes-range)).

The Apple jobs build and validate with the Xcode set by `XCODE_VERSION` in
`release.yml` (a stable Xcode 26.x, since App Store Connect requires Xcode
26 or later), and `release-consumer.yml` sets the same version. Check the
**Build Apple release package** step summary for the recorded Rust and Xcode
versions and the iOS simulator runtime the iOS flow ran on. To change the
Xcode version, update the runner label and `XCODE_VERSION` in both
workflows together, after checking the
[runner-images README](https://github.com/actions/runner-images/tree/main/images/macos)
for the image's installed Xcode versions and simulator runtimes.

## 3. Publish

Dispatch from `main` with **publish** checked:

```sh
gh workflow run release.yml --ref main -f version=X.Y.Z -f publish=true
```

The run rebuilds and revalidates everything; the archive it publishes, and
the checksum written into `Package.swift`, come from this run, not from the
candidate run in step 2, and its bytes may differ from the candidate's.
Then the `publish` job:

1. Commits the validated `Package.swift` as `release: vX.Y.Z` on top of the
   dispatched `main` commit (it fails if anything else changed).
2. Creates the annotated `vX.Y.Z` tag on that commit and pushes **only the
   tag**. `main` is not updated.
3. Creates the GitHub Release with the Apple, Android, Windows, and API docs
   assets plus `SHA256SUMS`, and release notes generated from the previous
   release (see [Release notes range](#release-notes-range)).

After the GitHub Release is created, the `publish_maven` job checks out the
`vX.Y.Z` tag, builds the Android library, checks the signed publication with
`scripts/check-android-maven-publication.sh`, and publishes
`net.project-flora.nativeoidc:native-oidc-android:X.Y.Z` to Maven Central through
the Central Portal (`publishAndReleaseToMavenCentral`). The candidate run
and pull request CI run the same check on an unsigned publication.

Publishing is refused unless the run is dispatched from `main`, the commit is
on `main`, and the `vX.Y.Z` tag does not already exist.

## 4. Verify the published release

Tags pushed by the workflow's `GITHUB_TOKEN` do not trigger other workflows,
so run the published consumer checks manually:

```sh
gh workflow run release-consumer.yml --ref main -f version=X.Y.Z
```

This downloads each published asset, verifies it against `SHA256SUMS`, and
runs the Apple, Android, and Windows consumers against the downloaded
archives. Its `android_maven` job additionally consumes the Android library
from Maven Central the way a foreign Gradle consumer would: a
publication-status check fails fast when the version was never published to
Central (releases before `publish_maven` was added in #132, for example
v0.5.0, or a release whose `publish_maven` job failed or was cancelled --
the tag is pushed before that job runs, so the check reads the release
run's job results, and checks Maven Central itself before rejecting a
failed publication: a visible or still-syncing artifact is let through,
and an incomplete or in-progress outcome falls back to the retry loop),
then a retry loop absorbs the Central sync -- a direct HTTP check
on the full publication (the AAR, the POM, the module metadata, the
sources and javadoc jars, and their signatures), a strict
`checkDebugAarMetadata` resolution of the POM, AAR and transitive
dependencies, and the full consumer smoke on an emulator (Issue #137).

Its `spm` job resolves the `vX.Y.Z` tag through Swift Package Manager by URL, which also verifies the
manifest's checksum against the published archive. Record the run URL in
the release tracking issue.

## License notices

Every release package ships `LICENSE`, `THIRD_PARTY_LICENSES.txt` and
`RUST_STANDARD_LIBRARY_COPYRIGHT.html` (see the README's
[Third-party licenses](../README.md#third-party-licenses) section for the
locations). The notices are generated, never edited by hand:

- `scripts/generate-third-party-licenses.sh` runs cargo-about with
  `about.toml` (which crates and targets: the crates linked into the
  release libraries for every release target, without dev and build
  dependencies) and `about.hbs` (the text, including the Rust standard
  library and UniFFI-generated bindings sections). It runs offline and
  requires the pinned cargo-about version.
- The Rust standard library is not in `Cargo.lock`, so the script takes its
  notices from the active Rust toolchain: it appends the toolchain version
  and the license files of compiler-builtins and libm (the parts not under
  `MIT OR Apache-2.0`, with copyright notices of their own) from the
  rust-src component, which it installs, and copies the toolchain's
  `share/doc/rust/COPYRIGHT-library.html` as
  `RUST_STANDARD_LIBRARY_COPYRIGHT.html`. The output therefore depends on
  `Cargo.lock` and the toolchain, and each package generates it with the
  toolchain that builds it. The release workflow pins every package job to
  the same Rust version (`dtolnay/rust-toolchain@1.100.0`), so all packages
  ship the same notices; change them together.
- The Apple packaging script, the Android release build
  (`generateLicenseNotices`) and `scripts/package-windows.ps1` (after the
  workflow step that runs the script) put the files into the packages.
  The consumer checks and `scripts/check-android-maven-publication.sh`
  fail when a package lacks them; the Android consumer check also requires
  them in the consumer app's APK.
- `cargo deny check licenses` (`deny.toml`) runs in CI and in the release
  workflow's version validation. It allows MPL-2.0 only for the UniFFI
  crates and CDLA-Permissive-2.0 only for `webpki-roots`.

Maintenance:

- **A dependency under a new license**: check that the license is
  compatible with Apache-2.0 and what it requires of binary distribution,
  then add it to `deny.toml` (as a per-crate exception when it should stay
  limited to that crate) and to `accepted` in `about.toml`.
- **A `ring` update**: `about.toml` pins the checksums of ring's license
  files, so generation fails until they are reviewed and the checksums
  updated.
- **A Rust toolchain update**: check that the toolchain still has the two
  license files the script appends, and whether another part of the
  standard library gained a license other than `MIT OR Apache-2.0` (its
  `library/` sources in rust-src).
- **A cargo-about or cargo-deny update**: change the version in
  `scripts/generate-third-party-licenses.sh` (cargo-about) and in every
  `taiki-e/install-action` step of `ci.yml` and `release.yml` together.

`release-consumer.yml` runs the same consumer checks, so it requires the
notices too and can validate only v0.7.1 and later. v0.1.0 through v0.7.0
shipped without them; their notices were generated afterwards from each
tag's `Cargo.lock` and the Rust version of each release run, and attached
to the GitHub Releases as `THIRD_PARTY_LICENSES-<version>.txt` and
`RUST_STANDARD_LIBRARY_COPYRIGHT-<version>.html`, leaving `SHA256SUMS`
unchanged
([#161](https://github.com/ProjectFlora/NativeOIDC/issues/161)).

## Why CI creates the tag

Swift Package Manager reads `Package.swift` at the version tag, and that
manifest must contain the SHA-256 checksum of the published XCFramework
archive. The checksum is a build output: it is only known after the
archive is actually built, so a tag pushed before the build can never
contain it. The workflow therefore builds and validates the archive first
and then tags a release commit that carries it:

```text
main ── A ── B            (B: dispatched commit)
               \
                R          release: vX.Y.Z  (Package.swift only)  ← tag vX.Y.Z
```

The release commit is reachable only from its tag; the workflow never
rewrites `main`'s `Package.swift`. `main` therefore keeps the binary target
last committed to it by hand, and it falls further behind the Cargo version
with every release unless someone updates it.
`scripts/check-spm-manifest.sh` accepts any such lag and rejects only a
manifest that leads the Cargo version. Releases up to 0.6.0 were published
while the repository was named `ProjectFlora/AppAuth-Rust`; the check also
accepts their original asset URLs, which GitHub redirects after the rename
([#146](https://github.com/ProjectFlora/NativeOIDC/issues/146)), so
renaming the repository does not invalidate the binary target on `main`.
SPM consumers resolve released
versions by tag and are unaffected; depending on the `main` branch through
SPM is not supported.

### Updating main's Package.swift

To keep `main` in sync with releases, update the `NativeOIDCBinary` target in
`Package.swift` during release preparation pull requests:

- Set the binary target to point at the **previous** published release (e.g., for
  preparing v0.8.0, use v0.7.0's URL and checksum).
- Update both `url` and `checksum` together; do not edit them manually after
  that.
- Merge the PR once CI passes (`scripts/check-spm-manifest.sh` will succeed if
  the manifest does not lead the Cargo version).

Once main catches up to a prior release (e.g., v0.7.x), legacy URL acceptances
in `scripts/check-spm-manifest.sh` will no longer be needed but are retained
for safety until then.

### Release notes range

Because each release commit is reachable only from its tag, earlier release
tags are not in the new tag's history. Left to choose the starting tag
itself, GitHub picks the last tag in that history, which is `v0.4.0`, the
last release tagged on `main`, so every release would list everything
since `v0.4.0`. The workflow therefore passes the starting tag explicitly
(`--notes-start-tag`): the highest published, non-draft,
non-prerelease GitHub Release whose `vX.Y.Z` tag sorts below the new
version by SemVer. A patch for an older line (for example `v0.6.1` after
`v0.7.0`) therefore starts at `v0.6.0`, and a tag left without a GitHub
Release by a failed run is skipped. If no earlier release is found, the
run fails rather than generating notes from the wrong range. GitHub
compares the two tags through their merge base, so the notes list the pull
requests merged to `main` between the two dispatched commits.
Releases v0.6.0 and v0.7.0 were published with notes starting at `v0.4.0`
and were corrected afterwards
([#151](https://github.com/ProjectFlora/NativeOIDC/issues/151)).

### What the packaging self-test checks

This section is the reference description of the determinism self-test in
`scripts/package-apple-xcframework.sh`; other documents link here rather
than restating it.

The release run builds the Rust libraries and stages the package once.
The script then repeats two steps and requires identical bytes:

- `xcodebuild -create-xcframework` runs a second time, and both
  canonicalized `Info.plist` files must match
  (`scripts/normalize_xcframework_plist.py`).
- `ditto` zips the same staged tree a second time, and both archives must
  have the same SHA-256 after `scripts/normalize_zip.py`.

Staging (`cp`, `lipo`, `xattr -cr`, `touch -t`) runs once, and both
comparisons run in the same job, on the same machine, with the same
toolchain. Only the zip comparison runs under `TZ=UTC`; the plist
comparison runs earlier, in the runner's local timezone. The self-test
therefore shows only that the plist and zip steps repeat byte-identically
within one run. It does not show that a rebuild, a repeated staging pass,
or a run on another machine would produce the same archive. The manifest
checksum does not rely on that: it is computed from the one archive that
is published.

Each self-test output is removed as soon as its comparison succeeds, and
an EXIT trap removes whatever exists when the script exits any other way,
so a run never leaves its self-test outputs behind. The guard checks the
whole output directory rather than just the staged package, and the
directory remains after any run — successful, failed, or interrupted —
so re-running requires removing it in full
(`rm -rf target/apple/release-package`). The removal also deletes archives
of previous runs, so move any archive you keep somewhere else first.

## Recovering from a failed run

- **Failed before "Create release commit and tag"**: nothing was published.
  Fix the cause and dispatch the workflow again.

- **Tag pushed, but the GitHub Release was not created**: SPM cannot resolve
  the tag yet because its binary asset does not exist. Delete the tag, then
  use **Re-run failed jobs** so that the same built artifacts are reused:

```sh
git push origin :refs/tags/vX.Y.Z
```

- **Release published with a problem**: do not move or recreate the tag or replace its assets. Consumers may already have resolved it, and SPM caches the checksum. Fix forward with a new patch version.

- **GitHub Release created, but `publish_maven` failed**: if the Central
  Portal deployment was not released, fix the cause (for example, credentials
  or the signing key) and use **Re-run failed jobs**. If the version already
  appears on Maven Central, it cannot be replaced or deleted; fix forward with
  a new patch version.

- **Consumer validation (`release-consumer.yml`) failed**: the `android_maven`
  job logs four distinct causes. The publication-status check failing means
  the version never reached Maven Central: a release predating #132 or a
  mistyped version has no Maven publication at all, so dispatch a published
  version; a release whose `publish_maven` job failed or was cancelled
  fails the check only when the artifact is also absent from Maven Central
  (the job can fail after the Central Portal deployment was released): if
  the deployment was not released, **Re-run failed jobs** on the release
  run (remove the tag first if the tag-pushing job also did not complete);
  if it was released, re-dispatch once the sync completes. The
  availability gate
  404ing means the Central sync is still propagating: re-dispatch once the
  portal deployment is released. A strict-resolution or emulator-smoke
  failure is a real consumer problem in the published artifact; a version
  already on Central cannot be replaced, so fix forward with a new patch
  version.

- **Publish run cancelled (same-version dispatch)**: if you accidentally dispatched another release candidate while a publish was queued, the pending publish may be cancelled without notice. Check the Actions tab for a cancelled run; if so, dispatch the publish again.

## Repository settings

- The repository was renamed from `ProjectFlora/AppAuth-Rust` to
  `ProjectFlora/NativeOIDC` for v0.7.0
  ([#146](https://github.com/ProjectFlora/NativeOIDC/issues/146)). GitHub
  redirects the former URL for git, the web, and release asset downloads,
  and Swift packages pinned to v0.1.0 through v0.6.0 resolve through that
  redirect. **Never create a new repository named `ProjectFlora/AppAuth-Rust`**:
  doing so ends the redirect and breaks those consumers.

- `release-consumer.yml` expects the release asset names and Maven
  coordinates of v0.7.0 and later, and the license notices of v0.7.1 and
  later (see [License notices](#license-notices)). Releases up to v0.6.0
  used the former names, and v0.7.0 lacks the notices, so none of them can
  be revalidated with the current workflow.

- The `publish` job needs `contents: write`. If tag rulesets protect `v*`,
  allow `github-actions[bot]` (the GitHub Actions app) to create those tags.

- Branch protection on `main` is unaffected: the workflow pushes only tags.

- The `publish_maven` job reads these repository secrets:
  - `MAVEN_USER` and `MAVEN_PASSWORD`: a Central Portal user token with
    publishing rights to the verified `net.project-flora` namespace.
  - `GPG_PRIVATE_KEY`: the ASCII-armored private signing key. Its public key
    must be published to a key server that Maven Central checks, such as
    `keys.openpgp.org`.
  - `GPG_PASSPHRASE`: the passphrase of that key.