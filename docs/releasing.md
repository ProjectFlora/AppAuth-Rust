# Releasing

This is the maintainer procedure for publishing a version of AppAuth-Rust.
Every release is produced by the [Release workflow](../.github/workflows/release.yml),
which is dispatched manually. Do not push version tags by hand: the workflow
creates the tag itself (see [Why CI creates the tag](#why-ci-creates-the-tag)).

## Overview

| Step | Where | Result |
| --- | --- | --- |
| 1. Prepare | Pull request to `main` | Version, changelog, and docs updated |
| 2. Candidate run | Release workflow, `publish: false` | All packages built and consumer-validated; nothing published |
| 3. Publish run | Release workflow from `main`, `publish: true` | Release commit, `vX.Y.Z` tag, and GitHub Release with assets and `SHA256SUMS` |
| 4. Verify | Published release consumer validation workflow | Published assets and the Swift package resolve and build |

## 1. Prepare the release

In a pull request to `main`:

- Set `version` in `Cargo.toml` to the release version and update
  `Cargo.lock` (`cargo update -p appauth-rust`). The workflow rejects any
  version that does not match the crate version.
- Move the `CHANGELOG.md` `[Unreleased]` entries under the new version.
- Update README's download section, the SPM installation version (the
  `from:` version and Xcode dependency rule), and any version-specific notes.
- Recheck Windows client support as required by the
  [support matrix](support-matrix.md). For 1.0.0, complete the
  [final verification record](support-matrix.md#final-100-verification).

Do not edit the `AppAuthRustBinary` URL or checksum in `Package.swift`; the
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
`https://github.com/ProjectFlora/AppAuth-Rust/releases/download/vX.Y.Z/AppAuthRust-Apple-X.Y.Z.zip`.

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
   assets plus `SHA256SUMS`, and generated release notes.

Publishing is refused unless the run is dispatched from `main`, the commit is
on `main`, and the `vX.Y.Z` tag does not already exist.

## 4. Verify the published release

Tags pushed by the workflow's `GITHUB_TOKEN` do not trigger other workflows,
so run the published consumer checks manually:

```sh
gh workflow run release-consumer.yml --ref main -f version=X.Y.Z
```

This downloads each published asset, verifies it against `SHA256SUMS`, and
runs the Apple, Android, and Windows consumers. Its `spm` job resolves the
`vX.Y.Z` tag through Swift Package Manager by URL, which also verifies the
manifest's checksum against the published archive. Record the run URL in
the release tracking issue.

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
manifest that leads the Cargo version. SPM consumers resolve released
versions by tag and are unaffected; depending on the `main` branch through
SPM is not supported.

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

- **Publish run cancelled (same-version dispatch)**: if you accidentally dispatched another release candidate while a publish was queued, the pending publish may be cancelled without notice. Check the Actions tab for a cancelled run; if so, dispatch the publish again.

## Repository settings

- The `publish` job needs `contents: write`. If tag rulesets protect `v*`,
  allow `github-actions[bot]` (the GitHub Actions app) to create those tags.

- Branch protection on `main` is unaffected: the workflow pushes only tags.