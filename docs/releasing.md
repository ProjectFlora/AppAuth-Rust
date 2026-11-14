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
release workflow writes them.

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

The run rebuilds and revalidates everything, then the `publish` job:

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
archive. The checksum is a build output: the packaging step proves the
archive is reproducible (two builds in the same run must be byte-identical),
but its checksum is only known after the archive is actually built, so a tag
pushed before the build can never contain it. The workflow therefore builds
and validates the archive first and then tags a release commit that carries
it:

```text
main ── A ── B            (B: dispatched commit)
              \
               R          release: vX.Y.Z  (Package.swift only)  ← tag vX.Y.Z
```

As a consequence, `main`'s `Package.swift` keeps the previous release's
binary target. SPM consumers resolve released versions by tag and are
unaffected; depending on the `main` branch through SPM is not supported.

## Recovering from a failed run

- **Failed before "Create release commit and tag"**: nothing was published.
  Fix the cause and dispatch the workflow again.
- **Tag pushed, but the GitHub Release was not created**: SPM cannot resolve
  the tag yet because its binary asset does not exist. Delete the tag, then
  use **Re-run failed jobs** so that the same built artifacts are reused:

  ```sh
  git push origin :refs/tags/vX.Y.Z
  ```

- **Release published with a problem**: do not move or recreate the tag or
  replace its assets. Consumers may already have resolved it, and SPM caches
  the checksum. Fix forward with a new patch version.

## Repository settings

- The `publish` job needs `contents: write`. If tag rulesets protect `v*`,
  allow `github-actions[bot]` (the GitHub Actions app) to create those tags.
- Branch protection on `main` is unaffected: the workflow pushes only tags.
