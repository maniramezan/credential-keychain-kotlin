# Release and maintenance guide

The release pipeline targets Maven Central (`com.maniramezan:credential-keychain-kotlin`) and
GitHub Pages. A successful local compiler run alone does not establish release readiness:
the complete Verify workflow, artifact consumer, and device tests must pass on the exact
release commit.

Versions and tags are bare SemVer (`0.1.0`), never `v`-prefixed.

## One-time repository setup

1. Enable GitHub Actions. In branch rules for `main`, require the **Required checks**
   status and pull request review, and block force-pushes. Add a tag ruleset that
   prevents updating or deleting release tags.
2. In **Settings → Pages → Build and deployment**, select **GitHub Actions**. In
   **Settings → Environments → github-pages**, add a deployment rule that allows tags
   (for example the pattern `*.*.*`): Pages deploys from the release tag, and the default
   rule only allows the default branch. The Documentation workflow builds Dokka for pull
   requests and `main`, and deploys only for published releases.
3. In **Settings → Code security**, enable **Private vulnerability reporting** so the
   link in `SECURITY.md` works.
4. Register/verify ownership of the `com.maniramezan` namespace in the
   [Sonatype Central Portal](https://central.sonatype.com/).
5. Generate a Central Portal user token and prepare an OpenPGP signing key whose public
   key is available to Central. Create a GitHub environment named `maven-central` with
   required reviewers and a deployment rule limited to release tags. Add these
   environment secrets:

   | Secret | Value |
   |---|---|
   | `MAVEN_CENTRAL_USERNAME` | Central Portal user-token username |
   | `MAVEN_CENTRAL_PASSWORD` | Central Portal user-token password |
   | `SIGNING_KEY` | ASCII-armored private signing key |
   | `SIGNING_PASSWORD` | Signing-key passphrase; empty if the key has no passphrase |

   Never commit these values or paste them into issues, pull requests, or build logs.
   No credentials are needed for ordinary tests, docs, or the local publication check.
6. Add the repository secret `RELEASE_PLEASE_TOKEN`: a fine-grained personal access
   token restricted to this repository with **Contents**, **Pull requests**, and
   **Issues** read/write permissions. Enable Actions to create pull requests in
   repository settings. Keep this separate from the `maven-central` environment secrets.

Release Please deliberately requires this token instead of falling back to `GITHUB_TOKEN`:
the built-in token's PR/release events do not start the required PR checks, the release
workflow, or the Pages deployment. See
[Release Please's token guidance](https://github.com/googleapis/release-please-action#other-actions-on-release-please-prs)
and the [publisher's Central setup guide](https://vanniktech.github.io/gradle-maven-publish-plugin/central/).

## Verify a candidate

Run from an Apple silicon macOS host with JDK 21, Android SDK 36, and compatible Xcode:

```sh
./gradlew ktlintCheck jvmCoverageVerification
bash scripts/macos-keychain-tests.sh ./gradlew jvmTest macosArm64Test --rerun-tasks
./gradlew assemble checkKotlinAbi dokkaGeneratePublicationHtml
./gradlew publishAllPublicationsToVerificationRepository
python3 scripts/verify-artifacts.py build/verification-repository
./gradlew -p verification/consumer assemble -PverificationRepository="$PWD/build/verification-repository"
bash scripts/swift-interop-tests.sh
bash scripts/apple-simulator-tests.sh
python3 -m unittest discover -s scripts/tests
```

The macOS helper temporarily selects a new default keychain and restores the original on
exit. It creates only disposable test entries. Do not interrupt it with `kill -9`.

Run Android device tests on API 23 and a recent API (CI currently uses 35):

```sh
./gradlew connectedAndroidDeviceTest
```

CI also creates an isolated Secret Service session on Linux and tests Windows DPAPI
under the Windows runner's account. The separate consumer resolves this library only
from the generated filesystem repository and compiles for every declared target.

## Coverage and API stability

- Run `./gradlew ktlintCheck` before submitting changes; use `./gradlew ktlintFormat`
  to apply the repository's `.editorconfig`.
- `jvmCoverageReport` produces HTML and XML under `build/reports/jacoco/`.
  `jvmCoverageVerification` requires at least **85% line** and **70% branch** coverage
  across commonMain compiled for JVM plus jvmMain. It is part of `check`. It does not
  measure Android or Apple native execution.
- `checkKotlinAbi` checks the committed JVM, Android, and KLIB public API baselines in `api/`.
  After intentionally changing a public API, run `./gradlew updateKotlinAbi` on macOS
  and review the entire baseline diff. Do not update baselines just to silence a failure.
- Public declarations must have explicit visibility/types; Dokka fails on warnings and
  undocumented public API. Generated API docs are also packaged in javadoc JARs.
- `scripts/verify-artifacts.py` rejects JVM class files newer than Java 17. Raising the
  JVM target is a breaking change for consumers.

## Stage and publish

1. Squash-merge changes into `main` with conventional commit titles: `fix: ...` for
   fixes, `feat: ...` for features, and `feat!: ...` or a `BREAKING CHANGE:` footer
   for breaking changes. Release Please opens or updates a release PR with generated
   notes, `VERSION_NAME`, the README dependency example, and its version manifest.
   Add user-facing details and credential migration instructions to the PR description.
   No changelog file is generated; release notes live in GitHub Releases.
2. Merge only after the complete Verify and Documentation workflows pass. Review the
   native/mobile platform evidence and the public API baseline before merging.
3. Release Please creates the `VERSION_NAME` tag (for example `0.1.0`) and GitHub release.
   The published release starts **Stage Maven Central release** and the Pages deployment.
   A GitHub release does not mean the artifacts are already available in Central.
4. The staging workflow verifies the tag/version match and reruns the complete Verify
   workflow on that commit. After the `maven-central` environment gate, it builds and
   checks the full signed artifact set and stages it with `publishToMavenCentral`.
5. Inspect the staged deployment and its validation results in Central Portal. Publish
   it there after final review. The workflow does **not** call
   `publishAndReleaseToMavenCentral`; merging and tagging alone do not publish to Central.
6. Once Central serves the version, compile a fresh consumer using `mavenCentral()`
   without `mavenLocal()` or the verification repository. Check the Android AAR, JVM,
   and Apple KLIB variants, and confirm the GitHub Pages documentation is live.

The empty initial `.release-please-manifest.json` represents an unreleased package;
`initial-version` selects `0.1.0` for the first release PR. After that, Release Please
maintains the manifest. Do not reset it or leave a permanent `release-as` override.
Before 1.0, fixes and features bump the patch version and breaking changes bump the
minor version. To intentionally release 1.0.0, use a conventional commit with a
`Release-As: 1.0.0` footer. Snapshot PRs are disabled.

If automation needs recovery, rerun **Release Please** on `main`. If the GitHub release
already exists but staging or documentation did not start, dispatch them on its tag:

```sh
gh workflow run release.yml --ref 0.1.0
gh workflow run pages.yml --ref 0.1.0
```

Do not create a second tag or republish a version already released to Central. A manual
staging dispatch still checks the tag/version match and runs the complete Verify workflow.

For a local signed staging run, supply the same credentials through
`ORG_GRADLE_PROJECT_*` environment variables and pass `-PreleaseSigning=true`.
Published Maven Central versions cannot be overwritten; repair defects in a new version.
