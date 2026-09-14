# Release and maintenance guide

The release pipeline targets Maven Central (`dev.amoo:credential-keychain-kotlin`) and
GitHub Pages. A successful local compiler run alone does not establish release readiness:
the complete Verify workflow, artifact consumer, and device tests must pass on the exact
release commit.

## One-time repository setup

1. Connect this checkout to `maniramezan/credential-keychain-kotlin`, or update the repository
   URLs in the POM, Dokka source links, module guide, and README to the intended repository.
   Commit the sources, API baselines, scripts, and workflows; push them to `main`.
2. Enable GitHub Actions. Require the Verify workflow's desktop, multiplatform, Android,
   and workflow-lint jobs in the repository's branch rules. Enable required pull request
   review and prevent force-pushing release tags.
3. In **Settings → Pages → Build and deployment**, select **GitHub Actions**. The
   Documentation workflow builds Dokka for pull requests and deploys only `main` to
   the `github-pages` environment. Until it has deployed successfully, the Pages URL
   in README is only the intended destination.
4. Register/verify ownership of the `dev.amoo` namespace in the
   [Sonatype Central Portal](https://central.sonatype.com/). If that namespace is not
   yours, choose a verified namespace and update both publishing and consumer checks
   before the first release.
5. Generate a Central Portal user token and prepare an OpenPGP signing key whose public
   key is available to Central. Create a GitHub environment named `maven-central` with
   required reviewers and tag-only deployment rules. Add these environment secrets:

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
   **Issues** read/write permissions. The token owner must be allowed to create
   release branches, PRs, tags, and releases. Approve the token for the organization
   if required, and enable Actions to create pull requests in repository settings.
   Keep this separate from the `maven-central` environment secrets.

Release Please deliberately requires this token instead of falling back to `GITHUB_TOKEN`:
the built-in token's PR/release events do not start the required PR checks or release
workflow. See [Release Please's token guidance](https://github.com/googleapis/release-please-action#other-actions-on-release-please-prs).

See the [publisher's Central setup guide](https://vanniktech.github.io/gradle-maven-publish-plugin/central/)
for namespace, token, and key requirements.

## Verify a candidate

Run from a macOS host with JDK 21, Android SDK 36, and compatible Xcode:

```sh
./gradlew jvmCoverageVerification
bash scripts/macos-keychain-tests.sh ./gradlew jvmTest macosArm64Test --rerun-tasks
./gradlew assemble jsNodeTest wasmJsNodeTest checkKotlinAbi dokkaGeneratePublicationHtml
./gradlew publishAllPublicationsToVerificationRepository
python3 scripts/verify-artifacts.py build/verification-repository
./gradlew -p verification/consumer assemble -PverificationRepository="$PWD/build/verification-repository"
python3 -m unittest discover -s scripts/tests
```

The macOS helper temporarily selects a new keychain and restores the original default
on exit. It creates only disposable test entries. Do not interrupt it with `kill -9`.

Run Android device tests on API 23 and a recent API (CI currently uses 35):

```sh
./gradlew connectedAndroidDeviceTest
```

CI also creates an isolated Secret Service session on Linux and tests Windows DPAPI
under the Windows runner's account. The separate consumer resolves this library only
from the generated filesystem repository and compiles for every declared target.

## Coverage and API stability

- `jvmCoverageReport` produces HTML and XML under `build/reports/jacoco/`.
- `jvmCoverageVerification` requires at least **85% line** and **70% branch** coverage
  across **commonMain compiled for JVM plus jvmMain**, including backend adapters.
  It is part of `check`. No production packages are excluded to raise the percentage.
- This percentage does not measure Android, Apple native, JS, or Wasm execution.
  Android emulator tests cover real encryption, tampering, ciphertext substitution,
  key loss, concurrency, atomic-backup recovery, and account isolation. Native Apple
  tests run on macOS against an isolated Keychain. iOS/tvOS/watchOS are compiled in CI;
  their signing/access behavior still needs representative device validation.
- `checkKotlinAbi` checks committed JVM and KLIB public API baselines in `api/`.
  Kotlin's current built-in validator does not include the new Android KMP plugin's
  Context extension in these dumps; the separate Android consumer checks its source API.
- After intentionally changing a public API, run `./gradlew updateKotlinAbi` on macOS
  and review the entire baseline diff. Do not update baselines just to silence a failure.
- Public declarations must have explicit visibility/types; Dokka fails on warnings and
  undocumented public API. Generated API docs are also packaged in javadoc JARs.

## Stage and publish

1. Squash-merge changes into `main` with conventional commit titles: `fix: ...` for
   fixes, `feat: ...` for features, and `feat!: ...` or a `BREAKING CHANGE:` footer
   for breaking changes. Release Please opens or updates a release PR with generated
   notes, `VERSION_NAME`, the README dependency example, and its version manifest.
   Add user-facing details and credential migration instructions to the PR description.
   Keep the generated version/notes section intact. No changelog file is generated.
2. Merge only after the complete Verify and Documentation workflows pass. Review the
   native/mobile platform evidence and the public API baseline before merging the release PR.
3. Release Please creates the corresponding `vVERSION_NAME` tag and GitHub release.
   The published GitHub release event starts **Stage Maven Central release** automatically.
   A GitHub release does not mean that the artifacts are already available in Central.
4. The workflow verifies the tag/version match and reruns the complete Verify workflow
   on that commit. After the `maven-central` environment gate, it builds and checks the
   full signed artifact set and stages it with `publishToMavenCentral`.
5. Inspect the staged deployment and its validation results in Central Portal. Publish
   it there after final review. This workflow does **not** call
   `publishAndReleaseToMavenCentral`; merging and tagging alone do not publish to Central.
6. Once Central serves the version, compile a fresh consumer using `mavenCentral()`
   without `mavenLocal()` or the verification repository. Check the Android AAR, JVM,
   Apple KLIB, and web variants, and confirm the GitHub Pages documentation is live.

The empty initial `.release-please-manifest.json` represents an unreleased package;
`initial-version` selects `0.1.0` for the first release PR. After that, Release Please
maintains the manifest. Do not reset it or leave a permanent `release-as` override.
Before 1.0, fixes and features bump the patch version and breaking changes bump the
minor version. To intentionally release 1.0.0, use a conventional commit with a
`Release-As: 1.0.0` footer. Snapshot PRs are disabled.

If automation needs recovery, rerun **Release Please** on `main`. If the GitHub release
already exists but staging did not start, dispatch staging on its existing tag:

```sh
gh workflow run release.yml --ref v0.1.0
```

Do not create a second tag or republish a version already released to Central. A manual
staging dispatch still checks the tag/version match and runs the complete Verify workflow.

For a local signed staging run, supply the same credentials through
`ORG_GRADLE_PROJECT_*` environment variables and pass `-PreleaseSigning=true`.
Published Maven Central versions cannot be overwritten; repair defects in a new version.
