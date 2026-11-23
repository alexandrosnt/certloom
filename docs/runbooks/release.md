# Cutting a release

Releases are built, signed and published by `.github/workflows/release.yml`
when a `vX.Y.Z` tag is pushed (ADR-0031). Nothing is built on a workstation.

## One-time setup

1. **Packaging key.** On an offline or trusted machine:
   ```sh
   gpg --quick-gen-key 'certloom packages <certloom@example.com>' rsa4096 sign 2y
   gpg --armor --export-secret-keys <FPR> > package-key.asc      # secret
   gpg --armor --export <FPR> > gpg.key                         # public
   ```
   Keep an offline backup of the secret key and its revocation certificate
   (`~/.gnupg/openpgp-revocs.d/<FPR>.rev`). Publish the fingerprint in
   `docs/verify-release.md`. Use this key for packages only.
2. **Package repository.** Create the public repo `alexandrosnt/certloom-packages`
   with one commit containing `gpg.key` and a short README, and turn on GitHub
   Pages for its default branch (root).
3. **Token.** A fine-grained personal access token limited to
   `certloom-packages`, permission Contents: read and write, one-year expiry.
4. **Environment.** In the certloom repo settings, create environment
   `release`:
   - required reviewer: the owner; deployment tags: `v*` only;
   - secrets `PACKAGE_GPG_KEY` (contents of `package-key.asc`),
     `PACKAGE_GPG_PASSPHRASE`, `PACKAGES_REPO_TOKEN`.
   Delete `package-key.asc` from the workstation afterwards.
5. **Tag protection.** A ruleset on `refs/tags/v*` that only the owner may
   create, update or delete.

## Release

1. Rename `## Unreleased` in `CHANGELOG.md` to `## X.Y.Z - YYYY-MM-DD`, add a
   new empty `## Unreleased` above it, commit and push to `main`. Wait for CI.
2. Tag and push:
   ```sh
   git tag -s vX.Y.Z -m vX.Y.Z
   git push origin vX.Y.Z
   ```
   A tag with a suffix (`v0.2.0-rc.1`) makes a pre-release and does not move
   the `latest` image tag.
3. Approve the two `release` deployments in the Actions run (build, then
   repository publish).
4. After the first release only: set both GHCR packages (`certloom`,
   `certloom-agent`) to public in their package settings; new packages start
   private, and users and mirrors pull them without credentials.
5. Verify what was published, from a clean machine, with the commands in
   `docs/verify-release.md`: cosign on `SHA256SUMS` and `SHA256SUMS-offline`,
   `gh attestation verify` on one archive and both images, and an
   `apt-get install` / `dnf install` from the repositories.

The workflow refuses to run when the tag is not on `main` or `CHANGELOG.md`
has no section for the version.

A first release, or one after changes to `.goreleaser.yaml` or the release
workflows, should be a release candidate: local and CI snapshots skip all
signing (GoReleaser's `--skip=sign` also turns off package signing), so only a
tagged run exercises the signing steps.

## Rotating the packaging key

Every two years, or at once if the key may have leaked.

1. Generate the new key as above and sign it with the old one:
   `gpg --default-key <OLD> --sign-key <NEW>`.
2. Publish both public keys in `gpg.key` of `certloom-packages` (concatenated)
   for one release cycle, announce the new fingerprint in the release notes and
   in `docs/verify-release.md`.
3. Replace `PACKAGE_GPG_KEY` and `PACKAGE_GPG_PASSPHRASE` in the `release`
   environment. The next release re-signs the repository metadata with the
   new key.
4. After the overlap, drop the old key from `gpg.key`.

If the key leaked, publish the revocation certificate, rotate at once, re-sign
all packages still in the repository and say so in a security advisory.

## Windows signing (SignPath Foundation)

Pending: apply at https://signpath.org/apply. The project needs the code
signing policy page (`docs/code-signing-policy.md`) and fully automated
builds, which the release workflow provides. Once approved, add the SignPath
step to `release-build.yml` before archives are made.
