# Verifying a release

Every release file is listed in `SHA256SUMS`. That file is signed with Sigstore
(cosign keyless) by the release workflow, and GitHub attests the build
provenance of every file and image (ADR-0031). Verify before installing.

The signer is always the release workflow at the release tag:

```
identity: https://github.com/alexandrosnt/certloom/.github/workflows/release-build.yml@refs/tags/vX.Y.Z
issuer:   https://token.actions.githubusercontent.com
```

## Files

Download the files you need plus `SHA256SUMS` and `SHA256SUMS.sigstore.json`.

```sh
V=v1.2.3
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/alexandrosnt/certloom/.github/workflows/release-build.yml@refs/tags/$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing SHA256SUMS
```

Both commands must succeed. On Windows, `Get-FileHash` gives the SHA-256 to
compare with the line in `SHA256SUMS`.

Build provenance (SLSA, from GitHub artifact attestations):

```sh
gh attestation verify certloom-agent_1.2.3_linux_amd64.tar.gz \
  --repo alexandrosnt/certloom \
  --signer-workflow alexandrosnt/certloom/.github/workflows/release-build.yml
```

Each archive and package has an SPDX SBOM next to it (`<file>.sbom.json`),
covered by `SHA256SUMS`.

## Container images

Use the digest, not the tag, once verified.

```sh
IMG=ghcr.io/alexandrosnt/certloom:1.2.3
cosign verify "$IMG" \
  --certificate-identity "https://github.com/alexandrosnt/certloom/.github/workflows/release-build.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "oci://$IMG" --repo alexandrosnt/certloom
```

The image SBOM is attached as a BuildKit attestation:
`docker buildx imagetools inspect "$IMG" --format '{{ json .SBOM }}'`.

## Without network access

The Sigstore bundle contains the transparency log proof, so verification works
offline once you have Sigstore's trusted root. Fetch it on a connected machine
(cosign checks it against Sigstore's TUF root) and carry it over with the
release files:

```sh
cosign initialize
cp ~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json .
```

Then, on the offline machine:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --trusted-root trusted_root.json \
  --certificate-identity "https://github.com/alexandrosnt/certloom/.github/workflows/release-build.yml@refs/tags/$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`gh attestation verify --bundle <file> --custom-trusted-root trusted_root.json`
does the same for provenance downloaded with `gh attestation download`.

## Offline bundles

`certloom-offline_<version>_linux_<arch>.tar.gz` are listed in
`SHA256SUMS-offline`, signed the same way (`SHA256SUMS-offline.sigstore.json`,
same identity). See `docs/runbooks/airgap.md`.

## deb and rpm packages

Packages are also signed with the certloom packaging key (OpenPGP, RSA 4096):

```
fingerprint: C43A 8AC9 70C2 7697 1D48  89C2 94E7 B14D D223 1CF4
key:         https://alexandrosnt.github.io/certloom-packages/gpg.key
```

The apt and yum repositories check this key on every install and upgrade; see
`docs/runbooks/install-packages.md`. For a single downloaded file:

```sh
rpm --import gpg.key && rpm --checksig certloomd-1.2.3-1.x86_64.rpm
```

## Windows

Windows binaries are covered by `SHA256SUMS`, cosign and provenance like
everything else. Authenticode signing through SignPath Foundation is pending;
until then Windows shows an unknown-publisher warning.
