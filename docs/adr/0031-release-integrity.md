# ADR-0031: Signed releases, SBOMs and build provenance

**Status:** Accepted (2026-11-23)

## Context
ADR-0014 commits to reproducible builds, SPDX SBOMs, cosign keyless signatures and SLSA
provenance, but nothing is released yet. Today `deploy/packaging/build.sh` builds the
agent deb/rpm by hand, CI builds the two images without pushing them, and the Windows
agent is a bare exe. certloom runs with high privilege on customer hosts (it writes
keys, trust stores and web server config), so a tampered release would be a direct path
into every installation. The air-gapped install (next M8 item) also needs artifacts
that can be verified without network access.

Artifacts per release:
- binaries: `certloomd` (linux amd64/arm64), `certloom` CLI (linux, windows, darwin;
  amd64/arm64), `certloom-agent` and `certloom-plugin` (linux amd64/arm64, windows
  amd64), as tar.gz (zip on Windows);
- deb and rpm packages for `certloom-agent` and `certloomd`;
- container images `ghcr.io/alexandrosnt/certloom` and `certloom-agent` (multi-arch);
- a Windows MSI for the agent.

## Options considered
| Question | Options | Chosen |
|---|---|---|
| Build tool | **GoReleaser** / hand-written scripts | GoReleaser: used by Smallstep and by our Terraform provider; drives nFPM (already used), images, archives and checksums from one file |
| Provenance | **GitHub artifact attestations (`actions/attest`)** / slsa-github-generator | attest: Sigstore bundles verifiable with `gh` and cosign, SLSA Build L3 when run from an isolated reusable workflow; one fewer project to depend on |
| deb/rpm distribution | **own signed apt/yum repo on GitHub Pages** / Cloudsmith / release assets only | own repo: we hold the key, no third party, `apt upgrade` and `dnf upgrade` work |
| Windows signing | **SignPath Foundation** / Azure Artifact Signing / cosign only | SignPath: free for OSI-licensed projects with automated builds |

## Decision

### Pipeline
- A tag `vX.Y.Z` on `main` starts `.github/workflows/release.yml`. The job runs in a
  GitHub environment `release` that requires the owner's approval and holds the only
  release secrets (packaging GPG key, SignPath token). Actions are pinned by commit
  SHA, GoReleaser, syft and cosign by version. Job permissions are the minimum:
  `contents: write`, `packages: write`, `id-token: write`, `attestations: write`.
- GoReleaser builds everything with `CGO_ENABLED=0 -trimpath`, `mod_timestamp` set to
  the commit time and `SOURCE_DATE_EPOCH` for nFPM, so the same commit gives the same
  bytes. A CI job builds a release snapshot twice on separate runners and compares the
  checksums of binaries and archives. Packages and images are best effort, not
  claimed reproducible.
- Images use the existing Dockerfiles with base images pinned by digest and are pushed
  by digest.

### Signatures and SBOMs
- `SHA256SUMS` lists every release file. It is signed with cosign keyless (GitHub OIDC)
  and published with its Sigstore bundle `SHA256SUMS.sigstore.json`, so one
  verification covers all files. The bundle carries the Rekor inclusion proof and
  verifies offline with a `trusted_root.json`, the same model as signed plugins
  (ADR-0027).
- Images are signed by digest with cosign keyless.
- syft writes one SPDX JSON SBOM per archive and package, listed in `SHA256SUMS`, and
  one per image, attached as an attestation.
- The signing identity is the release workflow:
  `https://github.com/alexandrosnt/certloom/.github/workflows/release-build.yml@refs/tags/vX.Y.Z`
  (the reusable workflow that `release.yml` calls),
  issuer `https://token.actions.githubusercontent.com`. `docs/verify-release.md` gives
  the cosign, `gh attestation verify` and `rpm`/`apt` commands.

### Provenance
- `actions/attest-build-provenance` (or `actions/attest`, which newer releases of it
  wrap) runs in a reusable workflow called by the release job, with the checksums file
  as subjects and the image digests. This is SLSA Build L3 as documented by GitHub. We
  claim L3 only once the reusable workflow is in place and verified.

### deb and rpm
- nFPM signs each rpm and deb with a dedicated packaging key (RSA 4096, two-year
  expiry, not the Terraform provider key). The public key and its fingerprint are in
  the repo and the docs.
- The release workflow regenerates apt (`InRelease`/`Release.gpg`) and yum
  (`repomd.xml.asc`) metadata and pushes it to a separate repo
  `alexandrosnt/certloom-packages` served by GitHub Pages. yum configs set both
  `gpgcheck` and `repo_gpgcheck`.
- A runbook covers key rotation: new key signed by the old one, both published for an
  overlap period, rotation well before expiry (Grafana's 2023 rotation and Caddy's
  expired-subkey outage are the cautionary cases).

### Windows
- The agent MSI is built with WiX and installs the existing service.
- Apply to SignPath Foundation (owner action). Once approved, the release signs
  `certloom-agent.exe` and `certloom-plugin.exe` before the MSI is built, then the MSI,
  then checksums and cosign. SignPath requires a code signing policy page, which goes
  in the docs.
- Until then Windows files are released unsigned by Authenticode but covered by
  `SHA256SUMS`, cosign and provenance like everything else. The release notes say so.

## Consequences
- A release is a tag push plus one approval; no manual build steps.
- Users can verify every file offline. Air-gapped installs (next) build on the same
  bundles and need a `trusted_root.json` obtained once from Sigstore's TUF repository.
- The packaging key is a long-lived secret in a GitHub environment. Its compromise
  would let an attacker sign packages but not the cosign signatures or provenance,
  which are bound to the workflow identity.
- The package repo URL is a GitHub Pages URL; moving to a custom domain later means
  users change their source files.
- New build dependencies: GoReleaser, syft, cosign, WiX (all pinned, none linked into
  certloom).

## Industry practice (surveyed 2026-11-23)
| Who | Practice | Source |
|---|---|---|
| Smallstep step-ca / step CLI | GoReleaser + nFPM deb/rpm; cosign signatures and checksums for all assets | [.goreleaser.yml](https://www.github.com/smallstep/certificates/blob/master/.goreleaser.yml), [release process](https://smallstep.com/blog/five-years-of-oss-releases/) |
| Kubernetes | cosign keyless on binaries, tarballs and SPDX SBOM; image verification by OIDC identity | [verify signed artifacts](https://kubernetes.io/docs/tasks/administer-cluster/verify-signed-artifacts/) |
| cert-manager | cosign-signed images (public key), GPG-signed Helm charts | [code signing](https://cert-manager.io/docs/installation/code-signing/) |
| GitHub | artifact attestations: SLSA Build L2, L3 from an isolated reusable workflow | [docs](https://docs.github.com/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds), [blog](https://github.blog/enterprise-software/devsecops/enhance-build-security-and-reach-slsa-level-3-with-github-artifact-attestations/) |
| slsa-github-generator | L3 provenance from reusable workflows, verified by slsa-verifier | [GoReleaser example](https://github.com/goreleaser/goreleaser-example-slsa-provenance) |
| Grafana | own apt/yum repos with `gpgcheck` and `repo_gpgcheck`; key rotated after a 2023 leak | [apt.grafana.com](https://apt.grafana.com/), [review](https://grafana.com/blog/2023/09/06/grafana-security-update-post-incident-review-and-timeline-for-gpg-signing-key-rotation) |
| Caddy | apt repo on Cloudsmith, which signs; Oct 2026 outage from an expired subkey | [setup](https://cloudsmith.io/~caddy/repos/stable/setup), [thread](https://caddy.community/t/cloudsmith-debian-repository-signing-key-expired/33954) |
| SignPath Foundation | free Authenticode for OSI-licensed projects with automated builds | [SignPath OSS](https://about.signpath.io/product/open-source) |
| Microsoft | Azure Artifact Signing as the managed (paid) service | [signing overview](https://learn.microsoft.com/en-us/windows/msix/package/signing-package-overview) |

Not found: HashiCorp's own release signing and repo setup; SBOMs from Smallstep or
cert-manager.

## As built (2026-11-23)
- `.goreleaser.yaml` (GoReleaser v2.20.0) is the only package definition;
  `deploy/packaging/nfpm.yaml` is gone and `deploy/packaging/build.sh` runs an
  unsigned snapshot of the same file in the GoReleaser image (Docker only).
  New `certloomd` deb/rpm: unprivileged unit, sysusers entry,
  `/etc/certloom/certloomd.env`; migrations stay a manual owner-role step.
- The release tag is passed as `GORELEASER_CURRENT_TAG`: the `client/v*` tags
  of the nested module would otherwise be picked up, and tag-prefix filtering
  is not in the open-source edition.
- Reproducibility: with `SOURCE_DATE_EPOCH` and a fixed rpm build host, all
  unsigned outputs (binaries, archives, deb, rpm) are byte-identical across
  runs. CI builds on ubuntu-24.04 and ubuntu-22.04 and diffs `SHA256SUMS`. Both
  use the same pinned GoReleaser image, so this shows host and time
  independence, not an independent toolchain.
- GoReleaser's `--skip=sign` also turns off nFPM package signing, and `signs`
  cannot be disabled per run, so snapshots are fully unsigned. The package
  signing path is exercised only by a tagged run; the first release is a
  release candidate (`docs/runbooks/release.md`).
- Images: `deploy/docker/*.Dockerfile` copy the GoReleaser binaries onto
  distroless pinned by digest; image SBOMs are BuildKit attestations (syft
  scanner), signatures by digest with cosign keyless.
- Provenance: `actions/attest-build-provenance` in `release-build.yml`, the
  reusable workflow called by `release.yml`, for `SHA256SUMS` subjects and both
  image digests.
- Repositories: `deploy/packaging/publish-repo.sh` (apt-ftparchive,
  createrepo_c, keeps 5 versions per package and architecture because a Pages
  site is limited to 1 GB). Release notes come from the CHANGELOG section of
  the version (`deploy/release/notes.sh`); a missing section stops the release.
- Tests: `TestCertloomdPackage` (deb in a systemd image with
  `systemd-analyze verify`, rpm on Rocky 9), `TestPackageRepo` (publish, apt
  install with signed metadata, dnf install with `gpgcheck` and
  `repo_gpgcheck`, tampered `repomd.xml` refused), `TestSystemdPackageRenewal`
  now uses the GoReleaser-built package.
- Docs: `docs/verify-release.md`, `docs/runbooks/release.md`,
  `docs/runbooks/install-packages.md`, `docs/code-signing-policy.md`.
- Not yet: the Windows MSI (WiX v6 and later fall under the Open Source
  Maintenance Fee; tool choice pending) and Authenticode (SignPath application).
