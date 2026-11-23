# ADR-0032: Air-gapped installation

**Status:** Accepted (2026-11-23)

## Context
Certificate management often runs in closed networks: internal PKI, OT sites,
regulated environments. certloom itself needs no internet access: there is no
telemetry or update check, ACME and private CAs can be internal (ADR-0028),
and plugin signatures verify against a local Sigstore trusted root
(ADR-0027). The only built-in external endpoints are the Let's Encrypt
directory presets and the cloud APIs, both used only when configured. What is
missing is a way to get a release into such a network with its integrity
intact, and a test that proves the product works there.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Offline bundle per architecture, plus documented mirroring, plus a no-egress e2e test** | Small sites carry one file; large sites use the registry and mirrors they already run; the claim is tested | One more release asset (~200 MB per architecture) |
| B. Mirroring docs and the test only | Least to build | Small sites without a registry or mirror have to assemble files by hand |
| C. Bundle only | One path to document | Ignores the infrastructure most enterprises already have; untested claim |

## Decision
Option A.

### Offline bundle
- Per release and architecture: `certloom-offline_<version>_linux_<arch>.tar.gz`,
  built by `deploy/release/offline-bundle.sh` in the release workflow after the
  images are pushed. Contents: the Linux archives and deb/rpm packages of that
  architecture, the release `SHA256SUMS` and its Sigstore bundle, the public
  packaging key, the `certloom`, `certloom-agent` and `postgres:18-alpine`
  images as docker-archive tarballs (`docker load`, `podman load`,
  `skopeo copy`), the Compose files, the air-gap, install and verification
  docs, and `CONTENTS.sha256` over every file.
- The bundles are listed in `SHA256SUMS-offline`, signed with cosign keyless
  (`SHA256SUMS-offline.sigstore.json`) and attested like the other release
  files. Verification works offline with a `trusted_root.json` that the user
  fetches through Sigstore's TUF client on the connected side; the bundle does
  not carry one, because a root shipped with the thing it verifies proves
  nothing.
- The tar has fixed order, owners and times (`SOURCE_DATE_EPOCH`) and is
  gzipped without a timestamp, so the same inputs give the same bytes.
- Images in the bundle are single-platform copies. Their signatures are on the
  multi-platform index, so the bundle tarball's signature covers them instead;
  sites that verify images at admission use the mirroring path.

### Mirroring
- Images with their signature, SBOM and provenance: `oras copy -r` (OCI
  referrers), or `cosign save` / `cosign load` across a disk. `cosign copy` is
  deprecated in cosign v3.
- Packages: the site's own tools (`dnf reposync`, `apt-mirror`, `aptly`),
  keeping the signed metadata.

### Test
- `TestAirgapRenewal` runs PostgreSQL, certloomd, step-ca's ACME provisioner
  and nginx with the agent on a Docker network created with `--internal`. A
  socat container on both networks is the only way in, for the CLI on the
  host. Enrollment, issuance, a renewal that replaces the certificate,
  deployment and verification must succeed, and a request to the internet from
  the web container must fail.
- CI builds an amd64 bundle from the snapshot images on every push, checks
  `CONTENTS.sha256` and loads and runs the certloom image.

## Consequences
- Each release carries about 400 MB more assets (two bundles).
- Bundle images are mutable only by a new release; a PostgreSQL security fix
  between certloom releases means pulling the newer image through the
  site's usual process.
- The GHCR packages must be public for `skopeo` and `oras` to pull them
  without credentials.
- Not covered: Kubernetes manifests or a Helm chart for offline clusters
  (there is no chart yet), Windows offline installs beyond the zip archive.

## Industry practice (surveyed 2026-11-23)
| Who | Practice | Source |
|---|---|---|
| RKE2 (SUSE) | Download binaries, image tarballs and checksums on a connected host, copy the directory, `install.sh` checks the checksums | [RKE2 air-gap install](https://docs.rke2.io/install/airgap) |
| Harbor | Separate offline installer with all images, GPG `.asc` signature | [download the installer](https://goharbor.io/docs/install-config/download-installer/) |
| SUSE Private Registry / Hauler | Store tarball carried by removable media, then copied into an internal registry | [air-gap install](https://documentation.suse.com/cloudnative/suse-private-registry/html/private-registry/pr-install-airgap.html) |
| Zarf, Hauler (as documented by NVIDIA) | Mirror images into an internal registry; cosign v3 bundle signatures need a TLS registry | [air-gapped mirroring](https://docs.nvidia.com/aicr/user-guide/air-gapped-mirroring) |
| NGINX, Cortex XSOAR | Prepare on a connected host, transfer, install locally | [NGINX](https://docs.nginx.com/waf/install/disconnected-environment/), [XSOAR](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Engine-air-gap-installation) |

Not found: how Venafi/CyberArk and Keyfactor document disconnected installs
(Keyfactor's container install pulls from its own registry).
