# Installing without internet access

certloom makes no outbound connection unless configured to: no telemetry, no
update checks. It reaches only what you point it at: PostgreSQL, your ACME CA
or private CA (Vault, step-ca), your OIDC provider, the endpoints you scan and,
if you enable them, cloud APIs. In a closed network, issue from an internal CA
(step-ca's or Vault's ACME server, or the native Vault and step-ca issuers of
`docs/runbooks/agent.md`). `TestAirgapRenewal` runs enrollment, issuance,
renewal and deployment on a network without a route out (ADR-0032).

There are two ways in: carry the offline bundle, or mirror into the registry
and package repositories you already run.

## A. Offline bundle

Each release has `certloom-offline_<version>_linux_<arch>.tar.gz` (amd64,
arm64), plus `SHA256SUMS-offline` and `SHA256SUMS-offline.sigstore.json`.

On the connected side:

```sh
V=1.2.3
cosign initialize
cp ~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json .
cosign verify-blob SHA256SUMS-offline --bundle SHA256SUMS-offline.sigstore.json \
  --certificate-identity "https://github.com/alexandrosnt/certloom/.github/workflows/release-build.yml@refs/tags/v$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing SHA256SUMS-offline
```

Carry the bundle, `SHA256SUMS-offline*` and `trusted_root.json` in. On the
closed side, repeat the check with `--trusted-root trusted_root.json` (no
network needed), then unpack and check every file:

```sh
tar xzf certloom-offline_${V}_linux_amd64.tar.gz
cd certloom-offline_${V}_linux_amd64
sha256sum -c CONTENTS.sha256
```

### Compose install

```sh
docker load -i images/certloom.tar          # certloom:<version>
docker load -i images/postgres.tar          # postgres:18-alpine
cd compose && cp .env.example .env          # set passwords, see README.md
echo "CERTLOOM_IMAGE=certloom:$V" >> .env
docker compose up -d --no-build
```

`--no-build` matters: the Compose file can also build from source, which needs
the repository and the network. Continue with section 3 of `compose/README.md`.

### Packages

Install directly (`dpkg -i` / `dnf install ./…rpm` from `packages/`), or add
them to an internal repository. Import `gpg.key` so rpm can check signatures:

```sh
rpm --import gpg.key
dnf install ./packages/certloomd-*.rpm      # or certloom-agent
```

Then follow `docs/install-packages.md` (in the bundle) from "certloomd" on.

### Agents in containers

`docker load -i images/certloom-agent.tar`, or push it to the internal
registry (below).

## B. Mirroring

Most sites already run a registry (Harbor, Artifactory, Nexus, Quay) and a
package mirror. Copy by digest and keep the signatures and attestations with
the images, so `cosign verify` keeps working inside:

```sh
V=1.2.3
for img in certloom certloom-agent; do
  oras copy -r ghcr.io/alexandrosnt/$img:$V registry.internal/certloom/$img:$V
done
```

`oras copy -r` copies the image index with everything that refers to it: the
signature, the SBOM and the provenance attestation. Without a path between the
networks, `cosign save --dir` writes the same to disk and `cosign load` pushes
it inside. `skopeo copy --all` copies the image without them. The internal
registry must support OCI referrers (or the fallback tag scheme) and serve TLS.
Verify inside with `--trusted-root trusted_root.json` and the identity in
`docs/verify-release.md`.

Packages: mirror `https://alexandrosnt.github.io/certloom-packages/` with the
tool you use for other vendors (`reposync` / `dnf reposync` for
`rpm/<arch>`, `apt-mirror` or `aptly mirror` for `deb stable main`), keeping
the signed metadata, and point the repo files of `install-packages.md` at the
mirror.

## Inside the closed network

- **Plugins** (ADR-0027): set `plugins.trusted_root` in the agent config (an
  absolute path) to the file you carried in; keyless verification then needs
  no network.
- **ACME CA bundle**: `CERTLOOM_ACME_CA_FILE` on certloomd and `acme_ca_file` in
  the agent config must hold the internal CA's root.
- **Endpoint checks**: certloomd decides "publicly trusted" with the OS store
  of its host; private roots belong in a trust bundle (ADR-0030).
- **Time**: certificates and Sigstore verification depend on correct clocks;
  run NTP from an internal source.
- **Upgrades**: the next release's bundle, verified the same way. For
  certloomd, migrate before or right after the upgrade (`install-packages.md`).
