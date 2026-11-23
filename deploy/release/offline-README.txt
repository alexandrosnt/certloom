# certloom offline bundle

Everything needed to install certloom without internet access. Full guide:
docs/airgap.md in this bundle.

Before carrying this file in, verify the bundle itself on the connected side
with SHA256SUMS-offline and its Sigstore bundle (docs/verify-release.md).

Inside:
  archives/   certloomd, certloom CLI, certloom-agent + certloom-plugin
  packages/   deb and rpm of certloomd and certloom-agent
  images/     certloom, certloom-agent, postgres:18-alpine (docker load -i)
  compose/    compose.yaml, .env.example, README.md
  docs/       airgap.md, install-packages.md, verify-release.md
  SHA256SUMS, SHA256SUMS.sigstore.json   the release checksums and signature
  gpg.key     the packaging key (rpm --import, apt signed-by)
  CONTENTS.sha256                        checksums of every file here

Check the files after copying:   sha256sum -c CONTENTS.sha256
