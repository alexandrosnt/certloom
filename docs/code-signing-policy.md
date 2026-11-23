# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io/),
certificate by [SignPath Foundation](https://signpath.org/) (pending approval).

## What is signed

- Windows binaries `certloom.exe`, `certloom-agent.exe` and
  `certloom-plugin.exe` from this repository, built from a tagged commit by the
  release workflow (`.github/workflows/release-build.yml`).
- Nothing built outside that workflow, and no third-party binaries.

All release files are also covered by a Sigstore signature and GitHub build
provenance; see [verify-release.md](verify-release.md).

## Roles

- Committers and reviewers: [Alexandros Nt.](https://github.com/alexandrosnt)
- Approver of each release: [Alexandros Nt.](https://github.com/alexandrosnt),
  through the `release` environment of the repository.

Every change reaches `main` through the repository's CI. Releases run only
from tags on `main` and need the approver's confirmation.

## Privacy

The signed programs do not transfer data to any system unless the user
configures it: the agent connects only to the certloom control plane, ACME CAs
and endpoints its configuration names, and the CLI only to the control plane
it is given. There is no telemetry.
