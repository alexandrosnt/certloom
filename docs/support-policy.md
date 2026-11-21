# Support and compatibility policy

Pre-1.0 policy. "Tested" means CI runs it on every change. "Best effort" means it is
expected to work but nothing proves it. Anything not listed here is unsupported.

Versions last checked **2026-11-20**. This file is
re-checked at every milestone.

## Toolchain
| Component | Policy | Current |
|---|---|---|
| Go | Builds with the two supported Go release lines; `go.mod` declares the older one | 1.26 (minimum) and 1.27 |

## Control plane (`certloomd`)
| Platform | Status |
|---|---|
| Linux amd64 / arm64 container image | Tested (M1) |
| Linux amd64 / arm64 static binary | Best effort (M1) |
| Windows / macOS | Development only; not supported for production |
| PostgreSQL 16, 17, 18 | Tested (M1) |
| PostgreSQL 15 | Best effort until upstream EOL (2027-11-11) |
| PostgreSQL 19 | Added to CI after its first minor release |

## CLI (`certloom`)
Linux, macOS and Windows on amd64/arm64: builds are tested; e2e tests run on Linux only.

## Agent (`certloom-agent`, M2)
| OS | Status |
|---|---|
| Ubuntu 22.04, 24.04 | Planned: tested in M2 |
| Debian 12 | Planned: tested in M2 |
| RHEL 9 (SELinux enforcing) | Planned: tested in M2 |
| Windows Server | Planned for M4 |

| Software | Status |
|---|---|
| Nginx (distribution and nginx.org stable/mainline packages) under systemd | Planned for M2; exact versions are pinned when M2 starts |
| Certbot >= 4.1.0 (ARI-aware) for read-only discovery | Planned for M2; older versions are discovered but flagged as not ARI-aware |

## ACME servers
| Server | Status |
|---|---|
| Pebble v2.10.x | Tested in CI (M2) |
| Let's Encrypt staging | Manually tested before each release (M2) |
| Let's Encrypt production | Supported once the staging tests pass |
| Other ACME CAs | Not claimed until tested |

## Deprecation
- Dropping a platform or version is announced one minor release ahead in the changelog.
- API versions follow ADR-0010.
