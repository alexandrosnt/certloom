# ADR-0014: License, governance and release integrity

**Status:** Accepted (2026-11-21). The project owner chose the license on 2026-11-20.

## Options considered
| License | For | Against |
|---|---|---|
| **Apache-2.0** | Explicit patent grant; enterprise-friendly; same as the cert-manager and Kubernetes ecosystem | Allows closed forks |
| MPL-2.0 | File-level copyleft | Less familiar to infrastructure adopters |
| AGPL-3.0 | Prevents closed SaaS forks | Many companies ban it; reduces adoption |

## Decision
**License and contributions**
- Apache-2.0, with DCO sign-off (no CLA).

**Dependency licenses**
- Allowed: MIT, BSD, Apache-2.0, ISC.
- MPL-2.0 only as an unmodified dependency, recorded in `NOTICE`/`THIRD_PARTY`. This applies to River if ADR-0003 ever swaps it in.
- GPL/AGPL dependencies are not accepted. A license check (go-licenses) runs in CI from M1.

**Versioning**
- SemVer. Before 1.0, the only compatibility promise is the documented API version.

**Releases (from M1)**
- Reproducible builds with `go build -trimpath`.
- SBOM (SPDX via syft).
- cosign keyless signatures and SLSA build provenance. How: ADR-0031.
- Container images on a minimal/distroless base.

**Telemetry**
- None. If it is ever added, it is opt-in with a published data dictionary.

**Compliance**
- The project provides controls and evidence. It does not claim SOC 2, ISO 27001 or NIS2 compliance.
