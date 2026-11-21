# ADR-0005: Private-key custody

**Status:** Accepted (2026-11-21)

## Context
The control plane must not turn into a private-key vault by accident.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Keys are generated where they are used (agent, OS store, HSM, or provider-managed non-exportable key); only CSRs and public certificates leave that place** | Compromising the control plane does not expose leaf keys | Targets that require us to hand over a key can only be served where an agent runs |
| B. Central generation + encrypted escrow | Simple deployment to any API-driven target | The control plane becomes the most valuable target; backups contain keys |

## Decision
Option A is the only mode in v1.

Each key is represented by a `KeyReference` with these fields:
- custody mode (local file, OS store, HSM/TPM, cloud KMS, provider-managed, external secret store, escrow, unknown);
- exportable flag;
- location fingerprint: a hash of the path, store or handle, rather than the raw path when that is sensitive;
- algorithm;
- `created_at`.

Rules:
- A new key is generated on every renewal by default. Reusing a key is a policy setting that must be set explicitly.
- For imported PKCS#12 files, the private key is used only to confirm it matches the certificate, then dropped from memory. It is never persisted.
- Escrow (option B) can only be added later through a new ADR, and then only as an explicit opt-in per policy.

## Consequences
Some cloud targets have "import certificate + key" APIs. Those need either the agent or a later, explicitly approved escrow mode. The integration matrix documents this gap.

## Verification
- A schema test confirms that no column type or name can hold private-key material.
- A log-scan test seeded with known key bytes finds them nowhere in the logs.
