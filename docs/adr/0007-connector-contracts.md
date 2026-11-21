# ADR-0007: Connector and plugin contracts

**Status:** Accepted (2026-11-21)

## Context
Every integration must state exactly what it can do and be tested capability by
capability. Loading arbitrary third-party code into the
privileged process is a supply-chain risk.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Connectors compiled into the binary, behind versioned Go interfaces** | Only reviewed code runs; simple; fast | Third parties have to upstream their connector or fork |
| B. Out-of-process plugins (hashicorp/go-plugin over gRPC) | Isolation; third parties can extend | Plugin signing, distribution and version negotiation all have to exist first |
| C. Go `plugin` package or embedded scripting | - | Fragile (needs an exact toolchain match) and gives no isolation. Rejected |

## Decision
Option A for v1. Option B arrives in Phase 6, together with signed packages and explicit operator trust.

Connector kinds: `Discoverer`, `Issuer`, `ChallengeSolver`, `DeployTarget`, `Notifier`, `SecretProvider`. Every connector implements:

```go
type Descriptor struct {
    Name, Version   string
    ContractVersion int          // bumped on any breaking interface change
    Capabilities    []Capability // discover, read_metadata, request, renew, revoke, ...
    Permissions     []string     // human-readable least-privilege requirements
    Compatibility   []string     // tested external versions, e.g. "nginx 1.26-1.29"
}

// Preflight validates configuration and permissions without mutating anything.
Preflight(ctx context.Context, cfg Config) (Report, error)
```

Rules for every call:
- It receives only the `CredentialReference`s resolved for that one call (ADR-0009).
- Every mutating call takes an idempotency key.
- Errors come back as one of a fixed set of classes: `transient`, `permanent`, `auth`, `rate_limited{retry_after}`, `conflict`.

`connectors/contracttest` holds the shared test suite that every connector must pass.

## Consequences
`docs/integration-matrix.md` is generated from the capability lists. A capability that has no test cannot be declared.

## Verification
CI fails when a connector declares a capability that has no matching contract-test case.
