# ADR-0001: Deployment topology, modular monolith

**Status:** Accepted (2026-11-21)

## Context
Renewals will depend on this platform, so it has to be easier to keep running than
the infrastructure it manages. Operators range from a two-person team to
a large organization. A hosted SaaS is not a goal.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Modular monolith** (`certloomd`: API, UI, scheduler and workers in one binary; internal packages behind interfaces) | One artifact to deploy, upgrade and back up; in-process calls; simple HA (N replicas + Postgres) | Module boundaries need discipline; a single blast radius |
| B. Microservices (inventory, scheduler, notifier, API...) | Each part scales on its own | Network failure modes, service discovery and distributed tracing are all needed from day one; small teams cannot run it |
| C. Kubernetes-only operator | Natural fit for Kubernetes shops | Shuts out VM- and Windows-first users; duplicates cert-manager |

## Decision
Option A. Process roles can be selected by flag (`--roles=api,ui,worker,scheduler`,
default: all), so splitting them later needs no code restructuring.

Multi-organization support is **logical**. Every row owned by a tenant carries `org_id`,
enforced by service-layer authorization plus Postgres row-level security (ADR-0008).
It is not designed, and must not be claimed, as an isolation boundary for a hostile
multi-tenant SaaS.

## Consequences
- Module boundaries are enforced through Go `internal/` packages and an import-lint rule.
- HA means several `certloomd` replicas sharing one Postgres. Correctness depends on database leases (ADR-0003), never on in-memory state.
- Untrusted third-party plugins must never run inside this process (ADR-0007).

## Verification
In e2e, kill one of two replicas in the middle of a probe sweep. The other replica must finish the work without sending duplicate notifications.
