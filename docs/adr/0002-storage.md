# ADR-0002: Authoritative storage, PostgreSQL only

**Status:** Accepted (2026-11-21)

## Context
We need durable state, audit records, row-level security, and locking primitives for
leases (`SELECT ... FOR UPDATE SKIP LOCKED`, advisory locks). Small teams still need a
single-node install with minimal dependencies.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. PostgreSQL only** | RLS, SKIP LOCKED, transactional DDL, mature backup/PITR; one dialect to test | Small installs must run a database server (shipped in the bundled Compose file) |
| B. PostgreSQL + SQLite | No DB server needed for tiny installs | Every query and migration tested twice; SQLite has no RLS and no SKIP LOCKED, so lease semantics would differ |
| C. Embedded KV store (bbolt/Badger) | Zero dependencies | No relational queries or RLS; HA impossible |

## Decision
Option A.
- **Supported versions:** PostgreSQL **16, 17 and 18** in CI. Supported upstream: 15-19. PG 15 reaches EOL on 2027-11-11. PG 19.0 was released 2026-11-19 and joins the CI matrix after its first minor release.
- **Driver and tooling:** pgx v5 with hand-written queries kept in `internal/store`, goose for migrations (embedded in the binary; `certloomd migrate up|status`). sqlc is deferred until the schema settles; the store package is the only place that writes SQL, so adopting it later is a local change.
- **Migrations:** forward-only in production. Every migration ships with a tested rollback note (restore from backup, or a compensating migration). Destructive changes take two releases: expand, then contract.
- **Single-node mode:** `deploy/compose` bundles Postgres with a named volume and a backup sidecar script.
- **SQLite:** may be revisited **only** for the CLI's offline/standalone mode, which does not need leases.

## Consequences
Backup and restore run on standard Postgres tooling (`pg_dump`/PITR). The restore drill runs in CI (`TestBackupRestoreDrill`).

## Verification
The CI matrix runs the full test suite on PG 16/17/18 via testcontainers.
