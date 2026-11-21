# ADR-0003: Durable jobs and workflow execution

**Status:** Accepted (2026-11-21)

## Context
Requirements:
- durable schedules that survive restarts;
- at-least-once delivery with idempotent handlers;
- leases with fencing, so no two workers ever issue or deploy for the same lineage or target;
- concurrency limits per issuer, account, domain, target and agent;
- backoff with jitter, a kill switch, and pause/cancel/retry;
- resuming from a checkpoint after a crash.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Own small `jobs` + `workflow_runs` tables in Postgres** | Exactly the semantics we need (fencing epochs, per-key concurrency); no new dependency; Apache-2.0 throughout | We maintain ~1-2k lines of scheduler code and its tests |
| B. River (riverqueue/river) | Mature features: unique, scheduled and periodic jobs, transactional enqueue, `JobCompleteTx` | Licensed MPL-2.0 (compatible as an unmodified dependency, but needs a notice); **pre-1.0** (v0.51.2) with breaking changes in 0.x; no fencing tokens exposed to handlers; per-key concurrency limits would need extra code |
| C. Temporal | Strong durable-execution model | A separate cluster with its own database. That is too heavy for small installs, and nothing yet requires it |
| D. Redis/NATS/RabbitMQ queue | Fast | A second durable store with weaker transactional coupling to our state |

## Decision
Option A, behind a `jobs.Queue` interface so that River (option B) can be swapped in if
our code turns out to be the weak spot.

Design:
- **`jobs` table:** `id, org_id, kind, dedupe_key (unique while active), run_at, attempts, max_attempts, state, lease_owner, lease_until, lease_epoch, last_error, payload(jsonb, no secrets)`.
- **Claiming a job:** `UPDATE ... SET lease_owner=$w, lease_until=now()+ttl, lease_epoch=lease_epoch+1 WHERE id IN (SELECT id ... FOR UPDATE SKIP LOCKED LIMIT n) RETURNING *`.
- **Fencing:** every state-changing write a handler makes includes `WHERE lease_epoch = $claimed_epoch`. A stale worker whose lease expired gets 0 rows back and stops.
- **Target ordering:** each deployment has a monotonic `target_seq`. Every mutating task sent to an agent carries the next value, and the agent refuses a task whose sequence is lower than one it already executed for that target. Together with "at most one active run per deployment" (a unique index) this gives the same protection a separate lease table would, with less machinery.
- **Concurrency limits:** one active run per deployment, enforced by the database. Per-issuer and per-account limits are added together with multi-issuer support; until then the CA's own rate limits (honoured via `Retry-After`) are the bound.
- **Retries:** exponential backoff with full jitter. Errors are classified per ADR-0007; `rate_limited` honors `Retry-After`.
- **Kill switches:** global and per org (`automation_switches`); per-environment and per-issuer switches come with environments and multiple issuers. They are rows read at claim time, so they take effect with no restart.
- **Workflows:** `workflow_runs` + `workflow_steps` with an explicit state machine (docs/domain-model.md). Each step records an idempotency key and a checkpoint. Issuance and deployment are separate checkpoints, so retrying a deploy never re-orders the certificate.
- **Outbox:** events and notifications are written to `outbox` in the same transaction as the state change. Delivery is at-least-once, with dedupe keys.

## Consequences
- Scale target for M1: thousands of jobs per minute on a single Postgres. This must be measured, not assumed.
- The scheduler loop polls (default 1 s) and uses `LISTEN/NOTIFY` only as a wake-up hint, never for correctness.

## Verification
- Property tests: under randomized worker crashes and lease expiry, no two committed writes for the same resource carry the same epoch.
- Chaos e2e: kill -9 a worker mid-job; the job resumes exactly once from its checkpoint.
