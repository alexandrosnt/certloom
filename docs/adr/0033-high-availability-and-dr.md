# ADR-0033: High availability and disaster recovery

**Status:** Accepted (2026-11-23)

## Context
ADR-0001 says HA means several `certloomd` replicas sharing one Postgres, with
correctness coming from database leases (ADR-0003), and asks for a test that
kills one of two replicas during a probe sweep. Only one replica has been tested
so far. A review of the code for anything a second replica would break found:

- The web UI's CSRF key is random per process, so a form served by one replica
  fails its check on another unless the load balancer is sticky.
- `certloomd migrate` takes no lock; two replicas upgrading at the same time
  would race.
- Every replica runs every periodic loop (probe scheduling, certificate
  sweeps, escalation, exception expiry, EAB pools, inventory requests, trust
  bundles, pruning, renewal scheduling). Running a loop twice in parallel is
  only safe if every loop is idempotent under concurrency, which nothing proves.
- Rate limits are counted per process.

Disaster recovery today is a logical `pg_dump` with an automated restore drill
(`TestBackupRestoreDrill`). The key-encryption key (`CERTLOOM_KEK_FILE`)
protects the agent CA and the task signing key; a database restored without it
cannot talk to enrolled agents.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Active-active replicas, database HA left to the operator** | Matches ADR-0001 and the lease design; any load balancer works; operators reuse the Postgres HA they already run | certloom's availability is only as good as the operator's Postgres |
| B. A plus a supported Patroni or CloudNativePG setup | One answer for the database too | A database distribution to maintain and test; none of the surveyed vendors ship one |
| C. Active-passive with a standby | Simplest to reason about | Throws away the existing lease design; failover needs its own detection |

## Decision
Option A.

### Replicas
- Any number of `certloomd` replicas behind any HTTP load balancer, without
  sticky sessions. Agents may reach any replica.
- No request may depend on state held in one process. The CSRF key is derived
  from the KEK (HKDF, label `certloom csrf v1`), so every replica with the same
  KEK accepts the same tokens. OIDC state, nonce and PKCE verifier already
  travel in a short-lived cookie; idempotency keys stay in the database.
- Rate limits stay per replica and are documented as such; the effective limit
  is the per-replica limit times the number of replicas.

### Periodic loops
- Periodic schedulers run only on the elected leader. Leadership is a row in a
  `leader` table taken and renewed with a lease (TTL 15s, renewed every 5s),
  the same pattern as River's `river_leader` and Oban's `oban_peers`. A lease
  row works behind a transaction pooler, unlike session advisory locks.
- A replica that loses or cannot renew the lease stops starting new ticks.
  Ticks already running finish; their writes must stay safe if they overlap
  with the next leader's. Every periodic loop must therefore stay safe when
  two runs overlap (SKIP LOCKED, upserts, conditional updates); this is a rule
  for new loops and a review item for the existing ones.
- Job execution (probes, renewals, deliveries, audit export) is not
  leader-only: every replica claims jobs with SKIP LOCKED and lease fencing
  (ADR-0003).

### Migrations
- `certloomd migrate` takes goose's Postgres session lock (`WithSessionLocker`),
  so concurrent runs wait instead of racing. It needs a direct connection, not a
  transaction pooler; the upgrade docs say so.

### Database
- Postgres HA is the operator's choice: Patroni, CloudNativePG, or a managed
  service with automatic failover. certloom connects through one read-write
  endpoint and reconnects after a failover. `docs/runbooks/ha.md` describes
  the reference topologies; certloom does not ship one.

### Disaster recovery
- Two backup levels, documented with their RPO and RTO:
  - `pg_dump` daily (existing): RPO up to a day, fine for small installs.
  - WAL archiving with point-in-time recovery (pgBackRest, or the managed
    service's PITR): RPO of minutes.
- The KEK is part of every backup plan. It is escrowed separately from the
  database (offline copy or a secrets manager); a backup without it cannot
  drive agents.
- After a restore, enrolled agents reconnect and keep their identities, because
  the agent CA and task key are restored with the database.
- The restored `deployments.target_seq` can be lower than what an agent has
  already executed, and the agent's sequence fence (ADR-0004 replay rules)
  would reject every task for that target until the counter caught up. Agents
  therefore report their highest executed sequence per target in the heartbeat,
  and the control plane raises `target_seq` to at least that value before it
  signs the next task. The fence itself stays unchanged.
- Tasks that were pending at the backup point are offered again. An agent that
  already ran one answers with its stored result, even if the control plane had
  acknowledged it before the failure, and never runs it twice.

## Consequences
- New migration for the `leader` table.
- `docs/runbooks/ha.md` (topologies, load balancer, health checks, Postgres HA
  options, upgrades) and `docs/runbooks/dr.md` (backup levels, KEK escrow,
  restore, verification).
- Operators who run only one replica see no change.
- The threat model gains the HA section it reserved for M8.

## Verification
- e2e: two replicas behind a proxy with an enrolled agent. `kill -9` one replica
  during a probe sweep and again during a renewal. The work finishes on the
  other replica, each notification and task goes out once, and leadership moves.
- e2e: restart Postgres while both replicas run; both reconnect and continue.
- DR drill: back up, restore onto a fresh database and a fresh `certloomd` with
  the escrowed KEK; the audit chain verifies and the existing agent renews
  without re-enrolling.
- Unit: CSRF tokens issued by one UI instance verify on another with the same
  KEK; two concurrent `migrate` runs both succeed.

## Industry practice (surveyed 2026-11-23)
| Who | What they do | Source |
|---|---|---|
| Keyfactor Command | Several Command servers behind a load balancer, all on one SQL database; database HA through SQL Server Always On | [Command servers](https://software.keyfactor.com/Core-OnPrem/Current/Content/InstallingServer/Main/KeyfactorServers.htm), [SQL Server](https://software.keyfactor.com/Core-OnPrem/Current/Content/InstallingServer/Main/SQL%20Server.htm) |
| Keyfactor Command | DR: restore the database together with its master encryption key; without the key some data is unrecoverable | [Disaster recovery](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Disaster%20Recovery.htm) |
| EJBCA | Independent nodes on one HA database; DR site with manual failover | [HA and clustering](https://docs.keyfactor.com/ejbca/9.6/high-availability-and-clustering) |
| Keycloak | Stateless replicas; database HA and failover are the operator's, example with CloudNativePG | [Multi-AZ](https://www.keycloak.org/high-availability/single-cluster/deploy-keycloak), [CloudNativePG](https://www.keycloak.org/high-availability/single-cluster/deploy-cnpg) |
| River (Go job queue) | One leader per database through the `river_leader` table; periodic jobs enqueued by the leader only | [leadership package](https://pkg.go.dev/github.com/riverqueue/river@v0.38.0/internal/leadership) |
| Oban | Leadership through the `oban_peers` table; only the leader runs Cron and other global plugins | [Oban.Peer](https://hexdocs.pm/oban/Oban.Peer.html) |
| goose | `WithSessionLocker` takes a Postgres advisory lock against concurrent migrations | [goose provider](https://pressly.github.io/goose/blog/2023/goose-provider) |
| step-ca, Venafi | Nothing found on multi-instance control planes on one database | - |
