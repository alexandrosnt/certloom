# Backup and disaster recovery

A certloom installation is the PostgreSQL database plus the key-encryption key
(KEK). Everything else (binaries, configuration, server certificates) can be
reinstalled. Lose the database and you lose the inventory, history and
workflow state; lose the KEK and the restored database can no longer sign tasks
for agents or decrypt the secrets it holds (ADR-0033).

## What to back up

| Item | How | Notes |
|---|---|---|
| Database | `pg_dump` or WAL archiving (below) | Contains no private keys of certificates (ADR-0005) |
| KEK (`CERTLOOM_KEK_FILE`) | Escrow once, separately from the database | Required for agents, sealed DNS credentials, EAB keys and webhook secrets |
| Environment / config | Configuration management | Notification secrets, OIDC client secret, audit-export key |
| Server certificates for the UI/API | Your usual PKI process | Can be reissued |

### The KEK

The KEK does not change unless you rotate it, so back it up once and again
after each rotation:

- Keep at least two copies outside the database backups: for example a
  sealed offline copy and an entry in your secrets manager.
- Never store it next to the database dumps. A dump plus the KEK is enough to
  impersonate the control plane to every agent.
- Record where the copies are in your DR plan, and test reading them back
  during the drill.

## Backup levels

| Level | Method | RPO | RTO (typical) | For |
|---|---|---|---|---|
| 1 | Daily `pg_dump -Fc` (see `deploy/compose/README.md`) | up to 24 h | minutes for small databases | Small installs, labs |
| 2 | Continuous WAL archiving with point-in-time recovery: pgBackRest, Barman, WAL-G, or the managed service's PITR | minutes | restore time of a base backup plus WAL replay | Production |

Losing recent changes is less harmful than it sounds: certificates issued after
the backup point are still deployed on the hosts and are found again by probes
and agent inventory. What is lost is history (runs, audit records, settings
changed since the backup). The external audit export (ADR-0012) keeps a copy of
the audit trail outside the database; enable it in production.

## Restore

1. Stop every certloomd replica.
2. Restore the database:
   - Level 1: `pg_restore` the dump into an empty database (exact commands in
     `deploy/compose/README.md`, section 5).
   - Level 2: restore with your tool to the chosen point in time and promote
     the server.
3. Put the escrowed KEK in place (`CERTLOOM_KEK_FILE`), same file on every
   replica.
4. Run `certloomd migrate` (recreates the `certloom_app` role and grants on a
   new server; a no-op otherwise).
5. Start the replicas.
6. Check:
   ```sh
   certloom audit verify      # the restored audit chain must verify
   certloom status
   certloom agent list        # agents return to "active" within a minute
   ```
   With the external audit export, also run
   `certloomd audit-verify-export --compare` to see which audit records were
   lost between the backup point and the failure.

Agents do not need to enroll again. Their identities chain to the agent CA in
the restored database. Each agent reports the last task sequence it executed
per target in its heartbeat, and the control plane raises its own counters to
match, so renewals continue even when the backup predates the agent's last
tasks. certloomd logs `raised task sequences to the agent's fence` when that
happens.

Tasks that were pending at the backup point are delivered again. An agent
that already ran one does not run it twice; it sends back the result it
stored, and the run continues from there.

## Drill

Run a restore at least once a year and after major upgrades, onto a separate
host:

1. Restore the latest backup and the KEK from escrow, as above.
2. Point one test agent (or a copy of a production agent's state directory) at
   the restored control plane and trigger a renewal on a test deployment.
3. Note how long the restore took and how far back the backup point was; these
   are your real RTO and RPO.

`TestBackupRestoreDrill` covers the dump and restore steps in CI and
`TestRestoredSequenceCatchesUp` covers agents after a restore.
