# Running several certloomd replicas

certloomd keeps all state in PostgreSQL, so any number of replicas can run
against one database (ADR-0001, ADR-0033). `TestHAReplicas` runs two replicas
behind a TCP load balancer, kills the scheduler leader with SIGKILL in the
middle of a renewal and restarts PostgreSQL under both.

## What each replica does

| Work | Runs on |
|---|---|
| API, web UI, agent endpoint | every replica |
| Probe, renewal and sweep jobs | every replica; each job is claimed by one (`SKIP LOCKED`, fenced leases) |
| Notification, webhook and audit-export delivery | every replica, same claiming |
| Periodic schedulers (due probes, sweeps, renewals, escalation, exceptions, EAB pools, inventory requests, trust bundles, pruning) | the replica holding the scheduler lease |

The scheduler lease is a row in the `leader` table, renewed every 5 seconds and
valid for 15. A replica that stops cleanly gives it up at once; one that dies
loses it after 15 seconds and another replica takes over and runs every
scheduler straight away. `certloomd` logs `leadership changed` on both sides.

A job held by a replica that dies is picked up by another one when its lease
runs out (2 minutes). A renewal in progress therefore pauses for up to two
minutes and then continues from its last checkpoint; the agent's nonce and
sequence checks keep a task from running twice.

## Requirements

- **Same KEK on every replica** (`CERTLOOM_KEK_FILE`). It protects the agent CA
  and task key, and the web UI derives its CSRF key from it, so forms work no
  matter which replica serves the next request. Without a KEK there is no agent
  support and UI forms only work with sticky sessions.
- **Same configuration** otherwise: database URL, OIDC settings,
  `CERTLOOM_AGENT_SERVER_NAMES` and `CERTLOOM_AGENT_PUBLIC_URL` must name the
  load balancer, not a single replica.
- **Server certificates** on every replica for the dashboard/API name.

## Load balancer

- **API and UI (8443):** any HTTP or TCP load balancer. No sticky sessions are
  needed. Health check: `GET /readyz` (200 when the replica can reach the
  database, 503 otherwise); `GET /healthz` only says the process is up.
- **Agent endpoint (8444):** TCP pass-through only. Agents authenticate with
  mutual TLS against the replica, so the load balancer must not terminate TLS
  on this port. Use a TCP health check, or `/readyz` on 8443 of the same
  replica.
- Rate limits are counted per replica, so the effective limit is the
  configured one times the number of replicas.

Example with nginx (`stream` module):

```nginx
stream {
  upstream certloom_api    { server cl-1:8443; server cl-2:8443; }
  upstream certloom_agents { server cl-1:8444; server cl-2:8444; }
  server { listen 8443; proxy_pass certloom_api; }
  server { listen 8444; proxy_pass certloom_agents; }
}
```

## PostgreSQL

certloom does not ship a highly available PostgreSQL; use the one you run:

| Option | Notes |
|---|---|
| Patroni (with etcd or Consul) | Point certloom at the leader through HAProxy or a virtual IP |
| CloudNativePG on Kubernetes | Use the `-rw` service |
| Managed: Amazon RDS / Aurora Multi-AZ, Azure Database for PostgreSQL with zone-redundant HA, Cloud SQL HA | Use the primary endpoint |

Several hosts in one URL also work:
`postgres://certloom_app@db1,db2/certloom?target_session_attrs=read-write`.
After a failover, certloomd reconnects on its own. Requests during the switch
fail, `/readyz` returns 503, and failed jobs are retried.

Use a PostgreSQL version from `docs/support-policy.md` and the same major
version on all nodes.

## Upgrades

1. Take a backup (see `dr.md`).
2. Run `certloomd migrate` once, with `CERTLOOM_MIGRATE_DATABASE_URL`. If
   several replicas run it at the same time, a PostgreSQL advisory lock makes
   them take turns. The lock needs a direct connection: do not run `migrate`
   through PgBouncer in transaction mode.
3. Replace the replicas one at a time. Destructive schema changes take two
   releases (expand, then contract; ADR-0002), so the previous release keeps
   working on the new schema while both run.

## Scaling

Each replica opens its own connection pool (pgx default: the larger of 4 and the
number of CPUs). Size `max_connections` for all replicas plus `migrate`, or put
PgBouncer in session mode in front of the database.
