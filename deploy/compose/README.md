# Single-node install (Docker Compose)

This runs PostgreSQL 18 and `certloomd` on one host: inventory, monitoring, alerts,
and renewal through agents on your other hosts. It is suitable for small teams and
evaluation. For several replicas see [docs/runbooks/ha.md](../../docs/runbooks/ha.md).

## 1. Prepare

```sh
cd deploy/compose
cp .env.example .env        # then set strong passwords and CERTLOOM_HOSTNAME in .env
mkdir -p tls backups
mkdir -m 700 secrets
docker compose build
docker compose run --rm --no-deps certloomd gen-kek > secrets/kek
chmod 644 secrets/kek       # certloomd runs as uid 65532 in the container; the 700 directory keeps others out
```

Put a server certificate and key for the dashboard/API in `tls/server.crt` and
`tls/server.key`. `certloomd` refuses to serve plain HTTP on a non-loopback address.

`secrets/kek` is the key-encryption key. It protects the agent CA, the task signing
key and stored credentials. Copy it somewhere safe **apart from database backups**:
a backup is useless without it, and anyone holding both can read the credentials.

## 2. Start

```sh
docker compose up -d --build
docker compose logs -f certloomd          # wait for "listening"
```

Order of operations: database -> `migrate` (as schema owner) -> `app-role` (sets the
runtime role's password) -> `certloomd` (runs as the least-privilege `certloom_app` role).

## 3. Create the first organization

```sh
docker compose exec certloomd certloomd bootstrap --org "Example Corp"
```

This prints a one-time **owner** token that expires in 24 h. Use it to sign in to the
dashboard at `https://<host>:8443/`, or with the CLI:

```sh
certloom login --server https://<host>:8443 --ca-file tls/ca.pem   # paste token at the prompt
certloom token create ops --role operator --ttl 2160h             # long-lived, least privilege
certloom scope create internet --allow-host '*.example.com'
certloom endpoint add www.example.com --scope internet
certloom status
```

## 3a. Connect an agent

Agents dial out to port 8444 on `CERTLOOM_HOSTNAME`. If they run on other machines,
set `CERTLOOM_AGENT_PUBLISH=0.0.0.0:8444` in `.env` and allow only the agent hosts
through the firewall. Then, on the agent host:

```sh
certloom agent token --name web-01      # run where the CLI is logged in; prints the enroll command
certloom-agent enroll --config /etc/certloom-agent/config.yaml --ca-hash sha256:...
```

The agent config, packages and the first renewal are in
[docs/runbooks/agent.md](../../docs/runbooks/agent.md) (Linux and nginx) and
[docs/runbooks/windows-iis.md](../../docs/runbooks/windows-iis.md) (Windows and IIS).

## 4. Backup

The database holds everything. Notification secrets live in `.env`, not in the database.

```sh
docker compose exec -T db pg_dump -U certloom_owner -d certloom -Fc > backups/certloom-$(date +%F).dump
```

Running `pg_dump` inside the `db` container (as above) keeps the tools on the
server's own major version. A dump made with newer tools can contain settings an
older server rejects on restore (for example `transaction_timeout`, new in 17),
so do not back up with a newer client than the server you will restore into.

Back up `.env`, `tls/` and `secrets/kek` separately and securely. They contain
credentials, and a restore needs the same KEK as the dump.

## 4a. External audit export (strongly recommended)

The audit trail in the database is hash-chained, but a database owner could rewrite
it and recompute the hashes. To make that detectable, stream events to a collector
that admin does not control. Set in `.env`:

```sh
CERTLOOM_AUDIT_EXPORT=webhook:https://audit-collector.example.internal/certloom
CERTLOOM_AUDIT_EXPORT_KEY_REF=env:CERTLOOM_AUDIT_EXPORT_KEY   # HMAC key; payloads carry X-Certloom-Signature
CERTLOOM_AUDIT_EXPORT_KEY=<random secret>
```

A file sink (`file:/path/audit.jsonl`) also works when the path sits on storage the
database admin can't modify. The container runs as uid 65532, so the directory
must be writable by that uid. Check progress with `certloom audit export-status`.

To check the database against the exported copy, run this anywhere that can read
the export and reach the database:

```sh
CERTLOOM_DATABASE_URL=... certloomd audit-verify-export audit.jsonl --compare
```

It reports any event that was changed or deleted in the database after export.

## 4b. Single sign-on (optional)

Register two clients with your IdP:
- A confidential **web** client, redirect URL `https://<host>:8443/auth/oidc/callback`.
- Optionally, a public client with the **device authorization grant**, for `certloom login --oidc`.

Fill in the `CERTLOOM_OIDC_*` values in `.env`. Then grant access by verified email:

```sh
certloom member add alice@example.com --role operator
```

Only identities whose IdP asserts `email_verified` can sign in. Removing a member
ends their sessions immediately.

## 5. Restore (tested drill; automated as `TestBackupRestoreDrill`)

```sh
docker compose stop certloomd
docker compose exec -T db dropdb -U certloom_owner --force certloom
docker compose exec -T db createdb -U certloom_owner certloom
docker compose exec -T db pg_restore -U certloom_owner -d certloom --no-owner --role=certloom_owner < backups/certloom-YYYY-MM-DD.dump
docker compose up -d migrate app-role certloomd
certloom audit verify        # the restored audit chain must verify
certloom status
```

`certloom_app` is a cluster-wide role and survives `dropdb`. If you restore onto a new
server, the `migrate` and `app-role` steps recreate the role and its grants.

## 6. Upgrade

```sh
git pull && docker compose up -d --build
```

Migrations are forward-only (ADR-0002). Take a backup before upgrading. To roll
back, restore that backup and run the previous image.

Installs set up before the KEK was part of this file need one first: create
`secrets/kek` as in step 1 and add `CERTLOOM_HOSTNAME` (and `CERTLOOM_AGENT_PUBLISH`)
to `.env` before `docker compose up`.

## 7. Pause automation (kill switch)

```sh
certloom automation pause --reason "investigating alert storm"
certloom automation resume
```

## Known limitations

- One `certloomd` on one host. Several replicas work (leader lease in the database,
  tested in `TestHAReplicas`), but this file runs one; see
  [docs/runbooks/ha.md](../../docs/runbooks/ha.md).
- Rate limits apply per process; with N replicas the effective limit is Nx higher.
- Observation history is pruned to the policy's retention (default 30 days), always keeping each endpoint's latest observation.
