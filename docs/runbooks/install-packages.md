# Installing from the deb and rpm repositories

certloom publishes `certloom-agent` and `certloomd` for amd64 and arm64 in an
apt and a yum repository, signed with the certloom packaging key (ADR-0031).
Check the key fingerprint against `docs/verify-release.md` before trusting it.

## Debian and Ubuntu

```sh
curl -fsSL https://alexandrosnt.github.io/certloom-packages/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/certloom.gpg
gpg --show-keys /usr/share/keyrings/certloom.gpg      # compare the fingerprint
echo 'deb [signed-by=/usr/share/keyrings/certloom.gpg] https://alexandrosnt.github.io/certloom-packages/deb stable main' \
  | sudo tee /etc/apt/sources.list.d/certloom.list
sudo apt-get update
sudo apt-get install certloom-agent        # or certloomd
```

## RHEL, Rocky, Alma, Fedora

```sh
sudo curl -fsSL -o /etc/yum.repos.d/certloom.repo \
  https://alexandrosnt.github.io/certloom-packages/certloom.repo
sudo dnf install certloom-agent            # or certloomd
```

The repo file sets `gpgcheck=1` and `repo_gpgcheck=1`: dnf checks both the
package signatures and the repository metadata, and asks to import the key on
first use. Compare the fingerprint it shows.

## Agent

After installing, enroll and start the agent as in `docs/runbooks/agent.md`.

## certloomd

```sh
sudo apt-get install certloomd      # also installs PostgreSQL
sudo certloomd setup
```

`setup` creates the database, the key-encryption key and a self-signed TLS
certificate, fills in `/etc/certloom/certloomd.env`, starts the service and
prints the web UI address and a one-time sign-in token. Running it again is
safe: it applies migrations and restarts the service.

- `--hostname`: the name agents and browsers use to reach this host
  (default: the host name). It goes into the TLS certificate.
- `--org`: name of the first organization (default `default`).
- `--owner-database-url`: use an existing PostgreSQL 16+ instead of the
  local one. The role needs CREATEROLE and must own the database; the URL must
  use `sslmode=verify-full`.

### How the local database is secured

Even on the same host, certloomd talks to PostgreSQL only over TLS 1.3 with full
certificate verification. `setup` creates a one-off CA, issues PostgreSQL a
certificate for `127.0.0.1` and `localhost`, and discards the CA's private
key, so no other certificate can pass. `pg_hba.conf` then refuses the certloom
roles on any connection without TLS. The new certificate replaces the
server's default one (Debian's snakeoil) for every client of that PostgreSQL.

### Files

| File | What it holds |
|---|---|
| `/etc/certloom/certloomd.env` | Settings read by `certloomd.service` |
| `/etc/certloom/kek` | Key-encryption key. **Back it up apart from the database**; a restore needs both |
| `/etc/certloom/migrate.env` | Schema-owner URL (root only); package upgrades use it to migrate |
| `/etc/certloom/tls/` | Web UI and API certificate. Replace with one from your CA, then `systemctl restart certloomd` |
| `/etc/certloom/postgres-ca.crt` | CA that signed the local PostgreSQL certificate |

The unit runs certloomd unprivileged with a read-only file system; it cannot
bind ports below 1024. Put a load balancer or reverse proxy in front for 443.

## Upgrades

`apt-get upgrade` or `dnf upgrade` installs the new version. On a host set up
with `certloomd setup`, the package applies the database migrations and
restarts the service by itself.

## Package signing key rotation

The packaging key expires after two years and is replaced well before that
(`docs/runbooks/release.md`). A new key is announced in the release notes and
signed by the old one; fetch it again with the commands above.
