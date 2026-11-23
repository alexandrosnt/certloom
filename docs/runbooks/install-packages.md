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

The package installs `/usr/bin/certloomd`, the `certloom` CLI, the
`certloomd.service` unit, a `certloom` system user and
`/etc/certloom/certloomd.env`. It does not set up PostgreSQL or start the
service.

1. Create the database and the two roles as in `deploy/compose` (owner role
   `certloom_owner`, runtime role `certloom_app`). PostgreSQL 16 or later.
2. Run the migrations as the owner role. Repeat after every upgrade:
   ```sh
   sudo -u certloom CERTLOOM_MIGRATE_DATABASE_URL='postgres://certloom_owner:...@127.0.0.1/certloom' certloomd migrate
   ```
3. Create the key-encryption key and TLS files, readable by the service:
   ```sh
   sudo sh -c 'umask 027; certloomd gen-kek > /etc/certloom/kek'
   sudo chgrp certloom /etc/certloom/kek
   # server.crt / server.key into /etc/certloom/tls, group certloom, key mode 0640
   ```
4. Edit `/etc/certloom/certloomd.env` (database URL of the runtime role,
   listen address, TLS paths, OIDC).
5. `sudo systemctl enable --now certloomd` and check `journalctl -u certloomd`.

The unit runs certloomd unprivileged with a read-only file system; it cannot
bind ports below 1024. Put a load balancer or reverse proxy in front for 443.

## Upgrades

`apt-get upgrade` or `dnf upgrade` installs the new version and restarts a
running service. For certloomd, run the migrations first (step 2), or stop the
service, upgrade, migrate, start.

## Package signing key rotation

The packaging key expires after two years and is replaced well before that
(`docs/runbooks/release.md`). A new key is announced in the release notes and
signed by the old one; fetch it again with the commands above.
