# Running certloom-agent next to Nginx

The agent runs on the host that serves TLS. It:
- generates each certificate's private key locally, and the key never leaves the host;
- obtains certificates via ACME HTTP-01, using Nginx to serve the challenge files;
- switches the certificate in **one atomic symlink rename**;
- runs `nginx -t`, reloads, and verifies the served fingerprint;
- restores the previous certificate when anything fails.

The control plane can only name a *target*. Paths, commands and the names a host may
obtain certificates for all come from this host's config file.

## 1. Enable agents on the control plane

```sh
certloomd gen-kek > /etc/certloom/kek && chmod 600 /etc/certloom/kek     # back this up separately from the DB
CERTLOOM_KEK_FILE=/etc/certloom/kek
CERTLOOM_AGENT_LISTEN=0.0.0.0:8444
CERTLOOM_AGENT_SERVER_NAMES=certloom.example.internal          # name(s) agents use to reach port 8444
CERTLOOM_AGENT_PUBLIC_URL=https://certloom.example.internal:8444
```

Agents dial out to port 8444 (mutual TLS 1.3). No inbound access to agent hosts is needed.

## 2. Configure the agent: `/etc/certloom-agent/config.yaml`

```yaml
server: https://certloom.example.internal:8444
state_dir: /var/lib/certloom-agent          # holds keys (0600) and local state; back up or treat as disposable
name: web-01
targets:
  - name: www
    type: nginx
    live_link: /etc/certloom/live/www       # symlink managed by the agent
    webroot: /var/www/acme             # HTTP-01 challenge files are written here (not needed for DNS-01)
    test_command: [nginx, -t]
    reload_command: [systemctl, reload, nginx]
    verify_address: 127.0.0.1:443
    allowed_sans: [www.example.com, "*.example.com"]   # "*.x" = any ONE label under x; a wildcard certificate also needs DNS-01 (2a)
# allowed_tasks: [inventory.scan, verify.local]       # optional: restrict to monitor-only
```

Check it with `certloom-agent check-config --config /etc/certloom-agent/config.yaml`.

## 2a. DNS-01 (wildcards, hosts without port 80)

With DNS-01 the agent proves control of a name by publishing a TXT record instead of
serving a file, so the host needs no inbound port 80, and wildcard certificates become
possible. DNS credentials stay on the agent host; the control plane never sees them.

```yaml
resolvers: ["10.0.0.53:53"]          # optional; used for CNAME lookups and propagation checks
dns_solvers:
  - name: internal                   # RFC 2136 dynamic update with TSIG (BIND, Knot, PowerDNS)
    provider: rfc2136
    nameserver: 10.0.0.53:53
    tsig_file: /etc/certloom-agent/dns/internal.key   # tsig-keygen output, hmac-sha256 or stronger
    zones: [corp.example.com]
  - name: public
    provider: cloudflare
    token_file: /etc/certloom-agent/dns/cloudflare.token   # API token with Zone:DNS:Edit on these zones only
    zones: [example.com]
  - name: other                      # anything else: a plugin (see docs/dns-plugins.md)
    plugin: /usr/libexec/certloom/dns/certloom-dns-example
    sha256: <sha256sum of the plugin>
    zones: [example.net]
    config: {endpoint: "https://dns-api.internal"}   # non-secret settings only
    env: [EXAMPLE_DNS_TOKEN]                           # agent variables passed through
```

- The record for `www.example.com` is `_acme-challenge.www.example.com`. If that name is a
  CNAME (for example to a dedicated validation zone), the agent follows it and picks the
  solver whose zone is the longest match for the target.
- Keep credential files `0600`, owned by the agent's user.
- For a wildcard, list it literally in the target's `allowed_sans` (`"*.example.com"`).
  The entry also allows single names one label below, as before.

Check a solver before relying on it. This writes and removes a random TXT record:

```sh
certloom-agent dns-test --config /etc/certloom-agent/config.yaml --solver public --name www.example.com
```

Then create the deployment with `--challenge dns-01`:

```sh
certloom deployment create --lineage www --agent web-01 --target www --issuer letsencrypt \
  --challenge dns-01 --san '*.example.com' --san example.com
```

The challenge type is part of the approved spec, so switching an existing deployment to
DNS-01 needs a new approval.

### Central solvers (credentials managed in certloom)

Instead of configuring each host, a solver can be defined once in the control plane and
assigned to agents (ADR-0018). The credential is stored encrypted with the KEK, never
returned by the API, and sent only inside an issue task, sealed to that one agent for that
one task. The agent keeps it in memory.

```sh
certloom dns-solver create internal --provider rfc2136 --zone corp.example.com \
  --config nameserver=10.0.0.53:53 --tsig-key-file ./internal.key
echo "$CF_TOKEN" | certloom dns-solver create public --provider cloudflare --zone example.com --api-token-stdin
certloom dns-solver assign internal web-01
certloom dns-solver set-secret public --api-token-stdin < new-token.txt   # rotation
```

Plugins can use the host's cloud identity instead of a stored secret:
`--provider plugin --plugin /usr/libexec/certloom/dns/route53 --plugin-sha256 ... --credential ambient`.

- A solver in the host's own config wins over a central one for the same zone.
- `central_dns_solvers: false` in the agent config makes that host refuse central solvers.
- Policy `dns.centralCredentials: forbidden` stops certloom from storing or sending DNS
  credentials for the whole organization.
- Every delivery is audited (`dns_solvers.secret_delivered`).

## 3. Point Nginx at the live link

```nginx
server {
    listen 80;
    server_name www.example.com;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://$host$request_uri; }
}
server {
    listen 443 ssl;
    server_name www.example.com;
    ssl_certificate     /etc/certloom/live/www/fullchain.pem;
    ssl_certificate_key /etc/certloom/live/www/privkey.pem;
}
```

`/etc/certloom/live/www` must be a **symlink** to a directory holding `fullchain.pem` and
`privkey.pem`. To migrate an existing setup, copy your current files into a directory,
then run `ln -sfn /that/dir /etc/certloom/live/www`. The agent refuses to replace a regular
directory.

## 4. Enroll (once)

On a workstation:

```sh
certloom agent token --name web-01      # prints the enroll command and a one-time token (valid <= 1h)
```

On the host, paste the token when prompted. The `--ca-hash` pins the control plane on
first contact:

```sh
certloom-agent enroll --config /etc/certloom-agent/config.yaml --ca-hash sha256:...
certloom-agent run --config /etc/certloom-agent/config.yaml      # run under systemd in production
```

## 4a. Install as a systemd service (deb / rpm)

Build the packages (needs Go and Docker; nfpm runs from its container image):

```sh
deploy/packaging/build.sh                         # dist/certloom-agent_<version>_<arch>.deb and .rpm
VERSION=1.2.3 GOARCH=arm64 deploy/packaging/build.sh
```

The package installs:

| Path | |
|---|---|
| `/usr/bin/certloom-agent` | static binary |
| `/usr/lib/systemd/system/certloom-agent.service` | the unit |
| `/etc/certloom-agent/config.yaml` | example config; a conffile, never overwritten on upgrade |
| `/var/lib/certloom-agent` (0700), `/etc/certloom/live` | created by the post-install script |

Installing does **not** enable or start the service, because the agent has to be enrolled
first:

```sh
apt install ./certloom-agent_1.2.3-1_amd64.deb         # or: dnf install ./certloom-agent-1.2.3-1.x86_64.rpm
vi /etc/certloom-agent/config.yaml
certloom-agent check-config
certloom-agent enroll --ca-hash sha256:...             # paste the token from `certloom agent token`
systemctl enable --now certloom-agent
journalctl -u certloom-agent -f
```

Upgrades restart the agent only if it is already running. Removing the package stops and
disables the service but keeps `/var/lib/certloom-agent` (enrollment identity and private keys)
and `/etc/certloom`; delete them by hand to decommission the host.

**reload_command.** When nginx runs as a systemd unit, use
`reload_command: [systemctl, reload, nginx]`. systemd then performs the reload with the
unit's own `ExecReload`, tracks it in the unit state and the journal, and nginx keeps its
main PID (no restart, no dropped connections). Use `[nginx, -s, reload]` only when nginx
is not managed by systemd (containers, hand-started servers). Keep `test_command:
[nginx, -t]` in both cases: a failed test rolls back before anything is reloaded.

**Sandbox.** The unit runs as root (it must run the test and reload commands) but with
systemd sandboxing: `/usr`, `/boot` and `/etc` are read-only except `/etc/certloom`; `/home`,
`/root` and `/run/user` are hidden; no new privileges, a reduced capability set, private
`/tmp` and devices, and only unix/IPv4/IPv6 sockets. `/var` stays writable, so
`state_dir` under `/var/lib` and webroots such as `/var/www/acme` work as is. For a
`live_link` or `webroot` elsewhere, add a drop-in rather than editing the unit:

```sh
systemctl edit certloom-agent
#   [Service]
#   ReadWritePaths=/srv/tls/live
systemctl restart certloom-agent
```

`systemd-analyze security certloom-agent` lists the effective settings.

## 5. Wire up renewal

```sh
certloom issuer create le-staging --directory https://acme-staging-v02.api.letsencrypt.org/directory --agree-tos
certloom scope create web --allow-host '*.example.com'
certloom endpoint add www.example.com --scope web            # used for external verification
certloom lineage create www                                    # skip if it exists, e.g. from `inventory import --lineage`
certloom deployment create --lineage www --agent web-01 --target www --issuer le-staging \
    --endpoint <endpoint-id> --san www.example.com
certloom deployment renew <deployment-id>
certloom run show <run-id>
```

A run is `verified` only when **both** checks pass:
- the agent's local handshake serves the new fingerprint;
- the control plane's own probe of the endpoint serves the new fingerprint.

Afterwards the deployment's next renewal time comes from the CA's ARI window when
the CA offers one, and otherwise from 2/3 of the certificate's lifetime.

### Templates

A template is an approved recipe that deployments reference: which issuer, which
challenge, which keys and which names (ADR-0020). Changing it in one place moves every
deployment that uses it.

```yaml
# web.yaml
apiVersion: certloom/v1
kind: CertificateTemplate
metadata:
  name: public-web
spec:
  issuer: le-production
  challenge: http-01
  keyAlgorithms: [ecdsa-p256]
  sans:
    allowed: ["*.example.com", "example.com", "api-*.corp.example.com"]
    maxNames: 10
    wildcards: false        # true needs challenge dns-01
  maintenanceWindow: "Mon-Fri 02:00-05:00 Europe/Athens"
```

```sh
certloom template validate web.yaml
certloom template plan web.yaml       # which deployments change, which need re-approval
certloom template apply web.yaml
certloom deployment create --template public-web --lineage www --agent web-01 --target www --san www.example.com
```

- In patterns, `*` matches one or more characters inside one DNS label: `*.example.com`
  allows `www.example.com` but not `a.b.example.com`.
- `apply` is refused while a deployment would break the new template (a name no longer
  allowed, too many names, a key algorithm removed). Fix those first.
- When the issuer or challenge changes, each affected deployment gets the new values. If
  approvals are required, or the person applying cannot manage deployments (for example
  `issuer_admin`), the changed deployments wait for a new approval.
- Policy `templates.required: true` makes templates mandatory for new deployments.

### CAs that require External Account Binding

Commercial ACME CAs (DigiCert, Sectigo, ZeroSSL, SSL.com, Google Trust Services) issue an
EAB key id and HMAC key. Each agent registers its own ACME account with it once; after
that the account key alone is used (ADR-0019). Give the key to certloom once:

```sh
# One key for any number of accounts (most CAs)
certloom issuer set-eab digicert --mode reusable --kid "$KID" --hmac-stdin < hmac.txt

# One key per account (Google Trust Services: each key registers one account and
# expires 7 days after it was created). Add one key per agent, ahead of time.
certloom issuer set-eab gts --mode single_use
gcloud publicca external-account-keys create --format=json > key.json   # keyId, b64MacKey
certloom issuer eab-key add gts --kid "$(jq -r .keyId key.json)" --expires-in 168h \
    --hmac-stdin <<< "$(jq -r .b64MacKey key.json)"
certloom issuer eab-key list gts
```

- The HMAC key is stored encrypted with the KEK, never returned, and sent to an agent only
  sealed to it inside the issue task, until the agent reports the account as registered.
- A single-use key is claimed by one agent, retried with that agent only, and marked
  `consumed` once the account exists. An issuer finding (`eab_pool`) opens when more agents
  wait for a key than the pool holds; `eab_key_expiring` when a claimed key is close to
  expiry before registration.
- When the CA refuses a key the run fails without retries and a single-use key is marked
  `failed`; the next run claims another one.
- A host can keep its own key instead:

  ```yaml
  acme_eab:
    - directory_url: https://acme.example-ca.com/directory
      kid: "..."
      hmac_file: /etc/certloom-agent/eab.hmac   # mode 0600
  central_eab: false   # optional: refuse keys sent by the control plane
  ```

  A host key for the directory wins over one sent by the control plane.

## Failure behavior

| What happens | Result |
|---|---|
| ACME error (rate limit, validation failure) | Retried with backoff, 3 attempts; then `failed`; nothing deployed |
| `nginx -t` fails | Link restored; Nginx was never reloaded; run `rolled_back` |
| Reload fails | Link restored, reload retried; `rolled_back` if that succeeds, otherwise escalated |
| Served fingerprint != new certificate | Rollback task; `rolled_back` |
| Rollback itself fails | `failed` + critical notification: **manual intervention** |
| Agent offline | Tasks wait until they expire (issue 2h, deploy 30m), then retry or fail |
| Agent revoked | Requests refused immediately; active runs fail |

Revoke a host: `certloom agent revoke web-01`.
