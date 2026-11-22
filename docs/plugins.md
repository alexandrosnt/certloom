# Agent plugins

certloom-agent runs plugins for what it has no built-in support for: DNS services
(`dns_solver`), applications and appliances to deploy certificates to (`deploy_target`),
and systems to discover certificates in (`discovery`). A plugin is an executable on the
agent host, written in any language. The design is recorded in
[ADR-0027](adr/0027-plugin-sdk.md); DNS plugins in particular are described in
[dns-plugins.md](dns-plugins.md).

Plugins run only on agents, never on the control plane, and they are installed by the
host's administrator. The control plane sees which plugins a host has, but cannot install
or change them.

## Protocol (version 1)

The agent runs the plugin directly (no shell) with one argument, the action, writes one
JSON request to its stdin and reads one JSON response from its stdout. Every call is a new
process. Stdout is limited to 64 KiB (4 MiB for `inventory`); stderr goes to the agent
log.

Every plugin answers `describe`:

```json
{"ok":true,"protocol":1,"name":"corp-f5","version":"1.2.0","kinds":["deploy_target"]}
```

A plugin without `kinds` is taken to be a `dns_solver`, as plugins written before other
kinds existed.

Every other response is `{"ok":true,...}` on success or, on failure,
`{"error":"...","class":"...","retry_after":30}` with class `auth`, `rate_limited`,
`transient` or `permanent`. A non-zero exit without a valid response counts as
`transient`.

Requests always carry `"protocol":1`, `"kind"` and the `config` map from the agent config,
which holds no secrets. The fields per kind:

### deploy_target

| Action | Request fields | Response |
|---|---|---|
| `deploy` | `target`, `idempotency_key`, `files` {`key`, `certificate`, `chain`, `fullchain`}, `names` | `{"ok":true}` |
| `verify` | `target`, `idempotency_key` | `{"ok":true,"certificate":"-----BEGIN CERTIFICATE-----..."}` |
| `rollback` | `target`, `idempotency_key` | `{"ok":true}` |
| `inventory` (optional) | `target` | `{"ok":true,"items":[...]}` as for discovery |

- `files` are PEM files in a directory only the agent can read, removed after the call.
  Read them during `deploy`; do not keep their paths.
- `idempotency_key` is the same for `deploy`, `verify` and `rollback` of one renewal and
  for their retries. A `deploy` with a key that already succeeded must succeed again.
- `rollback` restores whatever the `deploy` with that key replaced. The plugin keeps what
  it needs for that (for example the name of the previous certificate object). A
  rollback for a key it never deployed succeeds and changes nothing.
- `verify` returns the leaf certificate the target serves now. The agent compares its
  SHA-256 with the issued certificate and retries for up to ten seconds, for appliances
  that apply changes asynchronously. If the target config sets `verify_address`, the
  agent does a TLS handshake there instead and does not call `verify`.
- If `deploy` fails, the agent calls `rollback` before it reports the failure.

### discovery

| Action | Request fields | Response |
|---|---|---|
| `inventory` | (config only) | `{"ok":true,"items":[{"certificate":"PEM","location":"...","used_by":["..."]}]}` |

`location` says where the certificate was found, `used_by` what serves or references it.
Certificates are imported into the inventory with source `plugin`. Private keys are never
reported.

### dns_solver

See [dns-plugins.md](dns-plugins.md).

## Packages and signatures

A plugin package is a gzip tar with `plugin.yaml` at its root:

```yaml
name: corp-f5             # lower case letters, digits and dashes
version: 1.2.0            # semantic version
protocol: 1
kinds: [deploy_target]
executable: bin/corp-f5   # path inside the package
description: Deploys certificates to F5 BIG-IP client SSL profiles
homepage: https://github.com/example/certloom-plugin-f5
permissions:
  - BIG-IP user with the Certificate Manager role on the target partitions
```

Build the package and sign it with [cosign](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/):

```sh
certloom-plugin pack ./dist/linux-amd64 --os linux --arch amd64
# certloom-plugin-corp-f5_1.2.0_linux_amd64.tar.gz

# keyless, in CI (GitHub Actions needs `permissions: id-token: write`)
cosign sign-blob --yes --bundle certloom-plugin-corp-f5_1.2.0_linux_amd64.tar.gz.sigstore.json \
  certloom-plugin-corp-f5_1.2.0_linux_amd64.tar.gz

# or with a key, for private or offline publishing
cosign sign-blob --key cosign.key --tlog-upload=false \
  --bundle certloom-plugin-corp-f5_1.2.0_linux_amd64.tar.gz.sigstore.json \
  certloom-plugin-corp-f5_1.2.0_linux_amd64.tar.gz
```

`pack` writes the same bytes for the same files (sorted entries, no owners or times), so
a package can be rebuilt and compared. Publish the package and the `.sigstore.json` next to
each other.

## Trusting publishers

The agent config lists who may publish plugins for the host:

```yaml
plugins:
  trust:
    - name: example                        # keyless: a CI workflow identity
      keyless:
        issuer: https://token.actions.githubusercontent.com
        identity_regexp: ^https://github\.com/example/certloom-plugin-[a-z0-9-]+/\.github/workflows/release\.yml@refs/tags/v
    - name: corp                           # a public key
      public_key: /etc/certloom-agent/keys/corp-plugins.pub
  # trusted_root: /etc/certloom-agent/sigstore-trusted-root.json   # air-gapped or private Sigstore
  # require_signed: true                   # refuse plugins pinned by path below
```

- Keyless entries check the Fulcio certificate chain, its SCT, the Rekor entry and the
  signer identity, as `cosign verify-blob` does. Anchor `identity_regexp` with `^` and the
  full repository URL.
- Without `trusted_root`, the Sigstore public-good trusted root is fetched through its TUF
  repository. For air-gapped hosts, copy a `trusted_root.json` and set `trusted_root`, or
  use key entries.
- Removing a trust entry disables every plugin installed under it, without uninstalling.

## Installing

`certloom-plugin` ships in the agent packages next to `certloom-agent`. Run it as root
(or an administrator on Windows):

```sh
certloom-plugin verify https://downloads.example.com/certloom-plugin-corp-f5_1.2.0_linux_amd64.tar.gz
certloom-plugin install https://downloads.example.com/certloom-plugin-corp-f5_1.2.0_linux_amd64.tar.gz
certloom-plugin list
certloom-plugin remove corp-f5@1.1.0
```

The signature bundle is fetched from the package URL plus `.sigstore.json` unless
`--bundle` says otherwise. A package without a bundle, with a bundle that does not
verify, or signed by no one in `plugins.trust` is refused; there is no flag to skip the
check. Installs go to `<state_dir>/plugins/<name>/<version>/` (or `plugins.dir`) and each
version gets an `install.json` with the digests and the signer. The agent checks the
executable against that digest before every call.

Then use the plugin by name in the agent config, optionally with a version:

```yaml
targets:
  - name: lb-prod
    type: plugin
    plugin: corp-f5            # newest installed version; corp-f5@1.2.0 pins one
    config: {host: bigip.internal, partition: Common, profile: clientssl-www}
    env: [F5_PASSWORD_FILE]
    allowed_sans: [www.example.com]
    inventory: true            # also ask the plugin what the target holds
discovery_plugins:
  - name: java-keystores
    plugin: corp-jks
    config: {paths: [/opt/app/conf/*.jks]}
dns_solvers:
  - name: corp-dns
    plugin: corp-dns           # installed DNS plugins work too
    zones: [corp.example]
```

The plugin a target uses is part of the approved deployment spec: pointing a target at
another plugin needs a new approval, upgrading the same plugin does not. `certloom agent
plugins AGENT` shows what a host reports.

Plugins pinned by path and digest (`plugin: /usr/libexec/...` with `sha256:`) keep
working for every kind and are reported as `pinned`; `require_signed: true` refuses them.

A signature says who published a plugin, not that it is safe. Plugins run with the agent's
privileges; review what you trust.

## Testing

```sh
certloom-agent plugin-test --target lb-prod
certloom-agent plugin-test --discovery java-keystores
```

`plugin-test` runs `describe`, then `verify` and `inventory` where they apply. It never
calls `deploy` or `rollback`; exercise those against a staging target with a renewal
(`certloom deployment renew`).

## Go

`github.com/alexandrosnt/certloom/plugin` implements the protocol: fill a `plugin.Server`
with a handler per kind and call `Serve` from `main`.

```go
func main() {
	s := &plugin.Server{Name: "corp-f5", Version: version, Deploy: &bigip{}}
	os.Exit(s.Serve(context.Background(), os.Args[1:], os.Stdin, os.Stdout))
}
```

Return a `*plugin.Classified` to choose the error class.
