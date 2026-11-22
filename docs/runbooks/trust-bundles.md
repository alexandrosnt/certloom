# Trust bundles

A trust bundle is a named, versioned set of CA certificates (anchors) that certloom
pushes to trust stores on agent hosts. It also reports stores that drift from their
bundle, and anchors that no bundle approves (ADR-0030).

## 1. Declare the stores on the host

A host takes part only through stores listed in its agent config:

```yaml
trust_stores:
  - name: os
    type: debian          # /usr/local/share/ca-certificates/certloom + update-ca-certificates
  - name: java
    type: pkcs12
    path: /etc/myapp/truststore.p12
    password_file: /etc/certloom-agent/java-trust.pw
    reload_command: [systemctl, restart, myapp]
  - name: haproxy
    type: pem
    path: /etc/haproxy/ca.pem
    reload_command: [systemctl, reload, haproxy]
  - name: legacy
    type: pem
    path: /opt/legacy/ca.pem
    mode: observe         # reported, never written
```

| type | what certloom writes | what it reports |
|---|---|---|
| `pem` | the whole file | every certificate in the file |
| `pkcs12` | the whole file, a trust-only PKCS#12 Java reads (8u301 and later) | every certificate in the file |
| `debian` | `*.crt` in `/usr/local/share/ca-certificates/certloom/`, then `update-ca-certificates` | every locally added anchor under `/usr/local/share/ca-certificates` |
| `rhel` | `certloom-*.pem` in `/etc/pki/ca-trust/source/anchors/`, then `update-ca-trust extract` | the files in both anchors directories |
| `windows` | LocalMachine\Root entries named `certloom:...` | every certificate in LocalMachine\Root |

certloom never removes an anchor it did not write. If an update or reload command fails,
the agent restores the previous content.

Restart the agent; `certloom agent trust-stores web-01` lists its stores.

## 2. Write and apply a bundle

```yaml
# corp-trust.yaml
name: corp
team: platform
anchors:
  - file: roots/corp-root-2024.pem
  - file: roots/corp-root-2026.pem
stores:
  - {agent: web-01, store: os}
  - {agent: app-01, store: java}
```

```sh
certloom trust-bundle plan corp-trust.yaml    # anchors and stores added or removed, blockers
certloom trust-bundle apply corp-trust.yaml   # new version, sent to every store
certloom trust-bundle status                  # version each store confirmed, last error
```

A store that has not confirmed the current version gets it again every hour. Removing a
store from the file stops updates; the store keeps the anchors it has.

## 3. Roll a root over

1. Add the new root to the bundle and apply it. Wait until `status` shows every store
   at the new version.
2. Move issuance to the new hierarchy and renew (docs/runbooks/ca-rollover.md).
3. Remove the old root from the bundle and apply. certloom refuses while:
   - a CA in use still chains to the root (`certloom ca impact`), or
   - a store has not confirmed the current version.

`--force --reason "..."` overrides both checks, for example after a compromise. The
reason is kept in the audit log.

## Findings

| Check | Meaning |
|---|---|
| `trust_store_drift` | A managed store lacks an anchor of its bundle, holds a certloom anchor that is not in it, or has not confirmed a version within an hour. Critical when the missing anchor is the root of certificates in use. |
| `trust_store_unknown_anchor` | A store holds a locally added anchor that is in no bundle. Add it to a bundle if it is approved, remove it from the host, or accept it with an exception. |

The anchors of all bundles are also certloom's private anchors. Endpoint checks trust
them in addition to the system roots, and a CA under them never counts as publicly
trusted (`ca_expiring` keeps its severity).
