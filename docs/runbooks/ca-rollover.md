# CA inventory and rollover

certloom keeps every root and intermediate CA certificate it sees: chains from
imports, probed endpoints and issued certificates, agent and cloud inventory, and the
CA bundles of Vault and step-ca issuers. Cross-signed copies of one CA (same subject and
key) are grouped into one *authority*. Each authority has an effective expiry: the end of
the longest valid path through it.

## See what you depend on

```sh
certloom ca list --in-use           # CAs above a lineage's current certificate or a served leaf
certloom ca show <key-prefix>       # copies, parents, children
certloom ca impact <key-prefix>     # lineages, deployments, endpoints and issuers under the CA
certloom ca plan --within 365d      # CAs in use that expire in the window, and the renew-by date
```

A key prefix of 8 or more characters is enough. The web UI has the same view under
**CAs**.

## Findings

| Check | Subject | Meaning |
|---|---|---|
| `ca_expiring` | authority | A CA in use expires within `caExpiry` (default warning 180d, critical 30d). For a CA that chains to the system roots it is only `info`: the public CA rotates it, and `chain_outlived` shows the real risk. |
| `chain_outlived` | certificate | The certificate is valid after every path above it has expired. |
| `chain_cert_expiring` | endpoint | The endpoint serves an intermediate that expires within 30 days, before the leaf. Usually a stale chain file after the CA rotated. |

Tune the CA thresholds in the policy:

```yaml
spec:
  caExpiry:
    warning: 365d
    critical: 60d
```

## Roll a private CA over

certloom does not change your CA. A typical Vault or step-ca rollover:

1. Create the new intermediate (or root) in the CA. With Vault, see its *rotation
   primitives*: cross-sign the new intermediate so both hierarchies validate.
2. Distribute the new root to relying parties before any leaf depends on it.
3. Point the issuer at the new intermediate. For Vault, set the mount's default issuer.
4. Run `certloom ca plan` to list what still depends on the old CA, then
   `certloom ca renew-affected <old-ca> --dry-run` to see which deployments it would
   renew.
5. `certloom ca renew-affected <old-ca>` starts one renewal run per deployment whose
   certificate outlives the old chain. Add `--all` to move every deployment under the CA
   now. Approvals, maintenance windows and the one-active-run rule apply to each run.
   Deployments that already have a run are skipped and reported.
6. When `certloom ca impact <old-ca>` lists no lineages and no endpoints, retire the
   old CA in the CA itself.

Public CAs (Let's Encrypt and others) rotate their intermediates on their own. Renewals
pick up the new chain. Watch for `chain_cert_expiring` on endpoints that kept an old
chain file.
