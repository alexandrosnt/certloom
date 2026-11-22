# ADR-0030: Trust-bundle distribution and drift detection

**Status:** Accepted (2026-11-22)

## Context
Clients only accept a private CA's certificates if its root is in their trust store. A
CA rollover (ADR-0029) works only if the new root reaches every relying party before
any leaf depends on it, and the old root stays until nothing chains to it. Today
certloom only observes trust-manager Bundles in Kubernetes (ADR-0023). Hosts get roots
by hand, by Ansible or by `step certificate install`, and nobody notices a store that
is missing the new root or holds a root nobody approved. A rogue root in a trust store
enables interception.

certloom also has no list of private anchors. Endpoint checks use the system roots, and
ADR-0029 treats any CA that chains to a root in the certloomd host's OS store as public.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Desired-state bundles pushed to agent trust stores, plus observe-only stores** | One place defines trust; rollover order can be enforced; drift is measured against an explicit desired state | Agents write trust stores (a sensitive write); more code |
| B. Observe stores and compare them with an allowlist; distribution stays external | No writes | Rollover order cannot be enforced; two tools must agree |
| C. Export the bundle only (download or API) | Least code | No drift detection at all |

## Decision
Option A.

### Bundles
- A **trust bundle** has a name, an optional team and a list of anchors, all CA
  certificates. Anchors are stored in `certificates` (source `trust_bundle`), so the CA
  graph of ADR-0029 knows them.
- Every change creates an immutable **version** with a digest of the sorted anchor
  hashes. `certloom trust-bundle plan|apply -f bundle.yaml` works like templates
  (ADR-0020): plan shows the anchors added and removed and the stores affected, and
  apply needs the base version so nobody overwrites a concurrent change.
- **Assignments** bind a bundle to an agent trust store (`agent`, `store`). Each records
  the version the agent last confirmed and when.
- Permission `trust:manage`, owner only by default. Every apply, assignment and forced
  removal is audited.

### Removal safety (rollover order)
Adding an anchor is always allowed. Apply refuses to remove one when:

1. an authority in use (ADR-0029) chains to it, or
2. a store assigned to the bundle has not yet confirmed the current version, so it may
   still lack the successor anchor added earlier.

`--force --reason` overrides this, and the override is audited with its reason. The plan
lists the blocking lineages, endpoints and stores.

### Agent trust stores
The agent config gets a `trust_stores` list. A host takes part only through stores
declared there, just as targets declare `allowed_sans`:

| type | managed by certloom | observed |
|---|---|---|
| `pem` | the whole file at `path`, written atomically, then the optional `reload_command` | the certificates in the file |
| `pkcs12` | a Java-compatible trust-only PKCS#12 file at `path` (`password_file`, default `changeit`), then `reload_command` | the certificates in the file |
| `debian` | one file per anchor in `/usr/local/share/ca-certificates/certloom/`, then `update-ca-certificates` | the locally added anchors (`/usr/local/share/ca-certificates`) |
| `rhel` | `certloom-<hash>.pem` files in `/etc/pki/ca-trust/source/anchors/`, then `update-ca-trust extract` | the files in both anchors directories |
| `windows` | certificates in LocalMachine\Root whose friendly name starts with `certloom:` | every certificate in LocalMachine\Root |

`mode: manage` (default) or `mode: observe`. An observed store is never written. OS
stores are managed only as far as certloom's own entries go. Anchors the distribution
or the administrator added stay, and are reported.

- **Delivery:** new task `trust.apply`, signed like every task. Its payload holds the
  store name, bundle version, digest and anchor PEMs. The agent writes the anchors,
  runs the update or reload command, reads the store back, and returns what it now
  holds. If the command fails, it restores the previous content. The task is sent on
  apply, and again by the inventory loop for assignments that have not confirmed the
  current version.
- **Reporting:** the heartbeat lists the stores (name, type, mode). `inventory.scan`
  returns per store the anchors present (SHA-256 and PEM), which of them certloom
  owns, and any read error.
- Kubernetes stays observe-only through the existing trust-manager inventory.

### Findings (subject `trust_store`, id `agent/store`)
| Check | Fires when | Severity |
|---|---|---|
| `trust_store_drift` | a managed store lacks an anchor of its bundle version, holds certloom-owned anchors not in it, or has not confirmed the current version 1h after apply | warning; critical if a missing anchor is the root of an in-use authority |
| `trust_store_unknown_anchor` | a store holds a locally added anchor that is in no bundle (Linux anchors directories, PEM and PKCS#12 files, certloom-owned Windows entries) | warning |

Exceptions (ADR-0016) apply to both, for example for an anchor that is known and
accepted.

### Private anchors
The anchors of all bundles become the organization's private anchors. Endpoint trust
checks verify against the system roots plus these anchors. ADR-0029's "publicly
trusted" test means the system roots only, minus any CA that also chains to a private
anchor.

## Consequences
- Migration adds `trust_bundles`, `trust_bundle_versions`, `trust_assignments`, the
  finding and exception subject `trust_store`, and the permission `trust:manage`.
- A control plane that is compromised and has `trust:manage` can push a root to every
  managed store. Mitigations: the store must be declared `manage` on the host, the
  permission belongs to owners only, every change is audited, and drift is reported by
  the agents themselves. This is threat model entry T30. A policy-gated second-person
  approval for bundle changes is a follow-up (docs/TODO.md).
- JKS keystores, NSS (Firefox) and macOS keychains are not covered (docs/TODO.md).
- Windows unknown-anchor detection is limited to certloom-owned entries. LocalMachine\Root
  also holds Microsoft root-program roots, and certloom cannot tell those from local
  additions without the root program list.

## As built (2026-11-22)
- A failed `trust.apply` is recorded as `last_error` on the assignment (`certloom
  trust-bundle status`). The worker resends unconfirmed versions every hour, and the
  assignment's sent and confirmed versions drive the "not confirmed" drift.
- Removing a store from a bundle stops updates; the store keeps its anchors. A bundle can
  be deleted only once no store is assigned to it.
- A Windows root already present without certloom's label counts as present, and
  certloom never labels or removes it.
- Agents with trust stores ask for an inventory every 15 minutes.
- Runbook: docs/runbooks/trust-bundles.md.

## Industry practice (surveyed 2026-11-22)
| Who | Approach |
|---|---|
| [DigiCert Trust Lifecycle Manager](https://docs.digicert.com/de/trust-lifecycle-manager/automate-management-of-certificates/trust-stores-management.html), [solution brief](https://www.digicert.com/content/dam/digicert/pdfs/solution-brief/enterprise-trust-store-management.pdf) | Central inventory of trust anchors with allow and block lists; distributes approved roots and tracks provisioning status; detects unauthorized changes as drift |
| [Keyfactor Remote File orchestrator](https://github.com/Keyfactor/remote-file-orchestrator), [store types](https://software.keyfactor.com/Core-OnPrem/v26.2/Content/ReferenceGuide/Certificate%20Store%20Types.htm) | Agent-managed certificate stores with inventory, add and remove: PEM, DER, PKCS#12, JKS trust stores and Windows LocalMachine stores |
| [Venafi root certificate management](https://docs.venafi.com/Docs/current/TopNav/Content/Certificates/cco-certs-root-managing.php), [CyberArk on trust stores](https://www.cyberark.com/de/what-is/trust-stores/) | Discover roots on hosts; recommend a corporate allowlist, since a rogue root enables interception |
| [cert-manager trust-manager](https://cert-manager.io/docs/trust/trust-manager/api-reference/) | Bundle = sources (ConfigMap, Secret, inline, default CAs) written to targets as PEM plus PKCS#12; JKS output deprecated |
| [Smallstep `step certificate install`](https://smallstep.com/docs/cli/certificate/install/) | Installs a root into the system store, Java or NSS |
| [RHEL shared system certificates](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/securing_networks/using-shared-system-certificates) | Local anchors in `/etc/pki/ca-trust/source/anchors`, then `update-ca-trust`; Debian uses `/usr/local/share/ca-certificates` and `update-ca-certificates` |

Prevailing practice among CLM vendors: a central desired set of anchors, pushed by
agents to file and OS trust stores, with drift reported against that desired set.
certloom follows that and adds rollover-order checks based on its CA graph.
