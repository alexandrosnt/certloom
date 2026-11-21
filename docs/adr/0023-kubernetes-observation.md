# ADR-0023: Kubernetes observation of cert-manager and trust-manager

**Status:** Accepted (2026-11-21)

## Context
In Kubernetes, cert-manager issues and renews certificates and trust-manager distributes
CA bundles. certloom should show those certificates next to everything else and raise
findings when they fail, without competing with cert-manager's controller (ADR-0001,
option C rejected).

## Options considered
| Option | For | Against |
|---|---|---|
| **A. `certloom-agent` in the cluster (Deployment, one per cluster), read-only ClusterRole, small REST client, no Secret access** | Outbound only (ADR-0004); least privilege; few dependencies | Own list/pagination code |
| B. Same, with `client-go` informers | Standard library, watch caches | Around 40 more modules and a much larger binary for read-only polling |
| C. `certloomd` connects to each API server with a kubeconfig | No component in the cluster | Inbound access to the API server and central cluster credentials, against ADR-0001/0004 |

## Decision
Option A.

**Deployment**
- The agent runs with `kubernetes:` in its config. In this mode its capability allowlist
  holds only `inventory`; the control plane never sends issue, deploy or rollback tasks
  to it.
- Manifests in `deploy/kubernetes/` (namespace, service account, ClusterRole and
  binding, PVC for the agent state, Deployment with one replica). A Helm chart may follow.
- Enrollment as for any agent: a one-time token from a Secret in the agent's namespace
  that the agent only reads at first start; identity and state on the PVC.

**Permissions (ClusterRole, verbs `get`, `list` only)**
- `cert-manager.io`: `certificates`, `certificaterequests`, `issuers`, `clusterissuers`
- `trust.cert-manager.io`: `bundles`
- `networking.k8s.io`: `ingresses` (to map TLS secret names to hosts)
- No `secrets`, no `configmaps`, no write verbs.

**Data**
- The certificate itself is taken from `CertificateRequest.status.certificate` of the
  request matching the Certificate's current revision. That field holds the PEM
  certificate without a key, so no Secret access is needed. When that request has been
  garbage-collected, the Certificate is reported from its status only (names, issuer,
  `notAfter`, `renewalTime`, conditions).
- Polling with paginated `list` (`limit`/`continue`) every 5 minutes by default; no
  watch in v1. The service account token is re-read from its projected file on each
  request; 429 with `Retry-After` is honoured.
- Certificates go into the inventory with source `kubernetes`, keyed by cluster,
  namespace and name.

**Findings**
- `k8s_certificate_not_ready`: Ready=False for longer than a threshold (default 1 h).
- `k8s_renewal_overdue`: `renewalTime` passed and no new revision.
- `k8s_issuer_not_ready`: an Issuer or ClusterIssuer used by a Certificate is not Ready.
- `k8s_request_failed`: the latest CertificateRequest is Denied or Failed.
- `k8s_bundle_not_synced`: a trust-manager Bundle is not Synced.
- The usual expiry checks apply to the observed certificates.

## Industry practice (surveyed 2026-11-21)
| Who | Approach |
|---|---|
| [CyberArk Certificate Manager for Kubernetes (Venafi agent)](https://docs.paloaltonetworks.com/content/techdocs/en_US/next-gen-trust-security/next-gen-trust-security/about-vaas/c-Cloud-discovery-service-sectionOverview/discover-certificates-in-kubernetes-clusters/connect-kubernetes-cluster-manually) ([source](https://github.com/jetstack/jetstack-secure)) | One discovery agent per cluster, Helm chart, outbound, periodic data gatherers; a ClusterRole per gathered resource type |
| [Venafi TPP Kubernetes discovery](https://docs.venafi.com/Docs/26.1/TopNav/Content/Discovery/cco-Discovery-Kubernetes-configuring-tpp.php) | Discovery jobs against clusters |
| [cert-manager](https://cert-manager.io/docs/) | The controller owns issuance; other tools observe its resources |

The survey did not find the exact ClusterRole of the CyberArk agent, so whether it reads
Secrets was not confirmed. No Keyfactor or DigiCert Kubernetes discovery document was
found.

## Consequences
- Certificates whose CertificateRequest is gone are visible without their PEM, so
  fingerprint-based features (lineage, revocation checks) do not apply to them until the
  next renewal.
- TLS Secrets not managed by cert-manager are not seen. Reading them would need Secret
  access; that is a possible opt-in later, with the key field never read.

## Verification
- Unit: REST client against an `httptest` API server (pagination, token re-read, 429),
  revision matching, finding rules.
- e2e: kind cluster in Docker with pinned cert-manager and trust-manager releases, a
  self-signed issuer, a working and a failing Certificate, a Bundle; the agent pod
  reports both certificates and the failing one raises `k8s_certificate_not_ready`.
  RBAC check: `kubectl auth can-i get secrets` as the agent's service account is "no".

## As built (2026-11-21)
- Observations are stored per agent (`agent_inventories`, migration 00012) without
  certificate PEMs; those go into the certificate inventory with source `kubernetes`.
- Finding subjects are `k8s_object` with id `<agent>/<kind>/<namespace>/<name>`.
  Findings of objects missing from the next inventory resolve, except for kinds the
  agent reported it could not list.
- `k8s_issuer_not_ready` is raised only for issuers that at least one Certificate uses.
- `certloom-agent run --enroll-token-file FILE --ca-hash ...` enrolls on first start, so
  the distroless image needs no init script.
- The e2e test runs the agent outside the cluster with a token of the manifest's
  service account (same RBAC as the pod) against kind with cert-manager v1.17.2 and the
  trust-manager Bundle CRD v0.16.0 (no trust-manager controller, so the Bundle is
  never Synced). The pod itself is not started in the test.
