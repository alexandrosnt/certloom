# ADR-0029: Root and intermediate CA inventory and rollover planning

**Status:** Accepted (2026-11-22)

## Context
certloom already stores CA certificates. Imports, probe chains, issued chains, agent
inventory (IIS, Kubernetes, cloud) and the CA bundles of Vault and step-ca issuers all
go into `certificates` with `is_ca` set. But nothing links a certificate to the CA that
signed it, CA certificates get no findings, and nobody can answer "what breaks when this
intermediate expires or is replaced".

Intermediates now rotate often. Let's Encrypt replaced its intermediates in 2024 and
started issuing from a new hierarchy in January 2026. DigiCert will rotate its TLS
intermediates about once a year from October 2027. Private CAs such as Vault rotate
issuers and cross-sign them. An outage happens when one of the following is true:

- a leaf outlives its chain;
- an endpoint keeps serving an old intermediate copy after that copy expired;
- nobody knows which deployments depend on a CA that is about to go away.

This ADR covers inventory and planning. Trust-bundle distribution and drift detection
come in a later ADR.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Derived CA graph from the inventory, with planning and bulk renew** | Needs no configuration; covers public and private CAs seen anywhere; uses data already collected | Graph has to be recomputed when CA certificates arrive later |
| B. Configured CA objects only | Explicit; smaller | Misses public CAs on probed endpoints; duplicate data entry |
| C. A or B, plus driving the CA rotation itself (create or cross-sign intermediates in Vault or step-ca) | One tool for the whole rollover | Needs CA admin credentials, not just sign rights (ADR-0028); no surveyed CLM does this through its issuer connector |

## Decision
Option A.

### Model
- **Authority.** A CA is its subject plus its public key, as in Vault's rotation
  model. A cross-signed copy has the same subject and key with a different issuer, so it
  belongs to the same authority. `ca_key` = hex SHA-256 of
  `len(subject) || subject DER || SPKI DER`, stored on every `is_ca` certificate.
  `ca_root` is true when any copy is self-signed.
- **Issuer link.** Every certificate gets `issuer_ca_key`: the authority whose key
  verifies its signature. Candidates are found by subject (RawIssuer = RawSubject), and
  AKI = SKI when both are present; the signature check decides. A certificate signed by
  an authority not yet in the inventory keeps a NULL link. When a new CA certificate is
  stored, NULL links that match its subject are re-checked.
- **Effective expiry.** For an authority, this is the latest date on which any of its
  copies still has a valid path upward. The value for one copy is
  `min(copy.not_after, effective expiry of its issuer authority)`. A copy whose issuer is
  unknown, or a root, uses its own `not_after`. This is computed in Go over the
  in-memory graph, with a depth cap of 8 and cycle protection for mutual cross-signs.
- **In use.** An authority counts as in use when at least one of these is true:
  - it signs, directly or through intermediates, the current certificate of a lineage;
  - it signs the leaf last observed on an enabled endpoint;
  - it is an ancestor of such an authority.

  The CA certificates in an issuer's `ca_bundle` are added to the inventory, so the root
  above a private CA's chain is known.

  Findings apply only to authorities in use. This keeps public CA noise out.

### Findings
| Check | Subject | Fires when | Severity |
|---|---|---|---|
| `ca_expiring` | `authority` | an in-use authority's effective expiry is within policy `caExpiry` (default warning 180d, critical 30d) | warning or critical; info when the authority chains to the system roots |
| `chain_outlived` | `certificate` | an unexpired certificate has `not_after` later than the effective expiry of its issuer authority | warning; critical within 30d of the chain expiry |
| `chain_cert_expiring` | `endpoint` | the chain an endpoint served contains a CA certificate that expires before the leaf and within 30d, even if another copy of that authority lives longer | warning; critical within 7d |

Thresholds use the existing versioned policy. Findings support exceptions like any
other finding (ADR-0016). `authority` is added as a finding and exception subject type.

### Planning
- `certloom ca list [--roots|--intermediates] [--in-use]` lists authorities with their
  copies, effective expiry, and counts of the lineages, endpoints and issuers that use
  them.
- `certloom ca show CA` shows copies, parents, children and the issuers whose bundles
  hold the authority.
- `certloom ca impact CA` lists everything that chains through the authority, directly
  or transitively: lineages (current leaf), deployments of those lineages, endpoints,
  inventory objects and issuers. For each lineage it says whether the leaf expires
  before the chain (normal renewal handles it) or after (renew early).
- `certloom ca plan [--within 365d]` lists every in-use authority whose effective
  expiry falls in the window, with its impact counts and the date by which affected
  lineages must be renewed.
- `certloom ca renew-affected CA [--dry-run] [--all]` starts a normal renewal run for
  each deployment whose current leaf chains to the authority and outlives the chain.
  `--all` includes every deployment under the authority. Approvals, maintenance
  windows, spec checks and the one-active-run rule all apply unchanged. It needs
  `renewals:run` and is audited once, with the list of runs it started. A
  deployment that already has an active run is reported and skipped.

The same data is available at `GET /api/v1/authorities`, `GET /api/v1/authorities/plan`,
`GET /api/v1/authorities/{key}` and `POST /api/v1/authorities/{key}/renew-affected`, and
in the UI under "CAs".

## Consequences
- Migration adds `certificates.ca_key`, `certificates.issuer_ca_key` (indexed) and the
  `authority` subject type. A backfill fills both columns for existing rows.
- A CA certificate import now costs one subject lookup plus signature checks on
  certificates that have no link yet. This is bounded per batch and measured in the
  scale test.
- certloom does not rotate CAs. Operators rotate their CA (Vault rotation primitives,
  step-ca, or their public CA). certloom then shows what still depends on the old one
  and renews it.
- Trust stores (which roots relying parties trust) are not modeled here. That is the
  next M7 item.

## As built (2026-11-22)
- Linking runs inside `UpsertCertificate` for new rows. Rows stored before migration
  00016 carry `issuer_link_pending` and are linked by the hourly certificate sweep. The
  derived columns are the only ones `certloom_app` may update; the certificate itself
  stays immutable.
- Inventory objects (IIS, Kubernetes, cloud) do not count as "in use" yet (docs/TODO.md).
- "Publicly trusted" means a copy verifies against the roots used for endpoint checks.
  That is the system pool unless configured. A private root in the OS store of the
  certloomd host therefore lowers `ca_expiring` to info (docs/TODO.md).
- Runbook: docs/runbooks/ca-rollover.md.

## Industry practice (surveyed 2026-11-22)
| Who | Approach |
|---|---|
| [Keyfactor Command reports](https://software.keyfactor.com/Core/Current/Content/ReferenceGuide/ReportExpirationReport.htm) | "Issued certificates per CA" report; separate expiry tables for CA certificates, 6 to 30 months ahead, next to the 12-week leaf window |
| [Keyfactor PKI status](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/ReportPKIStatusforCollection.htm) | PKI status per collection, grouped by issuing CA |
| [DigiCert expiring CA advisory](https://knowledge.digicert.com/alerts/digicert-expiring-public-root-and-intermediate-ca-certificates) | When a root expires, every intermediate under it expires; install the full chain; annual intermediate rotation from 2027 |
| [Vault PKI rotation primitives](https://developer.hashicorp.com/vault/docs/secrets/pki/rotation-primitives) | Authority = subject + key; a cross-signed copy reuses both; remove old issuers after their leaves expire |
| [Let's Encrypt 2024 chains](https://letsencrypt.org/2024/04/12/changes-to-issuance-chains.html), [Gen Y hierarchy](https://letsencrypt.org/2025/11/24/gen-y-hierarchy.html) | Regular intermediate and root rotations that clients and servers must follow |
| [cert-manager trust](https://cert-manager.io/docs/trust/), [OpenShift Serverless CA rotation](https://docs.redhat.com/ja/documentation/red_hat_openshift_serverless/1.36/html/serving/serving-transport-encryption-ensuring-seamless-ca-rotation_serving-transport-encryption) | Rollover order: trust old and new together, rotate leaves, verify live endpoints, then drop the old CA |

The search found no public Venafi/CyberArk documentation on per-CA impact reports, and no
specific SP 1800-16 text on intermediate rollover.

Prevailing practice: a CLM inventories CA certificates, alerts on them months ahead,
and reports which certificates each CA issued. The CA performs the rotation. certloom
follows that and adds chain-aware checks, so it catches a leaf that outlives its chain
or an endpoint that serves a stale copy.
