# Domain model and state machines

Status: Proposed (M0). This is a conceptual model. M1 turns it into a SQL schema under
`internal/store/migrations`.

## Principles
- A certificate's identity is the **SHA-256 of its DER encoding**. A serial number is
  unique only together with the issuer DN and AKI. The common name is never an identity.
- **Desired state and observed state live in separate tables.** Lifecycle decisions
  compare the two; they never overwrite one with the other.
- Certificates are immutable. History survives replacement and revocation.
- Every timestamp is UTC (`timestamptz`). Schedules also keep their IANA zone.
- No table stores private keys or plaintext credentials (ADR-0005, ADR-0009).
- Every tenant-owned row carries `org_id`.

## Entities

| Entity | Key fields | Notes |
|---|---|---|
| Organization | id, name | Logical tenant (ADR-0001) |
| Team | id, org_id, name, escalation contacts | Owns lineages and services |
| Service | id, org_id, team_id, name, criticality | Business/application grouping |
| Environment | id, org_id, name, class (dev/stage/prod/regulated) | Used for policy scoping |
| **Certificate** | sha256 (PK within org), der, serial, issuer_dn, subject_dn, aki, ski, sans[], not_before, not_after, key_alg, key_size/curve, sig_alg, eku[], ku[], is_ca, path_len, aia/crl/ocsp URLs, parse_warnings[] | Immutable; parse failures are recorded, not dropped |
| CertificateChainLink | child_sha256, parent_sha256, source (served/built/imported) | Several parents are allowed (cross-signs) |
| **CertificateLineage** | id, org_id, name, team_id, service_id, environment_id, profile_id, current_cert, management_level, expected_sans[] | The logical "slot" that successive certificates fill |
| LineageMember | lineage_id, cert_sha256, since, reason (issued/imported/observed) | Replacement history |
| **Endpoint** | id, org_id, host, resolved_ip (pinned per probe), port, sni, probe_scope_id, expected_lineage_id? | A target explicitly configured for probing |
| ProbeScope | id, org_id, allowed CIDRs/hostnames, rate limit, enabled | Opt-in network scope (SSRF control) |
| **EndpointObservation** | id, endpoint_id, observed_at, leaf_sha256, chain[], tls_version, cipher, alpn, error_class, latency_ms | Time series; old rows are pruned by retention policy |
| **Finding** | id, org_id, subject (cert/endpoint/lineage), check, severity, first_seen, last_seen, resolved_at, detail | Produced by `internal/checks` |
| Alert | id, finding_id, state (open/acked/resolved/suppressed), routed_to, escalation_level | Notification state |
| NotificationChannel | id, org_id, kind (email/webhook), config, credential_ref | |
| Policy | id, org_id, version, scope selector, document (validated YAML/JSON) | Versioned; changes are audited |
| KeyReference (M2) | id, lineage_id, custody_mode, exportable, location_fp, alg | Never holds key material |
| Issuer / IssuerAccount (M2) | id, kind (acme...), directory_url, account location (agent), capabilities | |
| Agent (M2) | id, org_id, group, identity serial, version, last_heartbeat, state, capabilities[] | |
| Deployment (M2) | id, lineage_id, target_id, desired_cert, state | Desired binding of a lineage to a target |
| WorkflowRun / WorkflowStep (M2) | id, lineage_id, kind, state, lease_epoch, checkpoint, idempotency_key | ADR-0003 |
| Job | see ADR-0003 | Durable scheduling |
| AuditEvent | org_id, seq, at, actor, action, resource, decision, result, request_id, prev_hash, hash | ADR-0012 |
| CredentialReference | provider, name, version | Pointer only |
| ApiToken | id, org_id, hash, role, scope, expires_at, revoked_at | |

## Management level (per lineage)

`discovered -> monitored -> owned -> enrolled -> provisioned -> verified`

- `discovered`: seen through import or a probe; no owner yet.
- `monitored`: findings and alerts are active.
- `owned`: a team is assigned.
- `enrolled` (M2): an issuer and profile are bound.
- `provisioned` (M2): at least one deployment target is bound.
- `verified` (M2): every required target is observed serving `current_cert`.

The level can move down (for example, when a target drifts -> `provisioned`). Every change writes an audit event.

## Finding checks (M1)

| Check | Severity rule (defaults, set by policy) |
|---|---|
| `expiry` | warning < 30 d, critical < 7 d, **critical if expired**; thresholds scale with lifetime for short-lived certificates |
| `not_yet_valid` | critical when an endpoint serves it |
| `hostname_mismatch` | critical: the SNI/host is not covered by the leaf's SANs |
| `chain_incomplete` | warning: the served chain does not reach a configured trust anchor without AIA fetching |
| `untrusted` | critical: no path to any configured trust store |
| `weak_key` / `weak_signature` | warning/critical, per policy (e.g. RSA < 2048, SHA-1) |
| `fingerprint_changed` | info, or warning if no lineage expected the change |
| `lineage_mismatch` | critical: the endpoint serves a certificate that is not its expected lineage's `current_cert` |
| `probe_failed` | warning after N consecutive failures |
| `unowned` | info: a lineage has no team |
| `ca_expiring` | on an authority in use: warning < 180 d, critical < 30 d (policy `caExpiry`); info for publicly trusted CAs (ADR-0029) |
| `chain_outlived` | warning when a certificate stays valid after its CA chain ends; critical within 30 d of the chain's end |
| `chain_cert_expiring` | on an endpoint: a served intermediate expires before the leaf, warning < 30 d, critical < 7 d |

## State machines

### WorkflowRun (M2)

```
planned -> [awaiting_approval] -> preflight -> validating_identity -> issuing -> issued
issued -> staged -> deploying -> activating -> verifying -> verified

failure paths:
  preflight -> preflight_failed
  issuing -> retry_scheduled -> issuing      (until attempts run out -> failed)
  deploying | activating | verifying -> rolling_back -> rolled_back
  any non-terminal -> blocked (deadline, policy, kill switch) -> resume
  any non-terminal -> failed | cancelled
```

- Checkpoints: `issued` (the certificate is persisted) and `staged` (the agent confirms the files are staged). Resuming after a crash restarts from the last checkpoint.
- A deploy-only retry starts at `staged`, so it never creates a new ACME order.
- `verified` requires every required target to report the new leaf SHA-256 through an independent probe.
- Revocation runs as a separate workflow kind (`revocation_pending -> revoked`). It never fires automatically on renewal.

### Deployment (M2)

`pending -> staged -> active_unverified -> verified`, plus `drifted` (an observation no longer matches) and `rolled_back`.

### Agent (M2)

`enrolling -> active <-> stale (heartbeat > 3x interval) -> offline (> 24 h) -> revoked (terminal)`

### Alert

`open -> acked -> resolved`; `acked -> open` after `alerts.ackExpiry`; `open -> suppressed (approved
exception only, while it covers the finding) -> open`.
An alert resolves automatically when its finding has been resolved for one full probe interval.

### PolicyException (M3)

`requested -> active | denied | expired`; `active -> expired | revoked`. One live exception per
subject and check (ADR-0016). It covers one condition (check version + fingerprint) and
never hides the finding.

### Approval (M3)

`requested -> approved | denied | expired` (one open request per deployment). An approval covers
a digest of the deployment spec; the deployment renews only while that digest still matches
(ADR-0015).

### TrustBundle (Phase 7)

`draft -> staged -> distributing -> verified -> retiring -> retired`
