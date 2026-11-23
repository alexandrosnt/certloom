# Threat model

Status: Accepted, updated 2026-11-22. It covers what is built through M6: inventory and
monitoring (M1), agent renewal (M2), approvals, DNS-01 and webhooks (M3), Windows and
Kubernetes (M4), cloud observation (M5), and IaC and agent plugins (M6). Revisit at every
milestone.

## Assets
| Asset | M1 | M2 |
|---|---|---|
| Leaf private keys | Not stored. Imported PFX keys are used only to match the certificate, then discarded | Stay on the agent (ADR-0005) |
| ACME account keys | - | On the agent |
| Agent internal CA key, task-signing key | - | In the control plane, envelope-encrypted (ADR-0009) |
| Notification credentials (SMTP, webhook secrets) | Envelope-encrypted or env/file | same |
| OIDC client secret, API tokens (hashed) | yes | yes |
| Audit trail | yes | yes |
| Inventory (hostnames, internal topology) | yes. **Sensitive reconnaissance data** | yes |
| Policies, ownership | yes | yes |
| DNS provider credentials, EAB HMAC keys (M3) | - | On the host, or stored centrally under the KEK, write-only, and sealed per agent and task (ADR-0018, ADR-0019) |
| Cloud and Kubernetes read credentials (M4, M5) | - | On the agent host only; ambient identity preferred (ADR-0023, ADR-0024) |
| Plugin trust policy and installed plugins (M6) | - | On the agent host only (ADR-0027) |

## Trust boundaries
1. Browser / CLI <-> `certloomd` API/UI (TLS; OIDC session or API token)
2. `certloomd` <-> PostgreSQL (TLS, or a local socket; app role with limited grants)
3. `certloomd` prober <-> configured endpoints (untrusted peers, untrusted certificate data)
4. `certloomd` <-> notification sinks (SMTP, webhook URLs: untrusted destinations)
5. `certloomd` <-> external audit sink
6. **M2:** `certloomd` <-> agent (mTLS + signed tasks); agent <-> local OS/Nginx; agent <-> ACME CA
. **M8:** load balancer in front of several `certloomd` replicas (TCP pass-through for agents, so mTLS still ends at certloomd)
. **M4/M5:** agent <-> Kubernetes API and cloud provider APIs (read-only)
9. **M6:** plugin publisher -> package + signature -> `certloom-plugin` -> agent host; agent <-> plugin process
10. **M6:** Terraform/OpenTofu and Ansible (operator machines, plan/state files, logs) <-> REST API

## Threats and mitigations (STRIDE)

| # | Threat | Category | Mitigation | Milestone / test |
|---|---|---|---|---|
| T1 | Prober abused for SSRF or internal port scanning (e.g. cloud metadata `169.254.169.254`, loopback, RFC 1918 ranges outside the intended scope) | Elevation / Info disclosure | Endpoints must fall inside an enabled `ProbeScope`. Loopback, link-local, metadata and unspecified addresses are denied by default (override per scope, audited). DNS is resolved once and the IP pinned for the connection, so DNS rebinding cannot redirect it. Per-scope rate limits. TLS handshake only, no HTTP. | M1: unit + e2e denylist tests |
| T2 | Malicious certificate or chain crashes or slows the parser | DoS | Size limits (cert <= 64 KiB, chain <= 10, SANs <= 1000). Go `crypto/x509` with recover around parse. Native fuzzing in CI. No AIA fetching unless explicitly enabled. | M1: fuzz >= 10 min in CI |
| T3 | Secrets or keys leak into logs, errors, events, metrics or CLI output | Info disclosure | `secret.Value` redaction type. Allowlisted event payloads. PFX passwords only via stdin, prompt or file, never argv. Log-scan test seeded with canary values. No high-cardinality or secret Prometheus labels. | M1 |
| T4 | Cross-organization data access | Info disclosure | Service-layer authz plus Postgres RLS on `org_id`. Not-found responses for other orgs' IDs. | M1: authz matrix + RLS tests |
| T5 | Privilege escalation through the API (e.g. Viewer mutates) | Elevation | Permission checks in the service layer, re-checked inside job handlers. Deny by default. | M1 |
| T6 | Stolen API token | Spoofing | Hashed at rest, shown once, scoped, expiring, revocable. Last-used tracking. | M1 |
| T7 | CSRF / XSS in the UI | Tampering | `html/template` auto-escaping, strict CSP, CSRF tokens, SameSite cookies (ADR-0011). Certificate fields are rendered as text only. | M1 |
| T8 | Audit tampering or suppression | Repudiation | Append-only role, hash chain, external export, `certloom audit verify` (ADR-0012). | M1 |
| T9 | Webhook notifications used for SSRF | Elevation | Webhook URLs are validated against the same deny rules as T1 (configurable). HMAC-signed payloads. No redirects followed. | M1 |
| T10 | Alert fatigue or suppression hides a real expiry | Tampering (operational) | Suppressions expire and are audited. Expired certificates cannot be suppressed beyond 24 h without Owner role. | M1 |
| T11 | Compromised agent | Spoofing / Elevation | Per-agent identity, a capability allowlist on the agent, no arbitrary-command tasks, signed tasks bound to the agent, fast revocation, short certificate lifetime. The agent holds no credentials for other hosts. | M2 |
| T12 | Compromised control plane orders malicious issuance or deployment | Elevation | It cannot read leaf keys. Policy SAN allowlists per lineage. Issuance rate and concurrency caps. Approvals (M3). External audit export. Agents validate that a task's SANs fall within their locally configured allowlist as well. | M2 |
| T13 | Unauthorized issuance for a hostname | Spoofing | Lineage `expected_sans` plus policy domain patterns. CAA awareness. CT monitoring (Research). | M2/M3 |
| T14 | Replay of an agent task or a stale worker writing after losing its lease | Tampering | Nonce, `not_after`, task binding, lease-epoch fencing (ADR-0003/0004). | M2 |
| T15 | Malicious dependency or compromised release | Tampering | `go.sum` pinning, govulncheck, license checks, Dependabot, signed releases + SBOM + provenance (ADR-0014). certloomd loads no third-party code; agent plugins run out of process and only from packages a trusted publisher signed (ADR-0027, T23). | M0 CI, M1 release; signed releases M8 |
| T16 | Loss of the KEK or the DB | DoS | Documented backup of the KEK separate from the DB. Restore drill in CI. | M1 |
| T17 | Inventory disclosure (reconnaissance value) | Info disclosure | The inventory itself is treated as sensitive: auth on all reads, no public dashboards, exports audited. | M1 |
| T18 | OIDC login CSRF, code injection, ID-token replay | Spoofing | State (constant-time compare), nonce, and PKCE S256 in a short-lived HttpOnly cookie. ID token verified for issuer, audience and expiry. `email_verified` required. Device-flow tokens accepted only for the configured public client. | M1: e2e forged-state, unverified-email and non-member tests |
| T19 | Token or password guessing; API abuse | Spoofing / DoS | Per-IP throttle on failed authentication (API and UI), per-IP limit on public sign-in endpoints, per-principal API rate limit, 256-bit random tokens. | M1: `api.TestRateLimits` |
| T20 | Duplicate side effects from client retries | Tampering | Idempotency-Key replay. Secret-bearing responses (token creation) are never stored. | M1: `api.TestIdempotencyKeys` |
| T21 | Lost update between concurrent editors | Tampering | ETag/If-Match with versioned rows; 412 on a stale write. | M1: `api.TestETagIfMatch` |
| T22 | Consistent rewrite of the audit table by a DB owner | Repudiation | External export + `certloomd audit-verify-export --compare`. | M1: `auditexport` tests, e2e |
| T23 | Malicious or substituted agent plugin | Tampering / Elevation | `certloom-plugin` installs only packages whose Sigstore bundle verifies against `plugins.trust` (keyless CI identity or public key); no skip flag. Safe extraction (no links, no traversal). The agent re-checks the executable digest from the install record before every call and ignores installs whose trust entry was removed. The control plane cannot install plugins. Residual: a trusted plugin runs with the agent's privileges. | M6: `cmd/certloom-plugin` tests, `agent.TestInstalledPluginResolution` |
| T24 | Central DNS or EAB credentials leak | Info disclosure | Stored under the KEK, write-only in the API, sealed with HPKE to the agent key for one task, kept in agent memory only, every delivery audited; hosts can opt out (ADR-0018, ADR-0019). | M3: workflow `central_dns_test`, `eab_test` (no plaintext in tasks, audit or ciphertext column) |
| T25 | Control plane redirects an approved deployment (other SANs, issuer, target, plugin) | Elevation | The approved spec digest covers SANs, key, issuer, challenge and target (IIS site and bindings, plugin name) and is re-checked before issue and deploy; a mismatch cancels the run (ADR-0015, ADR-0027). Agents still enforce their local SAN allowlists. | M3/M6: workflow `approval_test`, `plugin_test` |
| T26 | Over-privileged observer credentials (Kubernetes, cloud) | Elevation / Info disclosure | Read-only roles documented per provider; the Kubernetes agent has no access to Secrets and reads PEMs from CertificateRequests; ambient identity preferred over key files (ADR-0023, ADR-0024). | M4: kind e2e; M5: API fakes |
| T27 | Secrets in Terraform plan/state or Ansible output | Info disclosure | User-supplied secrets are write-only arguments (Terraform) or `no_log` (Ansible); server-generated secrets are not exposed (ADR-0025, ADR-0026). | M6: plan/state and playbook output secret scans in those repositories' CI |
| T30 | A rogue root pushed to trust stores through certloom, or planted on a host outside it | Elevation / Tampering | Hosts write only stores declared `manage` in their own agent config; certloom adds and removes only its own entries; tasks are signed (T6); bundle changes need `trust:manage` (owner) and are audited with every anchor added or removed; forced removals carry an audited reason; agents report what each store really holds, and anchors in no bundle raise `trust_store_unknown_anchor` (ADR-0030). Residual: an owner account, or whoever controls certloomd, can push a root to every managed store; a second-person approval gate is in docs/TODO.md. | M7: agent trust tests, workflow `TestTrustBundleDeliveryAndDrift` and `TestTrustBundleRemovalSafety`, Debian and Rocky containers (`TestOSTrustStores`), LocalMachine\Root on the Windows CI runner |
| T29 | Private CA credentials on the control plane misused or leaked (Vault AppRole secret_id or token, step-ca provisioner key) | Elevation / Info disclosure | Stored under the KEK bound to the issuer, write-only in the API, never in tasks; the CA side limits what they sign (Vault role, step-ca provisioner). certloomd sends only CSRs that match the approved spec exactly (names, key, no extra extensions) and never uses `sign-verbatim`; AppRole tokens are revoked after each call; every use is audited. TLS to the CA trusts only the issuer's CA bundle, with no redirects (ADR-0028). Residual: anyone who controls certloomd can sign within the role. | M7: privateca unit tests, workflow `privateca_test`, e2e `TestVaultAndStepCAIssuers` |
| T28 | Forged or replayed event webhooks; webhooks used for SSRF | Spoofing / Elevation | Standard Webhooks signatures with timestamps and secret rotation; destination checks as in T9; failing endpoints are disabled (ADR-0021). | M3: Standard Webhooks test vectors, workflow `TestEventWebhooks` |
| T31 | Two replicas run the same scheduler, or a replica keeps acting after losing leadership (split brain) | Tampering / DoS | One scheduler lease row; a replica counts its lease from before the renewing query, so it stops before the database lets another take over; a tick still running when the lease is lost may overlap the next leader's, so loops must stay safe under overlap (a rule in ADR-0033; most use SKIP LOCKED or upserts); job results stay lease-epoch fenced (T14, ADR-0033). | M8: `leader` tests, e2e `TestHAReplicas` (SIGKILL of the leader mid-renewal) |
| T32 | A restored or rolled-back database replays old state to agents | Tampering | The agent's per-target sequence fence and nonce store are unchanged by a restore. Agents report their fence in the heartbeat and the control plane only ever raises its counters, for that agent's own deployments; a lying agent can only block its own targets. Tasks it already ran are answered from its stored results, never re-run (ADR-0033). | M8: workflow `TestRestoredSequenceCatchesUp`, `agent.TestExecutedTaskResultResent`, e2e `TestDRRestoreWithAgent` |
| T33 | More copies of the KEK with several replicas, and its escrow copy | Info disclosure | One KEK file per replica, readable only by certloomd; escrow copies kept apart from database backups (`docs/runbooks/dr.md`). Keys derived from it (CSRF) are bound to their purpose with HKDF labels. | M8 |
| T34 | An API caller turns certloomd's cloud reading into a way to read its own files or leak its cloud identity | Info disclosure / elevation | Cloud account settings are a fixed list of fields per provider; unknown keys are refused. No file paths, no endpoint overrides (only Key Vault domains), and stored Google credentials must be service account keys, since external account configurations can name local files and token URLs. Stored keys are KEK-encrypted, bound to the account id, never returned; `cloud.centralCredentials: forbidden` disables them. Accounts need `cloud:manage` (owner) (ADR-0034). | Post-rc.1: workflow `TestCloudAccountSettingsAreRestricted`, `TestCloudAccountScan` |

## Accepted residual risks (to be reviewed)
- If no external audit sink is configured, a DB superuser can rewrite the audit trail undetectably by recomputing the hashes. `certloomd` logs a warning at startup, and the UI shows an error banner, in that case.
- Logical multi-org within one deployment is not a hostile-tenant boundary (ADR-0001).
- OCSP/CRL results reflect what the platform saw. They do not show how every client enforces revocation.

## Open items
- Offline autonomy is deliberately limited: agents never start issuance on their own (ADR-0004).
- Keyless plugin verification is tested against a virtual Sigstore only (docs/TODO.md).
