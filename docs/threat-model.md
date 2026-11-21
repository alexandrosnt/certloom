# Threat model

Status: Proposed (M0). It covers M1 (agentless inventory and monitoring) in full, and M2
(agent, ACME, Nginx) at design level. Revisit at every milestone.

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

## Trust boundaries
1. Browser / CLI <-> `certloomd` API/UI (TLS; OIDC session or API token)
2. `certloomd` <-> PostgreSQL (TLS, or a local socket; app role with limited grants)
3. `certloomd` prober <-> configured endpoints (untrusted peers, untrusted certificate data)
4. `certloomd` <-> notification sinks (SMTP, webhook URLs: untrusted destinations)
5. `certloomd` <-> external audit sink
6. **M2:** `certloomd` <-> agent (mTLS + signed tasks); agent <-> local OS/Nginx; agent <-> ACME CA
7. Supply chain: source -> CI -> release artifacts -> operator

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
| T15 | Malicious dependency or compromised release | Tampering | `go.sum` pinning, govulncheck, license checks, Dependabot, signed releases + SBOM + provenance (ADR-0014). Compiled-in connectors only (ADR-0007). | M0 CI, M1 release |
| T16 | Loss of the KEK or the DB | DoS | Documented backup of the KEK separate from the DB. Restore drill in CI. | M1 |
| T17 | Inventory disclosure (reconnaissance value) | Info disclosure | The inventory itself is treated as sensitive: auth on all reads, no public dashboards, exports audited. | M1 |
| T18 | OIDC login CSRF, code injection, ID-token replay | Spoofing | State (constant-time compare), nonce, and PKCE S256 in a short-lived HttpOnly cookie. ID token verified for issuer, audience and expiry. `email_verified` required. Device-flow tokens accepted only for the configured public client. | M1: e2e forged-state, unverified-email and non-member tests |
| T19 | Token or password guessing; API abuse | Spoofing / DoS | Per-IP throttle on failed authentication (API and UI), per-IP limit on public sign-in endpoints, per-principal API rate limit, 256-bit random tokens. | M1: `api.TestRateLimits` |
| T20 | Duplicate side effects from client retries | Tampering | Idempotency-Key replay. Secret-bearing responses (token creation) are never stored. | M1: `api.TestIdempotencyKeys` |
| T21 | Lost update between concurrent editors | Tampering | ETag/If-Match with versioned rows; 412 on a stale write. | M1: `api.TestETagIfMatch` |
| T22 | Consistent rewrite of the audit table by a DB owner | Repudiation | External export + `certloomd audit-verify-export --compare`. | M1: `auditexport` tests, e2e |

## Accepted residual risks (to be reviewed)
- If no external audit sink is configured, a DB superuser can rewrite the audit trail undetectably by recomputing the hashes. `certloomd` logs a warning at startup, and the UI shows an error banner, in that case.
- Logical multi-org within one deployment is not a hostile-tenant boundary (ADR-0001).
- OCSP/CRL results reflect what the platform saw. They do not show how every client enforces revocation.

## Open items
- Offline autonomy is deliberately limited: agents never start issuance on their own (ADR-0004).
- Threat-model the Phase 4+ connectors (Windows, Kubernetes, cloud) as each is planned.
