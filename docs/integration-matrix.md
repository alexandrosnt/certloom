# Integration matrix

**Rule:** a capability is listed as *supported* only when a named test proves it
(ADR-0007). Anything else is *planned* or *not claimed*.

Capability vocabulary: `discover`, `read_metadata`, `request`, `renew`, `revoke`,
`export_certificate`, `export_private_key`, `import`, `deploy`, `bind`, `activate`,
`verify`, `rollback`, `manage_trust_bundle`, `health_check`.

## Test status (2026-11-21)

- **M1 rows:** supported, covered by the unit, store and e2e tests.
- **M2 rows** (Linux agent discovery, Certbot discovery, ACME via lego v5, Nginx target): supported for the claimed capabilities, with these limits:
  - Tested against **Pebble** in `test/acme`, running a real HTTP-01 challenge, the real Nginx 1.29 Alpine image and the real `certloom-agent`.
  - **Let's Encrypt staging** exercised by hand on 2026-11-21 (Debian 13, nginx 1.26.3 under systemd, PostgreSQL 17, packaged agent): first issuance over HTTP-01, renewal with `replaces`, ARI window used for the next renewal, and a forced `nginx -t` failure that rolled back while the old certificate stayed live. Staging accepted a second order that `replaces` the same certificate once the earlier replacing order had finished; Pebble rejects that with `alreadyReplaced`, and the agent handles both.
  - **Let's Encrypt production**: one issuance on the same host (2026-11-21), switched over from a staging certificate; trusted chain ISRG Root X2 / YE1.
  - Wildcard SANs need DNS-01 (M3).
  - Tested on Nginx 1.29 (Alpine) in CI and on Nginx 1.26 with `systemctl reload nginx` (packaged agent e2e on Debian 13, plus the staging run).

## Evidence levels

Each supported capability names the kind of test behind it:
- **unit**: logic tested in isolation.
- **mock API**: the real client against a recorded or hand-written fake of the provider's API.
- **local server**: the real software run in CI (Pebble, Nginx, BIND, PostgreSQL).
- **live**: the real hosted service (Let's Encrypt, Cloudflare). Run by hand or opt-in.

A mock or local-server test proves our side of the protocol. It does not prove the
provider behaves as the fake does; only a live run does.

## Committed scope

| Connector | Milestone | Claimed capabilities | Explicitly NOT claimed | Privileges required | Test strategy |
|---|---|---|---|---|---|
| File import (PEM, DER, PKCS#12) | M1 | discover, read_metadata | export_private_key. Keys are only matched against the certificate, never stored | Read access to the provided file | Unit tests + adversarial corpus + fuzzing |
| TLS endpoint prober | M1 | discover, read_metadata, verify, health_check | Any mutation; HTTP-level checks; OCSP/CRL enforcement claims | Network reachability inside an enabled ProbeScope | e2e against Nginx containers with multiple SNIs, broken chains, expired and self-signed certificates |
| Email (SMTP) notifier | M1 | notify | - | SMTP credentials (CredentialReference) | e2e with a local SMTP sink (e.g. MailHog-compatible) |
| Generic webhook notifier | M1 | notify (HMAC-signed) | Following redirects | Destination URL inside allowed scope | e2e with a local HTTP sink; SSRF deny tests |
| Linux agent, filesystem discovery | M2 | discover, read_metadata | Reading or uploading private keys | Read access to configured paths | e2e in containers (Ubuntu, Debian, RHEL UBI) |
| Certbot lineage discovery | M2 | discover, read_metadata (renewal conf, version, ARI capability >= 4.1.0) | renew, modify, or take over `/etc/letsencrypt` | Read `/etc/letsencrypt` | e2e with Certbot against Pebble |
| ACME issuer (lego v5) | M2 | request, renew, revoke (explicit, permission-gated); ARI; `replaces`; HTTP-01 and DNS-01 challenges | TLS-ALPN-01; profiles beyond `default`/`shortlived` until tested | ACME account key on the agent; HTTP-01 webroot write access | Pebble v2.10.x in CI (ARI always on); Let's Encrypt staging manually |
| Nginx target (Linux, systemd) | M2 | deploy, activate, verify, rollback | Containerized Nginx, Apache, config generation | Write to the cert directory; run `nginx -t`; `systemctl reload nginx` | e2e: success, `nginx -t` failure, reload failure, old cert still served |
| DNS-01 via RFC 2136 (built-in) | M3 | Create and remove TXT records with TSIG (hmac-sha256+); CNAME delegation; wildcards | GSS-TSIG (Kerberos, Active Directory DNS) | TSIG key allowed to update TXT records in the zone | unit (fake server checking TSIG); local server: BIND 9.20 + Pebble in `test/acme`, wildcard and CNAME-delegated names, issuance and renewal |
| DNS-01 via Cloudflare (built-in) | M3 | Create and remove TXT records | Any other Cloudflare product | API token with Zone:DNS:Edit on the zones used | mock API only (lego's client against an httptest server). Not live-verified yet |
| DNS plugin protocol v1 | M3 | Any DNS service through an executable plugin (`docs/dns-plugins.md`) | Behaviour of a given plugin: each needs its own `certloom-agent dns-test` run | Whatever the plugin needs; pinned by SHA-256 | unit (protocol, error classes, timeout, digest pin, minimal environment); `dns-test` against BIND |
| Windows agent + IIS / HTTP.sys | M4 | Non-exportable CNG machine keys, CSR signed in CNG; certificate into `WebHosting`; switch the HTTP.sys entries of configured bindings (other settings kept), read back, TLS verify, rollback; binding drift findings | Central Certificate Store bindings (reported only); creating bindings; TPM keys | Windows service as LocalSystem (HTTP.sys configuration, machine keys) | unit (bindings, appcmd XML, deploy/restore/prune with a fake host); Windows (user-scope CNG key, CSR, store link resolved by Windows); local server in CI (windows-2022, elevated): real IIS site, HTTP.sys IP and SNI entries, deploy, verify, drift via `netsh`, rollback, HTTP-01 `web.config`. ACME issuance itself shares the Linux path (Pebble e2e) |
| win-acme discovery | M4 | discover, read_metadata (renewal files: hosts, plugins, last result) | Changing win-acme renewals or its scheduled task | Read `%ProgramData%\win-acme` | unit (renewal file parsing, stored credentials not reported) |
| cert-manager / trust-manager observation | M4 | discover, read_metadata: Certificates (PEM from the current CertificateRequest), Issuers, ClusterIssuers, Bundles, Ingress TLS hosts; findings for not ready, overdue renewal, failed request, issuer not ready, bundle not synced | Any write; TLS Secrets not managed by cert-manager; Bundle contents | `get`, `list` on those resources only; no Secrets or ConfigMaps | unit (REST client: pagination, token re-read, 429, missing CRD); workflow (findings, vanished objects, unlisted kinds); local server: kind + cert-manager v1.17.2 + Bundle CRD, agent with the manifest's RBAC, `can-i get secrets` = no |
| Event webhooks (Standard Webhooks) | M3 | notify: typed lifecycle events to subscribed HTTPS endpoints, signed with replay protection; delivery log, redelivery, secret rotation | Exactly-once delivery; event replay beyond 30 days | `webhooks:manage`; a KEK on the control plane | unit (Standard Webhooks symmetric vector, rotation, filters, catalog documented); workflow (real HTTP receiver: signatures, retry on 5xx, stop on 4xx, redelivery, rotation, auto-disable, no secret in events, audit or idempotency store); local server: certloomd worker delivering from a Pebble renewal to a receiver container |
| Central DNS solvers with sealed credential delivery | M3 | Store a DNS credential once, deliver it sealed to assigned agents per issue task; ambient identity for plugins | Vault or cloud secret-manager references (planned) | `dns:manage`; a KEK on the control plane | unit (HPKE binding to agent, task and solver; key rotation); workflow (no plaintext in tasks, audit or ciphertext column; policy and opt-out); local server: BIND + Pebble with a central RFC 2136 solver |
| ACME External Account Binding | M3 | Register per-agent ACME accounts with EAB: one reusable key, a pool of single-use keys (claimed per agent, consumed on registration), or a host-local key; the key reaches the agent sealed to it for one task | Live runs against commercial CAs; whether accounts survive key revocation at a given CA | `issuers:manage`; a KEK on the control plane | unit (sealing bound to agent, task and issuer; host key wins; opt-out; refusal classification; account slots); workflow (no plaintext in tasks, audit or issuer row; pool claims, consumption, refusal, findings, host control); local server: Pebble requiring EAB in `test/acme` with a single-use pool (empty pool, key refused by the CA, valid key, account reused) and a host-local key |
| AWS ACM / AWS Private CA observation | M5 | discover, read_metadata: certificates with chain, type, renewal eligibility and status, in-use resources; CA certificates; several regions and accounts (STS AssumeRole) | Any write; `ExportCertificate`; CloudFront/ELB attachment details beyond `InUseBy` | ACM List/Describe/GetCertificate, Private CA ListCertificateAuthorities/GetCertificateAuthorityCertificate | mock API only: the AWS SDK against a fake speaking JSON 1.1 (ACM) and RPC v2 CBOR (Private CA), checking signing, all key types and the call allowlist. Not live-verified yet |
| Azure Key Vault observation | M5 | discover, read_metadata: certificates, AutoRenew policy, pending/failed operations, versions; new-version adoption by probed endpoints (polling instead of Event Grid) | The secrets API (private keys); Event Grid push | Key Vault Reader | mock API only: the Azure SDK with its challenge-based auth against a TLS fake, certificates paths only. Not live-verified yet |
| Google Certificate Manager / CA Service observation | M5 | discover, read_metadata: certificates with managed state and authorization failures, certificate map entries as usage; CA pools and authorities | Any write; classic Compute SSL certificates | `roles/certificatemanager.viewer`, `roles/privateca.auditor` | mock API only (REST fake with paging and per-scope errors). Not live-verified yet |
| Cloudflare edge packs and Origin CA observation | M5 | discover, read_metadata: certificate packs of all types (metadata only; the API returns no certificate) and Origin CA certificates (marked not publicly trusted) | Any write; Keyless SSL; mTLS client certificates | Token with Zone SSL and Certificates Read (+ Zone Read without a zone list) | mock API only. Not live-verified yet; the exact token permission for the Origin CA list is unconfirmed |

## Deferred (planned; no support is claimed)

| Integration | Planned milestone | First capability set | Notes |
|---|---|---|---|
| `certloom-dns-lego` (all lego DNS providers as one plugin) | M3+ | ChallengeSolver | Needs a long-running transport: many lego providers keep record ids in memory between present and cleanup |
| Docker Compose / Swarm | M4+ | discover | Versioned secret rotation for Swarm |
| Vault PKI, step-ca | M7 | request (ACME) | |
| Terraform/OpenTofu provider, Ansible collection | M6 | desired-state resources | Never put keys or secrets in state |
| SCEP / EST / CMP, device certificates | Research | - | Only if a concrete use case requires it |
