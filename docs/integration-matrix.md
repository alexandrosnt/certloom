# Integration matrix

**Rule:** a capability is listed as *supported* only when a named test proves it
(ADR-0007). Anything else is *planned* or *not claimed*.

Capability vocabulary: `discover`, `read_metadata`, `request`, `renew`, `revoke`,
`export_certificate`, `export_private_key`, `import`, `deploy`, `bind`, `activate`,
`verify`, `rollback`, `manage_trust_bundle`, `health_check`.

## Test status (2026-11-20)

- **M1 rows:** supported, covered by the unit, store and e2e tests.
- **M2 rows** (Linux agent discovery, Certbot discovery, ACME via lego v5, Nginx target): supported for the claimed capabilities, with these limits:
  - Tested against **Pebble** in `test/acme`, running a real HTTP-01 challenge, the real Nginx 1.29 Alpine image and the real `certloom-agent`.
  - **Let's Encrypt staging has not been exercised.** It needs a publicly reachable hostname. Do that before claiming production Let's Encrypt support.
  - Wildcard SANs are refused (HTTP-01 only).
  - Tested on Nginx 1.29 (Alpine). The systemd reload path (`systemctl reload nginx`) is not tested.

## Committed scope

| Connector | Milestone | Claimed capabilities | Explicitly NOT claimed | Privileges required | Test strategy |
|---|---|---|---|---|---|
| File import (PEM, DER, PKCS#12) | M1 | discover, read_metadata | export_private_key. Keys are only matched against the certificate, never stored | Read access to the provided file | Unit tests + adversarial corpus + fuzzing |
| TLS endpoint prober | M1 | discover, read_metadata, verify, health_check | Any mutation; HTTP-level checks; OCSP/CRL enforcement claims | Network reachability inside an enabled ProbeScope | e2e against Nginx containers with multiple SNIs, broken chains, expired and self-signed certificates |
| Email (SMTP) notifier | M1 | notify | - | SMTP credentials (CredentialReference) | e2e with a local SMTP sink (e.g. MailHog-compatible) |
| Generic webhook notifier | M1 | notify (HMAC-signed) | Following redirects | Destination URL inside allowed scope | e2e with a local HTTP sink; SSRF deny tests |
| Linux agent, filesystem discovery | M2 | discover, read_metadata | Reading or uploading private keys | Read access to configured paths | e2e in containers (Ubuntu, Debian, RHEL UBI) |
| Certbot lineage discovery | M2 | discover, read_metadata (renewal conf, version, ARI capability >= 4.1.0) | renew, modify, or take over `/etc/letsencrypt` | Read `/etc/letsencrypt` | e2e with Certbot against Pebble |
| ACME issuer (lego v5) | M2 | request, renew, revoke (explicit, permission-gated); ARI; `replaces` | DNS-01, TLS-ALPN-01, EAB (M3); profiles beyond `default`/`shortlived` until tested | ACME account key on the agent; HTTP-01 webroot write access | Pebble v2.10.x in CI (ARI always on); Let's Encrypt staging manually |
| Nginx target (Linux, systemd) | M2 | deploy, activate, verify, rollback | Containerized Nginx, Apache, config generation | Write to the cert directory; run `nginx -t`; `systemctl reload nginx` | e2e: success, `nginx -t` failure, reload failure, old cert still served |

## Deferred (planned; no support is claimed)

| Integration | Planned milestone | First capability set | Notes |
|---|---|---|---|
| DNS-01 (RFC 2136 + one provider) | M3 | ChallengeSolver | CNAME delegation; authoritative checks |
| Windows agent + IIS / HTTP.sys, win-acme discovery | M4 | discover, read_metadata | Then bind/verify, with a binding-drift test (win-acme #2728) |
| cert-manager / trust-manager | M4 | discover, read_metadata (CRDs, status, events) | Never stand in for cert-manager's controller |
| Docker Compose / Swarm | M4+ | discover | Versioned secret rotation for Swarm |
| AWS ACM / ACM PCA | M5 | discover, read_metadata | Imported certs are not managed-renewal eligible; CloudFront requires us-east-1 |
| Azure Key Vault | M5 | discover, read_metadata, Event Grid correlation | A new version does not prove the consumer adopted it |
| Google Certificate Manager / CAS | M5 | discover, read_metadata | Track map -> target-proxy relationships |
| Cloudflare edge packs vs Origin CA | M5 | discover, read_metadata | Separate modules; Origin CA is not browser-trusted |
| Vault PKI, step-ca | M7 | request (ACME) | |
| Terraform/OpenTofu provider, Ansible collection | M6 | desired-state resources | Never put keys or secrets in state |
| SCEP / EST / CMP, device certificates | Research | - | Only if a concrete use case requires it |
