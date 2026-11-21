# ADR-0019: ACME External Account Binding

**Status:** Accepted (2026-11-21)

## Context
Many commercial ACME CAs (DigiCert, Sectigo, ZeroSSL, SSL.com, Google Trust Services,
AWS) require External Account Binding (RFC 8555 section 7.3): a key id and an HMAC key,
issued by the CA, that tie a new ACME account to a customer account. EAB is only used
when an account is registered; after that the ACME account key alone authenticates.

ADR-0006 keeps ACME accounts per agent, with the account key on the agent host. Each
agent therefore registers its own account and needs EAB once per CA.

CAs differ in how EAB keys can be used:
- **Reusable:** the same key id and HMAC register any number of accounts (DigiCert
  profile credentials, ZeroSSL, Sectigo, SSL.com).
- **Single-use:** one key registers one account and expires if unused (Google Trust
  Services: 7 days).

## Options considered
| Option | For | Against |
|---|---|---|
| **A. EAB stored on the issuer, sealed to the agent only when it registers; agent-local EAB also allowed** | Configured once; reuses the ADR-0018 delivery path; works for hosts that refuse central secrets | Control plane holds the HMAC (as with central DNS credentials) |
| B. Issuer only | Smaller surface | Air-gapped or locked-down hosts have no option |
| C. Agent config only | Control plane never sees the HMAC | Every host configured by hand; single-use keys distributed manually |
| D. One shared ACME account in the control plane | One registration | Contradicts ADR-0006 (account keys on hosts); one key compromise affects every host |

## Decision
Option A. Per-agent accounts stay as in ADR-0006.

**Issuer configuration**
- An issuer gains `eab_mode`: `none` (default), `reusable` or `single_use`.
- `reusable`: one key id and HMAC on the issuer. The HMAC is stored under the KEK
  (ADR-0009) with additional data bound to the issuer id, write-only through the API and
  CLI. Replacing it affects only agents that have not registered yet.
- `single_use`: the issuer holds a pool of keys (key id, HMAC under the KEK, optional
  expiry). When an agent without an account needs one, a key is claimed for that agent
  in the same transaction that builds the task, so two agents never get the same key.
  Retries for the same agent reuse its claimed key. The key is marked consumed once the
  agent reports the account as registered. Expired, unclaimed keys are never handed out.
- Managing EAB needs `issuers:manage`. Adding keys, claims, consumption and every
  delivery are audited.

**Account slots and delivery**
- The issue task names an account slot (`issuer:<id>`). The agent keeps one ACME account
  per directory URL and slot, and reports registered slots in its heartbeat and in issue
  results.
- EAB is only sent while the agent has not reported the slot as registered. It is sealed
  to the agent's HPKE key exactly as in ADR-0018 (HPKE info binds agent id, task id and
  issuer id), opened in memory for the registration and never written to disk.
- Accounts registered before this change (no slot) remain in use for issuers with
  `eab_mode: none`.

**Host control**
- The agent config may define EAB per directory URL (`acme_eab`: key id and an HMAC
  file). A local entry wins over central EAB.
- `central_eab: false` in the agent config refuses central EAB, like
  `central_dns_solvers: false`.
- EAB is not part of the approved deployment spec. The issuer id already is (ADR-0015).

**Findings**
- `single_use` pool: a finding when fewer unclaimed, unexpired keys remain than agents
  assigned to the issuer without an account, and when a claimed key is close to expiry
  before registration.
- Registration errors from the CA (`externalAccountRequired`, `unauthorized`,
  `malformed`) are reported as a non-retryable issuance failure with the ACME problem
  type, so a revoked or mistyped key does not loop.

## Industry practice (surveyed 2026-11-21)
| Who | Approach |
|---|---|
| [cert-manager](https://cert-manager.io/docs/configuration/acme/) | `externalAccountBinding.keyID` and `keySecretRef` on the Issuer; used at account registration |
| [DigiCert Trust Lifecycle Manager](https://docs.digicert.com/en/trust-lifecycle-manager/integration-guides/third-party-acme-integration/acme-external-account-binding--eab-.html) | EAB credentials per certificate profile, reusable by many clients, shown once; regeneration revokes the old ones |
| [Google Trust Services / Public CA](https://docs.cloud.google.com/certificate-manager/docs/public-ca-tutorial) | Each EAB key registers one account and must be used within 7 days; a new key per additional account |
| [AWS Certificate Manager](https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-eab.html) | EAB credentials obtained through an API call |
| [Certbot](https://docs.cloud.google.com/certificate-manager/docs/public-ca-tutorial), [acme.sh](https://redmine.pfsense.org/issues/16623), [Caddy](https://mail-archive.com/haproxy@formilux.org/msg47064.html), [lego](https://www.github.com/go-acme/lego/pull/1501) | EAB passed per host at account registration; each host has its own account |

No Sectigo or Venafi document describing their EAB storage model was found.

Central platforms attach EAB to the issuer or profile; host clients take it at
registration and keep their own account. This decision does both, and adds a key pool
because single-use keys are otherwise unusable with per-agent accounts.

## Consequences
- A compromised control plane can read stored EAB HMACs and register accounts at the CA
  under the customer account. Mitigations are the same as ADR-0018: audit of every
  delivery, host-local EAB, host opt-out. A leaked reusable key is revoked at the CA.
  Whether accounts already registered with it keep working is not documented in the
  sources found; it is recorded per CA in the integration matrix once tested.
- Single-use pools need refilling by an operator; the finding gives notice before
  renewals stall.

## Verification
- Unit: slot naming; EAB omitted once a slot is reported; local EAB wins; `central_eab:
  false`; HMAC never returned by the API.
- Workflow: two agents on a `single_use` issuer get different keys; retries reuse the
  claim; consumption on registration; expired keys skipped; pool-low finding; no
  plaintext HMAC in tasks or audit.
- e2e: Pebble with `externalAccountBindingRequired`, issuance with central reusable EAB,
  central single-use EAB, and agent-local EAB.

## As built (2026-11-21)
- Migration 00009: issuer columns `eab_mode`, `eab_kid`, `eab_hmac_ciphertext` (KEK, AAD
  `issuer_eab:<id>`); table `eab_keys` (AAD `eab_key:<id>`, states available, claimed,
  consumed, failed; one open claim per agent and issuer). Findings may now have subject
  type `issuer`.
- A claim is only made for a key valid for at least two more hours. A claimed key that
  expires unused is marked failed at the next run, and another is claimed.
- A consumed key counts as a registered account even before the agent's next heartbeat,
  so a quick second run does not claim a second key.
- The agent reports `acme_accounts`, `local_eab`, `no_central_dns` and `no_central_eab` in
  its heartbeat. It now sends its sealing key when it accepts either kind of central
  secret; the control plane reads the explicit refusal flags (older agents signal a DNS
  refusal by omitting the key, as before).
- A run fails early, without contacting the agent, when the pool is empty, a reusable
  issuer has no key, or the agent refuses central EAB and has no key of its own.
- e2e covers single-use central keys and host-local keys against Pebble. Reusable central
  keys use the same agent path and are covered by the workflow tests.
