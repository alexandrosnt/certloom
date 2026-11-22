# ADR-0028: Vault PKI and step-ca issuers

**Status:** Accepted (2026-11-22)

## Context
Private PKI is the next issuer family (brief, Phase 7). HashiCorp Vault PKI and
Smallstep step-ca are the two open, self-hostable CAs most teams run. Both expose two
ways to get a certificate:

- **ACME** (RFC 8555). Vault PKI has an ACME server since 1.14, with optional EAB. step-ca
  has an `ACME` provisioner. certloom's existing ACME issuer (ADR-0006, ADR-0019) can
  point at either one with only a directory URL, EAB and a trusted CA bundle.
- **A native signing API.** Vault: `POST /v1/<mount>/sign/<role>` with a CSR, after
  authenticating (token, AppRole, Kubernetes, JWT, ...). step-ca: `POST /1.0/sign` with a
  CSR and a one-time token (a JWT signed by a `JWK` provisioner key).

ACME needs a challenge the CA can validate. Internal hosts are often unreachable from the
CA for HTTP-01, and internal zones often have no automatable DNS. Agents also have no
outbound path to the CA in some segmented networks. The native API instead authorizes
the caller, and the CA role (Vault) or provisioner policy (step-ca) limits the names.

ADR-0005 still applies: private keys are generated on the host and never leave it.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. ACME as today, plus native CSR signing by the control plane** | ACME needs no new code; native signing covers hosts with no usable challenge; one place holds CA credentials, as with central DNS solvers (ADR-0018) | Control plane holds CA signing credentials; new run step |
| B. ACME only | Least code | Every internal host needs HTTP-01 reachability or DNS automation |
| C. Native signing on each agent, with per-host CA credentials | Control plane holds no CA credentials | A CA credential on every host; per-host CA-side setup; nothing like it among CLM vendors |

## Decision
Option A.

**ACME path (no code change)**
- An ACME issuer pointing at Vault or step-ca is a supported, tested configuration. The
  integration matrix gains rows for both, and the docs show the CA-side setup.

**Native path: new issuer kinds `vault` and `stepca`**
- The deployment workflow gains one agent task, `csr.create`. The agent checks the SANs
  against its `allowed_sans` exactly as for ACME, generates the key in the run directory
  (the same key the deploy step later uses), and returns only the CSR.
- The control plane checks the CSR before sending it anywhere. Its SANs must equal the
  approved spec, the key algorithm must match it, the signature must verify, and it must
  carry no extensions beyond the SAN extension. A CSR that fails is a failed run, not a
  retry.
- The CA call runs in its own durable job (ADR-0003), outside the database transaction.
  The run moves `issuing -> signing -> issued`. The returned chain then goes through the
  same `acceptIssued` checks as an ACME chain, and deploy, verify and rollback are
  unchanged.
- A retried signing job can produce a second certificate for the same CSR. That is
  harmless: only the recorded one is deployed, and both are in the inventory.
- A deployment with a native issuer is refused unless the agent's last heartbeat
  reports `csr.create`. Agents that predate it, or that exclude it in `allowed_tasks`,
  keep working with ACME issuers.

**Vault (`kind: vault`)**
- Settings: address, PKI mount, role, optional `issuer_ref`, optional Vault namespace,
  and an optional TTL.
- The signing endpoint is always `sign/<role>`. `sign-verbatim` is never used, so the
  Vault role's `allowed_domains` and key rules still apply as a second check.
- Authentication: `approle` (role_id plus a stored secret_id) or `token` (a stored
  token). Kubernetes and JWT auth come later through the same field. Each signing call
  logs in, uses the short-lived token once, and revokes it with `auth/token/revoke-self`
  (token auth skips the login and the revoke).

**step-ca (`kind: stepca`)**
- Settings: CA URL, `JWK` provisioner name, key id, and a stored provisioner private key
  (JWK, already decrypted by the operator with `step crypto jwk`).
- Each call mints a one-time token with `iss` = provisioner name, `aud` =
  `<ca>/1.0/sign`, `sub` = first SAN, `sans` = all SANs, a random `jti`, and a 5-minute
  lifetime.

**Common rules**
- Stored secrets use the ADR-0018 `stored` credential: KEK envelope encryption
  (ADR-0009), additional data bound to the issuer id, write-only through the API and
  CLI, rotated without recreating the issuer. Every use and change is audited.
- Each issuer carries a PEM CA bundle for TLS to the CA. The system roots are not used
  for these kinds, because both CAs are almost always private. A step-ca root
  fingerprint can be given instead of a bundle.
- Issuer URLs are set by `issuer_admin` and may be private addresses (that is where
  these CAs live). They are fetched only from the control plane, with no redirects
  followed. Responses are size-limited, and the request has a timeout.
- Errors map onto the existing retry rules. 4xx responses for authentication or
  policy (Vault `permission denied`, a role rejecting a name, a step-ca unauthorized
  token) fail the run without retrying. 5xx responses and network errors retry with
  backoff, and a 429 honors `Retry-After`.
- Revocation stays out of scope, as it is for ACME issuers today.

## As built (2026-11-22)
- Implemented as decided: task `csr.create`, run states `issuing -> signing -> issued`,
  the CA call in the advance job before its transaction (`externalSign`), the CSR check in
  `internal/privateca.CheckCSR`, the Vault and step-ca clients in `internal/privateca`
  (standard library plus go-jose). Each signing call is audited as
  `issuers.credential_used`.
- The approved spec gains `mount`, `role`, `issuer_ref`, `namespace` and `provisioner`,
  all omitted when empty, so the digests of existing ACME deployments did not change.
  Settings are fixed after creation; the CA bundle and the credential can be replaced.
- A deployment with a native issuer gets challenge `none`. A template's challenge is
  ignored for such an issuer.
- The CA bundle is required for both kinds. The step-ca root fingerprint alternative was
  not built (docs/TODO.md).
- Vault roles default to RSA keys while agents make ECDSA P-256 keys, so the role needs
  `key_type=ec` or `any`. The runbook says so.
- The ACME path against Vault's and step-ca's ACME servers is not tested yet, so the
  integration matrix does not claim it (docs/TODO.md). The native path is tested end to
  end in `test/acme` (`TestVaultAndStepCAIssuers`, Vault 1.20 and step-ca 0.28.4).

## Industry practice (surveyed 2026-11-22)
| Who | Approach |
|---|---|
| [cert-manager Vault issuer](https://cert-manager.io/docs/configuration/vault/) | Controller holds Vault credentials (Kubernetes, AppRole, token); key generated in cluster; CSR to `<mount>/sign/<role>` |
| [HashiCorp Vault Secrets Operator](https://developer.hashicorp.com/vault/docs/deploy/kubernetes/vso/cert-manager) | Same CSR-sign model; operator authenticates as itself |
| [Smallstep step-ca integrations](https://smallstep.com/docs/step-ca/integrations/) | Documents both step-issuer (JWK provisioner signs CSRs) and plain ACME against step-ca |
| [step-ca provisioners](https://smallstep.com/docs/step-ca/provisioners/) | `JWK` provisioner (one-time-token signing) and `ACME` provisioner side by side |
| [Vault PKI ACME](https://developer.hashicorp.com/vault/docs/secrets/pki/acme) | Vault PKI serves ACME (with EAB) alongside the native API |
| [Venafi / CyberArk](https://venafi.com/blog/patterns-vault-integration-venafi-part-1) | Central platform integrates with Vault PKI through plugins and its API |
| [AppViewX](https://www.appviewx.com/hashicorp/) | Central platform acts as RA over Vault through its API |
| [Keyfactor](https://www.keyfactor.com/integration/hashicorp/) | Vault plugins and API-level integration from the central platform |

Prevailing practice: offer both ACME and a native CSR-signing integration, with CA
credentials held by the central controller and keys generated where they are used.
Option C has no counterpart among the vendors or open-source projects surveyed.

## Consequences
- The control plane gains CA signing credentials. They are scoped by the Vault role or
  step-ca provisioner policy, and the threat model gains an entry for them.
- Old agents keep working. Native issuers need an agent that reports `csr.create`.
- New dependencies: none. Vault's HTTP API and the step-ca token are small enough to
  call with the standard library plus the JOSE library already in use.

## Verification
- Integration tests in CI run against real `hashicorp/vault` (dev mode, PKI mount, AppRole)
  and `smallstep/step-ca` containers. They cover the ACME path and the native path end to
  end through deploy and verify.
- A Vault role that does not allow a name makes the run fail without a retry.
- A CSR with extra SANs or extensions is rejected before any CA call.
- Stored credentials never appear in API responses, logs or task payloads.
