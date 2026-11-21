# ADR-0018: Central DNS solvers and credential delivery

**Status:** Accepted (2026-11-21)

## Context
ADR-0017 keeps DNS-01 solvers and their credentials in each agent's local config. That
limits the blast radius, but every host has to be configured, and rotating a token means
touching every host that uses it. Business buyers expect what DigiCert, Venafi and
AppViewX offer: DNS connectors defined once, centrally, with credentials stored in the
platform or fetched from a vault.

ACME still runs on the agent (ADR-0006), so a centrally held credential has to reach the
agent that solves the challenge.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Central solver definitions; secret delivered just in time inside the signed issue task, encrypted to that agent** | One place to configure and rotate; one delivery path for every secret source; database and task log hold only ciphertext | A control-plane compromise can obtain DNS write access (mitigated below) |
| B. Vault only: the agent fetches from an external vault with its own identity | Certloom stores no secret | Every customer must run a vault; vault auth on every host |
| C. Ambient cloud identity only | No secret anywhere | Works only for cloud DNS; not RFC 2136 or Cloudflare |

## Decision
Option A, with ambient identity as a credential type and vault sources added later
through the same path.

**Central solvers**
- A `dns_solver` holds a name, provider (`rfc2136`, `cloudflare` or a plugin path with its
  pinned SHA-256), zones, non-secret settings, and a credential:
  - `stored`: a secret kept in the database under the KEK (ADR-0009), additional data
    bound to the solver id. Write-only through the API and CLI; it is never returned.
  - `ambient`: nothing is delivered; a plugin uses the host's cloud identity (IAM role,
    managed identity, workload identity). Only valid for plugins.
  - Vault and cloud secret-manager references are added with the ADR-0009 Phase 6
    providers and use the same delivery.
- A solver is assigned to agents explicitly. Managing solvers needs a new
  `dns:manage` permission (owner and `issuer_admin`). Every change, and every delivery of
  a secret, is audited.

**Delivery**
- Each agent has a dedicated HPKE key pair (RFC 9180, `MLKEM768X25519`, HKDF-SHA256,
  AES-256-GCM), separate from its TLS and task keys. The private key never leaves the
  host. The public key is reported in the heartbeat over mTLS and replaced when the agent
  rotates its identity.
- An issue task for a DNS-01 deployment carries the assigned central solvers. Each
  secret is sealed to the agent's HPKE key, with the task id, agent id and solver id as
  HPKE info, so a sealed secret only opens for that agent and task. The control plane
  seals at send time; stored tasks hold ciphertext only.
- The agent opens the secret in memory for that issue step only and never writes it to
  disk. Built-in providers receive it directly; plugins receive it as `secrets` in the
  stdin request (never in argv or the environment).
- The hybrid post-quantum KEM is used because sealed secrets persist in the task table
  and must not become readable later.

**Host control and policy**
- Host-local solvers (ADR-0017) keep working. When a local and a central solver claim the
  same zone, the local one wins.
- The agent config can refuse central solvers entirely (`central_dns_solvers: false`),
  for hosts whose owners do not accept credentials from the control plane.
- Policy `dns.centralCredentials: allowed | forbidden` (default `allowed`) lets an
  organization choose the smaller blast radius for every agent.
- Solver definitions and credentials are not part of the approved deployment spec
  (ADR-0015 leaves secrets and operational settings out of it). The challenge type is
  part of it, as before.

## Industry practice (surveyed 2026-11-21)
| Who | Approach |
|---|---|
| [DigiCert Trust Lifecycle Manager](https://docs.digicert.com/nl/trust-lifecycle-manager/connectors/dns-integrations.html) | DNS connector credentials entered centrally; optional just-in-time fetch from a password vault |
| [Venafi / CyberArk](https://docs.paloaltonetworks.com/trust-protection-foundation/Docs/26.2/TopNav/Content/Credentials/t-Credentials-AdaptableCreds-creating.php) | Central credential objects; "adaptable credentials" fetched from vaults |
| [AppViewX](https://securityboulevard.com/2024/06/appviewx-avx-one-certificate-lifecycle-management-integration-with-hashicorp-vault) | Central platform with HashiCorp Vault integration |
| [Keyfactor](https://keyfactor.github.io/integrations-catalog/integrations/azure-azuredns-dnsplugin) | DNS plugin using a service principal or managed identity |
| [cert-manager](https://cert-manager.io/docs/configuration/acme/dns01/route53) ([Azure DNS](https://cert-manager.io/docs/configuration/acme/dns01/azuredns)) | Ambient cloud identity (IRSA, workload identity) preferred over static secrets |
| [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), [HashiCorp](https://developer.hashicorp.com/well-architected-framework/secure-systems/identity-access-management/use-dynamic-credentials) | Short-lived, just-in-time credentials and workload identity over long-lived static secrets |

No vendor document on CyberArk Conjur for DNS validation was found.

Enterprise platforms configure DNS credentials centrally and offer vault retrieval; open
source and security guidance prefer ambient identity and short-lived credentials. This
decision does both: central definitions with just-in-time, per-agent sealed delivery, and
ambient identity where the DNS provider supports it.

## Consequences
- A compromised control plane can read stored DNS credentials (it holds the KEK). The
  policy switch, host opt-out, scoped tokens per zone, and audit of every delivery are
  the mitigations; vault references and ambient identity avoid stored secrets entirely.
- The plugin protocol gains an optional `secrets` field (still version 1; plugins that
  read their own credentials ignore it).
- Rotating a stored credential is one API call; the next issuance uses it.

## Verification
- Unit: HPKE seal/open bound to agent, task and solver (a secret sealed for another task
  or agent fails); the stored secret is never returned by the API; solver selection with
  local and central solvers on the same zone; host opt-out; policy `forbidden`.
- Workflow: a central solver assigned to an agent reaches the issue task sealed; the task
  table and audit log contain no plaintext (secret scan, as for the DB dump).
- e2e: the BIND test from ADR-0017 run with a central RFC 2136 solver instead of a local
  one.
