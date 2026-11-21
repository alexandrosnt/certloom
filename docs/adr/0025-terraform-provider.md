# ADR-0025: Terraform/OpenTofu provider and public Go client

**Status:** Accepted (2026-11-21)

## Context
Teams that run certloom want its configuration (teams, scopes, endpoints, templates,
issuers, DNS solvers, channels, webhooks, exceptions, policy) in the same Terraform or
OpenTofu code as the rest of their infrastructure, reviewed and applied the same way.
The hard requirement is that no secret ends up in Terraform plan or state files, which
are often stored in shared backends and read by many people and CI jobs.

Today only the CLI talks to the API, through a client in `cmd/certloom` (package
`main`), so nothing outside this repository can reuse it.

## Options considered
**Plugin library**
| Option | For | Against |
|---|---|---|
| **A. terraform-plugin-framework** | HashiCorp's recommendation for new providers; supports write-only arguments and ephemeral resources; typed schemas | Newer than SDKv2, fewer examples in older providers |
| B. terraform-plugin-sdk/v2 | Most existing providers use it | In maintenance mode; new features land in the framework first |

**What the provider manages**
| Option | For | Against |
|---|---|---|
| **A. Control-plane configuration only** | Private keys stay on agents (ADR-0009); nothing secret has to be read back; fits a review-and-apply workflow | Certificates themselves are not Terraform resources |
| B. Also a certificate resource that returns cert and key | Familiar from Venafi, DigiCert and Vault providers | Puts private keys in state and moves key handling out of the agent; renewal then depends on someone running `apply` |

**Secrets in configuration**
| Option | For | Against |
|---|---|---|
| **A. Write-only arguments plus a `*_wo_version` argument to trigger rotation; server-generated secrets not exposed** | Never written to plan or state; same pattern as the AWS provider | Needs Terraform 1.11+ or OpenTofu 1.11+ |
| B. `Sensitive` attributes | Works on any version | Values are still stored in state in clear text |

**Where the code lives**
| Option | For | Against |
|---|---|---|
| **A. Public Go client as a nested module in this repo (`github.com/alexandrosnt/certloom/client`); provider in its own repo `terraform-provider-certloom`** | Registries require the `terraform-provider-<name>` repo name; client versioned with the API it describes; the CLI can use the same client | Two repos to release |
| B. Provider in this repo | One repo | Cannot be published to the registries from here |
| C. Client generated from `api/openapi.yaml` | Stays in step with the spec | Extra build-time generator; generated code is harder to read and review. The existing route-parity test plus client tests against a real server give the same safety |

## Decision
Option A in all four cases.

**Client module (`client/`)**
- Own `go.mod`, standard library only, no imports from `internal/`. Request and response
  types are defined in the module, matching `api/openapi.yaml`.
- Bearer token auth, `Idempotency-Key` on create calls, `If-Match` with ETags on
  updates, retries only for idempotent requests and 429/503 with `Retry-After`.
- Errors carry the HTTP status and the problem detail from the API, so callers can tell
  not-found (resource deleted outside Terraform) from other failures.
- The CLI moves to this client over time; not a blocker for the provider.
- Versioned with tags `client/vX.Y.Z` as Go expects for nested modules.

**Provider (`terraform-provider-certloom`)**
- Provider block: `endpoint` and `token` (sensitive), both also from
  `CERTLOOM_ENDPOINT` and `CERTLOOM_TOKEN`; optional `ca_file` for a private CA.
  Provider configuration is not stored in state.
- Resources map one-to-one to API objects that have create, read and delete: team,
  scope, endpoint, template, issuer, issuer EAB key, DNS solver, channel, webhook,
  exception, policy (single object, versioned). Data sources for lookups (teams, scopes,
  issuers, agents).
- Secrets the user supplies (DNS solver credentials, EAB HMAC key, channel credentials)
  are write-only arguments with a matching `*_wo_version` number. Bumping the number
  sends the new value.
- Secrets the server generates (webhook signing secret, API tokens, agent enrollment
  tokens) are not exposed. Rotating or reading them stays in the CLI and UI.
- Import supported for every resource by ID.
- Prerequisite: the API gains `GET`, `PATCH` and `DELETE` by ID where they are missing
  (teams, scopes, endpoints, channels, issuers). `DELETE` returns 409 while other
  objects still reference the target, rather than cascading.
- Drift: `Read` refreshes from the API; a 404 removes the resource from state.

**Release**
- GoReleaser config from `hashicorp/terraform-provider-scaffolding-framework`, signed
  SHA256SUMS with a dedicated RSA GPG key kept only in CI secrets.
- Published to the Terraform Registry and the OpenTofu Registry.

## Industry practice (surveyed 2026-11-21)
| Who | Practice | Source |
|---|---|---|
| HashiCorp | Plugin Framework recommended for new providers; SDKv2 feature development mostly stopped | https://developer.hashicorp.com/terraform/plugin/framework-benefits |
| HashiCorp | Write-only arguments are never persisted to plan or state (Terraform 1.11+); pair with a version argument to detect changes | https://developer.hashicorp.com/terraform/plugin/framework/resources/write-only-arguments, https://www.hashicorp.com/blog/ephemeral-values-in-terraform |
| AWS provider | `password_wo` with `password_wo_version` for database passwords | https://developer.hashicorp.com/terraform/language/manage-sensitive-data/write-only |
| Venafi | Separate `terraform-provider-venafi` repo; certificate resource with keys, docs tell users to protect state | https://github.com/Venafi/terraform-provider-venafi/releases |
| DigiCert TLM | Provider tracks certificate data in state; sample writes keys to files | https://www.digicert.com/content/dam/digicert/pdfs/solution-brief/digicert-terraform-solution-brief-en.pdf, https://docs.digicert.com/en/trust-lifecycle-manager/automate-management-of-certificates/infrastructure-automation/terraform/digicert-terraform-provider-configuration.html |
| Vault provider | PKI resources keep private keys in state, a known complaint | https://discuss.hashicorp.com/t/using-vault-terraform-to-manage-root-ca-rotation/56681 |
| Vault | Public Go client as nested module `github.com/hashicorp/vault/api` | (known layout of the hashicorp/vault repo) |
| Terraform Registry | Repo named `terraform-provider-<name>`, GoReleaser, RSA/DSA GPG-signed SHA256SUMS | https://developer.hashicorp.com/terraform/registry/providers/publishing |
| OpenTofu Registry | Providers and signing keys added through issues on the registry repo | https://www.github.com/opentofu/registry |

Not found: Keyfactor and Smallstep provider details did not come up in the search.

## Consequences
- certloom avoids the main weakness of other certificate providers: state files never
  hold keys or secrets.
- Minimum Terraform 1.11 / OpenTofu 1.11 for resources with write-only arguments.
- Certificates are not created through Terraform; they come from deployments and
  renewals as before. Users who want Terraform-issued certificates use other providers.
- The API becomes a public contract for the client; breaking changes need a new API
  version.

## Verification
- Client unit tests with `httptest`, plus workflow tests against a real `certloomd` and
  Postgres.
- Provider acceptance tests (`terraform-plugin-testing`) in CI against `certloomd` in a
  container, running both `terraform` and `tofu`.
- A test that runs `apply`, then scans the state and plan JSON for every secret value
  used, and fails if any is found.
