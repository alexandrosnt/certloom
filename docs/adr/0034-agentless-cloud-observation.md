# ADR-0034: Cloud observation without an agent

**Status:** Accepted (2026-11-23). Amends ADR-0024.

## Context
ADR-0024 reads cloud certificate services (AWS Certificate Manager and Private
CA, Azure Key Vault, Google Certificate Manager and CA Service, Cloudflare)
only through an agent. It rejected calls from `certloomd` because the control
plane would then need cloud egress and would hold cloud credentials.

In practice that made the simplest case the hardest: to see the certificates
in one AWS account, a user had to run and enroll an agent somewhere, even when
`certloomd` itself runs in that cloud with an instance role. Users asked for a
setup that needs no agent and can be described entirely in OpenTofu.

## Options considered
| Option | For | Against |
|---|---|---|
| A. Agent only (ADR-0024 as is) | Credentials and egress stay off the control plane | An extra component for the most common case; no pure-OpenTofu setup |
| **B. Also let `certloomd` read cloud accounts itself, configured through the API** | No agent; one resource in OpenTofu; uses `certloomd`'s own cloud identity where it has one | The control plane needs egress to the provider APIs and may hold credentials |
| C. Move cloud observation to `certloomd` only | One code path | Breaks hosts that cannot reach the providers, and the per-account isolation some users want |

## Decision
Option B. The agent path stays unchanged; a "cloud account" is a second way to
run the same collectors.

- The collectors move from the agent into `internal/cloudobs`, used by both.
  Same read-only calls, same least-privilege roles as ADR-0024, same inventory
  sources and findings. Findings of an account use the account id where an
  agent uses its id (`cla_.../aws_acm/<scope>/<arn>`).
- `certloomd` scans each account on its interval (default 1 hour, at least
  5 minutes). The elected scheduler (ADR-0033) queues a `cloud_scan` job; any
  replica runs it. A scan is bounded to 75 seconds to stay within the job
  lease; scopes that do not finish are reported as errors, and their findings
  are kept, as for agents.
- Credentials: `ambient` (the default) uses `certloomd`'s own identity through
  each SDK's default chain: instance or task roles, IRSA, workload identity,
  managed identity, Application Default Credentials. `stored` keeps a secret
  encrypted with the KEK, bound to the account id, never returned by the API,
  and audited when set or replaced: an AWS access key, an Azure service
  principal secret, a Google service account key, a Cloudflare API token.
  AWS accounts can also assume a role with an external id.
- Policy `cloud.centralCredentials: forbidden` stops `certloomd` from storing
  or using cloud secrets; ambient accounts and agents keep working.
- New permission `cloud:manage`, owner only by default.
- API `/api/v1/cloud-accounts`, CLI `certloom cloud-account`, OpenTofu resource
  `certloom_cloud_account` with typed `aws`, `azure`, `gcp` and `cloudflare`
  blocks and the secret as a write-only argument.

**What the API may not set.** Unlike an agent's config file, account settings
come from API callers, so they are limited to the documented fields and
unknown keys are refused:

- no file paths (credentials files, token files), which would let a caller make
  `certloomd` read its own secrets, such as the KEK;
- no endpoint overrides, which would send cloud tokens to a host the caller
  picks; Key Vault URLs must be on a Key Vault domain;
- stored Google credentials must be service account keys: external account
  configurations can name local files and token URLs.

Host-level settings of `certloomd` (environment such as `AWS_ENDPOINT_URL`,
proxies, VPC endpoints) still apply, because only the operator sets them.

## Industry practice (surveyed 2026-11-23)
| Who | Approach |
|---|---|
| [DigiCert Trust Lifecycle Manager](https://docs.digicert.com/en/trust-lifecycle-manager/build-your-inventory-and-ecosystem/connectors/cloud-services/amazon-web-services-aws.html) | AWS connector configured in the platform; access key and secret typed in on the connector page or taken from a PAM vault; one common member-account role across an AWS organization; discovery runs on a DigiCert sensor ([permissions](https://docs.digicert.com/en/trust-lifecycle-manager/connectors/network-appliances-and-cloud-services/minimum-required-permissions-for-aws-unified-connectors.html)) |
| [Keyfactor Command](https://www.keyfactor.com/resources/certificate-automation-with-aws-azure-key-vault/) | AWS ACM and Azure Key Vault through Universal Orchestrator extensions; store credentials are kept in Command |
| [Prowler](https://docs.prowler.com/user-guide/providers/aws/authentication.md) | Scans from one place with the default credential chain or STS AssumeRole into each account; external id required for its scan role ([ACM expiry check](https://hub.prowler.com/check/acm_certificates_expiration_check)) |
| [Steampipe](https://hub.steampipe.io/plugins/turbot/aws/tables/aws_acm_certificate), [CloudQuery](https://www.cloudquery.io/blog/list-expired-ssl-certificates-aws) | Central collectors that read ACM with the default credential chain and query expiry |
| [External id for cross-account roles](https://slaw.securosis.com/p/the-secure-way-to-integrate-cloudsec-tools-using-external-ids-cspm-lab-1) | Standard guard against the confused-deputy problem when a central tool assumes customer roles |

Central collection with ambient identity or an assumed role, and stored keys as
the fallback, is the common pattern. Not found: how CyberArk's (Venafi) SaaS
authenticates to customer clouds.

## Consequences
- `certloomd` needs outbound HTTPS to the provider APIs for the accounts that
  are configured, and nothing otherwise. Air-gapped installs are unaffected.
- A compromised control plane with stored secrets can read certificate metadata
  in those accounts. The documented roles exclude private keys and secret
  values, so it cannot read those. Ambient identity or agents avoid stored
  secrets entirely; the policy switch enforces that.
- Very large accounts (thousands of certificates in many regions) may not
  finish in 75 seconds; split them into several accounts or use an agent.
- Agents' `certloom agent observations` now also prints cloud objects.

## Verification
- Workflow tests (fake provider APIs behind the real collectors): a Cloudflare
  account with a stored token (the token never appears in API output, findings
  under the account id, deletion resolves them), Azure and Google through the
  same server path, and the refused settings above.
- OpenTofu acceptance test in the provider: an ambient AWS account updated in
  place, a stored Cloudflare token rotated without reaching plan or state,
  import.
- End to end: `certloomd` from the deb package with a stored AWS key against
  moto (an AWS emulator) through the real AWS SDK; the imported ACM
  certificate reached the inventory and raised `cloud_renewal_manual`.
- No run against a real cloud account yet; the integration matrix says so.
