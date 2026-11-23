# ADR-0024: Read-only cloud certificate observation

**Status:** Accepted (2026-11-21). Amended by ADR-0034 (cloud accounts read by certloomd without an agent).

## Context
Many certificates never touch a host we manage. They live in AWS Certificate Manager
(ACM), AWS Private CA, Azure Key Vault, Google Certificate Manager and CA Service, and in
Cloudflare edge certificate packs and Origin CA. certloom should list them next to
everything else and raise findings when they are about to break, without changing
anything in the cloud. Issuing or deploying to these services is out of scope here and
will get its own ADR.

The open questions were where the cloud calls run, how they get credentials, and which
client libraries to use.

## Options considered
**Where the calls run**
| Option | For | Against |
|---|---|---|
| **A. `certloom-agent` in an observer mode, one config block per provider** | Same model as ADR-0023; outbound only; the agent can run inside the cloud account and use its ambient identity; control plane needs no cloud egress or cloud credentials | One more agent to run per cloud account or network |
| B. `certloomd` calls the clouds | No extra component | The self-hosted control plane would need cloud egress and would hold credentials for every account centrally (against ADR-0009 and ADR-0017) |
| C. Both | Flexible | Two code paths to secure and test |

**Credentials**
| Option | For | Against |
|---|---|---|
| **A. Ambient identity first (each SDK's default chain), static credentials only from files named in the agent config** | No long-lived secrets in the common case; matches DNS solvers (ADR-0017) | Static keys still possible where no workload identity exists |
| B. Also central credentials sealed to agents (ADR-0018 path) | One place to manage keys | More scope; not asked for yet. Can be added later without format changes |

**Client libraries**
| Option | For | Against |
|---|---|---|
| **A. By risk: official SDKs where signing and credential chains are hard (AWS, Azure), plain REST where auth is simple (Google with `golang.org/x/oauth2/google`, Cloudflare)** | Credential chains (IMDSv2, IRSA, SSO, managed identity, workload identity federation) stay with their owners; avoids gRPC and protobuf from the Google Cloud Go libraries | Our own small REST types for Google and Cloudflare |
| B. Official SDKs everywhere | Least own code | Pulls in gRPC, protobuf and many transitive modules for a few read calls |
| C. Own REST everywhere | Fewest dependencies | Re-implementing SigV4 and every credential chain is a security risk |

## Decision
Option A in all three cases.

**Agent mode**
- New optional agent config blocks `aws:`, `azure:`, `gcp:` and `cloudflare:`. They can
  be combined with each other and with `kubernetes:`. An agent that has only cloud
  and/or Kubernetes blocks gets the inventory-only capability allowlist (ADR-0023);
  an agent that also serves local targets keeps its normal capabilities and reports the
  cloud observations in the same inventory.
- Polling every hour by default (`interval_seconds`), at most every 5 minutes. Each
  provider is a separate section of the inventory result. When a provider, account,
  region or vault cannot be listed, the agent reports that scope as an error, and the
  control plane does not resolve findings of objects in that scope (same rule as
  ADR-0023).
- The agent never calls an API that returns private keys or secret values. The
  documented roles below exclude them, so a misconfigured agent still cannot read them.

**Credentials**
- AWS: the SDK default chain (environment, shared config/profile, web identity/IRSA,
  ECS and EC2 instance roles with IMDSv2). Optional `assume_role_arns` per account for
  multi-account discovery (STS AssumeRole with an external ID if set).
- Azure: `DefaultAzureCredential` (environment, workload identity, managed identity,
  Azure CLI). A client secret or certificate only through a file path.
- Google: Application Default Credentials via `golang.org/x/oauth2/google`
  (metadata server, workload identity federation config files, service account key
  file as last resort).
- Cloudflare: an API token read from a file (`api_token_file`), as for the DNS solver.

**Libraries**
- `github.com/aws/aws-sdk-go-v2` modules `config`, `service/acm`, `service/acmpca`,
  `service/sts`.
- `github.com/Azure/azure-sdk-for-go/sdk/azidentity` and
  `.../security/keyvault/azcertificates`.
- Google and Cloudflare: plain JSON over `net/http` against the stable REST APIs.

**What is read, and the least privilege needed**
| Provider | Calls | Permissions |
|---|---|---|
| AWS ACM | `ListCertificates` (with all key types in `Includes`; the default filter hides ECDSA and RSA larger than 2048), `DescribeCertificate`, `GetCertificate` (certificate and chain only) per configured region | `acm:ListCertificates`, `acm:DescribeCertificate`, `acm:GetCertificate` |
| AWS Private CA | `ListCertificateAuthorities`, `GetCertificateAuthorityCertificate` | `acm-pca:ListCertificateAuthorities`, `acm-pca:GetCertificateAuthorityCertificate` |
| Azure Key Vault | list certificates, list versions, get certificate (`cer` only) and its policy, per configured vault; never the secrets endpoint | Built-in role **Key Vault Reader** (metadata, no secret contents). Not "Key Vault Certificate User", which can read secrets |
| Google Certificate Manager | certificates, certificate maps and map entries, per project and location | `roles/certificatemanager.viewer` |
| Google CA Service | CA pools and certificate authorities | `roles/privateca.auditor` |
| Cloudflare | zones, certificate packs (`status=all`), custom certificates, Origin CA certificates per zone | Token with Zone - SSL and Certificates - Read (Origin CA scope confirmed during implementation) |

**Data**
- Certificates go into the inventory with sources `aws_acm`, `aws_pca`,
  `azure_keyvault`, `gcp_certmanager`, `gcp_cas`, `cloudflare_edge` and
  `cloudflare_origin_ca`, keyed by provider resource id (ARN, vault + name + version,
  resource name, zone + pack id).
- Where a service returns no PEM (for example some Cloudflare packs before
  activation), the object is stored from its metadata only, as in ADR-0023.
- Usage data the service returns is kept with the observation: ACM `InUseBy`,
  certificate map entries, Key Vault versions with their created and enabled state.

**Findings** (finding subject `cloud_object`, id `<agent>/<provider>/<resource id>`)
- `acm_renewal_ineligible`: an imported or otherwise not renewal-eligible ACM
  certificate that is in use and inside the expiry window.
- `acm_renewal_failed`: `RenewalSummary.RenewalStatus` is `FAILED` or stuck in
  `PENDING_VALIDATION` beyond a threshold.
- `cloud_ca_expiring`: a Private CA or CAS certificate authority inside its window.
- `kv_autorenew_off`: a Key Vault certificate inside the expiry window with no
  `AutoRenew` lifetime action.
- `kv_version_not_adopted`: a newer enabled version exists, but a probed endpoint that
  serves this certificate's name still presents the previous version after a grace
  period (default 24 h). This is the Event Grid correlation from the integration matrix,
  done by polling.
- `gcp_cert_not_active`: a managed Google certificate is not `ACTIVE`, or an
  authorization is failing.
- `cloudflare_pack_not_active`: a certificate pack is not `active` past a threshold.
- The usual expiry checks apply to every observed certificate. Origin CA certificates
  are marked not publicly trusted, so the trust checks treat them like a private CA.

## Industry practice (surveyed 2026-11-21)
| Who | Approach |
|---|---|
| [DigiCert Trust Lifecycle Manager](https://docs.digicert.com/en/trust-lifecycle-manager/build-your-inventory-and-ecosystem/connectors/cloud-services/amazon-web-services-aws.html) | AWS connector runs on an on-premises DigiCert sensor; credentials entered directly, from the AWS default credential chain on the sensor host, or from a PAM vault; organisation-wide discovery through a common member-account role; ACM import every 24 h by default ([permissions](https://docs.digicert.com/en/trust-lifecycle-manager/connectors/network-appliances-and-cloud-services/minimum-required-permissions-for-aws-unified-connectors.html)) |
| Keyfactor Universal Orchestrator ([AWS ACM](https://github.com/Keyfactor/aws-orchestrator), [Azure Key Vault](https://github.com/Keyfactor/azurekeyvault-windows-orchestrator)) | Extensions on an orchestrator host; AWS via the EC2 instance role or OIDC; Azure via a service principal with RBAC or access policies |
| [CyberArk / Venafi](https://www.cyberark.com/press/venafi-unveils-new-product-capabilities-to-help-organizations-prepare-for-a-multi-cloud-and-post-quantum-future/) | Native AWS, Azure and GCP integrations in the SaaS; credential model not publicly documented |
| [Azure Key Vault events](https://learn.microsoft.com/en-us/azure/event-grid/event-schema-key-vault) | `CertificateNearExpiry` 30 days before expiry and new-version events, push delivery only |
| [Azure Key Vault RBAC](https://learn.microsoft.com/azure/key-vault/general/rbac-guide) | Key Vault Reader reads metadata only; Key Vault Certificate User can also read secret contents |
| [Cloudflare certificate packs](https://developers.cloudflare.com/api/resources/ssl/subresources/certificate_packs/methods/list) | Listable with SSL and Certificates Read; [Origin CA list](https://developers.cloudflare.com/api/resources/origin_ca_certificates/methods/list/) accepts an Origin CA key or an API token |

Not found in the survey: how CyberArk's SaaS authenticates to customer clouds, and the
exact token permission for the Cloudflare Origin CA list endpoint.

## Consequences
- The agent binary grows by the AWS and Azure SDK modules. AWS v2 modules depend only on
  `smithy-go`; `azidentity` brings MSAL. Google Cloud Go libraries are not added.
- Push events (Azure Event Grid, AWS EventBridge) are not used. Detection is bounded by
  the polling interval; an Event Grid receiver on `certloomd` stays a possible later
  addition for installations where Azure can reach it.
- Static cloud keys, where used, live on the agent host only. Central delivery can be
  added later through the ADR-0018 mechanism.

## Verification
- Unit: each provider client against an `httptest` server shaped after the documented
  responses (pagination, throttling with `Retry-After`, partial failures reported as
  scope errors). The AWS and Azure SDK clients are pointed at the test server with
  their endpoint overrides.
- A test asserts the agent never requests a Key Vault `secrets` path or any AWS call
  outside the list in this ADR.
- Workflow: observations import into the inventory, finding rules, resolution, and no
  resolution for scopes reported as failed.
- Live runs are opt-in (`CERTLOOM_CLOUD_LIVE=aws,azure,gcp,cloudflare` with real
  read-only credentials) and are recorded in the integration matrix as such; until a
  live run is done the matrix says "mock API only".

## As built (2026-11-21)
- The provider blocks sit under one `cloud:` block (`cloud.aws`, `cloud.azure`,
  `cloud.gcp`, `cloud.cloudflare`, shared `interval_seconds`), each entry with a `name`.
- The agent normalises renewal state (`renewal`: `pending` or `failed`, with reason and
  since), so the findings are provider-independent: `cloud_renewal_failing` (covers the
  planned `acm_renewal_failed`, `gcp_cert_not_active`, `cloudflare_pack_not_active`, and
  a managed certificate inside the critical window that was not renewed),
  `cloud_renewal_manual` (covers `acm_renewal_ineligible` and `kv_autorenew_off`) and
  `cloud_version_not_adopted`. CA expiry is left to the normal certificate checks, so
  there is no `cloud_ca_expiring`.
- Finding subject ids are `<agent>/<provider>/<scope>/<resource id>`, so findings in a
  scope reported as failed are recognised by prefix.
- AWS Private CA uses the Smithy RPC v2 CBOR protocol in current SDKs; the test fake
  speaks it.
- Cloudflare: the certificate pack list with `status=all` includes custom
  certificates, so the separate custom certificates endpoint is not called. Origin CA
  listing is opt-in (`origin_ca: true`) because the token permission is unconfirmed.
- Key Vault: the SHA-256 of the two newest enabled versions is reported, which is
  enough to find endpoints still serving the previous one. The pending-operation call
  is skipped when the role is not allowed to read it.
- Origin CA certificates carry `not_publicly_trusted`; there is no separate trust
  check for imported certificates, so nothing else changes for them.
