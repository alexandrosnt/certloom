# Runbook: observing cloud certificate services

certloom can list certificates held by AWS Certificate Manager, AWS Private CA, Azure
Key Vault, Google Certificate Manager, Google CA Service and Cloudflare, and raise
findings when the service will not renew them in time (ADR-0024). Nothing in the
cloud is changed.

A `certloom-agent` does the reading. Run it where it can use the cloud's own identity:
an EC2 instance or ECS task with a role, an AKS or Azure VM with a managed identity, a
GKE workload or GCE VM with a service account. The control plane needs no cloud
access and holds no cloud credentials.

## 1. Agent configuration

Add a `cloud:` block to the agent config. One agent can read several accounts and
providers. An agent with only a `cloud:` block (no targets) accepts inventory tasks only.

```yaml
cloud:
  interval_seconds: 3600        # default; at least 300
  aws:
    - name: prod                # label, used in finding names
      regions: [us-east-1, eu-west-1]
      private_ca: true          # also list AWS Private CA authorities
      # assume_role_arn: arn:aws:iam::111122223333:role/certloom-read
      # external_id: ...
      # profile: ... / credentials_file: /etc/certloom-agent/aws-credentials
  azure:
    - name: corp
      vaults: [https://corp-tls.vault.azure.net]
      # tenant_id, client_id + client_certificate_file or client_secret_file
      # for a service principal instead of DefaultAzureCredential
  gcp:
    - name: shop
      project: shop-prod
      locations: [global, europe-west1]   # default [global]
      cas: true                 # also list CA Service authorities
      # credentials_file: /etc/certloom-agent/gcp-wif.json (service account key or WIF config)
  cloudflare:
    - name: main
      api_token_file: /etc/certloom-agent/cloudflare-token
      zones: [example.com]      # empty = every zone the token sees
      origin_ca: true           # also list Origin CA certificates
```

Credentials, in order of preference:
- **AWS**: the SDK default chain (instance or task role, IRSA, `AWS_*` environment,
  shared config). `assume_role_arn` reads other accounts through STS.
- **Azure**: `DefaultAzureCredential` (workload identity, managed identity, environment,
  Azure CLI).
- **Google**: Application Default Credentials (metadata server, workload identity
  federation file in `GOOGLE_APPLICATION_CREDENTIALS`).
- **Cloudflare**: an API token in a file readable only by the agent.

## 2. Permissions (read-only)

| Provider | Grant |
|---|---|
| AWS ACM | `acm:ListCertificates`, `acm:DescribeCertificate`, `acm:GetCertificate` |
| AWS Private CA | `acm-pca:ListCertificateAuthorities`, `acm-pca:GetCertificateAuthorityCertificate` |
| AWS cross-account | `sts:AssumeRole` on the role; the role holds the grants above |
| Azure Key Vault | Role **Key Vault Reader** on each vault (RBAC model). Do not use "Key Vault Certificate User": it can read the private keys through the secrets API |
| Google Certificate Manager | `roles/certificatemanager.viewer` |
| Google CA Service | `roles/privateca.auditor` |
| Cloudflare | Token with Zone - SSL and Certificates - Read, and Zone - Zone - Read if `zones` is empty |

A minimal AWS policy:

```json
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Resource": "*",
  "Action": ["acm:ListCertificates", "acm:DescribeCertificate", "acm:GetCertificate",
             "acm-pca:ListCertificateAuthorities", "acm-pca:GetCertificateAuthorityCertificate"]}]}
```

The agent never calls an API that returns a private key (ACM `ExportCertificate`, the
Key Vault secrets API). The grants above do not allow it either.

## 3. What is reported

`certloom agent observations <agent>` shows the last inventory. Certificates the service
returns are imported with source `aws_acm`, `aws_pca`, `azure_keyvault`,
`gcp_certmanager`, `gcp_cas` or `cloudflare_origin_ca` and get the usual expiry and key
checks. Cloudflare edge certificate packs are reported from their metadata only; the API
does not return the certificates.

Findings (subject `cloud_object`):

| Check | Raised when |
|---|---|
| `cloud_renewal_failing` | The service reports a failed issuance or renewal; validation has been pending for 3 days; or a certificate the service should renew expires within the critical window (default 7 days) |
| `cloud_renewal_manual` | A certificate the service does not renew (ACM imported, Key Vault without AutoRenew, Cloudflare custom) is inside the expiry window |
| `cloud_version_not_adopted` | A Key Vault certificate has a new version for more than 24 h, but a probed endpoint still serves the previous version |

The last check needs the endpoints that use the vault certificate to be probed
(`certloom endpoint add`).

A provider scope (account and region, vault, project and location, Cloudflare account)
that cannot be read is listed in the inventory's `errors`, and its findings stay open
until it can be read again.

## 4. Troubleshooting

- `AccessDeniedException` or `403` in the inventory errors: compare the identity's grants
  with section 2. For Azure, check that the vault uses the RBAC permission model, or give
  the identity "Get" and "List" on certificates in its access policy.
- Cloudflare `origin_ca` errors while packs work: the token may lack access to the Origin
  CA endpoint; leave `origin_ca` off or create a token that has it.
