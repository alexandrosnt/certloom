# See certificates in AWS, Azure, Google Cloud and Cloudflare

certloom lists the certificates your cloud services hold, next to all your
other certificates, and warns before one expires or when the cloud cannot
renew it: an imported ACM certificate nobody renews, a Key Vault certificate
without auto-renewal, a managed certificate stuck in validation.

The certloom server reads the clouds itself. No agent, nothing to install in
the cloud, and nothing in the cloud is ever changed: certloom only needs
read access.

Supported: AWS Certificate Manager and AWS Private CA, Azure Key Vault,
Google Certificate Manager and CA Service, Cloudflare edge and Origin CA
certificates.

Tested with OpenTofu 1.13 against an AWS emulator (moto) through the real AWS
SDK. The certloom side of Azure, Google and Cloudflare was tested against fakes
of their APIs; the permission names below come from each provider's
documentation.

## What you need

- A certloom server, with OpenTofu set up as in the
  [OpenTofu guide](opentofu.md) (steps 1 and 2).
- The certloom server can reach the provider's API over HTTPS
  (`*.amazonaws.com`, `*.vault.azure.net` and `login.microsoftonline.com`,
  `*.googleapis.com`, `api.cloudflare.com`).

## 1. Give certloom read access

Pick the line for your cloud. Two ways to give access:

- **Use the server's own cloud identity (best).** If the certloom server runs
  in that cloud, give its instance role, managed identity or service account
  the permission below. certloom then stores no secret at all.
- **A read-only key.** Create one with only the permission below, and give it
  to certloom in step 2. certloom keeps it encrypted and never shows it again.

| Cloud | Read-only permission |
|---|---|
| AWS | The policy below (ACM and Private CA read calls only) |
| Azure | Role **Key Vault Reader** on each vault. Not "Key Vault Certificate User", which can read private keys |
| Google Cloud | `roles/certificatemanager.viewer` (and `roles/privateca.auditor` for CA Service) |
| Cloudflare | API token with **Zone - SSL and Certificates - Read** (and **Zone - Zone - Read** to see every zone) |

For AWS, with the AWS CLI:

```sh
cat > certloom-read.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Resource": "*",
    "Action": [
      "acm:ListCertificates", "acm:DescribeCertificate", "acm:GetCertificate",
      "acm-pca:ListCertificateAuthorities", "acm-pca:GetCertificateAuthorityCertificate"
    ]
  }]
}
EOF
aws iam create-user --user-name certloom-read
aws iam put-user-policy --user-name certloom-read --policy-name certloom-read --policy-document file://certloom-read.json
aws iam create-access-key --user-name certloom-read
```

The last command prints an `AccessKeyId` and a `SecretAccessKey`. (With the
server's own role instead, attach the same policy to that role and skip the
key.)

## 2. Describe the accounts in OpenTofu

Add to your `main.tf` the blocks for the clouds you use:

```hcl
variable "aws_secret_access_key" {
  type      = string
  sensitive = true
  ephemeral = true   # never written to the plan or state
}

# AWS with a read-only key
resource "certloom_cloud_account" "aws_prod" {
  name       = "aws-prod"
  credential = "stored"
  aws = {
    regions = ["us-east-1", "eu-west-1"]
  }
  secret_wo = jsonencode({
    access_key_id     = "AKIA..."
    secret_access_key = var.aws_secret_access_key
  })
  secret_wo_version = 1   # raise it to send a new key
}

# AWS through the server's own role: no credential, no secret
resource "certloom_cloud_account" "aws_shared" {
  name = "aws-shared"
  aws = {
    regions         = ["us-east-1"]
    assume_role_arn = "arn:aws:iam::111122223333:role/certloom-read"   # optional: another account
  }
}

# Azure Key Vault with a service principal
resource "certloom_cloud_account" "azure" {
  name       = "azure-corp"
  credential = "stored"
  azure = {
    vaults    = ["https://corp-tls.vault.azure.net"]
    tenant_id = "00000000-0000-0000-0000-000000000000"
    client_id = "11111111-1111-1111-1111-111111111111"
  }
  secret_wo         = jsonencode({ client_secret = var.azure_client_secret })
  secret_wo_version = 1
}

# Google Cloud with a service account key file
resource "certloom_cloud_account" "gcp" {
  name       = "gcp-shop"
  credential = "stored"
  gcp = {
    project = "shop-prod"
  }
  secret_wo         = jsonencode({ service_account_key = file("gcp-key.json") })
  secret_wo_version = 1
}

# Cloudflare with an API token
resource "certloom_cloud_account" "cloudflare" {
  name       = "cloudflare"
  credential = "stored"
  cloudflare = {
    zones     = ["example.com"]
    origin_ca = true
  }
  secret_wo         = jsonencode({ api_token = var.cloudflare_token })
  secret_wo_version = 1
}
```

Declare `azure_client_secret` and `cloudflare_token` like
`aws_secret_access_key`. Pass the secrets as environment variables so they
are not in any file:

```sh
export TF_VAR_aws_secret_access_key=...
tofu apply
```

`secret_wo` is write-only: OpenTofu sends it once and never stores it in the
plan or the state. Needs OpenTofu 1.11 or Terraform 1.11 or later.

## 3. See what certloom found

The first scan starts right away; after that, every hour.

```sh
certloom cloud-account show aws-prod
```

```
Scanned 2026-11-23 14:04

Cloud certificates
PROVIDER  SCOPE               NAME              NAMES             NOT_AFTER             STATUS  RENEWAL
aws_acm   aws-prod/us-east-1  api.example.com   api.example.com   2026-12-13T13:59:21Z  ISSUED  -
aws_acm   aws-prod/us-east-1  shop.example.com  shop.example.com  2026-11-28T14:01:10Z  ISSUED  -
```

```sh
certloom findings
```

```
SEVERITY  CHECK                 SUBJECT                        MESSAGE
critical  cloud_renewal_manual  cloud_object cla_01m84b8vddd3  ACM certificate arn:aws:acm:us-east-1:...:certificate/1e35... expires in 4 days and is not renewed by the service
```

The certificates also appear in `certloom inventory list` (source `aws_acm`,
`azure_keyvault`, `gcp_certmanager` and so on) and get the same expiry and key
checks as everything else. Alerts go to the channels you set up in the
OpenTofu guide.

To scan again now: `certloom cloud-account scan aws-prod`.

## What certloom warns about

| Check | When |
|---|---|
| `cloud_renewal_manual` | A certificate the cloud does not renew by itself (imported into ACM, Key Vault without auto-renewal, a Cloudflare custom certificate) is about to expire |
| `cloud_renewal_failing` | The cloud reports a failed renewal, validation has been pending for 3 days, or a certificate it should renew expires within 7 days |
| `cloud_version_not_adopted` | Key Vault has a new version of a certificate, but a site certloom checks still serves the old one after a day |
| `expiry` and the other certificate checks | As for any certificate |

## Without OpenTofu

The same with the CLI:

```sh
echo "$SECRET_ACCESS_KEY" | certloom cloud-account create aws-prod --provider aws \
  --region us-east-1 --region eu-west-1 --access-key-id AKIA... --secret-stdin
certloom cloud-account create aws-shared --provider aws --region us-east-1   # the server's own role
certloom cloud-account list
```

`certloom cloud-account create --help` shows the options for every cloud.

## If something goes wrong

`certloom cloud-account show NAME` lists what could not be read, with the
cloud's error, under "not read". Findings of a part that could not be read
stay open until it can be read again.

| What you see | What to do |
|---|---|
| `AccessDenied`, `403` or `AuthorizationFailed` | The key or identity lacks the permission from step 1. |
| Azure `Forbidden` although the role is assigned | The vault uses access policies instead of RBAC. Give the identity Get and List on certificates in the vault's access policy, or switch the vault to RBAC. |
| `policy cloud.centralCredentials is forbidden` | Your policy forbids storing cloud secrets in certloom. Use the server's own identity (`credential = "ambient"`) or an [agent](../runbooks/cloud.md). |
| A timeout | The server cannot reach the provider's API. Check its outbound firewall and proxy (`HTTPS_PROXY` in `/etc/certloom/certloomd.env`). |

Prefer to keep cloud access off the certloom server entirely? An agent inside
the cloud can read the same accounts: [runbooks/cloud.md](../runbooks/cloud.md).
