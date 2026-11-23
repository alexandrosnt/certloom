# Monitor your certificates with OpenTofu

In about ten minutes you get alerts before any of your websites' certificates
expire or break. No agent, and you never have to open the web UI. Everything
is in a `.tf` file you can keep in git.

Tested on Debian 13 with OpenTofu 1.13. Terraform 1.11 or later works the same.

## 1. Install the server

```sh
# Add the certloom package repository
sudo apt-get install -y curl gpg
curl -fsSL https://alexandrosnt.github.io/certloom-packages/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/certloom.gpg
echo 'deb [signed-by=/usr/share/keyrings/certloom.gpg] https://alexandrosnt.github.io/certloom-packages/deb stable main' \
  | sudo tee /etc/apt/sources.list.d/certloom.list

# Install and set up
sudo apt-get update
sudo apt-get install -y certloomd
sudo certloomd setup
```

`setup` ends with something like:

```
certloom is running.
  Web UI and API: https://myhost:8443/

Sign in with this owner token (shown once, valid 24 hours):

  certloom_...
```

Copy the token.

## 2. Create a token for OpenTofu

The setup token expires after a day. Create one that lasts a year:

```sh
export CERTLOOM_SERVER=https://localhost:8443
export CERTLOOM_CA_FILE=/etc/certloom/tls/server.crt
export CERTLOOM_TOKEN=certloom_...        # the token from step 1

certloom token create opentofu --role owner --ttl 8760h
```

It prints the new token once. Keep it in your secret store, then point
OpenTofu at the server:

```sh
export CERTLOOM_ENDPOINT=https://localhost:8443
export CERTLOOM_CA_FILE=/etc/certloom/tls/server.crt
export CERTLOOM_TOKEN=certloom_...        # the new token
```

Running OpenTofu on another machine? Use the server's name instead of
`localhost` and copy `/etc/certloom/tls/server.crt` there.

## 3. Describe what to watch

Create `main.tf`:

```hcl
terraform {
  required_providers {
    certloom = { source = "alexandrosnt/certloom" }
  }
}

provider "certloom" {}   # reads CERTLOOM_ENDPOINT, CERTLOOM_TOKEN, CERTLOOM_CA_FILE

# Which hosts certloom may connect to. Nothing outside a scope is ever contacted.
resource "certloom_scope" "public" {
  name        = "public"
  allow_hosts = ["*.example.com", "example.com"]
  ports       = [443]
}

# The sites to watch.
locals {
  sites = ["example.com", "www.example.com", "shop.example.com"]
}

resource "certloom_endpoint" "site" {
  for_each = toset(local.sites)
  host     = each.value
  scope_id = certloom_scope.public.id
}

# Where alerts go: a webhook (Slack- or Teams-style relays, your own service...).
resource "certloom_channel" "ops" {
  name         = "ops"
  kind         = "webhook"
  config       = jsonencode({ url = "https://hooks.example.com/certloom" })
  min_severity = "warning"
}
```

Replace the hosts and the webhook URL with yours. For email alerts, see
`certloom_channel` in the provider documentation.

## 4. Apply

```sh
tofu init
tofu apply
```

certloom checks each site within a minute, then every 6 hours (set
`interval_seconds` on an endpoint to change it).

## 5. See what it found

```sh
certloom findings
```

```
SEVERITY  CHECK              SUBJECT                    MESSAGE
critical  expiry             endpoint ept_01m848bphdpx  expired 4242 days ago (2015-04-12T23:59:59Z)
critical  hostname_mismatch  endpoint ept_01m848bphdzg  certificate does not cover "wrong.host.badssl.com" (SANs: *.badssl.com, badssl.com)
```

(This output is from a test against badssl.com, a site with deliberately
broken certificates. Add `expired.badssl.com` to your list to try it.)

Other useful commands: `certloom status` (overview), `certloom endpoint list`,
`certloom endpoint show <id>`. Every command takes `-o json` for scripts.

## What it checks

Expiry (warning at 30 days, critical at 7 by default), hostname mismatch,
untrusted or incomplete chains, weak keys and signatures, and endpoints that
cannot be reached. Change the thresholds and escalation with the
`certloom_policy` resource.

## Next

- Renew certificates automatically on Linux with nginx: [linux-nginx.md](linux-nginx.md),
  or on Windows with IIS: [windows-iis.md](windows-iis.md)
- See cert-manager certificates from Kubernetes: [kubernetes.md](kubernetes.md)
- Watch AWS, Azure, Google Cloud or Cloudflare certificates, no agent needed: [cloud.md](cloud.md)
- Everything certloom can do: [overview.md](../overview.md)
