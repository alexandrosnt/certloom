# What certloom does

certloom tells you about every TLS certificate you have before it causes an
outage, and can renew the ones on your own servers for you.

## The pieces

```
                          you
          OpenTofu / CLI / API / web UI (all optional, pick one)
                           |
                           v
   +-----------------------------------------------+
   | certloomd  (one server you install)           |      checks websites
   |  - list of all certificates                   | ---> and services over
   |  - checks and alerts (email, webhook)         |      the network
   |  - renewal schedule                           |      (no agent needed)
   +-----------------------------------------------+
                           ^
                           | only if you want automatic renewal
                           | or need to look inside a machine
                           v
   certloom-agent  on a server, in Kubernetes, or in a cloud account
```

| Piece | What it is | Do you need it? |
|---|---|---|
| **certloomd** | The server. Keeps the list of certificates, checks them, sends alerts, plans renewals. | Yes, one. |
| **OpenTofu / Terraform provider** | Describe what to watch and where alerts go in `.tf` files. | Optional. Same for the CLI and the web UI: use whichever you like. |
| **certloom-agent** | Small program on a machine. Renews and installs certificates there, and reports what it finds on disk, in Kubernetes or in a cloud account. | Only for renewal or for looking inside a machine. |

## What you can do, and what it needs

| You want to... | Agent? | Guide |
|---|---|---|
| Be warned before any website or service certificate expires, is for the wrong name, uses a weak key or comes from an untrusted CA | No | [Monitor with OpenTofu](getting-started/opentofu.md) |
| Keep an inventory of certificate files you already have | No | `certloom inventory import` |
| Renew and install certificates on Linux with nginx (Let's Encrypt or any ACME CA) | Yes, on that server | [Linux and nginx](getting-started/linux-nginx.md) |
| The same on Windows with IIS | Yes | [runbooks/windows-iis.md](runbooks/windows-iis.md) |
| See cert-manager certificates in Kubernetes | Yes, in the cluster | [runbooks/kubernetes.md](runbooks/kubernetes.md) |
| See certificates in AWS, Azure, Google Cloud or Cloudflare | Yes, in the cloud account | [runbooks/cloud.md](runbooks/cloud.md) |
| Push your own root CAs to servers' trust stores | Yes | [runbooks/trust-bundles.md](runbooks/trust-bundles.md) |

## Why renewal needs an agent

A certificate is only useful with its private key, and certloom never lets
private keys travel. The agent creates the key on the machine that uses it,
asks the CA for the certificate, installs it, checks the site really serves
it, and rolls back if anything fails. The server only ever sees public
certificates. That also means a stolen certloom server cannot impersonate
your websites.

## Install the server

On Debian 13 or Ubuntu 24.04:

```sh
sudo apt-get install certloomd     # after adding the repository, see below
sudo certloomd setup
```

`setup` prints the address and a sign-in token. Adding the repository takes
three commands: [runbooks/install-packages.md](runbooks/install-packages.md).
With Docker instead: [deploy/compose/README.md](../deploy/compose/README.md).

Next: [monitor your first sites with OpenTofu](getting-started/opentofu.md).
