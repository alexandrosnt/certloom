# Renew certificates on Windows with IIS

certloom gets a Let's Encrypt certificate for your IIS site, binds it,
checks that the site really serves it, and renews it before it expires. If
anything goes wrong the old certificate stays bound. IIS is never restarted.

This takes about fifteen minutes. Tested on Windows Server 2025 with IIS 10;
Windows Server 2016 and later work the same.

## What you need

- A certloom server. If you do not have one yet, do step 1 of
  [Monitor with OpenTofu](opentofu.md) first.
- A Windows server with IIS and the site you want a certificate for. In this
  guide the site is called `Shop` and its name is `shop.example.com`; replace
  both everywhere with yours.
- Network:
  - the IIS server can reach the certloom server on port **8444**;
  - Let's Encrypt can reach the IIS server on port **80** (that is how it
    checks you own the name);
  - the certloom server can reach the IIS server on port **443** (to check the
    new certificate is served).

Run every PowerShell command in this guide **as Administrator**.

## 1. Install the agent

Download `certloom-agent_<version>_windows_amd64.zip` from the
[latest release](https://github.com/alexandrosnt/certloom/releases) and
unpack it:

```powershell
$v = "0.1.0-rc.2"     # the version you downloaded
Expand-Archive "$HOME\Downloads\certloom-agent_${v}_windows_amd64.zip" "C:\Program Files\certloom-agent"
$env:Path += ";C:\Program Files\certloom-agent"
```

## 2. Check the IIS bindings

The site needs an http binding on port 80 (for the Let's Encrypt check) and
an https binding on port 443, both for `shop.example.com`. If it has them
already, skip to step 3. Otherwise:

```powershell
Import-Module WebAdministration
New-WebBinding -Name Shop -Protocol http  -Port 80  -HostHeader shop.example.com
New-WebBinding -Name Shop -Protocol https -Port 443 -HostHeader shop.example.com -SslFlags 1
```

(`-SslFlags 1` turns on SNI, so several https sites can share port 443.)

The https binding does not need a certificate yet; certloom adds it.

## 3. Configure the agent

Create `C:\ProgramData\certloom-agent\config.yaml`:

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\certloom-agent
notepad C:\ProgramData\certloom-agent\config.yaml
```

```yaml
server: https://certloom.example.com:8444     # your certloom server, port 8444
state_dir: C:\ProgramData\certloom-agent\state
name: iis-01                                  # how this server shows up in certloom
targets:
  - name: shop
    type: iis
    site: Shop                                # the site name in IIS Manager
    bindings: ["*:443:shop.example.com"]      # the https binding(s) to manage
    webroot: C:\inetpub\shop                  # the site's physical path
    allowed_sans: [shop.example.com]          # the only names this server may get certificates for
```

A binding is written the way IIS shows it: `IP:port:host name`, with `*` for
all addresses. `Get-WebBinding -Name Shop` lists them.

Check the file:

```powershell
certloom-agent check-config
```

```
config OK
```

## 4. Connect the agent to certloom

**On the certloom server** (with `CERTLOOM_SERVER`, `CERTLOOM_CA_FILE` and
`CERTLOOM_TOKEN` set as in [step 2 of the OpenTofu guide](opentofu.md#2-create-a-token-for-opentofu)):

```sh
certloom agent token --name iis-01
```

It prints a one-time token (valid for an hour) and the command to run:

```
certloomenr_...
One-time token (expires 2026-11-23 14:15). On the target host run:
  certloom-agent enroll --server https://certloom.example.com:8444 --ca-hash sha256:4778... --token-stdin
and paste the token below when prompted:
```

**On the IIS server**, run that command, paste the token, then install and
start the service:

```powershell
certloom-agent enroll --server https://certloom.example.com:8444 --ca-hash sha256:4778... --token-stdin
certloom-agent service install
sc.exe start certloom-agent
```

The service runs as LocalSystem, starts with Windows and restarts after a
crash. Its log is `C:\ProgramData\certloom-agent\agent.log`.

**On the certloom server**, `certloom agent list` now shows `iis-01` as
`active` with the target `shop`.

## 5. Get the certificate

**On the certloom server:**

```sh
# Let's Encrypt as the certificate authority (skip if you created it before)
certloom issuer create letsencrypt \
  --directory https://acme-v02.api.letsencrypt.org/directory --agree-tos

# Allow certloom to check the site, and add it.
# Add --allow-private if shop.example.com is an internal (10.x, 192.168.x) address.
certloom scope create shop --allow-host shop.example.com
certloom endpoint add shop.example.com --scope shop

# Tie it together: this certificate, on this server, from Let's Encrypt
certloom lineage create shop
certloom deployment create --lineage shop --agent iis-01 --target shop \
  --issuer letsencrypt --endpoint shop.example.com --san shop.example.com
```

The last command prints the deployment id. Get the first certificate now:

```sh
certloom deployment renew dep_...
certloom run show run_...
```

After about half a minute the run is `VERIFIED`: the IIS server and the
certloom server both saw the new certificate on port 443. In IIS Manager the
binding now shows a certificate named `certloom:shop:run_...`.

Trying things out? Use Let's Encrypt's test service first, which has much
higher limits: `--directory https://acme-staging-v02.api.letsencrypt.org/directory`.
Its certificates are not trusted by browsers.

## 6. That's it

certloom renews the certificate by itself, about a month before it expires.
`certloom deployment list` shows when. Each renewal makes a new key in the
Windows machine key store (it cannot be exported), adds the certificate to
`LocalMachine\WebHosting`, switches the binding, and deletes certloom's older
certificates except the previous one, which it keeps for a rollback.
Certificates certloom did not create are never touched.

If someone rebinds the site to another certificate in IIS Manager, certloom
reports it within 15 minutes (`certloom findings`, check `iis_binding_drift`).

## If something goes wrong

| What you see | What to do |
|---|---|
| `certloom-agent enroll` cannot connect | The IIS server must reach the certloom server on port 8444. Check firewalls. |
| Run `failed` with `urn:ietf:params:acme:error:connection` or `unauthorized` | Let's Encrypt could not fetch `http://shop.example.com/.well-known/acme-challenge/...`. Port 80 must be open, the name must point at this server, and the site needs the http binding from step 2. |
| Run `failed` with `rateLimited` | Too many certificates for this name this week. Wait, and use the staging directory while testing. |
| Run `rolled_back` with `external verification failed` | The certloom server could not reach port 443 of the site. The old binding is back. A name that resolves to a private address needs a scope created with `--allow-private` (step 5). |
| Run `rolled_back` for another reason | `certloom run show run_...` and `C:\ProgramData\certloom-agent\agent.log` show why. The previous binding is back in place. |
| The site was renewed by win-acme before | Stop win-acme's renewal for it (`wacs --cancel --id <id>`) so the two do not fight over the binding. `certloom agent observations iis-01` lists win-acme renewals it found. |

Remove the agent with `certloom-agent service uninstall`. Keys and
certificates stay in place, since IIS may still use them.

More options (DNS validation, other CAs, maintenance windows, approvals):
[runbooks/windows-iis.md](../runbooks/windows-iis.md) and
[runbooks/agent.md](../runbooks/agent.md).
