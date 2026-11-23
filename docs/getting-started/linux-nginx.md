# Renew certificates on Linux with nginx

certloom gets a Let's Encrypt certificate for your nginx site, installs it,
checks that the site really serves it, and renews it before it expires. If
anything goes wrong the old certificate stays in place.

This takes about fifteen minutes. Tested on Debian 13 with nginx 1.26;
Ubuntu 24.04 works the same.

## What you need

- A certloom server. If you do not have one yet, do step 1 of
  [Monitor with OpenTofu](opentofu.md) first.
- A Linux server running (or about to run) your website. In this guide it is
  called `www.example.com`; replace that name everywhere with yours.
- Network:
  - the web server can reach the certloom server on port **8444**;
  - Let's Encrypt can reach the web server on port **80** (that is how it
    checks you own the name);
  - the certloom server can reach the web server on port **443** (to check the
    new certificate is served).

There are two machines in this guide. Each step says where to run it.

## 1. Install nginx and the agent

**On the web server:**

```sh
# Add the certloom package repository
sudo apt-get install -y curl gpg
curl -fsSL https://alexandrosnt.github.io/certloom-packages/gpg.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/certloom.gpg
echo 'deb [signed-by=/usr/share/keyrings/certloom.gpg] https://alexandrosnt.github.io/certloom-packages/deb stable main' \
  | sudo tee /etc/apt/sources.list.d/certloom.list

sudo apt-get update
sudo apt-get install -y nginx certloom-agent
```

## 2. Give nginx a temporary certificate

nginx will not start an HTTPS site without a certificate, and the real one
does not exist yet. Make a throwaway one; certloom replaces it in step 6:

```sh
sudo mkdir -p /etc/certloom/placeholder /var/www/acme
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj /CN=placeholder \
  -keyout /etc/certloom/placeholder/privkey.pem \
  -out /etc/certloom/placeholder/fullchain.pem
sudo ln -sfn /etc/certloom/placeholder /etc/certloom/live/www
```

`/etc/certloom/live/www` is a link. nginx always reads the certificate through
it, and certloom switches the link to each new certificate in one step.

Already have a certificate for this site? Copy its two files into
`/etc/certloom/placeholder` under those names instead of running `openssl`.

## 3. Set up the nginx site

Create `/etc/nginx/sites-available/www`:

```nginx
server {
    listen 80;
    server_name www.example.com;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://$host$request_uri; }
}
server {
    listen 443 ssl;
    server_name www.example.com;
    ssl_certificate     /etc/certloom/live/www/fullchain.pem;
    ssl_certificate_key /etc/certloom/live/www/privkey.pem;
    root /var/www/html;
}
```

Turn it on:

```sh
sudo ln -s /etc/nginx/sites-available/www /etc/nginx/sites-enabled/www
sudo nginx -t && sudo systemctl reload nginx
```

If you already have a site, keep it as it is and only change two things: add
the `/.well-known/acme-challenge/` location to its port 80 server, and point
`ssl_certificate` and `ssl_certificate_key` at `/etc/certloom/live/www/`.

## 4. Configure the agent

Replace `/etc/certloom-agent/config.yaml` with:

```yaml
server: https://certloom.example.com:8444     # your certloom server, port 8444
state_dir: /var/lib/certloom-agent
name: web-01                                  # how this server shows up in certloom
targets:
  - name: www
    type: nginx
    live_link: /etc/certloom/live/www
    webroot: /var/www/acme
    test_command: [nginx, -t]
    reload_command: [systemctl, reload, nginx]
    verify_address: 127.0.0.1:443
    allowed_sans: [www.example.com]           # the only names this server may get certificates for
```

Check it:

```sh
sudo certloom-agent check-config
```

```
config OK
```

## 5. Connect the agent to certloom

**On the certloom server** (with `CERTLOOM_SERVER`, `CERTLOOM_CA_FILE` and
`CERTLOOM_TOKEN` set as in [step 2 of the OpenTofu guide](opentofu.md#2-create-a-token-for-opentofu)):

```sh
certloom agent token --name web-01
```

It prints a one-time token (valid for an hour) and the command to run:

```
certloomenr_...
One-time token (expires 2026-11-23 14:15). On the target host run:
  certloom-agent enroll --server https://certloom.example.com:8444 --ca-hash sha256:4778... --token-stdin
and paste the token below when prompted:
```

**On the web server**, run that command with `sudo`, paste the token, then
start the agent:

```sh
sudo certloom-agent enroll --server https://certloom.example.com:8444 --ca-hash sha256:4778... --token-stdin
sudo systemctl enable --now certloom-agent
```

**On the certloom server**, the agent now shows up:

```sh
certloom agent list
```

```
ID                              NAME    HEALTH  HOST             VERSION  TARGETS
agt_01m848s2sx6ym1s1bkst9dznnz  web-01  active  www.example.com  0.1.0    www
```

## 6. Get the certificate

**On the certloom server:**

```sh
# Let's Encrypt as the certificate authority
certloom issuer create letsencrypt \
  --directory https://acme-v02.api.letsencrypt.org/directory --agree-tos

# Allow certloom to check the site, and add it.
# Add --allow-private if www.example.com is an internal (10.x, 192.168.x) address.
certloom scope create web --allow-host www.example.com
certloom endpoint add www.example.com --scope web

# Tie it together: this certificate, on this server, from Let's Encrypt
certloom lineage create www
certloom deployment create --lineage www --agent web-01 --target www \
  --issuer letsencrypt --endpoint www.example.com --san www.example.com
```

The last command prints the deployment id. Get the first certificate now:

```sh
certloom deployment renew dep_...
certloom run show run_...
```

After about half a minute:

```
Run run_01m848sn9h5eantpvwwb95xn7s: VERIFIED (manual)
  ... planned        manual
  ... issuing        issue task sent to agent (attempt 1)
  ... issued         certificate c746e3f92a90a389 issued and recorded (checkpoint)
  ... deploying      deploy task sent to agent
  ... verifying      activated on target; verifying
  ... verified       verified locally by the agent and externally by the control plane
```

`verified` means the web server and the certloom server both saw the new
certificate on port 443. Your site now has a Let's Encrypt certificate.

Trying things out? Use Let's Encrypt's test service first, which has much
higher limits: `--directory https://acme-staging-v02.api.letsencrypt.org/directory`.
Its certificates are not trusted by browsers.

## 7. That's it

certloom renews the certificate by itself, about a month before it expires
(Let's Encrypt tells it the best time). See when:

```sh
certloom deployment list
```

```
ID                              TARGET  SANS             APPROVAL  RENEW AT          WHY
dep_01m848shajkmx1tp6fgffc60em  www     www.example.com  approved  2027-01-22 02:05  ARI window 2027-01-21T13:16:23Z - 2027-01-23T13:16:23Z
```

If a renewal fails, certloom retries, keeps the old certificate in place, and
alerts your channels (set them up as in the [OpenTofu guide](opentofu.md)).

## More names, more sites

- **More names on one certificate:** add them to `allowed_sans` in the agent
  config, restart the agent (`sudo systemctl restart certloom-agent`), and
  repeat `--san` in `deployment create`.
- **Another site on the same server:** add a second entry under `targets`
  with its own `name` and `live_link` (for example `/etc/certloom/live/shop`),
  then do steps 2, 3 and 6 for it.
- **Another server:** repeat this guide on it with a different `name`.

## If something goes wrong

| What you see | What to do |
|---|---|
| `certloom-agent enroll` cannot connect | The web server must reach the certloom server on port 8444. Check firewalls. |
| Run `failed` with `urn:ietf:params:acme:error:connection` or `unauthorized` | Let's Encrypt could not fetch `http://www.example.com/.well-known/acme-challenge/...`. Port 80 must be open and the name must point at this server. |
| Run `failed` with `rateLimited` | Too many certificates for this name this week. Wait, and use the staging directory while testing. |
| Run `rolled_back` with `external verification failed` | The certloom server could not reach port 443 of the site. The old certificate is back in place. A name that resolves to a private address (10.x, 172.16-31.x, 192.168.x) needs a scope created with `--allow-private` (step 6). |
| Run `rolled_back` for another reason | `nginx -t` failed or the site did not serve the new certificate. The old one is back in place. `certloom run show run_...` and `journalctl -u certloom-agent` on the web server show why. |
| `deployment create` says the SAN is not in `allowed_sans` | Add the name to `allowed_sans` in the agent config and restart the agent. |

More options (DNS validation and wildcards, other CAs, maintenance windows,
approvals): [runbooks/agent.md](../runbooks/agent.md).
