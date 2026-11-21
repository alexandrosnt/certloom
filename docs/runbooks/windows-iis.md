# Runbook: certloom-agent on Windows with IIS

The Windows agent renews certificates for IIS sites (ADR-0022). Keys are created in the
machine key store and cannot be exported; certificates go into `LocalMachine\WebHosting`
(`My` on IIS 7.5); bindings are switched in HTTP.sys without restarting IIS.
Enrollment, approvals, issuers and DNS-01 work as on Linux (see [agent.md](agent.md)).

Supported: Windows Server 2016 or later, IIS 8.5 or later, bindings by IP:port or with
SNI. Not managed: Central Certificate Store bindings (reported only) and creating new
bindings.

## 1. Install

Copy `certloom-agent.exe` to `C:\Program Files\certloom-agent\` and create
`C:\ProgramData\certloom-agent\config.yaml`:

```yaml
server: https://certloom.example.com:8444
state_dir: C:\ProgramData\certloom-agent\state
name: iis-01
targets:
  - name: shop
    type: iis
    site: Shop                       # IIS site name
    bindings:                        # https bindings to manage, as IIS lists them
      - "*:443:shop.example.com"
      - "10.0.0.5:443:"
    webroot: C:\inetpub\shop         # HTTP-01; omit for DNS-01
    allowed_sans: [shop.example.com]
```

The bindings must exist in IIS before the first renewal. `certloom-agent check-config`
validates the file.

In an elevated prompt:

```powershell
certloom-agent enroll --ca-hash sha256:...       # paste the token from `certloom agent token`
certloom-agent service install
sc.exe start certloom-agent
```

The service runs as LocalSystem (HTTP.sys configuration and machine keys need it) and
restarts after a crash. Logs go to `C:\ProgramData\certloom-agent\agent.log`. The state
directory is restricted to SYSTEM and Administrators.

## 2. Wire up renewal

```sh
certloom deployment create --lineage shop --agent iis-01 --target shop --issuer letsencrypt --san shop.example.com
```

The site and bindings are part of the approved spec: adding a binding to the agent
config sends the deployment back for approval where approvals are required.

For HTTP-01 the agent writes the challenge file and a `web.config` into
`<webroot>\.well-known\acme-challenge` so IIS serves the extensionless file as text.
Port 80 must reach the site.

## 3. What a renewal does

1. A new non-exportable key `certloom-<target>-<run>` is created; the CSR is signed in CNG.
2. The certificate is added to the store, linked to the key, with the friendly name
   `certloom:<target>:<run>`; intermediates go to `LocalMachine\CA`.
3. For each configured binding the HTTP.sys entry is pointed at the new certificate.
   Other settings of the entry (client certificates, revocation, TLS flags) are kept.
   The entry is read back; if any binding fails, all are restored.
4. Verify: a TLS handshake to each binding (SNI = binding host) must serve the new
   certificate, otherwise the run rolls back.
5. Older certloom certificates and keys of the target are removed; the previous one is
   kept for rollback. Certificates certloom did not create are never touched.

## 4. Binding drift

IIS agents report every https binding every 15 minutes. A finding `iis_binding_drift`
opens on the deployment when a managed binding:

- serves another certificate than the deployment's current one (someone rebound it in
  IIS Manager, or another ACME client renewed it): warning;
- has no HTTP.sys entry, or its certificate is missing from the store: critical;
- was removed from the site: warning.

`certloom agent observations iis-01` shows the bindings with their thumbprints. Deployments
with a renewal in progress are not checked.

## 5. win-acme

If win-acme is installed, its renewal files (`%ProgramData%\win-acme\*\*.renewal.json`)
are listed read-only in `certloom agent observations`: id, hosts, plugins, last result.
certloom never changes win-acme files or its scheduled task. Before moving a site to
certloom, disable its win-acme renewal (`wacs --cancel --id <id>`) so the two do not
fight over the binding.

## Uninstall

```powershell
certloom-agent service uninstall
```

Keys and certificates created by certloom stay in place (IIS may still use them).
