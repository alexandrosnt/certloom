# ADR-0022: Windows agent, IIS / HTTP.sys bindings and win-acme discovery

**Status:** Accepted (2026-11-21)

## Context
Windows Server with IIS is the second most common TLS endpoint after Linux web servers.
On Windows the private key normally lives in the machine key store (CNG), the
certificate in a system store (`WebHosting` on IIS 8+, otherwise `My`), and the binding
in two places:
- `applicationHost.config` holds the site binding (`https`, `ip:port:host`) and its
  `sslFlags` (SNI, Central Certificate Store);
- HTTP.sys holds the certificate hash and store per `ip:port` or `host:port`
  (`HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\SslBindingInfo`).

The two can disagree. Known failure modes: a renewal adds the new certificate but the
binding keeps pointing at the old thumbprint, and changing `sslFlags` clears the
certificate hash of a binding.

ADR-0005 says keys are generated where they are used. ADR-0004 says agents dial out.

## Options considered
**Key custody**
| Option | For | Against |
|---|---|---|
| **A. CNG key created non-exportable in the machine key store; CSR signed through CNG** | Key material never in the agent process; same model as Keyfactor re-enrollment and certreq | Own small `ncrypt.dll` bindings (no Go library covers CNG key creation) |
| B. Key generated in Go, imported as PKCS#12 with no export flag (win-acme) | Simple | Key sits in agent memory and in a PFX buffer for a moment |

**Binding changes**
| Option | For | Against |
|---|---|---|
| **A. HTTP.sys API from Go for certificate bindings; `appcmd` (ships with IIS) for site configuration; both read back** | No PowerShell; supported interfaces; drift is visible because both sides are read | Two interfaces to keep consistent |
| B. PowerShell `IISAdministration` cmdlets as a subprocess (Keyfactor uses PowerShell over WinRM) | High-level API | Slow start, execution policy, parsing text output |

**Install:** `certloom-agent service install|uninstall` now; a signed MSI with the M8
release work. A WiX MSI now would be unsigned anyway.

## Decision
Key custody A, bindings A, install via the service command.

**Agent on Windows**
- Same binary and protocol as on Linux (`windows/amd64`, `windows/arm64`). Runs as a
  Windows service as `LocalSystem`, which HTTP.sys configuration and the machine key
  store require. State in `%ProgramData%\certloom-agent`, ACL limited to `SYSTEM` and
  `Administrators`.

**Keys and certificates**
- On each renewal a new key is created with the Microsoft Software Key Storage Provider,
  machine scope, export policy none, named `certloom-<deployment>-<random>`. Algorithms
  as in the approved spec (ECDSA P-256/P-384, RSA 2048/3072/4096).
- The issued certificate is added to `LocalMachine\WebHosting` (`My` where `WebHosting`
  does not exist) and linked to its key. The previous certificate stays for rollback;
  older generations created by certloom are removed after a successful verify, others
  are never touched.
- TPM (Platform Crypto Provider) is a later option; the key reference already records
  custody `os_store` and exportable false.

**Target type `iis`**
- Target name is the IIS site name. The deployment attribute `bindings` lists the
  `ip:port:host` entries to manage; it is part of the approved spec (ADR-0015).
- Deploy: for each listed binding, the agent checks that the site has the `https`
  binding in `applicationHost.config` (read with `appcmd list site /xml`), then points
  the HTTP.sys entry (`ip:port` or, with SNI, `host:port`) at the new certificate and
  store. All other HTTP.sys parameters of the entry are copied from the existing one.
  Bindings missing from the site configuration fail the task; creating bindings and
  Central Certificate Store bindings are out of scope for v1 (CCS bindings are reported,
  not managed).
- No IIS restart: HTTP.sys uses the new certificate for new connections.
- Verify: HTTP.sys entry read back, `sslFlags` consistent with the entry type, and a TLS
  handshake to the binding (SNI = host) serving the new fingerprint.
- Rollback: the HTTP.sys entries are pointed back at the previous certificate.

**Binding drift**
- The inventory task reports every `https` binding: site, binding, `sslFlags`, and the
  HTTP.sys certificate hash and store. The control plane raises `iis_binding_drift` when
  a managed binding serves a certificate other than the deployment's current one, or
  when the site has an `https` binding without an HTTP.sys entry.

**HTTP-01 on IIS**
- Webroot challenge into the site's physical path, plus a `web.config` in
  `.well-known/acme-challenge` that serves extensionless files as `text/plain` (as
  win-acme does). DNS-01 works unchanged.

**win-acme discovery (read-only)**
- The inventory task reads `%ProgramData%\win-acme\*\*.renewal.json` and reports id,
  friendly name, hosts, target, store and installation plugins, and last result. It
  never changes win-acme files or scheduled tasks, as with Certbot discovery.

## Industry practice (surveyed 2026-11-21)
| Who | Approach |
|---|---|
| [DigiCert Trust Lifecycle Manager](https://docs.digicert.com/en/trust-lifecycle-manager/get-started/quick-start-guides/quick-start-guides-for-agents/deploy-a-digicert-agent-windows-version.html) ([IIS](https://www.digicert.com/integrations/microsoft-iis)) | Agent on the IIS host, outbound HTTPS only; installs into the Windows certificate store and binds; manages SSL flags |
| [Keyfactor IIS/Windows orchestrator](https://github.com/Keyfactor/iis-orchestrator) | `IISU` store type: inventory, add, remove, re-enrollment on the target; PowerShell over WinRM |
| [win-acme](https://www.win-acme.com/reference/plugins/installation/iis) | Certificate in `WebHosting`; updates the HTTPS bindings that used the previous certificate; CCS as a separate store plugin |
| [Microsoft IIS support blog](https://techcommunity.microsoft.com/blog/iis-support-blog/centralized-certificate-store-ccs-and-iis-bindings/582708) | Binding data split between `applicationHost.config` and HTTP.sys `SslBindingInfo`; `sslFlags` 2/3 for CCS |
| [ACMESharp #357](https://www.github.com/ebekker/ACMESharp/issues/357), [LE community](https://community.letsencrypt.org/t/automatic-rebind-of-renewed-certificate-not-working/246277) | Setting `sslFlags` clears the certificate hash; bindings left on the old thumbprint after renewal |

The win-acme issue (#2728) cited in the integration matrix could not be found again in
this survey; the drift cases above are taken from the sources listed.

## Consequences
- The agent runs as `LocalSystem` on Windows. Its task allowlist and signed tasks
  (ADR-0004) are what limit it, as on Linux under root.
- Two native interfaces (CNG, HTTP.sys) are called through `syscall`; their wrappers are
  small and covered by Windows-only tests.

## Verification
- Unit (any OS): binding parsing, `appcmd` XML parsing, win-acme renewal file parsing,
  drift rules.
- Windows tests: CNG key creation (user scope when not elevated), CSR signed by the CNG
  key, store add and lookup, PKCS#10 verified in Go.
- e2e on a Windows CI runner with IIS installed: Pebble (native binary), certloomd with
  the runner's PostgreSQL, Windows agent as a service; issue, bind, verify, renew,
  rollback; an external change of the HTTP.sys binding raises `iis_binding_drift`.

## As built (2026-11-21)
- `internal/winapi` wraps CNG (`ncrypt.dll`), the certificate store (`crypt32.dll`) and
  HTTP.sys (`httpapi.dll`). Entries are changed with `HttpUpdateServiceConfiguration`
  where it exists, otherwise deleted and re-added with the same parameters. A new entry
  gets IIS's application id.
- `appcmd` is used read-only (`list site /config /xml`); the agent never edits
  `applicationHost.config`.
- The approved spec carries the target attributes `site` and `bindings` (lower-cased,
  sorted), so nginx specs and their approvals are unchanged.
- Drift is a finding on the deployment (subject type `deployment`, migration 00012).
  IIS agents ask for an inventory every 15 minutes through the heartbeat field
  `inventory_seconds`.
- The service logs to `agent.log` beside the config file (restarted at 10 MB).
- Not covered by automated tests yet: a full ACME renewal on Windows (the CI job tests
  keys, store, HTTP.sys, verify, drift and rollback against real IIS without a CA).
