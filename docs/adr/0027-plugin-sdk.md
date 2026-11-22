# ADR-0027: Out-of-process plugins with signed packages

**Status:** Accepted (2026-11-22)

## Context
ADR-0007 kept every connector compiled into the binaries for v1 and deferred
third-party extensions to M6, "together with signed packages and explicit operator
trust". ADR-0017 then shipped a small exec protocol for DNS-01 solvers
(`dnsplugin`, protocol 1): the agent runs an absolute-path executable whose sha256 is
pinned in its config.

The main remaining gap is deployment to things certloom has no built-in target for:
in-house applications, appliances, Java keystores, mail servers. Commercial CLM tools
cover these with drivers or orchestrator extensions written by customers. The other
gap is discovery from sources certloom does not read itself.

What is missing today for that:
- one plugin contract for more than DNS,
- a way to know who published a plugin, not just that its bytes did not change,
- a package format, an install path and a trust policy an operator can audit.

Constraints from earlier decisions: private keys are generated on agents and do not
reach the control plane (ADR-0009); the control plane must not become a way to run
arbitrary code on every host (threat model); air-gapped installs are a goal (M8).

## Options considered
**Protocol**
| Option | For | Against |
|---|---|---|
| **A. Exec + JSON: one request on stdin, one response on stdout, per call; generalise `dnsplugin`** | Any language (shell, PowerShell, Python, Go); no long-running process to supervise; same model as CNI, kubectl exec credentials, Docker credential helpers and Venafi Adaptable drivers; already shipped for DNS | No streaming; process start per call; plugins that need state between calls need their own store or a later HTTP mode |
| B. gRPC via hashicorp/go-plugin (as ADR-0007 planned) | Typed; long-running; used by Terraform, Vault, Packer | Plugin authors need protobuf and in practice Go; a second protocol next to `dnsplugin`; more moving parts on the agent |

**Where plugins run**
| Option | For | Against |
|---|---|---|
| **A. On agents only** | The control plane loads no third-party code and stays next to the database and KEK alone; matches the Keyfactor orchestrator model; agents already hold the keys a deploy target needs | Issuer and notifier plugins have to wait (custom CAs come with M7; event webhooks already cover most notifier needs) |
| B. Agents and control plane | Covers custom CAs and notifiers now (Venafi Adaptable CA style) | Third-party code in the process that holds the KEK and the database role |

**Signing**
| Option | For | Against |
|---|---|---|
| **A. Sigstore bundle, keyless or key-based** | Publisher identity from CI (OIDC) with a transparency log, or a plain public key for private and air-gapped publishers; offline verification with a trusted root; the same tool for certloom's own releases in M8 | `sigstore-go` dependency on the agent |
| B. GPG detached signature (Terraform SHA256SUMS, Helm `.prov`) | Familiar | Keyrings are awkward to distribute; no transparency log; no CI identity |
| C. sha256 pin only (Vault, today's ADR-0017) | Simple | Says nothing about the publisher; does not meet "signed packages" |

**Install path**
| Option | For | Against |
|---|---|---|
| **A. Host-local install, verified against a local trust policy; control plane sees inventory only** | Installing code stays a host-administrator decision, as for `reload_command` today; Ansible and packages scale it | No one-click rollout from the UI |
| B. Control plane pushes plugins to agents | Convenient | A compromised control plane can deliver code to every host, even with a local trust policy it only has to find one trusted package with a bug |

## Decision
Option A in all four cases. This amends ADR-0007 (exec + JSON instead of gRPC) and
extends ADR-0017.

**Plugin kinds (agent only)**
- `dns_solver`: unchanged ADR-0017 contract (`present`, `cleanup`).
- `deploy_target`: `deploy`, `verify`, `rollback`, optional `inventory`. The agent
  writes the new key, certificate and chain to a private temporary directory (0700,
  owned by the agent user; on Windows an ACL for SYSTEM and Administrators) and passes
  the paths; the plugin installs them where they belong, which for an appliance means
  sending the key over the appliance's API. The agent keeps owning scheduling, the
  approved spec, checkpoints, external TLS verification and rollback decisions.
- `discovery`: `inventory` returns certificates (PEM) and the objects that use them;
  imported like IIS and Kubernetes observations (ADR-0022, ADR-0023).
- Issuer and notifier plugins are out of scope; custom CAs are revisited in M7.

**Protocol 1**
- The agent runs `<executable> <action>` directly (no shell), writes one JSON request
  to stdin and reads one JSON response (max 64 KiB) from stdout, with a per-call
  timeout. The environment holds `PATH` plus variables the operator lists.
- `describe` returns `protocol`, `name`, `version`, `kinds` (absent means
  `["dns_solver"]`, so existing DNS plugins keep working), and per kind the config keys
  it accepts.
- Every response is `{"ok":true,...}` or `{"error":"...","class":"...",
  "retry_after":N}` with the ADR-0007 error classes, the flat form DNS plugins already
  use.
- Mutating actions carry the run id and step as an idempotency key.
- Secrets: plugins read their own credentials, or receive central credentials sealed to
  the agent (ADR-0018) as `secrets` in the request, as DNS plugins do today.
- Incompatible changes get a new protocol number; `describe` lets the agent refuse
  plugins it does not understand.
- The Go SDK becomes the public package `github.com/alexandrosnt/certloom/plugin`
  (`Serve` with one handler per kind); `dnsplugin` stays as a thin, compatible wrapper.

**Package**
- `certloom-plugin-<name>_<version>_<os>_<arch>.tar.gz` containing `plugin.yaml`
  (name, version, protocol, kinds, executable path inside the archive, description,
  homepage, required permissions in plain words) and the files it needs.
- Next to it, `<package>.sigstore.json`: a Sigstore bundle over the archive, produced
  with `cosign sign-blob --bundle` (keyless in CI, or with a key).
- `certloom-plugin pack` builds the archive from a directory and checks the manifest;
  signing is done with cosign, and the docs include a GitHub Actions example.

**Trust policy (agent config)**
```yaml
plugins:
  trust:
    - name: certloom
      keyless:
        issuer: https://token.actions.githubusercontent.com
        identity_regexp: ^https://github\.com/alexandrosnt/certloom-plugin-[a-z0-9-]+/\.github/workflows/release\.yml@refs/tags/v
    - name: corp
      public_key: /etc/certloom-agent/keys/corp-plugins.pub
  trusted_root: ""        # Sigstore trusted root file for air-gapped or private Sigstore
  require_signed: false   # true refuses plugins pinned by path and sha256 in this file
```
- Keyless verification uses the Sigstore public-good trusted root (embedded and updated
  through TUF), or `trusted_root` when set, so verification works offline.
- A package with no bundle, a bundle that does not verify, or a signer not in `trust`
  is refused. There is no warning-only mode (see Helm CVE-2026-35205).
- The ADR-0017 form (absolute path plus a sha256 pinned in the agent config) stays
  valid for every kind: the host administrator trusts that one binary explicitly, as
  Vault's plugin catalog does. Such plugins are reported as `pinned` in the heartbeat.
  `require_signed: true` refuses them, for hosts that may run signed plugins only.
  Existing DNS plugin configs keep working without changes.

**Install and use**
- Packing, verification and installation live in a separate binary, `certloom-plugin`
  (`pack`, `verify`, `install`, `list`, `remove`), shipped in the agent packages next
  to `certloom-agent`, the way falcoctl installs Falco plugins and the Helm CLI checks
  plugin provenance. It is its own Go module (`cmd/certloom-plugin`), so the Sigstore
  libraries are linked into neither the agent daemon nor certloomd.
- `certloom-plugin install <file|https URL>` downloads the archive and bundle,
  verifies both against the trust policy in the agent config and the manifest, and
  unpacks into `<state_dir>/plugins/<name>/<version>/` (owned by root or SYSTEM, not
  writable by the agent user). Install needs the same privileges as editing the agent
  config.
- The installer writes an install record next to the files (archive digest,
  executable digest, verified signer, trust entry name). The agent reads the record,
  refuses a plugin whose trust entry is no longer in its config, and checks the
  executable's digest before every call.
- Config refers to installed plugins by name (`plugin: corp-f5`); several versions may
  be installed, the config picks one or the newest.
- The heartbeat reports installed plugins (name, version, kinds, signer, digest,
  unsigned flag). The control plane shows them and uses them to validate targets; it has
  no API to install, upgrade or remove plugins.
- Deployment targets of kind `plugin` carry `plugin` and `kind` in the approved spec
  (ADR-0015), so pointing a deployment at a different plugin needs a new approval.
  Plugin upgrades do not, as long as the signer is unchanged.
- `certloom-agent plugin-test <name> --kind <kind>` is the conformance test for authors
  (extends `dns-test`); it lives in the agent because it uses the agent's own call path.

## As built (2026-11-22)
- `plugin` is the public package; `dnsplugin` keeps its API as type aliases and a
  `Serve` wrapper. Existing DNS plugins and configs work unchanged; `describe` now also
  returns `kinds`.
- Fixed on the way: the 64 KiB output limit of ADR-0017 was never enforced, because the
  limited buffer embedded `bytes.Buffer` and `os/exec` copied through its `ReadFrom`.
- The verify task now carries the run id, which plugin targets pass on as the
  idempotency key; verify falls back to a TLS handshake when the target sets
  `verify_address`.
- Plugin targets ask the plugin for `inventory` only with `inventory: true`, rather than
  probing. Discovery plugins live in `discovery_plugins`. Plugin inventories are stored
  without PEMs; their certificates are imported with source `plugin`.
- `CreateDeployment` refuses a plugin target whose plugin the agent does not report as
  installed and trusted (or pinned) for `deploy_target`.
- The conformance check is `certloom-agent plugin-test --target NAME | --discovery NAME`.
  It runs only read-only calls (`describe`, `verify`, `inventory`); deploy and rollback
  are exercised against a staging target with a renewal.
- Keyless verification requires an SCT, a transparency log entry and an observer
  timestamp, as `cosign verify-blob` does. Key-based entries accept bundles without a
  transparency log entry.
- Not done yet (docs/TODO.md): the Docker e2e with a shell plugin, a live keyless test
  against the public-good instance, Windows ACLs for the installer, Ansible variables.

## Industry practice (surveyed 2026-11-22)
| Who | Practice | Source |
|---|---|---|
| Venafi/CyberArk Trust Protection Platform | Adaptable Application and Adaptable CA drivers: one PowerShell script per integration with a fixed set of functions, placed in a folder on the server by an admin; no signing | https://docs.venafi.com/Docs/25.1/TopNav/Content/Drivers/cco-drivers-AdaptableCA-Overview.php, https://mim.pan.dev/dev-docs/building-integrations-tpp-adaptable |
| Keyfactor | Universal Orchestrator extensions: .NET DLLs plus `manifest.json` in the orchestrator's `extensions` folder, installed by the host admin, orchestrator re-approved in Command; no signature check documented | https://software.keyfactor.com/Core/Current/Content/InstallingAgents/NetCoreOrchestrator/CustomExtensions.htm |
| HashiCorp Vault | go-plugin over gRPC; operator registers each plugin with its sha256 in the catalog | https://developer.hashicorp.com/vault/docs/plugins/register |
| Terraform / OpenTofu | go-plugin over gRPC; provider releases signed with GPG over SHA256SUMS | (certloom's own provider, ADR-0025) |
| Helm 4 | Exec plugins; GPG provenance verified by default for tarballs, local directories exempt as dev installs; CVE-2026-35205 made a missing signature a hard error | https://helm.sh/docs/helm/helm_plugin_install, https://nvd.nist.gov/vuln/detail/CVE-2026-35205 |
| Falco | Plugins as OCI artifacts signed with cosign keyless (GitHub OIDC), verified by falcoctl at install | https://falco.org/blog/sign-verify-plugins-rules |
| CNI, kubectl exec credentials, Docker credential helpers | Exec + JSON on stdin/stdout with a versioned spec; binary installed by the host admin | (specifications of each project) |
| Sigstore | `cosign sign-blob --bundle`; verification by certificate identity and OIDC issuer; offline verification with a trusted root | https://docs.sigstore.dev/cosign/signing/signing_with_blobs/, https://docs.sigstore.dev/cosign/verifying/verify/ |

Not found: DigiCert Trust Lifecycle Manager's custom connector model did not come up in
the search. Commercial CLM tools do not document signature checks for customer
extensions; certloom departs from them here because extensions run with the agent's
privileges next to private keys, and recent open-source practice (Helm 4, Falco) makes
verification the default.

## Consequences
- One contract for all agent plugin kinds; existing DNS plugins keep working unchanged.
- Plugin authors can use any language; the Go SDK is a convenience.
- `sigstore-go` is used only by `certloom-plugin`. Measured on 2026-11-22 (v1.4.0):
  about 70 extra modules (gRPC, OpenTelemetry, Rekor, in-toto, go-openapi) and a 27 MB
  binary for verification alone, which is why it is kept out of the agent daemon
  rather than reimplemented: keyless verification needs Rekor proof checks that should
  not be hand-written.
- Operators must manage a trust policy; the Ansible role gains variables for it.
- Plugins still run with the agent's privileges. Signing tells who published a plugin,
  not that it is safe; the docs say so.
- No issuer or notifier plugins until a later ADR.

## Verification
- Protocol: unit tests with test plugins per kind (success, each error class, timeout,
  oversized output, wrong protocol, missing kind).
- Signing: tests for keyless bundles (Sigstore staging or a local test CA and trusted
  root), key-based bundles, tampered archive, tampered manifest, signer not trusted,
  missing bundle, `allow_unsigned` paths; executable digest re-checked before each call.
- e2e: an example `deploy_target` plugin (in shell, outside Go) packed, signed with a
  test key, installed, used for a renewal with rollback, and reported in the
  heartbeat; the existing DNS plugin e2e keeps passing unchanged.
- A secret scan of task payloads and logs, as for central DNS credentials.
