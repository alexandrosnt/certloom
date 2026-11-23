# Changelog

## Unreleased

### Added
- Cloud accounts read by certloomd itself, without an agent (ADR-0034): AWS
  Certificate Manager and Private CA, Azure Key Vault, Google Certificate
  Manager and CA Service, Cloudflare. `certloom cloud-account`,
  `/api/v1/cloud-accounts` and the OpenTofu resource `certloom_cloud_account`.
  certloomd uses its own cloud identity, or a read-only key stored encrypted
  with the KEK and never returned. Settings cannot name local files or
  endpoints. New permission `cloud:manage` and policy
  `cloud.centralCredentials`. Guide: `docs/getting-started/cloud.md`.
- `certloom agent observations` also shows cloud objects.
- `certloomd setup` configures a package install in one step: local database,
  key-encryption key, TLS certificate, settings, service and the first
  organization with a sign-in token. The local database is reached only over
  TLS 1.3 with full verification (one-off CA whose key is discarded; `pg_hba`
  refuses the certloom roles without TLS). Package upgrades of a host set up
  this way migrate the database by themselves. The deb package recommends
  `postgresql`.
- Getting-started guides, each tested end to end on a fresh host: an overview
  of what certloom does (`docs/overview.md`), monitoring with OpenTofu and no
  agent, renewal on Linux with nginx, renewal on Windows with IIS,
  cert-manager observation in Kubernetes, and cloud accounts. The Windows
  guide runs on a hosted Windows Server with IIS in the `guides` workflow.
- `certloom deployment create --endpoint` (and the API's `endpoint` field)
  also takes the endpoint's host or `host:port` instead of its id.

### Changed
- The cloud collectors moved from the agent into a package that the agent and
  certloomd share; agent configuration and behavior are unchanged.
- `deploy/kubernetes/agent.yaml` uses the released image from GHCR instead of
  a locally built one; the release workflow checks that it names the version
  being released.

### Fixed
- The Windows agent could not finish an ACME order for an IIS target: with the
  key in the machine key store, nothing had created the run directory the
  issued chain is saved in. Found by the first full renewal on Windows.
- certloomd ignored a configured KEK unless the agent listener was on, so a package
  install without `CERTLOOM_AGENT_LISTEN` could not store webhook, EAB, DNS or CA
  credentials and used a per-process CSRF key. The packaged `certloomd.env` now
  enables the agent listener, and the install runbook gives every setup step.

## 0.1.0-rc.1 - 2026-11-23

First release candidate. Everything below is new since the project started;
the "Fixed" list covers bugs found and fixed before this first release.

### Added
- Logo and brand files (`docs/brand`): mark in light, dark and one-colour versions, favicon,
  avatar and a social preview image. The web UI shows the mark in the header and on the
  sign-in page and serves an SVG favicon.
- High availability and disaster recovery (ADR-0033): any number of `certloomd`
  replicas behind a load balancer, with the periodic schedulers on one elected
  replica (`leader` table) and jobs on all of them; `certloomd migrate` takes an
  advisory lock. `docs/runbooks/ha.md` (load balancer, PostgreSQL HA options,
  upgrades) and `docs/runbooks/dr.md` (backup levels, KEK escrow, restore, drill).
  New e2e tests kill the leader mid-renewal and restore a backup older than the
  agent's last tasks.
- Release pipeline (ADR-0031): a `vX.Y.Z` tag builds archives, deb/rpm packages and
  multi-arch images with GoReleaser, signs `SHA256SUMS` and the images with Sigstore
  (keyless), attaches SPDX SBOMs and GitHub build provenance, and publishes the packages
  to signed apt and yum repositories. Builds are reproducible (checked in CI).
  `docs/verify-release.md` shows how to verify, also offline.
- Air-gapped installation (ADR-0032): each release gets a signed offline bundle per
  architecture (archives, packages, images including PostgreSQL, Compose files, docs,
  `CONTENTS.sha256`). `docs/runbooks/airgap.md` covers the bundle and mirroring into
  internal registries and package repositories with signatures kept. A new e2e test
  issues and renews through step-ca's ACME server on a network without a route out.
- `certloomd` deb and rpm packages with a hardened, unprivileged systemd unit
  (`docs/runbooks/install-packages.md`).
- `deploy/packaging/build.sh` now builds all archives and packages (amd64 and arm64)
  from `.goreleaser.yaml` and needs Docker only; `deploy/packaging/nfpm.yaml` is removed.
- Trust bundles (ADR-0030): named, versioned sets of CA anchors pushed by the agent to
  trust stores declared in its config (`trust_stores`: `pem`, `pkcs12`, `debian`, `rhel`,
  `windows`; `mode: observe` only reports). New task `trust.apply` writes the anchors,
  runs the update or reload command, and restores the store if that fails.
  `certloom trust-bundle plan|apply|status|show|list|delete`, `/api/v1/trust-bundles*`,
  permission `trust:manage` (owner). Removing an anchor is refused while a CA in use
  chains to it or a store has not confirmed the current version, unless `--force
  --reason`. Findings `trust_store_drift` and `trust_store_unknown_anchor`. Bundle
  anchors are trusted by endpoint checks and never count as publicly trusted.
- Root and intermediate CA inventory (ADR-0029). Every stored certificate is linked to the
  CA that signed it (subject plus key, so cross-signed copies count as one CA), including
  certificates stored earlier. New findings: `ca_expiring` on CAs in use (policy
  `caExpiry`, default 180d/30d; info for publicly trusted CAs), `chain_outlived` when a
  certificate outlives its chain, and `chain_cert_expiring` when an endpoint serves an
  intermediate that expires soon. `certloom ca list|show|impact|plan|renew-affected`,
  `/api/v1/authorities*` and a CAs page in the UI. `renew-affected` starts normal
  renewal runs for the deployments under a CA. Issuer CA bundles are added to the
  inventory.
- Vault PKI and step-ca issuers (ADR-0028): `certloom issuer create --kind vault|stepca`.
  The agent makes the key and a CSR (new task `csr.create`); certloomd checks the CSR
  against the approved deployment and has it signed through Vault `sign/<role>` (AppRole,
  token revoked after each call, or a fixed token) or a step-ca JWK provisioner. No ACME
  challenge, so wildcards and unreachable hosts work. The credential is stored under the
  KEK and never returned (`certloom issuer set-credential`); TLS to the CA trusts only the
  issuer's CA bundle (`set-ca-bundle`). New run state `signing`. API: `kind`, `settings`,
  `ca_bundle` and `credential` on issuers, `PUT /api/v1/issuers/{id}/credential`; the Go
  client has the same fields. `certloom issuer show`.
- Agent plugins (ADR-0027): one exec + JSON protocol for DNS solvers, deploy targets
  (`type: plugin`: deploy, verify, rollback, inventory) and discovery plugins, with the
  public Go package `github.com/alexandrosnt/certloom/plugin` (`dnsplugin` now wraps it).
  Signed packages: `certloom-plugin pack|verify|install|list|remove`, a separate binary in
  the agent packages that checks Sigstore bundles (keyless CI identity or public key,
  offline with a trusted root) against `plugins.trust` in the agent config and refuses
  unsigned packages. The agent re-checks the installed digest before every call, reports
  its plugins in the heartbeat (`certloom agent plugins`), and `certloom-agent
  plugin-test` runs a plugin's read-only calls. The plugin of a plugin target is part of
  the approved deployment spec.
- Ansible collection `alexandrosnt.certloom` in its own repository (ADR-0026): modules for
  the configuration objects the Terraform provider covers, plus EAB pool keys, info
  modules and agent enrollment tokens, and a role that installs, configures and
  enrolls certloom-agent on Debian and Red Hat family hosts. No pip dependencies;
  secrets are `no_log` and write-only.
- Go client for the REST API as its own module, `github.com/alexandrosnt/certloom/client`
  (standard library only; ADR-0025). Covers teams, scopes, endpoints, channels,
  issuers (including EAB), templates, DNS solvers, the policy and agent lookups. Create calls carry an
  `Idempotency-Key` and are retried on 429/503 with `Retry-After`; endpoint updates can
  pass the version for `If-Match`. Tagged `client/vX.Y.Z`.
- API: `GET`, `PATCH` and `DELETE` by id or name for teams, scopes, channels and
  issuers, and `PATCH`/`DELETE` for endpoints (with `If-Match`), as groundwork for the
  Terraform/OpenTofu provider (ADR-0025). PATCH leaves absent fields unchanged. A
  delete answers 409 `in-use` while something still references the object, and a
  channel named in the active policy cannot be renamed or deleted. Deleting an
  endpoint resolves its open findings. An issuer's directory URL and terms-of-service
  decision cannot be changed; use a new issuer for a different CA.
- Read-only cloud observation (ADR-0024): a `cloud:` block in the agent config lists
  certificates in AWS Certificate Manager and AWS Private CA, Azure Key Vault, Google
  Certificate Manager and CA Service, and Cloudflare (edge certificate packs, Origin CA).
  Credentials come from the cloud's own identity (instance role, managed identity,
  workload identity) or a file on the agent host. Returned certificates are imported;
  findings `cloud_renewal_failing`, `cloud_renewal_manual` and
  `cloud_version_not_adopted` (a new Key Vault version that probed endpoints have not
  picked up). See `docs/runbooks/cloud.md`.
- Windows agent for IIS (ADR-0022): target type `iis` (site + bindings). Keys are
  created non-exportable in the machine key store and sign the CSR inside CNG; the
  certificate goes to `WebHosting` and the configured HTTP.sys bindings are switched
  in place, read back, verified by TLS handshake and restored on failure. Older
  certloom certificates are pruned. `certloom-agent service install|uninstall` runs it
  as a Windows service. IIS hosts report their https bindings every 15 minutes;
  `iis_binding_drift` findings show bindings that no longer serve the deployment's
  certificate. win-acme renewals are discovered read-only.
- Kubernetes observation (ADR-0023): `certloom-agent` with a `kubernetes:` block runs
  in the cluster (`deploy/kubernetes/agent.yaml`, `Dockerfile.agent`) with `get`/`list`
  on cert-manager and trust-manager objects and Ingresses only, no Secret access.
  Certificates are imported from CertificateRequest status; findings
  `k8s_certificate_not_ready`, `k8s_renewal_overdue`, `k8s_request_failed`,
  `k8s_issuer_not_ready`, `k8s_bundle_not_synced`. `certloom-agent run
  --enroll-token-file` enrolls on first start.
- Agents can ask for periodic inventories (`inventory_seconds` in the heartbeat);
  `GET /api/v1/agents/{id}/inventory` and `certloom agent observations` show the last
  one.
- Web UI pages for members, policy and channels. Owners add and remove OIDC members
  (removal goes through a confirmation page; you cannot remove yourself there). The
  policy page shows the active version; with `policy:manage` you edit the YAML, review
  the same impact plan as `certloom policy plan`, then apply. An apply is refused if
  another version was applied after the plan was shown. Channels can be listed, created
  (webhook or email, secrets only as `env:`/`file:` references) and sent a test.
- Event webhooks (ADR-0021): `certloom webhook create|list|show|deliveries|redeliver|rotate-secret|enable|disable|delete`.
  Endpoints subscribe to typed events (`docs/events.md`: certificate.issued, renewal.*,
  approval.*, exception.*, finding.*, agent.*, ...) and receive them signed per Standard
  Webhooks (webhook-id, webhook-timestamp, HMAC-SHA256 over id, timestamp and body), with
  the same SSRF guard as channels. Secrets are generated, shown once, stored under the KEK
  and rotated with a 24-hour overlap. At-least-once delivery with retries for about a
  day, a per-endpoint delivery log, redelivery, and auto-disable after 3 days of
  failures. New permission `webhooks:manage` (owner).
- Certificate templates (ADR-0020): `kind: CertificateTemplate` documents fix the issuer and
  challenge, list allowed key algorithms and constrain names with glob patterns, a name
  count and a wildcard switch. `certloom template validate|plan|apply|show|list|delete`;
  `certloom deployment create --template`. Deployments follow their template: an apply
  re-resolves them in one transaction, refuses while any would break the new
  constraints, and sends changed specs back for approval where needed. Policy
  `templates.required`; new permission `templates:manage` (owner, issuer_admin).
- ACME External Account Binding (ADR-0019): `certloom issuer set-eab --mode none|reusable|single_use`
  and `certloom issuer eab-key add|list|delete`. HMAC keys are stored encrypted with the
  KEK, never returned, and sent sealed to an agent only until it has registered its
  account (account slot per issuer, reported in heartbeats). Single-use keys (Google
  Trust Services) form a pool: one key is claimed per agent, consumed on registration,
  marked failed when the CA refuses it; issuer findings `eab_pool` and
  `eab_key_expiring` warn before renewals stall. Agents can keep their own key
  (`acme_eab`, wins over a central one) or refuse central keys (`central_eab: false`).
- DNS-01 challenges and wildcard certificates (ADR-0017). Agents get `dns_solvers` with
  built-in `rfc2136` (TSIG) and `cloudflare` providers, plus executable plugins for any
  other DNS service (protocol in `docs/dns-plugins.md`, Go SDK in package `dnsplugin`).
  DNS credentials stay on the agent host. The agent follows `_acme-challenge` CNAMEs to a
  delegated validation zone and picks the solver with the longest matching zone.
  `certloom deployment create --challenge dns-01`; the challenge type is part of the
  approved spec, and existing HTTP-01 approvals stay valid. A wildcard must be listed
  literally in the target's `allowed_sans`.
- `certloom-agent dns-test --solver NAME --name DOMAIN` writes, resolves and removes a
  test record to check a solver's credentials and permissions.
- Central DNS solvers (ADR-0018): `certloom dns-solver create|list|show|set-secret|assign|unassign|delete`.
  Credentials are stored encrypted with the KEK, never returned, and delivered only inside
  an issue task, sealed with HPKE (ML-KEM-768 + X25519) to that agent for that task; every
  delivery is audited. Ambient (host cloud identity) credentials for plugins. Agents can
  refuse central solvers (`central_dns_solvers: false`) and policy
  `dns.centralCredentials: forbidden` turns them off for the organization. New role
  permission `dns:manage` (owner, issuer_admin).
- Policy exceptions (ADR-0016): time-bound, approved acceptance of one condition (check,
  check version and fingerprint) on one subject at its current severity, with risk owner,
  rationale, compensating controls, optional remediation plan and the finding as
  evidence. The alert is suppressed while the finding stays visible and counted;
  alerting returns at once on expiry, revocation, escalation or a changed condition.
  Policy `exceptions.maxDuration` (default 90d) and `exceptions.prohibitedChecks`;
  `certloom exception request|list|show|revoke`.
- Acknowledgements lapse after policy `alerts.ackExpiry` (default 7d) and the alert
  opens again; acknowledging never hides a finding.
- Findings record their check version and a fingerprint of the condition.
- Approvals with separation of duties (ADR-0015): roles `requester`, `approver`,
  `deployment_operator` and `issuer_admin`; policy `approvals.deployments: required`,
  `approvals.expireAfter` and `approvals.channels`; `certloom approval
  list|show|approve|deny` and `certloom deployment request-approval|revoke-approval`.
  An approval covers the effective deployment spec (names, key algorithm, issuer,
  target), so renewals of an approved spec stay automatic while any change to it, or a
  revocation, stops runs before they touch the target. Nobody decides their own request,
  including through a token they created.
- Tested against Let's Encrypt staging: issuance, renewal with `replaces`, ARI
  scheduling and rollback on a real host.
- Maintenance windows per deployment (`certloom deployment set-window`, e.g.
  "Mon-Fri 02:00-05:00 Europe/Athens"). Activation waits for the window; if no
  window starts before the current certificate gets too close to expiry the run is
  blocked with a critical alert, or proceeds when the deployment allows
  `renew_outside_window` (audited).
- Rate-limited ACME orders honour the CA's Retry-After and do not use up attempts.
- systemd unit and deb/rpm packages for `certloom-agent` (`deploy/packaging/build.sh`).
- Web UI pages for agents, deployments (with "Renew now") and runs (with cancel).
- Agent (`certloom-agent`): mTLS enrollment with CA pinning, signed tasks, local key
  generation, ACME HTTP-01 via lego, atomic Nginx activation with `nginx -t`,
  reload, local verification and rollback. Read-only Certbot discovery.
- Renewal workflow: checkpointed runs (issue, deploy, verify), retries, rollback,
  external verification through the prober, ARI-based scheduling with fallback.
- `certloom agent|issuer|deployment|run` commands.
- OIDC sign-in (auth code + PKCE in the browser, device flow in the CLI) and members.
- External audit export (file or signed webhook) and `certloomd audit-verify-export --compare`.
- Idempotency keys, ETag/If-Match, rate limits, OpenAPI spec checked against the router.
- Versioned monitoring policy (`certloom policy`), alert escalation, observation pruning.
- Inventory, endpoint probing, checks, alerts, audit log, API, CLI and web UI.
- Docker image and a Compose setup with a tested backup/restore procedure.

### Fixed
- After a database restore, renewals of targets the agent had worked on since the
  backup were rejected as stale until the task counter caught up, and tasks whose
  results had been acknowledged before the failure went unanswered until they
  expired. Agents now
  report their sequence fence in the heartbeat and re-send stored results.
- Web UI forms failed across replicas without sticky sessions: the CSRF key is now
  derived from the KEK.
- The plugin output limit (64 KiB) was not enforced: the buffer inherited `ReadFrom`, which
  `os/exec` used instead of the limited `Write`.
- The Compose install had no KEK, so agents could not connect and web forms used a
  per-process CSRF key. It now reads the KEK from a Compose secret (`secrets/kek`) and
  publishes the agent listener on port 8444 (`CERTLOOM_HOSTNAME`, `CERTLOOM_AGENT_PUBLISH`).
- The web UI footer still said renewal works only for Linux, nginx and HTTP-01.
- The "Endpoint added" confirmation in the web UI was never shown: messages containing a
  semicolon were dropped by the query parser.
- An ARI check that was still running when a renewal finished could overwrite the new
  certificate's schedule with the old certificate's, delaying the next ARI check by a day.
- Agents reported `0.0.0-dev` as their version instead of the version they were built with.
- Renewing a certificate from another CA (or from Let's Encrypt staging) failed every
  attempt, because the CA refused the `replaces` hint. When an order is refused as
  `malformed`, `unauthorized` or `alreadyReplaced`, the agent now logs it and orders once
  more without the hint.
- Session cookies are marked Secure from a server setting instead of per request, so
  they stay Secure behind a TLS-terminating proxy (`CERTLOOM_SECURE_COOKIES=true`).
- Audit export to a file reports errors from closing the file.
- The CLI cancels in-flight requests on Ctrl+C; SMTP delivery honours cancellation.
- An order whose predecessor was already marked replaced is retried without `replaces`.
- A task interrupted by an agent crash is reported as interrupted (outcome unknown)
  instead of a replay error, and the run rolls back.
- Agent restore after a failed `nginx -t` no longer runs a reload that fails for the same reason.
- Wildcard SANs are refused (an allowlist pattern used to authorize a literal wildcard cert).
- Agent sequence fence can no longer move backwards.
- Lost wake-ups and clock-skew stalls in the workflow engine.
- Scheduler re-selected endpoints that already had a queued probe.
- Windows: "connection refused" was misclassified.
- `certloom login --ca-file` stored a relative path.
