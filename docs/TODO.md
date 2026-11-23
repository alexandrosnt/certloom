# TODO / known issues

Not done yet, roughly in the order I want to tackle it.

## Plugins
- Docker e2e with a shell `deploy_target` plugin packed, signed, installed with
  `certloom-plugin` and used for a renewal against Pebble (today: unit, agent, installer
  and workflow tests).
- Keyless verification is tested against a virtual Sigstore only; add an opt-in live test
  against a package signed in GitHub Actions and the public-good trusted root.
- Key-based bundles uploaded to Rekor (cosign without `--tlog-upload=false`) are not
  covered by a test yet.
- `certloom-plugin` on Windows: ACLs of the plugins directory and the MSI (M8).
- Ansible role variables for `plugins.trust` and plugin installs.
- Distribution through OCI registries (falcoctl style); issuer and notifier plugins on
  the control plane need their own ADR.

## Private CAs
- Test the ACME issuer against Vault's ACME server (HTTP-01 from the CA to nginx, EAB)
  in `test/acme`. step-ca's ACME provisioner is covered by `TestAirgapRenewal`.
- Vault: Kubernetes and JWT auth, and the secret_id from a file or Vault Agent instead of
  the database. step-ca: a root fingerprint instead of a CA bundle, and the X5C and OIDC
  provisioners.
- Revocation through Vault and step-ca (none of the issuers revokes yet).
- Terraform provider and Ansible modules: issuer kind, settings and credential.

## CA inventory
- Count agent and cloud inventory objects (IIS bindings, Kubernetes, cloud certificates)
  as "in use" for `ca_expiring`; today only lineages and probed endpoints do.
- Go client, Terraform data source and Ansible info module for authorities.
- A private root in the certloomd host's OS store that is in no trust bundle still
  counts as publicly trusted; put private roots in a bundle.

## Trust bundles
- Second-person approval for bundle changes, gated by policy (ADR-0030 consequences).
- JKS keystores, NSS (Firefox) and macOS keychains.
- Writing trust-manager Bundle sources in Kubernetes (observe-only today).
- Windows: unknown-anchor detection covers only certloom's own entries in
  LocalMachineRoot; telling local roots from the Microsoft root program needs that list.
- UI page for bundles and store status; Terraform and Ansible support.

## Renewal
- No command to change a deployment's issuer (e.g. staging to production); today it
  means recreating the deployment.
- `certloom-dns-lego` plugin: many lego providers keep the record id in memory between
  present and cleanup, so they need a long-running plugin (HTTP transport) or a
  per-provider answer.
- DNS-01: lego resolves the authoritative nameservers' names through the system resolver,
  not `resolvers`; split-horizon setups may need an option to check through the
  configured resolvers only.
- Cloudflare DNS has only mock-API tests; run it once live against a test zone.
- EAB: live runs against a commercial CA (only Pebble so far), and recording per CA
  whether accounts survive revocation of the key that registered them.
- Event webhooks: channel webhooks still sign without a timestamp; move them to Standard
  Webhooks signing in a later version (breaking for existing receivers).
- Templates do not set validity or EKU yet (ACME CAs decide lifetimes via profiles).
- EAB keys come from the database only; vault references with ADR-0009 Phase 6.
- Central DNS credentials come from the database only; Vault and cloud secret-manager
  references are planned with the ADR-0009 Phase 6 providers (ADR-0018).
- No web UI for approvals and exceptions yet (API and CLI only).
- `deployment list` shows the stored approval state; a legacy deployment under required
  approvals still shows "approved" until it is next checked.

## Windows and Kubernetes
- IIS: Central Certificate Store bindings are only reported; creating bindings and TPM
  keys are not supported yet.
- The Windows IIS test runs in CI without ACME; run one renewal against Pebble or
  Let's Encrypt staging on a real Windows Server.
- Windows agent: logs go to a file, not the Event Log.

## Releases
- Windows MSI for the agent (WiX v6+ needs the Open Source Maintenance Fee for
  revenue-generating users; tool not chosen) and Authenticode through SignPath
  Foundation (application pending; `docs/code-signing-policy.md` is ready).
- First tagged run is a release candidate: snapshots are unsigned, so package
  signing, cosign and attestations are only exercised by a tag.
- Publish the packaging key fingerprint in `docs/verify-release.md` once the key
  exists.
- The reproducibility job uses one pinned GoReleaser image on two runners; a rebuild
  with an independent toolchain (plain `go build` with the same flags) is not compared.
- Ansible role: install from the apt/yum repository instead of a package URL.
- `latest` and version tags only; no `X.Y` moving image tags yet.
- Kubernetes: no Helm chart yet; trust-manager is tested with its CRD only (no
  controller); TLS Secrets not managed by cert-manager are not seen.
- An agent result whose import fails is retried by the agent forever without a visible
  error on the control plane; surface it.

## Cloud
- AWS, Azure, Google and Cloudflare observation is tested against fakes only. Run each
  once live with read-only credentials and record it in the integration matrix: in
  particular that Key Vault Reader can read certificates and pending operations, and
  which Cloudflare token permission the Origin CA list needs.
- Policy exceptions cannot target `cloud_object` or `k8s_object` findings yet (the
  schema allows it; the API accepts certificate, endpoint and lineage only).
- Central cloud credentials sealed to agents (ADR-0018 path) and Event Grid /
  EventBridge push are not built; polling only.
- Classic Compute Engine SSL certificates and load balancer attachments in Google are
  not listed.

## Control plane
- systemd unit and a non-Docker install guide for `certloomd`. With a distro PostgreSQL
  the owner role needs `CREATEROLE` (PG 16+), because the first migration creates
  `certloom_app`.
- `test/acme` pulls `pebble:latest`; pin it.
- `certloom schedule preview` (next renewal and window times with reasons).
- Rate limits are per replica (documented in `docs/runbooks/ha.md`); a shared limiter in
  PostgreSQL if that turns out to matter.
- Review the existing periodic loops for safety when two runs overlap (a leader that
  lost its lease mid-tick); ADR-0033 makes it a rule for new loops.
- The Compose install sets no KEK, so it runs without agent support and with a
  per-process CSRF key; add a generated KEK file to the Compose setup.
- HA e2e covers two replicas behind nginx and a PostgreSQL restart, not a real
  Patroni or CloudNativePG failover.
- `members` has no RLS on purpose (sign-in needs it before the org is known); maybe move
  the lookup into a SECURITY DEFINER function instead.
- OpenAPI check only compares routes, not request/response bodies.
- sqlc instead of hand-written queries once the schema settles.

## Decided
- Agents never start issuance on their own while the control plane is down.
- Agent channel is HTTPS + JSON over mTLS rather than gRPC.
- Wildcard certificates only with DNS-01, listed literally in `allowed_sans`.

## Open questions
- Where to publish images and packages.
- What "medium install" means for load tests.

## Scale notes (local, 2026-11-20)
10k certs + 2k endpoints on one box: sweep 6s, overview 18ms, probing ~550/s against
a local TLS server (real networks will be slower). `CERTLOOM_SCALE=1 go test ./test/scale/`.
CA inventory (2026-11-22, same box): inserting 10k certificates 4.8s -> 5.4s (issuer
link per new certificate, candidates cached per transaction), sweep 7.2s -> 7.3s, first
probe of 2k new leaves ~1s slower (one issuer lookup each).
