# External security review: scope

This page is for whoever reviews certloom from outside the project. It says what
to look at first, what is out of scope, how to set up a test installation and how
to report what you find. The threat model ([threat-model.md](threat-model.md))
lists the assets, trust boundaries and mitigations (T1-T33); this page does not
repeat it.

## Version under review

Tag `v0.1.0-rc.1` (or the commit named when the review starts). Release files are
signed and can be checked with [verify-release.md](verify-release.md).

## In scope, in order of priority

1. **Agent channel and task signing** (T11, T12, T14, T25, T32).
   `internal/agentapi`, `internal/agentpki`, `internal/agentproto`, `internal/agent`.
   Can anyone other than the control plane get an agent to act? Can the control
   plane get an agent to do more than its local config allows (other names,
   paths, commands, trust stores)? Enrollment tokens, CA pinning, mTLS identity
   rotation and revocation, nonce, expiry and sequence checks, the HPKE sealing of
   central DNS and EAB credentials.
2. **Tenant isolation and authorization** (T4, T5, T6).
   `internal/authz`, `internal/api`, `internal/store` and the row-level security
   policies in `internal/store/migrations`. Cross-organization reads or writes,
   role bypass, API token handling.
3. **Prober and outbound requests** (T1, T9, T28).
   `internal/probe` (scope checks, IP pinning), `internal/notify`,
   `internal/webhook`. SSRF to loopback, link-local, metadata or other internal
   addresses, DNS rebinding, redirects.
4. **Secrets at rest and in transit** (T3, T24, T29, T33).
   `internal/kek`, `internal/secret`, `internal/privateca`. KEK use and
   derivation, write-only credentials, anything that reaches logs, events, API
   or CLI output.
5. **Web UI and sign-in** (T7, T18, T19). `internal/web`, `internal/oidcauth`.
   CSRF, XSS through certificate fields, session cookies, OIDC state, nonce and
   PKCE, rate limits on failed sign-in.
6. **Audit log** (T8, T22). `internal/audit`, `internal/auditexport`. Ways to
   change or drop events without `certloom audit verify` or the export comparison
   noticing.
7. **Parsing untrusted input** (T2). `internal/certparse` (PEM, DER, PKCS#12),
   policy YAML, plugin packages (`cmd/certloom-plugin`, `internal/pluginstore`).
8. **Release and supply chain** (T15). `.github/workflows`, `.goreleaser.yaml`,
   `deploy/packaging`. Whether a published file can differ from what the tagged
   source builds, and whether signatures and provenance can be forged.

## Out of scope

- Denial of service by volume (floods against the API or the agent listener).
  Resource exhaustion from a single small request is in scope.
- Weaknesses in PostgreSQL, the Go standard library, lego, or the CAs
  themselves, unless certloom uses them unsafely.
- An attacker who already has root on the control-plane host or the database
  owner role: the threat model accepts that they can act as certloomd. What they
  can still *not* do (read leaf private keys, go beyond an agent's local
  allowlist, rewrite the audit log without the external export noticing) is in
  scope.
- The Terraform provider and Ansible collection, which live in their own
  repositories.
- Social engineering and the GitHub account itself.

## Test installation

Use test material only, never real keys or production certificates.

- Control plane: the Compose install in
  [deploy/compose/README.md](../deploy/compose/README.md) (PostgreSQL and
  certloomd with the agent listener).
- Agents: a Linux host with nginx ([runbooks/agent.md](runbooks/agent.md)) and,
  if possible, a Windows host with IIS ([runbooks/windows-iis.md](runbooks/windows-iis.md)).
- A CA to issue from: Let's Encrypt staging, or Pebble for a closed network. The
  ACME e2e suite (`CERTLOOM_ACME_E2E=1 go test ./test/acme/`) starts Pebble,
  nginx, BIND and agents in Docker and is a quick way to see a full renewal.
- Every API call is described in `api/openapi.yaml`; the CLI (`certloom`) and
  the web UI use the same API.

## What is already checked

So the review can go past it: unit, database, workflow and Docker e2e tests in
CI (`.github/workflows/ci.yml`), native fuzzing of the certificate parser
(10 minutes per CI run), `govulncheck`, `golangci-lint` with `gosec`, secret
scans of database dumps and logs, and reproducible release builds compared on
two runners. The test that backs each mitigation is named in the threat model.

## Reporting

Report findings privately through GitHub's private vulnerability reporting on
the certloom repository (Security tab, "Report a vulnerability"), as described in
[SECURITY.md](../SECURITY.md). One report per finding, with the version or
commit, impact, steps to reproduce and a suggested severity. At the end, a short
summary of what was covered and what was not is as useful as the findings: it
tells the next reviewer where to start.

Fixes are released with a GitHub security advisory that credits the reviewer
unless they ask not to be named.
