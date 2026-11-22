# ADR-0026: Ansible collection

**Status:** Accepted (2026-11-22)

## Context
Many of the teams that would run certloom manage their servers with Ansible rather than
(or next to) Terraform. They need two things from it:

1. Control-plane configuration (teams, scopes, endpoints, issuers, DNS solvers,
   templates, channels, policy) in playbooks, like the Terraform provider (ADR-0025).
2. Rolling out `certloom-agent` to a fleet: install the package, write `config.yaml`,
   enroll each host with a single-use token and start the service. Today that is a
   manual step per host.

Constraints from earlier decisions: private keys stay on agents (ADR-0009), user
supplied secrets are write-only in the API, and enrollment tokens are one-time, owner
only and expire within an hour.

## Options considered
**Scope**
| Option | For | Against |
|---|---|---|
| **A. Config modules plus an agent role** | Covers both needs; the role is where Ansible adds most over Terraform | More to test (role needs real hosts or containers) |
| B. Config modules only | Smaller | Fleet rollout stays manual |
| C. Agent role only | Smallest | Config split between tools for Ansible-only shops |

**How modules call the API**
| Option | For | Against |
|---|---|---|
| **A. Python modules on `ansible.module_utils.urls` (`fetch_url`), shared `module_utils`, no pip dependencies** | Nothing to install on the controller; same stdlib-only rule as the Go client | HTTP helpers written by us |
| B. Publish a Python SDK on PyPI and depend on it | Venafi (vcert) and NetBox (pynetbox) do this | One more artifact to version and release; users must pip install it into the right interpreter |
| C. Modules shell out to the `certloom` CLI | Reuses the Go code | Binary needed on the controller; check and diff modes are hard; unusual |

**Repo and namespace**
| Option | For | Against |
|---|---|---|
| **A. Separate repo `ansible-collection-certloom`, collection `certloom.certloom`** | Same split as the Terraform provider; Galaxy imports and `ansible-test` expect the collection at the repo root; namespace not tied to a person | Galaxy namespace `certloom` has to be requested |
| B. `alexandrosnt.certloom` | Works without a request | Tied to a personal login; renaming later breaks playbooks |
| C. Inside the certloom repo | One repo | Release tags and layout clash with the Go modules |

## Decision
Option A in all three cases.

**Modules**
- One module per API object, mirroring the Terraform resources: `team`, `scope`,
  `endpoint`, `channel`, `issuer`, `issuer_eab_key`, `dns_solver`, `template`,
  `policy`, plus `*_info` modules for lookups and `agent_info`.
- Common options from a shared doc fragment: `url`, `token` (`no_log`), `ca_path`,
  `validate_certs`, `timeout`; `url` and `token` default to `CERTLOOM_ENDPOINT` and
  `CERTLOOM_TOKEN`, the same names as the provider.
- `state: present|absent`. Objects are found by name (unique per org); a module reads,
  compares the requested fields and only writes on a difference, so a second run
  reports `changed=false`.
- Check mode in every module (no writes, `changed` computed from the comparison) and
  `--diff` output with before/after of the non-secret fields.
- Updates send `If-Match` with the ETag from the read; creates send an
  `Idempotency-Key`. A 412 fails the task with a message to re-run rather than
  overwriting someone else's change.
- `module_utils/api.py` holds auth, ETag/idempotency handling, retries on 429/503 with
  `Retry-After` for idempotent requests, and turns API problem details into
  `fail_json` messages.

**Secrets**
- User supplied secrets (DNS solver credentials, EAB HMAC key, channel credentials) are
  `no_log` options. Because the API never returns them, they cannot be compared; each
  module with a secret has `update_secret: on_create|always` (default `on_create`),
  the same pattern as `ansible.builtin.user`'s `update_password`. Diff output never
  includes them.
- `agent_enrollment_token` creates a one-time token and returns it with the CA hash.
  Ansible cannot hide a single return value without also hiding it from the caller,
  so the module documentation requires `no_log: true` on the task; the role does
  this, and the token reaches the host only on the agent's stdin.
- Webhook signing secrets and API tokens are not handled by the collection (as in
  ADR-0025).

**Role `certloom.certloom.agent`**
- Installs the agent from a package the user points to (`.deb`/`.rpm` URL or file,
  with a required SHA-256 checksum) or a Windows zip; no package repository until
  M8.
- Templates `config.yaml` from role variables, validates it with
  `certloom-agent check-config` before it is put in place, and restarts the service
  only on change.
- Enrolls only if the host is not enrolled yet: creates one token per host on the
  controller (`delegate_to: localhost`), pipes it to
  `certloom-agent enroll --token-stdin --ca-hash`, and never logs it.
- Linux: systemd unit from the package. Windows: `certloom-agent service install`.

**Testing and release**
- `ansible-test sanity`, `units` and `integration` in CI against `certloomd` in a
  container (same setup as the provider's test server), for the ansible-core versions
  still in upstream support. The role is tested with a Debian and a Rocky Linux
  container running systemd. Locally `ansible-test --docker`.
- A test runs a playbook with `-vvv`, check mode and diff, and fails if any secret
  value appears in the output.
- Semantic versioning, changelog with `antsibull-changelog` fragments, `meta/runtime.yml`
  states the minimum ansible-core. Publish to Galaxy from a signed tag in CI with a
  Galaxy API key kept in repository secrets. Red Hat certification (Automation Hub)
  is not planned now.

## As built (2026-11-22)
- Repository `alexandrosnt/ansible-collection-certloom`, `requires_ansible: >=2.20.0`,
  CI on ansible-core 2.20, 2.21 and 2.22. The modules form the action group
  `certloom.certloom.certloom`, so `module_defaults` can set `url` and `token` once.
- Channels hold only a `credential_ref`, never a secret, so `update_secret` exists on
  `issuer` (EAB HMAC) and `dns_solver` (provider credential) only.
- `template` and `policy` compare the server's parsed form of the current and the
  planned document (`dry_run`), so YAML formatting or key order does not count as a
  change.
- The role covers Debian and Red Hat family hosts only; it is tested on Debian 13,
  Ubuntu 24.04 and Rocky Linux 9 containers running systemd. Windows tasks are left
  out until there is a Windows host to test them on.
- Local `.rpm` installs check signatures by default and certloom packages are not
  signed yet (M8), so the role has `certloom_agent_package_gpg_check` (default
  false); the required SHA-256 is checked either way.
- ansible-core 2.22 also redacts the values of `no_log` options everywhere they
  appear later in the run. The secret scan therefore mostly guards module return
  values and diffs; it was checked to fail when the enrollment token is printed.

## Industry practice (surveyed 2026-11-22)
| Who | Practice | Source |
|---|---|---|
| Venafi/CyberArk | `venafi.machine_identity`: policy and certificate modules on the vcert Python SDK, plus roles; separate repo; Red Hat certified | https://catalog.redhat.com/en/software/collection/venafi/machine_identity, https://github.com/Venafi/ansible-collection-venafi |
| Keyfactor | `keyfactor.platform`: REST API modules, separate repo, GitHub release tarballs, no SLA | https://github.com/Keyfactor/ansible-collection-keyfactor-platform |
| DigiCert TLM | No collection; ACME through `community.crypto` with sample playbooks | https://www.digicert.com/integrations/ansible |
| NetBox | `netbox.netbox`: modules on pynetbox, published on Galaxy, certified | https://docs.ansible.com/projects/ansible/latest/collections/netbox/netbox/index.html |
| Ansible docs | Shared code in the collection's `module_utils`; support check mode; return diff where it makes sense; split large APIs into small modules | https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_best_practices.html, https://docs.ansible.com/projects/ansible-core/2.15/playbook_guide/playbooks_checkmode.html |
| ansible.builtin.user | `update_password: always|on_create` for values that cannot be read back | (ansible-core module documentation) |

Not found: details for `community.hashi_vault` and `kubernetes.core` did not come up in
the search. Most vendors depend on their own Python SDK; certloom has none and does not
want a second client to maintain, so the modules use `fetch_url` instead.

## Consequences
- No pip dependencies; works with any controller that has a supported ansible-core.
- The API stays the public contract; the collection is a second client next to the Go
  client and must be updated when the API grows.
- Secret options cannot detect drift; `update_secret: always` makes those tasks always
  report `changed`.
- Agent packages are not in a repository yet, so users host the package or pass a file.

## Verification
- Sanity, unit and integration tests in CI as above, plus the idempotency check: every
  integration target runs its playbook twice and asserts `changed=false` the second
  time.
- Secret scan of playbook output in normal, check and diff modes.
- Role test enrolls a container host against the test server and checks the agent shows
  up in `agent_info`.
