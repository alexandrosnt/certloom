# Architecture decision records

Format: Status / Context / Options considered / Decision / Consequences / Verification.
Status values: Proposed, Accepted, Superseded by ADR-NNNN.

All ADRs below were reviewed and accepted on 2026-11-21. A change of direction
is a new ADR that supersedes the old one, not an edit.

External facts (library versions, CA behavior) were last checked on 2026-11-20.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-topology.md) | Deployment topology: modular monolith | Accepted |
| [0002](0002-storage.md) | Authoritative storage: PostgreSQL only | Accepted |
| [0003](0003-job-orchestration.md) | Durable jobs and workflow execution | Accepted |
| [0004](0004-agent-protocol.md) | Agent model and protocol | Accepted |
| [0005](0005-key-custody.md) | Private-key custody | Accepted |
| [0006](0006-acme.md) | ACME implementation | Accepted |
| [0007](0007-connector-contracts.md) | Connector/plugin contracts | Accepted |
| [0008](0008-authn-authz.md) | Authentication and authorization | Accepted |
| [0009](0009-secrets.md) | Secrets and credential references | Accepted |
| [0010](0010-api.md) | Public API style and contract | Accepted |
| [0011](0011-ui.md) | Web UI technology | Accepted |
| [0012](0012-audit.md) | Audit trail integrity | Accepted |
| [0013](0013-scheduling.md) | Scheduling and renewal timing | Accepted |
| [0014](0014-license-governance.md) | License, governance, release integrity | Accepted |
| [0015](0015-approvals.md) | Approvals and separation of duties | Accepted |
| [0016](0016-policy-exceptions.md) | Policy exceptions and acknowledgement | Accepted |
| [0017](0017-dns01.md) | DNS-01 challenges and wildcard certificates | Accepted |
| [0018](0018-central-dns-credentials.md) | Central DNS solvers and credential delivery | Accepted |
| [0019](0019-acme-eab.md) | ACME External Account Binding | Accepted |
| [0020](0020-certificate-templates.md) | Certificate templates | Accepted |
| [0021](0021-event-webhooks.md) | Event webhooks | Accepted |
| [0022](0022-windows-iis.md) | Windows agent, IIS / HTTP.sys bindings, win-acme discovery | Accepted |
| [0023](0023-kubernetes-observation.md) | Kubernetes observation of cert-manager and trust-manager | Accepted |
| [0024](0024-cloud-observation.md) | Read-only cloud certificate observation | Accepted |
| [0025](0025-terraform-provider.md) | Terraform/OpenTofu provider and public Go client | Accepted |
| [0026](0026-ansible-collection.md) | Ansible collection | Accepted |
| [0027](0027-plugin-sdk.md) | Out-of-process plugins with signed packages | Accepted |
| [0028](0028-private-ca-issuers.md) | Vault PKI and step-ca issuers | Accepted |
| [0029](0029-ca-inventory.md) | Root and intermediate CA inventory and rollover planning | Accepted |
| [0030](0030-trust-bundles.md) | Trust-bundle distribution and drift detection | Accepted |
| [0031](0031-release-integrity.md) | Signed releases, SBOMs and build provenance | Accepted |
| [0032](0032-airgapped-install.md) | Air-gapped installation | Accepted |
