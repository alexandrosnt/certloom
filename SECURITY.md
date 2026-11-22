# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's
private vulnerability reporting ("Report a vulnerability" on the Security tab of
the affected repository: certloom, terraform-provider-certloom or
ansible-collection-certloom).

Include: affected version/commit, impact, reproduction steps, and whether the
issue is already public. Never include real private keys, credentials or
customer certificate data in a report; use test material.

## What we treat as security-sensitive

- Any path where private keys, ACME account keys, DNS/cloud credentials or PFX
  passwords could be logged, stored centrally, or exposed in API/CLI output.
- Authorization bypass, cross-organization data access.
- Unscoped network probing (SSRF) by the endpoint prober.
- Tampering with or suppressing audit events.
- Agent impersonation or forged tasks (from M2).
- Delivery of central DNS or EAB credentials to the wrong agent or task, or
  in plaintext (ADR-0018, ADR-0019).
- Bypassing approvals: a run that deploys something other than the approved
  spec (ADR-0015).
- Installing or running an agent plugin that no trusted publisher signed,
  or a plugin file changed after install (ADR-0027).
- Secrets in Terraform plan or state, or in Ansible output.

## Supported versions

Pre-1.0: only the latest commit on `main` receives fixes.
