# ADR-0008: Authentication and authorization

**Status:** Accepted (2026-11-21)

## Context
Viewing, requesting, approving, deploying, revoking and exporting must be separate
permissions. Small installs must work without an identity provider (IdP).

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Built-in RBAC with resource scopes; OIDC for people; hashed API tokens for automation** | No extra service to run; fits small and large installs | We own and maintain the permission model |
| B. External policy engine (OPA/Casbin) | Very expressive | Another moving part; harder to explain and test at this stage |
| C. Local username/password only | Simple | Weak; no SSO or MFA |

## Decision
Option A.

**People**
- The UI signs in with OIDC (authorization code + PKCE); the CLI uses the OAuth device flow. MFA comes from the IdP.
- On first start, a one-time setup token creates a single bootstrap admin, so installs without an IdP still work. Disable that account once OIDC is configured.

**Automation**
- API tokens are shown once and stored only as a hash.
- Each token carries a role, a scope and an expiry, and can be revoked.

**Permission model**
- A permission is a (verb, resource type) pair, granted to a role within a scope: org -> team -> environment.
- M1 roles: Owner, Operator, Viewer, Auditor.
- M3 adds Requester, Approver, Deployment Operator and Issuer Admin, with separation of duties: a requester cannot approve their own request.

**Enforcement**
- Checks run in the service layer, not only in HTTP handlers, and run again inside workflow actions at execution time.
- Postgres row-level security on `org_id` is a second line of defense.

v1 has no "export private key" permission, because nothing in v1 can export keys (ADR-0005).

## Verification
- A table-driven authz matrix test covers every role against every endpoint.
- Any cross-org access returns 404.
- An RLS test runs a deliberately unscoped query and confirms it sees only its own org's rows.
