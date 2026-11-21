# ADR-0015: Approvals and separation of duties

**Status:** Accepted (2026-11-21)

## Context
ADR-0008 promises Requester and Approver roles, and a rule that nobody approves their own
request. Renewals are fully automated, and public certificate lifetimes are heading for
47 days (ADR-0013). Unattended renewal is an availability requirement: an approval step
on every renewal would bring back the expiry outages that automation exists to prevent.

The goal is to authorize changes to what is issued and where it is deployed, not to put
a person in the path of routine renewals.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Approve the deployment spec once; renewals of that exact spec need no new approval** | Keeps renewals automatic; approval guards what changes (new names, another CA, another host) | A compromised approver approves once for the lifetime of the spec |
| B. Approve every run | Strongest control | Certificates expire when nobody approves in time; people approve on reflex |
| C. Both, chosen by policy | Flexible | Twice the code and test surface for a mode with no known user yet |

## Decision
Option A. Per-run approvals stay out of the initial implementation.

**What an approval covers**
- A SHA-256 digest of a canonical, versioned `DeploymentSpec` (`store.SpecVersion`):
  lineage, normalized SANs, purpose (`tls-server`), key algorithm, the effective issuer
  (id, kind, directory URL, profile) and the effective target (agent, target name, target
  type as reported by the agent, plus connector attributes such as a cloud account or
  cluster id once such targets exist).
- References are resolved, so editing an issuer's directory URL or profile, or an agent
  reporting a different target type, voids the approval just like editing the deployment.
- Secrets and operational settings (maintenance window, endpoint used for verification)
  are not part of it.
- The key algorithm is sent in the issue task and enforced by the agent, which refuses
  algorithms it does not know.

**Where it is enforced**
- A run records the digest it was started for. The scheduler, run start, the step before
  ordering a certificate, and every step before deployment check that the deployment is
  approved, that the approval covers the current effective spec, and that the spec still
  equals the run's digest. Otherwise the run is cancelled without touching the target;
  a certificate already issued is not deployed.
- A due renewal that is blocked on approval raises a notification once a day, so it is
  not silently left to expire.

**When approval is needed**
- When the creator lacks `deployments:manage` (the Requester role), or when the policy sets
  `approvals.deployments: required`. The default is `optional`, so a single-admin install
  keeps working.
- Deployments created before approvals existed have no recorded digest. They keep renewing
  while approvals are optional, but once they are required, such a deployment needs an
  explicit approval before its next issuance (`certloom deployment request-approval`).

**Who decides**
- Only signed-in people (`user:` principals). API tokens never decide, and approver tokens
  cannot be created.
- Nobody decides their own request, compared case-insensitively and following API-token
  provenance: whoever created the token, or chain of tokens, that made a request cannot
  decide it. Owners are bound by the same rule. certloom has no groups or impersonation;
  if either is added, the check must follow it the same way.
- Tokens minted by the bootstrap token trace back to no person and cannot be checked
  further. Disable the bootstrap token once OIDC is configured (ADR-0008).
- Denying needs a reason. Requests expire after `approvals.expireAfter` (default 7d,
  1h-30d).

**Revocation**
- An owner or approver can revoke a deployment's approval with a reason
  (`certloom deployment revoke-approval`). Runs stop at their next checkpoint before
  changing the target. Revoking needs no second person, since it only makes things safer.

**Records and routing**
- Every request, decision, revocation and expiry is audited. Approval events go to the
  channels in `approvals.channels`, or to all channels when it is empty.

**Roles**
- `requester` (request), `approver` (decide, revoke), `deployment_operator` (manage
  deployments, run renewals), `issuer_admin` (issuers). Only `owner` holds both request and
  decide permissions, and it is still bound by the self-approval rule.

## Consequences
- Changing what goes into `DeploymentSpec` changes every digest and voids every approval,
  so it needs a new `SpecVersion` and a plan for existing approvals.
- Switching the policy back to `optional` is an audited owner action, not an approved one.
  Owners can relax the control, but not quietly.
- Per-run approvals can still be added later as a policy value, with no change to the
  stored data.

## Verification
`test/workflow/approval_test.go` covers:
- refusals: self-approval, approval by the token's creator, token approvals, and operators;
- a pending deployment never renews;
- a spec changed through the deployment, the issuer or the agent's target type before the
  decision cannot be approved;
- revocation, and a change after approval, both cancel a run that issued but has not
  deployed yet;
- legacy deployments under required approvals, with the daily blocked-renewal
  notification;
- channel routing, expiry and deny.

`internal/agent` covers the agent refusing unknown key algorithms, and `internal/authz`
checks that no role except owner can both request and approve.
