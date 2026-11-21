# ADR-0016: Policy exceptions and acknowledgement

**Status:** Accepted (2026-11-21)

## Context
Some findings cannot be fixed right away: a legacy appliance that only does RSA 1024, a
certificate a vendor controls. Risk acceptance needs a named approver, an accountable
owner, a rationale, compensating controls, an expiry and an untouchable record.
Acknowledging an alert must not become a quiet way around that, least of all on a
single-admin install where no second person can approve.

The goal is risk acceptance that is temporary, accountable, auditable and narrow.

## Decision

**Acknowledgement is not acceptance**
- Acknowledging records that someone saw an alert. The finding stays open and visible
  and keeps counting in every metric.
- An acknowledgement lapses after `alerts.ackExpiry` (default 7d, 1h-30d). If the
  finding is still open, the alert opens again and notifies (`alert.ack_expired`). This
  applies even when escalation is off.
- There is no other way to snooze or silence an alert. Only an approved exception
  suppresses one.

**What an exception covers**
- One condition on one subject: canonical subject id (certificate SHA-256, endpoint or
  lineage id), check id, check-definition version, and a fingerprint of the condition.
  The fingerprint covers which certificate for certificate checks, the served leaf and
  expected name or lineage for endpoint checks, and the failure class for probe failures.
- An exception survives a finding being resolved and found again (new finding id), but
  never covers a different condition under the same check. A different key, another
  served certificate, or a new check version means alerting comes back at once
  (`finding.reopened`).
- It is never a pattern or a team scope.

**Severity is a ceiling**
- The accepted severity is the finding's current severity; it cannot be raised.
- The finding is checked again when the approval is given: it must still be open, with
  the same check version and fingerprint, and no worse.
- Any later escalation restores alerting immediately.

**Checks that cannot be accepted**
- `exceptions.prohibitedChecks` lists checks for which no exception may be requested or
  approved. Adding a check there revokes requested and active exceptions for it at once.
- Future checks for confirmed key compromise or revocation belong on this list in the
  shipped example policy.

**Approval**
- Always by someone else, through ADR-0015: signed-in people only, never the requester or
  the creator of the requesting token. The approval covers a digest of the whole request:
  condition, severity, rationale, controls, owners, dates and evidence.
- Extending an exception means a new request and a new approval.

**Expiry is authoritative**
- At most `exceptions.maxDuration` (default 90d, 1d-365d).
- Whether an exception covers a finding is decided at the moment it is consulted
  (`now()`), in alert listings, metrics, notifications and the sweep alike. An expired or
  revoked exception stops suppressing immediately; the sweep only brings the stored
  state into line.
- A reminder goes out once, 7 days before expiry, or half way through the exception's
  approved lifetime if that is sooner.

**Accountability and evidence**
- Required: rationale and risk owner.
- Optional: compensating controls, remediation owner, planned remediation date and a
  tracking reference.
- The finding as the requester saw it is stored as evidence.
- The application role may only update the state columns of `policy_exceptions` and
  `approvals` (column-level grants), so the request, its spec and its evidence cannot be
  rewritten. Every request, decision, revocation, reminder and expiry is in the
  hash-chained audit log with the full spec.

**Visibility**
- An exception suppresses the alert only. The finding keeps `exception_id`, still counts
  in every metric, and is also counted under "accepted risk" so reviewers see it.

**Permissions**
- `exceptions:request`: owner, operator, requester.
- Approving and revoking: `approvals:decide`. Revoking only restores alerting, so it needs
  no second person; an owner token may do it.

## Consequences
- Single-admin installs cannot accept risk; they can acknowledge, and the alert returns.
- Findings recorded before fingerprints existed cannot be excepted until the next probe or
  sweep refreshes them.
- Bumping a check's version voids its exceptions; that is intended.

## Verification
- `test/workflow/exception_test.go` covers:
  - authorization for request, approval and revocation, including API-token provenance;
  - condition matching, and revalidation on approval;
  - prohibited checks, immediate expiry and reminders for short exceptions;
  - immutability of requests and approvals;
  - acknowledgement lapsing.
- `internal/checks` checks that fingerprints are stable and distinct, and
  `internal/policy` validates the settings.
