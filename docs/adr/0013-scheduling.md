# ADR-0013: Scheduling and renewal timing

**Status:** Accepted (2026-11-21)

## Context
- Maximum lifetimes for public TLS certificates are shrinking: 200 days from 2026-03-15, 100 days from 2027-03-15, 47 days from 2029-03-15.
- Let's Encrypt offers a ~6-day `shortlived` profile and a 45-day `tlsserver` profile.
- ACME ARI (RFC 9773) lets a CA suggest a renewal window.
- Cron cannot express "renew inside an approved window, but never let the window cause expiry".

## Decision
Each activity has its own schedule, stored as data rather than as in-memory timers:

| Activity | Default (configurable by policy) |
|---|---|
| Endpoint probe | every 6 h +/- 10 % jitter |
| Discovery sync | every 24 h +/- jitter |
| ARI poll (M2) | follows the server's `Retry-After`, clamped to 1 h-24 h |
| Renewal eligibility | recomputed after every new observation or ARI result |
| Renewal execution | inside the maintenance window, if one is set |
| Retry (probes) | exponential backoff with full jitter: base 1 min, capped at the probe interval |
| Retry (issuance) | exponential backoff with full jitter: base 2 min, cap 1 h, 3 attempts per run; a CA `Retry-After` is honoured (up to 7 days) and does not use up an attempt; a failed run is retried 6 h later |

**When to renew, in order of precedence:**
1. If a valid ARI window exists, pick a random time inside it, as RFC 9773 specifies.
2. Otherwise, use the issuer-specific hint, if the connector provides one.
3. Otherwise, fall back to `NotBefore + p x (NotAfter - NotBefore)`. The default p is 2/3. Apply a minimum lead time: 7 days by default for lifetimes of 30 days or more, scaled down proportionally for short-lived certificates. These are starting values and must be tested.
4. In every case, add jitter so renewals spread across the allowed window.

**Safety deadline:** if no permitted maintenance window remains before `NotAfter - minimum_lead`:
- the run moves to `blocked` and raises a critical alert;
- if the policy sets `emergency: renew_outside_window`, the run goes ahead anyway, and the audit trail records that the window was overridden.

The scheduler never silently waits until the certificate expires.

**Time handling:**
- All times are stored in UTC.
- Maintenance windows are written in IANA time zones. They are evaluated against embedded tzdata (`time/tzdata`), so results do not depend on the host's zone files.
- Planned: `certloom schedule preview` shows the next N computed times, with the reason for each. Until then `certloom deployment list` shows the next renewal time and its reason.

## Verification
Table tests covering:
- DST transitions (e.g. Europe/Athens, America/New_York);
- ARI present, absent and invalid;
- very short (6-day) and long (398-day) lifetimes.
