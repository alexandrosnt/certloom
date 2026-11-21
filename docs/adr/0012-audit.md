# ADR-0012: Audit trail integrity

**Status:** Accepted (2026-11-21)

## Context
The audit trail has to hold up against a hostile or careless operator well enough to
serve as evidence, without overstating how tamper-proof it is.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Append-only table + per-org hash chain + continuous export to an external sink** | Tampering inside the DB is detectable; the external copy is out of the DB admin's reach | The external sink must be configured to get the real benefit |
| B. DB table only | Simple | A DB admin can rewrite history and nobody can tell |
| C. Mandatory external WORM store | Strongest guarantee | Too heavy for small installs |

## Decision
Option A.

- **Same transaction:** each `audit_events` row is written in the same transaction as the change it records.
- **Append-only:** the application's DB role can only INSERT and SELECT on the table.
- **Hash chain (per organization):** each event stores `prev_hash`, plus `hash = SHA-256(canonical_json(event) || prev_hash)`.
- **External export:** an exporter streams events to a file, syslog or webhook. Delivery is at-least-once, and the exporter tracks the last sequence number it exported.
- **Verification command:** `certloom audit verify` recomputes the chain.
- **Wording:** the docs say plainly that the hash chain alone does not make the audit trail immutable. The external export is what makes tampering hard.
- **No secrets:** events never contain secret values. Payloads are built from an allowlist of fields.

## Verification
Test: a superuser modifies one row, and `certloom audit verify` reports the first broken sequence number.
