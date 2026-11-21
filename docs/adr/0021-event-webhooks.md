# ADR-0021: Event webhooks

**Status:** Accepted (2026-11-21)

## Context
Notification channels (M1) tell people about findings and runs: a short human message,
routed by severity, signed with an HMAC over the body. Integrations need something else:
machine-readable events (a certificate was issued, a renewal failed, an approval is
waiting) to drive ticketing, CMDB updates, chat-ops and pipelines. The channel signature
also has no timestamp, so a captured request can be replayed.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Webhook endpoints subscribing to typed events, signed per Standard Webhooks** | Published signing scheme with replay protection and verifier libraries in many languages; event-type subscriptions like GitHub and Stripe | A second delivery path next to channels |
| B. CloudEvents envelope | CNCF standard, fits event buses | No signing scheme of its own |
| C. Event-type filters on existing channels | Least code | Keeps the replay-prone signature; mixes alerting with integration events |

## Decision
Option A. Channels stay as they are for people.

**Events**
- Written to an `events` table in the same transaction as the state change (ADR-0003
  outbox), with id, type, time, subject and data.
- Catalog v1: `certificate.issued`; `renewal.verified`, `renewal.failed`,
  `renewal.rolled_back`, `renewal.blocked`, `renewal.rate_limited`;
  `approval.requested`, `approval.approved`, `approval.denied`, `approval.revoked`,
  `approval.expired`; `exception.requested`, `exception.approved`, `exception.expired`,
  `exception.revoked`; `alert.opened`, `alert.escalated`, `alert.resolved`;
  `agent.enrolled`, `agent.revoked`; `deployment.created`; `template.applied`.
- Data carries ids, names, fingerprints, states and reasons; never keys, secrets or
  sealed material. Fields are only ever added; a breaking change gets a new type name
  with a `.v2` suffix. Schemas are documented in `docs/events.md` and as OpenAPI
  components.

**Endpoints**
- An endpoint has a URL, the event types it wants (exact names or a `prefix.*`), and a
  secret. certloom generates the secret (`whsec_` + 32 random bytes, base64), shows it
  once, and stores it under the KEK. Rotation keeps the old secret valid for 24 hours and
  signs with both meanwhile.
- The same SSRF guard as channels (no private, loopback or metadata addresses unless the
  endpoint allows private targets; no redirects; no environment proxy).
- Managing endpoints needs `webhooks:manage` (owner). Changes and rotations are audited.

**Delivery** ([Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md))
- Headers `webhook-id` (the event id, stable across retries), `webhook-timestamp`
  (seconds) and `webhook-signature` (`v1,` + base64 HMAC-SHA256 of
  `id.timestamp.body`). Body `{"type", "timestamp", "data"}`.
- At-least-once with exponential backoff for up to 24 hours. 2xx is success; 4xx other
  than 408 and 429 is permanent. Each attempt is logged (status, latency, error) and a
  delivery can be sent again by hand. Delivery logs are pruned after 30 days.
- An endpoint that has failed every delivery for 3 days is disabled and the owners are
  notified through the approval channels.

## Industry practice (surveyed 2026-11-21)
| Who | Approach |
|---|---|
| [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md) | `webhook-id`, `webhook-timestamp`, `webhook-signature`; HMAC over id, timestamp and body; receivers reject old timestamps |
| [OWASP Webhook Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Webhook_Security_Cheat_Sheet.html) | Signed payloads with timestamps against replay; SSRF protection on the sender |
| [DigiCert CertCentral](https://dev.digicert.com/en/certcentral-apis/webhooks/certcentral-event-types.html) | Typed events such as `certificate_issued` and revocations |
| [Cloudflare for SaaS](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/security/certificate-management/webhook-definitions/) | Typed events for validation, issuance, deployment, deletion and upcoming expiry |
| [AWS ACM](https://aws.amazon.com/blogs/security/how-to-manage-certificate-lifecycles-using-acm-event-driven-workflows) | EventBridge events: certificate available, approaching expiry, renewal failed |
| [Smallstep](https://smallstep.com/docs/platform/events) | Events and an expiry webhook |
| [Infisical](https://infisical.com/docs/documentation/platform/pki/alerting/webhook-alerts) | Alerts mapped to CloudEvents types |

No Venafi/CyberArk webhook reference was found.

Certificate platforms publish typed lifecycle events; the envelope varies (vendor JSON,
EventBridge, CloudEvents). For signing, Standard Webhooks is the one published scheme
with replay protection, so this decision uses it.

## Consequences
- Receivers verify with any Standard Webhooks library and dedupe on `webhook-id`.
- Two delivery paths exist: channels for people, endpoints for systems. A later change
  may move channel webhooks onto the same signing scheme.

## Verification
- Unit: signature against the Standard Webhooks test vectors; type filters; backoff.
- Workflow: events written with their state changes; delivery, retry, permanent failure,
  redelivery, rotation overlap, auto-disable; SSRF guard; no secret in events, logs or
  audit.
- e2e: a receiver in the ACME e2e verifies the signature of `renewal.verified` and
  `certificate.issued`.

## As built (2026-11-21)
- Migration 00011: `webhook_endpoints`, `events`, `webhook_deliveries` (a global queue
  like the outbox). An event is written only when at least one enabled endpoint
  subscribes to its type, so organizations without webhooks pay one small query per
  notification and nothing else.
- Every notification is also an event of the same name; its `data` is the notification.
  Catalog as delivered: see `docs/events.md` (it differs from the list above: findings
  use `finding.*`, and alerts only have `alert.escalated` and `alert.ack_expired`).
- The Standard Webhooks spec publishes only an asymmetric test vector and leaves the
  timestamp tolerance to receivers; signing is tested against the symmetric vector of
  its reference libraries, and the docs recommend 5 minutes.
- Responses that carry a secret (create, rotate) are exempt from Idempotency-Key storage
  and sent with `Cache-Control: no-store`.
- e2e: certloomd's worker delivers `renewal.verified` and `certificate.issued` from a real
  Pebble renewal to a receiver container, which verifies the signatures.
