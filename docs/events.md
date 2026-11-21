# Events

Webhook endpoints (`certloom webhook create`) receive the event types they subscribe to,
by exact name or as `prefix.*` (ADR-0021). Delivery follows
[Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md).

## Request

```
POST <url>
content-type: application/json
webhook-id: evt_...                       # the event id; the same on every retry
webhook-timestamp: 1795286871             # seconds, time of this attempt
webhook-signature: v1,<base64> [v1,<base64>]
```

```json
{"type": "renewal.verified", "timestamp": "2026-11-21T18:30:00Z", "data": { ... }}
```

The signature is `base64(HMAC-SHA256(key, "<webhook-id>.<webhook-timestamp>.<body>"))`,
where the key is the base64-decoded part of the `whsec_...` secret. During the 24 hours
after `certloom webhook rotate-secret` the header carries one signature per secret.

A receiver should:
- verify with any Standard Webhooks library, or as above, comparing in constant time;
- reject timestamps more than 5 minutes from its own clock;
- deduplicate on `webhook-id` (delivery is at-least-once);
- answer 2xx quickly. 4xx other than 408 and 429 stops retries for that event; anything
  else is retried for about 23 hours. An endpoint that fails everything for 3 days is
  disabled.

## Compatibility

Fields are only added. A change that removes or changes the meaning of a field gets a
new type name ending in `.v2`, sent alongside the old one for a deprecation period.

## Lifecycle events

| Type | When | `data` |
|---|---|---|
| `certificate.issued` | The CA issued a certificate in a renewal run and it was recorded | `sha256`, `run_id`, `deployment_id`, `lineage_id`, `issuer_id`, `sans` |
| `deployment.created` | A deployment was created or requested | `deployment_id`, `lineage_id`, `agent_id`, `target`, `issuer_id`, `sans`, `challenge`, `template_id`, `approval` |
| `template.applied` | A certificate template version was applied | `template_id`, `name`, `version`, `deployments_changed` |
| `agent.enrolled` | An agent enrolled | `agent_id`, `name`, `hostname` |
| `agent.revoked` | An agent was revoked | `agent_id`, `name`, `by` |

## Notification events

These are the same events the notification channels get. Their `data` is the
notification: `event`, `org_id`, `subject_type`, `subject_id`, `subject` (a label),
`severity`, `message`, `at`, and for findings `finding_id`, `check`, `remediation`.

| Type | When |
|---|---|
| `renewal.verified` | A run deployed and verified a new certificate |
| `renewal.failed` | A run failed |
| `renewal.rolled_back` | A run restored the previous certificate |
| `renewal.cancelled` | A run was cancelled |
| `renewal.rolling_back` | A run started restoring the previous certificate |
| `renewal.blocked` | A due renewal cannot proceed (approval, window) |
| `renewal.rate_limited` | The CA rate-limited issuance |
| `renewal.window_override` | A renewal was activated outside its maintenance window |
| `approval.requested` | Someone asked for approval |
| `approval.approved` | A request was approved |
| `approval.denied` | A request was denied |
| `approval.revoked` | An approval was revoked |
| `approval.expired` | A request expired undecided |
| `approval.blocking_renewal` | A missing approval blocks a due renewal |
| `exception.requested` | A policy exception was requested |
| `exception.approved` | A policy exception was approved |
| `exception.denied` | A policy exception was denied |
| `exception.expiring` | A policy exception expires soon |
| `exception.expired` | A policy exception expired |
| `exception.revoked` | A policy exception was revoked |
| `finding.opened` | A check found a problem |
| `finding.escalated` | A finding became more severe |
| `finding.reopened` | A resolved or acknowledged finding is open again |
| `finding.resolved` | A finding went away |
| `alert.escalated` | An unacknowledged alert was escalated |
| `alert.ack_expired` | An acknowledgement lapsed and the alert is open again |

Events never carry private keys, secrets or sealed material.
