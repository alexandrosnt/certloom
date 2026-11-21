# Changelog

## Unreleased

### Added
- Tested against Let's Encrypt staging: issuance, renewal with `replaces`, ARI
  scheduling and rollback on a real host.
- Maintenance windows per deployment (`certloom deployment set-window`, e.g.
  "Mon-Fri 02:00-05:00 Europe/Athens"). Activation waits for the window; if no
  window starts before the current certificate gets too close to expiry the run is
  blocked with a critical alert, or proceeds when the deployment allows
  `renew_outside_window` (audited).
- Rate-limited ACME orders honour the CA's Retry-After and do not use up attempts.
- systemd unit and deb/rpm packages for `certloom-agent` (`deploy/packaging/build.sh`).
- Web UI pages for agents, deployments (with "Renew now") and runs (with cancel).
- Agent (`certloom-agent`): mTLS enrollment with CA pinning, signed tasks, local key
  generation, ACME HTTP-01 via lego, atomic Nginx activation with `nginx -t`,
  reload, local verification and rollback. Read-only Certbot discovery.
- Renewal workflow: checkpointed runs (issue, deploy, verify), retries, rollback,
  external verification through the prober, ARI-based scheduling with fallback.
- `certloom agent|issuer|deployment|run` commands.
- OIDC sign-in (auth code + PKCE in the browser, device flow in the CLI) and members.
- External audit export (file or signed webhook) and `certloomd audit-verify-export --compare`.
- Idempotency keys, ETag/If-Match, rate limits, OpenAPI spec checked against the router.
- Versioned monitoring policy (`certloom policy`), alert escalation, observation pruning.
- Inventory, endpoint probing, checks, alerts, audit log, API, CLI and web UI.
- Docker image and a Compose setup with a tested backup/restore procedure.

### Fixed
- An ARI check that was still running when a renewal finished could overwrite the new
  certificate's schedule with the old certificate's, delaying the next ARI check by a day.
- Agents reported `0.0.0-dev` as their version instead of the version they were built with.
- Renewing a certificate from another CA (or from Let's Encrypt staging) failed every
  attempt, because the CA refused the `replaces` hint. When an order is refused as
  `malformed`, `unauthorized` or `alreadyReplaced`, the agent now logs it and orders once
  more without the hint.
- Session cookies are marked Secure from a server setting instead of per request, so
  they stay Secure behind a TLS-terminating proxy (`CERTLOOM_SECURE_COOKIES=true`).
- Audit export to a file reports errors from closing the file.
- The CLI cancels in-flight requests on Ctrl+C; SMTP delivery honours cancellation.
- An order whose predecessor was already marked replaced is retried without `replaces`.
- A task interrupted by an agent crash is reported as interrupted (outcome unknown)
  instead of a replay error, and the run rolls back.
- Agent restore after a failed `nginx -t` no longer runs a reload that fails for the same reason.
- Wildcard SANs are refused (an allowlist pattern used to authorize a literal wildcard cert).
- Agent sequence fence can no longer move backwards.
- Lost wake-ups and clock-skew stalls in the workflow engine.
- Scheduler re-selected endpoints that already had a queued probe.
- Windows: "connection refused" was misclassified.
- `certloom login --ca-file` stored a relative path.
