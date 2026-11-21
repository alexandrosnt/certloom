# TODO / known issues

Not done yet, roughly in the order I want to tackle it.

## Renewal
- No command to change a deployment's issuer (e.g. staging to production); today it
  means recreating the deployment.
- `certloom-dns-lego` plugin: many lego providers keep the record id in memory between
  present and cleanup, so they need a long-running plugin (HTTP transport) or a
  per-provider answer.
- DNS-01: lego resolves the authoritative nameservers' names through the system resolver,
  not `resolvers`; split-horizon setups may need an option to check through the
  configured resolvers only.
- Cloudflare DNS has only mock-API tests; run it once live against a test zone.
- EAB: live runs against a commercial CA (only Pebble so far), and recording per CA
  whether accounts survive revocation of the key that registered them.
- EAB keys come from the database only; vault references with ADR-0009 Phase 6.
- Central DNS credentials come from the database only; Vault and cloud secret-manager
  references are planned with the ADR-0009 Phase 6 providers (ADR-0018).
- No web UI for approvals and exceptions yet (API and CLI only).
- `deployment list` shows the stored approval state; a legacy deployment under required
  approvals still shows "approved" until it is next checked.

## Control plane
- systemd unit and a non-Docker install guide for `certloomd`. With a distro PostgreSQL
  the owner role needs `CREATEROLE` (PG 16+), because the first migration creates
  `certloom_app`.
- `test/acme` pulls `pebble:latest`; pin it.
- UI pages for members, policy and channels (CLI only for now).
- `certloom schedule preview` (next renewal and window times with reasons).
- Rate limits are per process.
- Only one `certloomd` replica has been tested.
- `members` has no RLS on purpose (sign-in needs it before the org is known); maybe move
  the lookup into a SECURITY DEFINER function instead.
- OpenAPI check only compares routes, not request/response bodies.
- sqlc instead of hand-written queries once the schema settles.

## Decided
- Agents never start issuance on their own while the control plane is down.
- Agent channel is HTTPS + JSON over mTLS rather than gRPC.
- Wildcard certificates only with DNS-01, listed literally in `allowed_sans`.

## Open questions
- Where to publish images and packages.
- What "medium install" means for load tests.

## Scale notes (local, 2026-11-20)
10k certs + 2k endpoints on one box: sweep 6s, overview 18ms, probing ~550/s against
a local TLS server (real networks will be slower). `CERTLOOM_SCALE=1 go test ./test/scale/`.
