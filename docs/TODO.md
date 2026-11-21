# TODO / known issues

Not done yet, roughly in the order I want to tackle it.

## Renewal
- No command to change a deployment's issuer (e.g. staging to production); today it
  means recreating the deployment.
- DNS-01, EAB, wildcards (M3).

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
- No wildcard certificates until DNS-01.

## Open questions
- Where to publish images and packages.
- What "medium install" means for load tests.

## Scale notes (local, 2026-11-20)
10k certs + 2k endpoints on one box: sweep 6s, overview 18ms, probing ~550/s against
a local TLS server (real networks will be slower). `CERTLOOM_SCALE=1 go test ./test/scale/`.
