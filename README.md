# certloom

Self-hosted certificate lifecycle management. It keeps an inventory of your TLS
certificates, watches what your endpoints actually serve, alerts before things expire,
and (for Linux/Nginx hosts running `certloom-agent`) renews and deploys certificates over
ACME. A renewal counts as done only once the endpoint is seen serving the new certificate.

Early days. What works today:

- Inventory: import PEM/DER/PKCS#12 (keys are never stored), probe endpoints, track lineages and owners.
- Checks and alerts: expiry, chain, hostname, weak keys, "endpoint serves the wrong cert". Webhook and email alerts.
- Renewal: `certloom-agent` on Linux + Nginx, ACME HTTP-01, atomic switch, `nginx -t`, reload, verify, rollback.
- Ops: REST API (`api/openapi.yaml`), `certloom` CLI, small web UI, OIDC sign-in, audit log with external export.

Everything else in `docs/integration-matrix.md` is planned, not done.

## Layout

```
cmd/certloomd        control plane (API, UI, scheduler, workers, agent listener)
cmd/certloom         CLI
cmd/certloom-agent   host agent
internal/       everything else
deploy/compose  single-node install
deploy/systemd  certloom-agent systemd unit
deploy/packaging  certloom-agent deb/rpm packages (nfpm)
docs/           ADRs, threat model, runbooks
test/           e2e, workflow and scale tests
```

## Build and test

```sh
go build ./cmd/...
go test ./...                                   # unit tests
CERTLOOM_TEST_DATABASE_URL=postgres://... go test ./... # + database, workflow and e2e tests (needs Docker for e2e)
CERTLOOM_ACME_E2E=1 go test ./test/acme/                 # full ACME/Nginx/agent run against Pebble (Docker)
```

To run it: `deploy/compose/README.md`. For agents (including the deb/rpm packages and
the systemd unit, built with `deploy/packaging/build.sh`): `docs/runbooks/agent.md`.
Open items: `docs/TODO.md`.

## License

Apache-2.0. Contributions need a DCO sign-off (`git commit -s`), see `CONTRIBUTING.md`.
