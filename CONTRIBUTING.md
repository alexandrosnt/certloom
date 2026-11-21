# Contributing

## Developer Certificate of Origin

Every commit must be signed off (`git commit -s`), certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).

## Ground rules

- Read the ADRs in `docs/adr/` before proposing architectural changes; changing
  a decision means a new ADR that supersedes the old one.
- Never commit real private keys, credentials or customer certificates. Test
  material lives under `testdata/` and must be generated for tests.
- A connector capability is only listed as supported in
  `docs/integration-matrix.md` once it has a named test proving it.
- Mutating operations need dry-run support, audit events and a failure test.

## Checks

`go vet ./...`, `go test -race ./...`, golangci-lint, govulncheck and gitleaks
run in CI and must pass.
