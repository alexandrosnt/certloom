# ADR-0009: Secrets and credential references

**Status:** Accepted (2026-11-21)

## Decision
Configuration and policies never hold secret values. They hold a
`CredentialReference`: `provider`, `path/name`, and an optional `version`.

**v1 providers**
1. `env` / `file`, for containers and systemd credentials.
2. `db`: secrets stored in Postgres with envelope encryption.
   - Each secret gets its own random data key (AES-256-GCM).
   - Data keys are wrapped by a key-encryption key (KEK). The KEK is loaded from a file or env var at startup and is never stored in the DB.

Vault, cloud secret managers and KMS-held KEKs arrive in Phase 6.

**Secrets in code**
- Secret values travel in a `secret.Value` type. Its `String`, `GoString`, `Format` and `MarshalJSON` all return `[REDACTED]`.
- Getting the bytes requires an explicit `.Reveal()` call, which is easy to spot in review.

The internal agent CA key and the task-signing key (ADR-0004) are stored through the same mechanism.

## Alternatives rejected
- Plaintext in config: prohibited.
- Requiring Vault for every install: too heavy for small teams.

## Consequences
If the KEK is lost, secrets stored in the DB cannot be recovered. Backup/restore runbooks must cover the KEK separately from the DB dump.

## Verification
- Unit tests check redaction on every formatting path.
- An e2e log-scan test confirms no secret value appears in the logs.
