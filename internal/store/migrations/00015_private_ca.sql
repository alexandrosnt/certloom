-- +goose Up
-- Vault PKI and step-ca issuers (ADR-0028). The control plane signs a CSR
-- from the agent, so these deployments have no ACME challenge.
ALTER TABLE issuers DROP CONSTRAINT IF EXISTS issuers_kind_check;
ALTER TABLE issuers ADD CONSTRAINT issuers_kind_check CHECK (kind IN ('acme','vault','stepca'));
ALTER TABLE issuers
  -- Non-secret, kind-specific settings (mount, role, provisioner, ...).
  ADD COLUMN settings              jsonb NOT NULL DEFAULT '{}',
  -- PEM roots trusted for TLS to the CA; empty for ACME (system roots).
  ADD COLUMN ca_bundle             text NOT NULL DEFAULT '',
  -- Vault secret_id or token, or the step-ca provisioner JWK, under the KEK.
  ADD COLUMN credential_ciphertext bytea,
  ADD COLUMN credential_updated_at timestamptz;

ALTER TABLE deployments DROP CONSTRAINT IF EXISTS deployments_challenge_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_challenge_check CHECK (challenge IN ('http-01','dns-01','none'));

-- +goose Down
ALTER TABLE deployments DROP CONSTRAINT IF EXISTS deployments_challenge_check;
ALTER TABLE deployments ADD CONSTRAINT deployments_challenge_check CHECK (challenge IN ('http-01','dns-01'));
ALTER TABLE issuers DROP COLUMN credential_updated_at, DROP COLUMN credential_ciphertext,
  DROP COLUMN ca_bundle, DROP COLUMN settings;
ALTER TABLE issuers DROP CONSTRAINT IF EXISTS issuers_kind_check;
ALTER TABLE issuers ADD CONSTRAINT issuers_kind_check CHECK (kind IN ('acme'));
