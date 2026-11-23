-- +goose Up
-- Cloud accounts that certloomd reads itself, without an agent (ADR-0034).
-- A stored secret is encrypted with the KEK, bound to the account id, and
-- never returned by the API. The last inventory is kept without PEMs.
CREATE TABLE cloud_accounts (
  id                text PRIMARY KEY,
  org_id            text NOT NULL REFERENCES organizations(id),
  name              text NOT NULL,
  provider          text NOT NULL CHECK (provider IN ('aws','azure','gcp','cloudflare')),
  settings          jsonb NOT NULL DEFAULT '{}',
  credential        text NOT NULL CHECK (credential IN ('stored','ambient')),
  secret_ciphertext bytea,
  secret_updated_at timestamptz,
  interval_seconds  integer NOT NULL DEFAULT 3600 CHECK (interval_seconds >= 300),
  next_scan_at      timestamptz NOT NULL DEFAULT now(),
  last_scan_at      timestamptz,
  last_inventory    jsonb,
  version           bigint NOT NULL DEFAULT 1,
  created_by        text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name),
  CHECK (credential = 'stored' OR provider <> 'cloudflare')
);
CREATE INDEX cloud_accounts_due ON cloud_accounts (next_scan_at);

ALTER TABLE cloud_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON cloud_accounts
  USING (org_id = current_setting('app.org_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON cloud_accounts TO certloom_app;

-- +goose Down
DROP TABLE IF EXISTS cloud_accounts;
