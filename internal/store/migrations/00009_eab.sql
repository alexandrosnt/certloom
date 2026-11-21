-- +goose Up
-- ACME External Account Binding (ADR-0019). HMAC keys are encrypted with the
-- KEK, bound to the issuer (reusable) or key row (single use), and never
-- returned by the API.
ALTER TABLE issuers
  ADD COLUMN eab_mode            text NOT NULL DEFAULT 'none' CHECK (eab_mode IN ('none','reusable','single_use')),
  ADD COLUMN eab_kid             text NOT NULL DEFAULT '',
  ADD COLUMN eab_hmac_ciphertext bytea,
  ADD COLUMN eab_updated_at      timestamptz;

-- Pool of single-use keys. A key is claimed by one agent, then consumed once
-- that agent reports the account as registered, or marked failed when the CA
-- refuses it.
CREATE TABLE eab_keys (
  id              text PRIMARY KEY,
  org_id          text NOT NULL REFERENCES organizations(id),
  issuer_id       text NOT NULL REFERENCES issuers(id),
  kid             text NOT NULL,
  hmac_ciphertext bytea NOT NULL,
  expires_at      timestamptz,
  state           text NOT NULL DEFAULT 'available' CHECK (state IN ('available','claimed','consumed','failed')),
  agent_id        text REFERENCES agents(id),
  claimed_at      timestamptz,
  done_at         timestamptz,
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (issuer_id, kid),
  CHECK ((state = 'available') = (agent_id IS NULL))
);
-- One open claim per agent and issuer, so retries reuse the same key.
CREATE UNIQUE INDEX eab_keys_claim ON eab_keys (issuer_id, agent_id) WHERE state = 'claimed';
CREATE INDEX eab_keys_available ON eab_keys (issuer_id, created_at) WHERE state = 'available';

ALTER TABLE eab_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE eab_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON eab_keys
  USING (org_id = current_setting('app.org_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON eab_keys TO certloom_app;

-- Issuers can now carry findings (EAB pool running out).
ALTER TABLE findings DROP CONSTRAINT findings_subject_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','issuer'));

-- +goose Down
DELETE FROM alerts WHERE finding_id IN (SELECT id FROM findings WHERE subject_type = 'issuer');
DELETE FROM findings WHERE subject_type = 'issuer';
ALTER TABLE findings DROP CONSTRAINT findings_subject_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage'));
DROP TABLE IF EXISTS eab_keys;
ALTER TABLE issuers DROP COLUMN eab_updated_at, DROP COLUMN eab_hmac_ciphertext, DROP COLUMN eab_kid, DROP COLUMN eab_mode;
