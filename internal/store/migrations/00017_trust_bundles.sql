-- +goose Up
-- Trust bundles pushed to agent trust stores (ADR-0030).
CREATE TABLE trust_bundles (
  id              text PRIMARY KEY,
  org_id          text NOT NULL REFERENCES organizations(id),
  name            text NOT NULL,
  team_id         text REFERENCES teams(id),
  current_version int  NOT NULL DEFAULT 0,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

-- Versions never change; anchors are certificate hashes in the inventory.
CREATE TABLE trust_bundle_versions (
  org_id       text NOT NULL,
  bundle_id    text NOT NULL REFERENCES trust_bundles(id) ON DELETE CASCADE,
  version      int  NOT NULL CHECK (version > 0),
  anchors      text[] NOT NULL,
  digest       text NOT NULL,
  created_by   text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  -- set when a removal was forced past the rollover checks
  force_reason text NOT NULL DEFAULT '',
  PRIMARY KEY (bundle_id, version)
);

CREATE TABLE trust_assignments (
  id                text PRIMARY KEY,
  org_id            text NOT NULL REFERENCES organizations(id),
  bundle_id         text NOT NULL REFERENCES trust_bundles(id) ON DELETE CASCADE,
  agent_id          text NOT NULL REFERENCES agents(id),
  store             text NOT NULL,
  confirmed_version int  NOT NULL DEFAULT 0,
  confirmed_at      timestamptz,
  sent_version      int  NOT NULL DEFAULT 0,
  sent_at           timestamptz,
  last_error        text NOT NULL DEFAULT '',
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, agent_id, store)
);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['trust_bundles','trust_bundle_versions','trust_assignments']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY org_isolation ON %I
                      USING (org_id = current_setting('app.org_id', true))
                      WITH CHECK (org_id = current_setting('app.org_id', true))$p$, t);
  END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT, UPDATE, DELETE ON trust_bundles, trust_assignments TO certloom_app;
GRANT SELECT, INSERT ON trust_bundle_versions TO certloom_app;

ALTER TABLE findings DROP CONSTRAINT findings_subject_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','issuer','deployment','k8s_object','cloud_object','authority','trust_store'));
ALTER TABLE policy_exceptions DROP CONSTRAINT policy_exceptions_subject_type_check;
ALTER TABLE policy_exceptions ADD CONSTRAINT policy_exceptions_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','deployment','k8s_object','cloud_object','authority','trust_store'));

-- +goose Down
DELETE FROM policy_exceptions WHERE subject_type = 'trust_store';
ALTER TABLE policy_exceptions DROP CONSTRAINT policy_exceptions_subject_type_check;
ALTER TABLE policy_exceptions ADD CONSTRAINT policy_exceptions_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','deployment','k8s_object','cloud_object','authority'));
DELETE FROM alerts WHERE finding_id IN (SELECT id FROM findings WHERE subject_type = 'trust_store');
DELETE FROM findings WHERE subject_type = 'trust_store';
ALTER TABLE findings DROP CONSTRAINT findings_subject_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','issuer','deployment','k8s_object','cloud_object','authority'));
DROP TABLE trust_assignments, trust_bundle_versions, trust_bundles;
