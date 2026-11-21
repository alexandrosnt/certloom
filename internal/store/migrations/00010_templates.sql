-- +goose Up
-- Certificate templates (ADR-0020). A deployment references a template; each
-- apply stores a new version and re-resolves every deployment using it.
CREATE TABLE templates (
  id              text PRIMARY KEY,
  org_id          text NOT NULL REFERENCES organizations(id),
  name            text NOT NULL,
  current_version int NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

CREATE TABLE template_versions (
  template_id text NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
  org_id      text NOT NULL REFERENCES organizations(id),
  version     int NOT NULL,
  document    jsonb NOT NULL,
  source      text NOT NULL,
  created_by  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (template_id, version)
);

ALTER TABLE deployments ADD COLUMN template_id text REFERENCES templates(id);
CREATE INDEX deployments_template ON deployments (template_id) WHERE template_id IS NOT NULL;

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['templates','template_versions']
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

GRANT SELECT, INSERT, UPDATE, DELETE ON templates TO certloom_app;
GRANT SELECT, INSERT, DELETE ON template_versions TO certloom_app;

-- +goose Down
ALTER TABLE deployments DROP COLUMN IF EXISTS template_id;
DROP TABLE IF EXISTS template_versions, templates;
