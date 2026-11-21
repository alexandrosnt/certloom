-- +goose Up
-- Last inventory per agent: IIS bindings, win-acme renewals and Kubernetes
-- objects (ADR-0022, ADR-0023). Public data only; agents never send keys.
CREATE TABLE agent_inventories (
  agent_id     text PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
  org_id       text NOT NULL REFERENCES organizations(id),
  data         jsonb NOT NULL,
  reported_at  timestamptz NOT NULL
);
ALTER TABLE agent_inventories ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_inventories FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON agent_inventories
  USING (org_id = current_setting('app.org_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true));
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_inventories TO certloom_app;

-- Periodic inventory: when the last task was queued for the agent.
ALTER TABLE agents ADD COLUMN inventory_requested_at timestamptz;

-- Binding drift is a finding on a deployment; Kubernetes conditions are
-- findings on the observed object (subject id agent/kind/namespace/name).
ALTER TABLE findings DROP CONSTRAINT findings_subject_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','issuer','deployment','k8s_object'));
ALTER TABLE policy_exceptions DROP CONSTRAINT policy_exceptions_subject_type_check;
ALTER TABLE policy_exceptions ADD CONSTRAINT policy_exceptions_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','deployment','k8s_object'));

-- +goose Down
DELETE FROM policy_exceptions WHERE subject_type IN ('deployment','k8s_object');
ALTER TABLE policy_exceptions DROP CONSTRAINT policy_exceptions_subject_type_check;
ALTER TABLE policy_exceptions ADD CONSTRAINT policy_exceptions_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage'));
DELETE FROM alerts WHERE finding_id IN (SELECT id FROM findings WHERE subject_type IN ('deployment','k8s_object'));
DELETE FROM findings WHERE subject_type IN ('deployment','k8s_object');
ALTER TABLE findings DROP CONSTRAINT findings_subject_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','issuer'));
ALTER TABLE agents DROP COLUMN inventory_requested_at;
DROP TABLE IF EXISTS agent_inventories;
