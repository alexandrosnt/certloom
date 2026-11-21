-- +goose Up
-- Findings on certificates held by cloud services (ADR-0024); subject id
-- agent/provider/scope/resource id.
ALTER TABLE findings DROP CONSTRAINT findings_subject_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','issuer','deployment','k8s_object','cloud_object'));
ALTER TABLE policy_exceptions DROP CONSTRAINT policy_exceptions_subject_type_check;
ALTER TABLE policy_exceptions ADD CONSTRAINT policy_exceptions_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','deployment','k8s_object','cloud_object'));

-- +goose Down
DELETE FROM policy_exceptions WHERE subject_type = 'cloud_object';
ALTER TABLE policy_exceptions DROP CONSTRAINT policy_exceptions_subject_type_check;
ALTER TABLE policy_exceptions ADD CONSTRAINT policy_exceptions_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','deployment','k8s_object'));
DELETE FROM alerts WHERE finding_id IN (SELECT id FROM findings WHERE subject_type = 'cloud_object');
DELETE FROM findings WHERE subject_type = 'cloud_object';
ALTER TABLE findings DROP CONSTRAINT findings_subject_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','issuer','deployment','k8s_object'));
