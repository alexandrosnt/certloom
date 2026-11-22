-- +goose Up
-- CA inventory (ADR-0029). A CA certificate carries its authority key
-- (subject + public key, shared by cross-signed copies); every certificate
-- carries the authority whose key verified its signature, once known.
ALTER TABLE certificates
  ADD COLUMN ca_key              text,
  ADD COLUMN issuer_ca_key       text,
  -- true until the issuer link was attempted; existing rows are linked by
  -- the certificate sweep.
  ADD COLUMN issuer_link_pending boolean NOT NULL DEFAULT true;
CREATE INDEX certificates_ca_subject ON certificates (org_id, subject) WHERE is_ca;
CREATE INDEX certificates_ca_key ON certificates (org_id, ca_key) WHERE ca_key IS NOT NULL;
CREATE INDEX certificates_issuer_ca_key ON certificates (org_id, issuer_ca_key);
CREATE INDEX certificates_unlinked ON certificates (org_id, issuer) WHERE issuer_ca_key IS NULL;
CREATE INDEX certificates_link_pending ON certificates (org_id) WHERE issuer_link_pending;
-- The certificate itself stays immutable; only the derived links change.
GRANT UPDATE (ca_key, issuer_ca_key, issuer_link_pending) ON certificates TO certloom_app;

ALTER TABLE findings DROP CONSTRAINT findings_subject_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','issuer','deployment','k8s_object','cloud_object','authority'));
ALTER TABLE policy_exceptions DROP CONSTRAINT policy_exceptions_subject_type_check;
ALTER TABLE policy_exceptions ADD CONSTRAINT policy_exceptions_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','deployment','k8s_object','cloud_object','authority'));

-- +goose Down
DELETE FROM policy_exceptions WHERE subject_type = 'authority';
ALTER TABLE policy_exceptions DROP CONSTRAINT policy_exceptions_subject_type_check;
ALTER TABLE policy_exceptions ADD CONSTRAINT policy_exceptions_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','deployment','k8s_object','cloud_object'));
DELETE FROM alerts WHERE finding_id IN (SELECT id FROM findings WHERE subject_type = 'authority');
DELETE FROM findings WHERE subject_type = 'authority';
ALTER TABLE findings DROP CONSTRAINT findings_subject_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_subject_type_check
  CHECK (subject_type IN ('certificate','endpoint','lineage','issuer','deployment','k8s_object','cloud_object'));
REVOKE UPDATE (ca_key, issuer_ca_key, issuer_link_pending) ON certificates FROM certloom_app;
DROP INDEX certificates_link_pending, certificates_unlinked, certificates_issuer_ca_key, certificates_ca_key, certificates_ca_subject;
ALTER TABLE certificates DROP COLUMN issuer_link_pending, DROP COLUMN issuer_ca_key, DROP COLUMN ca_key;
