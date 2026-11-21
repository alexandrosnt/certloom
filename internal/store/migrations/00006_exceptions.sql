-- +goose Up
-- Findings record which version of their check produced them and a
-- fingerprint of the condition (which certificate, which failure), so that
-- an exception accepted for one condition never covers a different one.
-- Findings from before this migration get an empty fingerprint and are
-- refreshed by the next probe or sweep.
ALTER TABLE findings
  ADD COLUMN check_version int NOT NULL DEFAULT 1,
  ADD COLUMN fingerprint   text NOT NULL DEFAULT '';

-- Policy exceptions: approved, time-bound acceptance of one condition (check,
-- check version and fingerprint) on one subject. They suppress the alert,
-- never the finding. Everything the approver approved is immutable: the app
-- role may only update the state columns.
CREATE TABLE policy_exceptions (
  id                     text PRIMARY KEY,
  org_id                 text NOT NULL REFERENCES organizations(id),
  subject_type           text NOT NULL CHECK (subject_type IN ('certificate','endpoint','lineage')),
  subject_id             text NOT NULL,
  check_id               text NOT NULL,
  check_version          int NOT NULL,
  fingerprint            text NOT NULL CHECK (fingerprint <> ''),
  max_severity           text NOT NULL CHECK (max_severity IN ('warning','critical')),
  rationale              text NOT NULL CHECK (rationale <> ''),
  compensating_controls  text NOT NULL DEFAULT '',
  risk_owner             text NOT NULL CHECK (risk_owner <> ''),
  remediation_owner      text NOT NULL DEFAULT '',
  remediation_due        date,
  tracking_ref           text NOT NULL DEFAULT '',
  evidence               jsonb NOT NULL,          -- the finding as the approver saw it
  expires_at             timestamptz NOT NULL,
  state                  text NOT NULL DEFAULT 'requested'
                           CHECK (state IN ('requested','active','denied','expired','revoked')),
  requested_by           text NOT NULL,
  created_at             timestamptz NOT NULL DEFAULT now(),
  approved_by            text,
  approved_at            timestamptz,
  ended_at               timestamptz,
  ended_by               text,
  end_reason             text NOT NULL DEFAULT '',
  reminded_at            timestamptz,
  CHECK (approved_by IS NULL OR approved_by <> requested_by),
  CHECK ((state = 'active') = (approved_at IS NOT NULL AND ended_at IS NULL))
);
-- At most one exception in force or waiting per subject and check.
CREATE UNIQUE INDEX policy_exceptions_one_live ON policy_exceptions (org_id, subject_type, subject_id, check_id)
  WHERE state IN ('requested','active');
CREATE INDEX policy_exceptions_state ON policy_exceptions (org_id, state, expires_at);

ALTER TABLE policy_exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_exceptions FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON policy_exceptions
  USING (org_id = current_setting('app.org_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true));
GRANT SELECT, INSERT ON policy_exceptions TO certloom_app;
GRANT UPDATE (state, approved_by, approved_at, ended_at, ended_by, end_reason, reminded_at) ON policy_exceptions TO certloom_app;

ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_resource_type_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_resource_type_check CHECK (resource_type IN ('deployment','exception'));
-- The request and its spec are immutable once made; only the decision
-- columns change.
REVOKE UPDATE ON approvals FROM certloom_app;
GRANT UPDATE (state, decided_by, decided_at, reason, revoked_by, revoked_at, revoke_reason) ON approvals TO certloom_app;

-- +goose Down
GRANT UPDATE ON approvals TO certloom_app;
ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_resource_type_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_resource_type_check CHECK (resource_type IN ('deployment'));
DROP TABLE IF EXISTS policy_exceptions;
ALTER TABLE findings DROP COLUMN IF EXISTS fingerprint, DROP COLUMN IF EXISTS check_version;
