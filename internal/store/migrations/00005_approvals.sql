-- +goose Up
-- Roles for separation of duties, and approvals for deployment specs.
ALTER TABLE api_tokens DROP CONSTRAINT IF EXISTS api_tokens_role_check;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_role_check
  CHECK (role IN ('owner','operator','viewer','auditor','requester','approver','deployment_operator','issuer_admin'));
ALTER TABLE members DROP CONSTRAINT IF EXISTS members_role_check;
ALTER TABLE members ADD CONSTRAINT members_role_check
  CHECK (role IN ('owner','operator','viewer','auditor','requester','approver','deployment_operator','issuer_admin'));

-- A deployment may renew only while approval = 'approved' and the approved
-- spec digest still matches its effective spec. approved_spec_sha256 is NULL
-- for deployments created before approvals existed; those count as approved
-- only while the policy does not require approvals.
ALTER TABLE deployments
  ADD COLUMN approval text NOT NULL DEFAULT 'approved' CHECK (approval IN ('pending','approved','denied','revoked')),
  ADD COLUMN approved_spec_sha256 text,
  ADD COLUMN key_algorithm text NOT NULL DEFAULT 'ecdsa-p256' CHECK (key_algorithm IN ('ecdsa-p256'));

-- The spec digest a run was started for; it must still be approved at every
-- checkpoint before the target is changed.
ALTER TABLE workflow_runs ADD COLUMN spec_sha256 text;

CREATE TABLE approvals (
  id             text PRIMARY KEY,
  org_id         text NOT NULL REFERENCES organizations(id),
  resource_type  text NOT NULL CHECK (resource_type IN ('deployment')),
  resource_id    text NOT NULL,
  spec_sha256    text NOT NULL,   -- the exact spec being approved
  spec           jsonb NOT NULL,  -- human-readable copy of that spec
  state          text NOT NULL DEFAULT 'requested' CHECK (state IN ('requested','approved','denied','expired','revoked')),
  requested_by   text NOT NULL,
  requested_at   timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  decided_by     text,
  decided_at     timestamptz,
  reason         text NOT NULL DEFAULT '',
  revoked_by     text,
  revoked_at     timestamptz,
  revoke_reason  text NOT NULL DEFAULT '',
  CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
  CHECK ((state = 'requested') = (decided_at IS NULL)),
  CHECK (decided_by IS NULL OR decided_by <> requested_by)
);
CREATE UNIQUE INDEX approvals_one_open ON approvals (org_id, resource_type, resource_id) WHERE state = 'requested';
CREATE INDEX approvals_state ON approvals (org_id, state, requested_at);

ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON approvals
  USING (org_id = current_setting('app.org_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true));
GRANT SELECT, INSERT, UPDATE ON approvals TO certloom_app;

-- +goose Down
DROP TABLE IF EXISTS approvals;
ALTER TABLE workflow_runs DROP COLUMN IF EXISTS spec_sha256;
ALTER TABLE deployments DROP COLUMN IF EXISTS key_algorithm, DROP COLUMN IF EXISTS approved_spec_sha256, DROP COLUMN IF EXISTS approval;
ALTER TABLE members DROP CONSTRAINT IF EXISTS members_role_check;
ALTER TABLE members ADD CONSTRAINT members_role_check CHECK (role IN ('owner','operator','viewer','auditor'));
ALTER TABLE api_tokens DROP CONSTRAINT IF EXISTS api_tokens_role_check;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_role_check CHECK (role IN ('owner','operator','viewer','auditor'));
