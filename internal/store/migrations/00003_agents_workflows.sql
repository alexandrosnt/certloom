-- +goose Up
-- M2: agents, signed tasks, ACME issuers, deployments and renewal workflows.

-- Deployment-wide system keys (internal agent CA, task-signing key). Private
-- keys are AES-256-GCM encrypted with the KEK, which is never stored here.
CREATE TABLE system_keys (
  name            text PRIMARY KEY,
  cert_der        bytea,
  public_key      bytea NOT NULL,
  key_ciphertext  bytea NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE enrollment_tokens (
  id          text PRIMARY KEY,
  org_id      text NOT NULL REFERENCES organizations(id),
  token_hash  bytea NOT NULL UNIQUE,
  name_hint   text NOT NULL DEFAULT '',
  created_by  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  agent_id    text
);

CREATE TABLE agents (
  id              text PRIMARY KEY,
  org_id          text NOT NULL REFERENCES organizations(id),
  name            text NOT NULL,
  state           text NOT NULL DEFAULT 'active' CHECK (state IN ('active','revoked')),
  hostname        text NOT NULL DEFAULT '',
  version         text NOT NULL DEFAULT '',
  cert_serial     text NOT NULL,
  cert_not_after  timestamptz NOT NULL,
  capabilities    jsonb NOT NULL DEFAULT '{}',   -- targets reported by the agent
  last_heartbeat  timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  revoked_at      timestamptz,
  UNIQUE (org_id, name)
);

CREATE TABLE agent_tasks (
  id            text PRIMARY KEY,
  org_id        text NOT NULL REFERENCES organizations(id),
  agent_id      text NOT NULL REFERENCES agents(id),
  run_id        text,
  type          text NOT NULL,
  envelope      jsonb NOT NULL,                 -- signed task as delivered
  not_after     timestamptz NOT NULL,
  state         text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','delivered','succeeded','failed','expired')),
  result        jsonb,
  error         text NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now(),
  delivered_at  timestamptz,
  completed_at  timestamptz
);
CREATE INDEX agent_tasks_pending ON agent_tasks (agent_id, created_at) WHERE state IN ('pending','delivered');

CREATE TABLE issuers (
  id             text PRIMARY KEY,
  org_id         text NOT NULL REFERENCES organizations(id),
  name           text NOT NULL,
  kind           text NOT NULL CHECK (kind IN ('acme')),
  directory_url  text NOT NULL,
  email          text NOT NULL DEFAULT '',
  agree_tos      boolean NOT NULL,
  profile        text NOT NULL DEFAULT '',
  created_by     text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

-- A deployment binds a lineage to an agent target and an issuer.
CREATE TABLE deployments (
  id               text PRIMARY KEY,
  org_id           text NOT NULL REFERENCES organizations(id),
  lineage_id       text NOT NULL REFERENCES lineages(id),
  agent_id         text NOT NULL REFERENCES agents(id),
  target           text NOT NULL,
  issuer_id        text NOT NULL REFERENCES issuers(id),
  endpoint_id      text REFERENCES endpoints(id),   -- external verification probe
  sans             text[] NOT NULL,
  target_seq       bigint NOT NULL DEFAULT 0,       -- monotonic per deployment; agents reject stale tasks
  renew_at         timestamptz,
  renew_reason     text NOT NULL DEFAULT '',
  ari_checked_at   timestamptz,
  ari_next_check   timestamptz,
  enabled          boolean NOT NULL DEFAULT true,
  created_by       text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  version          bigint NOT NULL DEFAULT 1,
  UNIQUE (org_id, agent_id, target)
);

CREATE TABLE workflow_runs (
  id               text PRIMARY KEY,
  org_id           text NOT NULL REFERENCES organizations(id),
  deployment_id    text NOT NULL REFERENCES deployments(id),
  state            text NOT NULL,
  reason           text NOT NULL,
  attempt          int NOT NULL DEFAULT 1,
  current_task_id  text,
  previous_sha256  text,
  issued_sha256    text,
  error            text NOT NULL DEFAULT '',
  created_by       text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  next_attempt_at  timestamptz,
  completed_at     timestamptz
);
-- At most one active run per deployment.
CREATE UNIQUE INDEX workflow_runs_active ON workflow_runs (deployment_id)
  WHERE state NOT IN ('verified','failed','rolled_back','cancelled');

CREATE TABLE workflow_steps (
  id      bigserial PRIMARY KEY,
  org_id  text NOT NULL,
  run_id  text NOT NULL REFERENCES workflow_runs(id),
  state   text NOT NULL,
  detail  text NOT NULL DEFAULT '',
  at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX workflow_steps_run ON workflow_steps (run_id, id);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['enrollment_tokens','agents','agent_tasks','issuers','deployments','workflow_runs','workflow_steps']
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

GRANT SELECT, INSERT ON system_keys TO certloom_app;
GRANT SELECT, INSERT, UPDATE ON enrollment_tokens, agents, agent_tasks, issuers, deployments, workflow_runs TO certloom_app;
GRANT SELECT, INSERT ON workflow_steps TO certloom_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO certloom_app;

-- +goose Down
DROP TABLE IF EXISTS workflow_steps, workflow_runs, deployments, issuers, agent_tasks, agents, enrollment_tokens, system_keys;
