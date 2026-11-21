-- +goose Up
-- DNS-01 solvers defined in the control plane (ADR-0018). A stored secret is
-- encrypted with the KEK, bound to the solver id, and never returned by the
-- API; it reaches an agent only sealed to that agent inside an issue task.
CREATE TABLE dns_solvers (
  id                text PRIMARY KEY,
  org_id            text NOT NULL REFERENCES organizations(id),
  name              text NOT NULL,
  provider          text NOT NULL CHECK (provider IN ('rfc2136','cloudflare','plugin')),
  plugin            text NOT NULL DEFAULT '',
  plugin_sha256     text NOT NULL DEFAULT '',
  zones             text[] NOT NULL,
  config            jsonb NOT NULL DEFAULT '{}',
  credential        text NOT NULL CHECK (credential IN ('stored','ambient')),
  secret_ciphertext bytea,
  secret_updated_at timestamptz,
  version           bigint NOT NULL DEFAULT 1,
  created_by        text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name),
  CHECK (credential = 'stored' OR provider = 'plugin')
);

CREATE TABLE dns_solver_agents (
  org_id    text NOT NULL REFERENCES organizations(id),
  solver_id text NOT NULL REFERENCES dns_solvers(id) ON DELETE CASCADE,
  agent_id  text NOT NULL REFERENCES agents(id),
  PRIMARY KEY (solver_id, agent_id)
);
CREATE INDEX dns_solver_agents_agent ON dns_solver_agents (agent_id);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['dns_solvers','dns_solver_agents']
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

GRANT SELECT, INSERT, UPDATE, DELETE ON dns_solvers, dns_solver_agents TO certloom_app;

-- +goose Down
DROP TABLE IF EXISTS dns_solver_agents, dns_solvers;
