-- +goose Up
-- M1 completion: audit export cursors, OIDC members and sessions, idempotency
-- keys, versioned policies, alert escalation, optimistic-concurrency versions.

-- External audit export (ADR-0012). System table: the exporter works across orgs.
CREATE TABLE audit_export_cursors (
  org_id      text NOT NULL REFERENCES organizations(id),
  sink        text NOT NULL,             -- sink identity, e.g. "file:/var/log/certloom/audit.jsonl"
  last_seq    bigint NOT NULL DEFAULT 0,
  last_error  text NOT NULL DEFAULT '',
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, sink)
);

-- OIDC members: which verified identity may act in which org with which role.
-- System table (looked up at sign-in before the org is known); management is
-- always org-filtered in the service layer.
CREATE TABLE members (
  id          text PRIMARY KEY,
  org_id      text NOT NULL REFERENCES organizations(id),
  issuer      text NOT NULL,
  email       text NOT NULL,             -- lowercased; requires email_verified=true at sign-in
  role        text NOT NULL CHECK (role IN ('owner','operator','viewer','auditor')),
  created_by  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, issuer, email)
);
CREATE INDEX members_identity ON members (issuer, email);

-- Browser/CLI sessions created by OIDC sign-in. The role is read from the
-- member row on every request, so removing a member ends their sessions.
CREATE TABLE sessions (
  id            text PRIMARY KEY,
  org_id        text NOT NULL REFERENCES organizations(id),
  member_id     text NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  token_hash    bytea NOT NULL UNIQUE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  revoked_at    timestamptz
);

-- Idempotency keys for POST requests (ADR-0010). Responses are stored for
-- replay; endpoints that return secrets never store their response.
CREATE TABLE idempotency_keys (
  org_id        text NOT NULL,
  key           text NOT NULL,
  actor         text NOT NULL,
  request_hash  bytea NOT NULL,
  status        int NOT NULL DEFAULT 0,  -- 0 = in progress
  response      bytea,
  content_type  text NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, key)
);
CREATE INDEX idempotency_keys_created ON idempotency_keys (created_at);

-- Versioned monitoring policy per org (one active version).
CREATE TABLE policies (
  org_id      text NOT NULL REFERENCES organizations(id),
  version     int NOT NULL,
  document    jsonb NOT NULL,
  source      text NOT NULL,             -- original YAML, for review/diff
  created_by  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, version)
);

ALTER TABLE alerts ADD COLUMN escalation_level int NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN last_escalated_at timestamptz;
ALTER TABLE endpoints ADD COLUMN version bigint NOT NULL DEFAULT 1;
ALTER TABLE lineages ADD COLUMN version bigint NOT NULL DEFAULT 1;

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['sessions','idempotency_keys','policies']
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

GRANT SELECT, INSERT, UPDATE ON audit_export_cursors TO certloom_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON members, sessions, idempotency_keys TO certloom_app;
GRANT SELECT, INSERT ON policies TO certloom_app;

-- +goose Down
ALTER TABLE lineages DROP COLUMN IF EXISTS version;
ALTER TABLE endpoints DROP COLUMN IF EXISTS version;
ALTER TABLE alerts DROP COLUMN IF EXISTS last_escalated_at;
ALTER TABLE alerts DROP COLUMN IF EXISTS escalation_level;
DROP TABLE IF EXISTS policies, idempotency_keys, sessions, members, audit_export_cursors;
