-- +goose Up
-- M1 schema. Conventions: text IDs with type prefix (ULID), timestamptz in UTC,
-- org_id on every tenant row, row-level security keyed on app.org_id
-- (ADR-0001, ADR-0008). No column holds private keys or plaintext secrets
-- (ADR-0005, ADR-0009).

-- Application role: the runtime connects as (or as a member of) certloom_app.
-- It is not the table owner, so RLS applies to it.
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'certloom_app') THEN
    CREATE ROLE certloom_app NOLOGIN;
  END IF;
EXCEPTION
  -- Roles are cluster-wide; a concurrent migration may create it first.
  WHEN duplicate_object OR unique_violation THEN NULL;
END
$$;
-- +goose StatementEnd

CREATE TABLE organizations (
  id          text PRIMARY KEY,
  name        text NOT NULL UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE teams (
  id          text PRIMARY KEY,
  org_id      text NOT NULL REFERENCES organizations(id),
  name        text NOT NULL,
  contact     text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

-- Immutable certificate identities (SHA-256 of DER).
CREATE TABLE certificates (
  org_id              text NOT NULL REFERENCES organizations(id),
  sha256              text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  der                 bytea NOT NULL,
  serial              text NOT NULL,
  subject             text NOT NULL,
  issuer              text NOT NULL,
  common_name         text NOT NULL DEFAULT '',
  ski                 text NOT NULL DEFAULT '',
  aki                 text NOT NULL DEFAULT '',
  dns_names           text[] NOT NULL DEFAULT '{}',
  ip_addresses        text[] NOT NULL DEFAULT '{}',
  not_before          timestamptz NOT NULL,
  not_after           timestamptz NOT NULL,
  key_algorithm       text NOT NULL,
  key_bits            int NOT NULL DEFAULT 0,
  is_ca               boolean NOT NULL,
  self_signed         boolean NOT NULL,
  metadata            jsonb NOT NULL,          -- full certparse.Certificate (public data only)
  source              text NOT NULL,           -- import, probe
  first_seen          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, sha256)
);
CREATE INDEX certificates_not_after ON certificates (org_id, not_after);
CREATE INDEX certificates_dns ON certificates USING gin (dns_names);

CREATE TABLE lineages (
  id                text PRIMARY KEY,
  org_id            text NOT NULL REFERENCES organizations(id),
  name              text NOT NULL,
  team_id           text REFERENCES teams(id),
  current_sha256    text,
  management_level  text NOT NULL DEFAULT 'monitored'
                    CHECK (management_level IN ('discovered','monitored','owned','enrolled','provisioned','verified')),
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name),
  FOREIGN KEY (org_id, current_sha256) REFERENCES certificates(org_id, sha256)
);

CREATE TABLE lineage_members (
  org_id      text NOT NULL,
  lineage_id  text NOT NULL REFERENCES lineages(id),
  sha256      text NOT NULL,
  since       timestamptz NOT NULL DEFAULT now(),
  reason      text NOT NULL,
  PRIMARY KEY (lineage_id, sha256),
  FOREIGN KEY (org_id, sha256) REFERENCES certificates(org_id, sha256)
);

CREATE TABLE probe_scopes (
  id          text PRIMARY KEY,
  org_id      text NOT NULL REFERENCES organizations(id),
  name        text NOT NULL,
  config      jsonb NOT NULL,   -- probe.Scope
  enabled     boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

CREATE TABLE endpoints (
  id                    text PRIMARY KEY,
  org_id                text NOT NULL REFERENCES organizations(id),
  host                  text NOT NULL,
  port                  int  NOT NULL CHECK (port BETWEEN 1 AND 65535),
  sni                   text NOT NULL DEFAULT '',
  scope_id              text NOT NULL REFERENCES probe_scopes(id),
  lineage_id            text REFERENCES lineages(id),
  team_id               text REFERENCES teams(id),
  interval_seconds      int  NOT NULL DEFAULT 21600 CHECK (interval_seconds >= 60),
  enabled               boolean NOT NULL DEFAULT true,
  last_leaf_sha256      text,
  consecutive_failures  int NOT NULL DEFAULT 0,
  last_observed_at      timestamptz,
  next_probe_at         timestamptz NOT NULL DEFAULT now(),
  created_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, host, port, sni)
);
CREATE INDEX endpoints_due ON endpoints (next_probe_at) WHERE enabled;

CREATE TABLE observations (
  id            bigserial PRIMARY KEY,
  org_id        text NOT NULL,
  endpoint_id   text NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  observed_at   timestamptz NOT NULL,
  address       text NOT NULL DEFAULT '',
  leaf_sha256   text,
  chain_sha256  text[] NOT NULL DEFAULT '{}',
  tls_version   text NOT NULL DEFAULT '',
  cipher        text NOT NULL DEFAULT '',
  alpn          text NOT NULL DEFAULT '',
  latency_ms    bigint NOT NULL DEFAULT 0,
  error_class   text NOT NULL DEFAULT '',
  error         text NOT NULL DEFAULT ''
);
CREATE INDEX observations_endpoint ON observations (endpoint_id, observed_at DESC);
CREATE INDEX observations_leaf ON observations (org_id, leaf_sha256);

CREATE TABLE findings (
  id            text PRIMARY KEY,
  org_id        text NOT NULL REFERENCES organizations(id),
  subject_type  text NOT NULL CHECK (subject_type IN ('certificate','endpoint','lineage')),
  subject_id    text NOT NULL,
  check_id      text NOT NULL,
  severity      text NOT NULL CHECK (severity IN ('info','warning','critical')),
  message       text NOT NULL,
  remediation   text NOT NULL DEFAULT '',
  first_seen    timestamptz NOT NULL DEFAULT now(),
  last_seen     timestamptz NOT NULL DEFAULT now(),
  resolved_at   timestamptz
);
CREATE UNIQUE INDEX findings_open ON findings (org_id, subject_type, subject_id, check_id) WHERE resolved_at IS NULL;

CREATE TABLE alerts (
  id                text PRIMARY KEY,
  org_id            text NOT NULL REFERENCES organizations(id),
  finding_id        text NOT NULL REFERENCES findings(id),
  state             text NOT NULL DEFAULT 'open' CHECK (state IN ('open','acked','resolved','suppressed')),
  severity          text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  acked_by          text,
  acked_at          timestamptz,
  resolved_at       timestamptz,
  suppressed_until  timestamptz,
  UNIQUE (finding_id)
);
CREATE INDEX alerts_state ON alerts (org_id, state);

CREATE TABLE notification_channels (
  id              text PRIMARY KEY,
  org_id          text NOT NULL REFERENCES organizations(id),
  name            text NOT NULL,
  kind            text NOT NULL CHECK (kind IN ('webhook','email')),
  config          jsonb NOT NULL,   -- non-secret settings only
  credential_ref  text NOT NULL DEFAULT '',  -- e.g. env:CERTLOOM_WEBHOOK_SECRET
  min_severity    text NOT NULL DEFAULT 'warning',
  enabled         boolean NOT NULL DEFAULT true,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

-- Transactional outbox: notifications are enqueued in the same transaction as
-- the state change and delivered at-least-once (ADR-0003).
CREATE TABLE outbox (
  id               bigserial PRIMARY KEY,
  org_id           text NOT NULL,
  channel_id       text NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
  dedupe_key       text NOT NULL UNIQUE,
  payload          jsonb NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  next_attempt_at  timestamptz NOT NULL DEFAULT now(),
  attempts         int NOT NULL DEFAULT 0,
  delivered_at     timestamptz,
  failed_at        timestamptz,
  last_error       text NOT NULL DEFAULT ''
);
CREATE INDEX outbox_pending ON outbox (next_attempt_at) WHERE delivered_at IS NULL AND failed_at IS NULL;

CREATE TABLE api_tokens (
  id            text PRIMARY KEY,
  org_id        text NOT NULL REFERENCES organizations(id),
  name          text NOT NULL,
  token_hash    bytea NOT NULL UNIQUE,   -- SHA-256 of the token; the token itself is never stored
  role          text NOT NULL CHECK (role IN ('owner','operator','viewer','auditor')),
  created_by    text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz,
  revoked_at    timestamptz,
  last_used_at  timestamptz
);

-- Audit: append-only, hash-chained per org (ADR-0012).
CREATE TABLE audit_heads (
  org_id  text PRIMARY KEY REFERENCES organizations(id),
  seq     bigint NOT NULL,
  hash    bytea  NOT NULL
);
CREATE TABLE audit_events (
  org_id         text NOT NULL REFERENCES organizations(id),
  seq            bigint NOT NULL,
  at             timestamptz NOT NULL,
  actor          text NOT NULL,
  action         text NOT NULL,
  resource_type  text NOT NULL,
  resource_id    text NOT NULL,
  request_id     text NOT NULL DEFAULT '',
  result         text NOT NULL,
  detail         jsonb NOT NULL DEFAULT '{}',
  prev_hash      bytea NOT NULL,
  hash           bytea NOT NULL,
  PRIMARY KEY (org_id, seq)
);

-- Durable jobs (ADR-0003). Cross-org by design: workers claim jobs, then set
-- app.org_id for the handler's transaction.
CREATE TABLE jobs (
  id            bigserial PRIMARY KEY,
  org_id        text NOT NULL,
  kind          text NOT NULL,
  dedupe_key    text NOT NULL,
  payload       jsonb NOT NULL DEFAULT '{}',
  state         text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','running','done','failed','cancelled')),
  run_at        timestamptz NOT NULL DEFAULT now(),
  attempts      int NOT NULL DEFAULT 0,
  max_attempts  int NOT NULL DEFAULT 5,
  lease_owner   text,
  lease_until   timestamptz,
  lease_epoch   bigint NOT NULL DEFAULT 0,
  last_error    text NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX jobs_active_dedupe ON jobs (kind, dedupe_key) WHERE state IN ('pending','running');
CREATE INDEX jobs_claim ON jobs (run_at) WHERE state = 'pending';
CREATE INDEX jobs_lease ON jobs (lease_until) WHERE state = 'running';

-- Global and per-org kill switches (ADR-0003).
CREATE TABLE automation_switches (
  scope       text PRIMARY KEY,   -- 'global' or 'org:<id>'
  paused      boolean NOT NULL,
  reason      text NOT NULL DEFAULT '',
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Row-level security on tenant tables.
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['teams','certificates','lineages','lineage_members','probe_scopes','endpoints',
                           'observations','findings','alerts','notification_channels','api_tokens',
                           'audit_events','audit_heads']
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

-- Grants: least privilege for the runtime role.
GRANT USAGE ON SCHEMA public TO certloom_app;
GRANT SELECT, INSERT ON organizations TO certloom_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON teams, lineages, lineage_members, probe_scopes, endpoints,
  findings, alerts, notification_channels, api_tokens, jobs, automation_switches TO certloom_app;
GRANT SELECT, INSERT ON certificates, observations, outbox TO certloom_app;
GRANT UPDATE ON outbox TO certloom_app;
GRANT DELETE ON observations TO certloom_app;          -- retention pruning
GRANT SELECT, INSERT ON audit_events TO certloom_app;  -- append-only: no UPDATE/DELETE
GRANT SELECT, INSERT, UPDATE ON audit_heads TO certloom_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO certloom_app;

-- +goose Down
-- Forward-only in production (ADR-0002). Down exists for development only.
DROP TABLE IF EXISTS automation_switches, jobs, audit_events, audit_heads, api_tokens, outbox,
  notification_channels, alerts, findings, observations, endpoints, probe_scopes, lineage_members,
  lineages, certificates, teams, organizations CASCADE;
