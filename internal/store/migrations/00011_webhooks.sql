-- +goose Up
-- Event webhooks (ADR-0021). Endpoints subscribe to event types; secrets are
-- encrypted with the KEK and never returned after creation.
CREATE TABLE webhook_endpoints (
  id                   text PRIMARY KEY,
  org_id               text NOT NULL REFERENCES organizations(id),
  name                 text NOT NULL,
  url                  text NOT NULL,
  event_types          text[] NOT NULL,
  secret_ciphertext    bytea NOT NULL,
  prev_secret_ciphertext bytea,
  prev_secret_until    timestamptz,
  allow_private        boolean NOT NULL DEFAULT false,
  enabled              boolean NOT NULL DEFAULT true,
  disabled_reason      text NOT NULL DEFAULT '',
  failing_since        timestamptz,
  created_by           text NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

-- An event is stored only when at least one endpoint subscribes to it.
CREATE TABLE events (
  id          text PRIMARY KEY,
  org_id      text NOT NULL REFERENCES organizations(id),
  type        text NOT NULL,
  dedupe_key  text NOT NULL,
  occurred_at timestamptz NOT NULL,
  data        jsonb NOT NULL,
  UNIQUE (org_id, dedupe_key)
);
CREATE INDEX events_time ON events (occurred_at);

-- Delivery queue, claimed across organizations like the outbox.
CREATE TABLE webhook_deliveries (
  id              bigserial PRIMARY KEY,
  org_id          text NOT NULL REFERENCES organizations(id),
  endpoint_id     text NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
  event_id        text NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  state           text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','delivered','failed')),
  attempts        int NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_status     int,
  last_error      text NOT NULL DEFAULT '',
  last_attempt_at timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (endpoint_id, event_id)
);
CREATE INDEX webhook_deliveries_due ON webhook_deliveries (next_attempt_at) WHERE state = 'pending';
CREATE INDEX webhook_deliveries_endpoint ON webhook_deliveries (endpoint_id, created_at);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['webhook_endpoints','events']
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

GRANT SELECT, INSERT, UPDATE, DELETE ON webhook_endpoints TO certloom_app;
GRANT SELECT, INSERT, DELETE ON events TO certloom_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON webhook_deliveries TO certloom_app;
GRANT USAGE, SELECT ON SEQUENCE webhook_deliveries_id_seq TO certloom_app;

-- +goose Down
DROP TABLE IF EXISTS webhook_deliveries, events, webhook_endpoints;
