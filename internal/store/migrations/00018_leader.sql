-- +goose Up
-- One row per elected role. The holder renews expires_at; any replica may take
-- the row once it has expired (ADR-0033). Not tenant data, so no RLS.
CREATE TABLE leader (
    name       text PRIMARY KEY,
    holder     text NOT NULL,
    expires_at timestamptz NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON leader TO certloom_app;

-- +goose Down
DROP TABLE IF EXISTS leader;
