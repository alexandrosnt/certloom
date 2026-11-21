-- +goose Up
-- Maintenance windows for deployments. The window gates the deploy step;
-- window_emergency decides what happens when no window is left before the
-- current certificate gets too close to expiry.
ALTER TABLE deployments
  ADD COLUMN maintenance_window text NOT NULL DEFAULT '',
  ADD COLUMN window_emergency  text NOT NULL DEFAULT 'block'
    CHECK (window_emergency IN ('block','renew_outside_window'));

-- +goose Down
ALTER TABLE deployments DROP COLUMN IF EXISTS window_emergency, DROP COLUMN IF EXISTS maintenance_window;
