-- +goose Up
-- How domain control is proven. It is part of the approved spec, so moving a
-- deployment to dns-01 needs a new approval.
ALTER TABLE deployments
  ADD COLUMN challenge text NOT NULL DEFAULT 'http-01' CHECK (challenge IN ('http-01','dns-01'));

-- +goose Down
ALTER TABLE deployments DROP COLUMN IF EXISTS challenge;
