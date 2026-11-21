-- +goose Up
-- Issuers can be deleted through the API once nothing references them
-- (ADR-0025). The foreign keys from deployments and EAB keys stay without
-- ON DELETE so the delete fails while they exist.
GRANT DELETE ON issuers TO certloom_app;

-- +goose Down
REVOKE DELETE ON issuers FROM certloom_app;
