-- +goose Up
ALTER TABLE tenant_configs
    ADD COLUMN default_scopes TEXT[] NOT NULL DEFAULT '{"openid","profile","email"}';

-- Backfill the existing test-app row with standard scopes.
-- The DEFAULT handles this automatically for new inserts, but this makes the
-- intention explicit and verifiable.
UPDATE tenant_configs
SET    default_scopes = '{"openid","profile","email"}'
WHERE  default_scopes = '{"openid","profile","email"}';

-- +goose Down
ALTER TABLE tenant_configs DROP COLUMN IF EXISTS default_scopes;
