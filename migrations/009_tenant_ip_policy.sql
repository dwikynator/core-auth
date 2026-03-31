-- +goose Up

-- Add nullable IP policy columns to tenant_configs.
-- Both columns are TEXT[] to store CIDR ranges (e.g., '192.168.1.0/24', '10.0.0.0/8').
-- NULL means "no policy configured" (allow all IPs for that column).
ALTER TABLE tenant_configs
    ADD COLUMN ip_allowlist TEXT[] DEFAULT NULL,
    ADD COLUMN ip_denylist  TEXT[] DEFAULT NULL;

-- Partial index for fast allowlist/denylist lookups.
-- Only indexes rows that actually have a policy configured.
CREATE INDEX idx_tenant_configs_ip_allowlist
    ON tenant_configs(client_id)
    WHERE ip_allowlist IS NOT NULL;

CREATE INDEX idx_tenant_configs_ip_denylist
    ON tenant_configs(client_id)
    WHERE ip_denylist IS NOT NULL;

-- +goose Down
ALTER TABLE tenant_configs
    DROP COLUMN IF EXISTS ip_allowlist,
    DROP COLUMN IF EXISTS ip_denylist;

DROP INDEX IF EXISTS idx_tenant_configs_ip_allowlist;
DROP INDEX IF EXISTS idx_tenant_configs_ip_denylist;
