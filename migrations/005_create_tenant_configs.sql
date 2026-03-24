-- +goose Up
CREATE TABLE tenant_configs (
    client_id         VARCHAR(255) PRIMARY KEY,
    access_token_ttl  INTERVAL NOT NULL DEFAULT '15 minutes',
    refresh_token_ttl INTERVAL NOT NULL DEFAULT '30 days',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed a default config for the test client.
INSERT INTO tenant_configs (client_id) VALUES ('test-app');

-- +goose Down
DROP TABLE IF EXISTS tenant_configs;