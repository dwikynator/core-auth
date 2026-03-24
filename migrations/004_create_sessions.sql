-- +goose Up
CREATE TABLE sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id          VARCHAR(255) NOT NULL DEFAULT '',
    refresh_token_hash TEXT NOT NULL,
    ip_address         INET,
    user_agent         TEXT NOT NULL DEFAULT '',
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Active sessions for a user. Covered by partial index for efficiency.
CREATE INDEX idx_sessions_user_active
    ON sessions (user_id, created_at DESC)
    WHERE revoked_at IS NULL;

-- Lookup by refresh token hash for rotation.
-- This is the hot path — every /v1/auth/refresh hits this index.
CREATE UNIQUE INDEX idx_sessions_token_hash
    ON sessions (refresh_token_hash)
    WHERE revoked_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS sessions;
