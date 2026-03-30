-- +goose Up
CREATE TABLE login_attempts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        REFERENCES users(id) ON DELETE CASCADE,
    ip_address  INET        NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    success     BOOLEAN     NOT NULL
);

-- Index for fast per-user failed attempt lookups.
-- We query "attempts for user X in the last N minutes" frequently.
CREATE INDEX idx_login_attempts_user_time
    ON login_attempts(user_id, attempted_at DESC);

-- Index for per-IP rate checks (Phase 6C Suspicious Login detection will reuse this).
CREATE INDEX idx_login_attempts_ip_time
    ON login_attempts(ip_address, attempted_at DESC);

-- +goose Down
DROP TABLE login_attempts;
