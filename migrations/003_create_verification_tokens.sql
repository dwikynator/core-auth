-- +goose Up
CREATE TABLE verification_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    type       VARCHAR(32) NOT NULL,   -- 'otp', 'magic_link', 'password_reset'
    status     VARCHAR(20) NOT NULL DEFAULT 'active', -- 'active', 'used', 'invalidated'
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Lookup by user + type: "find the latest active OTP for this user"
CREATE INDEX idx_vt_user_type ON verification_tokens (user_id, type)
    WHERE status = 'active';

-- Cleanup job index: find expired tokens efficiently
CREATE INDEX idx_vt_expires ON verification_tokens (expires_at)
    WHERE status = 'active';

-- +goose Down
DROP TABLE IF EXISTS verification_tokens;
