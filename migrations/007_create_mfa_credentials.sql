-- +goose Up
CREATE TABLE mfa_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type            VARCHAR(20) NOT NULL DEFAULT 'totp',   -- 'totp' or 'webauthn' (future)
    secret_encrypted TEXT NOT NULL,                         -- AES-256-GCM encrypted TOTP secret
    verified        BOOLEAN NOT NULL DEFAULT false,         -- true after first successful code validation
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ
);

-- Each user can have at most one credential per MFA type.
CREATE UNIQUE INDEX idx_mfa_credentials_user_type ON mfa_credentials(user_id, type);

-- Fast lookup by user_id for login-time MFA checks.
CREATE INDEX idx_mfa_credentials_user_id ON mfa_credentials(user_id);

-- +goose Down
DROP TABLE IF EXISTS mfa_credentials;
