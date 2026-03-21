-- +goose Up
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(320) UNIQUE,
    username VARCHAR(64) UNIQUE,
    phone VARCHAR(20) UNIQUE,
    password_hash TEXT,
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    email_verified_at TIMESTAMPTZ,
    phone_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- B-tree indexes for login lookups. Each covers one identifier column.
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(LOWER(username)); -- case-insensitive
CREATE INDEX idx_users_phone ON users(phone);

-- Partial index: only index non-deleted rows for status filters.
CREATE INDEX idx_users_status ON users (status) WHERE deleted_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS users;
