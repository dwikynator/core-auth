package auth

import (
	"context"
	"time"
)

// User is the domain model for a registered identity.
// Pointer fields are nullable columns in the database.
type User struct {
	ID              string
	Email           *string
	Username        *string
	Phone           *string
	PasswordHash    *string
	Role            string
	Status          string
	EmailVerifiedAt *time.Time
	PhoneVerifiedAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Session represents an active user session (one per device/login).
// Each session is bound to exactly one refresh token at any point in time.
type Session struct {
	ID               string
	UserID           string
	ClientID         string
	RefreshTokenHash string
	IPAddress        *string
	UserAgent        string
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	CreatedAt        time.Time
	LastUsedAt       time.Time
}

// TenantConfig holds per-tenant token lifetime settings.
// If no config is found for a client_id, the system defaults are used.
type TenantConfig struct {
	ClientID        string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	DefaultScopes   []string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// UserRepository defines the persistence contract for user operations.
// Implementations live in internal/auth/repository/.
type UserRepository interface {
	// Create inserts a new user. On success the receiver's ID, CreatedAt,
	// and UpdatedAt fields are populated. Returns ErrUserAlreadyExists if
	// a uniqueness constraint is violated.
	Create(ctx context.Context, u *User) error

	// FindByLogin looks up a user by email, username, or phone.
	// Returns ErrUserNotFound if no match exists.
	FindByLogin(ctx context.Context, identifier string) (*User, error)

	// FindByID looks up a user by their UUID primary key.
	// Returns ErrUserNotFound if no match exists.
	FindByID(ctx context.Context, userID string) (*User, error)

	// FindByEmail looks up a user by their normalized email address.
	// Returns ErrUserNotFound if no match exists.
	FindByEmail(ctx context.Context, email string) (*User, error)

	// VerifyEmailAndActivate atomically sets email_verified_at and changes status to active.
	// Returns ErrUserNotFound if the user doesn't exist.
	VerifyEmailAndActivate(ctx context.Context, userID string) error

	// UpdateStatus changes the user's status column (e.g., "active", "suspended").
	// Returns ErrUserNotFound if the user doesn't exist or is soft-deleted.
	UpdateStatus(ctx context.Context, userID string, status string) error

	// SoftDelete sets deleted_at = NOW() and status = "deleted" for the user.
	// Returns ErrUserNotFound if the user doesn't exist or is already deleted.
	SoftDelete(ctx context.Context, userID string) error
}

// TokenBlacklistRepository defines the contract for token revocation storage.
// Implementations live in internal/auth/repository/.
type TokenBlacklistRepository interface {
	// Blacklist adds a token's JTI to the blacklist.
	// The entry automatically expires at expiresAt (matching the token's own expiry),
	// so Redis memory is strictly bounded to the number of *active* revoked tokens.
	Blacklist(ctx context.Context, jti string, expiresAt time.Time) error

	// IsBlacklisted checks whether a JTI has been revoked.
	// Returns false if the JTI is not found (i.e., the token is still valid).
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
}

// SessionRepository defines the persistence contract for session operations.
// Implementations live in internal/auth/repository/.
type SessionRepository interface {
	// Create inserts a new session. On success the receiver's ID, CreatedAt,
	// and LastUsedAt fields are populated.
	Create(ctx context.Context, s *Session) error

	// FindByRefreshTokenHash returns the active (non-revoked) session matching
	// the given hash. Returns ErrSessionNotFound if no match exists.
	FindByRefreshTokenHash(ctx context.Context, hash string) (*Session, error)

	// RotateRefreshToken atomically updates the session's refresh_token_hash
	// and last_used_at. Returns ErrSessionNotFound if the session was revoked
	// concurrently.
	RotateRefreshToken(ctx context.Context, sessionID, newHash string) error

	// Revoke marks a single session as revoked by setting revoked_at = NOW().
	// Returns ErrSessionNotFound if the session doesn't exist, is already revoked,
	// or belongs to a different user.
	Revoke(ctx context.Context, sessionID, userID string) error

	// RevokeAllForUser revokes all active sessions for the given user.
	// If exceptSessionID is non-empty, that session is preserved (for "revoke
	// all other sessions"). Returns the number of sessions revoked.
	RevokeAllForUser(ctx context.Context, userID string, exceptSessionID string) (int, error)

	// ListActiveByUser returns all non-revoked, non-expired sessions for a user,
	// ordered by most recently created.
	ListActiveByUser(ctx context.Context, userID string) ([]*Session, error)
}

// TenantConfigRepository defines the persistence contract for tenant config lookups.
// Implementations should cache aggressively — this data changes very rarely.
type TenantConfigRepository interface {
	// FindByClientID returns the tenant config for the given client_id.
	// Returns ErrTenantNotFound if no config exists for this client.
	FindByClientID(ctx context.Context, clientID string) (*TenantConfig, error)
}
