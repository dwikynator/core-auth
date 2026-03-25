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

// MFACredential represents a user's enrolled MFA factor (TOTP, WebAuthn, etc.).
// The `Verified` flag indicates whether the user has completed enrollment by
// validating at least one code. Unverified credentials do NOT block login.
type MFACredential struct {
	ID              string
	UserID          string
	Type            string // "totp" or "webauthn"
	SecretEncrypted string
	Verified        bool
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

// MFASessionData is the payload stored in Redis during the MFA login flow.
// It bridges the gap between successful password verification and TOTP completion.
type MFASessionData struct {
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id"`
	Role     string `json:"role"`
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

	// UpdatePhoneVerified sets phone_verified_at for the given user.
	UpdatePhoneVerified(ctx context.Context, userID string) error

	// UpdatePasswordHash updates the user's password hash.
	// This is an intent-based partial update — only password_hash and updated_at are touched.
	// Returns ErrUserNotFound if the user doesn't exist or is soft-deleted.
	UpdatePasswordHash(ctx context.Context, userID string, newHash string) error
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

// MFACredentialRepository defines persistence operations for MFA credentials.
type MFACredentialRepository interface {
	// Create inserts a new MFA credential. Returns ErrMFAAlreadyEnrolled
	// if a credential of the same type already exists for the user.
	Create(ctx context.Context, cred *MFACredential) error

	// FindVerifiedByUserID returns the active (verified) MFA credential for a user.
	// Returns ErrMFANotEnrolled if no verified credential exists.
	FindVerifiedByUserID(ctx context.Context, userID string) (*MFACredential, error)

	// FindByUserID returns any MFA credential for a user (including unverified).
	// Returns ErrMFANotEnrolled if no credential exists at all.
	FindByUserID(ctx context.Context, userID string) (*MFACredential, error)

	// MarkVerified sets verified = true and updates last_used_at.
	MarkVerified(ctx context.Context, credID string) error

	// UpdateLastUsed updates the last_used_at timestamp after a successful challenge.
	UpdateLastUsed(ctx context.Context, credID string) error

	// DeleteByUserID removes all MFA credentials for a user (used in DisableMFA).
	DeleteByUserID(ctx context.Context, userID string) error
}

// MFASessionStore defines operations for the short-lived MFA login sessions.
// Implementations should use Redis with a short TTL (e.g. 5 minutes).
type MFASessionStore interface {
	// Create stores an MFA session and returns the raw token.
	// The token is a random 32-byte hex string. The store keys by SHA-256 hash.
	Create(ctx context.Context, data *MFASessionData) (rawToken string, err error)

	// Consume retrieves and immediately deletes the session (single-use).
	// Returns ErrInvalidMFASession if the token is not found or already consumed.
	Consume(ctx context.Context, rawToken string) (*MFASessionData, error)
}
