package domain

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

	// UpdatePhoneVerified sets phone_verified_at for the given user.
	UpdatePhoneVerified(ctx context.Context, userID string) error

	// UpdatePasswordHash updates the user's password hash.
	// This is an intent-based partial update — only password_hash and updated_at are touched.
	// Returns ErrUserNotFound if the user doesn't exist or is soft-deleted.
	UpdatePasswordHash(ctx context.Context, userID string, newHash string) error
}

// TenantConfigRepository defines the persistence contract for tenant config lookups.
// Implementations should cache aggressively — this data changes very rarely.
type TenantConfigRepository interface {
	// FindByClientID returns the tenant config for the given client_id.
	// Returns ErrTenantNotFound if no config exists for this client.
	FindByClientID(ctx context.Context, clientID string) (*TenantConfig, error)
}
