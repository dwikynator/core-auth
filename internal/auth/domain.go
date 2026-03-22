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
}
