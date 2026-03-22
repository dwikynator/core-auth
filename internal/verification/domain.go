package verification

import (
	"context"
	"time"
)

// TokenType discriminates the purpose of a verification token.
type TokenType string

const (
	TokenTypeOTP           TokenType = "otp"
	TokenTypeMagicLink     TokenType = "magic_link"
	TokenTypePasswordReset TokenType = "password_reset"
)

// TokenStatus represents the current state of a token.
type TokenStatus string

const (
	StatusActive      TokenStatus = "active"
	StatusUsed        TokenStatus = "used"
	StatusInvalidated TokenStatus = "invalidated"
)

// VerificationToken represents a single-use, time-limited token
// used for email verification, magic links, or password resets.
type VerificationToken struct {
	ID        string
	UserID    string
	TokenHash string // SHA-256 hash of the raw token/OTP
	Type      TokenType
	Status    TokenStatus
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsExpired reports whether the token has passed its expiry time.
func (t *VerificationToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsActive reports whether the token is still active (not used or invalidated).
func (t *VerificationToken) IsActive() bool {
	return t.Status == StatusActive
}

// Repository defines the persistence contract for verification tokens.
type Repository interface {
	// Create inserts a new verification token.
	Create(ctx context.Context, token *VerificationToken) error

	// FindByHashAndType looks up an unused token by its SHA-256 hash and type.
	// Returns ErrTokenNotFound if no match exists.
	FindByHashAndType(ctx context.Context, tokenHash string, tokenType TokenType) (*VerificationToken, error)

	// MarkUsed sets the used_at timestamp, consuming the token.
	// Returns ErrTokenNotFound if the token doesn't exist or is already used.
	MarkUsed(ctx context.Context, tokenID string) error

	// InvalidateAllForUser marks all active tokens of a given type for a user as used.
	// This is called when a new token is issued, invalidating any prior tokens.
	InvalidateAllForUser(ctx context.Context, userID string, tokenType TokenType) error
}
