package verification

import (
	"context"
	"time"

	"github.com/dwikynator/core-auth/internal/infra/audit"
	"github.com/dwikynator/core-auth/internal/libs/email"
	"github.com/dwikynator/core-auth/internal/session"
	"github.com/dwikynator/core-auth/internal/user"
)

type VerificationService interface {
	SendOTP(ctx context.Context, req *SendOTPRequest) (*SendOTPResponse, error)
	SendOTPToUser(ctx context.Context, userID, emailAddr string) (time.Time, error)
	VerifyOTP(ctx context.Context, req *VerifyOTPRequest) (*VerifyOTPResponse, error)
	SendMagicLink(ctx context.Context, req *SendMagicLinkRequest) error
	VerifyMagicLink(ctx context.Context, req *VerifyMagicLinkRequest) (*VerifyMagicLinkResponse, error)
	GetWhatsAppVerificationLink(ctx context.Context) (*GetWhatsAppVerificationLinkResponse, error)
	ValidateToken(ctx context.Context, rawToken string, tokenType TokenType) (*VerificationToken, error)
	SendPasswordReset(ctx context.Context, userID, emailAddr string) error
}

type AuditLogger interface {
	Log(ctx context.Context, event audit.Event)
}

type UserProvider interface {
	FindByEmail(ctx context.Context, email string) (*user.User, error)
	FindByID(ctx context.Context, id string) (*user.User, error)
}

type UserService interface {
	UpdatePhoneVerified(ctx context.Context, userID string) error
	VerifyEmailAndActivate(ctx context.Context, userID string) error
}

type EmailSender interface {
	Send(ctx context.Context, msg *email.Message) error
}

type SessionService interface {
	CreateSessionAndTokens(ctx context.Context, userID, role, clientID string) (*session.TokenPair, string, error)
}

type SendOTPRequest struct {
	EmailOrPhone string
	Target       OTPTarget
}

type SendOTPResponse struct {
	ExpiresAt time.Time
}

type VerifyOTPRequest struct {
	EmailOrPhone string
	OTPCode      string
	Target       OTPTarget
	ClientId     string
}

type VerifyOTPResponse struct {
	User   *user.User
	Tokens *session.TokenPair
}

type SendMagicLinkRequest struct {
	Email    string
	ClientId string
}

type VerifyMagicLinkRequest struct {
	Token    string
	ClientId string
}

type VerifyMagicLinkResponse struct {
	User   *user.User
	Tokens *session.TokenPair
}

type GetWhatsAppVerificationLinkResponse struct {
	WhatsappUrl string
	OTPCode     string
	ExpiresAt   time.Time
}

type OTPTarget string

const (
	OTPTargetUnspecified OTPTarget = "unspecified"
	OTPTargetEmail       OTPTarget = "email"
	OTPTargetPhone       OTPTarget = "phone"
)

// Default token lifetimes.
const (
	OTPExpiry           = 5 * time.Minute
	MagicLinkExpiry     = 15 * time.Minute
	PasswordResetExpiry = 30 * time.Minute
	OTPDigits           = 6
	SecureTokenBytes    = 32
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
