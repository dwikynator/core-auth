package mfa

import (
	"context"
	"time"

	"github.com/dwikynator/core-auth/internal/infra/audit"
	"github.com/dwikynator/core-auth/internal/session"
	"github.com/dwikynator/core-auth/internal/user"
)

type MFAUseCase interface {
	IsEnrolled(ctx context.Context, userID string) bool
	CreateSession(ctx context.Context, data *MFASessionData) (string, error)
	SetupTOTP(ctx context.Context) (*SetupTOTPResponse, error)
	ConfirmTOTP(ctx context.Context, req *ConfirmTOTPRequest) error
	ChallengeMFA(ctx context.Context, req *ChallengeMFARequest) (*ChallengeMFAResponse, error)
	DisableMFA(ctx context.Context, password string) error
}

type AuditLogger interface {
	Log(ctx context.Context, event audit.Event)
}

type UserProvider interface {
	FindByID(ctx context.Context, userID string) (*user.User, error)
}

type SessionService interface {
	CreateSessionAndTokens(ctx context.Context, userID, role, clientID string) (*session.TokenPair, string, error)
}

type SetupTOTPResponse struct {
	Secret string
	QRURI  string
}

type ConfirmTOTPRequest struct {
	TOTPCode string
}

type ChallengeMFARequest struct {
	MFASessionToken string
	Code            string
}

type ChallengeMFAResponse struct {
	User     *user.User
	Tokens   *session.TokenPair
	ClientID string
}

// SetupResult contains the information shown to the user during TOTP enrollment.
type SetupResult struct {
	Secret string // base32-encoded secret (show once, never again)
	QRURI  string // otpauth:// URI for QR code generation
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

// LinkSessionData is the payload stored in Redis during the account-linking flow.
// It bridges OAuthCallback (which detects the email conflict) and LinkProvider
// (which verifies ownership and completes the merge).
type LinkSessionData struct {
	// Provider is the OAuth2 provider name (e.g., "google").
	Provider string `json:"provider"`
	// ProviderUserID is the unique ID from the provider (e.g., the Google "sub" claim).
	// Stored so we can create the user_providers record without a second OAuth2 round-trip.
	ProviderUserID string `json:"provider_user_id"`
	// ProviderEmail is the email the provider reported.
	ProviderEmail string `json:"provider_email"`
	// ExistingUserID is the user_id of the local account with the conflicting email.
	// The user must prove ownership of this account to complete the link.
	ExistingUserID string `json:"existing_user_id"`
	// ClientID is the tenant/app that initiated the OAuth2 flow.
	// Used to issue the correct scopes and TTLs after linking succeeds.
	ClientID string `json:"client_id"`
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

// LinkSessionStore manages short-lived account-linking sessions.
// A link session is created when OAuthCallback detects an email conflict and
// consumed (single-use) when LinkProvider verifies the user's password.
type LinkSessionStore interface {
	// Create stores a link session and returns the raw token.
	// The raw token is returned to the client as link_session_token.
	Create(ctx context.Context, data *LinkSessionData) (rawToken string, err error)
	// Consume retrieves and atomically deletes the session (single-use).
	// Returns ErrLinkSessionExpired if the token doesn't exist or has expired.
	Consume(ctx context.Context, rawToken string) (*LinkSessionData, error)
}
