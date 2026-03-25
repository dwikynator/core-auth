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

// UserProvider represents a linked social identity provider for a user.
// Each row in the user_providers table maps one (provider, provider_user_id)
// pair to a user_id. A user can have multiple providers linked.
type UserProvider struct {
	ID             string
	UserID         string
	Provider       string  // "google", "apple"
	ProviderUserID string  // The unique ID from the provider (e.g., Google sub)
	ProviderEmail  *string // The email the provider reported (may differ from user.email)
	CreatedAt      time.Time
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

// OAuthCallbackResult is the outcome of an OAuth2 callback returned by OAuthSvc.HandleCallback.
// Using a flat struct (ProviderEmail string instead of a pointer into the oauth package) keeps
// auth free of any dependency on the oauth package, breaking the import cycle.
type OAuthCallbackResult struct {
	// IsNewUser is true if a brand-new account was created via social login.
	IsNewUser bool

	// IsExistingLink is true if the social identity was already linked — returning user.
	IsExistingLink bool

	// NeedsLinking is true if the provider email matches an existing password-based account.
	// The user must prove ownership before the accounts are merged (Phase 5B).
	NeedsLinking bool

	// User is the resolved user for IsNewUser or IsExistingLink cases. Nil when NeedsLinking.
	User *User

	// ProviderEmail is the email reported by the OAuth2 provider.
	// Used to populate AccountLinkRequired.provider_email when NeedsLinking is true.
	ProviderEmail string

	// ExistingUserID is the user_id of the existing account when NeedsLinking is true.
	ExistingUserID string

	// OAuthCallbackResult — add two new fields under ProviderEmail:
	// ProviderUserID is the provider's unique ID for the user (e.g., Google "sub").
	// Populated when NeedsLinking is true; used to create the provider link row.
	ProviderUserID string
	// ClientID is the client_id from the original GetOAuthURL request,
	// recovered from the state store. Used to issue correct scopes after linking.
	ClientID string
}

// OAuthSvc defines the contract the auth service uses for OAuth2 flows.
// Defined in the auth package so auth/service.go never needs to import the oauth package,
// avoiding a circular dependency (oauth already imports auth for shared domain types).
type OAuthSvc interface {
	// GenerateAuthURL returns the provider's consent URL and the server-generated CSRF state token.
	GenerateAuthURL(ctx context.Context, provider, clientID string) (authURL, state string, err error)

	// HandleCallback validates the state, exchanges the code, and resolves the user identity.
	HandleCallback(ctx context.Context, provider, code, state string) (*OAuthCallbackResult, error)

	// CreateLinkSession stores a link session and returns a short-lived raw token.
	// Called by OAuthCallback when NeedsLinking is true.
	CreateLinkSession(ctx context.Context, data *LinkSessionData) (rawToken string, err error)
	// ConsumeLinkSession validates and atomically deletes a link session.
	// Called by LinkProvider to retrieve the provider identity to be linked.
	ConsumeLinkSession(ctx context.Context, rawToken string) (*LinkSessionData, error)
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

// UserProviderRepository defines persistence operations for social provider links.
type UserProviderRepository interface {
	// Create inserts a new provider link. Returns ErrProviderAlreadyLinked if the
	// (provider, provider_user_id) pair already exists.
	Create(ctx context.Context, up *UserProvider) error
	// FindByProviderAndSubject looks up a linked provider by the provider name
	// and the provider's unique user ID. Returns ErrProviderNotLinked if not found.
	FindByProviderAndSubject(ctx context.Context, provider, providerUserID string) (*UserProvider, error)
	// FindByUserID returns all linked providers for a given user.
	FindByUserID(ctx context.Context, userID string) ([]*UserProvider, error)
	// Delete removes the provider link for the given user and provider name.
	// Returns ErrProviderNotLinked if the row doesn't exist.
	Delete(ctx context.Context, userID, provider string) error
	// CountByUserID returns the number of linked providers for a user.
	// Used to enforce the "must keep at least one credential" invariant before unlinking.
	CountByUserID(ctx context.Context, userID string) (int, error)
}
