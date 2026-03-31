package oauth

import (
	"context"
	"time"

	"github.com/dwikynator/core-auth/internal/infra/audit"
	"github.com/dwikynator/core-auth/internal/mfa"
	"github.com/dwikynator/core-auth/internal/session"
	"github.com/dwikynator/core-auth/internal/user"
)

type OAuthUseCase interface {
	GetOAuthURL(ctx context.Context, req *GetOAuthURLRequest) (string, error)
	OAuthCallback(ctx context.Context, req *OAuthCallbackRequest) (*OAuthCallbackResponse, error)
	LinkProvider(ctx context.Context, req *LinkProviderRequest) (*LinkProviderResponse, error)
	UnlinkProvider(ctx context.Context, provider string) error
}

type AuditLogger interface {
	Log(ctx context.Context, event audit.Event)
}

type LinkProviderRequest struct {
	LinkSessionToken string
	Password         string
}

type LinkProviderResponse struct {
	User     *user.User
	Tokens   *session.TokenPair
	ClientID string
}

type GetOAuthURLRequest struct {
	ClientId string
	Provider string
	State    string
}

type OAuthCallbackRequest struct {
	ClientId string
	Provider string
	State    string
	Code     string
}

type OAuthAccountLinkRequired struct {
	LinkSessionToken string
	Provider         string
	ProviderEmail    string
}

type OAuthSuccess struct {
	User   *user.User
	Tokens *session.TokenPair
}

type OAuthCallbackResponse struct {
	OAuthAccountLinkRequired *OAuthAccountLinkRequired
	OAuthSuccess             *OAuthSuccess
}

type UserFinder interface {
	FindByID(ctx context.Context, id string) (*user.User, error)
	FindByEmail(ctx context.Context, email string) (*user.User, error)
}

type UserService interface {
	CreateUser(ctx context.Context, user *user.User) error
	VerifyEmailAndActivate(ctx context.Context, userID string) error
}

type MFAProvider interface {
	IsEnrolled(ctx context.Context, userID string) bool
}

type MFAService interface {
	CreateSession(ctx context.Context, data *mfa.MFASessionData) (string, error)
}

type SessionService interface {
	CreateSessionAndTokens(ctx context.Context, userID, role, clientID string) (*session.TokenPair, string, error)
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
	// The user must prove ownership before the accounts are merged.
	NeedsLinking bool

	// User is the resolved user for IsNewUser or IsExistingLink cases. Nil when NeedsLinking.
	User *user.User

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

// OAuthUserInfo is the normalized user profile returned by any OAuth2 provider.
// All providers must map their response into this common structure.
type OAuthUserInfo struct {
	ProviderUserID string // Unique and stable user ID from the provider (e.g. Google "sub")
	Email          string // Provider-reported email (always lowercased)
	EmailVerified  bool   // Whether the provider considers this email verified
	Name           string // Display name (optional, not stored in our DB yet)
}

// OAuthProvider defines the contract for an OAuth2 identity provider.
// Each provider (Google, Apple) implements this interface.
//
// Why an interface? This lets us:
//   - Unit-test the OAuthService without hitting Google's APIs.
//   - Add Apple as a second provider without changing the orchestration layer.
//   - Swap the HTTP client in tests.
type OAuthProvider interface {
	// Name returns the provider identifier (e.g., "google", "apple").
	// This must match the `provider` values used in the proto and user_providers table.
	Name() string

	// AuthorizationURL returns the URL to redirect the user to for consent.
	// The state parameter is an opaque CSRF token that the callback must echo back.
	AuthorizationURL(state string) string

	// ExchangeCode exchanges an authorization code for user info.
	// This performs the token exchange and user profile fetch in one step.
	// Implementations should validate the ID token nonce if applicable.
	ExchangeCode(ctx context.Context, code string) (*OAuthUserInfo, error)
}

// StateStore manages short-lived OAuth2 CSRF state tokens.
// The state token is generated before the redirect to the provider and validated
// when the provider calls back — preventing cross-site request forgery.
//
// Implementations should enforce single-use semantics (consume-and-delete).
type StateStore interface {
	// Generate creates a new random state token tied to the given client_id
	// and returns it. The token is stored server-side with a short TTL.
	Generate(ctx context.Context, clientID string) (string, error)

	// Consume validates the state token and returns the client_id that was
	// stored with it. The token is deleted atomically — it cannot be reused.
	// Returns an error if the token is not found or expired.
	Consume(ctx context.Context, state string) (clientID string, err error)
}
