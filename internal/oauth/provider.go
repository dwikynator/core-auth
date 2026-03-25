package oauth

import "context"

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
