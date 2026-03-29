package oauth

import (
	"context"
	"fmt"
	"strings"

	domain "github.com/dwikynator/core-auth/internal/oauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	googleoidc "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

// GoogleProvider implements OAuthProvider for Google OAuth2.
type GoogleProvider struct {
	config *oauth2.Config
}

// NewGoogleProvider creates a Google OAuth2 provider.
//
// The redirectURL is computed from baseURL + the callback path.
// This ensures the redirect URI always matches what's configured in Google Console.
func NewGoogleProvider(clientID, clientSecret, baseURL string) *GoogleProvider {
	return &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  baseURL + "/v1/auth/oauth/google/callback",
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		},
	}
}

func (g *GoogleProvider) Name() string {
	return "google"
}

// AuthorizationURL returns the Google OAuth2 consent URL.
// AccessTypeOffline is intentionally NOT set — we don't need a Google refresh token.
// We only need the one-time authorization code to identify the user.
func (g *GoogleProvider) AuthorizationURL(state string) string {
	return g.config.AuthCodeURL(state)
}

// ExchangeCode exchanges the authorization code for user info by:
// 1. Exchanging the code for an OAuth2 token (which includes an ID token).
// 2. Calling Google's userinfo/tokeninfo endpoint to get user details.
//
// Why not decode the ID token ourselves? Using Google's official API client:
//   - Handles key rotation and signature verification transparently.
//   - Returns a clean Go struct instead of raw JWT claims.
//   - Is maintained by Google and follows their deprecation policies.
func (g *GoogleProvider) ExchangeCode(ctx context.Context, code string) (*domain.OAuthUserInfo, error) {
	// 1. Exchange the authorization code for tokens.
	token, err := g.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("google token exchange: %w", err)
	}

	// 2. Use the access token to fetch user info from Google.
	oauth2Service, err := googleoidc.NewService(ctx, option.WithTokenSource(g.config.TokenSource(ctx, token)))
	if err != nil {
		return nil, fmt.Errorf("google oauth2 service: %w", err)
	}

	userInfo, err := oauth2Service.Userinfo.Get().Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("google userinfo: %w", err)
	}

	return &domain.OAuthUserInfo{
		ProviderUserID: userInfo.Id,
		Email:          strings.ToLower(userInfo.Email),
		EmailVerified:  *userInfo.VerifiedEmail,
		Name:           userInfo.Name,
	}, nil
}
