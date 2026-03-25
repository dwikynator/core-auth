package oauth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/dwikynator/core-auth/internal/auth"
)

// OAuthService orchestrates the OAuth2 login flow.
// It satisfies the auth.OAuthSvc interface.
type OAuthService struct {
	providers    map[string]OAuthProvider
	stateStore   StateStore
	userRepo     auth.UserRepository
	providerRepo auth.UserProviderRepository
}

// NewOAuthService creates a new OAuthService.
// providers is a map of provider name → implementation.
// Only initialized providers are available — if Google creds are empty,
// don't add the Google provider and the service will return "unsupported provider".
func NewOAuthService(
	stateStore StateStore,
	userRepo auth.UserRepository,
	providerRepo auth.UserProviderRepository,
	providers ...OAuthProvider,
) *OAuthService {
	pm := make(map[string]OAuthProvider, len(providers))
	for _, p := range providers {
		pm[p.Name()] = p
	}

	return &OAuthService{
		providers:    pm,
		stateStore:   stateStore,
		userRepo:     userRepo,
		providerRepo: providerRepo,
	}
}

// GetProvider returns the provider by name, or an error if not registered.
func (s *OAuthService) GetProvider(name string) (OAuthProvider, error) {
	p, ok := s.providers[name]
	if !ok {
		return nil, auth.ErrUnsupportedProvider
	}
	return p, nil
}

// GenerateAuthURL generates the authorization URL for the given provider.
// Returns the URL and the state token (for the client to use in its callback).
// Implements auth.OAuthSvc.
func (s *OAuthService) GenerateAuthURL(ctx context.Context, providerName, clientID string) (authURL string, state string, err error) {
	provider, err := s.GetProvider(providerName)
	if err != nil {
		return "", "", err
	}

	state, err = s.stateStore.Generate(ctx, clientID)
	if err != nil {
		return "", "", fmt.Errorf("generate state: %w", err)
	}

	authURL = provider.AuthorizationURL(state)
	return authURL, state, nil
}

// HandleCallback processes the OAuth2 callback.
// Returns *auth.OAuthCallbackResult (defined in the auth package) to avoid
// a circular import — auth imports oauth would create a cycle since oauth imports auth.
// Implements auth.OAuthSvc.
//
// The flow is:
//  1. Validate state (CSRF check).
//  2. Exchange the authorization code for user info.
//  3. Check if this social identity is already linked → returning user.
//  4. Check if the email matches an existing account → needs linking.
//  5. Otherwise → create a new user and link the provider.
func (s *OAuthService) HandleCallback(ctx context.Context, providerName, code, state string) (*auth.OAuthCallbackResult, error) {
	// 1. Validate and consume the state token.
	clientID, err := s.stateStore.Consume(ctx, state)
	if err != nil {
		return nil, auth.ErrOAuthStateMismatch
	}
	_ = clientID // Will be used in Phase 5B for tenant-scoped linking

	// 2. Get the provider and exchange the code.
	provider, err := s.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	userInfo, err := provider.ExchangeCode(ctx, code)
	if err != nil {
		slog.Error("oauth code exchange failed", "provider", providerName, "error", err)
		return nil, auth.ErrOAuthCodeInvalid
	}

	// 3. Check if this provider identity is already linked to a user.
	existingLink, err := s.providerRepo.FindByProviderAndSubject(ctx, providerName, userInfo.ProviderUserID)
	if err == nil {
		// Provider is already linked — this is a returning social login.
		user, err := s.userRepo.FindByID(ctx, existingLink.UserID)
		if err != nil {
			return nil, fmt.Errorf("fetch linked user: %w", err)
		}

		return &auth.OAuthCallbackResult{
			IsExistingLink: true,
			User:           user,
			ProviderEmail:  userInfo.Email,
		}, nil
	}
	// If the error is "not linked", continue. Any other error is unexpected.
	if err != auth.ErrProviderNotLinked {
		return nil, fmt.Errorf("check provider link: %w", err)
	}

	// 4. Check if an existing user has the same email.
	if userInfo.Email != "" {
		existingUser, err := s.userRepo.FindByEmail(ctx, userInfo.Email)
		if err == nil {
			// Email clash — the user needs to prove they own the existing account.
			return &auth.OAuthCallbackResult{
				NeedsLinking:   true,
				ProviderEmail:  userInfo.Email,
				ExistingUserID: existingUser.ID,
			}, nil
		}
		if err != auth.ErrUserNotFound {
			return nil, fmt.Errorf("check email conflict: %w", err)
		}
	}

	// 5. No existing user — create a new account and link the provider.
	newUser := &auth.User{
		Email:  &userInfo.Email,
		Role:   "user",
		Status: "active", // Social logins bypass email verification — the provider verified it.
	}

	// If the provider says the email is verified, mark it as verified.
	if userInfo.EmailVerified {
		now := ctx.Value(auth.ClaimsContextKey) // won't have claims in this context
		_ = now
		// We'll set email_verified_at after creation via repo.
	}

	if err := s.userRepo.Create(ctx, newUser); err != nil {
		return nil, fmt.Errorf("create social user: %w", err)
	}

	// Mark email as verified if the provider says so.
	// Social providers like Google have already verified the email.
	if userInfo.EmailVerified {
		if err := s.userRepo.VerifyEmailAndActivate(ctx, newUser.ID); err != nil {
			slog.Error("failed to verify social user email", "user_id", newUser.ID, "error", err)
			// Non-fatal: the user is already active, they just won't show as email_verified.
		}
	}

	// Link the provider to the new user.
	up := &auth.UserProvider{
		UserID:         newUser.ID,
		Provider:       providerName,
		ProviderUserID: userInfo.ProviderUserID,
		ProviderEmail:  &userInfo.Email,
	}
	if err := s.providerRepo.Create(ctx, up); err != nil {
		slog.Error("failed to link provider to new user", "user_id", newUser.ID, "provider", providerName, "error", err)
		// Non-fatal: user was created but provider wasn't linked.
		// They can retry or link later.
	}

	// Re-fetch to get all generated fields (id, email_verified_at, etc.)
	newUser, err = s.userRepo.FindByID(ctx, newUser.ID)
	if err != nil {
		return nil, fmt.Errorf("re-fetch new user: %w", err)
	}

	return &auth.OAuthCallbackResult{
		IsNewUser:     true,
		User:          newUser,
		ProviderEmail: userInfo.Email,
	}, nil
}
