package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/dwikynator/core-auth/internal/infra/audit"
	"github.com/dwikynator/core-auth/internal/libs/crypto"
	errs "github.com/dwikynator/core-auth/internal/libs/errors"
	"github.com/dwikynator/core-auth/internal/mfa"
	"github.com/dwikynator/core-auth/internal/oauth"
	userdomain "github.com/dwikynator/core-auth/internal/user"
)

type oauthUseCase struct {
	stateStore       oauth.StateStore
	linkStore        oauth.LinkSessionStore
	userProviderRepo oauth.UserProviderRepository
	userFinder       oauth.UserFinder
	userService      oauth.UserService
	mfaService       oauth.MFAService
	mfaProvider      oauth.MFAProvider
	sessionService   oauth.SessionService
	auditLogger      oauth.AuditLogger
	providers        map[string]oauth.OAuthProvider
}

func NewOAuthUseCase(
	stateStore oauth.StateStore,
	linkStore oauth.LinkSessionStore,
	userProviderRepo oauth.UserProviderRepository,
	userFinder oauth.UserFinder,
	userService oauth.UserService,
	mfaService oauth.MFAService,
	mfaProvider oauth.MFAProvider,
	sessionService oauth.SessionService,
	auditLogger oauth.AuditLogger,
	providers ...oauth.OAuthProvider,
) oauth.OAuthUseCase {
	pm := make(map[string]oauth.OAuthProvider, len(providers))
	for _, p := range providers {
		pm[p.Name()] = p
	}
	return &oauthUseCase{
		stateStore:       stateStore,
		linkStore:        linkStore,
		userProviderRepo: userProviderRepo,
		userFinder:       userFinder,
		userService:      userService,
		mfaService:       mfaService,
		mfaProvider:      mfaProvider,
		sessionService:   sessionService,
		auditLogger:      auditLogger,
		providers:        pm,
	}
}

// GetOAuthURL returns the OAuth2 authorization URL for the requested provider.
// The client should redirect the user to this URL to begin the consent flow.
func (uc *oauthUseCase) GetOAuthURL(ctx context.Context, req *oauth.GetOAuthURLRequest) (string, error) {
	if req.Provider == "" {
		return "", errs.ErrUnsupportedProvider
	}

	if req.ClientId == "" {
		return "", errs.ErrInvalidIdentifier
	}

	authURL, _, err := uc.generateAuthURL(ctx, req.Provider, req.ClientId)
	if err != nil {
		return "", err
	}

	return authURL, nil
}

// OAuthCallback handles the redirect from the OAuth2 provider.
// It exchanges the authorization code for user info and either:
//   - Returns tokens for a new or returning social user (OAuthSuccess)
//   - Returns account_link_required if the email conflicts with an existing account
func (uc *oauthUseCase) OAuthCallback(ctx context.Context, req *oauth.OAuthCallbackRequest) (*oauth.OAuthCallbackResponse, error) {
	providerName := req.Provider
	if providerName == "" {
		return nil, errs.ErrUnsupportedProvider
	}

	code := req.Code
	if code == "" {
		return nil, errs.ErrInvalidIdentifier
	}

	state := req.State
	if state == "" {
		return nil, errs.ErrOAuthStateMismatch
	}

	// 1. Handle the callback through the OAuthService.
	result, err := uc.HandleCallback(ctx, providerName, code, state)
	if err != nil {
		return nil, err
	}

	// 2. Branch on the result.
	if result.NeedsLinking {
		// Create a short-lived link session so the client can complete the merge
		// without restarting the OAuth2 flow from scratch.
		linkToken, err := uc.createLinkSession(ctx, &oauth.LinkSessionData{
			Provider:       providerName,
			ProviderUserID: result.ProviderUserID,
			ProviderEmail:  result.ProviderEmail,
			ExistingUserID: result.ExistingUserID,
			ClientID:       result.ClientID,
		})
		if err != nil {
			// Non-fatal: log and fall through without a token.
			// The client will still receive account_link_required and can
			// restart the flow manually if link_session_token is empty.
			slog.Error("failed to create link session", "error", err)
			linkToken = ""
		}

		return &oauth.OAuthCallbackResponse{
			OAuthAccountLinkRequired: &oauth.OAuthAccountLinkRequired{
				LinkSessionToken: linkToken,
				Provider:         providerName,
				ProviderEmail:    result.ProviderEmail,
			},
		}, nil
	}

	// 3. Existing link or new user — issue tokens.
	user := result.User

	// Check account status.
	switch user.Status {
	case "suspended":
		return nil, errs.ErrAccountSuspended
	case "deleted":
		return nil, errs.ErrAccountDeleted
	}

	// Check if MFA is enrolled.
	if uc.mfaProvider.IsEnrolled(ctx, user.ID) {
		// MFA is active — create a short-lived MFA session instead of issuing tokens.
		mfaToken, err := uc.mfaService.CreateSession(ctx, &mfa.MFASessionData{
			UserID:   user.ID,
			ClientID: req.ClientId,
			Role:     user.Role,
		})
		if err != nil {
			return nil, errs.WithMessage(errs.ErrInternal, "failed to create MFA session")
		}

		// Return MFA required via the OAuthSuccess path with an indicator.
		// Note: The proto doesn't have a dedicated MFA path for OAuth callbacks.
		// For now, we return OAuthSuccess with empty tokens and the MFA session token
		// in a way the client can detect. Alternatively, you can extend the proto.
		//
		// A pragmatic approach: return the MFA required as an error so the client
		// retries via ChallengeMFA, identical to the password login flow.
		_ = mfaToken
		return nil, errs.WithMessage(errs.ErrMFARequired, "multi-factor authentication required; use ChallengeMFA with the mfa_session_token")
	}

	// 4. Generate token pair.
	// For the client_id, use the one from the original GetOAuthURL request
	// (stored in the state). For now, we use the one from the callback request.
	tokens, _, err := uc.sessionService.CreateSessionAndTokens(ctx, user.ID, user.Role, req.ClientId)
	if err != nil {
		return nil, err
	}

	return &oauth.OAuthCallbackResponse{
		OAuthSuccess: &oauth.OAuthSuccess{
			User:   user,
			Tokens: tokens,
		},
	}, nil
}

// LinkProvider completes the account-linking flow.
// The user authenticates their existing account by providing its password,
// and the social identity from the link session is attached to that account.
func (uc *oauthUseCase) LinkProvider(ctx context.Context, req *oauth.LinkProviderRequest) (*oauth.LinkProviderResponse, error) {
	linkToken := req.LinkSessionToken
	if linkToken == "" {
		return nil, errs.WithMessage(errs.ErrLinkSessionExpired, "link_session_token is required")
	}
	password := req.Password
	if password == "" {
		return nil, errs.WithMessage(errs.ErrInvalidIdentifier, "password is required")
	}
	// 1. Retrieve and consume the link session (single-use, atomic).
	session, err := uc.consumeLinkSession(ctx, linkToken)
	if err != nil {
		return nil, err // ErrLinkSessionExpired
	}
	// 2. Load the conflicting user account.
	user, err := uc.userFinder.FindByID(ctx, session.ExistingUserID)
	if err != nil {
		return nil, err
	}
	// 3. Verify the user's password to prove they own the existing account.
	if user.PasswordHash == nil {
		// Social-only users have no password. This path shouldn't be reachable
		// today (email conflicts only happen with password-based accounts), but
		// guard it defensively.
		return nil, errs.WithMessage(errs.ErrNoPassword, "this account has no password; contact support to link your provider")
	}
	if _, err := crypto.ComparePassword(password, *user.PasswordHash); err != nil {
		return nil, errs.ErrInvalidCredentials
	}
	// 4. Check account status.
	switch user.Status {
	case "suspended":
		return nil, errs.ErrAccountSuspended
	case "deleted":
		return nil, errs.ErrAccountDeleted
	}
	// 5. Create the provider link.
	up := &oauth.UserProvider{
		UserID:         user.ID,
		Provider:       session.Provider,
		ProviderUserID: session.ProviderUserID,
		ProviderEmail:  &session.ProviderEmail,
	}
	if err := uc.userProviderRepo.Create(ctx, up); err != nil {
		return nil, err // ErrProviderAlreadyLinked if a race occurred
	}
	// 6. Issue a token pair for the now-linked account.
	clientID := session.ClientID
	if clientID == "" {
		clientID = "default" // fallback — should not normally happen
	}
	tokens, _, err := uc.sessionService.CreateSessionAndTokens(ctx, user.ID, user.Role, clientID)
	if err != nil {
		return nil, err
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventOAuthLink, user.ID))

	return &oauth.LinkProviderResponse{
		User:     user,
		Tokens:   tokens,
		ClientID: clientID,
	}, nil
}

// UnlinkProvider removes a social provider link from the authenticated user's account.
// The user must retain at least one credential (password or another provider) to prevent lockout.
func (uc *oauthUseCase) UnlinkProvider(ctx context.Context, provider string) error {
	if provider == "" {
		return errs.WithMessage(errs.ErrUnsupportedProvider, "provider is required")
	}
	// 1. Resolve the caller from the JWT.
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return err
	}
	userID := claims.Subject
	// 2. Load the user to check whether they have a password.
	user, err := uc.userFinder.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	// 3. Enforce the "last credential" invariant before touching the database.
	//    Check: does the user have a password OR at least 2 providers?
	providerCount, err := uc.userProviderRepo.CountByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("count providers: %w", err)
	}
	hasPassword := user.PasswordHash != nil
	if !hasPassword && providerCount <= 1 {
		// Unlinking would leave the account with no way to log in.
		return errs.ErrCannotUnlinkLastCredential
	}
	// 4. Delete the provider link.
	if err := uc.userProviderRepo.Delete(ctx, userID, provider); err != nil {
		return err // ErrProviderNotLinked → 404
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventOAuthUnlink, userID))

	return nil
}

// GetProvider returns the provider by name, or an error if not registered.
func (uc *oauthUseCase) getProvider(name string) (oauth.OAuthProvider, error) {
	p, ok := uc.providers[name]
	if !ok {
		return nil, errs.ErrUnsupportedProvider
	}
	return p, nil
}

// GenerateAuthURL generates the authorization URL for the given provider.
// Returns the URL and the state token (for the client to use in its callback).
// Implements auth.OAuthSvc.
func (uc *oauthUseCase) generateAuthURL(ctx context.Context, providerName, clientID string) (authURL string, state string, err error) {
	provider, err := uc.getProvider(providerName)
	if err != nil {
		return "", "", err
	}

	state, err = uc.stateStore.Generate(ctx, clientID)
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
func (uc *oauthUseCase) HandleCallback(ctx context.Context, providerName, code, state string) (*oauth.OAuthCallbackResult, error) {
	// 1. Validate and consume the state token.
	clientID, err := uc.stateStore.Consume(ctx, state)
	if err != nil {
		return nil, errs.ErrOAuthStateMismatch
	}

	// 2. Get the provider and exchange the code.
	provider, err := uc.getProvider(providerName)
	if err != nil {
		return nil, err
	}

	userInfo, err := provider.ExchangeCode(ctx, code)
	if err != nil {
		slog.Error("oauth code exchange failed", "provider", providerName, "error", err)
		return nil, errs.ErrOAuthCodeInvalid
	}

	// 3. Check if this provider identity is already linked to a user.
	existingLink, err := uc.userProviderRepo.FindByProviderAndSubject(ctx, providerName, userInfo.ProviderUserID)
	if err == nil {
		// Provider is already linked — this is a returning social login.
		user, err := uc.userFinder.FindByID(ctx, existingLink.UserID)
		if err != nil {
			return nil, fmt.Errorf("fetch linked user: %w", err)
		}

		return &oauth.OAuthCallbackResult{
			IsExistingLink: true,
			User:           user,
			ProviderEmail:  userInfo.Email,
		}, nil
	}
	// If the error is "not linked", continue. Any other error is unexpected.
	if err != errs.ErrProviderNotLinked {
		return nil, fmt.Errorf("check provider link: %w", err)
	}

	fmt.Println(userInfo)

	// 4. Check if an existing user has the same email.
	if userInfo.Email != "" {
		existingUser, err := uc.userFinder.FindByEmail(ctx, userInfo.Email)
		if err == nil {
			// Email clash — the user needs to prove they own the existing account.
			return &oauth.OAuthCallbackResult{
				NeedsLinking:   true,
				ProviderEmail:  userInfo.Email,
				ProviderUserID: userInfo.ProviderUserID,
				ClientID:       clientID,
				ExistingUserID: existingUser.ID,
			}, nil
		}
		if !errors.Is(err, errs.ErrUserNotFound) {
			return nil, fmt.Errorf("check email conflict: %w", err)
		}
	}

	// 5. No existing user — create a new account and link the provider.
	newUser := &userdomain.User{
		Email:  &userInfo.Email,
		Role:   "user",
		Status: "active", // Social logins bypass email verification — the provider verified it.
	}

	// If the provider says the email is verified, mark it as verified.
	if userInfo.EmailVerified {
		now := ctx.Value(crypto.ClaimsContextKey) // won't have claims in this context
		_ = now
		// We'll set email_verified_at after creation via repo.
	}

	if err := uc.userService.CreateUser(ctx, newUser); err != nil {
		return nil, fmt.Errorf("create social user: %w", err)
	}

	// Mark email as verified if the provider says so.
	// Social providers like Google have already verified the email.
	if userInfo.EmailVerified {
		if err := uc.userService.VerifyEmailAndActivate(ctx, newUser.ID); err != nil {
			slog.Error("failed to verify social user email", "user_id", newUser.ID, "error", err)
			// Non-fatal: the user is already active, they just won't show as email_verified.
		}
	}

	// Link the provider to the new user.
	up := &oauth.UserProvider{
		UserID:         newUser.ID,
		Provider:       providerName,
		ProviderUserID: userInfo.ProviderUserID,
		ProviderEmail:  &userInfo.Email,
	}
	if err := uc.userProviderRepo.Create(ctx, up); err != nil {
		slog.Error("failed to link provider to new user", "user_id", newUser.ID, "provider", providerName, "error", err)
		// Non-fatal: user was created but provider wasn't linked.
		// They can retry or link later.
	}

	// Re-fetch to get all generated fields (id, email_verified_at, etc.)
	newUser, err = uc.userFinder.FindByID(ctx, newUser.ID)
	if err != nil {
		return nil, fmt.Errorf("re-fetch new user: %w", err)
	}

	return &oauth.OAuthCallbackResult{
		IsNewUser:     true,
		User:          newUser,
		ProviderEmail: userInfo.Email,
	}, nil
}

// CreateLinkSession stores a link session and returns the raw token.
// Implements auth.OAuthSvc.
func (uc *oauthUseCase) createLinkSession(ctx context.Context, data *oauth.LinkSessionData) (string, error) {
	return uc.linkStore.Create(ctx, data)
}

// ConsumeLinkSession retrieves and atomically deletes a link session.
// Implements auth.OAuthSvc.
func (uc *oauthUseCase) consumeLinkSession(ctx context.Context, rawToken string) (*oauth.LinkSessionData, error) {
	return uc.linkStore.Consume(ctx, rawToken)
}
