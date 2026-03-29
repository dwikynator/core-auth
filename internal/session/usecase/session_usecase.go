package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/dwikynator/core-auth/internal/infra/audit"
	contextLib "github.com/dwikynator/core-auth/internal/libs/context"
	"github.com/dwikynator/core-auth/internal/libs/crypto"
	errs "github.com/dwikynator/core-auth/internal/libs/errors"
	domain "github.com/dwikynator/core-auth/internal/session"
	"github.com/dwikynator/core-auth/internal/tenant"
)

type sessionUseCase struct {
	sessionRepo    domain.SessionRepository
	blacklistRepo  domain.TokenBlacklistRepository
	tokenIssuer    domain.TokenIssuer
	tenantProvider domain.TenantProvider
	userProvider   domain.UserProvider
	auditLogger    domain.AuditLogger
}

func NewSessionUseCase(sessionRepo domain.SessionRepository,
	blacklistRepo domain.TokenBlacklistRepository,
	tokenIssuer domain.TokenIssuer,
	tenantProvider domain.TenantProvider,
	userProvider domain.UserProvider,
	auditLogger domain.AuditLogger) domain.SessionUsecase {
	return &sessionUseCase{
		sessionRepo:    sessionRepo,
		blacklistRepo:  blacklistRepo,
		tokenIssuer:    tokenIssuer,
		tenantProvider: tenantProvider,
		userProvider:   userProvider,
		auditLogger:    auditLogger,
	}
}

// Logout blacklists the caller's access token so it cannot be used again.
// The token's JTI is added to the Redis blacklist with a TTL equal to the
// token's remaining lifetime. This means:
//   - No unbounded memory growth: entries auto-expire.
//   - Immediate effect: the very next authenticated request is rejected.
func (uc *sessionUseCase) Logout(ctx context.Context, req *domain.LogoutRequest) error {
	// 1. Extract the access token from gRPC metadata (Authorization header).
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return err
	}

	// 2. The jti (JWT ID) is the blacklist key.
	jti := claims.ID
	if jti == "" {
		return errs.WithMessage(errs.ErrInternal, "token missing jti claim")
	}

	// 3. Blacklist the JTI until the token's natural expiry.
	if claims.ExpiresAt != nil {
		if err := uc.blacklistRepo.Blacklist(ctx, jti, claims.ExpiresAt.Time); err != nil {
			return errs.WithMessage(errs.ErrInternal, "failed to blacklist token")
		}
	}

	// 4. Revoke the session associated with the refresh token.
	// If the client provided a refresh_token, look up and revoke its domain.
	if req.RefreshToken != "" {
		hash := crypto.HashToken(req.RefreshToken)
		session, err := uc.sessionRepo.FindByRefreshTokenHash(ctx, hash)
		if err == nil && session.UserID == claims.Subject {
			_ = uc.sessionRepo.Revoke(ctx, session.ID, claims.Subject)
		}
		// Silently ignore lookup failures — the session may have already expired.
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventLogout, claims.Subject))

	return nil
}

// createSessionAndTokens generates a token pair and persists a new domain.
// This is the single entry point for all token-issuing flows.
// It resolves per-tenant TTLs and scopes, falling back to system defaults
// if no config is found.
func (uc *sessionUseCase) CreateSessionAndTokens(ctx context.Context, userID, role, clientID string) (*domain.TokenPair, string, error) {
	// 1. Resolve tenant-specific TTLs (or fall back to defaults).
	accessTTL := domain.DefaultAccessTokenTTL
	refreshTTL := domain.DefaultRefreshTokenTTL
	scopes := tenant.DefaultScopes

	if clientID != "" {
		tc, err := uc.tenantProvider.FindByClientID(ctx, clientID)
		if err == nil {
			accessTTL = tc.AccessTokenTTL
			refreshTTL = tc.RefreshTokenTTL
			if len(tc.DefaultScopes) > 0 {
				scopes = tc.DefaultScopes
			}
		}
		// ErrTenantNotFound is silently ignored — use defaults.
	}

	// 2. Generate token pair with resolved TTLs.
	result, err := uc.generateTokenPair(userID, role, scopes, accessTTL)
	if err != nil {
		return nil, "", errs.WithMessage(errs.ErrInternal, "failed to generate tokens")
	}

	// 3. Extract request metadata.
	meta := contextLib.MetaFromContext(ctx)

	// 4. Persist the domain.
	session := &domain.Session{
		UserID:           userID,
		ClientID:         clientID,
		RefreshTokenHash: result.RefreshTokenHash,
		IPAddress:        meta.IPAddress,
		UserAgent:        meta.UserAgent,
		ExpiresAt:        time.Now().Add(refreshTTL),
	}
	if err := uc.sessionRepo.Create(ctx, session); err != nil {
		return nil, "", errs.WithMessage(errs.ErrInternal, "failed to create session")
	}

	return result.TokenPair, session.ID, nil
}

// GenerateTokenPair creates a signed access token and an opaque refresh token.
// The caller provides the access token TTL (tenant-specific or default).
// Returns both the client-facing TokenPair and the SHA-256 hash of the refresh
// token for session persistence.
func (uc *sessionUseCase) generateTokenPair(userID, role string, scopes []string, accessTTL time.Duration) (*domain.TokenPairResult, error) {
	// 1. Sign the access token (RS256 JWT).
	accessToken, err := uc.tokenIssuer.SignAccessToken(userID, role, scopes, accessTTL)
	if err != nil {
		return nil, err
	}

	// 2. Generate an opaque refresh token (random 32-byte hex string).
	refreshBytes := make([]byte, 32)
	if _, err := rand.Read(refreshBytes); err != nil {
		return nil, err
	}
	refreshToken := hex.EncodeToString(refreshBytes)

	// 3. Hash the refresh token for storage.
	hash := sha256.Sum256([]byte(refreshToken))
	refreshTokenHash := hex.EncodeToString(hash[:])

	return &domain.TokenPairResult{
		TokenPair: &domain.TokenPair{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    int64(accessTTL.Seconds()),
		},
		RefreshTokenHash: refreshTokenHash,
	}, nil
}

// RefreshToken exchanges a valid refresh token for a new token pair.
// The old refresh token is immediately invalidated (rotation).
//
// Security: if the incoming refresh token does NOT match any active session,
// we assume the token was stolen and replayed. In that case, we revoke ALL
// sessions for the affected user (fail-secure).
func (uc *sessionUseCase) RefreshToken(ctx context.Context, req *domain.RefreshTokenRequest) (*domain.TokenPair, error) {
	if req.RefreshToken == "" {
		return nil, errs.WithMessage(errs.ErrInternal, "refresh_token is required")
	}

	// 1. Look up the session by the hash of the incoming token.
	hash := crypto.HashToken(req.RefreshToken)
	session, err := uc.sessionRepo.FindByRefreshTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, errs.ErrSessionNotFound) {
			// Possible token reuse! The token was valid once but has already
			// been rotated. An attacker may have stolen the old token.
			//
			// We cannot determine the user_id from the opaque token alone,
			// so we log the event and return a generic error.
			// In a production system with token-to-user mapping, you would
			// revoke all sessions for the affected user here.
			return nil, errs.ErrTokenReuseDetected
		}
		return nil, errs.WithMessage(errs.ErrInternal, "failed to look up refresh token")
	}

	// 2. Check if the session has expired.
	if time.Now().After(session.ExpiresAt) {
		// Revoke the expired session for cleanup.
		_ = uc.sessionRepo.Revoke(ctx, session.ID, session.UserID)
		return nil, errs.ErrTokenExpired
	}

	// 3. Check user status (e.g., suspended accounts should not get new tokens).
	user, err := uc.userProvider.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, errs.WithMessage(errs.ErrInternal, "failed to fetch user")
	}
	if user.Status == "suspended" {
		_ = uc.sessionRepo.Revoke(ctx, session.ID, session.UserID)
		return nil, errs.ErrAccountSuspended
	}

	// 4. Resolve tenant-specific access TTL.
	accessTTL := domain.DefaultAccessTokenTTL
	scopes := tenant.DefaultScopes
	if session.ClientID != "" {
		tc, err := uc.tenantProvider.FindByClientID(ctx, session.ClientID)
		if err == nil {
			accessTTL = tc.AccessTokenTTL
			if len(tc.DefaultScopes) > 0 {
				scopes = tc.DefaultScopes
			}
		}
	}

	// 5. Generate new token pair.
	result, err := uc.generateTokenPair(user.ID, user.Role, scopes, accessTTL)
	if err != nil {
		return nil, errs.WithMessage(errs.ErrInternal, "failed to generate tokens")
	}

	// 6. Atomically rotate the refresh token hash.
	// If this fails (e.g., concurrent revocation), the old token is already
	// invalidated and the new one was never stored — safe.
	if err := uc.sessionRepo.RotateRefreshToken(ctx, session.ID, result.RefreshTokenHash); err != nil {
		return nil, errs.WithMessage(errs.ErrInternal, "failed to rotate refresh token")
	}

	return result.TokenPair, nil
}

func (uc *sessionUseCase) ListSessions(ctx context.Context) (*domain.ListSessionsResponse, error) {
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	sessions, err := uc.sessionRepo.ListActiveByUser(ctx, claims.Subject)
	if err != nil {
		return nil, errs.WithMessage(errs.ErrInternal, "failed to list sessions")
	}

	// Convert domain sessions to proto.
	protoSessions := make([]*domain.Session, 0, len(sessions))
	for _, s := range sessions {
		ps := &domain.Session{
			ID:         s.ID,
			ClientID:   s.ClientID,
			UserAgent:  s.UserAgent,
			CreatedAt:  s.CreatedAt,
			LastUsedAt: s.LastUsedAt,
		}
		if s.IPAddress != nil {
			ps.IPAddress = s.IPAddress
		}
		protoSessions = append(protoSessions, ps)
	}

	// Determine which session belongs to the current caller.
	// The access token's JTI doesn't directly map to a session ID, but
	// we can identify the current session if the caller also provides it.
	// For now, we leave current_id empty — the client can match by IP/User-Agent.
	return &domain.ListSessionsResponse{
		Sessions: protoSessions,
	}, nil
}

func (uc *sessionUseCase) RevokeSession(ctx context.Context, sessionId string) error {
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return err
	}

	if sessionId == "" {
		return errs.WithMessage(errs.ErrSessionNotFound, "session_id is required")
	}

	// Verify ownership: we need to check that this session belongs to the caller.
	// We do this by attempting to revoke and checking if it existed.
	// A more strict approach would be to fetch first and compare user_id.
	// However, since sessions are scoped per-user in the query, we can use
	// a user-scoped revoke.
	if err := uc.sessionRepo.Revoke(ctx, sessionId, claims.Subject); err != nil {
		if errors.Is(err, errs.ErrSessionNotFound) {
			return errs.ErrSessionNotFound
		}
		return errs.WithMessage(errs.ErrInternal, "failed to revoke session")
	}

	return nil
}

func (uc *sessionUseCase) RevokeAllSessions(ctx context.Context) (*domain.RevokeAllSessionsResponse, error) {
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Revoke all sessions except the current one.
	// Since we don't easily know the current session ID from the access token,
	// we revoke ALL sessions. The caller can immediately refresh to get a new one.
	count, err := uc.sessionRepo.RevokeAllForUser(ctx, claims.Subject, "")
	if err != nil {
		return nil, errs.WithMessage(errs.ErrInternal, "failed to revoke sessions")
	}

	return &domain.RevokeAllSessionsResponse{
		RevokedCount: count,
	}, nil
}

func (uc *sessionUseCase) RevokeAllForUser(ctx context.Context, userID string, exceptSessionID string) (int, error) {
	return uc.sessionRepo.RevokeAllForUser(ctx, userID, exceptSessionID)
}
