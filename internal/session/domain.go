package session

import (
	"context"
	"time"

	"github.com/dwikynator/core-auth/internal/infra/audit"
	"github.com/dwikynator/core-auth/internal/tenant"
	"github.com/dwikynator/core-auth/internal/user"
)

type SessionUsecase interface {
	Logout(ctx context.Context, req *LogoutRequest) error
	CreateSessionAndTokens(ctx context.Context, userID, role, clientID string) (*TokenPair, string, error)
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*TokenPair, error)
	ListSessions(ctx context.Context) (*ListSessionsResponse, error)
	RevokeSession(ctx context.Context, sessionId string) error
	RevokeAllSessions(ctx context.Context) (*RevokeAllSessionsResponse, error)
	RevokeAllForUser(ctx context.Context, userID string, exceptSessionID string) (int, error)
}

type AuditLogger interface {
	Log(ctx context.Context, event audit.Event)
}

type RefreshTokenRequest struct {
	RefreshToken string
	ClientId     string
}

type ListSessionsResponse struct {
	Sessions  []*Session
	CurrentId string
}

type RevokeAllSessionsResponse struct {
	RevokedCount int
}

type TokenIssuer interface {
	SignAccessToken(userID, role string, scopes []string, accessTTL time.Duration) (string, error)
}

type TenantProvider interface {
	FindByClientID(ctx context.Context, clientID string) (*tenant.TenantConfig, error)
}

type UserProvider interface {
	FindByID(ctx context.Context, id string) (*user.User, error)
}

// Default token lifetimes.
// TODO: These will become per-tenant configurable in the future.
const (
	DefaultAccessTokenTTL  = 15 * time.Minute
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour // 30 days
)

type LogoutRequest struct {
	RefreshToken string
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

// TokenPairResult contains the generated tokens and the refresh token hash
// needed for session storage. The hash is never sent to the client.
type TokenPairResult struct {
	TokenPair        *TokenPair
	RefreshTokenHash string
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
