package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/crypto"
)

// Default token lifetimes. These will become per-tenant configurable in Phase 3C.
const (
	DefaultAccessTokenTTL  = 15 * time.Minute
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour // 30 days
)

// TokenService generates access/refresh token pairs.
type TokenService struct {
	issuer *crypto.TokenIssuer
}

// NewTokenService creates a TokenService with the given JWT issuer.
func NewTokenService(issuer *crypto.TokenIssuer) *TokenService {
	return &TokenService{issuer: issuer}
}

// TokenPairResult contains the generated tokens and the refresh token hash
// needed for session storage. The hash is never sent to the client.
type TokenPairResult struct {
	TokenPair        *authv1.TokenPair
	RefreshTokenHash string
}

// GenerateTokenPair creates a signed access token and an opaque refresh token.
// The caller provides the access token TTL (tenant-specific or default).
// Returns both the client-facing TokenPair and the SHA-256 hash of the refresh
// token for session persistence.
func (ts *TokenService) GenerateTokenPair(userID, role string, accessTTL time.Duration) (*TokenPairResult, error) {
	// 1. Sign the access token (RS256 JWT).
	accessToken, err := ts.issuer.SignAccessToken(userID, role, accessTTL)
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

	return &TokenPairResult{
		TokenPair: &authv1.TokenPair{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    int64(accessTTL.Seconds()),
		},
		RefreshTokenHash: refreshTokenHash,
	}, nil
}

// HashRefreshToken computes the SHA-256 hash of a raw refresh token.
// Used during refresh rotation to look up the session by hash.
func HashRefreshToken(rawToken string) string {
	hash := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hash[:])
}
