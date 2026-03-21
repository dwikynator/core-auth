package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/crypto"
)

// Default token lifetimes. These will become per-tenant configurable in the future.
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

// GenerateTokenPair creates a signed access token and an opaque refresh token.
func (ts *TokenService) GenerateTokenPair(userID, role string) (*authv1.TokenPair, error) {
	// 1. Sign the access token (RS256 JWT).
	accessToken, err := ts.issuer.SignAccessToken(userID, role, DefaultAccessTokenTTL)
	if err != nil {
		return nil, err
	}

	// 2. Generate an opaque refresh token (random 32-byte hex string).
	// In the future, this will be stored in the `sessions` table for rotation
	// and revocation tracking. For now, it is stateless.
	refreshBytes := make([]byte, 32)
	if _, err := rand.Read(refreshBytes); err != nil {
		return nil, err
	}
	refreshToken := hex.EncodeToString(refreshBytes)

	return &authv1.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(DefaultAccessTokenTTL.Seconds()),
	}, nil
}
