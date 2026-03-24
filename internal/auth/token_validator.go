package auth

import (
	"context"
	"crypto/rsa"
	"fmt"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/crypto"
	"github.com/dwikynator/minato/merr"
	"github.com/golang-jwt/jwt/v5"
)

// TokenValidator holds the parsed RSA public key and a pre-built JWT parser.
// It is constructed once at startup and safe for concurrent use — both fields
// are immutable after NewTokenValidator returns.
type TokenValidator struct {
	blacklistRepo TokenBlacklistRepository
	parser        *jwt.Parser
	keyFunc       jwt.Keyfunc
}

// NewTokenValidator constructs a TokenValidator.
// The jwt.Parser is built once here — allocating it per-request would add
// unnecessary heap pressure on every authenticated call.
func NewTokenValidator(publicKey *rsa.PublicKey, issuer string, blacklistRepo TokenBlacklistRepository) *TokenValidator {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		return publicKey, nil
	}

	return &TokenValidator{
		blacklistRepo: blacklistRepo,
		parser:        parser,
		keyFunc:       keyFunc,
	}
}

// Validate is the function signature expected by middleware.WithAuthValidator.
// It receives the raw Bearer token string and must return the resolved identity
// (stored into the context) or an error.
//
// Performance path per request:
//  1. jwt.ParseWithClaims  — RSA verify + claims decode  (~1 ms)
//  2. redis.Exists          — O(1) blacklist check        (~0.2 ms loopback)
//
// Fail-closed on Redis error: if we cannot confirm the token is NOT revoked,
// we reject it. A brief Redis outage causes a 503; a revoked token slipping
// through would be a security incident.
func (v *TokenValidator) Validate(ctx context.Context, rawToken string) (context.Context, error) {
	// 1. Parse and verify the JWT (signature, expiry, issuer).
	token, err := v.parser.ParseWithClaims(rawToken, &crypto.Claims{}, v.keyFunc)
	if err != nil {
		return nil, merr.Unauthorized(authv1.ErrorReason_INVALID_TOKEN.String(), fmt.Sprintf("invalid or expired token: %v", err))
	}

	claims, ok := token.Claims.(*crypto.Claims)
	if !ok || !token.Valid {
		return nil, merr.Unauthorized(authv1.ErrorReason_INVALID_TOKEN.String(), "invalid token claims")
	}

	// 2. Check the Redis blacklist by jti.
	if claims.ID != "" {
		revoked, err := v.blacklistRepo.IsBlacklisted(ctx, claims.ID)
		if err != nil {
			return nil, merr.Internal(errReasonInternal, "failed to check token revocation status")
		}
		if revoked {
			return nil, ErrTokenRevoked
		}
	}

	// Store claims in context so handlers can call claimsFromContext(ctx)
	return context.WithValue(ctx, ClaimsContextKey, claims), nil
}
