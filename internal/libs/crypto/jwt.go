package crypto

import (
	"context"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// claimsContextKey is an unexported type to avoid context collisions.
type claimsContextKey struct{}

// ClaimsContextKey is the key used to store *crypto.Claims in the context.
// Exported so the auth middleware can inject claims, but the key type is
// unexported to prevent external packages from overwriting it.
var ClaimsContextKey = claimsContextKey{}

// Claims defines the JWT payload. Embedding jwt.RegisteredClaims provides
// standard fields (sub, iss, exp, iat, jti, etc.).
type Claims struct {
	Role   string   `json:"role"`
	Scopes []string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

// ClaimsFromContext extracts the validated JWT claims injected by the minato
// auth interceptor. The interceptor stores the return value of Validate,
// which is *crypto.Claims.
func ClaimsFromContext(ctx context.Context) (*Claims, error) {
	claims, ok := ctx.Value(ClaimsContextKey).(*Claims)
	if !ok || claims == nil {
		return nil, errors.New("missing or invalid authentication context")
	}
	return claims, nil
}
