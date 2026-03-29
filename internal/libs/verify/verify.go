package verify

import (
	"context"

	"github.com/dwikynator/core-auth/internal/libs/crypto"
	"github.com/dwikynator/minato/merr"
)

// RequireScope verifies the authenticated caller's token contains the required scope.
// Returns the claims on success, or a Forbidden error if the scope is missing.
func RequireScope(ctx context.Context, scope string) (*crypto.Claims, error) {
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	for _, s := range claims.Scopes {
		if s == scope {
			return claims, nil
		}
	}

	return nil, merr.Forbidden("INSUFFICIENT_SCOPE", "token missing required scope: "+scope)
}
