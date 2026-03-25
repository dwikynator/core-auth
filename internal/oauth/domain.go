package oauth

import "context"

// StateStore manages short-lived OAuth2 CSRF state tokens.
// The state token is generated before the redirect to the provider and validated
// when the provider calls back — preventing cross-site request forgery.
//
// Implementations should enforce single-use semantics (consume-and-delete).
type StateStore interface {
	// Generate creates a new random state token tied to the given client_id
	// and returns it. The token is stored server-side with a short TTL.
	Generate(ctx context.Context, clientID string) (string, error)

	// Consume validates the state token and returns the client_id that was
	// stored with it. The token is deleted atomically — it cannot be reused.
	// Returns an error if the token is not found or expired.
	Consume(ctx context.Context, state string) (clientID string, err error)
}
