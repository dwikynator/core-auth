package auth

import "net/http"

// NewJWKSHandler returns an http.HandlerFunc that serves pre-computed JWKS JSON.
// The JSON bytes are computed once at startup and served on every request
// with zero per-request allocations.
func NewJWKSHandler(jwksJSON []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Allow consuming services to cache the response for 1 hour.
		// When you rotate keys, deploy the new key and wait for caches to expire,
		// or bump the version via a new kid.
		w.Header().Set("Cache-Control", "public, max-age=3600")

		w.WriteHeader(http.StatusOK)
		w.Write(jwksJSON)
	}
}
