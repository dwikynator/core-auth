package csrf

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

const (
	HeaderName = "X-CSRF-Token"
	CookieName = "csrf_token"
)

// Generate creates a cryptographically random, URL-safe CSRF token.
func Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Middleware validates the X-CSRF-Token header against the csrf_token cookie
// on non-safe HTTP methods (POST, PUT, PATCH, DELETE).
//
// Safe methods (GET, HEAD, OPTIONS) are skipped — they must be idempotent
// and should never mutate server state.
//
// If the header is absent or does not match the cookie, the request is rejected
// with 403 Forbidden before it reaches any handler.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip safe methods — they cannot mutate state.
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			next.ServeHTTP(w, r)
			return
		}

		// Read the csrf_token cookie.
		cookie, err := r.Cookie(CookieName)
		if err != nil || cookie.Value == "" {
			http.Error(w, `{"error":{"code":"CSRF_TOKEN_MISSING","message":"CSRF token cookie is missing"}}`, http.StatusForbidden)
			return
		}

		// Read the X-CSRF-Token header sent by the JavaScript client.
		header := r.Header.Get(HeaderName)
		if header == "" {
			http.Error(w, `{"error":{"code":"CSRF_TOKEN_MISSING","message":"X-CSRF-Token header is required"}}`, http.StatusForbidden)
			return
		}

		// Constant-time comparison prevents timing attacks.
		if !secureCompare(cookie.Value, header) {
			http.Error(w, `{"error":{"code":"CSRF_TOKEN_INVALID","message":"CSRF token mismatch"}}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// secureCompare performs a constant-time string comparison.
// Using a simple string equality check would allow timing attacks where an
// attacker brute-forces the CSRF token character-by-character by measuring
// response times.
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
