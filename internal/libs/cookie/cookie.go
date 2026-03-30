package cookie

import (
	"net/http"
	"time"
)

const (
	RefreshTokenCookieName = "refresh_token"
	CSRFTokenCookieName    = "csrf_token"
)

// SetRefreshToken writes the refresh token as a secure HttpOnly cookie.
// The cookie is scoped to /v1/session to minimize its exposure surface —
// the browser will only send it on requests to that path.
func SetRefreshToken(w http.ResponseWriter, token string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    token,
		Path:     "/v1/session", // Scope to refresh/logout endpoints only
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,                 // Not accessible from JavaScript
		Secure:   secure,               // HTTPS-only (set to false only in local dev)
		SameSite: http.SameSiteLaxMode, // Lax allows navigation links; Strict blocks all cross-site
	})
}

// SetCSRFToken writes the CSRF synchronization token as a readable (non-HttpOnly)
// cookie. JavaScript must read this value and echo it back as the X-CSRF-Token header.
func SetCSRFToken(w http.ResponseWriter, token string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFTokenCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: false, // Must be readable by JavaScript
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearRefreshToken clears the refresh token cookie on logout.
func ClearRefreshToken(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Path:     "/v1/session",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// ClearCSRFToken clears the CSRF cookie on logout.
func ClearCSRFToken(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   CSRFTokenCookieName,
		Path:   "/",
		MaxAge: -1,
	})
}
