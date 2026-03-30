package delivery

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dwikynator/core-auth/internal/libs/cookie"
	"github.com/dwikynator/core-auth/internal/libs/csrf"
	"github.com/dwikynator/core-auth/internal/session"
	"github.com/dwikynator/minato"
)

type sessionHTTPHandler struct {
	sessionUc    session.SessionUsecase
	secureCookie bool
}

// RegisterSessionHTTPHandler registers the pure-HTTP cookie-based session routes.
// These routes are for browser web clients only.
// Mobile apps and non-browser clients continue to use the gRPC-gateway JSON endpoints.
func RegisterSessionHTTPHandler(s *minato.Server, sessionUc session.SessionUsecase, secureCookie bool) {
	h := &sessionHTTPHandler{
		sessionUc:    sessionUc,
		secureCookie: secureCookie,
	}
	s.Router().Group("/v1/web", func(r *minato.Router) {
		// These are pure-REST routes, not gRPC-gateway generated.
		// They are registered directly on the chi router.
		r.Use(csrf.Middleware)
		r.Post("/refresh", h.RefreshCookie)
		r.Post("/logout", h.LogoutCookie)
	})
}

// RefreshCookie reads the refresh token from the HttpOnly cookie,
// calls the session usecase to rotate it, and writes the new tokens
// back into a fresh cookie pair.
//
// The caller (JavaScript frontend) must echo the X-CSRF-Token header.
func (h *sessionHTTPHandler) RefreshCookie(w http.ResponseWriter, r *http.Request) {
	// 1. Read the refresh token from the HttpOnly cookie.
	//    The browser sends this automatically; JavaScript cannot read it.
	c, err := r.Cookie(cookie.RefreshTokenCookieName)
	if err != nil || c.Value == "" {
		http.Error(w, `{"error":{"code":"TOKEN_NOT_FOUND","message":"refresh token cookie is missing"}}`, http.StatusUnauthorized)
		return
	}

	clientID := r.Header.Get("X-Client-Id")

	// 2. Call the session usecase (same as the gRPC path).
	tp, err := h.sessionUc.RefreshToken(r.Context(), &session.RefreshTokenRequest{
		RefreshToken: c.Value,
		ClientId:     clientID,
	})
	if err != nil {
		// Map domain errors to HTTP responses.
		// In production, use your merr error handler for structured output.
		http.Error(w, `{"error":{"code":"INVALID_TOKEN","message":"failed to refresh token"}}`, http.StatusUnauthorized)
		return
	}

	// 3. Generate a new CSRF token for the next request cycle.
	csrfToken, err := csrf.Generate()
	if err != nil {
		http.Error(w, `{"error":{"code":"INTERNAL","message":"failed to generate csrf token"}}`, http.StatusInternalServerError)
		return
	}

	// 4. Set the new refresh token as a secure HttpOnly cookie.
	//    TTL mirrors the session domain default (30 days).
	cookie.SetRefreshToken(w, tp.RefreshToken, 30*24*time.Hour, h.secureCookie)
	cookie.SetCSRFToken(w, csrfToken, 30*24*time.Hour, h.secureCookie)

	// 5. Return ONLY the access token in the JSON body.
	//    The refresh token is now cookie-only; never expose it in JSON.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": tp.AccessToken,
		"expires_in":   tp.ExpiresIn,
	})
}

// LogoutCookie invalidates the cookie session by clearing both cookies.
// The gRPC Logout endpoint handles token blacklisting; this handler just
// clears the browser-side cookies regardless of the usecase call outcome.
func (h *sessionHTTPHandler) LogoutCookie(w http.ResponseWriter, r *http.Request) {
	// Clear both cookies immediately, even if the usecase call fails.
	// This ensures the browser's session is always wiped client-side.
	cookie.ClearRefreshToken(w)
	cookie.ClearCSRFToken(w)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{}`))
}
