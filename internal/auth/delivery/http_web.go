package delivery

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dwikynator/core-auth/internal/auth"
	"github.com/dwikynator/core-auth/internal/libs/cookie"
	"github.com/dwikynator/core-auth/internal/libs/csrf"
	"github.com/dwikynator/minato"
)

type authWebHandler struct {
	authUc       auth.AuthUsecase
	secureCookie bool
}

// RegisterAuthWebHandler registers the browser-client-specific HTTP routes
// under the /v1/web sub-router.
//
// These routes are a parallel to the gRPC-gateway auth routes but replace
// tokens-in-JSON-body with Set-Cookie headers so the browser's HttpOnly
// cookie jar is used. JavaScript never has access to the refresh token.
//
// The webRouter parameter is the /v1/web chi sub-router created in main.go.
// CSRF middleware is NOT applied here because this is the login endpoint —
// the user has no cookie yet and cannot provide a CSRF token.
func RegisterAuthWebHandler(webRouter *minato.Router, authUc auth.AuthUsecase, secureCookie bool) {
	h := &authWebHandler{
		authUc:       authUc,
		secureCookie: secureCookie,
	}

	// Login is outside the CSRF group — the user has no cookie yet.
	webRouter.Post("/login", h.LoginCookie)
}

// LoginCookie authenticates the user and, on success, writes the refresh token
// into a secure HttpOnly cookie and the CSRF token into a readable cookie.
// Only the access token is returned in the JSON body.
//
// MFA-required responses are passed through as JSON — the client must complete
// MFA via the standard gRPC-gateway endpoints before the cookie session begins.
func (h *authWebHandler) LoginCookie(w http.ResponseWriter, r *http.Request) {
	// 1. Decode the request body. Same fields as the gRPC Login endpoint.
	var req struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Phone    string `json:"phone"`
		Password string `json:"password"`
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"INVALID_REQUEST","message":"invalid JSON body"}}`, http.StatusBadRequest)
		return
	}

	// 2. Delegate to the auth usecase — identical to the gRPC handler.
	resp, err := h.authUc.Login(r.Context(), &auth.LoginRequest{
		Email:    req.Email,
		Username: req.Username,
		Phone:    req.Phone,
		Password: req.Password,
		ClientId: req.ClientID,
	})
	if err != nil {
		// Let the domain error bubble out as a structured JSON response.
		// In the future this can be wired to the merr error handler.
		http.Error(w, `{"error":{"code":"INVALID_CREDENTIALS","message":"invalid email or password"}}`, http.StatusUnauthorized)
		return
	}

	// 3. MFA required — pass through as JSON. No cookie is set yet because
	//    the user has not fully authenticated. The browser must complete MFA
	//    via the standard endpoint, then exchange for a cookie session.
	if resp.LoginMFARequired != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mfa_required":      true,
			"mfa_session_token": resp.LoginMFARequired.MfaSessionToken,
			"mfa_type":          resp.LoginMFARequired.MfaType,
		})
		return
	}

	// 4. Successful login — generate a CSRF token for the new session.
	csrfToken, err := csrf.Generate()
	if err != nil {
		http.Error(w, `{"error":{"code":"INTERNAL","message":"failed to generate CSRF token"}}`, http.StatusInternalServerError)
		return
	}

	tokens := resp.LoginSuccess.Tokens

	// 5. Write the refresh token as a secure HttpOnly cookie.
	//    TTL mirrors the session domain default (30 days).
	//    JavaScript cannot read this cookie — the browser manages it transparently.
	cookie.SetRefreshToken(w, tokens.RefreshToken, 30*24*time.Hour, h.secureCookie)

	// 6. Write the CSRF token as a readable (non-HttpOnly) cookie.
	//    JavaScript reads this value and echoes it back on every state-mutating
	//    request via the X-CSRF-Token header.
	cookie.SetCSRFToken(w, csrfToken, 30*24*time.Hour, h.secureCookie)

	// 7. Return ONLY the access token in the JSON body.
	//    The refresh token is cookie-only; it must never appear in the response body.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": tokens.AccessToken,
		"expires_in":   tokens.ExpiresIn,
	})
}
