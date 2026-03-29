package delivery

import (
	"encoding/json"
	"net/http"

	"github.com/dwikynator/minato"
)

type authHTTPHandler struct {
	jwksJSON      []byte
	discoveryJSON []byte
}

// RegisterAuthHTTPHandler sets up and registers pure HTTP routes for the core auth domain.
func RegisterAuthHTTPHandler(s *minato.Server, jwksJSON []byte, baseURL, issuer string) {
	doc := OIDCDiscovery{
		Issuer:                           issuer,
		JWKSURI:                          baseURL + "/.well-known/jwks.json",
		AuthorizationEndpoint:            baseURL + "/v1/auth/login",
		TokenEndpoint:                    baseURL + "/v1/auth/refresh",
		UserinfoEndpoint:                 baseURL + "/v1/auth/me",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	// Pre-marshal to avoid encoding on every request.
	discoveryJSON, err := json.Marshal(doc)
	if err != nil {
		panic("oidc: failed to marshal discovery document: " + err.Error())
	}

	handler := &authHTTPHandler{
		jwksJSON:      jwksJSON,
		discoveryJSON: discoveryJSON,
	}

	s.Router().Get("/.well-known/jwks.json", handler.JWKSHandler)
	s.Router().Get("/.well-known/openid-configuration", handler.OIDCDiscoveryHandler)
}

// JWKSHandler serves pre-computed JWKS JSON.
// The JSON bytes are computed once at startup and served on every request
// with zero per-request allocations.
func (h *authHTTPHandler) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Allow consuming services to cache the response for 1 hour.
	// When you rotate keys, deploy the new key and wait for caches to expire,
	// or bump the version via a new kid.
	w.Header().Set("Cache-Control", "public, max-age=3600")

	w.WriteHeader(http.StatusOK)
	w.Write(h.jwksJSON)
}

// OIDCDiscovery represents the OpenID Connect Discovery 1.0 response.
// Only fields relevant to our auth server are included.
type OIDCDiscovery struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                    string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// OIDCDiscoveryHandler serves pre-computed OIDC Discovery JSON.
// Like the JWKS handler, the JSON is computed once at startup and
// served on every request with zero per-request allocations.
func (h *authHTTPHandler) OIDCDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=86400") // 24h cache — this rarely changes
	w.WriteHeader(http.StatusOK)
	w.Write(h.discoveryJSON)
}
