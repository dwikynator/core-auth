package auth

import (
	"encoding/json"
	"net/http"
)

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

// NewOIDCDiscoveryHandler returns an http.HandlerFunc that serves pre-computed
// OIDC Discovery JSON. Like the JWKS handler, the JSON is computed once at
// startup and served on every request with zero per-request allocations.
func NewOIDCDiscoveryHandler(baseURL, issuer string) http.HandlerFunc {
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
	data, err := json.Marshal(doc)
	if err != nil {
		// This can only fail at startup if our struct has un-marshalable fields.
		// Since all fields are strings/slices, this is truly unreachable.
		panic("oidc: failed to marshal discovery document: " + err.Error())
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=86400") // 24h cache — this rarely changes
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}
