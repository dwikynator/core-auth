package crypto

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// JWKSResponse is the top-level JSON object for /.well-known/jwks.json.
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key (RSA public key).
type JWK struct {
	KTY string `json:"kty"` // Key Type: "RSA"
	Use string `json:"use"` // Key Use: "sig" (signature)
	Alg string `json:"alg"` // Algorithm: "RS256"
	KID string `json:"kid"` // Key ID: matches the "kid" in JWT headers
	N   string `json:"n"`   // RSA modulus (base64url, no padding)
	E   string `json:"e"`   // RSA exponent (base64url, no padding)
}

// BuildJWKS constructs the JWKS JSON bytes from a public key and key ID.
// The result is deterministic and can be safely cached.
func BuildJWKS(pub *rsa.PublicKey, kid string) ([]byte, error) {
	resp := JWKSResponse{
		Keys: []JWK{
			{
				KTY: "RSA",
				Use: "sig",
				Alg: "RS256",
				KID: kid,
				N:   base64URLEncode(pub.N.Bytes()),
				E:   base64URLEncode(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	return json.Marshal(resp)
}

// base64URLEncode encodes raw bytes to unpadded base64url (RFC 7515 §2).
func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
