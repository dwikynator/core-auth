package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenIssuer signs JWTs using an RSA private key.
// It is safe for concurrent use — the private key is immutable after construction.
type TokenIssuer struct {
	privateKey *rsa.PrivateKey
	keyID      string // "kid" header in JWTs, matches the "kid" in JWKS
	issuer     string // "iss" claim
}

// NewTokenIssuer loads the RSA private key from disk and derives a stable key ID
// from the public key fingerprint.
func NewTokenIssuer(keyPath, issuer string) (*TokenIssuer, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read rsa key: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("rsa key: failed to decode PEM block")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("rsa key: parse PKCS8: %w", err)
	}

	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("rsa key: not an RSA private key")
	}

	// Derive a stable kid from the public key DER bytes.
	// This means the kid changes automatically if you rotate the key file.
	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("rsa key: marshal public key: %w", err)
	}
	hash := sha256.Sum256(pubDER)
	kid := base64.RawURLEncoding.EncodeToString(hash[:8]) // 11-char truncated hash

	return &TokenIssuer{
		privateKey: rsaKey,
		keyID:      kid,
		issuer:     issuer,
	}, nil
}

// SignAccessToken creates a signed RS256 JWT with the given claims.
// Each token contains a unique `jti` (JWT ID) used for blacklist-based revocation.
func (ti *TokenIssuer) SignAccessToken(userID, role string, scopes []string, ttl time.Duration) (string, error) {
	now := time.Now()

	// Generate a unique jti: 16 random bytes → 32-char hex string.
	// This is the key we store in Redis on logout. Using 16 bytes gives us
	// 2^128 uniqueness — collision probability is negligible.
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	claims := Claims{
		Role:   role,
		Scopes: scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        hex.EncodeToString(jtiBytes),
			Subject:   userID,
			Issuer:    ti.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = ti.keyID

	return token.SignedString(ti.privateKey)
}

// PublicKey returns the RSA public key (used by the JWKS builder).
func (ti *TokenIssuer) PublicKey() *rsa.PublicKey {
	return &ti.privateKey.PublicKey
}

// KeyID returns the key ID used in JWT headers and JWKS.
func (ti *TokenIssuer) KeyID() string {
	return ti.keyID
}

// Issuer returns the configured issuer string for OIDC discovery.
func (ti *TokenIssuer) Issuer() string {
	return ti.issuer
}
