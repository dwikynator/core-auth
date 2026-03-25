package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// GenerateOTP produces a cryptographically random N-digit numeric string.
// It uses rejection sampling via crypto/rand to avoid modulo bias.
func GenerateOTP(digits int) (string, error) {
	// Upper bound: 10^digits (e.g., 1_000_000 for 6 digits).
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}

	// Left-pad with zeros to ensure consistent length (e.g., "007842").
	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, n), nil
}

// GenerateSecureToken returns a cryptographically random hex-encoded token
// of the specified byte length. A 32-byte token produces a 64-char hex string.
func GenerateSecureToken(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashToken returns the SHA-256 hex digest of a raw token string.
// Used to hash OTPs and tokens before storing in the database.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
