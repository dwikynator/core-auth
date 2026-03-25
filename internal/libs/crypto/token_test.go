package crypto_test

import (
	"testing"

	"github.com/dwikynator/core-auth/internal/libs/crypto"
)

func TestGenerateOTP(t *testing.T) {
	otp, err := crypto.GenerateOTP(6)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(otp) != 6 {
		t.Errorf("expected length 6, got %d for %s", len(otp), otp)
	}
}

func TestGenerateSecureToken(t *testing.T) {
	token, err := crypto.GenerateSecureToken(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 32 bytes encoded in hex is 64 characters
	if len(token) != 64 {
		t.Errorf("expected length 64, got %d", len(token))
	}
}

func TestHashToken(t *testing.T) {
	otp := "123456"
	hash1 := crypto.HashToken(otp)
	hash2 := crypto.HashToken(otp)

	if hash1 != hash2 {
		t.Errorf("expected hashes to match, got %s and %s", hash1, hash2)
	}
	if len(hash1) != 64 { // SHA-256 hex encoded
		t.Errorf("expected hash length 64, got %d", len(hash1))
	}
}
