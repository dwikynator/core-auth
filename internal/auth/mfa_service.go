package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// MFAService handles TOTP enrollment, validation, and credential management.
type MFAService struct {
	credRepo     MFACredentialRepository
	sessionStore MFASessionStore
	aesKey       []byte // 32-byte AES-256 key for encrypting TOTP secrets
	issuerName   string // display name in authenticator apps (e.g. "core-auth")
}

// NewMFAService constructs an MFAService.
// encryptionKey must be exactly 32 bytes (AES-256).
func NewMFAService(
	credRepo MFACredentialRepository,
	sessionStore MFASessionStore,
	encryptionKey []byte,
	issuerName string,
) *MFAService {
	return &MFAService{
		credRepo:     credRepo,
		sessionStore: sessionStore,
		aesKey:       encryptionKey,
		issuerName:   issuerName,
	}
}

// SetupResult contains the information shown to the user during TOTP enrollment.
type SetupResult struct {
	Secret string // base32-encoded secret (show once, never again)
	QRURI  string // otpauth:// URI for QR code generation
}

// Setup generates a new TOTP secret and stores the encrypted credential.
// The credential is marked as unverified until ConfirmSetup is called.
func (m *MFAService) Setup(ctx context.Context, userID, userEmail string) (*SetupResult, error) {
	// 1. Check if MFA is already enrolled (verified or not).
	existing, err := m.credRepo.FindByUserID(ctx, userID)
	if err == nil && existing != nil {
		if existing.Verified {
			return nil, ErrMFAAlreadyEnrolled
		}
		// Unverified enrollment exists — delete it to allow re-enrollment.
		_ = m.credRepo.DeleteByUserID(ctx, userID)
	}

	// 2. Generate a TOTP key.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      m.issuerName,
		AccountName: userEmail,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp key: %w", err)
	}

	// 3. Encrypt the secret for storage.
	encrypted, err := m.encrypt(key.Secret())
	if err != nil {
		return nil, fmt.Errorf("encrypt totp secret: %w", err)
	}

	// 4. Persist.
	cred := &MFACredential{
		UserID:          userID,
		Type:            "totp",
		SecretEncrypted: encrypted,
	}
	if err := m.credRepo.Create(ctx, cred); err != nil {
		return nil, err
	}

	return &SetupResult{
		Secret: key.Secret(),
		QRURI:  key.URL(),
	}, nil
}

// ConfirmSetup validates the first TOTP code to confirm enrollment.
// After this succeeds, future logins will require MFA.
func (m *MFAService) ConfirmSetup(ctx context.Context, userID, code string) error {
	// 1. Find the unverified credential.
	cred, err := m.credRepo.FindByUserID(ctx, userID)
	if err != nil {
		return ErrMFANotEnrolled
	}
	if cred.Verified {
		return ErrMFAAlreadyEnrolled
	}

	// 2. Decrypt the secret.
	secret, err := m.decrypt(cred.SecretEncrypted)
	if err != nil {
		return fmt.Errorf("decrypt totp secret: %w", err)
	}

	// 3. Validate the TOTP code.
	if !totp.Validate(code, secret) {
		return ErrMFAInvalidCode
	}

	// 4. Mark as verified.
	return m.credRepo.MarkVerified(ctx, cred.ID)
}

// ValidateCode checks a TOTP code against a user's enrolled secret.
// Used during the MFA challenge step of login.
func (m *MFAService) ValidateCode(ctx context.Context, userID, code string) error {
	// 1. Find the verified credential.
	cred, err := m.credRepo.FindVerifiedByUserID(ctx, userID)
	if err != nil {
		return err
	}

	// 2. Decrypt the secret.
	secret, err := m.decrypt(cred.SecretEncrypted)
	if err != nil {
		return fmt.Errorf("decrypt totp secret: %w", err)
	}

	// 3. Validate.
	if !totp.Validate(code, secret) {
		return ErrMFAInvalidCode
	}

	// 4. Update last_used_at.
	_ = m.credRepo.UpdateLastUsed(ctx, cred.ID)
	return nil
}

// IsEnrolled returns true if the user has a verified MFA credential.
func (m *MFAService) IsEnrolled(ctx context.Context, userID string) bool {
	_, err := m.credRepo.FindVerifiedByUserID(ctx, userID)
	return err == nil
}

// CreateSession generates an MFA session token and stores it in Redis.
func (m *MFAService) CreateSession(ctx context.Context, data *MFASessionData) (string, error) {
	return m.sessionStore.Create(ctx, data)
}

// ConsumeSession retrieves and deletes an MFA session (single-use).
func (m *MFAService) ConsumeSession(ctx context.Context, rawToken string) (*MFASessionData, error) {
	return m.sessionStore.Consume(ctx, rawToken)
}

// DisableForUser removes all MFA credentials for a user.
func (m *MFAService) DisableForUser(ctx context.Context, userID string) error {
	return m.credRepo.DeleteByUserID(ctx, userID)
}

// ── AES-256-GCM Encryption ─────────────────────────────────────────────────

// encrypt encrypts plaintext using AES-256-GCM and returns a base64-encoded
// string of nonce + ciphertext.
func (m *MFAService) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(m.aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decodes and decrypts a base64-encoded AES-256-GCM ciphertext.
func (m *MFAService) decrypt(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(m.aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
