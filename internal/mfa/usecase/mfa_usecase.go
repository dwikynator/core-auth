package usecase

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	appmetrics "github.com/dwikynator/core-auth/internal/infra/metrics"

	"github.com/dwikynator/core-auth/internal/infra/audit"
	"github.com/dwikynator/core-auth/internal/libs/crypto"
	errs "github.com/dwikynator/core-auth/internal/libs/errors"
	"github.com/dwikynator/core-auth/internal/mfa"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// MFAService handles TOTP enrollment, validation, and credential management.
type mfaUseCase struct {
	credRepo       mfa.MFACredentialRepository
	sessionStore   mfa.MFASessionStore
	userProvider   mfa.UserProvider
	sessionService mfa.SessionService
	auditLogger    mfa.AuditLogger
	aesKey         []byte // 32-byte AES-256 key for encrypting TOTP secrets
	issuerName     string // display name in authenticator apps (e.g. "core-auth")
}

// NewMFAService constructs an MFAService.
// encryptionKey must be exactly 32 bytes (AES-256).
func NewMFAService(
	credRepo mfa.MFACredentialRepository,
	sessionStore mfa.MFASessionStore,
	userProvider mfa.UserProvider,
	sessionService mfa.SessionService,
	auditLogger mfa.AuditLogger,
	encryptionKey []byte,
	issuerName string,
) mfa.MFAUseCase {
	return &mfaUseCase{
		credRepo:       credRepo,
		sessionStore:   sessionStore,
		userProvider:   userProvider,
		sessionService: sessionService,
		auditLogger:    auditLogger,
		aesKey:         encryptionKey,
		issuerName:     issuerName,
	}
}

// Setup generates a new TOTP secret and stores the encrypted credential.
// The credential is marked as unverified until ConfirmSetup is called.
func (uc *mfaUseCase) setup(ctx context.Context, userID, userEmail string) (*mfa.SetupResult, error) {
	// 1. Check if MFA is already enrolled (verified or not).
	existing, err := uc.credRepo.FindByUserID(ctx, userID)
	if err == nil && existing != nil {
		if existing.Verified {
			return nil, errs.ErrMFAAlreadyEnrolled
		}
		// Unverified enrollment exists — delete it to allow re-enrollment.
		_ = uc.credRepo.DeleteByUserID(ctx, userID)
	}

	// 2. Generate a TOTP key.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      uc.issuerName,
		AccountName: userEmail,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp key: %w", err)
	}

	// 3. Encrypt the secret for storage.
	encrypted, err := uc.encrypt(key.Secret())
	if err != nil {
		return nil, fmt.Errorf("encrypt totp secret: %w", err)
	}

	// 4. Persist.
	cred := &mfa.MFACredential{
		UserID:          userID,
		Type:            "totp",
		SecretEncrypted: encrypted,
	}
	if err := uc.credRepo.Create(ctx, cred); err != nil {
		return nil, err
	}

	return &mfa.SetupResult{
		Secret: key.Secret(),
		QRURI:  key.URL(),
	}, nil
}

// ConfirmSetup validates the first TOTP code to confirm enrollment.
// After this succeeds, future logins will require MFA.
func (uc *mfaUseCase) confirmSetup(ctx context.Context, userID, code string) error {
	// 1. Find the unverified credential.
	cred, err := uc.credRepo.FindByUserID(ctx, userID)
	if err != nil {
		return errs.ErrMFANotEnrolled
	}
	if cred.Verified {
		return errs.ErrMFAAlreadyEnrolled
	}

	// 2. Decrypt the secret.
	secret, err := uc.decrypt(cred.SecretEncrypted)
	if err != nil {
		return fmt.Errorf("decrypt totp secret: %w", err)
	}

	// 3. Validate the TOTP code.
	if !totp.Validate(code, secret) {
		return errs.ErrMFAInvalidCode
	}

	// 4. Mark as verified.
	return uc.credRepo.MarkVerified(ctx, cred.ID)
}

// ValidateCode checks a TOTP code against a user's enrolled secret.
// Used during the MFA challenge step of login.
func (uc *mfaUseCase) validateCode(ctx context.Context, userID, code string) error {
	// 1. Find the verified credential.
	cred, err := uc.credRepo.FindVerifiedByUserID(ctx, userID)
	if err != nil {
		return err
	}

	// 2. Decrypt the secret.
	secret, err := uc.decrypt(cred.SecretEncrypted)
	if err != nil {
		return fmt.Errorf("decrypt totp secret: %w", err)
	}

	// 3. Validate.
	if !totp.Validate(code, secret) {
		return errs.ErrMFAInvalidCode
	}

	// 4. Update last_used_at.
	_ = uc.credRepo.UpdateLastUsed(ctx, cred.ID)
	return nil
}

// IsEnrolled returns true if the user has a verified MFA credential.
func (uc *mfaUseCase) IsEnrolled(ctx context.Context, userID string) bool {
	_, err := uc.credRepo.FindVerifiedByUserID(ctx, userID)
	return err == nil
}

// CreateSession generates an MFA session token and stores it in Redis.
func (uc *mfaUseCase) CreateSession(ctx context.Context, data *mfa.MFASessionData) (string, error) {
	return uc.sessionStore.Create(ctx, data)
}

// ConsumeSession retrieves and deletes an MFA session (single-use).
func (uc *mfaUseCase) consumeSession(ctx context.Context, rawToken string) (*mfa.MFASessionData, error) {
	return uc.sessionStore.Consume(ctx, rawToken)
}

// DisableForUser removes all MFA credentials for a user.
func (uc *mfaUseCase) disableForUser(ctx context.Context, userID string) error {
	return uc.credRepo.DeleteByUserID(ctx, userID)
}

// ── AES-256-GCM Encryption ─────────────────────────────────────────────────

// encrypt encrypts plaintext using AES-256-GCM and returns a base64-encoded
// string of nonce + ciphertext.
func (uc *mfaUseCase) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(uc.aesKey)
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
func (uc *mfaUseCase) decrypt(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(uc.aesKey)
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

func (uc *mfaUseCase) SetupTOTP(ctx context.Context) (*mfa.SetupTOTPResponse, error) {
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Fetch the user to get their email for the authenticator app display.
	user, err := uc.userProvider.FindByID(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}

	accountName := user.ID
	if user.Email != nil {
		accountName = *user.Email
	}

	result, err := uc.setup(ctx, user.ID, accountName)
	if err != nil {
		return nil, err
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventMFASetup, user.ID))

	return &mfa.SetupTOTPResponse{
		Secret: result.Secret,
		QRURI:  result.QRURI,
	}, nil
}

func (uc *mfaUseCase) ConfirmTOTP(ctx context.Context, req *mfa.ConfirmTOTPRequest) error {
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return err
	}

	if req.TOTPCode == "" {
		return errs.WithMessage(errs.ErrMFAInvalidCode, "totp_code is required")
	}

	if err := uc.confirmSetup(ctx, claims.Subject, req.TOTPCode); err != nil {
		return err
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventMFAConfirmed, claims.Subject))

	return nil
}

// ChallengeMFA verifies the TOTP code and issues a new token pair.
func (uc *mfaUseCase) ChallengeMFA(ctx context.Context, req *mfa.ChallengeMFARequest) (*mfa.ChallengeMFAResponse, error) {
	// 1. Validate input.
	if req.MFASessionToken == "" {
		return nil, errs.WithMessage(errs.ErrInvalidMFASession, "mfa_session_token is required")
	}
	if req.Code == "" {
		return nil, errs.WithMessage(errs.ErrMFAInvalidCode, "code is required")
	}

	// 2. Consume the MFA session (single-use).
	// If the token is invalid, expired, or already consumed, this returns an error.
	sessionData, err := uc.consumeSession(ctx, req.MFASessionToken)
	if err != nil {
		return nil, err
	}

	// 3. Validate the TOTP code against the user's enrolled secret.
	if err := uc.validateCode(ctx, sessionData.UserID, req.Code); err != nil {
		// The MFA session is already consumed — the user must restart login.
		// This prevents brute-forcing the TOTP code.
		return nil, err
	}

	// 4. MFA passed — issue the full token pair.
	tokens, _, err := uc.sessionService.CreateSessionAndTokens(ctx, sessionData.UserID, sessionData.Role, sessionData.ClientID)
	if err != nil {
		return nil, err
	}
	appmetrics.RecordTokenIssued("mfa")

	// 5. Build response.
	user, err := uc.userProvider.FindByID(ctx, sessionData.UserID)
	if err != nil {
		return nil, errs.WithMessage(errs.ErrInternal, "failed to fetch user")
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventMFAChallenged, sessionData.UserID))

	return &mfa.ChallengeMFAResponse{
		User:     user,
		Tokens:   tokens,
		ClientID: sessionData.ClientID,
	}, nil
}

func (uc *mfaUseCase) DisableMFA(ctx context.Context, password string) error {
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return err
	}

	// 1. Require password re-confirmation for security.
	if password == "" {
		return errs.WithMessage(errs.ErrInvalidCredentials, "password is required to disable MFA")
	}

	user, err := uc.userProvider.FindByID(ctx, claims.Subject)
	if err != nil {
		return err
	}

	if user.PasswordHash == nil {
		return errs.ErrInvalidCredentials
	}
	match, err := crypto.ComparePassword(password, *user.PasswordHash)
	if err != nil || !match {
		return errs.ErrInvalidCredentials
	}

	// 2. Delete all MFA credentials.
	if err := uc.disableForUser(ctx, claims.Subject); err != nil {
		return errs.WithMessage(errs.ErrInternal, "failed to disable MFA")
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventMFADisabled, claims.Subject))

	return nil
}
