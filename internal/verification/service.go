package verification

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/dwikynator/core-auth/internal/crypto"
	"github.com/dwikynator/core-auth/internal/email"
)

// Default token lifetimes.
const (
	OTPExpiry           = 5 * time.Minute
	MagicLinkExpiry     = 15 * time.Minute
	PasswordResetExpiry = 30 * time.Minute
	OTPDigits           = 6
	SecureTokenBytes    = 32
)

// Service handles verification token lifecycle: creation, delivery, and validation.
type Service struct {
	repo        Repository
	emailSender email.Sender
	frontendURL string // base URL for magic-link and reset-link URLs
}

// NewService constructs a verification service.
func NewService(repo Repository, emailSender email.Sender, frontendURL string) *Service {
	return &Service{
		repo:        repo,
		emailSender: emailSender,
		frontendURL: frontendURL,
	}
}

// SendOTP generates a 6-digit OTP, stores its hash, and emails the raw OTP
// to the user. Any previously active OTPs for this user are invalidated.
func (s *Service) SendOTP(ctx context.Context, userID, emailAddr string) (time.Time, error) {
	// 1. Invalidate any existing OTPs for this user.
	if err := s.repo.InvalidateAllForUser(ctx, userID, TokenTypeOTP); err != nil {
		return time.Time{}, fmt.Errorf("invalidate old otps: %w", err)
	}

	// 2. Generate OTP.
	otp, err := crypto.GenerateOTP(OTPDigits)
	if err != nil {
		return time.Time{}, err
	}

	// 3. Hash and store.
	expiresAt := time.Now().Add(OTPExpiry)
	token := &VerificationToken{
		UserID:    userID,
		TokenHash: crypto.HashToken(otp),
		Type:      TokenTypeOTP,
		ExpiresAt: expiresAt,
	}
	if err := s.repo.Create(ctx, token); err != nil {
		return time.Time{}, fmt.Errorf("store otp: %w", err)
	}

	// 4. Send email (non-blocking would be future phase queue work; for now, synchronous).
	msg := email.OTPEmail(emailAddr, otp, int(OTPExpiry.Minutes()))
	if err := s.emailSender.Send(ctx, msg); err != nil {
		slog.Error("failed to send OTP email", "user_id", userID, "error", err)
		return time.Time{}, fmt.Errorf("send otp email: %w", err)
	}

	slog.Info("otp sent", "user_id", userID, "type", "otp", "expires_at", expiresAt)
	return expiresAt, nil
}

// SendMagicLink generates a secure token, stores its hash, and emails a
// clickable link to the user.
func (s *Service) SendMagicLink(ctx context.Context, userID, emailAddr string) error {
	// 1. Invalidate any existing magic links for this user.
	if err := s.repo.InvalidateAllForUser(ctx, userID, TokenTypeMagicLink); err != nil {
		return fmt.Errorf("invalidate old magic links: %w", err)
	}

	// 2. Generate token.
	rawToken, err := crypto.GenerateSecureToken(SecureTokenBytes)
	if err != nil {
		return err
	}

	// 3. Hash and store.
	expiresAt := time.Now().Add(MagicLinkExpiry)
	token := &VerificationToken{
		UserID:    userID,
		TokenHash: crypto.HashToken(rawToken),
		Type:      TokenTypeMagicLink,
		ExpiresAt: expiresAt,
	}
	if err := s.repo.Create(ctx, token); err != nil {
		return fmt.Errorf("store magic link: %w", err)
	}

	// 4. Build the link and send email.
	link := fmt.Sprintf("%s/auth/magic-link?token=%s", s.frontendURL, rawToken)
	msg := email.MagicLinkEmail(emailAddr, link, int(MagicLinkExpiry.Minutes()))
	if err := s.emailSender.Send(ctx, msg); err != nil {
		slog.Error("failed to send magic link email", "user_id", userID, "error", err)
		return fmt.Errorf("send magic link email: %w", err)
	}

	slog.Info("magic link sent", "user_id", userID, "type", "magic_link")
	return nil
}

// SendPasswordReset generates a secure token, stores its hash, and emails
// a reset link to the user.
func (s *Service) SendPasswordReset(ctx context.Context, userID, emailAddr string) error {
	// 1. Invalidate any existing reset tokens for this user.
	if err := s.repo.InvalidateAllForUser(ctx, userID, TokenTypePasswordReset); err != nil {
		return fmt.Errorf("invalidate old reset tokens: %w", err)
	}

	// 2. Generate token.
	rawToken, err := crypto.GenerateSecureToken(SecureTokenBytes)
	if err != nil {
		return err
	}

	// 3. Hash and store.
	expiresAt := time.Now().Add(PasswordResetExpiry)
	token := &VerificationToken{
		UserID:    userID,
		TokenHash: crypto.HashToken(rawToken),
		Type:      TokenTypePasswordReset,
		ExpiresAt: expiresAt,
	}
	if err := s.repo.Create(ctx, token); err != nil {
		return fmt.Errorf("store reset token: %w", err)
	}

	// 4. Build the link and send email.
	link := fmt.Sprintf("%s/auth/reset-password?token=%s", s.frontendURL, rawToken)
	msg := email.PasswordResetEmail(emailAddr, link, int(PasswordResetExpiry.Minutes()))
	if err := s.emailSender.Send(ctx, msg); err != nil {
		slog.Error("failed to send password reset email", "user_id", userID, "error", err)
		return fmt.Errorf("send reset email: %w", err)
	}

	slog.Info("password reset sent", "user_id", userID, "type", "password_reset")
	return nil
}

// ValidateToken verifies a raw token (OTP or opaque) against the database.
// On success it marks the token as used and returns the associated VerificationToken.
func (s *Service) ValidateToken(ctx context.Context, rawToken string, tokenType TokenType) (*VerificationToken, error) {
	hash := crypto.HashToken(rawToken)

	token, err := s.repo.FindByHashAndType(ctx, hash, tokenType)
	if err != nil {
		return nil, err // ErrTokenNotFound
	}

	// Check expiry.
	if token.IsExpired() {
		return nil, ErrTokenExpired
	}

	// Check active (belt-and-suspenders; the query already filters status = 'active').
	if !token.IsActive() {
		return nil, ErrTokenAlreadyUsed
	}

	// Mark as consumed.
	if err := s.repo.MarkUsed(ctx, token.ID); err != nil {
		return nil, fmt.Errorf("mark token used: %w", err)
	}

	return token, nil
}

// GeneratePhoneOTP generates a 6-digit OTP and stores its hash, but does NOT
// send it via email. The raw OTP is returned to the caller for embedding
// in a WhatsApp pre-filled message link.
//
// This reuses the same verification_tokens table as email OTPs.
// The OTP can be validated via the existing ValidateToken method.
func (s *Service) GeneratePhoneOTP(ctx context.Context, userID string) (otp string, expiresAt time.Time, err error) {
	// 1. Invalidate any existing OTPs for this user.
	if err := s.repo.InvalidateAllForUser(ctx, userID, TokenTypeOTP); err != nil {
		return "", time.Time{}, fmt.Errorf("invalidate old otps: %w", err)
	}
	// 2. Generate OTP.
	rawOTP, err := crypto.GenerateOTP(OTPDigits)
	if err != nil {
		return "", time.Time{}, err
	}
	// 3. Hash and store.
	expires := time.Now().Add(OTPExpiry)
	token := &VerificationToken{
		UserID:    userID,
		TokenHash: crypto.HashToken(rawOTP),
		Type:      TokenTypeOTP,
		ExpiresAt: expires,
	}
	if err := s.repo.Create(ctx, token); err != nil {
		return "", time.Time{}, fmt.Errorf("store phone otp: %w", err)
	}
	slog.Info("phone otp generated", "user_id", userID, "type", "phone_otp", "expires_at", expires)
	return rawOTP, expires, nil
}
