package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/dwikynator/core-auth/internal/libs/crypto"

	"github.com/dwikynator/core-auth/internal/infra/audit"
	"github.com/dwikynator/core-auth/internal/libs/email"
	errs "github.com/dwikynator/core-auth/internal/libs/errors"
	"github.com/dwikynator/core-auth/internal/verification"
)

type verificationUseCase struct {
	verificationRepo verification.Repository
	userProvider     verification.UserProvider
	userService      verification.UserService
	emailSender      verification.EmailSender
	sessionService   verification.SessionService
	auditLogger      verification.AuditLogger
	frontendURL      string
	whatsappPhone    string
}

func NewVerificationUseCase(
	verificationRepo verification.Repository,
	userProvider verification.UserProvider,
	emailSender verification.EmailSender,
	userService verification.UserService,
	sessionService verification.SessionService,
	auditLogger verification.AuditLogger,
	frontendURL string,
	whatsappPhone string,
) verification.VerificationService {
	return &verificationUseCase{
		verificationRepo: verificationRepo,
		userProvider:     userProvider,
		emailSender:      emailSender,
		userService:      userService,
		sessionService:   sessionService,
		auditLogger:      auditLogger,
		frontendURL:      frontendURL,
		whatsappPhone:    whatsappPhone,
	}
}

// SendOTP sends a verification OTP to the user's email.
func (uc *verificationUseCase) SendOTP(ctx context.Context, req *verification.SendOTPRequest) (*verification.SendOTPResponse, error) {
	// 1. Validate input.
	emailAddr := strings.ToLower(strings.TrimSpace(req.EmailOrPhone))
	if emailAddr == "" {
		return nil, errs.WithMessage(errs.ErrInvalidIdentifier, "email_or_phone is required")
	}

	// 2. Look up user by email.
	user, err := uc.userProvider.FindByEmail(ctx, emailAddr)
	if err != nil {
		return nil, err // ErrUserNotFound → 404
	}

	// 3. Reject if already verified.
	if user.EmailVerifiedAt != nil {
		return nil, errs.ErrAlreadyVerified
	}

	// 4. Delegate to verification service.
	expiresAt, err := uc.SendOTPToUser(ctx, user.ID, emailAddr)
	if err != nil {
		return nil, errs.WithMessage(errs.ErrInternal, "failed to send otp")
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventOTPSent, user.ID))

	return &verification.SendOTPResponse{
		ExpiresAt: expiresAt,
	}, nil
}

// VerifyOTP verifies a 6-digit OTP code and activates the user's account.
func (uc *verificationUseCase) VerifyOTP(ctx context.Context, req *verification.VerifyOTPRequest) (*verification.VerifyOTPResponse, error) {
	// 1. Validate input.
	identifier := strings.ToLower(strings.TrimSpace(req.EmailOrPhone))
	if identifier == "" {
		return nil, errs.WithMessage(errs.ErrInvalidIdentifier, "email_or_phone is required")
	}
	if req.OTPCode == "" {
		return nil, errs.WithMessage(errs.ErrInvalidOTP, "otp_code is required")
	}

	// 2. Validate the OTP token. This marks it as "used" on success.
	vToken, err := uc.ValidateToken(ctx, req.OTPCode, verification.TokenTypeOTP)
	if err != nil {
		return nil, err
	}

	// 3. Look up the user associated with the OTP.
	user, err := uc.userProvider.FindByID(ctx, vToken.UserID)
	if err != nil {
		return nil, err
	}

	// 4. Branch by target.
	switch req.Target {
	case verification.OTPTargetPhone:
		// Phone verification — set phone_verified_at.
		if err := uc.userService.UpdatePhoneVerified(ctx, user.ID); err != nil {
			return nil, err
		}
	default:
		// Email verification (default, backward-compatible behavior).
		// Atomically mark email as verified and activate the account.
		if err := uc.userService.VerifyEmailAndActivate(ctx, user.ID); err != nil {
			return nil, err
		}
	}

	// 5. Re-fetch the user to get updated verification timestamps.
	user, err = uc.userProvider.FindByID(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	// 6. Generate token pair.
	tokens, _, err := uc.sessionService.CreateSessionAndTokens(ctx, user.ID, user.Role, req.ClientId)
	if err != nil {
		return nil, err
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventOTPVerified, user.ID))

	return &verification.VerifyOTPResponse{
		User:   user,
		Tokens: tokens,
	}, nil
}

// SendMagicLink sends a magic link to the user's email for passwordless login.
func (uc *verificationUseCase) SendMagicLink(ctx context.Context, req *verification.SendMagicLinkRequest) error {
	// 1. Validate input.
	emailAddr := strings.ToLower(strings.TrimSpace(req.Email))
	if emailAddr == "" {
		return errs.WithMessage(errs.ErrInvalidIdentifier, "email is required")
	}

	// 2. Look up user by email.
	user, err := uc.userProvider.FindByEmail(ctx, emailAddr)
	if err != nil {
		// Swallow ErrUserNotFound to prevent user enumeration.
		if errors.Is(err, errs.ErrUserNotFound) {
			return nil
		}
		return errs.WithMessage(errs.ErrInternal, "failed to lookup user")
	}

	// 3. Delegate to verification service.
	if err := uc.sendMagicLink(ctx, user.ID, emailAddr); err != nil {
		slog.Error("failed to send magic link", "user_id", user.ID, "error", err)
		return errs.WithMessage(errs.ErrInternal, "failed to send magic link")
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventMagicLinkSent, user.ID))

	return nil
}

// VerifyMagicLink verifies a magic link token and issues a token pair.
func (uc *verificationUseCase) VerifyMagicLink(ctx context.Context, req *verification.VerifyMagicLinkRequest) (*verification.VerifyMagicLinkResponse, error) {
	// 1. Validate input.
	if req.Token == "" {
		return nil, errs.WithMessage(errs.ErrInvalidToken, "token is required")
	}

	// 2. Validate the magic link token. This marks it as "used" on success.
	token, err := uc.ValidateToken(ctx, req.Token, verification.TokenTypeMagicLink)
	if err != nil {
		return nil, err // ErrTokenNotFound, ErrTokenExpired, or ErrTokenAlreadyUsed
	}

	// 3. Fetch the user.
	user, err := uc.userProvider.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, errs.WithMessage(errs.ErrInternal, "failed to fetch user")
	}

	// 4. Atomically verify and activate the account (if unverified).
	if user.EmailVerifiedAt == nil || user.Status == "unverified" {
		_ = uc.userService.VerifyEmailAndActivate(ctx, user.ID)
		user.Status = "active" // update local struct for response mapping
	}

	// 5. Generate token pair.
	tokens, _, err := uc.sessionService.CreateSessionAndTokens(ctx, user.ID, user.Role, req.ClientId)
	if err != nil {
		return nil, err
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventMagicLinkUsed, user.ID))

	return &verification.VerifyMagicLinkResponse{
		User:   user,
		Tokens: tokens,
	}, nil
}

// ValidateToken verifies a raw token (OTP or opaque) against the database.
// On success it marks the token as used and returns the associated VerificationToken.
func (uc *verificationUseCase) ValidateToken(ctx context.Context, rawToken string, tokenType verification.TokenType) (*verification.VerificationToken, error) {
	hash := crypto.HashToken(rawToken)

	token, err := uc.verificationRepo.FindByHashAndType(ctx, hash, tokenType)
	if err != nil {
		return nil, err // ErrTokenNotFound
	}

	// Check expiry.
	if token.IsExpired() {
		return nil, errs.ErrTokenExpired
	}

	// Check active (belt-and-suspenders; the query already filters status = 'active').
	if !token.IsActive() {
		return nil, errs.ErrTokenAlreadyUsed
	}

	// Mark as consumed.
	if err := uc.verificationRepo.MarkUsed(ctx, token.ID); err != nil {
		return nil, fmt.Errorf("mark token used: %w", err)
	}

	return token, nil
}

// GetWhatsAppVerificationLink generates a pre-filled WhatsApp message link
// containing a 6-digit OTP code for phone verification.
//
// The returned URL follows the wa.me deep-link format:
//
//	https://wa.me/<phone>?text=<encoded_message>
//
// The user taps the link, which opens WhatsApp with the verification code
// pre-typed as a message to the business phone number.
func (uc *verificationUseCase) GetWhatsAppVerificationLink(ctx context.Context) (*verification.GetWhatsAppVerificationLinkResponse, error) {
	// 1. Get the authenticated user.
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	user, err := uc.userProvider.FindByID(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}

	// 2. Ensure the user has a phone number set.
	if user.Phone == nil || *user.Phone == "" {
		return nil, errs.ErrPhoneNotSet
	}

	// 3. Reject if phone is already verified.
	if user.PhoneVerifiedAt != nil {
		return nil, errs.ErrAlreadyVerified
	}

	// 4. Generate a phone OTP (stored in verification_tokens, no email sent).
	otpCode, expiresAt, err := uc.generatePhoneOTP(ctx, user.ID)
	if err != nil {
		return nil, errs.WithMessage(errs.ErrInternal, "failed to generate phone OTP")
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventOTPSent, user.ID))

	// 5. Build the wa.me deep-link URL.
	// Strip the "+" prefix from the phone number for the wa.me URL format.
	bizPhone := strings.TrimPrefix(uc.whatsappPhone, "+")
	message := fmt.Sprintf("My verification code is: %s", otpCode)
	waURL := fmt.Sprintf("https://wa.me/%s?text=%s", bizPhone, url.QueryEscape(message))

	return &verification.GetWhatsAppVerificationLinkResponse{
		WhatsappUrl: waURL,
		OTPCode:     otpCode,
		ExpiresAt:   expiresAt,
	}, nil
}

// SendPasswordReset generates a secure token, stores its hash, and emails
// a reset link to the user.
func (uc *verificationUseCase) SendPasswordReset(ctx context.Context, userID, emailAddr string) error {
	// 1. Invalidate any existing reset tokens for this user.
	if err := uc.verificationRepo.InvalidateAllForUser(ctx, userID, verification.TokenTypePasswordReset); err != nil {
		return fmt.Errorf("invalidate old reset tokens: %w", err)
	}

	// 2. Generate token.
	rawToken, err := crypto.GenerateSecureToken(verification.SecureTokenBytes)
	if err != nil {
		return err
	}

	// 3. Hash and store.
	expiresAt := time.Now().Add(verification.PasswordResetExpiry)
	token := &verification.VerificationToken{
		UserID:    userID,
		TokenHash: crypto.HashToken(rawToken),
		Type:      verification.TokenTypePasswordReset,
		ExpiresAt: expiresAt,
	}
	if err := uc.verificationRepo.Create(ctx, token); err != nil {
		return fmt.Errorf("store reset token: %w", err)
	}

	// 4. Build the link and send email.
	link := fmt.Sprintf("%s/auth/reset-password?token=%s", uc.frontendURL, rawToken)
	msg := email.PasswordResetEmail(emailAddr, link, int(verification.PasswordResetExpiry.Minutes()))
	if err := uc.emailSender.Send(ctx, msg); err != nil {
		slog.Error("failed to send password reset email", "user_id", userID, "error", err)
		return fmt.Errorf("send reset email: %w", err)
	}

	slog.Info("password reset sent", "user_id", userID, "type", "password_reset")
	return nil
}

// SendOTP generates a 6-digit OTP, stores its hash, and emails the raw OTP
// to the user. Any previously active OTPs for this user are invalidated.
func (uc *verificationUseCase) SendOTPToUser(ctx context.Context, userID, emailAddr string) (time.Time, error) {
	// 1. Invalidate any existing OTPs for this user.
	if err := uc.verificationRepo.InvalidateAllForUser(ctx, userID, verification.TokenTypeOTP); err != nil {
		return time.Time{}, fmt.Errorf("invalidate old otps: %w", err)
	}

	// 2. Generate OTP.
	otp, err := crypto.GenerateOTP(verification.OTPDigits)
	if err != nil {
		return time.Time{}, err
	}

	// 3. Hash and store.
	expiresAt := time.Now().Add(verification.OTPExpiry)
	token := &verification.VerificationToken{
		UserID:    userID,
		TokenHash: crypto.HashToken(otp),
		Type:      verification.TokenTypeOTP,
		ExpiresAt: expiresAt,
	}
	if err := uc.verificationRepo.Create(ctx, token); err != nil {
		return time.Time{}, fmt.Errorf("store otp: %w", err)
	}

	// 4. Send email (non-blocking would be future phase queue work; for now, synchronous).
	msg := email.OTPEmail(emailAddr, otp, int(verification.OTPExpiry.Minutes()))
	if err := uc.emailSender.Send(ctx, msg); err != nil {
		slog.Error("failed to send OTP email", "user_id", userID, "error", err)
		return time.Time{}, fmt.Errorf("send otp email: %w", err)
	}

	slog.Info("otp sent", "user_id", userID, "type", "otp", "expires_at", expiresAt)
	return expiresAt, nil
}

// SendMagicLink generates a secure token, stores its hash, and emails a
// clickable link to the user.
func (uc *verificationUseCase) sendMagicLink(ctx context.Context, userID, emailAddr string) error {
	// 1. Invalidate any existing magic links for this user.
	if err := uc.verificationRepo.InvalidateAllForUser(ctx, userID, verification.TokenTypeMagicLink); err != nil {
		return fmt.Errorf("invalidate old magic links: %w", err)
	}

	// 2. Generate token.
	rawToken, err := crypto.GenerateSecureToken(verification.SecureTokenBytes)
	if err != nil {
		return err
	}

	// 3. Hash and store.
	expiresAt := time.Now().Add(verification.MagicLinkExpiry)
	token := &verification.VerificationToken{
		UserID:    userID,
		TokenHash: crypto.HashToken(rawToken),
		Type:      verification.TokenTypeMagicLink,
		ExpiresAt: expiresAt,
	}
	if err := uc.verificationRepo.Create(ctx, token); err != nil {
		return fmt.Errorf("store magic link: %w", err)
	}

	// 4. Build the link and send email.
	link := fmt.Sprintf("%s/auth/magic-link?token=%s", uc.frontendURL, rawToken)
	msg := email.MagicLinkEmail(emailAddr, link, int(verification.MagicLinkExpiry.Minutes()))
	if err := uc.emailSender.Send(ctx, msg); err != nil {
		slog.Error("failed to send magic link email", "user_id", userID, "error", err)
		return fmt.Errorf("send magic link email: %w", err)
	}

	slog.Info("magic link sent", "user_id", userID, "type", "magic_link")
	return nil
}

// GeneratePhoneOTP generates a 6-digit OTP and stores its hash, but does NOT
// send it via email. The raw OTP is returned to the caller for embedding
// in a WhatsApp pre-filled message link.
//
// This reuses the same verification_tokens table as email OTPs.
// The OTP can be validated via the existing ValidateToken method.
func (uc *verificationUseCase) generatePhoneOTP(ctx context.Context, userID string) (otp string, expiresAt time.Time, err error) {
	// 1. Invalidate any existing OTPs for this user.
	if err := uc.verificationRepo.InvalidateAllForUser(ctx, userID, verification.TokenTypeOTP); err != nil {
		return "", time.Time{}, fmt.Errorf("invalidate old otps: %w", err)
	}
	// 2. Generate OTP.
	rawOTP, err := crypto.GenerateOTP(verification.OTPDigits)
	if err != nil {
		return "", time.Time{}, err
	}
	// 3. Hash and store.
	expires := time.Now().Add(verification.OTPExpiry)
	token := &verification.VerificationToken{
		UserID:    userID,
		TokenHash: crypto.HashToken(rawOTP),
		Type:      verification.TokenTypeOTP,
		ExpiresAt: expires,
	}
	if err := uc.verificationRepo.Create(ctx, token); err != nil {
		return "", time.Time{}, fmt.Errorf("store phone otp: %w", err)
	}
	slog.Info("phone otp generated", "user_id", userID, "type", "phone_otp", "expires_at", expires)
	return rawOTP, expires, nil
}
