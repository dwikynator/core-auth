package usecase

import (
	"context"
	"log/slog"
	"strings"

	"github.com/dwikynator/core-auth/internal/auth"
	"github.com/dwikynator/core-auth/internal/infra/audit"
	"github.com/dwikynator/core-auth/internal/mfa"
	userdomain "github.com/dwikynator/core-auth/internal/user"

	"errors"

	contextlib "github.com/dwikynator/core-auth/internal/libs/context"
	"github.com/dwikynator/core-auth/internal/libs/crypto"
	errs "github.com/dwikynator/core-auth/internal/libs/errors"
	"github.com/dwikynator/core-auth/internal/libs/validate"
	"github.com/dwikynator/core-auth/internal/verification"
)

type authUsecase struct {
	userService         auth.UserService
	userProvider        auth.UserProvider
	verificationService auth.VerificationService
	sessionService      auth.SessionService
	mfaService          auth.MFAService
	mfaProvider         auth.MFAProvider
	rateLimiter         auth.RateLimiter
	tenantPolicy        auth.TenantPolicy
	auditLogger         auth.AuditLogger
}

func NewAuthUsecase(userService auth.UserService, userProvider auth.UserProvider, verificationService auth.VerificationService, sessionService auth.SessionService, mfaService auth.MFAService, mfaProvider auth.MFAProvider, rateLimiter auth.RateLimiter, tenantPolicy auth.TenantPolicy, auditLogger auth.AuditLogger) auth.AuthUsecase {
	return &authUsecase{
		userService:         userService,
		userProvider:        userProvider,
		verificationService: verificationService,
		sessionService:      sessionService,
		mfaService:          mfaService,
		mfaProvider:         mfaProvider,
		rateLimiter:         rateLimiter,
		tenantPolicy:        tenantPolicy,
		auditLogger:         auditLogger,
	}
}

// Register
func (uc *authUsecase) Register(ctx context.Context, req *auth.RegisterRequest) (*userdomain.User, error) {
	// 1. At least one identifier must be provided.
	if req.Email == "" && req.Username == "" && req.Phone == "" {
		return nil, errs.ErrInvalidIdentifier
	}

	// 2. Validate & normalise each provided identifier.
	user := &userdomain.User{
		Role:   "user",
		Status: "unverified",
	}

	if raw := req.Email; raw != "" {
		email, err := validate.NormaliseEmail(raw)
		if err != nil {
			return nil, errs.WithMessage(errs.ErrInvalidIdentifierFormat, err.Error())
		}
		user.Email = &email
	}

	if raw := req.Username; raw != "" {
		username, err := validate.ValidateUsername(raw)
		if err != nil {
			return nil, errs.WithMessage(errs.ErrInvalidIdentifierFormat, err.Error())
		}
		user.Username = &username
	}

	if raw := req.Phone; raw != "" {
		phone, err := validate.NormalisePhone(raw)
		if err != nil {
			return nil, errs.WithMessage(errs.ErrInvalidIdentifierFormat, err.Error())
		}
		user.Phone = &phone
	}

	// 3. Validate password against policy.
	if err := validate.ValidatePassword(req.Password); err != nil {
		return nil, errs.WithMessage(errs.ErrPasswordPolicyViolation, err.Error())
	}

	// 4. Hash the password.
	hash, err := crypto.HashPassword(req.Password, &crypto.DefaultArgon2Params)
	if err != nil {
		return nil, errs.WithMessage(errs.ErrInternal, "failed to hash password")
	}
	user.PasswordHash = &hash

	// 5. Persist.
	if err := uc.userService.CreateUser(ctx, user); err != nil {
		return nil, err // ErrUserAlreadyExists is already a *merr.Error
	}

	// 6. Send verification OTP (if email is provided).
	if user.Email != nil {
		if _, err := uc.verificationService.SendOTPToUser(ctx, user.ID, *user.Email); err != nil {
			// Log but don't fail registration — user can request a new OTP later.
			slog.Error("failed to send verification OTP on register", "user_id", user.ID, "error", err)
		}
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventRegister, user.ID))

	return user, nil
}

// Login
func (uc *authUsecase) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	meta := contextlib.MetaFromContext(ctx)
	ip := ""
	if meta.IPAddress != nil {
		ip = *meta.IPAddress
	}

	if err := uc.rateLimiter.CheckIPLimit(ctx, ip); err != nil {
		return nil, err // Returns ErrTooManyRequests
	}

	// 1. Determine which identifier the client sent.
	identifier := ""
	for _, v := range []string{req.Email, req.Username, req.Phone} {
		if v != "" {
			identifier = v
			break
		}
	}
	if identifier == "" {
		return nil, errs.ErrInvalidIdentifier
	}

	// Normalise: lowercase email for lookup.
	identifier = strings.ToLower(strings.TrimSpace(identifier))

	// 2. Find user.
	user, err := uc.userProvider.FindByLogin(ctx, identifier)
	if err != nil {
		// Map ErrUserNotFound → ErrInvalidCredentials to prevent user enumeration.
		if errors.Is(err, errs.ErrUserNotFound) {
			_ = uc.rateLimiter.RecordAttempt(ctx, &auth.LoginAttempt{
				UserID:    "", // Empty string maps to NULL in db
				IPAddress: ip,
				Success:   false,
			})

			return nil, errs.ErrInvalidCredentials
		}
		return nil, err
	}

	if err := uc.rateLimiter.CheckAccountLockout(ctx, user.ID); err != nil {
		if errors.Is(err, errs.ErrAccountLocked) {
			uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventAccountLocked, user.ID))
		}
		return nil, err // Returns ErrAccountLocked
	}

	// 3. Reject accounts that cannot log in.
	switch user.Status {
	case "suspended":
		return nil, errs.ErrAccountSuspended
	case "deleted":
		return nil, errs.ErrAccountDeleted
	case "unverified":
		return nil, errs.ErrAccountNotVerified
	}

	// 4. Verify password.
	if user.PasswordHash == nil {
		return nil, errs.ErrInvalidCredentials
	}
	match, err := crypto.ComparePassword(req.Password, *user.PasswordHash)
	if err != nil || !match {
		_ = uc.rateLimiter.RecordAttempt(ctx, &auth.LoginAttempt{
			UserID:    user.ID,
			IPAddress: ip,
			Success:   false,
		})

		uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventLoginFailed, user.ID))

		return nil, errs.ErrInvalidCredentials
	}

	// 5. IP policy check.
	// Run BEFORE recording the success. If the IP is blocked,
	// we reject the login without recording a successful attempt.
	if err := uc.tenantPolicy.CheckIPPolicy(ctx, req.ClientId, ip); err != nil {
		evt := audit.NewEvent(ctx, audit.EventIPBlocked, user.ID)
		evt.Metadata = map[string]string{"ip": ip, "client_id": req.ClientId}
		uc.auditLogger.Log(ctx, evt)
		return nil, errs.ErrIPNotAllowed
	}

	// 6. Suspicious login detection.
	// CheckSuspiciousLogin must run BEFORE we record this attempt as successful.
	result, _ := uc.rateLimiter.CheckSuspiciousLogin(ctx, user.ID, ip)
	if result.Suspicious {
		evt := audit.NewEvent(ctx, audit.EventSuspiciousLogin, user.ID)
		evt.Metadata = map[string]string{"ip": ip, "client_id": req.ClientId}
		uc.auditLogger.Log(ctx, evt)
	}

	// Record success now that the historical IP checks have completed.
	_ = uc.rateLimiter.RecordAttempt(ctx, &auth.LoginAttempt{
		UserID:    user.ID,
		IPAddress: ip,
		Success:   true,
	})

	// 7. MFA check — enroll-based OR forced by suspicious IP policy.
	// ForceMFA is true only when the IP is new AND action == "challenge_mfa".
	// If MFA is not enrolled and ForceMFA is true, we fall through to token
	// issuance — the audit log entry is the only signal in that case.
	if uc.mfaProvider.IsEnrolled(ctx, user.ID) || result.ForceMFA {
		// MFA is active — create a short-lived MFA session instead of issuing tokens.
		mfaToken, err := uc.mfaService.CreateSession(ctx, &mfa.MFASessionData{
			UserID:   user.ID,
			ClientID: req.ClientId,
			Role:     user.Role,
		})
		if err != nil {
			return nil, errs.WithMessage(errs.ErrInternal, "failed to create MFA session")
		}

		return &auth.LoginResponse{
			LoginMFARequired: &auth.LoginMFARequired{
				MfaSessionToken: mfaToken,
				MfaType:         "totp",
			},
		}, nil
	}

	// 6. No MFA — generate token pair directly.
	tokens, _, err := uc.sessionService.CreateSessionAndTokens(ctx, user.ID, user.Role, req.ClientId)
	if err != nil {
		return nil, err
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventLogin, user.ID))

	return &auth.LoginResponse{
		LoginSuccess: &auth.LoginSuccess{
			User:   user,
			Tokens: tokens,
		},
	}, nil
}

// ForgotPassword initiates a password reset by sending a reset link to the
// user's email. Always returns OK to prevent user enumeration.
func (uc *authUsecase) ForgotPassword(ctx context.Context, req *auth.ForgotPasswordRequest) error {
	// 1. Validate input.
	emailAddr := strings.ToLower(strings.TrimSpace(req.Email))
	if emailAddr == "" {
		return errs.WithMessage(errs.ErrInvalidIdentifierFormat, "email is required")
	}

	// 2. Look up user by email.
	user, err := uc.userProvider.FindByLogin(ctx, emailAddr)
	if err != nil {
		// Swallow ErrUserNotFound — always return OK.
		if errors.Is(err, errs.ErrUserNotFound) {
			return nil
		}
		return errs.WithMessage(errs.ErrInternal, "failed to lookup user")
	}

	// 3. Delegate to verification service (stores hashed token, sends email).
	if err := uc.verificationService.SendPasswordReset(ctx, user.ID, emailAddr); err != nil {
		slog.Error("failed to send password reset", "user_id", user.ID, "error", err)
		// Still return OK — don't leak that the account exists but email failed.
		return nil
	}

	evt := audit.NewEvent(ctx, audit.EventForgotPassword, user.ID)
	evt.Metadata = map[string]string{"email": emailAddr}
	uc.auditLogger.Log(ctx, evt)

	return nil
}

// ResetPassword completes a password reset by validating the token from the
// reset email and updating the user's password hash.
func (uc *authUsecase) ResetPassword(ctx context.Context, req *auth.ResetPasswordRequest) error {
	// 1. Validate input.
	if req.Token == "" {
		return errs.WithMessage(errs.ErrInvalidToken, "token is required")
	}

	// 2. Validate password policy BEFORE consuming the token.
	//    This avoids burning the one-time token if the new password is too weak.
	if err := validate.ValidatePassword(req.NewPassword); err != nil {
		return errs.WithMessage(errs.ErrPasswordPolicyViolation, err.Error())
	}

	// 3. Validate and consume the password reset token.
	token, err := uc.verificationService.ValidateToken(ctx, req.Token, verification.TokenTypePasswordReset)
	if err != nil {
		return err // ErrTokenNotFound, ErrTokenExpired, or ErrTokenAlreadyUsed
	}

	// 4. Hash the new password.
	hash, err := crypto.HashPassword(req.NewPassword, &crypto.DefaultArgon2Params)
	if err != nil {
		return errs.WithMessage(errs.ErrInternal, "failed to hash password")
	}

	// 5. Atomically update the password hash.
	if err := uc.userService.UpdatePasswordHash(ctx, token.UserID, hash); err != nil {
		return errs.WithMessage(errs.ErrInternal, "failed to update password")
	}

	// 6. Revoke all existing sessions — force re-login on all devices.
	//    This is a security best practice: if the password was compromised,
	//    the attacker's existing sessions should be invalidated.
	_, _ = uc.sessionService.RevokeAllForUser(ctx, token.UserID, "")

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventPasswordReset, token.UserID))

	return nil
}
