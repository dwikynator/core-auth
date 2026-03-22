package auth

import (
	"context"
	"log/slog"
	"strings"
	"time"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/crypto"
	"github.com/dwikynator/core-auth/internal/validate"
	"github.com/dwikynator/core-auth/internal/verification"
	"github.com/dwikynator/minato/merr"
)

// Service implements authv1.AuthServiceServer.
type Service struct {
	// UnimplementedAuthServiceServer ensures forward compatibility when new RPCs are added in the future.
	authv1.UnimplementedAuthServiceServer
	repo            UserRepository
	tokenSvc        *TokenService
	verificationSvc *verification.Service
}

// NewService constructs an auth service with the given repository.
func NewService(repo UserRepository, tokenSvc *TokenService, verificationSvc *verification.Service) *Service {
	return &Service{
		repo:            repo,
		tokenSvc:        tokenSvc,
		verificationSvc: verificationSvc,
	}

}

// Register
func (s *Service) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	// 1. At least one identifier must be provided.
	if req.GetEmail() == "" && req.GetUsername() == "" && req.GetPhone() == "" {
		return nil, ErrInvalidIdentifier
	}

	// 2. Validate & normalise each provided identifier.
	user := &User{
		Role:   "user",
		Status: "unverified",
	}

	if raw := req.GetEmail(); raw != "" {
		email, err := validate.NormaliseEmail(raw)
		if err != nil {
			return nil, merr.BadRequest(authv1.ErrorReason_INVALID_IDENTIFIER_FORMAT.String(), err.Error())
		}
		user.Email = &email
	}

	if raw := req.GetUsername(); raw != "" {
		username, err := validate.ValidateUsername(raw)
		if err != nil {
			return nil, merr.BadRequest(authv1.ErrorReason_INVALID_IDENTIFIER_FORMAT.String(), err.Error())
		}
		user.Username = &username
	}

	if raw := req.GetPhone(); raw != "" {
		phone, err := validate.NormalisePhone(raw)
		if err != nil {
			return nil, merr.BadRequest(authv1.ErrorReason_INVALID_IDENTIFIER_FORMAT.String(), err.Error())
		}
		user.Phone = &phone
	}

	// 3. Validate password against policy.
	if err := validate.ValidatePassword(req.GetPassword()); err != nil {
		return nil, merr.BadRequest(authv1.ErrorReason_PASSWORD_POLICY_VIOLATION.String(), err.Error())
	}

	// 4. Hash the password.
	hash, err := crypto.HashPassword(req.GetPassword(), &crypto.DefaultArgon2Params)
	if err != nil {
		return nil, merr.Internal("INTERNAL ERROR", "failed to hash password")
	}
	user.PasswordHash = &hash

	// 5. Persist.
	if err := s.repo.Create(ctx, user); err != nil {
		return nil, err // ErrUserAlreadyExists is already a *merr.Error
	}

	// 6. Send verification OTP (if email is provided).
	if user.Email != nil {
		if _, err := s.verificationSvc.SendOTP(ctx, user.ID, *user.Email); err != nil {
			// Log but don't fail registration — user can request a new OTP later.
			slog.Error("failed to send verification OTP on register", "user_id", user.ID, "error", err)
		}
	}

	// 7. Build response — NO tokens until verified.
	return &authv1.RegisterResponse{
		User: userToProto(user),
		// Tokens intentionally omitted. Client should redirect to OTP verification screen.
	}, nil
}

// Login
func (s *Service) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	// 1. Determine which identifier the client sent.
	identifier := firstNonEmpty(req.GetEmail(), req.GetUsername(), req.GetPhone())
	if identifier == "" {
		return nil, ErrInvalidIdentifier
	}

	// Normalise: lowercase email for lookup.
	identifier = strings.ToLower(strings.TrimSpace(identifier))

	// 2. Find user.
	user, err := s.repo.FindByLogin(ctx, identifier)
	if err != nil {
		// Map ErrUserNotFound → ErrInvalidCredentials to prevent user enumeration.
		if err == ErrUserNotFound {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// 3. Reject accounts that cannot log in.
	switch user.Status {
	case "suspended":
		return nil, merr.Forbidden(authv1.ErrorReason_ACCOUNT_SUSPENDED.String(), "account is suspended")
	case "deleted":
		return nil, merr.Forbidden(authv1.ErrorReason_ACCOUNT_DELETED.String(), "account has been deleted")
	case "unverified":
		return nil, ErrAccountNotVerified
	}

	// 4. Verify password.
	if user.PasswordHash == nil {
		return nil, ErrInvalidCredentials
	}
	match, err := crypto.ComparePassword(req.GetPassword(), *user.PasswordHash)
	if err != nil || !match {
		return nil, ErrInvalidCredentials
	}

	// 5. Generate token pair.
	tokens, err := s.tokenSvc.GenerateTokenPair(user.ID, user.Role)
	if err != nil {
		return nil, merr.Internal("INTERNAL_ERROR", "failed to generate tokens")
	}

	// 6. Build response.
	return &authv1.LoginResponse{
		Result: &authv1.LoginResponse_LoginSuccess{
			LoginSuccess: &authv1.LoginSuccess{
				User:   userToProto(user),
				Tokens: tokens,
			},
		},
	}, nil
}

// Helpers
func userToProto(u *User) *authv1.UserProfile {
	p := &authv1.UserProfile{
		UserId: u.ID,
		Role:   u.Role,
	}
	if u.Email != nil {
		p.Email = *u.Email
	}
	if u.Username != nil {
		p.Username = *u.Username
	}
	if u.Phone != nil {
		p.Phone = *u.Phone
	}
	if u.EmailVerifiedAt != nil {
		p.EmailVerified = true
	}
	if u.PhoneVerifiedAt != nil {
		p.PhoneVerified = true
	}
	return p
}

// firstNonEmpty returns the first non-empty string argument.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// SendOTP sends a verification OTP to the user's email.
func (s *Service) SendOTP(ctx context.Context, req *authv1.SendOTPRequest) (*authv1.SendOTPResponse, error) {
	// 1. Validate input.
	emailAddr := strings.ToLower(strings.TrimSpace(req.GetEmailOrPhone()))
	if emailAddr == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_INVALID_IDENTIFIER_FORMAT.String(), "email_or_phone is required")
	}

	// 2. Look up user by email.
	user, err := s.repo.FindByEmail(ctx, emailAddr)
	if err != nil {
		return nil, err // ErrUserNotFound → 404
	}

	// 3. Reject if already verified.
	if user.EmailVerifiedAt != nil {
		return nil, ErrAlreadyVerified
	}

	// 4. Delegate to verification service.
	expiresAt, err := s.verificationSvc.SendOTP(ctx, user.ID, emailAddr)
	if err != nil {
		return nil, merr.Internal("INTERNAL_ERROR", "failed to send otp")
	}

	return &authv1.SendOTPResponse{
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}, nil
}

// VerifyOTP verifies a 6-digit OTP code and activates the user's account.
func (s *Service) VerifyOTP(ctx context.Context, req *authv1.VerifyOTPRequest) (*authv1.VerifyOTPResponse, error) {
	// 1. Validate input.
	emailAddr := strings.ToLower(strings.TrimSpace(req.GetEmailOrPhone()))
	if emailAddr == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_INVALID_IDENTIFIER_FORMAT.String(), "email_or_phone is required")
	}
	if req.GetOtpCode() == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_INVALID_OTP.String(), "otp_code is required")
	}

	// 2. Validate the OTP token. This marks it as "used" on success.
	token, err := s.verificationSvc.ValidateToken(ctx, req.GetOtpCode(), verification.TokenTypeOTP)
	if err != nil {
		return nil, err // ErrTokenNotFound, ErrTokenExpired, or ErrTokenAlreadyUsed
	}

	// 3. Atomically verify email and activate the account.
	if err := s.repo.VerifyEmailAndActivate(ctx, token.UserID); err != nil {
		return nil, merr.Internal("INTERNAL_ERROR", "failed to verify and activate account")
	}

	// 4. Fetch the updated user.
	user, err := s.repo.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, merr.Internal("INTERNAL_ERROR", "failed to fetch user")
	}

	// 5. Generate token pair — user is now verified and active.
	tokens, err := s.tokenSvc.GenerateTokenPair(user.ID, user.Role)
	if err != nil {
		return nil, merr.Internal("INTERNAL_ERROR", "failed to generate tokens")
	}

	return &authv1.VerifyOTPResponse{
		User:   userToProto(user),
		Tokens: tokens,
	}, nil
}

// SendMagicLink sends a magic link to the user's email for passwordless login.
func (s *Service) SendMagicLink(ctx context.Context, req *authv1.SendMagicLinkRequest) (*authv1.SendMagicLinkResponse, error) {
	// 1. Validate input.
	emailAddr := strings.ToLower(strings.TrimSpace(req.GetEmail()))
	if emailAddr == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_INVALID_IDENTIFIER_FORMAT.String(), "email is required")
	}

	// 2. Look up user by email.
	user, err := s.repo.FindByEmail(ctx, emailAddr)
	if err != nil {
		// Swallow ErrUserNotFound to prevent user enumeration.
		if err == ErrUserNotFound {
			return &authv1.SendMagicLinkResponse{}, nil
		}
		return nil, merr.Internal("INTERNAL_ERROR", "failed to lookup user")
	}

	// 3. Delegate to verification service.
	if err := s.verificationSvc.SendMagicLink(ctx, user.ID, emailAddr); err != nil {
		slog.Error("failed to send magic link", "user_id", user.ID, "error", err)
		return nil, merr.Internal("INTERNAL_ERROR", "failed to send magic link")
	}

	return &authv1.SendMagicLinkResponse{}, nil
}

// VerifyMagicLink verifies a magic link token and issues a token pair.
func (s *Service) VerifyMagicLink(ctx context.Context, req *authv1.VerifyMagicLinkRequest) (*authv1.VerifyMagicLinkResponse, error) {
	// 1. Validate input.
	if req.GetToken() == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_INVALID_TOKEN.String(), "token is required")
	}

	// 2. Validate the magic link token. This marks it as "used" on success.
	token, err := s.verificationSvc.ValidateToken(ctx, req.GetToken(), verification.TokenTypeMagicLink)
	if err != nil {
		return nil, err // ErrTokenNotFound, ErrTokenExpired, or ErrTokenAlreadyUsed
	}

	// 3. Fetch the user.
	user, err := s.repo.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, merr.Internal("INTERNAL_ERROR", "failed to fetch user")
	}

	// 4. Atomically verify and activate the account (if unverified).
	if user.EmailVerifiedAt == nil || user.Status == "unverified" {
		_ = s.repo.VerifyEmailAndActivate(ctx, user.ID)
		user.Status = "active" // update local struct for response mapping
	}

	// 5. Generate token pair.
	tokens, err := s.tokenSvc.GenerateTokenPair(user.ID, user.Role)
	if err != nil {
		return nil, merr.Internal("INTERNAL_ERROR", "failed to generate tokens")
	}

	return &authv1.VerifyMagicLinkResponse{
		User:   userToProto(user),
		Tokens: tokens,
	}, nil
}
