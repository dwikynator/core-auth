package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/audit"
	"github.com/dwikynator/core-auth/internal/crypto"
	"github.com/dwikynator/core-auth/internal/validate"
	"github.com/dwikynator/core-auth/internal/verification"
	"github.com/dwikynator/minato/merr"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DefaultScopes are assigned when no tenant-specific scopes are configured.
// These follow the OpenID Connect standard scope set.
var DefaultScopes = []string{"openid", "profile", "email"}

// requestMeta holds per-request transport metadata used for session creation.
type requestMeta struct {
	IPAddress *string
	UserAgent string
}

// Service implements authv1.AuthServiceServer.
type Service struct {
	authv1.UnimplementedAuthServiceServer
	repo             UserRepository
	tokenSvc         *TokenService
	verificationSvc  *verification.Service
	blacklistRepo    TokenBlacklistRepository
	sessionRepo      SessionRepository
	tenantConfigRepo TenantConfigRepository
	mfaSvc           *MFAService
	whatsappPhone    string // E.164 WhatsApp Business phone number
	auditLogger      *audit.Logger
}

// NewService constructs an auth service with the given repository.
func NewService(
	repo UserRepository,
	tokenSvc *TokenService,
	verificationSvc *verification.Service,
	blacklistRepo TokenBlacklistRepository,
	sessionRepo SessionRepository,
	tenantConfigRepo TenantConfigRepository,
	mfaSvc *MFAService,
	whatsappPhone string,
	auditLogger *audit.Logger,
) *Service {
	return &Service{
		repo:             repo,
		tokenSvc:         tokenSvc,
		verificationSvc:  verificationSvc,
		blacklistRepo:    blacklistRepo,
		sessionRepo:      sessionRepo,
		tenantConfigRepo: tenantConfigRepo,
		mfaSvc:           mfaSvc,
		whatsappPhone:    whatsappPhone,
		auditLogger:      auditLogger,
	}
}

// auditEvent creates an audit.Event pre-filled with transport metadata from ctx.
func (s *Service) auditEvent(ctx context.Context, eventType audit.EventType, userID string) audit.Event {
	meta := metaFromContext(ctx)
	ip := ""
	if meta.IPAddress != nil {
		ip = *meta.IPAddress
	}
	return audit.Event{
		Type:      eventType,
		UserID:    userID,
		IP:        ip,
		UserAgent: meta.UserAgent,
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

	profile := userToProto(user)
	profile.Scopes = s.resolveScopes(ctx, req.GetClientId())
	profile.MfaEnabled = s.mfaSvc.IsEnrolled(ctx, user.ID)

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventRegister, user.ID))

	// 7. Build response — NO tokens until verified.
	return &authv1.RegisterResponse{
		User: profile,
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

	// 5. Check if MFA is enrolled.
	if s.mfaSvc.IsEnrolled(ctx, user.ID) {
		// MFA is active — create a short-lived MFA session instead of issuing tokens.
		mfaToken, err := s.mfaSvc.CreateSession(ctx, &MFASessionData{
			UserID:   user.ID,
			ClientID: req.GetClientId(),
			Role:     user.Role,
		})
		if err != nil {
			return nil, merr.Internal(errReasonInternal, "failed to create MFA session")
		}

		return &authv1.LoginResponse{
			Result: &authv1.LoginResponse_MfaRequired{
				MfaRequired: &authv1.MFARequired{
					MfaSessionToken: mfaToken,
					MfaType:         "totp",
				},
			},
		}, nil
	}

	// 6. No MFA — generate token pair directly.
	tokens, _, err := s.createSessionAndTokens(ctx, user.ID, user.Role, req.GetClientId())
	if err != nil {
		return nil, err
	}

	// 7. Build response.
	profile := userToProto(user)
	profile.Scopes = s.resolveScopes(ctx, req.GetClientId())
	profile.MfaEnabled = false

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventLogin, user.ID))

	return &authv1.LoginResponse{
		Result: &authv1.LoginResponse_LoginSuccess{
			LoginSuccess: &authv1.LoginSuccess{
				User:   profile,
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
		return nil, merr.Internal(errReasonInternal, "failed to send otp")
	}

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventOTPSent, user.ID))

	return &authv1.SendOTPResponse{
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}, nil
}

// VerifyOTP verifies a 6-digit OTP code and activates the user's account.
func (s *Service) VerifyOTP(ctx context.Context, req *authv1.VerifyOTPRequest) (*authv1.VerifyOTPResponse, error) {
	// 1. Validate input.
	identifier := strings.ToLower(strings.TrimSpace(req.GetEmailOrPhone()))
	if identifier == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_INVALID_IDENTIFIER_FORMAT.String(), "email_or_phone is required")
	}
	if req.GetOtpCode() == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_INVALID_OTP.String(), "otp_code is required")
	}

	// 2. Validate the OTP token. This marks it as "used" on success.
	vToken, err := s.verificationSvc.ValidateToken(ctx, req.GetOtpCode(), verification.TokenTypeOTP)
	if err != nil {
		return nil, err
	}

	// 3. Look up the user associated with the OTP.
	user, err := s.repo.FindByID(ctx, vToken.UserID)
	if err != nil {
		return nil, err
	}

	// 4. Branch by target.
	switch req.GetTarget() {
	case authv1.OTPTarget_OTP_TARGET_PHONE:
		// Phone verification — set phone_verified_at.
		if err := s.repo.UpdatePhoneVerified(ctx, user.ID); err != nil {
			return nil, err
		}
	default:
		// Email verification (default, backward-compatible behavior).
		// Atomically mark email as verified and activate the account.
		if err := s.repo.VerifyEmailAndActivate(ctx, user.ID); err != nil {
			return nil, err
		}
	}

	// 5. Re-fetch the user to get updated verification timestamps.
	user, err = s.repo.FindByID(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	// 6. Generate token pair.
	tokens, _, err := s.createSessionAndTokens(ctx, user.ID, user.Role, req.GetClientId())
	if err != nil {
		return nil, err
	}

	profile := userToProto(user)
	profile.Scopes = s.resolveScopes(ctx, req.GetClientId())
	profile.MfaEnabled = s.mfaSvc.IsEnrolled(ctx, user.ID)

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventOTPVerified, user.ID))

	return &authv1.VerifyOTPResponse{
		User:   profile,
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
		return nil, merr.Internal(errReasonInternal, "failed to lookup user")
	}

	// 3. Delegate to verification service.
	if err := s.verificationSvc.SendMagicLink(ctx, user.ID, emailAddr); err != nil {
		slog.Error("failed to send magic link", "user_id", user.ID, "error", err)
		return nil, merr.Internal(errReasonInternal, "failed to send magic link")
	}

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventMagicLinkSent, user.ID))

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
		return nil, merr.Internal(errReasonInternal, "failed to fetch user")
	}

	// 4. Atomically verify and activate the account (if unverified).
	if user.EmailVerifiedAt == nil || user.Status == "unverified" {
		_ = s.repo.VerifyEmailAndActivate(ctx, user.ID)
		user.Status = "active" // update local struct for response mapping
	}

	// 5. Generate token pair.
	tokens, _, err := s.createSessionAndTokens(ctx, user.ID, user.Role, req.GetClientId())
	if err != nil {
		return nil, err
	}

	profile := userToProto(user)
	profile.Scopes = s.resolveScopes(ctx, req.GetClientId())
	profile.MfaEnabled = s.mfaSvc.IsEnrolled(ctx, user.ID)

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventMagicLinkUsed, user.ID))

	return &authv1.VerifyMagicLinkResponse{
		User:   profile,
		Tokens: tokens,
	}, nil
}

// Logout blacklists the caller's access token so it cannot be used again.
//
// The token's JTI is added to the Redis blacklist with a TTL equal to the
// token's remaining lifetime. This means:
//   - No unbounded memory growth: entries auto-expire.
//   - Immediate effect: the very next authenticated request is rejected.
func (s *Service) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	// 1. Extract the access token from gRPC metadata (Authorization header).
	claims, err := claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// 2. The jti (JWT ID) is the blacklist key.
	jti := claims.ID
	if jti == "" {
		return nil, merr.Internal(errReasonInternal, "token missing jti claim")
	}

	// 3. Blacklist the JTI until the token's natural expiry.
	if claims.ExpiresAt != nil {
		if err := s.blacklistRepo.Blacklist(ctx, jti, claims.ExpiresAt.Time); err != nil {
			return nil, merr.Internal(errReasonInternal, "failed to blacklist token")
		}
	}

	// 4. Revoke the session associated with the refresh token.
	// If the client provided a refresh_token, look up and revoke its session.
	if rawRefresh := req.GetRefreshToken(); rawRefresh != "" {
		hash := HashRefreshToken(rawRefresh)
		session, err := s.sessionRepo.FindByRefreshTokenHash(ctx, hash)
		if err == nil && session.UserID == claims.Subject {
			_ = s.sessionRepo.Revoke(ctx, session.ID, claims.Subject)
		}
		// Silently ignore lookup failures — the session may have already expired.
	}

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventLogout, claims.Subject))

	return &authv1.LogoutResponse{}, nil
}

// ForgotPassword initiates a password reset by sending a reset link to the
// user's email. Always returns OK to prevent user enumeration.
func (s *Service) ForgotPassword(ctx context.Context, req *authv1.ForgotPasswordRequest) (*authv1.ForgotPasswordResponse, error) {
	// 1. Validate input.
	emailAddr := strings.ToLower(strings.TrimSpace(req.GetEmail()))
	if emailAddr == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_INVALID_IDENTIFIER_FORMAT.String(), "email is required")
	}

	// 2. Look up user by email.
	user, err := s.repo.FindByEmail(ctx, emailAddr)
	if err != nil {
		// Swallow ErrUserNotFound — always return OK.
		if err == ErrUserNotFound {
			return &authv1.ForgotPasswordResponse{}, nil
		}
		return nil, merr.Internal(errReasonInternal, "failed to lookup user")
	}

	// 3. Delegate to verification service (stores hashed token, sends email).
	if err := s.verificationSvc.SendPasswordReset(ctx, user.ID, emailAddr); err != nil {
		slog.Error("failed to send password reset", "user_id", user.ID, "error", err)
		// Still return OK — don't leak that the account exists but email failed.
		return &authv1.ForgotPasswordResponse{}, nil
	}

	evt := s.auditEvent(ctx, audit.EventForgotPassword, user.ID)
	evt.Metadata = map[string]string{"email": emailAddr}
	s.auditLogger.Log(ctx, evt)

	return &authv1.ForgotPasswordResponse{}, nil
}

// ResetPassword completes a password reset by validating the token from the
// reset email and updating the user's password hash.
func (s *Service) ResetPassword(ctx context.Context, req *authv1.ResetPasswordRequest) (*authv1.ResetPasswordResponse, error) {
	// 1. Validate input.
	if req.GetToken() == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_INVALID_TOKEN.String(), "token is required")
	}

	// 2. Validate password policy BEFORE consuming the token.
	//    This avoids burning the one-time token if the new password is too weak.
	if err := validate.ValidatePassword(req.GetNewPassword()); err != nil {
		return nil, merr.BadRequest(authv1.ErrorReason_PASSWORD_POLICY_VIOLATION.String(), err.Error())
	}

	// 3. Validate and consume the password reset token.
	token, err := s.verificationSvc.ValidateToken(ctx, req.GetToken(), verification.TokenTypePasswordReset)
	if err != nil {
		return nil, err // ErrTokenNotFound, ErrTokenExpired, or ErrTokenAlreadyUsed
	}

	// 4. Hash the new password.
	hash, err := crypto.HashPassword(req.GetNewPassword(), &crypto.DefaultArgon2Params)
	if err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to hash password")
	}

	// 5. Atomically update the password hash.
	if err := s.repo.UpdatePasswordHash(ctx, token.UserID, hash); err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to update password")
	}

	// 6. Revoke all existing sessions — force re-login on all devices.
	//    This is a security best practice: if the password was compromised,
	//    the attacker's existing sessions should be invalidated.
	_, _ = s.sessionRepo.RevokeAllForUser(ctx, token.UserID, "")

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventPasswordReset, token.UserID))

	return &authv1.ResetPasswordResponse{}, nil
}

// ChangePassword updates the authenticated user's password.
// Requires the current password for verification.
func (s *Service) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	// 1. Get the authenticated user from context.
	claims, err := claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// 2. Validate new password against policy.
	if err := validate.ValidatePassword(req.GetNewPassword()); err != nil {
		return nil, merr.BadRequest(authv1.ErrorReason_PASSWORD_POLICY_VIOLATION.String(), err.Error())
	}

	// 3. Fetch the user to get the current password hash.
	user, err := s.repo.FindByID(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}

	// 4. Verify the current password.
	if user.PasswordHash == nil {
		return nil, ErrInvalidCredentials
	}
	match, err := crypto.ComparePassword(req.GetCurrentPassword(), *user.PasswordHash)
	if err != nil || !match {
		return nil, ErrInvalidCredentials
	}

	// 5. Hash the new password.
	hash, err := crypto.HashPassword(req.GetNewPassword(), &crypto.DefaultArgon2Params)
	if err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to hash password")
	}

	// 6. Update the password hash.
	if err := s.repo.UpdatePasswordHash(ctx, user.ID, hash); err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to update password")
	}

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventPasswordChange, user.ID))

	return &authv1.ChangePasswordResponse{}, nil
}

// claimsContextKey is an unexported type to avoid context collisions.
type claimsContextKey struct{}

// ClaimsContextKey is the key used to store *crypto.Claims in the context.
// Exported so the auth middleware can inject claims, but the key type is
// unexported to prevent external packages from overwriting it.
var ClaimsContextKey = claimsContextKey{}

// claimsFromContext extracts the validated JWT claims injected by the minato
// auth interceptor. The interceptor stores the return value of Validate,
// which is *crypto.Claims.
func claimsFromContext(ctx context.Context) (*crypto.Claims, error) {
	claims, ok := ctx.Value(ClaimsContextKey).(*crypto.Claims)
	if !ok || claims == nil {
		return nil, merr.Unauthorized(authv1.ErrorReason_INVALID_TOKEN.String(), "missing or invalid authentication context")
	}
	return claims, nil
}

// metaFromContext extracts IP and User-Agent from gRPC metadata.
// In gateway mode, the grpc-gateway forwards these as metadata keys.
func metaFromContext(ctx context.Context) requestMeta {
	var meta requestMeta

	// IP address: grpc-gateway sets x-forwarded-for, or we fall back to peer address.
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("x-forwarded-for"); len(vals) > 0 {
			ip := vals[0]
			meta.IPAddress = &ip
		}
		if vals := md.Get("grpcgateway-user-agent"); len(vals) > 0 {
			meta.UserAgent = vals[0]
		} else if vals := md.Get("user-agent"); len(vals) > 0 {
			meta.UserAgent = vals[0]
		}
	}

	// Fallback: direct gRPC peer address.
	if meta.IPAddress == nil {
		if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
			addr := p.Addr.String()
			// Strip port from "ip:port" format.
			if host, _, err := net.SplitHostPort(addr); err == nil {
				meta.IPAddress = &host
			}
		}
	}

	return meta
}

// createSessionAndTokens generates a token pair and persists a new session.
// This is the single entry point for all token-issuing flows.
// It resolves per-tenant TTLs and scopes, falling back to system defaults
// if no config is found.
func (s *Service) createSessionAndTokens(ctx context.Context, userID, role, clientID string) (*authv1.TokenPair, string, error) {
	// 1. Resolve tenant-specific TTLs (or fall back to defaults).
	accessTTL := DefaultAccessTokenTTL
	refreshTTL := DefaultRefreshTokenTTL
	scopes := DefaultScopes

	if clientID != "" {
		tc, err := s.tenantConfigRepo.FindByClientID(ctx, clientID)
		if err == nil {
			accessTTL = tc.AccessTokenTTL
			refreshTTL = tc.RefreshTokenTTL
			if len(tc.DefaultScopes) > 0 {
				scopes = tc.DefaultScopes
			}
		}
		// ErrTenantNotFound is silently ignored — use defaults.
	}

	// 2. Generate token pair with resolved TTLs.
	result, err := s.tokenSvc.GenerateTokenPair(userID, role, scopes, accessTTL)
	if err != nil {
		return nil, "", merr.Internal(errReasonInternal, "failed to generate tokens")
	}

	// 3. Extract request metadata.
	meta := metaFromContext(ctx)

	// 4. Persist the session.
	session := &Session{
		UserID:           userID,
		ClientID:         clientID,
		RefreshTokenHash: result.RefreshTokenHash,
		IPAddress:        meta.IPAddress,
		UserAgent:        meta.UserAgent,
		ExpiresAt:        time.Now().Add(refreshTTL),
	}
	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, "", merr.Internal(errReasonInternal, "failed to create session")
	}

	return result.TokenPair, session.ID, nil
}

// RefreshToken exchanges a valid refresh token for a new token pair.
// The old refresh token is immediately invalidated (rotation).
//
// Security: if the incoming refresh token does NOT match any active session,
// we assume the token was stolen and replayed. In that case, we revoke ALL
// sessions for the affected user (fail-secure).
func (s *Service) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.RefreshTokenResponse, error) {
	rawToken := req.GetRefreshToken()
	if rawToken == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_INVALID_TOKEN.String(), "refresh_token is required")
	}

	// 1. Look up the session by the hash of the incoming token.
	hash := HashRefreshToken(rawToken)
	session, err := s.sessionRepo.FindByRefreshTokenHash(ctx, hash)
	if err != nil {
		if err == ErrSessionNotFound {
			// Possible token reuse! The token was valid once but has already
			// been rotated. An attacker may have stolen the old token.
			//
			// We cannot determine the user_id from the opaque token alone,
			// so we log the event and return a generic error.
			// In a production system with token-to-user mapping, you would
			// revoke all sessions for the affected user here.
			return nil, ErrTokenReuseDetected
		}
		return nil, merr.Internal(errReasonInternal, "failed to look up refresh token")
	}

	// 2. Check if the session has expired.
	if time.Now().After(session.ExpiresAt) {
		// Revoke the expired session for cleanup.
		_ = s.sessionRepo.Revoke(ctx, session.ID, session.UserID)
		return nil, ErrRefreshTokenExpired
	}

	// 3. Check user status (e.g., suspended accounts should not get new tokens).
	user, err := s.repo.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to fetch user")
	}
	if user.Status == "suspended" {
		_ = s.sessionRepo.Revoke(ctx, session.ID, session.UserID)
		return nil, merr.Forbidden(authv1.ErrorReason_ACCOUNT_SUSPENDED.String(), "account is suspended")
	}

	// 4. Resolve tenant-specific access TTL.
	accessTTL := DefaultAccessTokenTTL
	scopes := DefaultScopes
	if session.ClientID != "" {
		tc, err := s.tenantConfigRepo.FindByClientID(ctx, session.ClientID)
		if err == nil {
			accessTTL = tc.AccessTokenTTL
			if len(tc.DefaultScopes) > 0 {
				scopes = tc.DefaultScopes
			}
		}
	}

	// 5. Generate new token pair.
	result, err := s.tokenSvc.GenerateTokenPair(user.ID, user.Role, scopes, accessTTL)
	if err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to generate tokens")
	}

	// 6. Atomically rotate the refresh token hash.
	// If this fails (e.g., concurrent revocation), the old token is already
	// invalidated and the new one was never stored — safe.
	if err := s.sessionRepo.RotateRefreshToken(ctx, session.ID, result.RefreshTokenHash); err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to rotate refresh token")
	}

	return &authv1.RefreshTokenResponse{
		Tokens: result.TokenPair,
	}, nil
}

func (s *Service) GetMe(ctx context.Context, req *authv1.GetMeRequest) (*authv1.GetMeResponse, error) {
	claims, err := claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	user, err := s.repo.FindByID(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}

	profile := userToProto(user)
	profile.Scopes = claims.Scopes
	profile.MfaEnabled = s.mfaSvc.IsEnrolled(ctx, user.ID)

	return &authv1.GetMeResponse{
		User: profile,
	}, nil
}

func (s *Service) ListSessions(ctx context.Context, req *authv1.ListSessionsRequest) (*authv1.ListSessionsResponse, error) {
	claims, err := claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	sessions, err := s.sessionRepo.ListActiveByUser(ctx, claims.Subject)
	if err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to list sessions")
	}

	// Convert domain sessions to proto.
	protoSessions := make([]*authv1.Session, 0, len(sessions))
	for _, s := range sessions {
		ps := &authv1.Session{
			SessionId:  s.ID,
			ClientId:   s.ClientID,
			UserAgent:  s.UserAgent,
			CreatedAt:  timestamppb.New(s.CreatedAt),
			LastUsedAt: timestamppb.New(s.LastUsedAt),
		}
		if s.IPAddress != nil {
			ps.IpAddress = *s.IPAddress
		}
		protoSessions = append(protoSessions, ps)
	}

	// Determine which session belongs to the current caller.
	// The access token's JTI doesn't directly map to a session ID, but
	// we can identify the current session if the caller also provides it.
	// For now, we leave current_id empty — the client can match by IP/User-Agent.
	return &authv1.ListSessionsResponse{
		Sessions: protoSessions,
	}, nil
}

func (s *Service) RevokeSession(ctx context.Context, req *authv1.RevokeSessionRequest) (*authv1.RevokeSessionResponse, error) {
	claims, err := claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	sessionID := req.GetSessionId()
	if sessionID == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_SESSION_NOT_FOUND.String(), "session_id is required")
	}

	// Verify ownership: we need to check that this session belongs to the caller.
	// We do this by attempting to revoke and checking if it existed.
	// A more strict approach would be to fetch first and compare user_id.
	// However, since sessions are scoped per-user in the query, we can use
	// a user-scoped revoke.
	if err := s.sessionRepo.Revoke(ctx, sessionID, claims.Subject); err != nil {
		if err == ErrSessionNotFound {
			return nil, ErrSessionNotFound
		}
		return nil, merr.Internal(errReasonInternal, "failed to revoke session")
	}

	return &authv1.RevokeSessionResponse{}, nil
}

func (s *Service) RevokeAllSessions(ctx context.Context, req *authv1.RevokeAllSessionsRequest) (*authv1.RevokeAllSessionsResponse, error) {
	claims, err := claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Revoke all sessions except the current one.
	// Since we don't easily know the current session ID from the access token,
	// we revoke ALL sessions. The caller can immediately refresh to get a new one.
	count, err := s.sessionRepo.RevokeAllForUser(ctx, claims.Subject, "")
	if err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to revoke sessions")
	}

	return &authv1.RevokeAllSessionsResponse{
		RevokedCount: int32(count),
	}, nil
}

// requireAdmin verifies the authenticated caller has the "admin" role.
func requireAdmin(ctx context.Context) (*crypto.Claims, error) {
	claims, err := claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if claims.Role != "admin" {
		return nil, merr.Forbidden("PERMISSION_DENIED", "admin role required")
	}
	return claims, nil
}

func (s *Service) SuspendUser(ctx context.Context, req *authv1.SuspendUserRequest) (*authv1.SuspendUserResponse, error) {
	claims, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}

	userID := req.GetUserId()
	if userID == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_USER_NOT_FOUND.String(), "user_id is required")
	}

	// 1. Verify user exists and is not already suspended/deleted.
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user.Status == "suspended" {
		return nil, ErrAccountSuspended
	}

	// 2. Update status to "suspended".
	if err := s.repo.UpdateStatus(ctx, userID, "suspended"); err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to suspend user")
	}

	// 3. Revoke all active sessions immediately.
	// The user's existing access tokens will still work until they expire
	// (max 15 minutes), but they cannot refresh after this point.
	_, _ = s.sessionRepo.RevokeAllForUser(ctx, userID, "")

	evt := s.auditEvent(ctx, audit.EventAccountSuspend, userID)
	evt.Metadata = map[string]string{"reason": req.GetReason(), "admin_id": claims.Subject}
	s.auditLogger.Log(ctx, evt)

	return &authv1.SuspendUserResponse{}, nil
}

func (s *Service) UnsuspendUser(ctx context.Context, req *authv1.UnsuspendUserRequest) (*authv1.UnsuspendUserResponse, error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	userID := req.GetUserId()
	if userID == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_USER_NOT_FOUND.String(), "user_id is required")
	}

	// Update status back to "active".
	if err := s.repo.UpdateStatus(ctx, userID, "active"); err != nil {
		return nil, err
	}

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventAccountUnsuspend, userID))

	return &authv1.UnsuspendUserResponse{}, nil
}

func (s *Service) DeleteUser(ctx context.Context, req *authv1.DeleteUserRequest) (*authv1.DeleteUserResponse, error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	userID := req.GetUserId()
	if userID == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_USER_NOT_FOUND.String(), "user_id is required")
	}

	// 1. Soft-delete the user (sets deleted_at and status = "deleted").
	if err := s.repo.SoftDelete(ctx, userID); err != nil {
		return nil, err
	}

	// 2. Revoke all active sessions immediately.
	_, _ = s.sessionRepo.RevokeAllForUser(ctx, userID, "")

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventAccountDeleted, userID))

	return &authv1.DeleteUserResponse{}, nil
}

// resolveScopes returns the scopes for the given client_id, falling back to defaults.
// This is a read-only lookup — it does NOT modify any state.
func (s *Service) resolveScopes(ctx context.Context, clientID string) []string {
	if clientID == "" {
		return DefaultScopes
	}
	tc, err := s.tenantConfigRepo.FindByClientID(ctx, clientID)
	if err == nil && len(tc.DefaultScopes) > 0 {
		return tc.DefaultScopes
	}
	return DefaultScopes
}

// requireScope verifies the authenticated caller's token contains the required scope.
// Returns the claims on success, or a Forbidden error if the scope is missing.
func requireScope(ctx context.Context, scope string) (*crypto.Claims, error) {
	claims, err := claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	for _, s := range claims.Scopes {
		if s == scope {
			return claims, nil
		}
	}

	return nil, merr.Forbidden("INSUFFICIENT_SCOPE", "token missing required scope: "+scope)
}

func (s *Service) SetupTOTP(ctx context.Context, req *authv1.SetupTOTPRequest) (*authv1.SetupTOTPResponse, error) {
	claims, err := claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Fetch the user to get their email for the authenticator app display.
	user, err := s.repo.FindByID(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}

	accountName := user.ID
	if user.Email != nil {
		accountName = *user.Email
	}

	result, err := s.mfaSvc.Setup(ctx, user.ID, accountName)
	if err != nil {
		return nil, err
	}

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventMFASetup, user.ID))

	return &authv1.SetupTOTPResponse{
		Secret: result.Secret,
		QrUri:  result.QRURI,
	}, nil
}

func (s *Service) ConfirmTOTP(ctx context.Context, req *authv1.ConfirmTOTPRequest) (*authv1.ConfirmTOTPResponse, error) {
	claims, err := claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.GetTotpCode() == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_MFA_INVALID_CODE.String(), "totp_code is required")
	}

	if err := s.mfaSvc.ConfirmSetup(ctx, claims.Subject, req.GetTotpCode()); err != nil {
		return nil, err
	}

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventMFAConfirmed, claims.Subject))

	return &authv1.ConfirmTOTPResponse{}, nil
}

// ChallengeMFA verifies the TOTP code and issues a new token pair.
func (s *Service) ChallengeMFA(ctx context.Context, req *authv1.ChallengeMFARequest) (*authv1.ChallengeMFAResponse, error) {
	// 1. Validate input.
	if req.GetMfaSessionToken() == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_INVALID_MFA_SESSION.String(), "mfa_session_token is required")
	}
	if req.GetCode() == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_MFA_INVALID_CODE.String(), "code is required")
	}

	// 2. Consume the MFA session (single-use).
	// If the token is invalid, expired, or already consumed, this returns an error.
	sessionData, err := s.mfaSvc.ConsumeSession(ctx, req.GetMfaSessionToken())
	if err != nil {
		return nil, err
	}

	// 3. Validate the TOTP code against the user's enrolled secret.
	if err := s.mfaSvc.ValidateCode(ctx, sessionData.UserID, req.GetCode()); err != nil {
		// The MFA session is already consumed — the user must restart login.
		// This prevents brute-forcing the TOTP code.
		return nil, err
	}

	// 4. MFA passed — issue the full token pair.
	tokens, _, err := s.createSessionAndTokens(ctx, sessionData.UserID, sessionData.Role, sessionData.ClientID)
	if err != nil {
		return nil, err
	}

	// 5. Build response.
	user, err := s.repo.FindByID(ctx, sessionData.UserID)
	if err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to fetch user")
	}

	profile := userToProto(user)
	profile.Scopes = s.resolveScopes(ctx, sessionData.ClientID)
	profile.MfaEnabled = true

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventMFAChallenged, sessionData.UserID))

	return &authv1.ChallengeMFAResponse{
		User:   profile,
		Tokens: tokens,
	}, nil
}

func (s *Service) DisableMFA(ctx context.Context, req *authv1.DisableMFARequest) (*authv1.DisableMFAResponse, error) {
	claims, err := claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// 1. Require password re-confirmation for security.
	if req.GetPassword() == "" {
		return nil, merr.BadRequest(authv1.ErrorReason_INVALID_CREDENTIALS.String(), "password is required to disable MFA")
	}

	user, err := s.repo.FindByID(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}

	if user.PasswordHash == nil {
		return nil, ErrInvalidCredentials
	}
	match, err := crypto.ComparePassword(req.GetPassword(), *user.PasswordHash)
	if err != nil || !match {
		return nil, ErrInvalidCredentials
	}

	// 2. Delete all MFA credentials.
	if err := s.mfaSvc.DisableForUser(ctx, claims.Subject); err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to disable MFA")
	}

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventMFADisabled, claims.Subject))

	return &authv1.DisableMFAResponse{}, nil
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
func (s *Service) GetWhatsAppVerificationLink(ctx context.Context, req *authv1.GetWhatsAppVerificationLinkRequest) (*authv1.GetWhatsAppVerificationLinkResponse, error) {
	// 1. Get the authenticated user.
	claims, err := claimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	user, err := s.repo.FindByID(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}

	// 2. Ensure the user has a phone number set.
	if user.Phone == nil || *user.Phone == "" {
		return nil, ErrPhoneNotSet
	}

	// 3. Reject if phone is already verified.
	if user.PhoneVerifiedAt != nil {
		return nil, ErrPhoneAlreadyVerified
	}

	// 4. Generate a phone OTP (stored in verification_tokens, no email sent).
	otpCode, expiresAt, err := s.verificationSvc.GeneratePhoneOTP(ctx, user.ID)
	if err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to generate phone OTP")
	}

	// 5. Build the wa.me deep-link URL.
	// Strip the "+" prefix from the phone number for the wa.me URL format.
	bizPhone := strings.TrimPrefix(s.whatsappPhone, "+")
	message := fmt.Sprintf("My verification code is: %s", otpCode)
	waURL := fmt.Sprintf("https://wa.me/%s?text=%s", bizPhone, url.QueryEscape(message))

	s.auditLogger.Log(ctx, s.auditEvent(ctx, audit.EventOTPSent, claims.Subject))

	return &authv1.GetWhatsAppVerificationLinkResponse{
		WhatsappUrl: waURL,
		OtpCode:     otpCode,
		ExpiresAt:   expiresAt.Format(time.RFC3339),
	}, nil
}
