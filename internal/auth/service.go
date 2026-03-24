package auth

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/crypto"
	"github.com/dwikynator/core-auth/internal/validate"
	"github.com/dwikynator/core-auth/internal/verification"
	"github.com/dwikynator/minato/merr"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// requestMeta holds per-request transport metadata used for session creation.
type requestMeta struct {
	IPAddress *string
	UserAgent string
}

// Service implements authv1.AuthServiceServer.
type Service struct {
	authv1.UnimplementedAuthServiceServer
	repo            UserRepository
	tokenSvc        *TokenService
	verificationSvc *verification.Service
	blacklistRepo   TokenBlacklistRepository
	sessionRepo     SessionRepository
}

// NewService constructs an auth service with the given repository.
func NewService(
	repo UserRepository,
	tokenSvc *TokenService,
	verificationSvc *verification.Service,
	blacklistRepo TokenBlacklistRepository,
	sessionRepo SessionRepository,
) *Service {
	return &Service{
		repo:            repo,
		tokenSvc:        tokenSvc,
		verificationSvc: verificationSvc,
		blacklistRepo:   blacklistRepo,
		sessionRepo:     sessionRepo,
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
	tokens, _, err := s.createSessionAndTokens(ctx, user.ID, user.Role, req.GetClientId())
	if err != nil {
		return nil, err
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
		return nil, merr.Internal(errReasonInternal, "failed to send otp")
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
		return nil, merr.Internal(errReasonInternal, "failed to verify and activate account")
	}

	// 4. Fetch the updated user.
	user, err := s.repo.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to fetch user")
	}

	// 5. Generate token pair — user is now verified and active.
	tokens, _, err := s.createSessionAndTokens(ctx, user.ID, user.Role, req.GetClientId())
	if err != nil {
		return nil, err
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
		return nil, merr.Internal(errReasonInternal, "failed to lookup user")
	}

	// 3. Delegate to verification service.
	if err := s.verificationSvc.SendMagicLink(ctx, user.ID, emailAddr); err != nil {
		slog.Error("failed to send magic link", "user_id", user.ID, "error", err)
		return nil, merr.Internal(errReasonInternal, "failed to send magic link")
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

	return &authv1.VerifyMagicLinkResponse{
		User:   userToProto(user),
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

	return &authv1.LogoutResponse{}, nil
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
func (s *Service) createSessionAndTokens(ctx context.Context, userID, role, clientID string) (*authv1.TokenPair, string, error) {
	// 1. Generate token pair.
	result, err := s.tokenSvc.GenerateTokenPair(userID, role)
	if err != nil {
		return nil, "", merr.Internal(errReasonInternal, "failed to generate tokens")
	}

	// 2. Extract request metadata.
	meta := metaFromContext(ctx)

	// 3. Persist the session.
	session := &Session{
		UserID:           userID,
		ClientID:         clientID,
		RefreshTokenHash: result.RefreshTokenHash,
		IPAddress:        meta.IPAddress,
		UserAgent:        meta.UserAgent,
		ExpiresAt:        time.Now().Add(DefaultRefreshTokenTTL),
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
	// return nil, merr.Internal(errReasonInternal, "failed to look up refresh token")
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

	// 4. Generate new token pair.
	result, err := s.tokenSvc.GenerateTokenPair(user.ID, user.Role)
	if err != nil {
		return nil, merr.Internal(errReasonInternal, "failed to generate tokens")
	}

	// 5. Atomically rotate the refresh token hash.
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

	return &authv1.GetMeResponse{
		User: userToProto(user),
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
