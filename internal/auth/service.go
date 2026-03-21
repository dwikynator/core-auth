package auth

import (
	"context"
	"strings"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/crypto"
	"github.com/dwikynator/core-auth/internal/validate"
	"github.com/dwikynator/minato/merr"
)

// Service implements authv1.AuthServiceServer.
type Service struct {
	// UnimplementedAuthServiceServer ensures forward compatibility when new RPCs are added in later phases.
	authv1.UnimplementedAuthServiceServer
	repo UserRepository
}

// NewService constructs an auth service with the given repository.
func NewService(repo UserRepository) *Service {
	return &Service{repo: repo}
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
		Status: "active",
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

	// 6. Build response. Tokens are deferred to Phase 1B.
	return &authv1.RegisterResponse{
		User: userToProto(user),
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
	}

	// 4. Verify password.
	if user.PasswordHash == nil {
		return nil, ErrInvalidCredentials
	}
	match, err := crypto.ComparePassword(req.GetPassword(), *user.PasswordHash)
	if err != nil || !match {
		return nil, ErrInvalidCredentials
	}

	// 5. Build response. Tokens are deferred to Phase 1B.
	return &authv1.LoginResponse{
		Result: &authv1.LoginResponse_LoginSuccess{
			LoginSuccess: &authv1.LoginSuccess{
				User: userToProto(user),
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
