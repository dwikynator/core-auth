package auth

import (
	"context"
	"time"

	"github.com/dwikynator/core-auth/internal/mfa"
	"github.com/dwikynator/core-auth/internal/session"
	"github.com/dwikynator/core-auth/internal/user"
	"github.com/dwikynator/core-auth/internal/verification"

	"github.com/dwikynator/core-auth/internal/infra/audit"
)

type AuthUsecase interface {
	Register(ctx context.Context, req *RegisterRequest) (*user.User, error)
	Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error)
	ForgotPassword(ctx context.Context, req *ForgotPasswordRequest) error
	ResetPassword(ctx context.Context, req *ResetPasswordRequest) error
}

type AuditLogger interface {
	Log(ctx context.Context, event audit.Event)
}

type UserService interface {
	CreateUser(ctx context.Context, user *user.User) error
	UpdatePasswordHash(ctx context.Context, userId string, hash string) error
}

type UserProvider interface {
	FindByLogin(ctx context.Context, identifier string) (*user.User, error)
}

type VerificationService interface {
	SendOTPToUser(ctx context.Context, userID, emailAddr string) (time.Time, error)
	SendPasswordReset(ctx context.Context, userID, emailAddr string) error
	ValidateToken(ctx context.Context, rawToken string, tokenType verification.TokenType) (*verification.VerificationToken, error)
}

type SessionService interface {
	CreateSessionAndTokens(ctx context.Context, userID, role, clientID string) (*session.TokenPair, string, error)
	RevokeAllForUser(ctx context.Context, userID, clientID string) (int, error)
}

type MFAService interface {
	CreateSession(ctx context.Context, data *mfa.MFASessionData) (string, error)
}

type MFAProvider interface {
	IsEnrolled(ctx context.Context, userID string) bool
}

type RegisterRequest struct {
	Email    string
	Username string
	Phone    string
	Password string
	ClientId string
}

type LoginRequest struct {
	Email    string
	Username string
	Phone    string
	Password string
	ClientId string
}

type LoginSuccess struct {
	User   *user.User
	Tokens *session.TokenPair
}

type LoginMFARequired struct {
	MfaSessionToken string
	MfaType         string
}

type LoginResponse struct {
	LoginSuccess     *LoginSuccess
	LoginMFARequired *LoginMFARequired
}

type ForgotPasswordRequest struct {
	Email string
}

type ResetPasswordRequest struct {
	Token       string
	NewPassword string
}
