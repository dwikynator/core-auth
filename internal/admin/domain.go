package admin

import (
	"context"

	"github.com/dwikynator/core-auth/internal/infra/audit"
	"github.com/dwikynator/core-auth/internal/user"
)

type AdminUseCase interface {
	SuspendUser(ctx context.Context, req *SuspendUserRequest) error
	UnsuspendUser(ctx context.Context, req *UnsuspendUserRequest) error
	DeleteUser(ctx context.Context, req *DeleteUserRequest) error
}

type AuditLogger interface {
	Log(ctx context.Context, event audit.Event)
}

type SuspendUserRequest struct {
	UserID string
	Reason string
}

type UnsuspendUserRequest struct {
	UserID string
}

type DeleteUserRequest struct {
	UserID string
}

type UserProvider interface {
	FindByID(ctx context.Context, id string) (*user.User, error)
}

type UserService interface {
	UpdateStatus(ctx context.Context, userID string, status string) error
	SoftDelete(ctx context.Context, userID string) error
}

type SessionService interface {
	RevokeAllForUser(ctx context.Context, userID string, exceptSessionID string) (int, error)
}
