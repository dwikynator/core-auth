package usecase

import (
	"context"

	"github.com/dwikynator/core-auth/internal/admin"
	"github.com/dwikynator/core-auth/internal/infra/audit"
	contextLib "github.com/dwikynator/core-auth/internal/libs/context"
	errs "github.com/dwikynator/core-auth/internal/libs/errors"
)

type adminUseCase struct {
	userProvider   admin.UserProvider
	userService    admin.UserService
	sessionService admin.SessionService
	auditLogger    admin.AuditLogger
}

func NewAdminUseCase(userProvider admin.UserProvider, userService admin.UserService, sessionService admin.SessionService, auditLogger admin.AuditLogger) admin.AdminUseCase {
	return &adminUseCase{userProvider: userProvider, userService: userService, sessionService: sessionService, auditLogger: auditLogger}
}

func (uc *adminUseCase) SuspendUser(ctx context.Context, req *admin.SuspendUserRequest) error {
	claims, err := contextLib.RequireAdmin(ctx)
	if err != nil {
		return err
	}

	if req.UserID == "" {
		return errs.WithMessage(errs.ErrUserNotFound, "user_id is required")
	}

	// 1. Verify user exists and is not already suspended/deleted.
	user, err := uc.userProvider.FindByID(ctx, req.UserID)
	if err != nil {
		return err
	}
	if user.Status == "suspended" {
		return errs.ErrAccountSuspended
	}

	// 2. Update status to "suspended".
	if err := uc.userService.UpdateStatus(ctx, req.UserID, "suspended"); err != nil {
		return errs.WithMessage(errs.ErrInternal, "failed to suspend user")
	}

	// 3. Revoke all active sessions immediately.
	// The user's existing access tokens will still work until they expire
	// (max 15 minutes), but they cannot refresh after this point.
	_, _ = uc.sessionService.RevokeAllForUser(ctx, req.UserID, "")

	evt := audit.NewEvent(ctx, audit.EventAccountSuspend, req.UserID)
	evt.Metadata = map[string]string{
		"reason":   req.Reason,
		"admin_id": claims.Subject,
	}
	uc.auditLogger.Log(ctx, evt)

	return nil
}

func (uc *adminUseCase) UnsuspendUser(ctx context.Context, req *admin.UnsuspendUserRequest) error {
	claims, err := contextLib.RequireAdmin(ctx)
	if err != nil {
		return err
	}

	if req.UserID == "" {
		return errs.WithMessage(errs.ErrUserNotFound, "user_id is required")
	}

	// Update status back to "active".
	if err := uc.userService.UpdateStatus(ctx, req.UserID, "active"); err != nil {
		return errs.WithMessage(errs.ErrInternal, "failed to unsuspend user")
	}

	evt := audit.NewEvent(ctx, audit.EventAccountUnsuspend, req.UserID)
	evt.Metadata = map[string]string{
		"admin_id": claims.Subject,
	}
	uc.auditLogger.Log(ctx, evt)

	return nil
}

func (uc *adminUseCase) DeleteUser(ctx context.Context, req *admin.DeleteUserRequest) error {
	claims, err := contextLib.RequireAdmin(ctx)
	if err != nil {
		return err
	}

	if req.UserID == "" {
		return errs.WithMessage(errs.ErrUserNotFound, "user_id is required")
	}

	// 1. Soft-delete the user (sets deleted_at and status = "deleted").
	if err := uc.userService.SoftDelete(ctx, req.UserID); err != nil {
		return err
	}

	// 2. Revoke all active sessions immediately.
	_, _ = uc.sessionService.RevokeAllForUser(ctx, req.UserID, "")

	evt := audit.NewEvent(ctx, audit.EventAccountDeleted, req.UserID)
	evt.Metadata = map[string]string{
		"admin_id": claims.Subject,
	}
	uc.auditLogger.Log(ctx, evt)

	return nil
}
