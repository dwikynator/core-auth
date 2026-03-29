package usecase

import (
	"context"

	"github.com/dwikynator/core-auth/internal/infra/audit"
	"github.com/dwikynator/core-auth/internal/libs/crypto"
	errs "github.com/dwikynator/core-auth/internal/libs/errors"
	"github.com/dwikynator/core-auth/internal/libs/validate"
	userdomain "github.com/dwikynator/core-auth/internal/user"
)

type userUseCase struct {
	userRepo    userdomain.UserRepository
	auditLogger userdomain.AuditLogger
}

func NewUserUseCase(userRepo userdomain.UserRepository, auditLogger userdomain.AuditLogger) userdomain.UserUseCase {
	return &userUseCase{userRepo: userRepo, auditLogger: auditLogger}
}

// ChangePassword updates the authenticated user's password.
// Requires the current password for verification.
func (uc *userUseCase) ChangePassword(ctx context.Context, req *userdomain.ChangePasswordRequest) error {
	// 1. Get the authenticated user from context.
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return err
	}

	// 2. Validate new password against policy.
	if err := validate.ValidatePassword(req.NewPassword); err != nil {
		return errs.WithMessage(errs.ErrPasswordPolicyViolation, err.Error())
	}

	// 3. Fetch the user to get the current password hash.
	user, err := uc.userRepo.FindByID(ctx, claims.Subject)
	if err != nil {
		return err
	}

	// 4. Verify the current password.
	if user.PasswordHash == nil {
		return errs.ErrInvalidCredentials
	}
	match, err := crypto.ComparePassword(req.CurrentPassword, *user.PasswordHash)
	if err != nil || !match {
		return errs.ErrInvalidCredentials
	}

	// 5. Hash the new password.
	hash, err := crypto.HashPassword(req.NewPassword, &crypto.DefaultArgon2Params)
	if err != nil {
		return errs.WithMessage(errs.ErrInternal, "failed to hash password")
	}

	// 6. Update the password hash.
	if err := uc.userRepo.UpdatePasswordHash(ctx, user.ID, hash); err != nil {
		return errs.WithMessage(errs.ErrInternal, "failed to update password")
	}

	uc.auditLogger.Log(ctx, audit.NewEvent(ctx, audit.EventPasswordChange, user.ID))

	return nil
}

func (uc *userUseCase) FindByLogin(ctx context.Context, identifier string) (*userdomain.User, error) {
	return uc.userRepo.FindByLogin(ctx, identifier)
}

func (uc *userUseCase) FindByEmail(ctx context.Context, email string) (*userdomain.User, error) {
	return uc.userRepo.FindByEmail(ctx, email)
}

func (uc *userUseCase) FindByID(ctx context.Context, id string) (*userdomain.User, error) {
	return uc.userRepo.FindByID(ctx, id)
}

func (uc *userUseCase) CreateUser(ctx context.Context, user *userdomain.User) error {
	return uc.userRepo.Create(ctx, user)
}

func (uc *userUseCase) UpdatePhoneVerified(ctx context.Context, userID string) error {
	return uc.userRepo.UpdatePhoneVerified(ctx, userID)
}

func (uc *userUseCase) VerifyEmailAndActivate(ctx context.Context, userID string) error {
	return uc.userRepo.VerifyEmailAndActivate(ctx, userID)
}

func (uc *userUseCase) UpdatePasswordHash(ctx context.Context, userID string, newHash string) error {
	return uc.userRepo.UpdatePasswordHash(ctx, userID, newHash)
}

func (uc *userUseCase) GetMe(ctx context.Context) (*userdomain.User, error) {
	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	user, err := uc.userRepo.FindByID(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (uc *userUseCase) UpdateStatus(ctx context.Context, userID string, status string) error {
	return uc.userRepo.UpdateStatus(ctx, userID, status)
}

func (uc *userUseCase) SoftDelete(ctx context.Context, userID string) error {
	return uc.userRepo.SoftDelete(ctx, userID)
}
