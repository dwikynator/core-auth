package delivery

import (
	"context"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/libs/crypto"
	"github.com/dwikynator/core-auth/internal/mfa"
	"github.com/dwikynator/core-auth/internal/user"
	"github.com/dwikynator/minato"
	"google.golang.org/grpc"
)

type userGRPCHandler struct {
	authv1.UnimplementedUserServiceServer
	userUc user.UserUseCase
	mfaUc  mfa.MFAUseCase
}

func RegisterUserGRPCHandler(s *minato.Server, userUc user.UserUseCase, mfaUc mfa.MFAUseCase) {
	handler := &userGRPCHandler{
		userUc: userUc,
		mfaUc:  mfaUc,
	}
	s.RegisterGRPC(func(s grpc.ServiceRegistrar) {
		authv1.RegisterUserServiceServer(s, handler)
	})
	s.RegisterGateway(authv1.RegisterUserServiceHandlerFromEndpoint)
}

func (h *userGRPCHandler) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	err := h.userUc.ChangePassword(ctx, &user.ChangePasswordRequest{
		CurrentPassword: req.GetCurrentPassword(),
		NewPassword:     req.GetNewPassword(),
	})
	if err != nil {
		return nil, err
	}
	return &authv1.ChangePasswordResponse{}, nil
}

func (h *userGRPCHandler) GetMe(ctx context.Context, req *authv1.GetMeRequest) (*authv1.GetMeResponse, error) {
	u, err := h.userUc.GetMe(ctx)
	if err != nil {
		return nil, err
	}

	claims, err := crypto.ClaimsFromContext(ctx)
	if err != nil {
		return nil, err
	}

	profile := MapUserToProto(u)
	profile.Scopes = claims.Scopes
	profile.MfaEnabled = h.mfaUc.IsEnrolled(ctx, u.ID)

	return &authv1.GetMeResponse{
		User: profile,
	}, nil
}
