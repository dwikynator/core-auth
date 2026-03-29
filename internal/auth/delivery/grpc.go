package delivery

import (
	"context"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/auth"
	"github.com/dwikynator/core-auth/internal/tenant"
	userdelivery "github.com/dwikynator/core-auth/internal/user/delivery"

	"github.com/dwikynator/core-auth/internal/mfa"
	"github.com/dwikynator/minato"
	"google.golang.org/grpc"
)

type authGRPCHandler struct {
	authv1.UnimplementedAuthServiceServer
	authUc   auth.AuthUsecase
	mfaUc    mfa.MFAUseCase
	tenantUc tenant.TenantUseCase
}

func RegisterAuthGRPCHandler(s *minato.Server, authUsecase auth.AuthUsecase, mfaUc mfa.MFAUseCase, tenantUc tenant.TenantUseCase) {
	handler := &authGRPCHandler{
		authUc:   authUsecase,
		mfaUc:    mfaUc,
		tenantUc: tenantUc,
	}
	s.RegisterGRPC(func(s grpc.ServiceRegistrar) {
		authv1.RegisterAuthServiceServer(s, handler)
	})
	s.RegisterGateway(authv1.RegisterAuthServiceHandlerFromEndpoint)
}

func PublicMethods() []string {
	return []string{
		authv1.AuthService_Register_FullMethodName,
		authv1.AuthService_Login_FullMethodName,
		authv1.AuthService_ForgotPassword_FullMethodName,
		authv1.AuthService_ResetPassword_FullMethodName,
	}
}

func (h *authGRPCHandler) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {

	user, err := h.authUc.Register(ctx, &auth.RegisterRequest{
		Email:    req.Email,
		Username: req.Username,
		Phone:    req.Phone,
		Password: req.Password,
		ClientId: req.ClientId,
	})
	if err != nil {
		return nil, err
	}

	profile := userdelivery.MapUserToProto(user)
	profile.Scopes = h.tenantUc.ResolveScopes(ctx, req.GetClientId())
	profile.MfaEnabled = h.mfaUc.IsEnrolled(ctx, user.ID)

	return &authv1.RegisterResponse{
		User: profile,
	}, nil
}

func (h *authGRPCHandler) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	resp, err := h.authUc.Login(ctx, &auth.LoginRequest{
		Email:    req.Email,
		Username: req.Username,
		Phone:    req.Phone,
		Password: req.Password,
		ClientId: req.ClientId,
	})
	if err != nil {
		return nil, err
	}

	if resp.LoginMFARequired != nil {
		return &authv1.LoginResponse{
			Result: &authv1.LoginResponse_MfaRequired{
				MfaRequired: &authv1.MFARequired{
					MfaSessionToken: resp.LoginMFARequired.MfaSessionToken,
					MfaType:         resp.LoginMFARequired.MfaType,
				},
			},
		}, nil
	}

	user := resp.LoginSuccess.User

	profile := userdelivery.MapUserToProto(user)
	profile.Scopes = h.tenantUc.ResolveScopes(ctx, req.GetClientId())
	profile.MfaEnabled = h.mfaUc.IsEnrolled(ctx, user.ID)

	return &authv1.LoginResponse{
		Result: &authv1.LoginResponse_LoginSuccess{
			LoginSuccess: &authv1.LoginSuccess{
				User: profile,
				Tokens: &authv1.TokenPair{
					AccessToken:  resp.LoginSuccess.Tokens.AccessToken,
					RefreshToken: resp.LoginSuccess.Tokens.RefreshToken,
					ExpiresIn:    resp.LoginSuccess.Tokens.ExpiresIn,
				},
			},
		},
	}, nil
}

func (h *authGRPCHandler) ForgotPassword(ctx context.Context, req *authv1.ForgotPasswordRequest) (*authv1.ForgotPasswordResponse, error) {
	err := h.authUc.ForgotPassword(ctx, &auth.ForgotPasswordRequest{
		Email: req.Email,
	})
	if err != nil {
		return nil, err
	}

	return &authv1.ForgotPasswordResponse{}, nil
}

func (h *authGRPCHandler) ResetPassword(ctx context.Context, req *authv1.ResetPasswordRequest) (*authv1.ResetPasswordResponse, error) {
	err := h.authUc.ResetPassword(ctx, &auth.ResetPasswordRequest{
		Token:       req.Token,
		NewPassword: req.NewPassword,
	})
	if err != nil {
		return nil, err
	}

	return &authv1.ResetPasswordResponse{}, nil
}
