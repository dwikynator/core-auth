package delivery

import (
	"context"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/mfa"
	"github.com/dwikynator/core-auth/internal/tenant"
	userdelivery "github.com/dwikynator/core-auth/internal/user/delivery"
	"github.com/dwikynator/minato"
	"google.golang.org/grpc"
)

type mfaGRPCHandler struct {
	authv1.UnimplementedMFAServiceServer
	mfaUc    mfa.MFAUseCase
	tenantUc tenant.TenantUseCase
}

func PublicMethods() []string {
	return []string{
		authv1.MFAService_ChallengeMFA_FullMethodName,
	}
}

func RegisterMFAGRPCHandler(s *minato.Server, mfaUc mfa.MFAUseCase, tenantUc tenant.TenantUseCase) {
	handler := &mfaGRPCHandler{
		mfaUc:    mfaUc,
		tenantUc: tenantUc,
	}
	s.RegisterGRPC(func(s grpc.ServiceRegistrar) {
		authv1.RegisterMFAServiceServer(s, handler)
	})
	s.RegisterGateway(authv1.RegisterMFAServiceHandlerFromEndpoint)
}

func (h *mfaGRPCHandler) SetupTOTP(ctx context.Context, req *authv1.SetupTOTPRequest) (*authv1.SetupTOTPResponse, error) {
	res, err := h.mfaUc.SetupTOTP(ctx)
	if err != nil {
		return nil, err
	}
	return &authv1.SetupTOTPResponse{
		Secret: res.Secret,
		QrUri:  res.QRURI,
	}, nil
}

func (h *mfaGRPCHandler) ConfirmTOTP(ctx context.Context, req *authv1.ConfirmTOTPRequest) (*authv1.ConfirmTOTPResponse, error) {
	err := h.mfaUc.ConfirmTOTP(ctx, &mfa.ConfirmTOTPRequest{
		TOTPCode: req.GetTotpCode(),
	})
	if err != nil {
		return nil, err
	}
	return &authv1.ConfirmTOTPResponse{}, nil
}

func (h *mfaGRPCHandler) ChallengeMFA(ctx context.Context, req *authv1.ChallengeMFARequest) (*authv1.ChallengeMFAResponse, error) {
	res, err := h.mfaUc.ChallengeMFA(ctx, &mfa.ChallengeMFARequest{
		MFASessionToken: req.GetMfaSessionToken(),
		Code:            req.GetCode(),
	})
	if err != nil {
		return nil, err
	}

	profile := userdelivery.MapUserToProto(res.User)
	profile.Scopes = h.tenantUc.ResolveScopes(ctx, res.ClientID)
	profile.MfaEnabled = true // Guaranteed true since MFA challenge succeeded

	return &authv1.ChallengeMFAResponse{
		User: profile,
		Tokens: &authv1.TokenPair{
			AccessToken:  res.Tokens.AccessToken,
			RefreshToken: res.Tokens.RefreshToken,
			ExpiresIn:    res.Tokens.ExpiresIn,
		},
	}, nil
}

func (h *mfaGRPCHandler) DisableMFA(ctx context.Context, req *authv1.DisableMFARequest) (*authv1.DisableMFAResponse, error) {
	err := h.mfaUc.DisableMFA(ctx, req.GetPassword())
	if err != nil {
		return nil, err
	}
	return &authv1.DisableMFAResponse{}, nil
}
