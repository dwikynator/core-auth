package delivery

import (
	"context"
	"time"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/mfa"
	"github.com/dwikynator/core-auth/internal/tenant"
	userdelivery "github.com/dwikynator/core-auth/internal/user/delivery"
	"github.com/dwikynator/core-auth/internal/verification"
	"github.com/dwikynator/minato"
	"google.golang.org/grpc"
)

type verificationGRPCHandler struct {
	authv1.UnimplementedVerificationServiceServer
	verificationUc verification.VerificationService
	tenantUc       tenant.TenantUseCase
	mfaUc          mfa.MFAUseCase
}

func PublicMethods() []string {
	return []string{
		authv1.VerificationService_SendOTP_FullMethodName,
		authv1.VerificationService_VerifyOTP_FullMethodName,
		authv1.VerificationService_SendMagicLink_FullMethodName,
		authv1.VerificationService_VerifyMagicLink_FullMethodName,
	}
}

func RegisterVerificationGRPCHandler(s *minato.Server, verificationUc verification.VerificationService, tenantUc tenant.TenantUseCase, mfaUc mfa.MFAUseCase) {
	handler := &verificationGRPCHandler{
		verificationUc: verificationUc,
		tenantUc:       tenantUc,
		mfaUc:          mfaUc,
	}
	s.RegisterGRPC(func(s grpc.ServiceRegistrar) {
		authv1.RegisterVerificationServiceServer(s, handler)
	})
	s.RegisterGateway(authv1.RegisterVerificationServiceHandlerFromEndpoint)
}

func mapOTPTarget(target authv1.OTPTarget) verification.OTPTarget {
	switch target {
	case authv1.OTPTarget_OTP_TARGET_EMAIL:
		return verification.OTPTargetEmail
	case authv1.OTPTarget_OTP_TARGET_PHONE:
		return verification.OTPTargetPhone
	default:
		return verification.OTPTargetUnspecified
	}
}

func (h *verificationGRPCHandler) SendOTP(ctx context.Context, req *authv1.SendOTPRequest) (*authv1.SendOTPResponse, error) {
	res, err := h.verificationUc.SendOTP(ctx, &verification.SendOTPRequest{
		EmailOrPhone: req.GetEmailOrPhone(),
		Target:       mapOTPTarget(req.GetTarget()),
	})
	if err != nil {
		return nil, err
	}
	return &authv1.SendOTPResponse{
		ExpiresAt: res.ExpiresAt.Format(time.RFC3339),
	}, nil
}

func (h *verificationGRPCHandler) VerifyOTP(ctx context.Context, req *authv1.VerifyOTPRequest) (*authv1.VerifyOTPResponse, error) {
	res, err := h.verificationUc.VerifyOTP(ctx, &verification.VerifyOTPRequest{
		EmailOrPhone: req.GetEmailOrPhone(),
		OTPCode:      req.GetOtpCode(),
		Target:       mapOTPTarget(req.GetTarget()),
		ClientId:     req.GetClientId(),
	})
	if err != nil {
		return nil, err
	}

	profile := userdelivery.MapUserToProto(res.User)
	profile.Scopes = h.tenantUc.ResolveScopes(ctx, req.GetClientId())
	profile.MfaEnabled = h.mfaUc.IsEnrolled(ctx, res.User.ID)

	var tokenPair *authv1.TokenPair
	if res.Tokens != nil {
		tokenPair = &authv1.TokenPair{
			AccessToken:  res.Tokens.AccessToken,
			RefreshToken: res.Tokens.RefreshToken,
			ExpiresIn:    res.Tokens.ExpiresIn,
		}
	}

	return &authv1.VerifyOTPResponse{
		User:   profile,
		Tokens: tokenPair,
	}, nil
}

func (h *verificationGRPCHandler) SendMagicLink(ctx context.Context, req *authv1.SendMagicLinkRequest) (*authv1.SendMagicLinkResponse, error) {
	err := h.verificationUc.SendMagicLink(ctx, &verification.SendMagicLinkRequest{
		Email:    req.GetEmail(),
		ClientId: req.GetClientId(),
	})
	if err != nil {
		return nil, err
	}
	return &authv1.SendMagicLinkResponse{}, nil
}

func (h *verificationGRPCHandler) VerifyMagicLink(ctx context.Context, req *authv1.VerifyMagicLinkRequest) (*authv1.VerifyMagicLinkResponse, error) {
	res, err := h.verificationUc.VerifyMagicLink(ctx, &verification.VerifyMagicLinkRequest{
		Token:    req.GetToken(),
		ClientId: req.GetClientId(),
	})
	if err != nil {
		return nil, err
	}

	profile := userdelivery.MapUserToProto(res.User)
	profile.Scopes = h.tenantUc.ResolveScopes(ctx, req.GetClientId())
	profile.MfaEnabled = h.mfaUc.IsEnrolled(ctx, res.User.ID)

	var tokenPair *authv1.TokenPair
	if res.Tokens != nil {
		tokenPair = &authv1.TokenPair{
			AccessToken:  res.Tokens.AccessToken,
			RefreshToken: res.Tokens.RefreshToken,
			ExpiresIn:    res.Tokens.ExpiresIn,
		}
	}

	return &authv1.VerifyMagicLinkResponse{
		User:   profile,
		Tokens: tokenPair,
	}, nil
}

func (h *verificationGRPCHandler) GetWhatsAppVerificationLink(ctx context.Context, req *authv1.GetWhatsAppVerificationLinkRequest) (*authv1.GetWhatsAppVerificationLinkResponse, error) {
	res, err := h.verificationUc.GetWhatsAppVerificationLink(ctx)
	if err != nil {
		return nil, err
	}
	return &authv1.GetWhatsAppVerificationLinkResponse{
		WhatsappUrl: res.WhatsappUrl,
		OtpCode:     res.OTPCode,
		ExpiresAt:   res.ExpiresAt.Format(time.RFC3339),
	}, nil
}
