package delivery

import (
	"context"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/mfa"
	"github.com/dwikynator/core-auth/internal/oauth"
	"github.com/dwikynator/core-auth/internal/tenant"
	userdelivery "github.com/dwikynator/core-auth/internal/user/delivery"
	"github.com/dwikynator/minato"
	"google.golang.org/grpc"
)

type oauthGRPCHandler struct {
	authv1.UnimplementedOAuthServiceServer
	oauthUc  oauth.OAuthUseCase
	tenantUc tenant.TenantUseCase
	mfaUc    mfa.MFAUseCase
}

func PublicMethods() []string {
	return []string{
		authv1.OAuthService_GetOAuthURL_FullMethodName,
		authv1.OAuthService_OAuthCallback_FullMethodName,
		authv1.OAuthService_LinkProvider_FullMethodName,
	}
}

func RegisterOAuthGRPCHandler(s *minato.Server, oauthUc oauth.OAuthUseCase, tenantUc tenant.TenantUseCase, mfaUc mfa.MFAUseCase) {
	handler := &oauthGRPCHandler{
		oauthUc:  oauthUc,
		tenantUc: tenantUc,
		mfaUc:    mfaUc,
	}
	s.RegisterGRPC(func(s grpc.ServiceRegistrar) {
		authv1.RegisterOAuthServiceServer(s, handler)
	})
	s.RegisterGateway(authv1.RegisterOAuthServiceHandlerFromEndpoint)
}

func (h *oauthGRPCHandler) GetOAuthURL(ctx context.Context, req *authv1.GetOAuthURLRequest) (*authv1.GetOAuthURLResponse, error) {
	authURL, err := h.oauthUc.GetOAuthURL(ctx, &oauth.GetOAuthURLRequest{
		ClientId: req.GetClientId(),
		Provider: req.GetProvider(),
		State:    req.GetState(),
	})
	if err != nil {
		return nil, err
	}
	return &authv1.GetOAuthURLResponse{
		AuthorizationUrl: authURL,
	}, nil
}

func (h *oauthGRPCHandler) OAuthCallback(ctx context.Context, req *authv1.OAuthCallbackRequest) (*authv1.OAuthCallbackResponse, error) {
	res, err := h.oauthUc.OAuthCallback(ctx, &oauth.OAuthCallbackRequest{
		ClientId: req.GetClientId(),
		Provider: req.GetProvider(),
		State:    req.GetState(),
		Code:     req.GetCode(),
	})
	if err != nil {
		return nil, err
	}

	if res.OAuthAccountLinkRequired != nil {
		return &authv1.OAuthCallbackResponse{
			Result: &authv1.OAuthCallbackResponse_AccountLinkRequired{
				AccountLinkRequired: &authv1.AccountLinkRequired{
					LinkSessionToken: res.OAuthAccountLinkRequired.LinkSessionToken,
					Provider:         res.OAuthAccountLinkRequired.Provider,
					ProviderEmail:    res.OAuthAccountLinkRequired.ProviderEmail,
				},
			},
		}, nil
	}

	if res.OAuthSuccess != nil {
		profile := userdelivery.MapUserToProto(res.OAuthSuccess.User)
		profile.Scopes = h.tenantUc.ResolveScopes(ctx, req.GetClientId())
		profile.MfaEnabled = h.mfaUc.IsEnrolled(ctx, res.OAuthSuccess.User.ID)

		var tokenPair *authv1.TokenPair
		if res.OAuthSuccess.Tokens != nil {
			tokenPair = &authv1.TokenPair{
				AccessToken:  res.OAuthSuccess.Tokens.AccessToken,
				RefreshToken: res.OAuthSuccess.Tokens.RefreshToken,
				ExpiresIn:    res.OAuthSuccess.Tokens.ExpiresIn,
			}
		}

		return &authv1.OAuthCallbackResponse{
			Result: &authv1.OAuthCallbackResponse_OauthSuccess{
				OauthSuccess: &authv1.OAuthSuccess{
					User:   profile,
					Tokens: tokenPair,
				},
			},
		}, nil
	}

	return nil, nil // Should not be reached
}

func (h *oauthGRPCHandler) LinkProvider(ctx context.Context, req *authv1.LinkProviderRequest) (*authv1.LinkProviderResponse, error) {
	res, err := h.oauthUc.LinkProvider(ctx, &oauth.LinkProviderRequest{
		LinkSessionToken: req.GetLinkSessionToken(),
		Password:         req.GetPassword(),
	})
	if err != nil {
		return nil, err
	}

	profile := userdelivery.MapUserToProto(res.User)
	profile.Scopes = h.tenantUc.ResolveScopes(ctx, res.ClientID)
	profile.MfaEnabled = h.mfaUc.IsEnrolled(ctx, res.User.ID)

	var tokenPair *authv1.TokenPair
	if res.Tokens != nil {
		tokenPair = &authv1.TokenPair{
			AccessToken:  res.Tokens.AccessToken,
			RefreshToken: res.Tokens.RefreshToken,
		}
	}

	return &authv1.LinkProviderResponse{
		User:   profile,
		Tokens: tokenPair,
	}, nil
}

func (h *oauthGRPCHandler) UnlinkProvider(ctx context.Context, req *authv1.UnlinkProviderRequest) (*authv1.UnlinkProviderResponse, error) {
	err := h.oauthUc.UnlinkProvider(ctx, req.GetProvider())
	if err != nil {
		return nil, err
	}
	return &authv1.UnlinkProviderResponse{}, nil
}
