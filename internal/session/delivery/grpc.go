package delivery

import (
	"context"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/session"
	"github.com/dwikynator/minato"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type sessionGRPCHandler struct {
	authv1.UnimplementedSessionServiceServer
	sessionUc session.SessionUsecase
}

func PublicMethods() []string {
	return []string{
		authv1.SessionService_RefreshToken_FullMethodName,
	}
}

func RegisterSessionGRPCHandler(s *minato.Server, sessionUc session.SessionUsecase) {
	handler := &sessionGRPCHandler{
		sessionUc: sessionUc,
	}
	s.RegisterGRPC(func(s grpc.ServiceRegistrar) {
		authv1.RegisterSessionServiceServer(s, handler)
	})
	s.RegisterGateway(authv1.RegisterSessionServiceHandlerFromEndpoint)
}

func (h *sessionGRPCHandler) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	err := h.sessionUc.Logout(ctx, &session.LogoutRequest{
		RefreshToken: req.GetRefreshToken(),
	})
	if err != nil {
		return nil, err
	}
	return &authv1.LogoutResponse{}, nil
}

func (h *sessionGRPCHandler) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.RefreshTokenResponse, error) {
	tp, err := h.sessionUc.RefreshToken(ctx, &session.RefreshTokenRequest{
		RefreshToken: req.GetRefreshToken(),
		ClientId:     req.GetClientId(),
	})
	if err != nil {
		return nil, err
	}
	return &authv1.RefreshTokenResponse{
		Tokens: &authv1.TokenPair{
			AccessToken:  tp.AccessToken,
			RefreshToken: tp.RefreshToken,
			ExpiresIn:    tp.ExpiresIn,
		},
	}, nil
}

func (h *sessionGRPCHandler) ListSessions(ctx context.Context, req *authv1.ListSessionsRequest) (*authv1.ListSessionsResponse, error) {
	resp, err := h.sessionUc.ListSessions(ctx)
	if err != nil {
		return nil, err
	}

	protoSessions := make([]*authv1.Session, 0, len(resp.Sessions))
	for _, s := range resp.Sessions {
		ps := &authv1.Session{
			SessionId:  s.ID,
			ClientId:   s.ClientID,
			UserAgent:  s.UserAgent,
			CreatedAt:  timestamppb.New(s.CreatedAt),
			LastUsedAt: timestamppb.New(s.LastUsedAt),
		}
		if s.IPAddress != nil {
			ps.IpAddress = *s.IPAddress
		}
		protoSessions = append(protoSessions, ps)
	}

	return &authv1.ListSessionsResponse{
		Sessions:  protoSessions,
		CurrentId: resp.CurrentId,
	}, nil
}

func (h *sessionGRPCHandler) RevokeSession(ctx context.Context, req *authv1.RevokeSessionRequest) (*authv1.RevokeSessionResponse, error) {
	err := h.sessionUc.RevokeSession(ctx, req.GetSessionId())
	if err != nil {
		return nil, err
	}
	return &authv1.RevokeSessionResponse{}, nil
}

func (h *sessionGRPCHandler) RevokeAllSessions(ctx context.Context, req *authv1.RevokeAllSessionsRequest) (*authv1.RevokeAllSessionsResponse, error) {
	resp, err := h.sessionUc.RevokeAllSessions(ctx)
	if err != nil {
		return nil, err
	}
	return &authv1.RevokeAllSessionsResponse{
		RevokedCount: int32(resp.RevokedCount),
	}, nil
}
