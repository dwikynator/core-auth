package delivery

import (
	"context"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/admin"
	"github.com/dwikynator/minato"
	"google.golang.org/grpc"
)

type adminGRPCHandler struct {
	authv1.UnimplementedAdminServiceServer
	adminUc admin.AdminUseCase
}

func RegisterAdminGRPCHandler(s *minato.Server, adminUsecase admin.AdminUseCase) {
	handler := &adminGRPCHandler{
		adminUc: adminUsecase,
	}
	s.RegisterGRPC(func(s grpc.ServiceRegistrar) {
		authv1.RegisterAdminServiceServer(s, handler)
	})
	s.RegisterGateway(authv1.RegisterAdminServiceHandlerFromEndpoint)
}

func (h *adminGRPCHandler) SuspendUser(ctx context.Context, req *authv1.SuspendUserRequest) (*authv1.SuspendUserResponse, error) {
	err := h.adminUc.SuspendUser(ctx, &admin.SuspendUserRequest{
		UserID: req.GetUserId(),
		Reason: req.GetReason(),
	})
	if err != nil {
		return nil, err
	}
	return &authv1.SuspendUserResponse{}, nil
}

func (h *adminGRPCHandler) UnsuspendUser(ctx context.Context, req *authv1.UnsuspendUserRequest) (*authv1.UnsuspendUserResponse, error) {
	err := h.adminUc.UnsuspendUser(ctx, &admin.UnsuspendUserRequest{
		UserID: req.GetUserId(),
	})
	if err != nil {
		return nil, err
	}
	return &authv1.UnsuspendUserResponse{}, nil
}

func (h *adminGRPCHandler) DeleteUser(ctx context.Context, req *authv1.DeleteUserRequest) (*authv1.DeleteUserResponse, error) {
	err := h.adminUc.DeleteUser(ctx, &admin.DeleteUserRequest{
		UserID: req.GetUserId(),
	})
	if err != nil {
		return nil, err
	}
	return &authv1.DeleteUserResponse{}, nil
}
