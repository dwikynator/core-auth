package usecase

import (
	"context"

	"github.com/dwikynator/core-auth/internal/tenant"
)

type tenantUseCase struct {
	tenantConfigRepo tenant.TenantConfigRepository
}

func NewTenantUseCase(tenantConfigRepo tenant.TenantConfigRepository) tenant.TenantUseCase {
	return &tenantUseCase{tenantConfigRepo: tenantConfigRepo}
}

func (uc *tenantUseCase) FindByClientID(ctx context.Context, clientID string) (*tenant.TenantConfig, error) {
	return uc.tenantConfigRepo.FindByClientID(ctx, clientID)
}

func (uc *tenantUseCase) ResolveScopes(ctx context.Context, clientID string) []string {
	if clientID == "" {
		return tenant.DefaultScopes
	}
	tc, err := uc.tenantConfigRepo.FindByClientID(ctx, clientID)
	if err == nil && len(tc.DefaultScopes) > 0 {
		return tc.DefaultScopes
	}
	return tenant.DefaultScopes
}
