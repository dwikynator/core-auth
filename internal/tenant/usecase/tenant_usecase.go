package usecase

import (
	"context"
	"net"

	errs "github.com/dwikynator/core-auth/internal/libs/errors"
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

// CheckIPPolicy validates the caller IP against the tenant's configured IP policy.
// Uses Go's net package for CIDR matching — no external dependency.
func (uc *tenantUseCase) CheckIPPolicy(ctx context.Context, clientID string, ip string) error {
	if ip == "" {
		return nil // No IP available (internal gRPC calls) — skip.
	}

	cfg, err := uc.tenantConfigRepo.FindByClientID(ctx, clientID)
	if err != nil {
		// ErrTenantNotFound means no config exists — no policy to enforce.
		return nil
	}

	if cfg.IPPolicy.IsEmpty() {
		return nil
	}

	callerIP := net.ParseIP(ip)
	if callerIP == nil {
		// Malformed IP — fail closed.
		return errs.ErrIPNotAllowed
	}

	// Allowlist takes precedence when configured.
	if len(cfg.IPPolicy.Allowlist) > 0 {
		for _, cidr := range cfg.IPPolicy.Allowlist {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue // Skip malformed CIDRs — log in production.
			}
			if network.Contains(callerIP) {
				return nil // IP is explicitly allowed.
			}
		}
		return errs.ErrIPNotAllowed // Not in allowlist.
	}

	// Denylist check (only reached if no allowlist is configured).
	for _, cidr := range cfg.IPPolicy.Denylist {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(callerIP) {
			return errs.ErrIPNotAllowed // IP is explicitly blocked.
		}
	}

	return nil
}
