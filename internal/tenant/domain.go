package tenant

import (
	"context"
	"time"
)

type TenantUseCase interface {
	ResolveScopes(ctx context.Context, clientID string) []string
	FindByClientID(ctx context.Context, clientID string) (*TenantConfig, error)
}

// DefaultScopes are assigned when no tenant-specific scopes are configured.
// These follow the OpenID Connect standard scope set.
var DefaultScopes = []string{"openid", "profile", "email"}

// TenantConfig holds per-tenant token lifetime settings.
// If no config is found for a client_id, the system defaults are used.
type TenantConfig struct {
	ClientID        string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	DefaultScopes   []string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// TenantConfigRepository defines the persistence contract for tenant config lookups.
// Implementations should cache aggressively — this data changes very rarely.
type TenantConfigRepository interface {
	// FindByClientID returns the tenant config for the given client_id.
	// Returns ErrTenantNotFound if no config exists for this client.
	FindByClientID(ctx context.Context, clientID string) (*TenantConfig, error)
}
