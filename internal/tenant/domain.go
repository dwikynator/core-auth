package tenant

import (
	"context"
	"time"
)

type TenantUseCase interface {
	ResolveScopes(ctx context.Context, clientID string) []string
	FindByClientID(ctx context.Context, clientID string) (*TenantConfig, error)
	// CheckIPPolicy validates the given IP against the tenant's allowlist/denylist.
	// Returns nil if the IP is permitted.
	// Returns ErrIPNotAllowed if the IP is blocked by the policy.
	// If the tenant has no IP policy, always returns nil.
	CheckIPPolicy(ctx context.Context, clientID string, ip string) error
}

// DefaultScopes are assigned when no tenant-specific scopes are configured.
// These follow the OpenID Connect standard scope set.
var DefaultScopes = []string{"openid", "profile", "email"}

// IPPolicy holds the per-tenant IP access policy.
// Both Allowlist and Denylist store CIDR notation strings (e.g., "10.0.0.0/8").
// Rules:
//   - If Allowlist is non-empty, the IP must match at least one entry.
//   - If Denylist is non-empty, the IP must not match any entry.
//   - Allowlist takes precedence: if both are set, allowlist is checked first.
//   - If both are empty, all IPs are permitted.
type IPPolicy struct {
	Allowlist []string // CIDR ranges — nil or empty means "allow all"
	Denylist  []string // CIDR ranges — nil or empty means "block none"
}

// IsEmpty reports whether the policy has no rules configured.
func (p IPPolicy) IsEmpty() bool {
	return len(p.Allowlist) == 0 && len(p.Denylist) == 0
}

// TenantConfig holds per-tenant token lifetime settings.
// If no config is found for a client_id, the system defaults are used.
type TenantConfig struct {
	ClientID        string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	DefaultScopes   []string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	IPPolicy        IPPolicy
}

// TenantConfigRepository defines the persistence contract for tenant config lookups.
// Implementations should cache aggressively — this data changes very rarely.
type TenantConfigRepository interface {
	// FindByClientID returns the tenant config for the given client_id.
	// Returns ErrTenantNotFound if no config exists for this client.
	FindByClientID(ctx context.Context, clientID string) (*TenantConfig, error)
}
