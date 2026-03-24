package repository

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/dwikynator/core-auth/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// cacheTTL controls how long tenant configs are cached in memory.
// Tenant configs rarely change, so a long TTL is appropriate.
const cacheTTL = 5 * time.Minute

type cachedConfig struct {
	config    *auth.TenantConfig
	fetchedAt time.Time
}

type postgresTenantConfigRepo struct {
	db    *pgxpool.Pool
	mu    sync.RWMutex
	cache map[string]cachedConfig
}

// NewPostgresTenantConfigRepo returns a TenantConfigRepository backed by pgx
// with an in-memory cache. Cache entries expire after 5 minutes.
func NewPostgresTenantConfigRepo(db *pgxpool.Pool) auth.TenantConfigRepository {
	return &postgresTenantConfigRepo{
		db:    db,
		cache: make(map[string]cachedConfig),
	}
}

func (r *postgresTenantConfigRepo) FindByClientID(ctx context.Context, clientID string) (*auth.TenantConfig, error) {
	// 1. Check the cache first (hot path).
	r.mu.RLock()
	if entry, ok := r.cache[clientID]; ok && time.Since(entry.fetchedAt) < cacheTTL {
		r.mu.RUnlock()
		return entry.config, nil
	}
	r.mu.RUnlock()

	// 2. Cache miss or stale — query Postgres.
	const query = `
		SELECT client_id,
		       EXTRACT(EPOCH FROM access_token_ttl)::bigint,
		       EXTRACT(EPOCH FROM refresh_token_ttl)::bigint,
		       created_at, updated_at
		FROM   tenant_configs
		WHERE  client_id = $1
	`

	var accessSecs, refreshSecs int64
	tc := &auth.TenantConfig{}
	err := r.db.QueryRow(ctx, query, clientID).Scan(
		&tc.ClientID,
		&accessSecs,
		&refreshSecs,
		&tc.CreatedAt,
		&tc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrTenantNotFound
		}
		return nil, err
	}

	tc.AccessTokenTTL = time.Duration(accessSecs) * time.Second
	tc.RefreshTokenTTL = time.Duration(refreshSecs) * time.Second

	// 3. Populate the cache.
	r.mu.Lock()
	r.cache[clientID] = cachedConfig{config: tc, fetchedAt: time.Now()}
	r.mu.Unlock()

	return tc, nil
}
