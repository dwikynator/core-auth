package repository

import (
	"context"
	"fmt"
	"time"

	domain "github.com/dwikynator/core-auth/internal/session/domain"
	"github.com/redis/go-redis/v9"
)

// redisBlacklist implements auth.TokenBlacklistRepository using Redis.
type redisBlacklist struct {
	client *redis.Client
}

// NewRedisBlacklist creates a new Redis-backed token blacklist.
func NewRedisBlacklist(client *redis.Client) domain.TokenBlacklistRepository {
	return &redisBlacklist{client: client}
}

// Blacklist stores a revoked token's JTI in Redis with an auto-expire TTL.
//
// Performance characteristics:
//   - Time complexity: O(1) — Redis SET with EX.
//   - Key format: "blacklist:jti:<jti>" (≈46 bytes per key).
//   - Value: "1" (1 byte) — we only need existence, not content.
//   - TTL: Exact remaining lifetime of the token. Once the token would have
//     expired naturally, Redis evicts the key automatically. This means the
//     blacklist never grows unboundedly, unlike a database-backed approach.
func (r *redisBlacklist) Blacklist(ctx context.Context, jti string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token already expired — no need to blacklist.
		return nil
	}

	key := blacklistKey(jti)
	return r.client.Set(ctx, key, "1", ttl).Err()
}

// IsBlacklisted checks whether a JTI exists in the blacklist.
//
// Performance characteristics:
//   - Time complexity: O(1) — Redis EXISTS.
//   - We use EXISTS instead of GET because we don't need the value.
//     EXISTS returns an integer count and avoids a string copy on the Redis side.
func (r *redisBlacklist) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	key := blacklistKey(jti)
	n, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// blacklistKey builds the Redis key for a given JTI.
// Factored into a helper so the key format is defined in exactly one place.
func blacklistKey(jti string) string {
	return fmt.Sprintf("blacklist:jti:%s", jti)
}
