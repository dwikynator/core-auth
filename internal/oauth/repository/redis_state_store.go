package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// stateTTL is how long an OAuth2 state token is valid.
	// The user must complete the consent screen and be redirected back within this window.
	// 10 minutes is generous — most users complete this in seconds.
	stateTTL = 10 * time.Minute

	// statePrefix namespaces the Redis keys to avoid collisions with other features.
	statePrefix = "oauth:state:"
)

// RedisStateStore implements oauth.StateStore using Redis.
type RedisStateStore struct {
	rdb *redis.Client
}

// NewRedisStateStore creates a new Redis-backed state store.
func NewRedisStateStore(rdb *redis.Client) *RedisStateStore {
	return &RedisStateStore{rdb: rdb}
}

// Generate creates a new random state token, stores it in Redis, and returns it.
// The token is 16 random bytes encoded as a 32-character hex string.
//
// The value stored in Redis is the client_id, so we can recover it on callback.
func (s *RedisStateStore) Generate(ctx context.Context, clientID string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate oauth state: %w", err)
	}
	state := hex.EncodeToString(b)

	key := statePrefix + state
	if err := s.rdb.Set(ctx, key, clientID, stateTTL).Err(); err != nil {
		return "", fmt.Errorf("store oauth state: %w", err)
	}

	return state, nil
}

// Consume validates and deletes the state token in a single atomic operation.
// Returns the client_id that was stored with the state.
//
// Uses Redis GETDEL for atomicity — the token can only be used once.
// This prevents replay attacks where an attacker captures the callback URL.
func (s *RedisStateStore) Consume(ctx context.Context, state string) (clientID string, err error) {
	key := statePrefix + state
	clientID, err = s.rdb.GetDel(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("oauth state not found or expired")
		}
		return "", fmt.Errorf("consume oauth state: %w", err)
	}
	return clientID, nil
}
