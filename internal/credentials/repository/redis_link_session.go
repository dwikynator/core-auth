package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dwikynator/core-auth/internal/auth"
	domain "github.com/dwikynator/core-auth/internal/credentials/domain"
	"github.com/redis/go-redis/v9"
)

// linkSessionTTL is the maximum time the user has to complete the linking flow
// after clicking "link account" on the client side.
// 10 minutes is generous; most users complete this in seconds.
const linkSessionTTL = 10 * time.Minute

type redisLinkSessionStore struct {
	rdb *redis.Client
}

// NewRedisLinkSessionStore returns a LinkSessionStore backed by Redis.
func NewRedisLinkSessionStore(rdb *redis.Client) domain.LinkSessionStore {
	return &redisLinkSessionStore{rdb: rdb}
}
func linkSessionKey(hash string) string {
	return "oauth:link:" + hash
}

// Create generates a random token, stores the session data under its SHA-256 hash, and
// returns the raw token to the caller. Mirrors the MFA session store pattern exactly.
func (s *redisLinkSessionStore) Create(ctx context.Context, data *domain.LinkSessionData) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate link session token: %w", err)
	}
	rawToken := hex.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(rawToken))
	hashHex := hex.EncodeToString(hash[:])
	payload, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal link session: %w", err)
	}
	if err := s.rdb.Set(ctx, linkSessionKey(hashHex), payload, linkSessionTTL).Err(); err != nil {
		return "", fmt.Errorf("store link session: %w", err)
	}
	return rawToken, nil
}

// Consume retrieves and deletes the session atomically (single-use) using a Redis pipeline.
// A pipeline GET + DEL is used instead of GETDEL because it allows inspecting the
// GET result before the pipeline commits; both commands execute atomically on the server.
func (s *redisLinkSessionStore) Consume(ctx context.Context, rawToken string) (*domain.LinkSessionData, error) {
	hash := sha256.Sum256([]byte(rawToken))
	hashHex := hex.EncodeToString(hash[:])
	key := linkSessionKey(hashHex)
	pipe := s.rdb.Pipeline()
	getCmd := pipe.Get(ctx, key)
	pipe.Del(ctx, key)
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, auth.ErrLinkSessionExpired
	}
	payload, err := getCmd.Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, auth.ErrLinkSessionExpired
		}
		return nil, auth.ErrLinkSessionExpired
	}
	var data domain.LinkSessionData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("unmarshal link session: %w", err)
	}
	return &data, nil
}
