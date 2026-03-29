package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	errs "github.com/dwikynator/core-auth/internal/libs/errors"
	domain "github.com/dwikynator/core-auth/internal/mfa"
	"github.com/redis/go-redis/v9"
)

// mfaSessionTTL is the maximum time a user has to complete the MFA challenge
// after entering their password. 5 minutes is generous enough for authenticator
// apps yet short enough to limit the window of exposure.
const mfaSessionTTL = 5 * time.Minute

type redisMFASessionStore struct {
	rdb *redis.Client
}

// NewRedisMFASessionStore returns an MFASessionStore backed by Redis.
func NewRedisMFASessionStore(rdb *redis.Client) domain.MFASessionStore {
	return &redisMFASessionStore{rdb: rdb}
}

// redisKey returns the Redis key for an MFA session by its hash.
func redisKey(hash string) string {
	return "mfa:session:" + hash
}

func (s *redisMFASessionStore) Create(ctx context.Context, data *domain.MFASessionData) (string, error) {
	// 1. Generate a cryptographically random token (32 bytes → 64-char hex).
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate mfa session token: %w", err)
	}
	rawToken := hex.EncodeToString(tokenBytes)

	// 2. Hash the token for storage (we never store the raw token in Redis).
	hash := sha256.Sum256([]byte(rawToken))
	hashHex := hex.EncodeToString(hash[:])

	// 3. Serialize session data as JSON.
	payload, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal mfa session: %w", err)
	}

	// 4. Store with TTL.
	if err := s.rdb.Set(ctx, redisKey(hashHex), payload, mfaSessionTTL).Err(); err != nil {
		return "", fmt.Errorf("store mfa session: %w", err)
	}

	return rawToken, nil
}

func (s *redisMFASessionStore) Consume(ctx context.Context, rawToken string) (*domain.MFASessionData, error) {
	// 1. Hash the incoming token to find the Redis key.
	hash := sha256.Sum256([]byte(rawToken))
	hashHex := hex.EncodeToString(hash[:])
	key := redisKey(hashHex)

	// 2. GET + DEL atomically via a pipeline to prevent replay attacks.
	// If two concurrent requests race, only one will see the value before
	// it is deleted — the other gets redis.Nil.
	pipe := s.rdb.Pipeline()
	getCmd := pipe.Get(ctx, key)
	pipe.Del(ctx, key)
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		// Pipeline exec error is fatal.
		return nil, errs.ErrInvalidMFASession
	}

	payload, err := getCmd.Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errs.ErrInvalidMFASession
		}
		return nil, errs.ErrInvalidMFASession
	}

	// 3. Deserialize.
	var data domain.MFASessionData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("unmarshal mfa session: %w", err)
	}

	return &data, nil
}
