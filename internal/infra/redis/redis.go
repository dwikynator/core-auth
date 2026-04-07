package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/extra/redisotel/v9"
	redis "github.com/redis/go-redis/v9"
)

func NewClient(ctx context.Context, host, port, password string) (*redis.Client, error) {
	opts := &redis.Options{
		Addr:     fmt.Sprintf("%s:%s", host, port),
		Password: password, // no password set if empty
		DB:       0,        // use default DB
	}

	client := redis.NewClient(opts)

	// Instrument all Redis commands with OTel tracing.
	// Each command becomes a child span under the active trace from ctx.
	// The span includes the Redis command name (e.g., "GET", "SET", "EXPIRE").
	if err := redisotel.InstrumentTracing(client); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("instrument redis tracing: %w", err)
	}

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return client, nil
}
