package database

import (
	"context"
	"fmt"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}

	// Attach the OTel pgx tracer. Every query executed through this pool will
	// produce a child span named "pgx.query" (or "pgx.batch", "pgx.copy") under
	// the active trace from the request context.
	//
	// otelpgx.WithTrimSQLInSpanName() prevents the full SQL text from becoming
	// the span name (which can be very long and high-cardinality). The SQL is
	// still available as the "db.statement" attribute.
	config.ConnConfig.Tracer = otelpgx.NewTracer(
		otelpgx.WithTrimSQLInSpanName(),
	)

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return pool, nil
}
