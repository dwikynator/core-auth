package repository

import (
	"context"
	"time"

	"github.com/dwikynator/core-auth/internal/ratelimit"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresLoginAttemptsRepo struct {
	db *pgxpool.Pool
}

func NewPostgresLoginAttemptsRepo(db *pgxpool.Pool) ratelimit.LoginAttemptsRepository {
	return &postgresLoginAttemptsRepo{db: db}
}

func (r *postgresLoginAttemptsRepo) Record(ctx context.Context, attempt *ratelimit.LoginAttempt) error {
	const q = `
        INSERT INTO login_attempts (user_id, ip_address, attempted_at, success)
        VALUES ($1, $2, $3, $4)
    `
	var userID interface{}
	if attempt.UserID != "" {
		userID = attempt.UserID // passes the string
	}

	_, err := r.db.Exec(ctx, q,
		userID,
		attempt.IPAddress,
		attempt.AttemptedAt,
		attempt.Success,
	)
	return err
}

func (r *postgresLoginAttemptsRepo) CountFailed(ctx context.Context, userID string, since time.Time) (int, error) {
	const q = `
        SELECT COUNT(*) FROM login_attempts
        WHERE user_id = $1
          AND success = false
          AND attempted_at >= $2
    `
	var count int
	err := r.db.QueryRow(ctx, q, userID, since).Scan(&count)
	return count, err
}

func (r *postgresLoginAttemptsRepo) CountFailedByIP(ctx context.Context, ip string, since time.Time) (int, error) {
	const q = `
        SELECT COUNT(*) FROM login_attempts
        WHERE ip_address = $1::inet
          AND success = false
          AND attempted_at >= $2
    `
	var count int
	err := r.db.QueryRow(ctx, q, ip, since).Scan(&count)
	return count, err
}
