package repository

import (
	"context"
	"errors"

	"github.com/dwikynator/core-auth/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresSessionRepo struct {
	db *pgxpool.Pool
}

// NewPostgresSessionRepo returns a SessionRepository backed by pgx.
func NewPostgresSessionRepo(db *pgxpool.Pool) auth.SessionRepository {
	return &postgresSessionRepo{db: db}
}

func (r *postgresSessionRepo) Create(ctx context.Context, s *auth.Session) error {
	const query = `
		INSERT INTO sessions (user_id, client_id, refresh_token_hash, ip_address, user_agent, expires_at)
		VALUES ($1, $2, $3, $4::inet, $5, $6)
		RETURNING id, created_at, last_used_at
	`

	return r.db.QueryRow(ctx, query,
		s.UserID,
		s.ClientID,
		s.RefreshTokenHash,
		s.IPAddress,
		s.UserAgent,
		s.ExpiresAt,
	).Scan(&s.ID, &s.CreatedAt, &s.LastUsedAt)
}

func (r *postgresSessionRepo) FindByRefreshTokenHash(ctx context.Context, hash string) (*auth.Session, error) {
	const query = `
		SELECT id, user_id, client_id, refresh_token_hash,
		       ip_address::text, user_agent, expires_at, revoked_at,
		       created_at, last_used_at
		FROM   sessions
		WHERE  refresh_token_hash = $1
		  AND  revoked_at IS NULL
	`

	s := &auth.Session{}
	err := r.db.QueryRow(ctx, query, hash).Scan(
		&s.ID,
		&s.UserID,
		&s.ClientID,
		&s.RefreshTokenHash,
		&s.IPAddress,
		&s.UserAgent,
		&s.ExpiresAt,
		&s.RevokedAt,
		&s.CreatedAt,
		&s.LastUsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrSessionNotFound
		}
		return nil, err
	}
	return s, nil
}

func (r *postgresSessionRepo) RotateRefreshToken(ctx context.Context, sessionID, newHash string) error {
	const query = `
		UPDATE sessions
		SET    refresh_token_hash = $2,
		       last_used_at = NOW(),
			   expires_at = NOW() + INTERVAL '30 days'
		WHERE  id = $1
		  AND  revoked_at IS NULL
	`

	tag, err := r.db.Exec(ctx, query, sessionID, newHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrSessionNotFound
	}
	return nil
}

func (r *postgresSessionRepo) Revoke(ctx context.Context, sessionID, userID string) error {
	const query = `
		UPDATE sessions
		SET    revoked_at = NOW()
		WHERE  id = $1
		  AND  user_id = $2
		  AND  revoked_at IS NULL
	`
	tag, err := r.db.Exec(ctx, query, sessionID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrSessionNotFound
	}
	return nil
}

func (r *postgresSessionRepo) RevokeAllForUser(ctx context.Context, userID string, exceptSessionID string) (int, error) {
	var query string
	var args []any

	if exceptSessionID != "" {
		query = `
			UPDATE sessions
			SET    revoked_at = NOW()
			WHERE  user_id = $1
			  AND  id != $2
			  AND  revoked_at IS NULL
		`
		args = []any{userID, exceptSessionID}
	} else {
		query = `
			UPDATE sessions
			SET    revoked_at = NOW()
			WHERE  user_id = $1
			  AND  revoked_at IS NULL
		`
		args = []any{userID}
	}

	tag, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (r *postgresSessionRepo) ListActiveByUser(ctx context.Context, userID string) ([]*auth.Session, error) {
	const query = `
		SELECT id, user_id, client_id, refresh_token_hash,
		       ip_address::text, user_agent, expires_at, revoked_at,
		       created_at, last_used_at
		FROM   sessions
		WHERE  user_id = $1
		  AND  revoked_at IS NULL
		  AND  expires_at > NOW()
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*auth.Session
	for rows.Next() {
		s := &auth.Session{}
		if err := rows.Scan(
			&s.ID,
			&s.UserID,
			&s.ClientID,
			&s.RefreshTokenHash,
			&s.IPAddress,
			&s.UserAgent,
			&s.ExpiresAt,
			&s.RevokedAt,
			&s.CreatedAt,
			&s.LastUsedAt,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}
