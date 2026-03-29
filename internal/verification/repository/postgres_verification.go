package repository

import (
	"context"
	"errors"

	errs "github.com/dwikynator/core-auth/internal/libs/errors"
	"github.com/dwikynator/core-auth/internal/verification"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresVerificationRepo struct {
	db *pgxpool.Pool
}

// NewPostgresVerificationRepo returns a verification.Repository backed by pgx.
func NewPostgresVerificationRepo(db *pgxpool.Pool) verification.Repository {
	return &postgresVerificationRepo{db: db}
}

func (r *postgresVerificationRepo) Create(ctx context.Context, t *verification.VerificationToken) error {
	const query = `
		INSERT INTO verification_tokens (user_id, token_hash, type, status, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at
	`
	t.Status = verification.StatusActive
	return r.db.QueryRow(ctx, query,
		t.UserID,
		t.TokenHash,
		string(t.Type),
		string(t.Status),
		t.ExpiresAt,
	).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
}

func (r *postgresVerificationRepo) FindByHashAndType(
	ctx context.Context,
	tokenHash string,
	tokenType verification.TokenType,
) (*verification.VerificationToken, error) {
	const query = `
		SELECT id, user_id, token_hash, type, status, expires_at, created_at, updated_at
		FROM   verification_tokens
		WHERE  token_hash = $1
		  AND  type = $2
		  AND  status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`

	t := &verification.VerificationToken{}
	var tokenTypeStr, statusStr string

	err := r.db.QueryRow(ctx, query, tokenHash, string(tokenType)).Scan(
		&t.ID,
		&t.UserID,
		&t.TokenHash,
		&tokenTypeStr,
		&statusStr,
		&t.ExpiresAt,
		&t.CreatedAt,
		&t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrTokenNotFound
		}
		return nil, err
	}

	t.Type = verification.TokenType(tokenTypeStr)
	t.Status = verification.TokenStatus(statusStr)
	return t, nil
}

func (r *postgresVerificationRepo) MarkUsed(ctx context.Context, tokenID string) error {
	const query = `
		UPDATE verification_tokens
		SET    status = 'used', updated_at = NOW()
		WHERE  id = $1
		  AND  status = 'active'
	`

	tag, err := r.db.Exec(ctx, query, tokenID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errs.ErrTokenNotFound
	}
	return nil
}

func (r *postgresVerificationRepo) InvalidateAllForUser(
	ctx context.Context,
	userID string,
	tokenType verification.TokenType,
) error {
	const query = `
		UPDATE verification_tokens
		SET    status = 'invalidated', updated_at = NOW()
		WHERE  user_id = $1
		  AND  type = $2
		  AND  status = 'active'
	`

	_, err := r.db.Exec(ctx, query, userID, string(tokenType))
	return err
}
