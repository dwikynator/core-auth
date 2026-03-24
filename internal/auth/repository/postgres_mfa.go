package repository

import (
	"context"
	"errors"

	"github.com/dwikynator/core-auth/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresMFARepo struct {
	db *pgxpool.Pool
}

// NewPostgresMFARepo returns an MFACredentialRepository backed by pgx.
func NewPostgresMFARepo(db *pgxpool.Pool) auth.MFACredentialRepository {
	return &postgresMFARepo{db: db}
}

func (r *postgresMFARepo) Create(ctx context.Context, cred *auth.MFACredential) error {
	const query = `
		INSERT INTO mfa_credentials (user_id, type, secret_encrypted)
		VALUES ($1, $2, $3)
		RETURNING id, created_at
	`

	err := r.db.QueryRow(ctx, query,
		cred.UserID,
		cred.Type,
		cred.SecretEncrypted,
	).Scan(&cred.ID, &cred.CreatedAt)

	if err != nil {
		// Check for unique constraint violation (one MFA per type per user).
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return auth.ErrMFAAlreadyEnrolled
		}
		return err
	}
	return nil
}

func (r *postgresMFARepo) FindVerifiedByUserID(ctx context.Context, userID string) (*auth.MFACredential, error) {
	const query = `
		SELECT id, user_id, type, secret_encrypted, verified, created_at, last_used_at
		FROM   mfa_credentials
		WHERE  user_id = $1
		  AND  verified = true
		LIMIT  1
	`

	cred := &auth.MFACredential{}
	err := r.db.QueryRow(ctx, query, userID).Scan(
		&cred.ID,
		&cred.UserID,
		&cred.Type,
		&cred.SecretEncrypted,
		&cred.Verified,
		&cred.CreatedAt,
		&cred.LastUsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrMFANotEnrolled
		}
		return nil, err
	}
	return cred, nil
}

func (r *postgresMFARepo) FindByUserID(ctx context.Context, userID string) (*auth.MFACredential, error) {
	const query = `
		SELECT id, user_id, type, secret_encrypted, verified, created_at, last_used_at
		FROM   mfa_credentials
		WHERE  user_id = $1
		LIMIT  1
	`

	cred := &auth.MFACredential{}
	err := r.db.QueryRow(ctx, query, userID).Scan(
		&cred.ID,
		&cred.UserID,
		&cred.Type,
		&cred.SecretEncrypted,
		&cred.Verified,
		&cred.CreatedAt,
		&cred.LastUsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrMFANotEnrolled
		}
		return nil, err
	}
	return cred, nil
}

func (r *postgresMFARepo) MarkVerified(ctx context.Context, credID string) error {
	const query = `
		UPDATE mfa_credentials
		SET    verified = true, last_used_at = NOW()
		WHERE  id = $1
	`
	_, err := r.db.Exec(ctx, query, credID)
	return err
}

func (r *postgresMFARepo) UpdateLastUsed(ctx context.Context, credID string) error {
	const query = `
		UPDATE mfa_credentials
		SET    last_used_at = NOW()
		WHERE  id = $1
	`
	_, err := r.db.Exec(ctx, query, credID)
	return err
}

func (r *postgresMFARepo) DeleteByUserID(ctx context.Context, userID string) error {
	const query = `
		DELETE FROM mfa_credentials
		WHERE  user_id = $1
	`
	_, err := r.db.Exec(ctx, query, userID)
	return err
}
