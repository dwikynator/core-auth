package repository

import (
	"context"
	"errors"

	"github.com/dwikynator/core-auth/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresUserProviderRepo struct {
	db *pgxpool.Pool
}

// NewPostgresUserProviderRepo creates a new UserProviderRepository backed by Postgres.
func NewPostgresUserProviderRepo(db *pgxpool.Pool) auth.UserProviderRepository {
	return &postgresUserProviderRepo{db: db}
}

func isDuplicateKeyError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (r *postgresUserProviderRepo) Create(ctx context.Context, up *auth.UserProvider) error {
	const query = `
		INSERT INTO user_providers (user_id, provider, provider_user_id, provider_email)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`

	err := r.db.QueryRow(ctx, query,
		up.UserID,
		up.Provider,
		up.ProviderUserID,
		up.ProviderEmail,
	).Scan(&up.ID, &up.CreatedAt)
	if err != nil {
		// The UNIQUE(provider, provider_user_id) constraint will raise a duplicate key error.
		if isDuplicateKeyError(err) {
			return auth.ErrProviderAlreadyLinked
		}
		return err
	}
	return nil
}

func (r *postgresUserProviderRepo) FindByProviderAndSubject(ctx context.Context, provider, providerUserID string) (*auth.UserProvider, error) {
	const query = `
		SELECT id, user_id, provider, provider_user_id, provider_email, created_at
		FROM   user_providers
		WHERE  provider = $1 AND provider_user_id = $2
	`

	up := &auth.UserProvider{}
	err := r.db.QueryRow(ctx, query, provider, providerUserID).Scan(
		&up.ID,
		&up.UserID,
		&up.Provider,
		&up.ProviderUserID,
		&up.ProviderEmail,
		&up.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrProviderNotLinked
		}
		return nil, err
	}
	return up, nil
}

func (r *postgresUserProviderRepo) FindByUserID(ctx context.Context, userID string) ([]*auth.UserProvider, error) {
	const query = `
		SELECT id, user_id, provider, provider_user_id, provider_email, created_at
		FROM   user_providers
		WHERE  user_id = $1
		ORDER BY created_at ASC
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []*auth.UserProvider
	for rows.Next() {
		up := &auth.UserProvider{}
		if err := rows.Scan(
			&up.ID,
			&up.UserID,
			&up.Provider,
			&up.ProviderUserID,
			&up.ProviderEmail,
			&up.CreatedAt,
		); err != nil {
			return nil, err
		}
		providers = append(providers, up)
	}
	return providers, rows.Err()
}

func (r *postgresUserProviderRepo) Delete(ctx context.Context, userID, provider string) error {
	const query = `
		DELETE FROM user_providers
		WHERE user_id = $1 AND provider = $2
	`
	tag, err := r.db.Exec(ctx, query, userID, provider)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrProviderNotLinked
	}
	return nil
}
func (r *postgresUserProviderRepo) CountByUserID(ctx context.Context, userID string) (int, error) {
	const query = `SELECT COUNT(*) FROM user_providers WHERE user_id = $1`
	var count int
	if err := r.db.QueryRow(ctx, query, userID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
