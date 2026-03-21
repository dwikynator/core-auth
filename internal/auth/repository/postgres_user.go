package repository

import (
	"context"
	"errors"

	"github.com/dwikynator/core-auth/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgreSQL unique-violation error code (SQLSTATE 23505).
const pgUniqueViolation = "23505"

type postgresUserRepo struct {
	db *pgxpool.Pool
}

// NewPostgresUserRepo returns a UserRepository backed by pgx.
func NewPostgresUserRepo(db *pgxpool.Pool) auth.UserRepository {
	return &postgresUserRepo{db: db}
}

func (r *postgresUserRepo) Create(ctx context.Context, u *auth.User) error {
	const query = `
		INSERT INTO users (email, username, phone, password_hash, role, status)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at
	`

	err := r.db.QueryRow(ctx, query,
		u.Email,
		u.Username,
		u.Phone,
		u.PasswordHash,
		u.Role,
		u.Status,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return auth.ErrUserAlreadyExists
		}
		return err
	}
	return nil
}

func (r *postgresUserRepo) FindByLogin(ctx context.Context, identifier string) (*auth.User, error) {
	const query = `
		SELECT id, email, username, phone, password_hash,
		       role, status, email_verified_at, phone_verified_at,
		       created_at, updated_at
		FROM   users
		WHERE  deleted_at IS NULL
		  AND  (email = $1 OR LOWER(username) = LOWER($1) OR phone = $1)
		LIMIT  1
	`

	u := &auth.User{}
	err := r.db.QueryRow(ctx, query, identifier).Scan(
		&u.ID,
		&u.Email,
		&u.Username,
		&u.Phone,
		&u.PasswordHash,
		&u.Role,
		&u.Status,
		&u.EmailVerifiedAt,
		&u.PhoneVerifiedAt,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrUserNotFound
		}
		return nil, err
	}
	return u, nil
}
