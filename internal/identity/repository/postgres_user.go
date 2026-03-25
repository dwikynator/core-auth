package repository

import (
	"context"
	"errors"

	"github.com/dwikynator/core-auth/internal/auth"
	domain "github.com/dwikynator/core-auth/internal/identity/domain"
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
func NewPostgresUserRepo(db *pgxpool.Pool) domain.UserRepository {
	return &postgresUserRepo{db: db}
}

func (r *postgresUserRepo) Create(ctx context.Context, u *domain.User) error {
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

func (r *postgresUserRepo) FindByLogin(ctx context.Context, identifier string) (*domain.User, error) {
	const query = `
		SELECT id, email, username, phone, password_hash,
		       role, status, email_verified_at, phone_verified_at,
		       created_at, updated_at
		FROM   users
		WHERE  deleted_at IS NULL
		  AND  (email = $1 OR LOWER(username) = LOWER($1) OR phone = $1)
		LIMIT  1
	`

	u := &domain.User{}
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

func (r *postgresUserRepo) FindByID(ctx context.Context, userID string) (*domain.User, error) {
	const query = `
		SELECT id, email, username, phone, password_hash,
		       role, status, email_verified_at, phone_verified_at,
		       created_at, updated_at
		FROM   users
		WHERE  id = $1
		  AND  deleted_at IS NULL
	`

	u := &domain.User{}
	err := r.db.QueryRow(ctx, query, userID).Scan(
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

func (r *postgresUserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	const query = `
		SELECT id, email, username, phone, password_hash,
		       role, status, email_verified_at, phone_verified_at,
		       created_at, updated_at
		FROM   users
		WHERE  email = $1
		  AND  deleted_at IS NULL
	`

	u := &domain.User{}
	err := r.db.QueryRow(ctx, query, email).Scan(
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

func (r *postgresUserRepo) VerifyEmailAndActivate(ctx context.Context, userID string) error {
	const query = `
		UPDATE users
		SET    email_verified_at = COALESCE(email_verified_at, NOW()),
		       status = CASE WHEN status = 'unverified' THEN 'active' ELSE status END,
		       updated_at = NOW()
		WHERE  id = $1 AND deleted_at IS NULL
	`

	tag, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

func (r *postgresUserRepo) UpdateStatus(ctx context.Context, userID string, status string) error {
	const query = `
		UPDATE users
		SET    status = $2, updated_at = NOW()
		WHERE  id = $1
		  AND  deleted_at IS NULL
	`

	tag, err := r.db.Exec(ctx, query, userID, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

func (r *postgresUserRepo) SoftDelete(ctx context.Context, userID string) error {
	const query = `
		UPDATE users
		SET    status = 'deleted',
		       deleted_at = NOW(),
		       updated_at = NOW()
		WHERE  id = $1
		  AND  deleted_at IS NULL
	`

	tag, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

func (r *postgresUserRepo) UpdatePhoneVerified(ctx context.Context, userID string) error {
	const query = `
		UPDATE users
		SET    phone_verified_at = NOW(),
		       updated_at = NOW()
		WHERE  id = $1
		  AND  phone_verified_at IS NULL
	`
	result, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return auth.ErrPhoneAlreadyVerified
	}
	return nil
}

func (r *postgresUserRepo) UpdatePasswordHash(ctx context.Context, userID string, newHash string) error {
	const query = `
		UPDATE users
		SET    password_hash = $2, updated_at = NOW()
		WHERE  id = $1
		  AND  deleted_at IS NULL
	`

	tag, err := r.db.Exec(ctx, query, userID, newHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}
