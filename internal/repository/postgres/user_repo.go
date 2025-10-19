package postgres

import (
	"context"
	"errors"

	"github.com/and161185/goph-keeper/internal/errs"
	"github.com/and161185/goph-keeper/internal/model"
	"github.com/gofrs/uuid/v5"
)

// UserRepo implements UserRepository using PostgreSQL.
type UserRepo struct{ db *DB }

// NewUserRepo constructs a user repository.
func NewUserRepo(db *DB) *UserRepo { return &UserRepo{db: db} }

// Create inserts a new user row.
func (r *UserRepo) Create(ctx context.Context, u *model.User) error {
	const q = `
INSERT INTO users (id, username, pwd_hash, salt_auth, kek_salt, wrapped_dek)
VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.db.Pool.Exec(ctx, q, u.ID, u.Username, u.PwdHash, u.SaltAuth, u.KekSalt, u.WrappedDEK)
	if isUniqueViolation(err) {
		return errs.ErrVersionConflict // or define ErrAlreadyExists if нужно
	}
	return err
}

// GetByID selects a user by ID.
func (r *UserRepo) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	const q = `
SELECT id, username, pwd_hash, salt_auth, kek_salt, wrapped_dek, created_at
FROM users WHERE id=$1`
	row := r.db.Pool.QueryRow(ctx, q, id)
	var u model.User
	if err := row.Scan(&u.ID, &u.Username, &u.PwdHash, &u.SaltAuth, &u.KekSalt, &u.WrappedDEK, &u.CreatedAt); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		return nil, errs.ErrNotFound
	}
	return &u, nil
}

// GetByUsername selects a user by username.
func (r *UserRepo) GetByUsername(ctx context.Context, username string) (*model.User, error) {
	const q = `
SELECT id, username, pwd_hash, salt_auth, kek_salt, wrapped_dek, created_at
FROM users WHERE username=$1`
	row := r.db.Pool.QueryRow(ctx, q, username)
	var u model.User
	if err := row.Scan(&u.ID, &u.Username, &u.PwdHash, &u.SaltAuth, &u.KekSalt, &u.WrappedDEK, &u.CreatedAt); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		return nil, errs.ErrNotFound
	}
	return &u, nil
}

// SetWrappedDEKIfEmpty updates wrapped_dek only if currently empty.
func (r *UserRepo) SetWrappedDEKIfEmpty(ctx context.Context, id uuid.UUID, wrapped []byte) error {
	const q = `
UPDATE users
SET wrapped_dek = $2
WHERE id = $1 AND octet_length(wrapped_dek) = 0`
	tag, err := r.db.Pool.Exec(ctx, q, id, wrapped)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errs.ErrVersionConflict
	}
	return nil
}
