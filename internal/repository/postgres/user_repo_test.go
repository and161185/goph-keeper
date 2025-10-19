package postgres

import (
	"context"
	"testing"

	"github.com/and161185/goph-keeper/internal/errs"
	"github.com/and161185/goph-keeper/internal/model"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	pgxmock "github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/require"
)

func TestUserRepo_Create_OK_and_UniqueViolation(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewUserRepo(db)
	ctx := context.Background()
	u := &model.User{
		ID:         uuid.Must(uuid.NewV4()),
		Username:   "u",
		PwdHash:    []byte("h"),
		SaltAuth:   []byte("s"),
		KekSalt:    []byte("k"),
		WrappedDEK: []byte("w"),
	}

	// OK
	mock.ExpectExec(`INSERT INTO users \(id, username, pwd_hash, salt_auth, kek_salt, wrapped_dek\) VALUES \(\$1, \$2, \$3, \$4, \$5, \$6\)`).
		WithArgs(u.ID, u.Username, u.PwdHash, u.SaltAuth, u.KekSalt, u.WrappedDEK).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	require.NoError(t, r.Create(ctx, u))

	// Unique violation
	mock.ExpectExec(`INSERT INTO users \(id, username, pwd_hash, salt_auth, kek_salt, wrapped_dek\) VALUES \(\$1, \$2, \$3, \$4, \$5, \$6\)`).
		WithArgs(u.ID, u.Username, u.PwdHash, u.SaltAuth, u.KekSalt, u.WrappedDEK).
		WillReturnError(&pgconn.PgError{Code: "23505"})
	err := r.Create(ctx, u)
	require.ErrorIs(t, err, errs.ErrVersionConflict)
}

func TestUserRepo_GetByID(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewUserRepo(db)
	ctx := context.Background()
	id := uuid.Must(uuid.NewV4())

	mock.ExpectQuery(`SELECT id, username, pwd_hash, salt_auth, kek_salt, wrapped_dek, created_at FROM users WHERE id=\$1`).
		WithArgs(id).
		WillReturnRows(pgxmock.NewRows([]string{"id", "username", "pwd_hash", "salt_auth", "kek_salt", "wrapped_dek", "created_at"}).
			AddRow(id, "u", []byte("h"), []byte("s"), []byte("k"), []byte("w"), pgxmock.AnyArg()))
	u, err := r.GetByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, id, u.ID)

	mock.ExpectQuery(`SELECT id, username, pwd_hash, salt_auth, kek_salt, wrapped_dek, created_at FROM users WHERE id=\$1`).
		WithArgs(id).
		WillReturnError(pgx.ErrNoRows)
	_, err = r.GetByID(ctx, id)
	require.ErrorIs(t, err, errs.ErrNotFound)
}

func TestUserRepo_GetByUsername(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewUserRepo(db)
	ctx := context.Background()
	name := "u2"
	id := uuid.Must(uuid.NewV4())

	mock.ExpectQuery(`SELECT id, username, pwd_hash, salt_auth, kek_salt, wrapped_dek, created_at FROM users WHERE username=\$1`).
		WithArgs(name).
		WillReturnRows(pgxmock.NewRows([]string{"id", "username", "pwd_hash", "salt_auth", "kek_salt", "wrapped_dek", "created_at"}).
			AddRow(id, name, []byte("h"), []byte("s"), []byte("k"), []byte("w"), pgxmock.AnyArg()))
	u, err := r.GetByUsername(ctx, name)
	require.NoError(t, err)
	require.Equal(t, name, u.Username)

	mock.ExpectQuery(`SELECT id, username, pwd_hash, salt_auth, kek_salt, wrapped_dek, created_at FROM users WHERE username=\$1`).
		WithArgs(name).
		WillReturnError(pgx.ErrNoRows)
	_, err = r.GetByUsername(ctx, name)
	require.ErrorIs(t, err, errs.ErrNotFound)
}

func TestUserRepo_SetWrappedDEKIfEmpty(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewUserRepo(db)
	ctx := context.Background()
	id := uuid.Must(uuid.NewV4())
	w := []byte("wrapped")

	mock.ExpectExec(`UPDATE users SET wrapped_dek = \$2 WHERE id = \$1 AND octet_length\(wrapped_dek\) = 0`).
		WithArgs(id, w).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	require.NoError(t, r.SetWrappedDEKIfEmpty(ctx, id, w))

	mock.ExpectExec(`UPDATE users SET wrapped_dek = \$2 WHERE id = \$1 AND octet_length\(wrapped_dek\) = 0`).
		WithArgs(id, w).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	err := r.SetWrappedDEKIfEmpty(ctx, id, w)
	require.ErrorIs(t, err, errs.ErrVersionConflict)
}
