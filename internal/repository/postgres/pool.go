// Package postgres contains PostgreSQL implementations of repository interfaces.
package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgxPool is a minimal abstraction over a Postgres connection pool,
// used by repositories. It is implemented by *pgxpool.Pool and pgxmock.PgxPoolIface.
type PgxPool interface {
	// Exec executes a SQL command and returns the command tag.
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	// Query executes a SELECT and returns a rows iterator.
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	// QueryRow executes a query expected to return at most one row.
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	// BeginTx starts a transaction with the provided options.
	BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
	// Close shuts down the pool and frees resources.
	Close()
}

// DB wraps pgxpool.Pool to satisfy repository constructors and allow testing.
type DB struct{ Pool PgxPool }

// New creates a new connection pool for the given DSN.
func New(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &DB{Pool: pool}, nil
}

// Close closes the underlying pool.
func (db *DB) Close() { db.Pool.Close() }

// isUniqueViolation reports whether the error is a unique constraint violation.
func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}
