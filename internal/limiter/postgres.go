package limiter

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PG is a PostgreSQL-backed limiter implementation with sliding window and lockout.
type PG struct {
	pool     pgxQuerier
	window   time.Duration
	maxFails int
	blockFor time.Duration
}

type pgxQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// NewPG constructs a PostgreSQL-backed limiter.
func NewPG(pool *pgxpool.Pool, window time.Duration, maxFails int, blockFor time.Duration) *PG {
	return &PG{pool: pool, window: window, maxFails: maxFails, blockFor: blockFor}
}

// NewPGWithQuerier constructs a PostgreSQL-backed limiter.
func NewPGWithQuerier(q pgxQuerier, window time.Duration, maxFails int, blockFor time.Duration) *PG {
	return &PG{pool: q, window: window, maxFails: maxFails, blockFor: blockFor}
}

// HashIP returns a stable hash for an IP string to avoid storing raw addresses.
func HashIP(ip string) []byte {
	h := sha256.Sum256([]byte(ip))
	return h[:]
}

// Allow reports whether login is currently allowed and a retry-after duration.
func (l *PG) Allow(ctx context.Context, username string, ipHash []byte) (bool, time.Duration, error) {
	const q = `SELECT blocked_until, updated_at FROM auth_limiter WHERE username=$1 AND ip_hash=$2`
	var blockedUntil time.Time
	var updatedAt time.Time
	err := l.pool.QueryRow(ctx, q, username, ipHash).Scan(&blockedUntil, &updatedAt)
	switch err {
	case nil:
		now := time.Now()
		if blockedUntil.After(now) {
			return false, time.Until(blockedUntil), nil
		}

		return true, 0, nil
	case pgx.ErrNoRows:
		return true, 0, nil
	default:
		return false, 0, err
	}
}

// Success resets counters for (username, ip).
func (l *PG) Success(ctx context.Context, username string, ipHash []byte) error {
	const q = `
INSERT INTO auth_limiter (username, ip_hash, fail_count, blocked_until, updated_at)
VALUES ($1,$2,0,'epoch',now())
ON CONFLICT (username, ip_hash)
DO UPDATE SET fail_count=0, blocked_until='epoch', updated_at=now()`
	_, err := l.pool.Exec(ctx, q, username, ipHash)
	return err
}

// Failure records a failed attempt; may set a block until a future time.
func (l *PG) Failure(ctx context.Context, username string, ipHash []byte) (bool, time.Duration, error) {
	now := time.Now()

	const q = `
INSERT INTO auth_limiter (username, ip_hash, fail_count, blocked_until, updated_at)
VALUES ($1,$2,1,'epoch',now())
ON CONFLICT (username, ip_hash) DO UPDATE
SET
  fail_count = CASE WHEN EXCLUDED.updated_at - auth_limiter.updated_at > $3::interval THEN 1 ELSE auth_limiter.fail_count + 1 END,
  updated_at = now()
RETURNING fail_count`
	var fails int
	if err := l.pool.QueryRow(ctx, q, username, ipHash, l.window).Scan(&fails); err != nil {
		return false, 0, err
	}
	if fails >= l.maxFails {
		blockUntil := now.Add(l.blockFor)
		const upd = `UPDATE auth_limiter SET blocked_until=$3 WHERE username=$1 AND ip_hash=$2`
		if _, err := l.pool.Exec(ctx, upd, username, ipHash, blockUntil); err != nil {
			return false, 0, err
		}
		return true, l.blockFor, nil
	}
	return false, 0, nil
}
