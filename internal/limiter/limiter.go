// Package limiter defines interfaces and implementations for login rate limiting.
package limiter

import (
	"context"
	"time"
)

// Limiter controls login attempts and temporary lockouts.
type Limiter interface {
	// Allow reports whether login is currently allowed and optional retry-after.
	Allow(ctx context.Context, username string, ipHash []byte) (bool, time.Duration, error)
	// Success resets counters after a successful login.
	Success(ctx context.Context, username string, ipHash []byte) error
	// Failure records a failed attempt; may place a temporary block.
	Failure(ctx context.Context, username string, ipHash []byte) (bool, time.Duration, error)
}
