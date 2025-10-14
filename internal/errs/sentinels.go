// Package errs contains sentinel errors used across layers for stable error mapping.
package errs

import "errors"

// Common sentinels across repo/service layers.
var (
	// ErrNotFound indicates the requested entity does not exist.
	ErrNotFound = errors.New("not found")

	// ErrVersionConflict indicates optimistic concurrency failure (base version mismatch).
	ErrVersionConflict = errors.New("version conflict")

	// ErrUnauthorized indicates failed authentication/authorization.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrRateLimited indicates temporary login lock due to rate limiting.
	ErrRateLimited = errors.New("rate limited")

	// ErrAlreadyExists indicates a unique constraint violation (e.g., username taken).
	ErrAlreadyExists = errors.New("already exists")
)
