// Package repository defines storage interfaces implemented by concrete backends.
package repository

import (
	"context"

	"github.com/and161185/goph-keeper/internal/model"
	"github.com/gofrs/uuid/v5"
)

// UserRepository provides CRUD access for users and bootstrap data.
type UserRepository interface {
	// Create inserts a new user.
	Create(ctx context.Context, u *model.User) error
	// GetByID loads a user by ID.
	GetByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	// GetByUsername loads a user by username.
	GetByUsername(ctx context.Context, username string) (*model.User, error)
	// SetWrappedDEKIfEmpty stores wrapped DEK only if it is currently empty.
	SetWrappedDEKIfEmpty(ctx context.Context, id uuid.UUID, wrapped []byte) error
}
