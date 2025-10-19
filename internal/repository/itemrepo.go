package repository

import (
	"context"

	"github.com/and161185/goph-keeper/internal/model"
	"github.com/gofrs/uuid/v5"
)

// ItemRepository provides versioned access to encrypted items.
type ItemRepository interface {
	// UpsertBatch inserts or updates items using optimistic concurrency.
	UpsertBatch(ctx context.Context, userID uuid.UUID, items []model.UpsertItem) ([]model.ItemVersion, error)

	// Delete sets tombstone on item (ver++) with base version check.
	Delete(ctx context.Context, userID, itemID uuid.UUID, baseVer int64) (model.ItemVersion, error)

	// GetChangesSince returns all changes with version greater than sinceVer.
	GetChangesSince(ctx context.Context, userID uuid.UUID, sinceVer int64) ([]model.Change, error)

	// GetItem returns a single item by ID.
	GetItem(ctx context.Context, userID, itemID uuid.UUID) (*model.Item, error)

	// GetMaxVersion returns the latest version for a user.
	GetMaxVersion(ctx context.Context, userID uuid.UUID) (int64, error)
}
