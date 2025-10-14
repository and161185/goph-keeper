package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/gofrs/uuid/v5"

	"github.com/and161185/goph-keeper/internal/model"
	"github.com/and161185/goph-keeper/internal/repository"
)

// ItemService defines operations over encrypted items with versioning.
type ItemService interface {
	// Upsert creates or updates items atomically and returns new versions.
	Upsert(ctx context.Context, userID uuid.UUID, ups []model.UpsertItem) ([]model.ItemVersion, error)
	// Delete sets tombstone on an item and returns new version.
	Delete(ctx context.Context, userID, id uuid.UUID, baseVer int64) (model.ItemVersion, error)
	// GetChanges returns changes since provided version for delta sync.
	GetChanges(ctx context.Context, userID uuid.UUID, sinceVer int64) ([]model.Change, error)
	// GetOne returns a single item by ID.
	GetOne(ctx context.Context, userID, id uuid.UUID) (*model.Item, error)
}

type ItemServiceImpl struct {
	repo     repository.ItemRepository
	maxBatch int
}

// NewItemService constructs ItemService with batch limits.
func NewItemService(repo repository.ItemRepository, maxBatch int) *ItemServiceImpl {
	if maxBatch <= 0 {
		maxBatch = 1000
	}
	return &ItemServiceImpl{repo: repo, maxBatch: maxBatch}
}

// Upsert validates input and delegates atomic batch upsert to repository.
// Validation rules:
// - len(ups) > 0
// - each ID != uuid.Nil
// - BaseVer >= 0
// - BlobEnc not empty
func (s *ItemServiceImpl) Upsert(ctx context.Context, userID uuid.UUID, ups []model.UpsertItem) ([]model.ItemVersion, error) {
	if userID == uuid.Nil {
		return nil, errors.New("validation: empty userID")
	}
	if len(ups) == 0 {
		return []model.ItemVersion{}, nil
	}
	if s.maxBatch > 0 && len(ups) > s.maxBatch {
		return nil, fmt.Errorf("validation: batch too large (%d > %d)", len(ups), s.maxBatch)
	}
	for i := range ups {
		if ups[i].ID == uuid.Nil {
			return nil, fmt.Errorf("validation: item[%d] empty id", i)
		}
		if ups[i].BaseVer < 0 {
			return nil, fmt.Errorf("validation: item[%d] negative base_ver", i)
		}
		if len(ups[i].BlobEnc) == 0 {
			return nil, fmt.Errorf("validation: item[%d] empty blob", i)
		}
	}
	return s.repo.UpsertBatch(ctx, userID, ups)
}

// Delete applies tombstone with optimistic concurrency (ver++).
func (s *ItemServiceImpl) Delete(ctx context.Context, userID, id uuid.UUID, baseVer int64) (model.ItemVersion, error) {
	if userID == uuid.Nil || id == uuid.Nil {
		return model.ItemVersion{}, errors.New("validation: empty userID/id")
	}
	if baseVer < 0 {
		return model.ItemVersion{}, errors.New("validation: negative base_ver")
	}
	return s.repo.Delete(ctx, userID, id, baseVer)
}

// GetChanges returns all changes with ver > sinceVer ordered by ver ASC.
func (s *ItemServiceImpl) GetChanges(ctx context.Context, userID uuid.UUID, sinceVer int64) ([]model.Change, error) {
	if userID == uuid.Nil {
		return nil, errors.New("validation: empty userID")
	}
	if sinceVer < 0 {
		return nil, errors.New("validation: negative since_ver")
	}
	return s.repo.GetChangesSince(ctx, userID, sinceVer)
}

// GetOne fetches single item by id.
func (s *ItemServiceImpl) GetOne(ctx context.Context, userID, id uuid.UUID) (*model.Item, error) {
	if userID == uuid.Nil || id == uuid.Nil {
		return nil, errors.New("validation: empty userID/id")
	}
	return s.repo.GetItem(ctx, userID, id)
}
