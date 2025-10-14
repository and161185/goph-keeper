package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/and161185/goph-keeper/internal/errs"
	"github.com/and161185/goph-keeper/internal/model"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// ItemRepo implements ItemRepository using PostgreSQL.
type ItemRepo struct{ db *DB }

// NewItemRepo constructs an item repository.
func NewItemRepo(db *DB) *ItemRepo { return &ItemRepo{db: db} }

// UpsertBatch inserts/updates items with optimistic concurrency and returns new versions.
func (r *ItemRepo) UpsertBatch(
	ctx context.Context, userID uuid.UUID, ups []model.UpsertItem,
) (results []model.ItemVersion, err error) {
	tx, err := r.db.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
			return
		}
		if e := tx.Commit(ctx); e != nil {
			err = e
		}
	}()

	results = make([]model.ItemVersion, 0, len(ups))
	const sel = `SELECT ver FROM items WHERE id=$1 AND user_id=$2 FOR UPDATE`
	const ins = `INSERT INTO items (id, user_id, blob_enc, ver, deleted) VALUES ($1,$2,$3,$4,false)`
	const upd = `UPDATE items SET blob_enc=$3, ver=$4, deleted=false WHERE id=$1 AND user_id=$2`

	for i, up := range ups {
		var curVer int64
		row := tx.QueryRow(ctx, sel, up.ID, userID)
		scanErr := row.Scan(&curVer)
		switch {
		case scanErr == nil:
			if curVer != up.BaseVer {
				return nil, fmt.Errorf("item[%d]: %w", i, errs.ErrVersionConflict)
			}
			newVer := curVer + 1
			if _, err = tx.Exec(ctx, upd, up.ID, userID, []byte(up.BlobEnc), newVer); err != nil {
				return nil, err
			}
			results = append(results, model.ItemVersion{ID: up.ID, NewVer: newVer})
		case errors.Is(scanErr, pgx.ErrNoRows):
			if up.BaseVer != 0 {
				return nil, fmt.Errorf("item[%d]: %w", i, errs.ErrVersionConflict)
			}
			if _, err = tx.Exec(ctx, ins, up.ID, userID, []byte(up.BlobEnc), int64(1)); err != nil {
				return nil, err
			}
			results = append(results, model.ItemVersion{ID: up.ID, NewVer: 1})
		default:
			return nil, scanErr
		}
	}
	return results, nil
}

// Delete marks an item as deleted (tombstone) with version increment.
func (r *ItemRepo) Delete(
	ctx context.Context, userID, itemID uuid.UUID, baseVer int64,
) (ver model.ItemVersion, err error) {
	tx, err := r.db.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return model.ItemVersion{}, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
			return
		}
		if e := tx.Commit(ctx); e != nil {
			err = e
		}
	}()

	const sel = `SELECT ver FROM items WHERE id=$1 AND user_id=$2 FOR UPDATE`
	const upd = `UPDATE items SET deleted=true, ver=$3 WHERE id=$1 AND user_id=$2`

	var curVer int64
	if err = tx.QueryRow(ctx, sel, itemID, userID).Scan(&curVer); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.ItemVersion{}, errs.ErrNotFound
		}
		return model.ItemVersion{}, err
	}
	if curVer != baseVer {
		return model.ItemVersion{}, errs.ErrVersionConflict
	}
	newVer := curVer + 1
	if _, err = tx.Exec(ctx, upd, itemID, userID, newVer); err != nil {
		return model.ItemVersion{}, err
	}
	return model.ItemVersion{ID: itemID, NewVer: newVer}, nil
}

// GetChangesSince returns changes strictly after the provided version.
func (r *ItemRepo) GetChangesSince(ctx context.Context, userID uuid.UUID, sinceVer int64) ([]model.Change, error) {
	const q = `
SELECT id, ver, deleted, updated_at, blob_enc
FROM items
WHERE user_id=$1 AND ver>$2
ORDER BY ver ASC`
	rows, err := r.db.Pool.Query(ctx, q, userID, sinceVer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Change
	for rows.Next() {
		var (
			id   uuid.UUID
			ver  int64
			del  bool
			ts   time.Time
			blob []byte
		)
		if err = rows.Scan(&id, &ver, &del, &ts, &blob); err != nil {
			return nil, err
		}
		ch := model.Change{ID: id, Ver: ver, Deleted: del, UpdatedAt: ts}
		if !del {
			ch.BlobEnc = model.EncryptedBlob(blob)
		}
		out = append(out, ch)
	}
	return out, rows.Err()
}

// GetItem returns a single item by id.
func (r *ItemRepo) GetItem(ctx context.Context, userID, itemID uuid.UUID) (*model.Item, error) {
	const q = `
SELECT id, user_id, blob_enc, ver, deleted, updated_at
FROM items WHERE user_id=$1 AND id=$2`
	row := r.db.Pool.QueryRow(ctx, q, userID, itemID)
	var it model.Item
	if err := row.Scan(&it.ID, &it.UserID, &it.BlobEnc, &it.Ver, &it.Deleted, &it.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	return &it, nil
}

// GetMaxVersion returns the current maximum version for a user.
func (r *ItemRepo) GetMaxVersion(ctx context.Context, userID uuid.UUID) (int64, error) {
	const q = `SELECT COALESCE(MAX(ver),0) FROM items WHERE user_id=$1`
	var v int64
	if err := r.db.Pool.QueryRow(ctx, q, userID).Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}
