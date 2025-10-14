package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/and161185/goph-keeper/internal/errs"
	"github.com/and161185/goph-keeper/internal/model"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	pgxmock "github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/require"
)

func newDB(t *testing.T) (*DB, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	return &DB{Pool: mock}, mock
}

func TestItemRepo_UpsertBatch_Update_OK(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)

	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	itemID := uuid.Must(uuid.NewV4())
	base := int64(5)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(itemID, userID).
		WillReturnRows(pgxmock.NewRows([]string{"ver"}).AddRow(base))
	mock.ExpectExec(`UPDATE items SET blob_enc=\$3, ver=\$4, deleted=false WHERE id=\$1 AND user_id=\$2`).
		WithArgs(itemID, userID, []byte("enc"), base+1).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectCommit()

	res, err := r.UpsertBatch(ctx, userID, []model.UpsertItem{
		{ID: itemID, BaseVer: base, BlobEnc: model.EncryptedBlob("enc")},
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(res))
	require.Equal(t, base+1, res[0].NewVer)
}

func TestItemRepo_UpsertBatch_Create_OK(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)

	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	itemID := uuid.Must(uuid.NewV4())

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(itemID, userID).
		WillReturnError(pgx.ErrNoRows)
	mock.ExpectExec(`INSERT INTO items \(id, user_id, blob_enc, ver, deleted\) VALUES \(\$1,\$2,\$3,\$4,false\)`).
		WithArgs(itemID, userID, []byte("enc"), int64(1)).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectCommit()

	res, err := r.UpsertBatch(ctx, userID, []model.UpsertItem{
		{ID: itemID, BaseVer: 0, BlobEnc: model.EncryptedBlob("enc")},
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), res[0].NewVer)
}

func TestItemRepo_UpsertBatch_VersionConflict_OnUpdate(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)

	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	itemID := uuid.Must(uuid.NewV4())

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(itemID, userID).
		WillReturnRows(pgxmock.NewRows([]string{"ver"}).AddRow(int64(2)))
	mock.ExpectRollback()

	_, err := r.UpsertBatch(ctx, userID, []model.UpsertItem{
		{ID: itemID, BaseVer: 1, BlobEnc: model.EncryptedBlob("x")},
	})
	require.ErrorIs(t, err, errs.ErrVersionConflict)
}

func TestItemRepo_UpsertBatch_VersionConflict_OnCreate(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)

	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	itemID := uuid.Must(uuid.NewV4())

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(itemID, userID).
		WillReturnError(pgx.ErrNoRows)
	mock.ExpectRollback()

	_, err := r.UpsertBatch(ctx, userID, []model.UpsertItem{
		{ID: itemID, BaseVer: 10, BlobEnc: model.EncryptedBlob("x")},
	})
	require.ErrorIs(t, err, errs.ErrVersionConflict)
}

func TestItemRepo_Delete_OK(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)

	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	itemID := uuid.Must(uuid.NewV4())
	cur := int64(7)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(itemID, userID).
		WillReturnRows(pgxmock.NewRows([]string{"ver"}).AddRow(cur))
	mock.ExpectExec(`UPDATE items SET deleted=true, ver=\$3 WHERE id=\$1 AND user_id=\$2`).
		WithArgs(itemID, userID, cur+1).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectCommit()

	v, err := r.Delete(ctx, userID, itemID, cur)
	require.NoError(t, err)
	require.Equal(t, cur+1, v.NewVer)
}

func TestItemRepo_Delete_NotFound(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)

	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	itemID := uuid.Must(uuid.NewV4())

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(itemID, userID).
		WillReturnError(pgx.ErrNoRows)
	mock.ExpectRollback()

	_, err := r.Delete(ctx, userID, itemID, 1)
	require.ErrorIs(t, err, errs.ErrNotFound)
}

func TestItemRepo_Delete_VersionConflict(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)

	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	itemID := uuid.Must(uuid.NewV4())

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(itemID, userID).
		WillReturnRows(pgxmock.NewRows([]string{"ver"}).AddRow(int64(3)))
	mock.ExpectRollback()

	_, err := r.Delete(ctx, userID, itemID, 1)
	require.ErrorIs(t, err, errs.ErrVersionConflict)
}

func TestItemRepo_GetChangesSince(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)

	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	ts := time.Now().UTC()
	id1 := uuid.Must(uuid.NewV4())
	id2 := uuid.Must(uuid.NewV4())

	rows := pgxmock.NewRows([]string{"id", "ver", "deleted", "updated_at", "blob_enc"}).
		AddRow(id1, int64(2), false, ts, []byte("enc1")).
		AddRow(id2, int64(3), true, ts, []byte(nil))

	mock.ExpectQuery(`SELECT id, ver, deleted, updated_at, blob_enc FROM items WHERE user_id=\$1 AND ver>\$2 ORDER BY ver ASC`).
		WithArgs(userID, int64(1)).
		WillReturnRows(rows)

	out, err := r.GetChangesSince(ctx, userID, 1)
	require.NoError(t, err)
	require.Len(t, out, 2)
	require.False(t, out[0].Deleted)
	require.Equal(t, model.EncryptedBlob("enc1"), out[0].BlobEnc)
	require.True(t, out[1].Deleted)
	require.Nil(t, out[1].BlobEnc)
}

func TestItemRepo_GetItem_OK_And_NotFound(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)

	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	itemID := uuid.Must(uuid.NewV4())
	ts := time.Now().UTC()

	// OK
	mock.ExpectQuery(`SELECT id, user_id, blob_enc, ver, deleted, updated_at FROM items WHERE user_id=\$1 AND id=\$2`).
		WithArgs(userID, itemID).
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "blob_enc", "ver", "deleted", "updated_at"}).
			AddRow(itemID, userID, []byte("enc"), int64(10), false, ts))
	it, err := r.GetItem(ctx, userID, itemID)
	require.NoError(t, err)
	require.Equal(t, itemID, it.ID)
	require.Equal(t, int64(10), it.Ver)

	// NotFound
	mock.ExpectQuery(`SELECT id, user_id, blob_enc, ver, deleted, updated_at FROM items WHERE user_id=\$1 AND id=\$2`).
		WithArgs(userID, itemID).
		WillReturnError(pgx.ErrNoRows)
	_, err = r.GetItem(ctx, userID, itemID)
	require.ErrorIs(t, err, errs.ErrNotFound)
}

func TestItemRepo_GetMaxVersion(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)

	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())

	mock.ExpectQuery(`SELECT COALESCE\(MAX\(ver\),0\) FROM items WHERE user_id=\$1`).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"max"}).AddRow(int64(42)))

	v, err := r.GetMaxVersion(ctx, userID)
	require.NoError(t, err)
	require.Equal(t, int64(42), v)
}

func TestItemRepo_UpsertBatch_TxBeginErr(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)
	ctx := context.Background()

	mock.ExpectBegin().WillReturnError(errors.New("boom"))
	_, err := r.UpsertBatch(ctx, uuid.Must(uuid.NewV4()), nil)
	require.Error(t, err)
}

func TestItemRepo_UpsertBatch_Update_ExecErr(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)
	ctx := context.Background()
	uid := uuid.Must(uuid.NewV4())
	iid := uuid.Must(uuid.NewV4())

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(iid, uid).WillReturnRows(pgxmock.NewRows([]string{"ver"}).AddRow(int64(1)))
	mock.ExpectExec(`UPDATE items SET blob_enc=\$3, ver=\$4, deleted=false WHERE id=\$1 AND user_id=\$2`).
		WithArgs(iid, uid, []byte("enc"), int64(2)).WillReturnError(errors.New("exec-fail"))
	mock.ExpectRollback()

	_, err := r.UpsertBatch(ctx, uid, []model.UpsertItem{{ID: iid, BaseVer: 1, BlobEnc: model.EncryptedBlob("enc")}})
	require.Error(t, err)
}

func TestItemRepo_UpsertBatch_Insert_ExecErr(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)
	ctx := context.Background()
	uid := uuid.Must(uuid.NewV4())
	iid := uuid.Must(uuid.NewV4())

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(iid, uid).WillReturnError(pgx.ErrNoRows)
	mock.ExpectExec(`INSERT INTO items \(id, user_id, blob_enc, ver, deleted\) VALUES`).
		WithArgs(iid, uid, []byte("enc"), int64(1)).WillReturnError(errors.New("insert-fail"))
	mock.ExpectRollback()

	_, err := r.UpsertBatch(ctx, uid, []model.UpsertItem{{ID: iid, BaseVer: 0, BlobEnc: model.EncryptedBlob("enc")}})
	require.Error(t, err)
}

func TestItemRepo_UpsertBatch_ScanOtherErr(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)
	ctx := context.Background()
	uid := uuid.Must(uuid.NewV4())
	iid := uuid.Must(uuid.NewV4())

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(iid, uid).WillReturnError(errors.New("weird-scan"))
	mock.ExpectRollback()

	_, err := r.UpsertBatch(ctx, uid, []model.UpsertItem{{ID: iid, BaseVer: 0, BlobEnc: model.EncryptedBlob("x")}})
	require.Error(t, err)
}

func TestItemRepo_UpsertBatch_MultipleItems_StopOnFirstErr(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)
	ctx := context.Background()
	uid := uuid.Must(uuid.NewV4())
	i1, i2 := uuid.Must(uuid.NewV4()), uuid.Must(uuid.NewV4())

	mock.ExpectBegin()

	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(i1, uid).WillReturnRows(pgxmock.NewRows([]string{"ver"}).AddRow(int64(2)))
	mock.ExpectExec(`UPDATE items SET blob_enc=\$3, ver=\$4, deleted=false WHERE id=\$1 AND user_id=\$2`).
		WithArgs(i1, uid, []byte("a"), int64(3)).WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(i2, uid).WillReturnRows(pgxmock.NewRows([]string{"ver"}).AddRow(int64(5)))
	mock.ExpectRollback()

	_, err := r.UpsertBatch(ctx, uid, []model.UpsertItem{
		{ID: i1, BaseVer: 2, BlobEnc: model.EncryptedBlob("a")},
		{ID: i2, BaseVer: 1, BlobEnc: model.EncryptedBlob("b")},
	})
	require.ErrorIs(t, err, errs.ErrVersionConflict)
}

func TestItemRepo_Delete_CommitErr(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)
	ctx := context.Background()
	uid := uuid.Must(uuid.NewV4())
	iid := uuid.Must(uuid.NewV4())

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(iid, uid).WillReturnRows(pgxmock.NewRows([]string{"ver"}).AddRow(int64(1)))
	mock.ExpectExec(`UPDATE items SET deleted=true, ver=\$3 WHERE id=\$1 AND user_id=\$2`).
		WithArgs(iid, uid, int64(2)).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectCommit().WillReturnError(errors.New("commit-fail"))

	_, err := r.Delete(ctx, uid, iid, 1)
	require.Error(t, err)
}

func TestItemRepo_Delete_ExecErr(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)
	ctx := context.Background()
	uid := uuid.Must(uuid.NewV4())
	iid := uuid.Must(uuid.NewV4())

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT ver FROM items WHERE id=\$1 AND user_id=\$2 FOR UPDATE`).
		WithArgs(iid, uid).WillReturnRows(pgxmock.NewRows([]string{"ver"}).AddRow(int64(1)))
	mock.ExpectExec(`UPDATE items SET deleted=true, ver=\$3 WHERE id=\$1 AND user_id=\$2`).
		WithArgs(iid, uid, int64(2)).WillReturnError(errors.New("upd-fail"))
	mock.ExpectRollback()

	_, err := r.Delete(ctx, uid, iid, 1)
	require.Error(t, err)
}

func TestItemRepo_GetChangesSince_QueryErr(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)
	ctx := context.Background()
	uid := uuid.Must(uuid.NewV4())

	mock.ExpectQuery(`SELECT id, ver, deleted, updated_at, blob_enc FROM items WHERE user_id=\$1 AND ver>\$2 ORDER BY ver ASC`).
		WithArgs(uid, int64(0)).WillReturnError(errors.New("q-fail"))

	_, err := r.GetChangesSince(ctx, uid, 0)
	require.Error(t, err)
}

func TestItemRepo_GetChangesSince_RowScanErrAndRowsErr(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)
	ctx := context.Background()
	uid := uuid.Must(uuid.NewV4())

	rows := pgxmock.NewRows([]string{"id", "ver", "deleted", "updated_at", "blob_enc"}).
		RowError(0, errors.New("row0"))
	mock.ExpectQuery(`SELECT id, ver, deleted, updated_at, blob_enc FROM items WHERE user_id=\$1 AND ver>\$2 ORDER BY ver ASC`).
		WithArgs(uid, int64(0)).WillReturnRows(rows)

	_, err := r.GetChangesSince(ctx, uid, 0)
	require.Error(t, err)
}

func TestItemRepo_GetItem_QueryOtherErr(t *testing.T) {
	db, mock := newDB(t)
	defer mock.Close()
	r := NewItemRepo(db)
	ctx := context.Background()
	uid := uuid.Must(uuid.NewV4())
	iid := uuid.Must(uuid.NewV4())

	mock.ExpectQuery(`SELECT id, user_id, blob_enc, ver, deleted, updated_at FROM items WHERE user_id=\$1 AND id=\$2`).
		WithArgs(uid, iid).WillReturnError(errors.New("weird"))
	_, err := r.GetItem(ctx, uid, iid)
	require.Error(t, err)
}
