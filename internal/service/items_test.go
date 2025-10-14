package service

import (
	"context"
	"errors"
	"testing"

	"github.com/gofrs/uuid/v5"

	"github.com/and161185/goph-keeper/internal/model"
	"github.com/and161185/goph-keeper/internal/repository"
)

type fakeItemRepo struct {
	upsertInUser uuid.UUID
	upsertInUps  []model.UpsertItem
	upsertOut    []model.ItemVersion
	upsertErr    error

	delInUser uuid.UUID
	delInID   uuid.UUID
	delInBase int64
	delOut    model.ItemVersion
	delErr    error

	chInUser  uuid.UUID
	chInSince int64
	chOut     []model.Change
	chErr     error

	getInUser uuid.UUID
	getInID   uuid.UUID
	getOut    *model.Item
	getErr    error
}

var _ repository.ItemRepository = (*fakeItemRepo)(nil)

func (f *fakeItemRepo) UpsertBatch(_ context.Context, userID uuid.UUID, ups []model.UpsertItem) ([]model.ItemVersion, error) {
	f.upsertInUser, f.upsertInUps = userID, append([]model.UpsertItem(nil), ups...)
	return append([]model.ItemVersion(nil), f.upsertOut...), f.upsertErr
}
func (f *fakeItemRepo) Delete(_ context.Context, userID, id uuid.UUID, baseVer int64) (model.ItemVersion, error) {
	f.delInUser, f.delInID, f.delInBase = userID, id, baseVer
	return f.delOut, f.delErr
}
func (f *fakeItemRepo) GetChangesSince(_ context.Context, userID uuid.UUID, sinceVer int64) ([]model.Change, error) {
	f.chInUser, f.chInSince = userID, sinceVer
	return append([]model.Change(nil), f.chOut...), f.chErr
}
func (f *fakeItemRepo) GetItem(_ context.Context, userID, id uuid.UUID) (*model.Item, error) {
	f.getInUser, f.getInID = userID, id
	return f.getOut, f.getErr
}

func (f *fakeItemRepo) GetMaxVersion(_ context.Context, userID uuid.UUID) (int64, error) {
	return 0, nil
}

func TestNewItemService_DefaultMaxBatch(t *testing.T) {
	s := NewItemService(&fakeItemRepo{}, 0)
	if s.maxBatch != 1000 {
		t.Fatalf("default maxBatch want 1000, got %d", s.maxBatch)
	}
}

func TestItemService_Upsert_Validation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeItemRepo{}
	s := NewItemService(repo, 2)

	user := uuid.Must(uuid.NewV4())
	id := uuid.Must(uuid.NewV4())

	if _, err := s.Upsert(ctx, uuid.Nil, nil); err == nil {
		t.Fatalf("want validation error on empty userID")
	}

	out, err := s.Upsert(ctx, user, nil)
	if err != nil || len(out) != 0 {
		t.Fatalf("empty slice: out=%v err=%v", out, err)
	}
	if repo.upsertInUps != nil {
		t.Fatalf("repo should not be called on empty input")
	}

	ups := []model.UpsertItem{
		{ID: id, BaseVer: 0, BlobEnc: []byte{1}},
		{ID: id, BaseVer: 0, BlobEnc: []byte{1}},
		{ID: id, BaseVer: 0, BlobEnc: []byte{1}},
	}
	if _, err := s.Upsert(ctx, user, ups); err == nil {
		t.Fatalf("want error on batch too large")
	}

	if _, err := s.Upsert(ctx, user, []model.UpsertItem{{ID: uuid.Nil, BaseVer: 0, BlobEnc: []byte{1}}}); err == nil {
		t.Fatalf("want error on empty id")
	}

	if _, err := s.Upsert(ctx, user, []model.UpsertItem{{ID: id, BaseVer: -1, BlobEnc: []byte{1}}}); err == nil {
		t.Fatalf("want error on negative base_ver")
	}

	if _, err := s.Upsert(ctx, user, []model.UpsertItem{{ID: id, BaseVer: 0, BlobEnc: nil}}); err == nil {
		t.Fatalf("want error on empty blob")
	}
}

func TestItemService_Upsert_DelegatesToRepo(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeItemRepo{
		upsertOut: []model.ItemVersion{{ID: uuid.Must(uuid.NewV4()), NewVer: 2}},
	}
	s := NewItemService(repo, 10)

	user := uuid.Must(uuid.NewV4())
	id := uuid.Must(uuid.NewV4())
	ups := []model.UpsertItem{{ID: id, BaseVer: 0, BlobEnc: []byte{9}}}

	out, err := s.Upsert(ctx, user, ups)
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if len(out) != 1 || out[0].NewVer != 2 {
		t.Fatalf("unexpected repo result: %+v", out)
	}
	if repo.upsertInUser != user || len(repo.upsertInUps) != 1 || repo.upsertInUps[0].ID != id {
		t.Fatalf("repo args not forwarded correctly")
	}
}

func TestItemService_Delete_ValidationAndDelegate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeItemRepo{delOut: model.ItemVersion{ID: uuid.Must(uuid.NewV4()), NewVer: 11}}
	s := NewItemService(repo, 10)

	u := uuid.Must(uuid.NewV4())
	id := uuid.Must(uuid.NewV4())

	if _, err := s.Delete(ctx, uuid.Nil, id, 0); err == nil {
		t.Fatalf("want validation error on empty userID")
	}
	if _, err := s.Delete(ctx, u, uuid.Nil, 0); err == nil {
		t.Fatalf("want validation error on empty id")
	}

	if _, err := s.Delete(ctx, u, id, -1); err == nil {
		t.Fatalf("want validation error on negative base")
	}

	ver, err := s.Delete(ctx, u, id, 3)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if ver.NewVer != 11 || repo.delInUser != u || repo.delInID != id || repo.delInBase != 3 {
		t.Fatalf("delegate args/result mismatch: ver=%+v repo=%+v", ver, repo)
	}
}

func TestItemService_GetChanges_ValidationAndDelegate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeItemRepo{chOut: []model.Change{{Ver: 5}, {Ver: 6}}}
	s := NewItemService(repo, 10)

	u := uuid.Must(uuid.NewV4())

	if _, err := s.GetChanges(ctx, uuid.Nil, 0); err == nil {
		t.Fatalf("want validation error on empty userID")
	}

	if _, err := s.GetChanges(ctx, u, -1); err == nil {
		t.Fatalf("want validation error on negative since")
	}
	out, err := s.GetChanges(ctx, u, 4)
	if err != nil {
		t.Fatalf("GetChanges: %v", err)
	}
	if len(out) != 2 || out[0].Ver != 5 || repo.chInUser != u || repo.chInSince != 4 {
		t.Fatalf("delegate mismatch: out=%+v repo=%+v", out, repo)
	}
}

func TestItemService_GetOne_ValidationAndDelegate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	itID := uuid.Must(uuid.NewV4())
	repo := &fakeItemRepo{getOut: &model.Item{ID: itID, Ver: 9}}
	s := NewItemService(repo, 10)

	u := uuid.Must(uuid.NewV4())

	if _, err := s.GetOne(ctx, uuid.Nil, itID); err == nil {
		t.Fatalf("want validation error on empty userID")
	}
	if _, err := s.GetOne(ctx, u, uuid.Nil); err == nil {
		t.Fatalf("want validation error on empty id")
	}
	got, err := s.GetOne(ctx, u, itID)
	if err != nil {
		t.Fatalf("GetOne: %v", err)
	}
	if got.ID != itID || repo.getInUser != u || repo.getInID != itID {
		t.Fatalf("delegate mismatch: got=%+v repo=%+v", got, repo)
	}
}

func TestItemService_RepoErrorsPropagate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := &fakeItemRepo{
		upsertErr: errors.New("boom-upsert"),
		delErr:    errors.New("boom-del"),
		chErr:     errors.New("boom-ch"),
		getErr:    errors.New("boom-get"),
	}
	s := NewItemService(repo, 10)
	u := uuid.Must(uuid.NewV4())
	id := uuid.Must(uuid.NewV4())

	if _, err := s.Upsert(ctx, u, []model.UpsertItem{{ID: id, BaseVer: 0, BlobEnc: []byte{1}}}); err == nil {
		t.Fatalf("want repo error propagate (upsert)")
	}
	if _, err := s.Delete(ctx, u, id, 0); err == nil {
		t.Fatalf("want repo error propagate (delete)")
	}
	if _, err := s.GetChanges(ctx, u, 0); err == nil {
		t.Fatalf("want repo error propagate (changes)")
	}
	if _, err := s.GetOne(ctx, u, id); err == nil {
		t.Fatalf("want repo error propagate (get)")
	}
}
