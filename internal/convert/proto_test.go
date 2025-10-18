package convert

import (
	"strings"
	"testing"
	"time"

	pb "github.com/and161185/goph-keeper/gen/go/gophkeeper/v1"
	model "github.com/and161185/goph-keeper/internal/model"
	u "github.com/gofrs/uuid/v5"
)

func mustUUID(t *testing.T, s string) u.UUID {
	t.Helper()
	id, err := u.FromString(s)
	if err != nil {
		t.Fatalf("bad uuid %q: %v", s, err)
	}
	return id
}

func TestToFromProtoEncryptedBlob(t *testing.T) {
	t.Parallel()

	// nil → nil / empty
	if ToProtoEncryptedBlob(nil) != nil {
		t.Fatalf("nil domain blob must give nil pb")
	}
	if FromProtoEncryptedBlob(nil) != nil {
		t.Fatalf("nil pb blob must give nil domain")
	}
	eb := &pb.EncryptedBlob{}
	eb.SetCiphertext(nil)
	if FromProtoEncryptedBlob(eb) != nil {
		t.Fatalf("empty ciphertext must give nil domain")
	}

	// roundtrip
	d := model.EncryptedBlob([]byte{1, 2, 3})
	p := ToProtoEncryptedBlob(d)
	if p == nil || string(p.GetCiphertext()) != "\x01\x02\x03" {
		t.Fatalf("pb mismatch")
	}
	dr := FromProtoEncryptedBlob(p)
	if string(dr) != string(d) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestFromProtoUpsertItem_OK(t *testing.T) {
	t.Parallel()

	eb := &pb.EncryptedBlob{}
	eb.SetCiphertext([]byte{9, 9})

	ui := &pb.UpsertItem{}
	ui.SetId("6f1cbe8e-b2e7-4a3b-9f6e-2a2c0f2f9c11")
	ui.SetBaseVer(10)
	ui.SetBlobEnc(eb)

	got, err := FromProtoUpsertItem(ui)
	if err != nil {
		t.Fatalf("FromProtoUpsertItem: %v", err)
	}
	if got.ID.String() != ui.GetId() {
		t.Fatalf("id mismatch")
	}
	if got.BaseVer != ui.GetBaseVer() {
		t.Fatalf("baseVer mismatch")
	}
	if string(got.BlobEnc) != string(ui.GetBlobEnc().GetCiphertext()) {
		t.Fatalf("blob mismatch")
	}
}

func TestFromProtoUpsertItem_InvalidUUID(t *testing.T) {
	t.Parallel()

	ui := &pb.UpsertItem{}
	ui.SetId("not-a-uuid")

	_, err := FromProtoUpsertItem(ui)
	if err == nil || !strings.Contains(err.Error(), "invalid id") {
		t.Fatalf("want invalid id error, got: %v", err)
	}
}

func TestFromProtoUpsertItems_BatchAndEarlyError(t *testing.T) {
	t.Parallel()

	out, err := FromProtoUpsertItems(nil)
	if err != nil || len(out) != 0 {
		t.Fatalf("nil slice → empty, err=%v", err)
	}

	eb := &pb.EncryptedBlob{}
	eb.SetCiphertext([]byte{1})

	ui1 := &pb.UpsertItem{}
	ui1.SetId("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	ui1.SetBaseVer(1)
	ui1.SetBlobEnc(eb)

	ui2 := &pb.UpsertItem{}
	ui2.SetId("bad-uuid")

	ui3 := &pb.UpsertItem{}
	ui3.SetId("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	ui3.SetBaseVer(2)

	in := []*pb.UpsertItem{
		ui1,
		ui2,
		ui3,
	}
	_, err = FromProtoUpsertItems(in)
	if err == nil || !strings.Contains(err.Error(), "item[1]") {
		t.Fatalf("expected early error at item[1], got: %v", err)
	}
}

func TestToProtoItemVersion_ZerosAndTime(t *testing.T) {
	t.Parallel()

	id := mustUUID(t, "11111111-1111-1111-1111-111111111111")

	// zero time → UpdatedAt=nil
	p0 := ToProtoItemVersion(model.ItemVersion{ID: id, NewVer: 7})
	if p0.GetId() != id.String() || p0.GetNewVer() != 7 {
		t.Fatalf("basic fields mismatch")
	}
	if p0.GetUpdatedAt() != nil {
		t.Fatalf("zero time must map to nil timestamp")
	}

	// non-zero time → timestamp set
	ts := time.Now().UTC().Truncate(time.Second)
	p1 := ToProtoItemVersion(model.ItemVersion{ID: id, NewVer: 8, UpdatedAt: ts})
	if p1.GetUpdatedAt() == nil || p1.GetUpdatedAt().AsTime().UTC() != ts {
		t.Fatalf("timestamp mismatch")
	}
}

func TestToProtoItemVersions_Slice(t *testing.T) {
	t.Parallel()

	id := mustUUID(t, "22222222-2222-2222-2222-222222222222")
	ps := ToProtoItemVersions([]model.ItemVersion{
		{ID: id, NewVer: 1},
	})
	if len(ps) != 1 || ps[0].GetId() != id.String() || ps[0].GetNewVer() != 1 {
		t.Fatalf("slice mapping mismatch")
	}
	if len(ToProtoItemVersions(nil)) != 0 {
		t.Fatalf("nil slice must map to empty slice")
	}
}

func TestToProtoChange_DeletedOmitsBlob(t *testing.T) {
	t.Parallel()

	id := mustUUID(t, "33333333-3333-3333-3333-333333333333")

	pd := ToProtoChange(model.Change{
		ID:        id,
		Ver:       5,
		Deleted:   true,
		BlobEnc:   model.EncryptedBlob{1, 2, 3},
		UpdatedAt: time.Time{},
	})
	if !pd.GetDeleted() || pd.GetBlobEnc() != nil {
		t.Fatalf("deleted change must omit blob")
	}
	if pd.GetUpdatedAt() != nil {
		t.Fatalf("zero time must map to nil timestamp")
	}

	ts := time.Now().UTC().Truncate(time.Second)
	pa := ToProtoChange(model.Change{
		ID:        id,
		Ver:       6,
		Deleted:   false,
		BlobEnc:   model.EncryptedBlob{9, 9},
		UpdatedAt: ts,
	})
	if pa.GetDeleted() || pa.GetBlobEnc() == nil || string(pa.GetBlobEnc().GetCiphertext()) != "\x09\x09" {
		t.Fatalf("active change blob mismatch")
	}
	if pa.GetUpdatedAt() == nil || !pa.GetUpdatedAt().AsTime().UTC().Equal(ts) {
		t.Fatalf("timestamp mismatch")
	}
}

func TestToProtoChanges_Slice(t *testing.T) {
	t.Parallel()

	id1 := mustUUID(t, "44444444-4444-4444-4444-444444444444")
	id2 := mustUUID(t, "55555555-5555-5555-5555-555555555555")
	ps := ToProtoChanges([]model.Change{
		{ID: id1, Ver: 1, Deleted: false},
		{ID: id2, Ver: 2, Deleted: true},
	})
	if len(ps) != 2 || ps[0].GetId() != id1.String() || ps[1].GetId() != id2.String() {
		t.Fatalf("changes slice mapping mismatch")
	}
	if ps[1].GetBlobEnc() != nil {
		t.Fatalf("deleted change must not carry blob")
	}
}

func TestToProtoGetItemResponse(t *testing.T) {
	t.Parallel()

	id := mustUUID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

	// zero time → UpdatedAt=nil
	r0 := ToProtoGetItemResponse(model.Item{
		ID: id, Ver: 9, Deleted: false, BlobEnc: model.EncryptedBlob{7, 7, 7},
	})
	if r0.GetId() != id.String() || r0.GetVer() != 9 || r0.GetDeleted() != false {
		t.Fatalf("basic fields mismatch")
	}
	if r0.GetUpdatedAt() != nil {
		t.Fatalf("zero time must map to nil")
	}
	if r0.GetBlobEnc() == nil || string(r0.GetBlobEnc().GetCiphertext()) != "\x07\x07\x07" {
		t.Fatalf("blob mismatch")
	}

	// non-zero time
	ts := time.Now().UTC().Truncate(time.Second)
	r1 := ToProtoGetItemResponse(model.Item{
		ID: id, Ver: 10, Deleted: true, BlobEnc: nil, UpdatedAt: ts,
	})
	if r1.GetUpdatedAt() == nil || !r1.GetUpdatedAt().AsTime().UTC().Equal(ts) {
		t.Fatalf("timestamp mismatch")
	}
}
