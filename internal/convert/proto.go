package convert

import (
	"fmt"
	"time"

	pb "github.com/and161185/goph-keeper/gen/go/gophkeeper/v1"
	model "github.com/and161185/goph-keeper/internal/model"
	u "github.com/gofrs/uuid/v5"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- helpers ---

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// --- EncryptedBlob ---

// ToProtoEncryptedBlob wraps domain blob to protobuf message.
func ToProtoEncryptedBlob(b model.EncryptedBlob) *pb.EncryptedBlob {
	if b == nil {
		return nil
	}
	eblob := &pb.EncryptedBlob{}
	eblob.SetCiphertext([]byte(b))
	return eblob
}

// FromProtoEncryptedBlob unwraps protobuf blob into domain EncryptedBlob.
func FromProtoEncryptedBlob(b *pb.EncryptedBlob) model.EncryptedBlob {

	ctxt := b.GetCiphertext()
	if b == nil || len(ctxt) == 0 {
		return nil
	}
	return model.EncryptedBlob(ctxt)
}

// --- Upsert (client -> server) ---

// FromProtoUpsertItem converts protobuf UpsertItem to domain struct.
func FromProtoUpsertItem(in *pb.UpsertItem) (model.UpsertItem, error) {
	if in == nil {
		return model.UpsertItem{}, fmt.Errorf("nil UpsertItem")
	}
	var id u.UUID
	if err := id.UnmarshalText([]byte(in.GetId())); err != nil {
		return model.UpsertItem{}, fmt.Errorf("invalid id: %w", err)
	}
	return model.UpsertItem{
		ID:      id,
		BaseVer: in.GetBaseVer(),
		BlobEnc: FromProtoEncryptedBlob(in.GetBlobEnc()),
	}, nil
}

// FromProtoUpsertItems converts a slice of protobuf UpsertItem to domain structs.
func FromProtoUpsertItems(in []*pb.UpsertItem) ([]model.UpsertItem, error) {
	out := make([]model.UpsertItem, 0, len(in))
	for i, it := range in {
		m, err := FromProtoUpsertItem(it)
		if err != nil {
			return nil, fmt.Errorf("item[%d]: %w", i, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// --- Versions / Changes (server -> client) ---

// ToProtoItemVersion converts domain ItemVersion to protobuf result.
func ToProtoItemVersion(v model.ItemVersion) *pb.ItemVersion {
	iv := &pb.ItemVersion{}
	iv.SetId(v.ID.String())
	iv.SetNewVer(v.NewVer)
	iv.SetUpdatedAt(ts(v.UpdatedAt))
	return iv
}

// ToProtoItemVersions converts a slice of ItemVersion to protobuf results.
func ToProtoItemVersions(vs []model.ItemVersion) []*pb.ItemVersion {
	out := make([]*pb.ItemVersion, 0, len(vs))
	for _, v := range vs {
		out = append(out, ToProtoItemVersion(v))
	}
	return out
}

// ToProtoChange converts domain.Change to pb.Change.
func ToProtoChange(c model.Change) *pb.Change {
	var blob *pb.EncryptedBlob
	if !c.Deleted {
		blob = ToProtoEncryptedBlob(c.BlobEnc)
	}

	change := &pb.Change{}
	change.SetId(c.ID.String())
	change.SetVer(c.Ver)
	change.SetDeleted(c.Deleted)
	change.SetUpdatedAt(ts(c.UpdatedAt))
	change.SetBlobEnc(blob)

	return change

}

// ToProtoChanges converts domain changes to protobuf changes for sync.
func ToProtoChanges(cs []model.Change) []*pb.Change {
	out := make([]*pb.Change, 0, len(cs))
	for _, c := range cs {
		out = append(out, ToProtoChange(c))
	}
	return out
}

// --- GetItem (server -> client) ---

// ToProtoGetItemResponse converts domain Item to GetItemResponse.
func ToProtoGetItemResponse(it model.Item) *pb.GetItemResponse {

	iresp := &pb.GetItemResponse{}
	iresp.SetId(it.ID.String())
	iresp.SetVer(it.Ver)
	iresp.SetDeleted(it.Deleted)
	iresp.SetUpdatedAt(ts(it.UpdatedAt))
	iresp.SetBlobEnc(ToProtoEncryptedBlob(it.BlobEnc))

	return iresp
}
