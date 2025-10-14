package grpcserver

import (
	"context"
	"testing"

	"github.com/gofrs/uuid/v5"
)

func TestWithUserID_And_UserIDFromCtx(t *testing.T) {
	t.Parallel()

	if id, ok := UserIDFromCtx(context.Background()); ok || id != uuid.Nil {
		t.Fatalf("expected no user id in empty ctx")
	}

	want := uuid.Must(uuid.NewV4())
	ctx := WithUserID(context.Background(), want)

	got, ok := UserIDFromCtx(ctx)
	if !ok {
		t.Fatalf("expected user id in ctx")
	}
	if got != want {
		t.Fatalf("mismatch: got %s, want %s", got, want)
	}

	type ctxKey string
	const userIDKey ctxKey = "gk.userID"
	bad := context.WithValue(context.Background(), userIDKey, "not-uuid")
	if id, ok := UserIDFromCtx(bad); ok || id != uuid.Nil {
		t.Fatalf("expected miss on wrong typed value")
	}
}
