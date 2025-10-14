package grpcserver

import (
	"context"

	"github.com/gofrs/uuid/v5"
)

type ctxKey string

const userIDKey ctxKey = "gk.userID"

// WithUserID stores authenticated user ID in context.
func WithUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, id)
}

// UserIDFromCtx fetches user ID from context.
func UserIDFromCtx(ctx context.Context) (uuid.UUID, bool) {
	v := ctx.Value(userIDKey)
	if v == nil {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}
