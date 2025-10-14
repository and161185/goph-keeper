package grpcserver

import (
	"context"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/metadata"
)

func makeJWT(t *testing.T, sub string, key []byte, method jwt.SigningMethod, iat time.Time, ttl time.Duration) string {
	t.Helper()
	claims := jwt.RegisteredClaims{
		Subject:   sub,
		IssuedAt:  jwt.NewNumericDate(iat),
		NotBefore: jwt.NewNumericDate(iat),
		ExpiresAt: jwt.NewNumericDate(iat.Add(ttl)),
	}
	token := jwt.NewWithClaims(method, claims)
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return s
}

func ctxWithAuth(token string) context.Context {
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + token,
	})
	return metadata.NewIncomingContext(context.Background(), md)
}

func Test_bearerTokenFromMD_OkAndErrors(t *testing.T) {
	t.Parallel()

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer abc.def.ghi"))
	got, err := bearerTokenFromMD(ctx)
	if err != nil || got != "abc.def.ghi" {
		t.Fatalf("ok: got=%q err=%v", got, err)
	}

	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic foo"))
	if _, err := bearerTokenFromMD(ctx); err == nil {
		t.Fatalf("want error on non-bearer")
	}

	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer   "))
	if _, err := bearerTokenFromMD(ctx); err == nil {
		t.Fatalf("want error on empty token")
	}

	if _, err := bearerTokenFromMD(context.Background()); err == nil {
		t.Fatalf("want error on no metadata")
	}
}

func Test_userIDFromCtx_Valid(t *testing.T) {
	t.Parallel()

	s := &Server{signKey: []byte("secret")}
	sub := uuid.Must(uuid.NewV4()).String()
	j := makeJWT(t, sub, s.signKey, jwt.SigningMethodHS256, time.Now().UTC().Add(-time.Minute), 10*time.Minute)
	ctx := ctxWithAuth(j)

	id, err := s.userIDFromCtx(ctx)
	if err != nil {
		t.Fatalf("userIDFromCtx: %v", err)
	}
	if id.String() != sub {
		t.Fatalf("uuid mismatch: %s vs %s", id, sub)
	}
}

func Test_userIDFromCtx_NoMetadata(t *testing.T) {
	t.Parallel()

	s := &Server{signKey: []byte("secret")}
	if _, err := s.userIDFromCtx(context.Background()); err == nil {
		t.Fatalf("want error on missing metadata")
	}
}

func Test_userIDFromCtx_Expired(t *testing.T) {
	t.Parallel()

	s := &Server{signKey: []byte("secret")}
	sub := uuid.Must(uuid.NewV4()).String()

	j := makeJWT(t, sub, s.signKey, jwt.SigningMethodHS256, time.Now().UTC().Add(-2*time.Hour), -time.Hour)
	ctx := ctxWithAuth(j)

	if _, err := s.userIDFromCtx(ctx); err == nil {
		t.Fatalf("want error on expired token")
	}
}

func Test_userIDFromCtx_BadSubject(t *testing.T) {
	t.Parallel()

	s := &Server{signKey: []byte("secret")}
	j := makeJWT(t, "not-a-uuid", s.signKey, jwt.SigningMethodHS256, time.Now().UTC(), time.Hour)
	ctx := ctxWithAuth(j)

	if _, err := s.userIDFromCtx(ctx); err == nil {
		t.Fatalf("want error on bad subject")
	}
}

func Test_userIDFromCtx_WrongAlg(t *testing.T) {
	t.Parallel()

	s := &Server{signKey: []byte("secret")}
	sub := uuid.Must(uuid.NewV4()).String()

	j := makeJWT(t, sub, s.signKey, jwt.SigningMethodHS384, time.Now().UTC(), time.Hour)
	ctx := ctxWithAuth(j)

	if _, err := s.userIDFromCtx(ctx); err == nil {
		t.Fatalf("want error on wrong alg")
	}
}

func Test_userIDFromCtx_InvalidTokenString(t *testing.T) {
	t.Parallel()

	s := &Server{signKey: []byte("secret")}
	ctx := ctxWithAuth("this-is-not-a-jwt")

	if _, err := s.userIDFromCtx(ctx); err == nil {
		t.Fatalf("want error on invalid token string")
	}
}
