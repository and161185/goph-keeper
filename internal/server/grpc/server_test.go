package grpcserver

import (
	"context"
	"net"
	"testing"
	"time"

	pb "github.com/and161185/goph-keeper/gen/go/gophkeeper/v1"
	"github.com/and161185/goph-keeper/internal/model"
	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type fakeAuth struct {
	key []byte
	id  uuid.UUID
}

func (f *fakeAuth) Register(context.Context, string, string) (string, error) {
	if f.id == uuid.Nil {
		f.id = uuid.Must(uuid.NewV4())
	}
	return f.id.String(), nil
}
func (f *fakeAuth) LoginWithIP(context.Context, string, string, string) (model.Tokens, model.User, error) {
	if f.id == uuid.Nil {
		f.id = uuid.Must(uuid.NewV4())
	}
	return model.Tokens{AccessToken: "dummy", ExpiresAt: time.Now().Add(time.Minute)}, model.User{
		ID: f.id, KekSalt: []byte("keksalt"), WrappedDEK: []byte{},
	}, nil
}
func (f *fakeAuth) SetWrappedDEK(context.Context, uuid.UUID, []byte) error { return nil }

type fakeItems struct{ lastSince int64 }

func (f *fakeItems) Upsert(_ context.Context, _ uuid.UUID, ups []model.UpsertItem) ([]model.ItemVersion, error) {
	return []model.ItemVersion{{ID: ups[0].ID, NewVer: ups[0].BaseVer + 1}}, nil
}
func (f *fakeItems) Delete(_ context.Context, _ uuid.UUID, id uuid.UUID, baseVer int64) (model.ItemVersion, error) {
	return model.ItemVersion{ID: id, NewVer: baseVer + 1}, nil
}
func (f *fakeItems) GetChanges(_ context.Context, _ uuid.UUID, sinceVer int64) ([]model.Change, error) {
	f.lastSince = sinceVer
	return []model.Change{{ID: uuid.Must(uuid.NewV4()), Ver: sinceVer + 1}}, nil
}
func (f *fakeItems) GetOne(_ context.Context, _ uuid.UUID, id uuid.UUID) (*model.Item, error) {
	return &model.Item{ID: id, Ver: 2, BlobEnc: []byte{1, 2, 3}}, nil
}

const bufSize = 1 << 20

func startBufGRPC(t *testing.T, srv *Server) (*grpc.ClientConn, func()) {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	gs := grpc.NewServer()
	pb.RegisterGophKeeperServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
	//nolint:staticcheck // DialContext is supported through 1.x; migrate when grpc.NewClient is stable
	cc, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	stop := func() { _ = cc.Close(); gs.Stop(); _ = lis.Close() }
	return cc, stop
}

/************ helpers ************/
func jwtFor(t *testing.T, sub string, key []byte, ttl time.Duration) string {
	t.Helper()
	now := time.Now().UTC()
	claims := jwt.RegisteredClaims{
		Subject:   sub,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),    // небольшой запас
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl + 5*time.Second)), // небольшой запас
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return s
}

func ctxAuth(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))
}

func TestServer_E2E_BasicFlow(t *testing.T) {
	t.Parallel()

	signKey := []byte("test-secret")
	a := &fakeAuth{key: signKey, id: uuid.Must(uuid.NewV4())}
	it := &fakeItems{}
	srv := New(a, it, signKey)

	cc, stop := startBufGRPC(t, srv)
	defer stop()
	cl := pb.NewGophKeeperClient(cc)

	rr := &pb.RegisterRequest{}
	rr.SetUsername("u")
	rr.SetPassword("p")
	r1, err := cl.Register(context.Background(), rr)
	if err != nil || r1.GetUserId() == "" {
		t.Fatalf("register: %v, resp=%+v", err, r1)
	}

	lr := &pb.LoginRequest{}
	lr.SetUsername("u")
	lr.SetPassword("p")
	r2, err := cl.Login(context.Background(), lr)
	if err != nil || r2.GetKekSalt() == nil {
		t.Fatalf("login: %v, resp=%+v", err, r2)
	}

	token := jwtFor(t, a.id.String(), signKey, time.Minute)
	authIn := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))

	gotID, err := srv.userIDFromCtx(authIn)
	if err != nil {
		t.Fatalf("auth precheck failed: %v", err)
	}
	if gotID != a.id {
		t.Fatalf("auth precheck wrong sub: got=%s want=%s", gotID, a.id)
	}

	itemID := uuid.Must(uuid.NewV4())

	eb := &pb.EncryptedBlob{}
	eb.SetCiphertext([]byte{9})

	ui := &pb.UpsertItem{}
	ui.SetId(itemID.String())
	ui.SetBaseVer(0)
	ui.SetBlobEnc(eb)

	uir := &pb.UpsertItemsRequest{}
	uir.SetItems([]*pb.UpsertItem{ui})

	upr, err := srv.UpsertItems(authIn, uir)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if len(upr.GetResults()) != 1 || upr.GetResults()[0].GetNewVer() != 1 {
		t.Fatalf("bad upsert result: %+v", upr)
	}

	gir := &pb.GetItemRequest{}
	gir.SetId(itemID.String())
	gi, err := srv.GetItem(authIn, gir)
	if err != nil || gi.GetBlobEnc() == nil || gi.GetVer() != 2 {
		t.Fatalf("get item: %v, resp=%+v", err, gi)
	}

	gcr := &pb.GetChangesRequest{}
	gcr.SetSinceVer(0)
	gc, err := srv.GetChanges(authIn, gcr)
	if err != nil || len(gc.GetChanges()) != 1 || it.lastSince != 0 {
		t.Fatalf("get changes: %v, resp=%+v lastSince=%d", err, gc, it.lastSince)
	}

	dir := &pb.DeleteItemRequest{}
	dir.SetId(itemID.String())
	dir.SetBaseVer(1)
	dr, err := srv.DeleteItem(authIn, dir)
	if err != nil || dr.GetResult().GetNewVer() != 2 {
		t.Fatalf("delete: %v, resp=%+v", err, dr)
	}

	swDEKr := &pb.SetWrappedDEKRequest{}
	swDEKr.SetWrappedDek([]byte{1, 2})
	if _, err := srv.SetWrappedDEK(authIn, swDEKr); err != nil {
		t.Fatalf("set wrapped: %v", err)
	}
}

func Test_remoteIP_EmptyIsOk(t *testing.T) {
	if got := remoteIP(context.Background()); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
}
func Test_Register_EmptyFields(t *testing.T) {
	s := &Server{signKey: []byte("k")}
	_, err := s.Register(context.Background(), &pb.RegisterRequest{})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}
func Test_UpsertItems_Unauthenticated(t *testing.T) {
	s := &Server{signKey: []byte("k")}
	_, err := s.UpsertItems(context.Background(), &pb.UpsertItemsRequest{})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}
func Test_GetChanges_Unauthenticated(t *testing.T) {
	s := &Server{signKey: []byte("k")}

	gcr := &pb.GetChangesRequest{}
	gcr.SetSinceVer(0)
	_, err := s.GetChanges(context.Background(), gcr)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}
func Test_GetItem_Unauthenticated(t *testing.T) {
	s := &Server{signKey: []byte("k")}
	gir := &pb.GetItemRequest{}
	gir.SetId("x")
	_, err := s.GetItem(context.Background(), gir)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}
func Test_GetItem_BadID_WithAuth(t *testing.T) {
	key := []byte("secret")
	s := &Server{signKey: key}
	sub := uuid.Must(uuid.NewV4()).String()
	ctx := ctxAuth(jwtFor(t, sub, key, time.Hour))

	gir := &pb.GetItemRequest{}
	gir.SetId("not-a-uuid")
	_, err := s.GetItem(ctx, gir)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}
func Test_DeleteItem_BadID_WithAuth(t *testing.T) {
	key := []byte("secret")
	s := &Server{signKey: key}
	sub := uuid.Must(uuid.NewV4()).String()
	ctx := ctxAuth(jwtFor(t, sub, key, time.Hour))

	dir := &pb.DeleteItemRequest{}
	dir.SetId("bad")
	dir.SetBaseVer(0)
	_, err := s.DeleteItem(ctx, dir)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}
func Test_SetWrappedDEK_Empty_WithAuth(t *testing.T) {
	key := []byte("secret")
	s := &Server{signKey: key}
	sub := uuid.Must(uuid.NewV4()).String()
	ctx := ctxAuth(jwtFor(t, sub, key, time.Hour))

	swDEKr := &pb.SetWrappedDEKRequest{}
	swDEKr.SetWrappedDek(nil)
	_, err := s.SetWrappedDEK(ctx, swDEKr)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}
func Test_UpsertItems_BadItems_WithAuth(t *testing.T) {
	key := []byte("secret")
	s := &Server{signKey: key}
	sub := uuid.Must(uuid.NewV4()).String()
	ctx := ctxAuth(jwtFor(t, sub, key, time.Hour))

	ui := &pb.UpsertItem{}
	ui.SetId("bad-uuid")
	ui.SetBaseVer(0)

	uir := &pb.UpsertItemsRequest{}
	uir.SetItems([]*pb.UpsertItem{ui})
	_, err := s.UpsertItems(ctx, uir)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}
func Test_bearerTokenFromMD_MultipleHeaders_CaseInsensitive_Spaces(t *testing.T) {
	t.Parallel()
	md := metadata.New(nil)
	md.Append("authorization", "Basic foo")
	md.Append("authorization", "  bearer   tok.part.sig   ")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	got, err := bearerTokenFromMD(ctx)
	if err != nil || got != "tok.part.sig" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}
func Test_userIDFromCtx_NotBeforeInFuture(t *testing.T) {
	t.Parallel()
	key := []byte("k")
	s := &Server{signKey: key}
	sub := uuid.Must(uuid.NewV4()).String()
	nbf := time.Now().UTC().Add(10 * time.Minute)
	claims := jwt.RegisteredClaims{
		Subject:   sub,
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(nbf),
		ExpiresAt: jwt.NewNumericDate(nbf.Add(time.Hour)),
	}
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tok))
	if _, err := s.userIDFromCtx(ctx); err == nil {
		t.Fatalf("expected error for nbf in future")
	}
}
func Test_userIDFromCtx_WrongKeySignature(t *testing.T) {
	t.Parallel()
	signerKey := []byte("signer")
	verifyKey := []byte("verifier")
	sub := uuid.Must(uuid.NewV4()).String()
	now := time.Now().UTC()
	claims := jwt.RegisteredClaims{
		Subject:   sub,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(signerKey)
	s := &Server{signKey: verifyKey}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tok))
	if _, err := s.userIDFromCtx(ctx); err == nil {
		t.Fatalf("expected invalid signature error")
	}
}

type loopbackAddr struct{}

func (loopbackAddr) Network() string { return "tcp" }
func (loopbackAddr) String() string  { return "127.0.0.1:5555" }
func Test_remoteIP_WithPeer(t *testing.T) {
	t.Parallel()
	pctx := peer.NewContext(context.Background(), &peer.Peer{Addr: loopbackAddr{}})
	if got := remoteIP(pctx); got == "" {
		t.Fatalf("expected non-empty peer ip:port")
	}
}
func Test_SetWrappedDEK_Unauthenticated(t *testing.T) {
	t.Parallel()
	s := &Server{signKey: []byte("k")}
	_, err := s.SetWrappedDEK(context.Background(), nil)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}
func Test_bearerTokenFromMD_NoBearerAmongMany(t *testing.T) {
	t.Parallel()
	md := metadata.New(nil)
	md.Append("authorization", "Basic a")
	md.Append("authorization", "Digest b")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if _, err := bearerTokenFromMD(ctx); err == nil {
		t.Fatalf("expected error when no bearer present")
	}
}
func Test_userIDFromCtx_LeewayAllowsSmallClockSkew(t *testing.T) {
	t.Parallel()
	key := []byte("k")
	s := &Server{signKey: key}
	sub := uuid.Must(uuid.NewV4()).String()
	now := time.Now().UTC()
	claims := jwt.RegisteredClaims{
		Subject:   sub,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Second)),
	}
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tok))
	if _, err := s.userIDFromCtx(ctx); err != nil {
		t.Fatalf("unexpected leeway validation error: %v", err)
	}
}
