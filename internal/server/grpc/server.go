// Package grpcserver exposes the GophKeeper gRPC API handlers.
package grpcserver

import (
	"context"
	"errors"
	"strings"
	"time"

	pb "github.com/and161185/goph-keeper/gen/go/gophkeeper/v1"
	"github.com/and161185/goph-keeper/internal/convert"
	"github.com/and161185/goph-keeper/internal/errs"
	"github.com/and161185/goph-keeper/internal/service"
	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Server wires services into gRPC handlers.
type Server struct {
	pb.UnimplementedGophKeeperServer
	auth    service.AuthService
	items   service.ItemService
	signKey []byte
}

// New constructs a gRPC server with injected services.
func New(auth service.AuthService, items service.ItemService, signKey []byte) *Server {
	return &Server{auth: auth, items: items, signKey: signKey}
}

// --- Auth ---

// Register creates a new user account.
func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req.GetUsername() == "" || req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "empty username/password")
	}
	userID, err := s.auth.Register(ctx, req.GetUsername(), req.GetPassword())
	if err != nil {
		// map conflicts/validation as needed
		return nil, status.Errorf(codes.Internal, "register: %v", err)
	}

	rr := &pb.RegisterResponse{}
	rr.SetUserId(userID)
	return rr, nil
}

func remoteIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

// Login authenticates a user and returns tokens and bootstrap data.
func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {

	ip := remoteIP(ctx)
	tok, u, err := s.auth.LoginWithIP(ctx, req.GetUsername(), req.GetPassword(), ip)
	if err != nil {
		if errors.Is(err, errs.ErrUnauthorized) {
			return nil, status.Error(codes.Unauthenticated, "bad credentials")
		}
		if errors.Is(err, errs.ErrRateLimited) {
			return nil, status.Error(codes.ResourceExhausted, "rate limited")
		}
		return nil, status.Errorf(codes.Internal, "login: %v", err)
	}

	lg := &pb.LoginResponse{}
	lg.SetAccessToken(tok.AccessToken)
	lg.SetRefreshToken(tok.RefreshToken)
	lg.SetKekSalt(u.KekSalt)
	lg.SetWrappedDek(u.WrappedDEK)
	lg.SetUserId(u.ID.String())
	return lg, nil
}

// --- Items ---
// UpsertItems creates or updates items in batch with optimistic concurrency.
func (s *Server) UpsertItems(ctx context.Context, req *pb.UpsertItemsRequest) (*pb.UpsertItemsResponse, error) {
	userID, err := s.userIDFromCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "no auth")
	}
	ups, err := convert.FromProtoUpsertItems(req.GetItems())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "bad items: %v", err)
	}
	res, err := s.items.Upsert(ctx, userID, ups)
	if err != nil {
		if errors.Is(err, errs.ErrVersionConflict) {
			return nil, status.Error(codes.FailedPrecondition, "version conflict")
		}
		return nil, status.Errorf(codes.Internal, "upsert: %v", err)
	}
	uir := &pb.UpsertItemsResponse{}
	uir.SetResults(convert.ToProtoItemVersions(res))
	return uir, nil
}

// GetChanges returns changes since a given version for delta synchronization.
func (s *Server) GetChanges(ctx context.Context, req *pb.GetChangesRequest) (*pb.GetChangesResponse, error) {
	userID, err := s.userIDFromCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "no auth")
	}
	cs, err := s.items.GetChanges(ctx, userID, req.GetSinceVer())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get changes: %v", err)
	}

	gcr := &pb.GetChangesResponse{}
	gcr.SetChanges(convert.ToProtoChanges(cs))
	return gcr, nil
}

// GetItem returns a single item by id.
func (s *Server) GetItem(ctx context.Context, req *pb.GetItemRequest) (*pb.GetItemResponse, error) {
	userID, err := s.userIDFromCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "no auth")
	}
	itemID, err := uuid.FromString(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "bad id")
	}
	it, err := s.items.GetOne(ctx, userID, itemID)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "not found")
		}
		return nil, status.Errorf(codes.Internal, "get item: %v", err)
	}
	return convert.ToProtoGetItemResponse(*it), nil
}

// DeleteItem marks an item as deleted (tombstone).
func (s *Server) DeleteItem(ctx context.Context, req *pb.DeleteItemRequest) (*pb.DeleteItemResponse, error) {
	userID, err := s.userIDFromCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "no auth")
	}
	itemID, err := uuid.FromString(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "bad id")
	}
	ver, err := s.items.Delete(ctx, userID, itemID, req.GetBaseVer())
	if err != nil {
		switch {
		case errors.Is(err, errs.ErrVersionConflict):
			return nil, status.Error(codes.FailedPrecondition, "version conflict")
		case errors.Is(err, errs.ErrNotFound):
			return nil, status.Error(codes.NotFound, "not found")
		default:
			return nil, status.Errorf(codes.Internal, "delete: %v", err)
		}
	}

	dir := &pb.DeleteItemResponse{}
	dir.SetResult(convert.ToProtoItemVersion(ver))
	return dir, nil
}

// userIDFromCtx: extract "authorization: Bearer <JWT>", verify HS256, return sub as UUID.
func (s *Server) userIDFromCtx(ctx context.Context) (uuid.UUID, error) {
	tok, err := bearerTokenFromMD(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	var claims jwt.RegisteredClaims
	parsed, err := jwt.ParseWithClaims(tok, &claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return s.signKey, nil
	})
	if err != nil || !parsed.Valid {
		return uuid.Nil, errors.New("invalid token")
	}

	v := jwt.NewValidator(jwt.WithLeeway(30 * time.Second))
	if err := v.Validate(&claims); err != nil {
		return uuid.Nil, errors.New("token expired or not valid yet")
	}

	id, err := uuid.FromString(claims.Subject)
	if err != nil {
		return uuid.Nil, errors.New("bad subject")
	}
	return id, nil
}

func bearerTokenFromMD(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("no metadata")
	}
	for _, v := range md.Get("authorization") {
		v = strings.TrimSpace(v)
		if len(v) >= 7 && strings.EqualFold(v[:7], "bearer ") {
			t := strings.TrimSpace(v[7:])
			if t != "" {
				return t, nil
			}
		}
	}
	return "", errors.New("no bearer token")
}

func (s *Server) SetWrappedDEK(ctx context.Context, r *pb.SetWrappedDEKRequest) (*pb.SetWrappedDEKResponse, error) {
	userID, err := s.userIDFromCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "no auth")
	}
	if len(r.GetWrappedDek()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "empty wrapped_dek")
	}

	if err := s.auth.SetWrappedDEK(ctx, userID, r.GetWrappedDek()); err != nil {
		if errors.Is(err, errs.ErrVersionConflict) {
			return nil, status.Error(codes.FailedPrecondition, "already initialized")
		}
		return nil, status.Errorf(codes.Internal, "set wrapped dek: %v", err)
	}
	return &pb.SetWrappedDEKResponse{}, nil
}
