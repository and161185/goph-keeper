package grpcserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "127.0.0.1:12345" }

func TestLoggingUnary_Passthrough(t *testing.T) {
	t.Parallel()

	log := zaptest.NewLogger(t)
	ic := LoggingUnary(log)

	ctx := context.Background()

	ctx = peer.NewContext(ctx, &peer.Peer{Addr: fakeAddr{}})

	h := func(ctx context.Context, req any) (any, error) { return "ok", nil }
	info := &grpc.UnaryServerInfo{FullMethod: "/gk.Service/Method"}

	resp, err := ic(ctx, "req", info, h)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if s, _ := resp.(string); s != "ok" {
		t.Fatalf("resp mismatch: %v", resp)
	}

	wantErr := errors.New("boom")
	hErr := func(ctx context.Context, req any) (any, error) { return nil, wantErr }
	_, err = ic(ctx, "req", info, hErr)
	if !errors.Is(err, wantErr) {
		t.Fatalf("want original error, got: %v", err)
	}
}

func TestRecoverUnary_CatchesPanic(t *testing.T) {
	t.Parallel()

	log := zaptest.NewLogger(t)
	ic := RecoverUnary(log)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/gk.Service/Panic"}

	panicH := func(ctx context.Context, req any) (any, error) {
		panic("oh no")
	}

	_, err := ic(ctx, "req", info, panicH)
	if err == nil {
		t.Fatalf("expected error from panic")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Internal {
		t.Fatalf("want codes.Internal, got: %v", err)
	}
}

func TestRecoverUnary_NoPanicPassThrough(t *testing.T) {
	t.Parallel()

	log := zaptest.NewLogger(t)
	ic := RecoverUnary(log)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/gk.Service/Ok"}

	h := func(ctx context.Context, req any) (any, error) { return 42, nil }

	resp, err := ic(ctx, "req", info, h)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp.(int) != 42 {
		t.Fatalf("resp mismatch: %v", resp)
	}
}

func TestLoggingUnary_DurationFieldDoesNotBlock(t *testing.T) {
	t.Parallel()

	log := zaptest.NewLogger(t)
	ic := LoggingUnary(log)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/gk.Service/Sleep"}
	h := func(ctx context.Context, req any) (any, error) {
		time.Sleep(5 * time.Millisecond)
		return "done", nil
	}

	start := time.Now()
	resp, err := ic(ctx, "req", info, h)
	if err != nil || resp.(string) != "done" {
		t.Fatalf("unexpected result: %v, %v", resp, err)
	}
	if time.Since(start) < 5*time.Millisecond {
		t.Fatalf("duration should reflect handler time")
	}
}
