package grpcserver

import (
	"context"
	"runtime/debug"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// LoggingUnary returns a unary server interceptor for structured logging.
func LoggingUnary(log *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := next(ctx, req)
		code := status.Code(err)

		var remote string
		if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
			remote = p.Addr.String()
		}

		// никаких пейлоадов — только метаданные
		log.Info("grpc",
			zap.String("method", info.FullMethod),
			zap.String("code", code.String()),
			zap.Duration("dur", time.Since(start)),
			zap.String("peer", remote),
		)
		return resp, err
	}
}

// RecoverUnary returns a unary server interceptor that recovers from panics.
func RecoverUnary(log *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic",
					zap.Any("reason", r),
					zap.ByteString("stack", debug.Stack()),
					zap.String("method", info.FullMethod),
				)
				err = status.Error(codes.Internal, "internal")
			}
		}()
		return next(ctx, req)
	}
}
