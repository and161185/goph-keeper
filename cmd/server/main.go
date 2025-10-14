// Command gk-server starts the GophKeeper gRPC server.
package main

import (
	"context"
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	pb "github.com/and161185/goph-keeper/gen/go/gophkeeper/v1"
	"github.com/and161185/goph-keeper/internal/limiter"
	"github.com/and161185/goph-keeper/internal/migrate"
	"github.com/and161185/goph-keeper/internal/repository/postgres"
	grpcserver "github.com/and161185/goph-keeper/internal/server/grpc"
	"github.com/and161185/goph-keeper/internal/service"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

// main parses configuration, runs migrations, and starts a TLS-enabled gRPC server.
func main() {
	// Flags
	addr := flag.String("addr", ":8443", "listen address")
	dsn := flag.String("dsn", "postgres://user:pass@localhost:5432/gk?sslmode=disable", "PostgreSQL DSN")
	jwtKey := flag.String("jwt-key", "", "HS256 signing key (required)")
	accessTTL := flag.Duration("access-ttl", 15*time.Minute, "access token TTL")
	maxBatch := flag.Int("max-batch", 1000, "max upsert batch size")
	certFile := flag.String("tls-cert", "cert.pem", "TLS certificate (PEM)")
	keyFile := flag.String("tls-key", "key.pem", "TLS private key (PEM)")
	dev := flag.Bool("dev", false, "enable server reflection (dev only)")
	flag.Parse()

	logger, _ := zap.NewProduction()
	defer func() { _ = logger.Sync() }()
	logger.Info("starting",
		zap.String("version", version),
		zap.String("buildDate", buildDate),
		zap.String("addr", *addr),
	)

	if *jwtKey == "" {
		logger.Fatal("missing jwt signing key (--jwt-key)")
	}

	creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
	if err != nil {
		logger.Fatal("failed to load TLS cert/key", zap.Error(err))
	}

	// Context with OS signals
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := migrate.Up(ctx, *dsn); err != nil {
		logger.Fatal("migrate up", zap.Error(err))
	}

	// DB pool
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		logger.Fatal("pgxpool.New", zap.Error(err))
	}
	defer pool.Close()

	// Repositories
	db := &postgres.DB{Pool: pool}
	userRepo := postgres.NewUserRepo(db)
	itemRepo := postgres.NewItemRepo(db)

	lim := limiter.NewPG(pool, 15*time.Minute, 5, 15*time.Minute)

	// Services
	authSvc := service.NewAuthService(userRepo, []byte(*jwtKey), *accessTTL, lim)
	itemSvc := service.NewItemService(itemRepo, *maxBatch)

	// gRPC server with interceptors
	s := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(
			grpcserver.RecoverUnary(logger),
			grpcserver.LoggingUnary(logger),
		),
	)

	// App service
	app := grpcserver.New(authSvc, itemSvc, []byte(*jwtKey))
	pb.RegisterGophKeeperServer(s, app)

	// Health & reflection (dev)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(s, hs)
	if *dev {
		reflection.Register(s)
	}

	// Listen
	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Fatal("listen", zap.Error(err))
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening (TLS)", zap.String("addr", *addr))
		errCh <- s.Serve(lis)
	}()

	// Wait for stop
	select {
	case <-ctx.Done():
		// graceful shutdown
		done := make(chan struct{})
		go func() {
			s.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			s.Stop()
		}
	case err := <-errCh:
		logger.Error("server error", zap.Error(err))
		os.Exit(1)
	}

	logger.Info("shutdown complete")
}
