package server

import (
	"context"
	"fmt"
	"log"
	"log/slog"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/config"
	"github.com/dwikynator/core-auth/internal/database"
	internalredis "github.com/dwikynator/core-auth/internal/redis"
	"github.com/dwikynator/minato"
	"github.com/dwikynator/minato/merr"
	"github.com/dwikynator/minato/middleware"
	"google.golang.org/grpc"
)

func main() {
	if err := run(); err != nil {
		log.Fatal("fatal: %v", err)
	}
}

func run() error {
	ctx := context.Background()

	// 1. Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	slog.Info("configuration loaded", "grpc_port", cfg.GRPCPort, "http_port", cfg.HTTPPort)

	// 2. Connect to Postgres
	db, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	slog.Info("postgres connected")

	// 3. Connect to Redis
	rdb, err := internalredis.NewClient(ctx, cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("connect redis: %w", err)
	}
	slog.Info("redis connected")

	// 4. Create the minato server
	grpcAddr := fmt.Sprintf(":%d", cfg.GRPCPort)
	httpAddr := fmt.Sprintf(":%d", cfg.HTTPPort)

	server := minato.New(
		minato.WithAddr(httpAddr),
		minato.WithGRPCAddr(grpcAddr),
		minato.WithGRPCReflection(),
		minato.WithGatewayMuxOptions(merr.WithGatewayErrorHandler()),

		// Built-in /healthz and /readyz
		minato.WithHealthCheck(),
		minato.WithReadinessCheck("postgres", func(ctx context.Context) error {
			return db.Ping(ctx)
		}),
		minato.WithReadinessCheck("redis", func(ctx context.Context) error {
			return rdb.Ping(ctx).Err()
		}),

		// Graceful shutdown teardown — called in LIFO order
		minato.WithCloser("redis", func() error {
			return rdb.Close()
		}),
		minato.WithCloser("postgres", func() error {
			db.Close()
			return nil
		}),
	)

	// 5. Register cross-transport middleware (HTTP + gRPC)
	// RecoveryPlugin MUST be first — outermost wrapper catches all panics.
	server.UsePlugin(
		middleware.RecoveryPlugin(),
		middleware.RequestIDPlugin(),
		middleware.LoggerPlugin(),
	)

	// HTTP-only middleware
	server.Use(middleware.CORS())

	// 6. Register gRPC services
	// TODO: Wire up actual handlers
	server.RegisterGRPC(func(s grpc.ServiceRegistrar) {
		authv1.RegisterAuthServiceServer(s, &authv1.UnimplementedAuthServiceServer{})
	})
	server.RegisterGateway(authv1.RegisterAuthServiceHandlerFromEndpoint)

	// 7. Start (blocks until SIGINT/SIGTERM)
	slog.Info("starting server", "grpc_addr", grpcAddr, "http_addr", httpAddr)
	return server.Run()
}
