package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/auth"
	authrepo "github.com/dwikynator/core-auth/internal/auth/repository"
	"github.com/dwikynator/core-auth/internal/config"
	"github.com/dwikynator/core-auth/internal/crypto"
	"github.com/dwikynator/core-auth/internal/database"
	"github.com/dwikynator/core-auth/internal/email"
	internalredis "github.com/dwikynator/core-auth/internal/redis"
	"github.com/dwikynator/core-auth/internal/verification"
	verificationrepo "github.com/dwikynator/core-auth/internal/verification/repository"

	"github.com/dwikynator/minato"
	"github.com/dwikynator/minato/merr"
	"github.com/dwikynator/minato/middleware"
	"google.golang.org/grpc"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
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

	// 4. Initialize JWT infrastructure
	tokenIssuer, err := crypto.NewTokenIssuer(cfg.RSAPrivateKeyPath, cfg.JWTIssuer)
	if err != nil {
		return fmt.Errorf("init token issuer: %w", err)
	}
	slog.Info("token issuer ready", "kid", tokenIssuer.KeyID())

	// Pre-compute JWKS JSON (computed once, served on every request)
	jwksJSON, err := crypto.BuildJWKS(tokenIssuer.PublicKey(), tokenIssuer.KeyID())
	if err != nil {
		return fmt.Errorf("build jwks: %w", err)
	}

	// 5. Initialize email infrastructure
	emailClient := email.NewResendClient(cfg.ResendAPIKey, cfg.ResendFrom)
	slog.Info("email client ready", "from", cfg.ResendFrom)

	// 6. Initialize domain services
	userRepo := authrepo.NewPostgresUserRepo(db)
	verificationRepo := verificationrepo.NewPostgresVerificationRepo(db)

	tokenSvc := auth.NewTokenService(tokenIssuer)
	verificationSvc := verification.NewService(verificationRepo, emailClient, cfg.FrontendURL)
	authSvc := auth.NewService(userRepo, tokenSvc, verificationSvc)
	slog.Info("verification service ready")

	// 7. Create the minato server
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

	// 8. Register cross-transport middleware (HTTP + gRPC)
	// RecoveryPlugin MUST be first — outermost wrapper catches all panics.
	server.UsePlugin(
		middleware.RecoveryPlugin(),
		middleware.RequestIDPlugin(),
		middleware.LoggerPlugin(),
	)

	// HTTP-only middleware
	server.Use(middleware.CORS())

	// 9. Register gRPC services
	server.RegisterGRPC(func(s grpc.ServiceRegistrar) {
		authv1.RegisterAuthServiceServer(s, authSvc)
	})
	server.RegisterGateway(authv1.RegisterAuthServiceHandlerFromEndpoint)

	// 10. Register custom HTTP routes
	server.Router().Get("/.well-known/jwks.json", auth.NewJWKSHandler(jwksJSON))

	// 11. Start (blocks until SIGINT/SIGTERM)
	slog.Info("starting server", "grpc_addr", grpcAddr, "http_addr", httpAddr)
	return server.Run()
}
