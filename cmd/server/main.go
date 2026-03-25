package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"

	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/core-auth/internal/auth"
	"github.com/dwikynator/core-auth/internal/config"
	credrepo "github.com/dwikynator/core-auth/internal/credentials/repository"
	identityrepo "github.com/dwikynator/core-auth/internal/identity/repository"
	"github.com/dwikynator/core-auth/internal/infrastructure/audit"
	"github.com/dwikynator/core-auth/internal/infrastructure/database"
	internalredis "github.com/dwikynator/core-auth/internal/infrastructure/redis"
	"github.com/dwikynator/core-auth/internal/libs/crypto"
	"github.com/dwikynator/core-auth/internal/libs/email"
	"github.com/dwikynator/core-auth/internal/oauth"
	oauthrepo "github.com/dwikynator/core-auth/internal/oauth/repository"
	sessionrepo "github.com/dwikynator/core-auth/internal/session/repository"
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
	userRepo := identityrepo.NewPostgresUserRepo(db)
	verificationRepo := verificationrepo.NewPostgresVerificationRepo(db)
	blacklistRepo := sessionrepo.NewRedisBlacklist(rdb)
	sessionRepo := sessionrepo.NewPostgresSessionRepo(db)
	tenantConfigRepo := identityrepo.NewPostgresTenantConfigRepo(db)
	mfaCredRepo := credrepo.NewPostgresMFARepo(db)
	mfaSessionStore := credrepo.NewRedisMFASessionStore(rdb)

	// Parse the MFA encryption key from hex.
	mfaKey, err := hex.DecodeString(cfg.MFAEncryptionKey)
	if err != nil || len(mfaKey) != 32 {
		return fmt.Errorf("MFA_ENCRYPTION_KEY must be 64 hex characters (32 bytes): %w", err)
	}

	tokenSvc := auth.NewTokenService(tokenIssuer)
	verificationSvc := verification.NewService(verificationRepo, emailClient, cfg.FrontendURL)
	mfaSvc := auth.NewMFAService(mfaCredRepo, mfaSessionStore, mfaKey, cfg.JWTIssuer)

	// Initialize audit logger
	auditLogger := audit.NewLogger(slog.Default())

	// 6b. Initialize OAuth2 infrastructure
	userProviderRepo := credrepo.NewPostgresUserProviderRepo(db)
	oauthStateStore := oauthrepo.NewRedisStateStore(rdb)
	linkSessionStore := credrepo.NewRedisLinkSessionStore(rdb)

	var oauthProviders []oauth.OAuthProvider
	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		oauthProviders = append(oauthProviders, oauth.NewGoogleProvider(
			cfg.GoogleClientID,
			cfg.GoogleClientSecret,
			cfg.BaseURL,
		))
		slog.Info("oauth provider registered", "provider", "google")
	}

	oauthSvc := oauth.NewOAuthService(oauthStateStore, linkSessionStore, userRepo, userProviderRepo, oauthProviders...)

	authSvc := auth.NewService(userRepo, tokenSvc, verificationSvc,
		blacklistRepo, sessionRepo, tenantConfigRepo, userProviderRepo, mfaSvc,
		cfg.WhatsAppBusinessPhone, auditLogger, oauthSvc)

	tokenValidator := auth.NewTokenValidator(
		tokenIssuer.PublicKey(),
		tokenIssuer.Issuer(),
		blacklistRepo,
	)
	slog.Info("all services ready")

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

	// 8. Cross-transport plugins (runs on BOTH HTTP and gRPC perimeters)
	// RecoveryPlugin MUST be first — outermost wrapper catches all panics.
	server.UsePlugin(
		middleware.RecoveryPlugin(),
		middleware.RequestIDPlugin(),
		middleware.LoggerPlugin(),
	)

	// HTTP-only middleware (browser / REST concerns)
	server.Use(middleware.CORS())

	// 9. Auth interceptor — gRPC perimeter only (Template C from middleware guide).
	// The grpc-gateway automatically forwards the HTTP Authorization header as
	// the gRPC `authorization` metadata key, so every gateway request is
	// validated exactly once, at the gRPC boundary — no double-execution.
	server.UseGRPC(middleware.AuthInterceptor(
		middleware.WithAuthSkipPaths(auth.PublicMethods()...),
		middleware.WithAuthValidator(tokenValidator.Validate),
	))

	// 10. Register gRPC services
	server.RegisterGRPC(func(s grpc.ServiceRegistrar) {
		authv1.RegisterAuthServiceServer(s, authSvc)
	})
	server.RegisterGateway(authv1.RegisterAuthServiceHandlerFromEndpoint)

	// 11. Pure HTTP routes (not gRPC-gateway, not subject to gRPC auth interceptor)
	server.Router().Get("/.well-known/jwks.json", auth.NewJWKSHandler(jwksJSON))
	server.Router().Get("/.well-known/openid-configuration", auth.NewOIDCDiscoveryHandler(cfg.BaseURL, cfg.JWTIssuer))

	// 12. Start (blocks until SIGINT/SIGTERM)
	slog.Info("starting server", "grpc_addr", grpcAddr, "http_addr", httpAddr)
	return server.Run()
}
