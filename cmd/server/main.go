package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"

	"github.com/dwikynator/core-auth/internal/config"
	"github.com/dwikynator/core-auth/internal/infra/audit"
	"github.com/dwikynator/core-auth/internal/infra/database"
	internalredis "github.com/dwikynator/core-auth/internal/infra/redis"

	"github.com/dwikynator/core-auth/internal/libs/crypto"
	"github.com/dwikynator/core-auth/internal/libs/email"

	"github.com/dwikynator/core-auth/internal/oauth"

	oauthgateway "github.com/dwikynator/core-auth/internal/oauth/gateway"

	sessionmiddleware "github.com/dwikynator/core-auth/internal/session/middleware"

	admindelivery "github.com/dwikynator/core-auth/internal/admin/delivery"
	authdelivery "github.com/dwikynator/core-auth/internal/auth/delivery"
	mfadelivery "github.com/dwikynator/core-auth/internal/mfa/delivery"
	oauthdelivery "github.com/dwikynator/core-auth/internal/oauth/delivery"
	sessiondelivery "github.com/dwikynator/core-auth/internal/session/delivery"
	userdelivery "github.com/dwikynator/core-auth/internal/user/delivery"
	verificationdelivery "github.com/dwikynator/core-auth/internal/verification/delivery"

	adminusecase "github.com/dwikynator/core-auth/internal/admin/usecase"
	authusecase "github.com/dwikynator/core-auth/internal/auth/usecase"
	mfausecase "github.com/dwikynator/core-auth/internal/mfa/usecase"
	oauthusecase "github.com/dwikynator/core-auth/internal/oauth/usecase"
	sessionusecase "github.com/dwikynator/core-auth/internal/session/usecase"
	tenantusecase "github.com/dwikynator/core-auth/internal/tenant/usecase"
	userusecase "github.com/dwikynator/core-auth/internal/user/usecase"
	verificationusecase "github.com/dwikynator/core-auth/internal/verification/usecase"

	mfarepo "github.com/dwikynator/core-auth/internal/mfa/repository"
	oauthrepo "github.com/dwikynator/core-auth/internal/oauth/repository"
	sessionrepo "github.com/dwikynator/core-auth/internal/session/repository"
	tenantrepo "github.com/dwikynator/core-auth/internal/tenant/repository"
	userrepo "github.com/dwikynator/core-auth/internal/user/repository"
	verificationrepo "github.com/dwikynator/core-auth/internal/verification/repository"

	"github.com/dwikynator/minato"
	"github.com/dwikynator/minato/merr"
	"github.com/dwikynator/minato/middleware"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	slog.Info("configuration loaded", "grpc_port", cfg.GRPCPort, "http_port", cfg.HTTPPort)

	db, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	slog.Info("postgres connected")

	rdb, err := internalredis.NewClient(ctx, cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("connect redis: %w", err)
	}
	slog.Info("redis connected")

	tokenIssuer, err := crypto.NewTokenIssuer(cfg.RSAPrivateKeyPath, cfg.JWTIssuer)
	if err != nil {
		return fmt.Errorf("init token issuer: %w", err)
	}
	slog.Info("token issuer ready", "kid", tokenIssuer.KeyID())

	jwksJSON, err := crypto.BuildJWKS(tokenIssuer.PublicKey(), tokenIssuer.KeyID())
	if err != nil {
		return fmt.Errorf("build jwks: %w", err)
	}

	emailClient := email.NewResendClient(cfg.ResendAPIKey, cfg.ResendFrom)
	slog.Info("email client ready", "from", cfg.ResendFrom)

	userRepo := userrepo.NewPostgresUserRepo(db)
	verificationRepo := verificationrepo.NewPostgresVerificationRepo(db)
	blacklistRepo := sessionrepo.NewRedisBlacklist(rdb)
	sessionRepo := sessionrepo.NewPostgresSessionRepo(db)
	tenantConfigRepo := tenantrepo.NewPostgresTenantConfigRepo(db)
	mfaCredRepo := mfarepo.NewPostgresMFARepo(db)
	mfaSessionStore := mfarepo.NewRedisMFASessionStore(rdb)
	userProviderRepo := oauthrepo.NewPostgresUserProviderRepo(db)
	oauthStateStore := oauthrepo.NewRedisStateStore(rdb)
	linkSessionStore := oauthrepo.NewRedisLinkSessionStore(rdb)

	mfaKey, err := hex.DecodeString(cfg.MFAEncryptionKey)
	if err != nil || len(mfaKey) != 32 {
		return fmt.Errorf("MFA_ENCRYPTION_KEY must be 64 hex characters (32 bytes): %w", err)
	}

	auditLogger := audit.NewLogger(slog.Default())

	var oauthProviders []oauth.OAuthProvider
	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		oauthProviders = append(oauthProviders, oauthgateway.NewGoogleProvider(
			cfg.GoogleClientID,
			cfg.GoogleClientSecret,
			cfg.BaseURL,
		))
		slog.Info("oauth provider registered", "provider", "google")
	}

	userUc := userusecase.NewUserUseCase(userRepo, auditLogger)
	tenantUc := tenantusecase.NewTenantUseCase(tenantConfigRepo)
	sessionUc := sessionusecase.NewSessionUseCase(sessionRepo, blacklistRepo,
		tokenIssuer, tenantUc, userUc, auditLogger)
	mfaUc := mfausecase.NewMFAService(mfaCredRepo, mfaSessionStore,
		userUc, sessionUc, auditLogger, mfaKey, cfg.JWTIssuer)
	oauthUc := oauthusecase.NewOAuthUseCase(oauthStateStore, linkSessionStore,
		userProviderRepo, userUc, userUc,
		mfaUc, mfaUc, sessionUc,
		auditLogger, oauthProviders...)
	verificationUc := verificationusecase.NewVerificationUseCase(verificationRepo, userUc,
		emailClient, userUc, sessionUc,
		auditLogger, cfg.FrontendURL,
		cfg.WhatsAppBusinessPhone)
	adminUc := adminusecase.NewAdminUseCase(userUc, userUc, sessionUc, auditLogger)
	authUc := authusecase.NewAuthUsecase(userUc, userUc, verificationUc, sessionUc, mfaUc, mfaUc, auditLogger)

	slog.Info("all use cases ready")

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

	tokenValidator := sessionmiddleware.NewTokenValidator(tokenIssuer.PublicKey(), cfg.JWTIssuer, blacklistRepo)

	server.UsePlugin(
		middleware.RecoveryPlugin(),
		middleware.RequestIDPlugin(),
		middleware.LoggerPlugin(),
	)

	// HTTP-only middleware (browser / REST concerns)
	server.Use(middleware.CORS())

	var publicMethods []string
	publicMethods = append(publicMethods, authdelivery.PublicMethods()...)
	publicMethods = append(publicMethods, sessiondelivery.PublicMethods()...)
	publicMethods = append(publicMethods, mfadelivery.PublicMethods()...)
	publicMethods = append(publicMethods, verificationdelivery.PublicMethods()...)
	publicMethods = append(publicMethods, oauthdelivery.PublicMethods()...)

	server.UseGRPC(middleware.AuthInterceptor(
		middleware.WithAuthSkipPaths(publicMethods...),
		middleware.WithAuthValidator(tokenValidator.Validate),
	))

	authdelivery.RegisterAuthGRPCHandler(server, authUc, mfaUc, tenantUc)
	userdelivery.RegisterUserGRPCHandler(server, userUc, mfaUc)
	admindelivery.RegisterAdminGRPCHandler(server, adminUc)
	sessiondelivery.RegisterSessionGRPCHandler(server, sessionUc)
	mfadelivery.RegisterMFAGRPCHandler(server, mfaUc, tenantUc)
	oauthdelivery.RegisterOAuthGRPCHandler(server, oauthUc, tenantUc, mfaUc)
	verificationdelivery.RegisterVerificationGRPCHandler(server, verificationUc, tenantUc, mfaUc)

	authdelivery.RegisterAuthHTTPHandler(server, jwksJSON, cfg.BaseURL, cfg.JWTIssuer)

	slog.Info("starting server", "grpc_addr", grpcAddr, "http_addr", httpAddr)
	return server.Run()
}
