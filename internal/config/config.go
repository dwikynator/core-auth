package config

import (
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Config holds all environemnt-based configuration for the device.
type Config struct {
	GRPCPort    int    `env:"GRPC_PORT" envDefault:"50051"`
	HTTPPort    int    `env:"HTTP_PORT" envDefault:"8080"`
	DatabaseURL string `env:"DATABASE_URL,required"`
	RedisURL    string `env:"REDIS_URL,required"`

	// JWT
	RSAPrivateKeyPath string `env:"RSA_PRIVATE_KEY_PATH,required"`
	JWTIssuer         string `env:"JWT_ISSUER,required"`

	// Email & Verification
	ResendAPIKey string `env:"RESEND_API_KEY,required"`
	ResendFrom   string `env:"RESEND_FROM" envDefault:"onboarding@resend.dev"`
	FrontendURL  string `env:"FRONTEND_URL" envDefault:"http://localhost:3000"`

	BaseURL string `env:"BASE_URL" envDefault:"http://localhost:8080"`

	// MFA
	MFAEncryptionKey string `env:"MFA_ENCRYPTION_KEY,required"` // 32-byte hex-encoded AES-256 key

	WhatsAppBusinessPhone string `env:"WHATSAPP_BUSINESS_PHONE" envDefault:"+6281234567890"`

	// OAuth2 — Google
	GoogleClientID     string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET"`

	// Rate Limiting & Account Lockout
	RateLimitMaxFailedPerIP      int           `env:"RATE_LIMIT_MAX_FAILED_PER_IP"      envDefault:"30"`
	RateLimitIPWindow            time.Duration `env:"RATE_LIMIT_IP_WINDOW"              envDefault:"15m"`
	RateLimitMaxFailedPerAccount int           `env:"RATE_LIMIT_MAX_FAILED_PER_ACCOUNT" envDefault:"10"`
	RateLimitAccountLockout      time.Duration `env:"RATE_LIMIT_ACCOUNT_LOCKOUT"        envDefault:"15m"`

	SecureCookie bool `env:"SECURE_COOKIE" envDefault:"true"`

	// Advanced Abuse Detection
	SuspiciousLoginEnabled bool          `env:"SUSPICIOUS_LOGIN_ENABLED"    envDefault:"true"`
	SuspiciousLoginWindow  time.Duration `env:"SUSPICIOUS_LOGIN_WINDOW"     envDefault:"2160h"`      // 90 days
	SuspiciousLoginAction  string        `env:"SUSPICIOUS_LOGIN_ACTION"     envDefault:"audit_only"` // "audit_only" | "challenge_mfa"

	// Observability — OpenTelemetry
	// Leave empty to disable tracing (no-op TracerProvider is used instead).
	OTELEndpoint string `env:"OTEL_EXPORTER_OTLP_ENDPOINT" envDefault:""`
}

// Load reads .env (if present) and parses environment variables into Config.
func Load() (*Config, error) {
	// Best-effort .env load; ignore error if file doesn't exists.
	_ = godotenv.Load()

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
