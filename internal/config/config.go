package config

import (
	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Config holds all environemnt-based configuration for the device.
type Config struct {
	GRPCPort    int    `env:"GRPC_PORT" envDefault:"50051"`
	HTTPPort    int    `env:"HTTP_PORT" envDefault:"8080"`
	DatabaseURL string `env:"DATABASE_URL,required"`
	RedisURL    string `env:"REDIS_URL,required"`
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
