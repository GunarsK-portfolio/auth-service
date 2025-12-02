// Package config handles configuration loading for the auth service.
package config

import (
	common "github.com/GunarsK-portfolio/portfolio-common/config"
)

// Config holds all configuration for the auth service.
type Config struct {
	common.DatabaseConfig
	common.ServiceConfig
	common.RedisConfig
	common.JWTConfig
}

// Load reads configuration from environment variables.
func Load() *Config {
	cfg := &Config{
		DatabaseConfig: common.NewDatabaseConfig(),
		ServiceConfig:  common.NewServiceConfig(8084),
		RedisConfig:    common.NewRedisConfig(),
		JWTConfig:      common.NewJWTConfig(),
	}

	// Defense-in-depth: Explicitly verify JWT secret is configured
	//nolint:staticcheck // Explicit field access for security clarity
	if cfg.JWTConfig.Secret == "" {
		panic("JWT secret must be configured")
	}

	return cfg
}
