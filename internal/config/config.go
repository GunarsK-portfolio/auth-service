// Package config handles configuration loading for the auth service.
package config

import (
	"os"
	"strings"

	common "github.com/GunarsK-portfolio/portfolio-common/config"
)

// Config holds all configuration for the auth service.
type Config struct {
	common.DatabaseConfig
	common.ServiceConfig
	common.RedisConfig
	common.JWTConfig
	common.CookieConfig
	DeniedSelfAssignRoles []string
}

// Load reads configuration from environment variables.
func Load() *Config {
	cfg := &Config{
		DatabaseConfig:        common.NewDatabaseConfig(),
		ServiceConfig:         common.NewServiceConfig(8084),
		RedisConfig:           common.NewRedisConfig(),
		JWTConfig:             common.NewJWTConfig(),
		CookieConfig:          common.NewCookieConfig(),
		DeniedSelfAssignRoles: parseDeniedRoles(),
	}

	// Defense-in-depth: Explicitly verify JWT secret is configured
	//nolint:staticcheck // Explicit field access for security clarity
	if cfg.JWTConfig.Secret == "" {
		panic("JWT secret must be configured")
	}

	return cfg
}

func parseDeniedRoles() []string {
	val := os.Getenv("DENIED_SELF_ASSIGN_ROLES")
	if val == "" {
		return []string{"admin", "rpg-admin"}
	}
	var roles []string
	for _, r := range strings.Split(val, ",") {
		if trimmed := strings.TrimSpace(r); trimmed != "" {
			roles = append(roles, trimmed)
		}
	}
	return roles
}
