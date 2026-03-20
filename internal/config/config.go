// Package config handles configuration loading for the auth service.
package config

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	common "github.com/GunarsK-portfolio/portfolio-common/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Config holds all configuration for the auth service.
type Config struct {
	common.DatabaseConfig
	common.ServiceConfig
	common.RedisConfig
	common.JWTConfig
	common.CookieConfig
	common.RabbitMQConfig
	DeniedSelfAssignRoles []string
	VerifyRateLimitMax    int64
	VerifyRateLimitWindow time.Duration
	GoogleOAuth           *oauth2.Config
}

// Load reads configuration from environment variables.
func Load() *Config {
	cfg := &Config{
		DatabaseConfig:        common.NewDatabaseConfig(),
		ServiceConfig:         common.NewServiceConfig(8084),
		RedisConfig:           common.NewRedisConfig(),
		JWTConfig:             common.NewJWTConfig(),
		CookieConfig:          common.NewCookieConfig(),
		RabbitMQConfig:        common.NewRabbitMQConfig(),
		DeniedSelfAssignRoles: parseDeniedRoles(),
		VerifyRateLimitMax:    parseIntOrDefault("VERIFY_RATE_LIMIT_MAX", 3),
		VerifyRateLimitWindow: parseDurationOrDefault("VERIFY_RATE_LIMIT_WINDOW", time.Hour),
	}

	if clientID := os.Getenv("GOOGLE_CLIENT_ID"); clientID != "" {
		cfg.GoogleOAuth = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		}
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
	if strings.TrimSpace(val) == "" {
		defaults := []string{"admin", "rpg-admin"}
		slog.Info("DENIED_SELF_ASSIGN_ROLES not set, using defaults", "roles", defaults)
		return defaults
	}
	var roles []string
	for _, r := range strings.Split(val, ",") {
		if trimmed := strings.TrimSpace(r); trimmed != "" {
			roles = append(roles, trimmed)
		}
	}
	return roles
}

func parseIntOrDefault(key string, defaultVal int64) int64 {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		slog.Warn("Invalid integer for env var, using default", "key", key, "default", defaultVal)
		return defaultVal
	}
	if n <= 0 {
		slog.Warn("Non-positive integer for env var, using default", "key", key, "default", defaultVal)
		return defaultVal
	}
	return n
}

func parseDurationOrDefault(key string, defaultVal time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		slog.Warn("Invalid duration for env var, using default", "key", key, "default", defaultVal)
		return defaultVal
	}
	if d <= 0 {
		slog.Warn("Non-positive duration for env var, using default", "key", key, "default", defaultVal)
		return defaultVal
	}
	return d
}
