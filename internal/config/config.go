// Package config handles configuration loading for the auth service.
package config

import (
	"time"

	common "github.com/GunarsK-portfolio/portfolio-common/config"
)

// Config holds all configuration for the auth service.
type Config struct {
	DBHost           string
	DBPort           string
	DBUser           string
	DBPassword       string
	DBName           string
	RedisHost        string
	RedisPort        string
	RedisPassword    string
	JWTSecret        string
	JWTAccessExpiry  time.Duration
	JWTRefreshExpiry time.Duration
	Port             string
	Environment      string
}

// Load reads configuration from environment variables.
func Load() *Config {
	return &Config{
		DBHost:           common.GetEnvRequired("DB_HOST"),
		DBPort:           common.GetEnvRequired("DB_PORT"),
		DBUser:           common.GetEnvRequired("DB_USER"),
		DBPassword:       common.GetEnvRequired("DB_PASSWORD"),
		DBName:           common.GetEnvRequired("DB_NAME"),
		RedisHost:        common.GetEnvRequired("REDIS_HOST"),
		RedisPort:        common.GetEnvRequired("REDIS_PORT"),
		RedisPassword:    common.GetEnv("REDIS_PASSWORD", ""),
		JWTSecret:        common.GetEnvRequired("JWT_SECRET"),
		JWTAccessExpiry:  parseDuration(common.GetEnv("JWT_ACCESS_EXPIRY", "15m"), 15*time.Minute),
		JWTRefreshExpiry: parseDuration(common.GetEnv("JWT_REFRESH_EXPIRY", "168h"), 168*time.Hour),
		Port:             common.GetEnv("PORT", "8084"),
		Environment:      common.GetEnv("ENVIRONMENT", "development"),
	}
}

func parseDuration(value string, defaultValue time.Duration) time.Duration {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}
	return duration
}
