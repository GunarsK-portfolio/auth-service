// Package config handles configuration loading for the auth service.
package config

import (
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"

	common "github.com/GunarsK-portfolio/portfolio-common/config"
)

// Config holds all configuration for the auth service.
type Config struct {
	DBHost           string        `validate:"required"`
	DBPort           string        `validate:"required,number,min=1,max=65535"`
	DBUser           string        `validate:"required"`
	DBPassword       string        `validate:"required"`
	DBName           string        `validate:"required"`
	RedisHost        string        `validate:"required"`
	RedisPort        string        `validate:"required,number,min=1,max=65535"`
	RedisPassword    string        // Optional, no validation
	JWTSecret        string        `validate:"required,min=32"`
	JWTAccessExpiry  time.Duration `validate:"gt=0"`
	JWTRefreshExpiry time.Duration `validate:"gt=0"`
	Port             string        `validate:"required,number,min=1,max=65535"`
	Environment      string        `validate:"oneof=development staging production"`
}

// Load reads configuration from environment variables.
func Load() *Config {
	cfg := &Config{
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

	// Validate configuration
	validate := validator.New()
	if err := validate.Struct(cfg); err != nil {
		panic(fmt.Sprintf("Invalid configuration: %v", err))
	}

	return cfg
}

func parseDuration(value string, defaultValue time.Duration) time.Duration {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}
	return duration
}
