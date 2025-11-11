// Package redis provides Redis client utilities.
package redis

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/GunarsK-portfolio/auth-service/internal/config"
	"github.com/redis/go-redis/v9"
)

// NewClient creates a new Redis client instance.
//
//nolint:staticcheck // Embedded field names required due to ambiguous fields
func NewClient(cfg *config.Config) *redis.Client {
	options := &redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.RedisConfig.Host, cfg.RedisConfig.Port),
		Password: cfg.RedisConfig.Password,
		DB:       0,
	}

	// Enable TLS for production environments
	// Development: no TLS (localhost connections)
	// Production: TLS with proper certificate verification
	if cfg.ServiceConfig.Environment == "production" {
		options.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: cfg.RedisConfig.Host,
		}
	}

	client := redis.NewClient(options)

	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		panic(fmt.Sprintf("Failed to connect to Redis: %v", err))
	}

	return client
}
