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
func NewClient(cfg *config.Config) *redis.Client {
	options := &redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort),
		Password: cfg.RedisPassword,
		DB:       0,
	}

	// Enable TLS for production environments
	// Development: no TLS (localhost connections)
	// Production: TLS with proper certificate verification
	if cfg.Environment == "production" {
		options.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: cfg.RedisHost,
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
