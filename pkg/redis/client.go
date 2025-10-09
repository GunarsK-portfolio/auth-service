package redis

import (
	"context"
	"fmt"

	"github.com/GunarsK-portfolio/auth-service/internal/config"
	"github.com/redis/go-redis/v9"
)

func NewClient(cfg *config.Config) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort),
		DB:   0,
	})

	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		panic(fmt.Sprintf("Failed to connect to Redis: %v", err))
	}

	return client
}
