package config

import (
	"os"
	"time"
)

type Config struct {
	DBHost           string
	DBPort           string
	DBUser           string
	DBPassword       string
	DBName           string
	RedisHost        string
	RedisPort        string
	JWTSecret        string
	JWTAccessExpiry  time.Duration
	JWTRefreshExpiry time.Duration
	Port             string
}

func Load() *Config {
	return &Config{
		DBHost:           getEnvRequired("DB_HOST"),
		DBPort:           getEnvRequired("DB_PORT"),
		DBUser:           getEnvRequired("DB_USER"),
		DBPassword:       getEnvRequired("DB_PASSWORD"),
		DBName:           getEnvRequired("DB_NAME"),
		RedisHost:        getEnvRequired("REDIS_HOST"),
		RedisPort:        getEnvRequired("REDIS_PORT"),
		JWTSecret:        getEnvRequired("JWT_SECRET"),
		JWTAccessExpiry:  parseDuration(getEnv("JWT_ACCESS_EXPIRY", "15m"), 15*time.Minute),
		JWTRefreshExpiry: parseDuration(getEnv("JWT_REFRESH_EXPIRY", "168h"), 168*time.Hour),
		Port:             getEnv("PORT", "8084"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvRequired(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic("Required environment variable " + key + " is not set")
	}
	return value
}

func parseDuration(value string, defaultValue time.Duration) time.Duration {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}
	return duration
}
