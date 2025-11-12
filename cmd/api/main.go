// Package main is the entry point for the auth service.
package main

import (
	"fmt"
	"log"
	"os"

	_ "github.com/GunarsK-portfolio/auth-service/docs"
	"github.com/GunarsK-portfolio/auth-service/internal/config"
	"github.com/GunarsK-portfolio/auth-service/internal/handlers"
	"github.com/GunarsK-portfolio/auth-service/internal/repository"
	"github.com/GunarsK-portfolio/auth-service/internal/routes"
	"github.com/GunarsK-portfolio/auth-service/internal/service"
	"github.com/GunarsK-portfolio/auth-service/pkg/redis"
	commondb "github.com/GunarsK-portfolio/portfolio-common/database"
	"github.com/GunarsK-portfolio/portfolio-common/logger"
	"github.com/GunarsK-portfolio/portfolio-common/metrics"
	"github.com/gin-gonic/gin"
)

// @title Portfolio Auth Service API
// @version 1.0
// @description Authentication and authorization service for portfolio system
// @host localhost:8084
// @BasePath /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize structured logger
	appLogger := logger.New(logger.Config{
		Level:       os.Getenv("LOG_LEVEL"),  // debug, info, warn, error
		Format:      os.Getenv("LOG_FORMAT"), // json, text (default: json)
		ServiceName: "auth-service",
		AddSource:   os.Getenv("LOG_SOURCE") == "true", // Add file:line to logs
	})

	appLogger.Info("Starting auth service", "version", "1.0")

	// Initialize Prometheus metrics
	metricsCollector := metrics.New(metrics.Config{
		ServiceName: "auth",
		Namespace:   "portfolio",
	})

	// Initialize database
	//nolint:staticcheck // Embedded field name required due to ambiguous fields (DatabaseConfig.Host vs RedisConfig.Host)
	db, err := commondb.Connect(commondb.PostgresConfig{
		Host:     cfg.DatabaseConfig.Host,
		Port:     cfg.DatabaseConfig.Port,
		User:     cfg.DatabaseConfig.User,
		Password: cfg.DatabaseConfig.Password,
		DBName:   cfg.DatabaseConfig.Name,
		SSLMode:  "disable",
		TimeZone: "UTC",
	})
	if err != nil {
		appLogger.Error("Failed to connect to database", "error", err)
		log.Fatal("Failed to connect to database:", err)
	}
	appLogger.Info("Database connection established")

	// Initialize Redis
	redisClient := redis.NewClient(cfg)
	appLogger.Info("Redis connection established")

	// Initialize repository
	userRepo := repository.NewUserRepository(db)

	// Initialize services
	//nolint:staticcheck // Embedded field name required for clarity
	jwtService := service.NewJWTService(cfg.JWTConfig.Secret, cfg.JWTConfig.AccessExpiry, cfg.JWTConfig.RefreshExpiry)
	authService := service.NewAuthService(userRepo, jwtService, redisClient)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService)
	healthHandler := handlers.NewHealthHandler()

	// Setup router with custom middleware
	router := gin.New()

	// Add custom middleware
	router.Use(logger.Recovery(appLogger))      // Panic recovery with logging
	router.Use(logger.RequestLogger(appLogger)) // Request logging with context
	router.Use(metricsCollector.Middleware())   // Prometheus metrics collection

	// Setup routes
	routes.Setup(router, authHandler, healthHandler, cfg, metricsCollector)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8084"
	}

	appLogger.Info("Auth service ready", "port", port, "environment", os.Getenv("ENVIRONMENT"))
	if err := router.Run(fmt.Sprintf(":%s", port)); err != nil {
		appLogger.Error("Failed to start server", "error", err)
		log.Fatal("Failed to start server:", err)
	}
}
