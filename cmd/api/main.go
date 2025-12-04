// Package main is the entry point for the auth service.
package main

import (
	"log"
	"os"
	"strconv"
	"time"

	_ "github.com/GunarsK-portfolio/auth-service/docs"
	"github.com/GunarsK-portfolio/auth-service/internal/config"
	"github.com/GunarsK-portfolio/auth-service/internal/handlers"
	"github.com/GunarsK-portfolio/auth-service/internal/repository"
	"github.com/GunarsK-portfolio/auth-service/internal/routes"
	"github.com/GunarsK-portfolio/auth-service/internal/service"
	"github.com/GunarsK-portfolio/auth-service/pkg/redis"
	"github.com/GunarsK-portfolio/portfolio-common/audit"
	commondb "github.com/GunarsK-portfolio/portfolio-common/database"
	"github.com/GunarsK-portfolio/portfolio-common/health"
	"github.com/GunarsK-portfolio/portfolio-common/jwt"
	"github.com/GunarsK-portfolio/portfolio-common/logger"
	"github.com/GunarsK-portfolio/portfolio-common/metrics"
	commonrepo "github.com/GunarsK-portfolio/portfolio-common/repository"
	"github.com/GunarsK-portfolio/portfolio-common/server"
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
		Port:     strconv.Itoa(cfg.DatabaseConfig.Port),
		User:     cfg.DatabaseConfig.User,
		Password: cfg.DatabaseConfig.Password,
		DBName:   cfg.DatabaseConfig.Name,
		SSLMode:  cfg.DatabaseConfig.SSLMode,
	})
	if err != nil {
		appLogger.Error("Failed to connect to database", "error", err)
		log.Fatal("Failed to connect to database:", err)
	}
	defer func() {
		if closeErr := commondb.CloseDB(db); closeErr != nil {
			appLogger.Error("Failed to close database", "error", closeErr)
		}
	}()
	appLogger.Info("Database connection established")

	// Initialize Redis
	redisClient := redis.NewClient(cfg)
	appLogger.Info("Redis connection established")

	// Health checks
	healthAgg := health.NewAggregator(3 * time.Second)
	healthAgg.Register(health.NewPostgresChecker(db))
	healthAgg.Register(health.NewRedisChecker(redisClient))

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	actionLogRepo := commonrepo.NewActionLogRepository(db)

	// Initialize services
	//nolint:staticcheck // Embedded field name required for clarity
	jwtService, err := jwt.NewService(cfg.JWTConfig.Secret, cfg.JWTConfig.AccessExpiry, cfg.JWTConfig.RefreshExpiry)
	if err != nil {
		appLogger.Error("Failed to create JWT service", "error", err)
		log.Fatal("Failed to create JWT service:", err)
	}
	authService := service.NewAuthService(userRepo, jwtService, redisClient)

	// Initialize cookie helper
	cookieHelper := handlers.NewCookieHelper(cfg.CookieConfig)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, actionLogRepo, cookieHelper, jwtService)

	// Setup router with custom middleware
	router := gin.New()

	// Add custom middleware
	router.Use(logger.Recovery(appLogger))      // Panic recovery with logging
	router.Use(logger.RequestLogger(appLogger)) // Request logging with context
	router.Use(audit.ContextMiddleware())       // Extract IP and user agent for audit logging
	router.Use(metricsCollector.Middleware())   // Prometheus metrics collection

	// Setup routes
	routes.Setup(router, authHandler, cfg, metricsCollector, healthAgg)

	// Start server with graceful shutdown
	port := os.Getenv("PORT")
	if port == "" {
		port = "8084"
	}

	appLogger.Info("Auth service ready", "port", port, "environment", os.Getenv("ENVIRONMENT"))

	serverCfg := server.DefaultConfig(port)
	if err := server.Run(router, serverCfg, appLogger); err != nil {
		appLogger.Error("Server error", "error", err)
		log.Fatal("Server error:", err)
	}
}
