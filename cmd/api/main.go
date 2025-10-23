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

	// Initialize database
	db, err := commondb.Connect(commondb.PostgresConfig{
		Host:     cfg.DBHost,
		Port:     cfg.DBPort,
		User:     cfg.DBUser,
		Password: cfg.DBPassword,
		DBName:   cfg.DBName,
		SSLMode:  "disable",
		TimeZone: "UTC",
	})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Initialize Redis
	redisClient := redis.NewClient(cfg)

	// Initialize repository
	userRepo := repository.NewUserRepository(db)

	// Initialize services
	jwtService := service.NewJWTService(cfg.JWTSecret, cfg.JWTAccessExpiry, cfg.JWTRefreshExpiry)
	authService := service.NewAuthService(userRepo, jwtService, redisClient)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService)
	healthHandler := handlers.NewHealthHandler()

	// Setup router
	router := gin.Default()

	// Setup routes
	routes.Setup(router, authHandler, healthHandler)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8084"
	}

	log.Printf("Starting auth service on port %s", port)
	if err := router.Run(fmt.Sprintf(":%s", port)); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
