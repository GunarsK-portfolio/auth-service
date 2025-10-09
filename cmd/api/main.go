package main

import (
	"fmt"
	"log"
	"os"

	_ "github.com/GunarsK-portfolio/auth-service/docs"
	"github.com/GunarsK-portfolio/auth-service/internal/config"
	"github.com/GunarsK-portfolio/auth-service/internal/database"
	"github.com/GunarsK-portfolio/auth-service/internal/handlers"
	"github.com/GunarsK-portfolio/auth-service/internal/repository"
	"github.com/GunarsK-portfolio/auth-service/internal/service"
	"github.com/GunarsK-portfolio/auth-service/pkg/redis"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Portfolio Auth Service API
// @version 1.0
// @description Authentication and authorization service for portfolio system
// @host localhost:8084
// @BasePath /api/v1
func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize database
	db, err := database.Connect(cfg)
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

	// Enable CORS
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Health check
	router.GET("/api/v1/health", healthHandler.Check)

	// Auth routes
	v1 := router.Group("/api/v1/auth")
	{
		v1.POST("/login", authHandler.Login)
		v1.POST("/logout", authHandler.Logout)
		v1.POST("/refresh", authHandler.Refresh)
		v1.POST("/validate", authHandler.Validate)
	}

	// Swagger documentation
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

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
