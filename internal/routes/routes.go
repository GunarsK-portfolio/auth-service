// Package routes defines HTTP routes for the auth service.
package routes

import (
	"github.com/GunarsK-portfolio/auth-service/internal/handlers"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// Setup configures all HTTP routes for the application.
func Setup(router *gin.Engine, authHandler *handlers.AuthHandler, healthHandler *handlers.HealthHandler) {
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
		v1.GET("/token-status", authHandler.TokenStatus)
	}

	// Swagger documentation
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
}
