// Package routes defines HTTP routes for the auth service.
package routes

import (
	"github.com/GunarsK-portfolio/auth-service/docs"
	"github.com/GunarsK-portfolio/auth-service/internal/config"
	"github.com/GunarsK-portfolio/auth-service/internal/handlers"
	"github.com/GunarsK-portfolio/portfolio-common/health"
	"github.com/GunarsK-portfolio/portfolio-common/metrics"
	common "github.com/GunarsK-portfolio/portfolio-common/middleware"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// Setup configures all HTTP routes for the application.
func Setup(router *gin.Engine, authHandler *handlers.AuthHandler, cfg *config.Config, metricsCollector *metrics.Metrics, healthAgg *health.Aggregator) {
	// Security middleware with CORS validation
	securityMiddleware := common.NewSecurityMiddleware(
		cfg.AllowedOrigins,
		"GET,POST,PUT,DELETE,OPTIONS",
		"Content-Type,Authorization",
		true,
	)
	router.Use(securityMiddleware.Apply())

	// Health check
	router.GET("/health", healthAgg.Handler())
	// Metrics
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Auth routes
	v1 := router.Group("/api/v1/auth")
	{
		v1.POST("/login", authHandler.Login)
		v1.POST("/logout", authHandler.Logout)
		v1.POST("/refresh", authHandler.Refresh)
		v1.POST("/validate", authHandler.Validate)
		v1.GET("/token-status", authHandler.TokenStatus)
	}

	// Swagger documentation (only if SWAGGER_HOST is configured)
	if cfg.SwaggerHost != "" {
		docs.SwaggerInfo.Host = cfg.SwaggerHost
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}
}
