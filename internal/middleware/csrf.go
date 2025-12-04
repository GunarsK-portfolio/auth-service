// Package middleware provides HTTP middleware for the auth service.
package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// CSRFConfig holds configuration for CSRF protection middleware.
type CSRFConfig struct {
	// AllowedOrigins is a list of allowed origins for CSRF validation.
	// Should match CORS allowed origins.
	AllowedOrigins []string
}

// CSRF returns middleware that validates Origin/Referer headers
// to protect against Cross-Site Request Forgery attacks.
//
// This is required for cookie-based authentication because browsers
// automatically send cookies with every request to the domain.
func CSRF(config CSRFConfig) gin.HandlerFunc {
	// Build a set of allowed origins for O(1) lookup
	allowedSet := make(map[string]bool)
	for _, origin := range config.AllowedOrigins {
		// Normalize: remove trailing slash, lowercase
		normalized := strings.TrimSuffix(strings.ToLower(origin), "/")
		allowedSet[normalized] = true
	}

	return func(c *gin.Context) {
		// Only check state-changing methods (not GET, HEAD, OPTIONS)
		method := c.Request.Method
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			c.Next()
			return
		}

		// Check Origin header first (preferred)
		origin := c.GetHeader("Origin")
		if origin != "" {
			if !isAllowedOrigin(origin, allowedSet) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "CSRF validation failed: invalid origin",
				})
				return
			}
			c.Next()
			return
		}

		// Fall back to Referer header if Origin is not present
		referer := c.GetHeader("Referer")
		if referer != "" {
			refererOrigin := extractOrigin(referer)
			if !isAllowedOrigin(refererOrigin, allowedSet) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "CSRF validation failed: invalid referer",
				})
				return
			}
			c.Next()
			return
		}

		// No Origin or Referer header - reject request
		// This catches direct API calls without browser context
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "CSRF validation failed: missing origin",
		})
	}
}

// isAllowedOrigin checks if the given origin is in the allowed set.
func isAllowedOrigin(origin string, allowedSet map[string]bool) bool {
	normalized := strings.TrimSuffix(strings.ToLower(origin), "/")
	return allowedSet[normalized]
}

// extractOrigin extracts the origin (scheme://host:port) from a URL.
func extractOrigin(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	// Reconstruct origin: scheme://host (port included in Host if non-standard)
	return parsed.Scheme + "://" + parsed.Host
}
