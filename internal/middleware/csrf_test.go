package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCSRF(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := CSRFConfig{
		AllowedOrigins: []string{
			"https://localhost:8443",
			"https://admin.example.com",
		},
	}

	tests := []struct {
		name       string
		method     string
		origin     string
		referer    string
		wantStatus int
	}{
		// GET requests should pass without validation
		{
			name:       "GET request passes without headers",
			method:     http.MethodGet,
			origin:     "",
			referer:    "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "HEAD request passes without headers",
			method:     http.MethodHead,
			origin:     "",
			referer:    "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "OPTIONS request passes without headers",
			method:     http.MethodOptions,
			origin:     "",
			referer:    "",
			wantStatus: http.StatusOK,
		},
		// POST with valid Origin
		{
			name:       "POST with valid origin passes",
			method:     http.MethodPost,
			origin:     "https://localhost:8443",
			referer:    "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "POST with valid origin (trailing slash) passes",
			method:     http.MethodPost,
			origin:     "https://localhost:8443/",
			referer:    "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "POST with valid origin (case insensitive) passes",
			method:     http.MethodPost,
			origin:     "HTTPS://LOCALHOST:8443",
			referer:    "",
			wantStatus: http.StatusOK,
		},
		// POST with invalid Origin
		{
			name:       "POST with invalid origin blocked",
			method:     http.MethodPost,
			origin:     "https://evil.com",
			referer:    "",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "POST with different port blocked",
			method:     http.MethodPost,
			origin:     "https://localhost:9999",
			referer:    "",
			wantStatus: http.StatusForbidden,
		},
		// POST with Referer (fallback when no Origin)
		{
			name:       "POST with valid referer passes",
			method:     http.MethodPost,
			origin:     "",
			referer:    "https://localhost:8443/some/page",
			wantStatus: http.StatusOK,
		},
		{
			name:       "POST with invalid referer blocked",
			method:     http.MethodPost,
			origin:     "",
			referer:    "https://evil.com/attack",
			wantStatus: http.StatusForbidden,
		},
		// POST with no headers
		{
			name:       "POST with no origin or referer blocked",
			method:     http.MethodPost,
			origin:     "",
			referer:    "",
			wantStatus: http.StatusForbidden,
		},
		// Origin: null (privacy mode, file://, data: URLs, cross-origin redirects)
		{
			name:       "POST with Origin null blocked",
			method:     http.MethodPost,
			origin:     "null",
			referer:    "",
			wantStatus: http.StatusForbidden,
		},
		// Other state-changing methods
		{
			name:       "PUT with valid origin passes",
			method:     http.MethodPut,
			origin:     "https://admin.example.com",
			referer:    "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "DELETE with valid origin passes",
			method:     http.MethodDelete,
			origin:     "https://admin.example.com",
			referer:    "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "PATCH with invalid origin blocked",
			method:     http.MethodPatch,
			origin:     "https://evil.com",
			referer:    "",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, r := gin.CreateTestContext(w)

			// Setup middleware and handler
			r.Use(CSRF(config))
			r.Any("/test", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			// Create request
			req := httptest.NewRequest(tt.method, "/test", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			c.Request = req

			// Execute
			r.ServeHTTP(w, req)

			// Assert
			if w.Code != tt.wantStatus {
				t.Errorf("CSRF() status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestExtractOrigin(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		want   string
	}{
		{
			name:   "full URL",
			rawURL: "https://example.com/path/to/page?query=1",
			want:   "https://example.com",
		},
		{
			name:   "URL with port",
			rawURL: "https://localhost:8443/login",
			want:   "https://localhost:8443",
		},
		{
			name:   "HTTP URL",
			rawURL: "http://example.com/page",
			want:   "http://example.com",
		},
		{
			name:   "path only (no scheme)",
			rawURL: "not-a-url",
			want:   "", // No scheme means invalid origin
		},
		{
			name:   "empty string",
			rawURL: "",
			want:   "",
		},
		{
			name:   "null string",
			rawURL: "null",
			want:   "", // "null" has no scheme
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractOrigin(tt.rawURL)
			if got != tt.want {
				t.Errorf("extractOrigin() = %s, want %s", got, tt.want)
			}
		})
	}
}
