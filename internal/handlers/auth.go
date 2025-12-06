// Package handlers contains HTTP request handlers for the auth service.
package handlers

import (
	"net/http"
	"strings"

	"github.com/GunarsK-portfolio/auth-service/internal/service"
	"github.com/GunarsK-portfolio/portfolio-common/audit"
	commonHandlers "github.com/GunarsK-portfolio/portfolio-common/handlers"
	"github.com/GunarsK-portfolio/portfolio-common/jwt"
	"github.com/GunarsK-portfolio/portfolio-common/repository"
	"github.com/gin-gonic/gin"
)

// AuthHandler handles authentication HTTP requests.
type AuthHandler struct {
	authService   service.AuthService
	actionLogRepo repository.ActionLogRepository
	cookieHelper  *CookieHelper
	jwtService    jwt.Service
}

// NewAuthHandler creates a new AuthHandler instance.
func NewAuthHandler(
	authService service.AuthService,
	actionLogRepo repository.ActionLogRepository,
	cookieHelper *CookieHelper,
	jwtService jwt.Service,
) *AuthHandler {
	return &AuthHandler{
		authService:   authService,
		actionLogRepo: actionLogRepo,
		cookieHelper:  cookieHelper,
		jwtService:    jwtService,
	}
}

// LoginRequest represents the login request payload.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RefreshRequest represents the token refresh request payload.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// ValidateRequest represents the token validation request payload.
type ValidateRequest struct {
	Token string `json:"token" binding:"required"`
}

// LoginResponse is the response body for login (tokens are in httpOnly cookies).
type LoginResponse struct {
	Success   bool              `json:"success"`
	ExpiresIn int64             `json:"expires_in"`
	UserID    int64             `json:"user_id,omitempty"`
	Username  string            `json:"username,omitempty"`
	Scopes    map[string]string `json:"scopes,omitempty"`
}

// Login godoc
// @Summary User login
// @Description Authenticate user and set httpOnly cookies with tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		commonHandlers.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	response, err := h.authService.Login(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		// Log failed login attempt
		source := "auth-service"
		_ = audit.LogFromContext(c, h.actionLogRepo, audit.ActionLoginFailure, nil, nil, &source, map[string]interface{}{
			"username": req.Username,
			"reason":   "invalid_credentials",
		})
		commonHandlers.LogAndRespondError(c, http.StatusUnauthorized, err, "invalid credentials")
		return
	}

	// Set httpOnly cookies instead of returning tokens in body
	h.cookieHelper.SetAuthCookies(
		c,
		response.AccessToken,
		response.RefreshToken,
		h.jwtService.GetAccessExpiry(),
		h.jwtService.GetRefreshExpiry(),
	)

	// Log successful login with explicit user_id
	source := "auth-service"
	_ = audit.LogAction(c, h.actionLogRepo, audit.ActionLoginSuccess, nil, nil, &response.UserID, &source, map[string]interface{}{
		"username": response.Username,
	})

	c.JSON(http.StatusOK, LoginResponse{
		Success:   true,
		ExpiresIn: response.ExpiresIn,
		UserID:    response.UserID,
		Username:  response.Username,
		Scopes:    response.Scopes,
	})
}

// Logout godoc
// @Summary User logout
// @Description Invalidate refresh token and clear cookies
// @Tags auth
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	// Try cookie first, then header
	token := h.cookieHelper.GetAccessToken(c)
	if token == "" {
		token = extractToken(c)
	}
	if token == "" {
		commonHandlers.RespondError(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.authService.Logout(c.Request.Context(), token); err != nil {
		commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "logout failed")
		return
	}

	// Clear cookies
	h.cookieHelper.ClearAuthCookies(c)

	// Log logout (user_id automatically extracted from context by auth middleware)
	source := "auth-service"
	_ = audit.LogFromContext(c, h.actionLogRepo, audit.ActionLogout, nil, nil, &source, nil)

	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

// Refresh godoc
// @Summary Refresh access token
// @Description Get new tokens using refresh token from cookie
// @Tags auth
// @Produce json
// @Success 200 {object} LoginResponse
// @Failure 401 {object} map[string]string
// @Router /auth/refresh [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	// Get refresh token from cookie
	refreshToken := h.cookieHelper.GetRefreshToken(c)
	if refreshToken == "" {
		commonHandlers.RespondError(c, http.StatusUnauthorized, "refresh token required")
		return
	}

	response, err := h.authService.RefreshToken(c.Request.Context(), refreshToken)
	if err != nil {
		commonHandlers.LogAndRespondError(c, http.StatusUnauthorized, err, "invalid refresh token")
		return
	}

	// Set new cookies
	h.cookieHelper.SetAuthCookies(
		c,
		response.AccessToken,
		response.RefreshToken,
		h.jwtService.GetAccessExpiry(),
		h.jwtService.GetRefreshExpiry(),
	)

	// Log token refresh
	source := "auth-service"
	_ = audit.LogFromContext(c, h.actionLogRepo, audit.ActionTokenRefresh, nil, nil, &source, nil)

	c.JSON(http.StatusOK, LoginResponse{
		Success:   true,
		ExpiresIn: response.ExpiresIn,
	})
}

// ValidateResponse represents the token validation response.
type ValidateResponse struct {
	Valid      bool   `json:"valid"`
	TTLSeconds int64  `json:"ttl_seconds"`
	UserID     int64  `json:"user_id"`
	Username   string `json:"username"`
}

// Validate godoc
// @Summary Validate access token
// @Description Validate if access token is valid and return TTL with user claims
// @Tags auth
// @Accept json
// @Produce json
// @Param request body ValidateRequest true "Access token"
// @Success 200 {object} ValidateResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /auth/validate [post]
func (h *AuthHandler) Validate(c *gin.Context) {
	var req ValidateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		commonHandlers.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	ttl, claims, err := h.authService.ValidateTokenWithClaims(req.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ValidateResponse{Valid: false})
		return
	}

	c.JSON(http.StatusOK, ValidateResponse{
		Valid:      true,
		TTLSeconds: ttl,
		UserID:     claims.UserID,
		Username:   claims.Username,
	})
}

// TokenStatusResponse represents the token status response.
type TokenStatusResponse struct {
	Valid      bool              `json:"valid"`
	TTLSeconds int64             `json:"ttl_seconds"`
	Scopes     map[string]string `json:"scopes,omitempty"`
}

// TokenStatus godoc
// @Summary Check token status
// @Description Check if token is valid and return remaining TTL (reads from cookie or Authorization header)
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} TokenStatusResponse
// @Failure 401 {object} TokenStatusResponse
// @Router /auth/token-status [get]
func (h *AuthHandler) TokenStatus(c *gin.Context) {
	// Try cookie first, then header
	token := h.cookieHelper.GetAccessToken(c)
	if token == "" {
		token = extractToken(c)
	}
	if token == "" {
		c.JSON(http.StatusUnauthorized, TokenStatusResponse{Valid: false, TTLSeconds: 0})
		return
	}

	ttl, claims, err := h.authService.ValidateTokenWithClaims(token)
	if err != nil || ttl <= 0 {
		c.JSON(http.StatusUnauthorized, TokenStatusResponse{Valid: false, TTLSeconds: 0})
		return
	}

	c.JSON(http.StatusOK, TokenStatusResponse{
		Valid:      true,
		TTLSeconds: ttl,
		Scopes:     claims.Scopes,
	})
}

func extractToken(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	parts := strings.Split(bearerToken, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}
