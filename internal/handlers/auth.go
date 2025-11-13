// Package handlers contains HTTP request handlers for the auth service.
package handlers

import (
	"net/http"
	"strings"

	"github.com/GunarsK-portfolio/auth-service/internal/service"
	"github.com/GunarsK-portfolio/portfolio-common/audit"
	commonHandlers "github.com/GunarsK-portfolio/portfolio-common/handlers"
	"github.com/GunarsK-portfolio/portfolio-common/repository"
	"github.com/gin-gonic/gin"
)

// AuthHandler handles authentication HTTP requests.
type AuthHandler struct {
	authService   service.AuthService
	actionLogRepo repository.ActionLogRepository
}

// NewAuthHandler creates a new AuthHandler instance.
func NewAuthHandler(authService service.AuthService, actionLogRepo repository.ActionLogRepository) *AuthHandler {
	return &AuthHandler{
		authService:   authService,
		actionLogRepo: actionLogRepo,
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

// Login godoc
// @Summary User login
// @Description Authenticate user and return access and refresh tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} service.LoginResponse
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

	// Log successful login with explicit user_id
	source := "auth-service"
	_ = audit.LogAction(c, h.actionLogRepo, audit.ActionLoginSuccess, nil, nil, &response.UserID, &source, map[string]interface{}{
		"username": response.Username,
	})

	c.JSON(http.StatusOK, response)
}

// Logout godoc
// @Summary User logout
// @Description Invalidate refresh token
// @Tags auth
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	token := extractToken(c)
	if token == "" {
		commonHandlers.RespondError(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.authService.Logout(c.Request.Context(), token); err != nil {
		commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "logout failed")
		return
	}

	// Log logout (user_id automatically extracted from context by auth middleware)
	source := "auth-service"
	_ = audit.LogFromContext(c, h.actionLogRepo, audit.ActionLogout, nil, nil, &source, nil)

	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

// Refresh godoc
// @Summary Refresh access token
// @Description Get new access and refresh tokens using refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RefreshRequest true "Refresh token"
// @Success 200 {object} service.LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /auth/refresh [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		commonHandlers.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	response, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		commonHandlers.LogAndRespondError(c, http.StatusUnauthorized, err, "invalid refresh token")
		return
	}

	// Log token refresh
	source := "auth-service"
	_ = audit.LogFromContext(c, h.actionLogRepo, audit.ActionTokenRefresh, nil, nil, &source, nil)

	c.JSON(http.StatusOK, response)
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
	Valid      bool  `json:"valid"`
	TTLSeconds int64 `json:"ttl_seconds"`
}

// TokenStatus godoc
// @Summary Check token status
// @Description Check if token is valid and return remaining TTL (reads from Authorization header)
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} TokenStatusResponse
// @Failure 401 {object} TokenStatusResponse
// @Router /auth/token-status [get]
func (h *AuthHandler) TokenStatus(c *gin.Context) {
	token := extractToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, TokenStatusResponse{Valid: false, TTLSeconds: 0})
		return
	}

	ttl, err := h.authService.ValidateToken(token)
	if err != nil || ttl <= 0 {
		c.JSON(http.StatusUnauthorized, TokenStatusResponse{Valid: false, TTLSeconds: 0})
		return
	}

	c.JSON(http.StatusOK, TokenStatusResponse{
		Valid:      true,
		TTLSeconds: ttl,
	})
}

func extractToken(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	if len(strings.Split(bearerToken, " ")) == 2 {
		return strings.Split(bearerToken, " ")[1]
	}
	return ""
}
