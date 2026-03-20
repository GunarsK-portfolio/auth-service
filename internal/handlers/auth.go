// Package handlers contains HTTP request handlers for the auth service.
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/GunarsK-portfolio/auth-service/internal/service"
	"github.com/GunarsK-portfolio/portfolio-common/audit"
	commonHandlers "github.com/GunarsK-portfolio/portfolio-common/handlers"
	"github.com/GunarsK-portfolio/portfolio-common/jwt"
	"github.com/GunarsK-portfolio/portfolio-common/repository"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

const oauthStatePrefix = "oauth_state:"

// AuthHandler handles authentication HTTP requests.
type AuthHandler struct {
	authService        service.AuthService
	actionLogRepo      repository.ActionLogRepository
	cookieHelper       *CookieHelper
	jwtService         jwt.Service
	redis              *redis.Client
	allowedOrigins     map[string]bool
	verifyRateLimitMsg string
}

// NewAuthHandler creates a new AuthHandler instance.
func NewAuthHandler(
	authService service.AuthService,
	actionLogRepo repository.ActionLogRepository,
	cookieHelper *CookieHelper,
	jwtService jwt.Service,
	redisClient *redis.Client,
	allowedOrigins []string,
	verifyRateLimitMax int64,
	verifyRateLimitWindow string,
) *AuthHandler {
	origins := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		origins[strings.TrimRight(o, "/")] = true
	}
	return &AuthHandler{
		authService:        authService,
		actionLogRepo:      actionLogRepo,
		cookieHelper:       cookieHelper,
		jwtService:         jwtService,
		redis:              redisClient,
		allowedOrigins:     origins,
		verifyRateLimitMsg: fmt.Sprintf("maximum %d verification emails per %s, please try again later", verifyRateLimitMax, verifyRateLimitWindow),
	}
}

// LoginRequest represents the login request payload.
type LoginRequest struct {
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
	RememberMe bool   `json:"remember_me"`
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
	Success       bool              `json:"success"`
	ExpiresIn     int64             `json:"expires_in"`
	UserID        int64             `json:"user_id,omitempty"`
	Username      string            `json:"username,omitempty"`
	Email         string            `json:"email,omitempty"`
	EmailVerified bool              `json:"email_verified"`
	DisplayName   string            `json:"display_name,omitempty"`
	Scopes        map[string]string `json:"scopes,omitempty"`
}

// RegisterRequest represents the registration request payload.
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email,max=100" format:"email"`
	Password string `json:"password" binding:"required,min=8,max=72"`
	RoleCode string `json:"role_code,omitempty" example:"read-only"` // Any valid role not in denied list (default: admin, rpg-admin)
}

// RegisterResponse is the response body for registration.
type RegisterResponse struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// Register godoc
// @Summary User registration
// @Description Register a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "Registration data"
// @Success 201 {object} RegisterResponse
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		commonHandlers.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	result, err := h.authService.Register(c.Request.Context(), service.RegisterRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
		RoleCode: req.RoleCode,
	})
	if err != nil {
		source := "auth-service"
		switch {
		case errors.Is(err, service.ErrUsernameTaken):
			_ = audit.LogFromContext(c, h.actionLogRepo, "registration_failure", nil, nil, &source, map[string]interface{}{
				"username": req.Username,
				"reason":   "username_taken",
			})
			commonHandlers.RespondError(c, http.StatusConflict, "username or email already in use")
		case errors.Is(err, service.ErrEmailTaken):
			_ = audit.LogFromContext(c, h.actionLogRepo, "registration_failure", nil, nil, &source, map[string]interface{}{
				"email":  req.Email,
				"reason": "email_taken",
			})
			commonHandlers.RespondError(c, http.StatusConflict, "username or email already in use")
		case errors.Is(err, service.ErrRoleNotAllowed):
			_ = audit.LogFromContext(c, h.actionLogRepo, "registration_failure", nil, nil, &source, map[string]interface{}{
				"username":  req.Username,
				"role_code": req.RoleCode,
				"reason":    "role_not_allowed",
			})
			commonHandlers.RespondError(c, http.StatusForbidden, "role not allowed for self-registration")
		case errors.Is(err, service.ErrInvalidRoleCode):
			_ = audit.LogFromContext(c, h.actionLogRepo, "registration_failure", nil, nil, &source, map[string]interface{}{
				"username":  req.Username,
				"role_code": req.RoleCode,
				"reason":    "invalid_role_code",
			})
			commonHandlers.RespondError(c, http.StatusBadRequest, "invalid role code")
		case errors.Is(err, service.ErrPasswordTooLong):
			commonHandlers.RespondError(c, http.StatusBadRequest, "password exceeds maximum length")
		default:
			_ = audit.LogFromContext(c, h.actionLogRepo, "registration_failure", nil, nil, &source, map[string]interface{}{
				"username": req.Username,
				"reason":   "internal_error",
			})
			commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "registration failed")
		}
		return
	}

	source := "auth-service"
	_ = audit.LogAction(c, h.actionLogRepo, "registration_success", nil, nil, &result.UserID, &source, map[string]interface{}{
		"username": result.Username,
	})

	c.JSON(http.StatusCreated, RegisterResponse{
		UserID:   result.UserID,
		Username: result.Username,
		Email:    result.Email,
	})
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

	response, err := h.authService.Login(c.Request.Context(), req.Username, req.Password, req.RememberMe)
	if err != nil {
		source := "auth-service"
		if errors.Is(err, service.ErrInvalidCredentials) {
			_ = audit.LogFromContext(c, h.actionLogRepo, audit.ActionLoginFailure, nil, nil, &source, map[string]interface{}{
				"username": req.Username,
				"reason":   "invalid_credentials",
			})
			commonHandlers.LogAndRespondError(c, http.StatusUnauthorized, err, "invalid credentials")
		} else {
			_ = audit.LogFromContext(c, h.actionLogRepo, audit.ActionLoginFailure, nil, nil, &source, map[string]interface{}{
				"username": req.Username,
				"reason":   "internal_error",
			})
			commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "login failed")
		}
		return
	}

	if response.SessionID == "" {
		commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, errors.New("empty session ID"), "login failed")
		return
	}

	// Set httpOnly cookies instead of returning tokens in body
	h.cookieHelper.SetAuthCookies(
		c,
		response.AccessToken,
		response.RefreshToken,
		h.jwtService.GetAccessExpiry(),
		h.jwtService.GetRefreshExpiry(),
		response.RememberMe,
	)
	h.cookieHelper.SetSessionCookie(c, response.SessionID, response.RememberMe, h.jwtService.GetRefreshExpiry())

	// Log successful login with explicit user_id
	source := "auth-service"
	_ = audit.LogAction(c, h.actionLogRepo, audit.ActionLoginSuccess, nil, nil, &response.UserID, &source, map[string]interface{}{
		"username": response.Username,
	})

	c.JSON(http.StatusOK, LoginResponse{
		Success:       true,
		ExpiresIn:     response.ExpiresIn,
		UserID:        response.UserID,
		Username:      response.Username,
		Email:         response.Email,
		EmailVerified: response.EmailVerified,
		DisplayName:   response.DisplayName,
		Scopes:        response.Scopes,
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
		h.cookieHelper.ClearAuthCookies(c)
		commonHandlers.RespondError(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	sessionID := h.cookieHelper.GetSessionID(c)
	if sessionID == "" {
		h.cookieHelper.ClearAuthCookies(c)
		commonHandlers.RespondError(c, http.StatusUnauthorized, "session not found")
		return
	}

	if err := h.authService.Logout(c.Request.Context(), token, sessionID); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidToken):
			h.cookieHelper.ClearAuthCookies(c)
			commonHandlers.RespondError(c, http.StatusUnauthorized, "invalid or expired token")
		case errors.Is(err, service.ErrSessionNotFound):
			h.cookieHelper.ClearAuthCookies(c)
			commonHandlers.RespondError(c, http.StatusUnauthorized, "session not found")
		default:
			commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "logout failed")
		}
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
	// Get refresh token and session ID from cookies
	refreshToken := h.cookieHelper.GetRefreshToken(c)
	if refreshToken == "" {
		h.cookieHelper.ClearAuthCookies(c)
		commonHandlers.RespondError(c, http.StatusUnauthorized, "refresh token required")
		return
	}

	sessionID := h.cookieHelper.GetSessionID(c)
	if sessionID == "" {
		h.cookieHelper.ClearAuthCookies(c)
		commonHandlers.RespondError(c, http.StatusUnauthorized, "session not found")
		return
	}

	response, err := h.authService.RefreshToken(c.Request.Context(), refreshToken, sessionID)
	if err != nil {
		if errors.Is(err, service.ErrInvalidRefreshToken) {
			h.cookieHelper.ClearAuthCookies(c)
			commonHandlers.LogAndRespondError(c, http.StatusUnauthorized, err, "invalid refresh token")
		} else {
			commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "refresh failed")
		}
		return
	}

	if response.SessionID == "" {
		commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, errors.New("empty session ID"), "refresh failed")
		return
	}

	// Set new cookies
	h.cookieHelper.SetAuthCookies(
		c,
		response.AccessToken,
		response.RefreshToken,
		h.jwtService.GetAccessExpiry(),
		h.jwtService.GetRefreshExpiry(),
		response.RememberMe,
	)
	h.cookieHelper.SetSessionCookie(c, response.SessionID, response.RememberMe, h.jwtService.GetRefreshExpiry())

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
	Valid         bool              `json:"valid"`
	TTLSeconds    int64             `json:"ttl_seconds"`
	Username      string            `json:"username,omitempty"`
	Email         string            `json:"email,omitempty"`
	EmailVerified bool              `json:"email_verified"`
	DisplayName   string            `json:"display_name,omitempty"`
	Scopes        map[string]string `json:"scopes,omitempty"`
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
		Valid:         true,
		TTLSeconds:    ttl,
		Username:      claims.Username,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		DisplayName:   claims.DisplayName,
		Scopes:        claims.Scopes,
	})
}

// VerifyEmailRequest represents the email verification request payload.
type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

// ProfileUpdateRequest represents the profile update request payload.
type ProfileUpdateRequest struct {
	Email       *string `json:"email" binding:"omitempty,email,max=100"`
	DisplayName *string `json:"display_name" binding:"omitempty,max=100"`
}

// ForgotPasswordRequest represents the forgot password request payload.
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest represents the password reset request payload.
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=72"`
}

// ChangePasswordRequest represents the change password request payload.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8,max=72"`
}

// SendVerification godoc
// @Summary Send verification email
// @Description Send email verification link to the authenticated user's email
// @Tags auth
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 429 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /auth/send-verification [post]
func (h *AuthHandler) SendVerification(c *gin.Context) {
	claims, ok := h.authenticateRequest(c)
	if !ok {
		return
	}

	origin := strings.TrimRight(c.GetHeader("Origin"), "/")
	if origin == "" || !h.allowedOrigins[origin] {
		commonHandlers.RespondError(c, http.StatusBadRequest, "missing or disallowed origin")
		return
	}

	err := h.authService.SendVerification(c.Request.Context(), claims.UserID, claims.Email, origin)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrAlreadyVerified):
			commonHandlers.RespondError(c, http.StatusBadRequest, "email already verified")
		case errors.Is(err, service.ErrRateLimited):
			commonHandlers.RespondError(c, http.StatusTooManyRequests, h.verifyRateLimitMsg)
		case errors.Is(err, service.ErrTokenNotFound):
			commonHandlers.RespondError(c, http.StatusBadRequest, "no verification token found")
		case errors.Is(err, service.ErrEmailNotConfigured):
			commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "email service not configured")
		default:
			commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "failed to send verification email")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "verification email sent"})
}

// VerifyEmail godoc
// @Summary Verify email address
// @Description Verify email using token from verification email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body VerifyEmailRequest true "Verification token"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /auth/verify-email [post]
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		commonHandlers.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.authService.VerifyEmail(c.Request.Context(), req.Token)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTokenNotFound):
			commonHandlers.RespondError(c, http.StatusNotFound, "invalid or expired verification token")
		case errors.Is(err, service.ErrTokenEmailMismatch):
			commonHandlers.RespondError(c, http.StatusBadRequest, "email has changed since verification was requested")
		default:
			commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "email verification failed")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "email verified successfully"})
}

// UpdateProfile godoc
// @Summary Update user profile
// @Description Update email and/or display name
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body ProfileUpdateRequest true "Profile update data"
// @Success 200 {object} service.ProfileResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /auth/profile [patch]
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	claims, ok := h.authenticateRequest(c)
	if !ok {
		return
	}

	var req ProfileUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		commonHandlers.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	if req.Email == nil && req.DisplayName == nil {
		commonHandlers.RespondError(c, http.StatusBadRequest, "at least one field must be provided")
		return
	}

	result, err := h.authService.UpdateProfile(c.Request.Context(), claims.UserID, service.ProfileUpdateRequest{
		Email:       req.Email,
		DisplayName: req.DisplayName,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrEmailTaken):
			commonHandlers.RespondError(c, http.StatusConflict, "email already in use")
		case errors.Is(err, service.ErrOAuthUserCannotChangeEmail):
			commonHandlers.RespondError(c, http.StatusBadRequest, "oauth-only users cannot change email, set a password first")
		case errors.Is(err, service.ErrUserNotFound):
			commonHandlers.RespondError(c, http.StatusUnauthorized, "user not found")
		default:
			commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "profile update failed")
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

// ChangePassword godoc
// @Summary Change password
// @Description Change the authenticated user's password
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body ChangePasswordRequest true "Password change data"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /auth/change-password [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	claims, ok := h.authenticateRequest(c)
	if !ok {
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		commonHandlers.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.authService.ChangePassword(c.Request.Context(), claims.UserID, service.ChangePasswordRequest{
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrPasswordMismatch):
			commonHandlers.RespondError(c, http.StatusUnauthorized, "current password is incorrect")
		case errors.Is(err, service.ErrPasswordTooLong):
			commonHandlers.RespondError(c, http.StatusBadRequest, "password exceeds maximum length")
		default:
			commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "password change failed")
		}
		return
	}

	// Clear cookies since all sessions are invalidated
	h.cookieHelper.ClearAuthCookies(c)

	c.JSON(http.StatusOK, gin.H{"message": "password changed successfully"})
}

// ForgotPassword godoc
// @Summary Request password reset
// @Description Send a password reset email if the account exists and is verified
// @Tags auth
// @Accept json
// @Produce json
// @Param request body ForgotPasswordRequest true "Email address"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 429 {object} map[string]string
// @Router /auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		commonHandlers.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	origin := strings.TrimRight(c.GetHeader("Origin"), "/")
	if origin == "" || !h.allowedOrigins[origin] {
		commonHandlers.RespondError(c, http.StatusBadRequest, "missing or disallowed origin")
		return
	}

	err := h.authService.ForgotPassword(c.Request.Context(), req.Email, origin)
	if err != nil {
		if errors.Is(err, service.ErrRateLimited) {
			commonHandlers.RespondError(c, http.StatusTooManyRequests, "too many requests, please try again later")
			return
		}
		if errors.Is(err, service.ErrEmailNotConfigured) {
			commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "email service not configured")
			return
		}
		// Log but don't expose internal errors — always return 200 below
		c.Error(err) //nolint:errcheck // logged by middleware
	}

	// Always return success to prevent email enumeration
	c.JSON(http.StatusOK, gin.H{"message": "if an account with that email exists, a password reset link has been sent"})
}

// ResetPassword godoc
// @Summary Reset password with token
// @Description Set a new password using a valid reset token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body ResetPasswordRequest true "Reset token and new password"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		commonHandlers.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.authService.ResetPassword(c.Request.Context(), req.Token, req.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTokenNotFound):
			commonHandlers.RespondError(c, http.StatusBadRequest, "invalid or expired reset token")
		case errors.Is(err, service.ErrTokenExpired):
			commonHandlers.RespondError(c, http.StatusBadRequest, "reset token has expired, please request a new one")
		case errors.Is(err, service.ErrPasswordTooLong):
			commonHandlers.RespondError(c, http.StatusBadRequest, "password exceeds maximum length")
		default:
			commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "password reset failed")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password reset successfully"})
}

// authenticateRequest extracts and validates the JWT from cookies or Authorization header.
// Returns claims on success, or sends an error response and returns false.
func (h *AuthHandler) authenticateRequest(c *gin.Context) (*jwt.Claims, bool) {
	token := h.cookieHelper.GetAccessToken(c)
	if token == "" {
		token = extractToken(c)
	}
	if token == "" {
		commonHandlers.RespondError(c, http.StatusUnauthorized, "unauthorized")
		return nil, false
	}

	_, claims, err := h.authService.ValidateTokenWithClaims(token)
	if err != nil {
		commonHandlers.RespondError(c, http.StatusUnauthorized, "invalid or expired token")
		return nil, false
	}

	return claims, true
}

func extractToken(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	parts := strings.Split(bearerToken, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}

// GoogleCallbackRequest is the request body for the Google OAuth callback.
type GoogleCallbackRequest struct {
	Code  string `json:"code" binding:"required"`
	State string `json:"state" binding:"required"`
}

// SetPasswordRequest is the request body for setting a password.
type SetPasswordRequest struct {
	Password        string `json:"password" binding:"required,min=8,max=72"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
}

// AuthMethodsResponse describes the authentication methods available to a user.
type AuthMethodsResponse struct {
	HasPassword bool     `json:"has_password"`
	Providers   []string `json:"providers"`
}

// GoogleLogin returns the Google OAuth consent URL.
func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "failed to generate state")
		return
	}
	state := hex.EncodeToString(b)

	if err := h.redis.Set(c.Request.Context(), oauthStatePrefix+state, "1", 5*time.Minute).Err(); err != nil {
		commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "failed to store oauth state")
		return
	}

	url, err := h.authService.GoogleAuthURL(state)
	if err != nil {
		if errors.Is(err, service.ErrGoogleOAuthDisabled) {
			commonHandlers.RespondError(c, http.StatusNotImplemented, "google oauth is not configured")
			return
		}
		commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "failed to generate auth url")
		return
	}

	c.JSON(http.StatusOK, gin.H{"url": url})
}

// GoogleCallback exchanges the authorization code for tokens and logs the user in.
func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	var req GoogleCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		commonHandlers.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	// Validate and consume state (one-time use)
	key := oauthStatePrefix + req.State
	deleted, err := h.redis.Del(c.Request.Context(), key).Result()
	if err != nil {
		commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "failed to validate oauth state")
		return
	}
	if deleted == 0 {
		commonHandlers.RespondError(c, http.StatusBadRequest, "invalid or expired oauth state")
		return
	}

	response, err := h.authService.GoogleCallback(c.Request.Context(), req.Code)
	if err != nil {
		if errors.Is(err, service.ErrGoogleOAuthDisabled) {
			commonHandlers.RespondError(c, http.StatusNotImplemented, "google oauth is not configured")
			return
		}
		commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "google oauth callback failed")
		return
	}

	h.cookieHelper.SetAuthCookies(
		c,
		response.AccessToken,
		response.RefreshToken,
		h.jwtService.GetAccessExpiry(),
		h.jwtService.GetRefreshExpiry(),
		false,
	)
	h.cookieHelper.SetSessionCookie(c, response.SessionID, false, h.jwtService.GetRefreshExpiry())

	c.JSON(http.StatusOK, LoginResponse{
		Success:       true,
		ExpiresIn:     response.ExpiresIn,
		UserID:        response.UserID,
		Username:      response.Username,
		Email:         response.Email,
		EmailVerified: response.EmailVerified,
		DisplayName:   response.DisplayName,
		Scopes:        response.Scopes,
	})
}

// GetAuthMethods returns the authentication methods available to the current user.
func (h *AuthHandler) GetAuthMethods(c *gin.Context) {
	claims, ok := h.authenticateRequest(c)
	if !ok {
		return
	}

	hasPassword, err := h.authService.HasPassword(c.Request.Context(), claims.UserID)
	if err != nil {
		commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "failed to check auth methods")
		return
	}

	providers, err := h.authService.GetLinkedProviders(c.Request.Context(), claims.UserID)
	if err != nil {
		commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "failed to get linked providers")
		return
	}

	c.JSON(http.StatusOK, AuthMethodsResponse{
		HasPassword: hasPassword,
		Providers:   providers,
	})
}

// SetPassword sets a password for users who don't have one (OAuth-only users).
func (h *AuthHandler) SetPassword(c *gin.Context) {
	claims, ok := h.authenticateRequest(c)
	if !ok {
		return
	}

	var req SetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		commonHandlers.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	if req.Password != req.ConfirmPassword {
		commonHandlers.RespondError(c, http.StatusBadRequest, "passwords do not match")
		return
	}

	if err := h.authService.SetPassword(c.Request.Context(), claims.UserID, req.Password); err != nil {
		switch {
		case errors.Is(err, service.ErrPasswordAlreadySet):
			commonHandlers.RespondError(c, http.StatusConflict, "password already set, use change-password instead")
		case errors.Is(err, service.ErrPasswordTooShort):
			commonHandlers.RespondError(c, http.StatusBadRequest, "password must be at least 8 characters")
		case errors.Is(err, service.ErrPasswordTooLong):
			commonHandlers.RespondError(c, http.StatusBadRequest, "password exceeds maximum length")
		default:
			commonHandlers.LogAndRespondError(c, http.StatusInternalServerError, err, "failed to set password")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password set successfully"})
}
