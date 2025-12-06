package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GunarsK-portfolio/auth-service/internal/service"
	common "github.com/GunarsK-portfolio/portfolio-common/config"
	"github.com/GunarsK-portfolio/portfolio-common/jwt"
	"github.com/GunarsK-portfolio/portfolio-common/repository"
	"github.com/gin-gonic/gin"
)

// =============================================================================
// Mock Implementations
// =============================================================================

type mockAuthService struct {
	loginFunc                   func(ctx context.Context, username, password string) (*service.LoginResponse, error)
	logoutFunc                  func(ctx context.Context, token string) error
	refreshTokenFunc            func(ctx context.Context, refreshToken string) (*service.LoginResponse, error)
	validateTokenFunc           func(token string) (int64, error)
	validateTokenWithClaimsFunc func(token string) (int64, *jwt.Claims, error)
}

func (m *mockAuthService) Login(ctx context.Context, username, password string) (*service.LoginResponse, error) {
	if m.loginFunc != nil {
		return m.loginFunc(ctx, username, password)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAuthService) Logout(ctx context.Context, token string) error {
	if m.logoutFunc != nil {
		return m.logoutFunc(ctx, token)
	}
	return errors.New("not implemented")
}

func (m *mockAuthService) RefreshToken(ctx context.Context, refreshToken string) (*service.LoginResponse, error) {
	if m.refreshTokenFunc != nil {
		return m.refreshTokenFunc(ctx, refreshToken)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAuthService) ValidateToken(token string) (int64, error) {
	if m.validateTokenFunc != nil {
		return m.validateTokenFunc(token)
	}
	return 0, errors.New("not implemented")
}

func (m *mockAuthService) ValidateTokenWithClaims(token string) (int64, *jwt.Claims, error) {
	if m.validateTokenWithClaimsFunc != nil {
		return m.validateTokenWithClaimsFunc(token)
	}
	return 0, nil, errors.New("not implemented")
}

type mockJWTService struct {
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

func (m *mockJWTService) ValidateToken(tokenString string) (*jwt.Claims, error) {
	return &jwt.Claims{
		UserID:   1,
		Username: "testuser",
		Scopes:   map[string]string{},
	}, nil
}

func (m *mockJWTService) GenerateAccessToken(userID int64, username string, scopes map[string]string) (string, error) {
	return "access_token", nil
}

func (m *mockJWTService) GenerateRefreshToken(userID int64, username string, scopes map[string]string) (string, error) {
	return "refresh_token", nil
}

func (m *mockJWTService) GetAccessExpiry() time.Duration {
	return m.accessExpiry
}

func (m *mockJWTService) GetRefreshExpiry() time.Duration {
	return m.refreshExpiry
}

// mockJWTServiceWithScopes returns specific scopes when validating tokens
type mockJWTServiceWithScopes struct {
	scopes map[string]string
}

func (m *mockJWTServiceWithScopes) ValidateToken(tokenString string) (*jwt.Claims, error) {
	return &jwt.Claims{
		UserID:   1,
		Username: "testuser",
		Scopes:   m.scopes,
	}, nil
}

func (m *mockJWTServiceWithScopes) GenerateAccessToken(userID int64, username string, scopes map[string]string) (string, error) {
	return "access_token", nil
}

func (m *mockJWTServiceWithScopes) GenerateRefreshToken(userID int64, username string, scopes map[string]string) (string, error) {
	return "refresh_token", nil
}

func (m *mockJWTServiceWithScopes) GetAccessExpiry() time.Duration {
	return 15 * time.Minute
}

func (m *mockJWTServiceWithScopes) GetRefreshExpiry() time.Duration {
	return 7 * 24 * time.Hour
}

type mockActionLogRepository struct{}

func (m *mockActionLogRepository) LogAction(log *repository.ActionLog) error {
	return nil
}

func (m *mockActionLogRepository) GetActionsByType(actionType string, limit int) ([]repository.ActionLog, error) {
	return nil, nil
}

func (m *mockActionLogRepository) GetActionsByResource(resourceType string, resourceID int64) ([]repository.ActionLog, error) {
	return nil, nil
}

func (m *mockActionLogRepository) GetActionsByUser(userID int64, limit int) ([]repository.ActionLog, error) {
	return nil, nil
}

func (m *mockActionLogRepository) CountActionsByResource(resourceType string, resourceID int64) (int64, error) {
	return 0, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func setupTestHandler(mockService *mockAuthService) *AuthHandler {
	cookieHelper := NewCookieHelper(common.CookieConfig{
		Path:     "/",
		Domain:   "",
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
	jwtService := &mockJWTService{
		accessExpiry:  15 * time.Minute,
		refreshExpiry: 7 * 24 * time.Hour,
	}
	actionLogRepo := &mockActionLogRepository{}
	return NewAuthHandler(mockService, actionLogRepo, cookieHelper, jwtService)
}

func createTestContext(method, path string, body interface{}) (*httptest.ResponseRecorder, *gin.Context) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	var bodyBytes []byte
	if body != nil {
		bodyBytes, _ = json.Marshal(body)
	}

	c.Request = httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
	c.Request.Header.Set("Content-Type", "application/json")
	return w, c
}

// =============================================================================
// Login Handler Tests
// =============================================================================

func TestLogin_Success(t *testing.T) {
	mockService := &mockAuthService{
		loginFunc: func(ctx context.Context, username, password string) (*service.LoginResponse, error) {
			return &service.LoginResponse{
				AccessToken:  "access_token_123",
				RefreshToken: "refresh_token_456",
				ExpiresIn:    900,
				UserID:       1,
				Username:     "testuser",
			}, nil
		},
	}

	handler := setupTestHandler(mockService)
	w, c := createTestContext("POST", "/api/v1/auth/login", LoginRequest{
		Username: "testuser",
		Password: "password123",
	})

	handler.Login(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !response.Success {
		t.Error("expected success=true")
	}
	if response.ExpiresIn != 900 {
		t.Errorf("expected ExpiresIn=900, got %d", response.ExpiresIn)
	}
	if response.UserID != 1 {
		t.Errorf("expected UserID=1, got %d", response.UserID)
	}
	if response.Username != "testuser" {
		t.Errorf("expected Username=testuser, got %s", response.Username)
	}

	// Verify cookies are set
	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Errorf("expected 2 cookies, got %d", len(cookies))
	}

	var hasAccess, hasRefresh bool
	for _, cookie := range cookies {
		if cookie.Name == AccessTokenCookie {
			hasAccess = true
			if cookie.Value != "access_token_123" {
				t.Errorf("access_token value = %s, want access_token_123", cookie.Value)
			}
		}
		if cookie.Name == RefreshTokenCookie {
			hasRefresh = true
			if cookie.Value != "refresh_token_456" {
				t.Errorf("refresh_token value = %s, want refresh_token_456", cookie.Value)
			}
		}
	}
	if !hasAccess {
		t.Error("access_token cookie not set")
	}
	if !hasRefresh {
		t.Error("refresh_token cookie not set")
	}
}

func TestLogin_InvalidCredentials(t *testing.T) {
	mockService := &mockAuthService{
		loginFunc: func(ctx context.Context, username, password string) (*service.LoginResponse, error) {
			return nil, errors.New("invalid credentials")
		},
	}

	handler := setupTestHandler(mockService)
	w, c := createTestContext("POST", "/api/v1/auth/login", LoginRequest{
		Username: "testuser",
		Password: "wrongpassword",
	})

	handler.Login(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestLogin_MissingUsername(t *testing.T) {
	mockService := &mockAuthService{}
	handler := setupTestHandler(mockService)
	w, c := createTestContext("POST", "/api/v1/auth/login", map[string]string{
		"password": "password123",
	})

	handler.Login(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestLogin_MissingPassword(t *testing.T) {
	mockService := &mockAuthService{}
	handler := setupTestHandler(mockService)
	w, c := createTestContext("POST", "/api/v1/auth/login", map[string]string{
		"username": "testuser",
	})

	handler.Login(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestLogin_InvalidJSON(t *testing.T) {
	mockService := &mockAuthService{}
	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader([]byte("invalid json")))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.Login(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestLogin_ReturnsScopesFromToken(t *testing.T) {
	mockService := &mockAuthService{
		loginFunc: func(ctx context.Context, username, password string) (*service.LoginResponse, error) {
			return &service.LoginResponse{
				AccessToken:  "access_token_with_scopes",
				RefreshToken: "refresh_token_456",
				ExpiresIn:    900,
				UserID:       1,
				Username:     "admin",
				Scopes:       map[string]string{"profile": "edit", "projects": "delete"},
			}, nil
		},
	}

	// Create handler with custom JWT service that returns scopes
	cookieHelper := NewCookieHelper(common.CookieConfig{
		Path:     "/",
		Domain:   "",
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
	jwtService := &mockJWTServiceWithScopes{
		scopes: map[string]string{"profile": "edit", "projects": "delete"},
	}
	actionLogRepo := &mockActionLogRepository{}
	handler := NewAuthHandler(mockService, actionLogRepo, cookieHelper, jwtService)

	w, c := createTestContext("POST", "/api/v1/auth/login", LoginRequest{
		Username: "admin",
		Password: "password123",
	})

	handler.Login(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Scopes == nil {
		t.Fatal("expected scopes to be returned")
	}
	if response.Scopes["profile"] != "edit" {
		t.Errorf("expected scopes[profile]=edit, got %s", response.Scopes["profile"])
	}
	if response.Scopes["projects"] != "delete" {
		t.Errorf("expected scopes[projects]=delete, got %s", response.Scopes["projects"])
	}
}

// =============================================================================
// Logout Handler Tests
// =============================================================================

func TestLogout_Success_Cookie(t *testing.T) {
	mockService := &mockAuthService{
		logoutFunc: func(ctx context.Context, token string) error {
			return nil
		},
	}

	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	c.Request.AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: "valid_token"})

	handler.Logout(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify cookies are cleared (MaxAge=-1)
	cookies := w.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == AccessTokenCookie || cookie.Name == RefreshTokenCookie {
			if cookie.MaxAge != -1 {
				t.Errorf("cookie %s should have MaxAge=-1, got %d", cookie.Name, cookie.MaxAge)
			}
		}
	}
}

func TestLogout_Success_Header(t *testing.T) {
	mockService := &mockAuthService{
		logoutFunc: func(ctx context.Context, token string) error {
			if token != "header_token" {
				t.Errorf("expected token=header_token, got %s", token)
			}
			return nil
		},
	}

	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	c.Request.Header.Set("Authorization", "Bearer header_token")

	handler.Logout(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestLogout_NoToken(t *testing.T) {
	mockService := &mockAuthService{}
	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/logout", nil)

	handler.Logout(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestLogout_ServiceError(t *testing.T) {
	mockService := &mockAuthService{
		logoutFunc: func(ctx context.Context, token string) error {
			return errors.New("logout failed")
		},
	}

	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	c.Request.AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: "valid_token"})

	handler.Logout(c)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// =============================================================================
// Refresh Handler Tests
// =============================================================================

func TestRefresh_Success(t *testing.T) {
	mockService := &mockAuthService{
		refreshTokenFunc: func(ctx context.Context, refreshToken string) (*service.LoginResponse, error) {
			return &service.LoginResponse{
				AccessToken:  "new_access_token",
				RefreshToken: "new_refresh_token",
				ExpiresIn:    900,
			}, nil
		},
	}

	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/refresh", nil)
	c.Request.AddCookie(&http.Cookie{Name: RefreshTokenCookie, Value: "old_refresh_token"})

	handler.Refresh(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !response.Success {
		t.Error("expected success=true")
	}

	// Verify new cookies are set
	cookies := w.Result().Cookies()
	var hasNewAccess, hasNewRefresh bool
	for _, cookie := range cookies {
		if cookie.Name == AccessTokenCookie && cookie.Value == "new_access_token" {
			hasNewAccess = true
		}
		if cookie.Name == RefreshTokenCookie && cookie.Value == "new_refresh_token" {
			hasNewRefresh = true
		}
	}
	if !hasNewAccess {
		t.Error("new access_token cookie not set")
	}
	if !hasNewRefresh {
		t.Error("new refresh_token cookie not set")
	}
}

func TestRefresh_NoToken(t *testing.T) {
	mockService := &mockAuthService{}
	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/refresh", nil)

	handler.Refresh(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	mockService := &mockAuthService{
		refreshTokenFunc: func(ctx context.Context, refreshToken string) (*service.LoginResponse, error) {
			return nil, errors.New("invalid refresh token")
		},
	}

	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/refresh", nil)
	c.Request.AddCookie(&http.Cookie{Name: RefreshTokenCookie, Value: "invalid_token"})

	handler.Refresh(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// =============================================================================
// Validate Handler Tests
// =============================================================================

func TestValidate_Success(t *testing.T) {
	mockService := &mockAuthService{
		validateTokenWithClaimsFunc: func(token string) (int64, *jwt.Claims, error) {
			return 600, &jwt.Claims{UserID: 1, Username: "testuser"}, nil
		},
	}

	handler := setupTestHandler(mockService)
	w, c := createTestContext("POST", "/api/v1/auth/validate", ValidateRequest{
		Token: "valid_token",
	})

	handler.Validate(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response ValidateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !response.Valid {
		t.Error("expected valid=true")
	}
	if response.TTLSeconds != 600 {
		t.Errorf("expected TTLSeconds=600, got %d", response.TTLSeconds)
	}
	if response.UserID != 1 {
		t.Errorf("expected UserID=1, got %d", response.UserID)
	}
	if response.Username != "testuser" {
		t.Errorf("expected Username=testuser, got %s", response.Username)
	}
}

func TestValidate_InvalidToken(t *testing.T) {
	mockService := &mockAuthService{
		validateTokenWithClaimsFunc: func(token string) (int64, *jwt.Claims, error) {
			return 0, nil, errors.New("invalid token")
		},
	}

	handler := setupTestHandler(mockService)
	w, c := createTestContext("POST", "/api/v1/auth/validate", ValidateRequest{
		Token: "invalid_token",
	})

	handler.Validate(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	var response ValidateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Valid {
		t.Error("expected valid=false")
	}
}

func TestValidate_MissingToken(t *testing.T) {
	mockService := &mockAuthService{}
	handler := setupTestHandler(mockService)
	w, c := createTestContext("POST", "/api/v1/auth/validate", map[string]string{})

	handler.Validate(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// =============================================================================
// TokenStatus Handler Tests
// =============================================================================

func TestTokenStatus_Success_Cookie(t *testing.T) {
	mockService := &mockAuthService{
		validateTokenWithClaimsFunc: func(token string) (int64, *jwt.Claims, error) {
			return 600, &jwt.Claims{
				UserID:   1,
				Username: "testuser",
				Scopes:   map[string]string{"profile": "edit"},
			}, nil
		},
	}

	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/auth/token-status", nil)
	c.Request.AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: "valid_token"})

	handler.TokenStatus(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response TokenStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !response.Valid {
		t.Error("expected valid=true")
	}
	if response.TTLSeconds != 600 {
		t.Errorf("expected TTLSeconds=600, got %d", response.TTLSeconds)
	}
	if response.Scopes["profile"] != "edit" {
		t.Errorf("expected scopes[profile]=edit, got %v", response.Scopes)
	}
}

func TestTokenStatus_Success_Header(t *testing.T) {
	mockService := &mockAuthService{
		validateTokenWithClaimsFunc: func(token string) (int64, *jwt.Claims, error) {
			if token != "header_token" {
				t.Errorf("expected token=header_token, got %s", token)
			}
			return 600, &jwt.Claims{
				UserID:   1,
				Username: "testuser",
				Scopes:   map[string]string{"profile": "edit", "projects": "read"},
			}, nil
		},
	}

	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/auth/token-status", nil)
	c.Request.Header.Set("Authorization", "Bearer header_token")

	handler.TokenStatus(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response TokenStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify scopes are returned for header-based auth (symmetry with cookie test)
	if response.Scopes["profile"] != "edit" {
		t.Errorf("expected scopes[profile]=edit, got %s", response.Scopes["profile"])
	}
	if response.Scopes["projects"] != "read" {
		t.Errorf("expected scopes[projects]=read, got %s", response.Scopes["projects"])
	}
}

func TestTokenStatus_NoToken(t *testing.T) {
	mockService := &mockAuthService{}
	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/auth/token-status", nil)

	handler.TokenStatus(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	var response TokenStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Valid {
		t.Error("expected valid=false")
	}
}

func TestTokenStatus_InvalidToken(t *testing.T) {
	mockService := &mockAuthService{
		validateTokenWithClaimsFunc: func(token string) (int64, *jwt.Claims, error) {
			return 0, nil, errors.New("invalid token")
		},
	}

	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/auth/token-status", nil)
	c.Request.AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: "invalid_token"})

	handler.TokenStatus(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestTokenStatus_ExpiredToken(t *testing.T) {
	mockService := &mockAuthService{
		validateTokenWithClaimsFunc: func(token string) (int64, *jwt.Claims, error) {
			return 0, &jwt.Claims{}, nil // TTL=0 means expired
		},
	}

	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/auth/token-status", nil)
	c.Request.AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: "expired_token"})

	handler.TokenStatus(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// =============================================================================
// extractToken Tests
// =============================================================================

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		want       string
	}{
		{
			name:       "valid bearer token",
			authHeader: "Bearer valid_token",
			want:       "valid_token",
		},
		{
			name:       "no auth header",
			authHeader: "",
			want:       "",
		},
		{
			name:       "invalid format - no bearer",
			authHeader: "valid_token",
			want:       "",
		},
		{
			name:       "invalid format - multiple spaces",
			authHeader: "Bearer token extra",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/", nil)
			if tt.authHeader != "" {
				c.Request.Header.Set("Authorization", tt.authHeader)
			}

			got := extractToken(c)
			if got != tt.want {
				t.Errorf("extractToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

// =============================================================================
// Constructor Test
// =============================================================================

func TestNewAuthHandler(t *testing.T) {
	mockService := &mockAuthService{}
	cookieHelper := NewCookieHelper(common.CookieConfig{})
	jwtService := &mockJWTService{}

	handler := NewAuthHandler(mockService, nil, cookieHelper, jwtService)

	if handler == nil {
		t.Fatal("NewAuthHandler returned nil")
	}
	if handler.authService != mockService {
		t.Error("authService not set correctly")
	}
	if handler.cookieHelper != cookieHelper {
		t.Error("cookieHelper not set correctly")
	}
	if handler.jwtService != jwtService {
		t.Error("jwtService not set correctly")
	}
}

// =============================================================================
// Cookie Priority Tests (cookie preferred over header)
// =============================================================================

func TestLogout_CookiePriorityOverHeader(t *testing.T) {
	var receivedToken string
	mockService := &mockAuthService{
		logoutFunc: func(ctx context.Context, token string) error {
			receivedToken = token
			return nil
		},
	}

	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	c.Request.AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: "cookie_token"})
	c.Request.Header.Set("Authorization", "Bearer header_token")

	handler.Logout(c)

	if receivedToken != "cookie_token" {
		t.Errorf("expected cookie_token to be used, got %s", receivedToken)
	}
}

func TestTokenStatus_CookiePriorityOverHeader(t *testing.T) {
	var receivedToken string
	mockService := &mockAuthService{
		validateTokenWithClaimsFunc: func(token string) (int64, *jwt.Claims, error) {
			receivedToken = token
			return 600, &jwt.Claims{
				UserID:   1,
				Username: "testuser",
				Scopes:   map[string]string{},
			}, nil
		},
	}

	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/auth/token-status", nil)
	c.Request.AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: "cookie_token"})
	c.Request.Header.Set("Authorization", "Bearer header_token")

	handler.TokenStatus(c)

	if receivedToken != "cookie_token" {
		t.Errorf("expected cookie_token to be used, got %s", receivedToken)
	}
}

// =============================================================================
// Security Tests - Tokens Not Exposed in Response Body
// =============================================================================

func TestLogin_TokensNotInResponseBody(t *testing.T) {
	mockService := &mockAuthService{
		loginFunc: func(ctx context.Context, username, password string) (*service.LoginResponse, error) {
			return &service.LoginResponse{
				AccessToken:  "secret_access_token",
				RefreshToken: "secret_refresh_token",
				ExpiresIn:    900,
				UserID:       1,
				Username:     "testuser",
			}, nil
		},
	}

	handler := setupTestHandler(mockService)
	w, c := createTestContext("POST", "/api/v1/auth/login", LoginRequest{
		Username: "testuser",
		Password: "password123",
	})

	handler.Login(c)

	// Verify tokens are NOT in response body
	body := w.Body.String()
	if strings.Contains(body, "secret_access_token") {
		t.Error("access_token should not be in response body")
	}
	if strings.Contains(body, "secret_refresh_token") {
		t.Error("refresh_token should not be in response body")
	}
	if strings.Contains(body, "access_token") && strings.Contains(body, "secret") {
		t.Error("tokens should not be exposed in response body")
	}

	// Verify tokens ARE in cookies
	cookies := w.Result().Cookies()
	var foundAccess, foundRefresh bool
	for _, cookie := range cookies {
		if cookie.Name == AccessTokenCookie && cookie.Value == "secret_access_token" {
			foundAccess = true
		}
		if cookie.Name == RefreshTokenCookie && cookie.Value == "secret_refresh_token" {
			foundRefresh = true
		}
	}
	if !foundAccess {
		t.Error("access_token should be in cookie")
	}
	if !foundRefresh {
		t.Error("refresh_token should be in cookie")
	}
}

func TestRefresh_TokensNotInResponseBody(t *testing.T) {
	mockService := &mockAuthService{
		refreshTokenFunc: func(ctx context.Context, refreshToken string) (*service.LoginResponse, error) {
			return &service.LoginResponse{
				AccessToken:  "new_secret_access",
				RefreshToken: "new_secret_refresh",
				ExpiresIn:    900,
			}, nil
		},
	}

	handler := setupTestHandler(mockService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/auth/refresh", nil)
	c.Request.AddCookie(&http.Cookie{Name: RefreshTokenCookie, Value: "old_refresh"})

	handler.Refresh(c)

	// Verify tokens are NOT in response body
	body := w.Body.String()
	if strings.Contains(body, "new_secret_access") {
		t.Error("access_token should not be in response body")
	}
	if strings.Contains(body, "new_secret_refresh") {
		t.Error("refresh_token should not be in response body")
	}
}

// =============================================================================
// extractToken Security Tests
// =============================================================================

func TestExtractToken_RequiresBearerScheme(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		want       string
	}{
		{
			name:       "valid Bearer token",
			authHeader: "Bearer valid_token",
			want:       "valid_token",
		},
		{
			name:       "lowercase bearer rejected",
			authHeader: "bearer lowercase_token",
			want:       "",
		},
		{
			name:       "Basic auth rejected",
			authHeader: "Basic dXNlcjpwYXNz",
			want:       "",
		},
		{
			name:       "arbitrary scheme rejected",
			authHeader: "Token some_token",
			want:       "",
		},
		{
			name:       "no scheme rejected",
			authHeader: "just_a_token",
			want:       "",
		},
		{
			name:       "empty header",
			authHeader: "",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/", nil)
			if tt.authHeader != "" {
				c.Request.Header.Set("Authorization", tt.authHeader)
			}

			got := extractToken(c)
			if got != tt.want {
				t.Errorf("extractToken() = %q, want %q", got, tt.want)
			}
		})
	}
}
