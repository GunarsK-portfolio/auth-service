package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GunarsK-portfolio/auth-service/internal/models"
	"github.com/GunarsK-portfolio/portfolio-common/jwt"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	testSecret        = "this-is-a-test-secret-with-32-bytes!"
	testAccessExpiry  = 15 * time.Minute
	testRefreshExpiry = 168 * time.Hour
	// jwtTimestampBuffer ensures JWT tokens have different IssuedAt timestamps.
	// JWT timestamps have 1-second resolution, so we sleep just over 1 second.
	jwtTimestampBuffer = 1001 * time.Millisecond
)

// =============================================================================
// Mock UserRepository
// =============================================================================

type mockUserRepository struct {
	findByUsernameFunc func(ctx context.Context, username string) (*models.User, error)
	findByEmailFunc    func(ctx context.Context, email string) (*models.User, error)
	findByIDFunc       func(ctx context.Context, id int64) (*models.User, error)
	createFunc         func(ctx context.Context, user *models.User) error
	updateFunc         func(ctx context.Context, user *models.User) error
	getUserScopesFunc  func(ctx context.Context, userID int64) (map[string]string, error)
}

func (m *mockUserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	if m.findByUsernameFunc != nil {
		return m.findByUsernameFunc(ctx, username)
	}
	return nil, errors.New("not implemented")
}

func (m *mockUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	if m.findByEmailFunc != nil {
		return m.findByEmailFunc(ctx, email)
	}
	return nil, errors.New("not implemented")
}

func (m *mockUserRepository) FindByID(ctx context.Context, id int64) (*models.User, error) {
	if m.findByIDFunc != nil {
		return m.findByIDFunc(ctx, id)
	}
	return nil, errors.New("not implemented")
}

func (m *mockUserRepository) Create(ctx context.Context, user *models.User) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, user)
	}
	return errors.New("not implemented")
}

func (m *mockUserRepository) Update(ctx context.Context, user *models.User) error {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, user)
	}
	return errors.New("not implemented")
}

func (m *mockUserRepository) GetUserScopes(ctx context.Context, userID int64) (map[string]string, error) {
	if m.getUserScopesFunc != nil {
		return m.getUserScopesFunc(ctx, userID)
	}
	// Default: return nil scopes (user without role)
	return nil, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func setupTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create miniredis: %v", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	return client, mr
}

func setupTestAuthService(t *testing.T) (*authService, *miniredis.Miniredis, *mockUserRepository) {
	t.Helper()

	redisClient, mr := setupTestRedis(t)
	jwtService, err := jwt.NewService(testSecret, testAccessExpiry, testRefreshExpiry)
	if err != nil {
		t.Fatalf("Failed to create JWT service: %v", err)
	}
	mockRepo := &mockUserRepository{}

	service := NewAuthService(mockRepo, jwtService, redisClient).(*authService)
	return service, mr, mockRepo
}

func hashPassword(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	return string(hash)
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewAuthService(t *testing.T) {
	redisClient, mr := setupTestRedis(t)
	defer mr.Close()

	jwtService, _ := jwt.NewService(testSecret, testAccessExpiry, testRefreshExpiry)
	mockRepo := &mockUserRepository{}

	service := NewAuthService(mockRepo, jwtService, redisClient)

	if service == nil {
		t.Error("NewAuthService() should return non-nil service")
	}
}

func TestAuthServiceInterfaceCompliance(t *testing.T) {
	redisClient, mr := setupTestRedis(t)
	defer mr.Close()

	jwtService, _ := jwt.NewService(testSecret, testAccessExpiry, testRefreshExpiry)
	mockRepo := &mockUserRepository{}

	var _ = NewAuthService(mockRepo, jwtService, redisClient)
}

// =============================================================================
// Login Tests
// =============================================================================

func TestLogin_Success(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			Email:        "test@example.com",
			PasswordHash: passwordHash,
		}, nil
	}

	result, err := service.Login(context.Background(), "testuser", "testpassword")

	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if result.AccessToken == "" {
		t.Error("Login() should return access token")
	}

	if result.RefreshToken == "" {
		t.Error("Login() should return refresh token")
	}

	if result.ExpiresIn <= 0 {
		t.Error("Login() should return positive expires_in")
	}

	// Verify refresh token was stored in Redis
	stored, err := mr.Get("refresh_token:1")
	if err != nil || stored != result.RefreshToken {
		t.Error("Login() should store refresh token in Redis")
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	_, err := service.Login(context.Background(), "nonexistent", "password")

	if err == nil {
		t.Error("Login() should fail for non-existent user")
	}

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login() error = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "correctpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	_, err := service.Login(context.Background(), "testuser", "wrongpassword")

	if err == nil {
		t.Error("Login() should fail for wrong password")
	}

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login() error = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestLogin_EmptyCredentials(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	tests := []struct {
		name     string
		username string
		password string
	}{
		{"empty username", "", "password"},
		{"empty password", "username", ""},
		{"both empty", "", ""},
	}

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		if username == "" {
			return nil, gorm.ErrRecordNotFound
		}
		return &models.User{
			ID:           1,
			Username:     username,
			PasswordHash: hashPassword(t, "password"),
		}, nil
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.Login(context.Background(), tt.username, tt.password)
			if err == nil {
				t.Error("Login() should fail for empty credentials")
			}
		})
	}
}

func TestLogin_RedisFailure(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	// Close Redis to simulate failure
	mr.Close()

	_, err := service.Login(context.Background(), "testuser", "testpassword")

	if err == nil {
		t.Error("Login() should fail when Redis is unavailable")
	}
}

func TestLogin_ContextCancellation(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: hashPassword(t, "password"),
		}, nil
	}

	_, err := service.Login(ctx, "testuser", "password")

	if err == nil {
		t.Error("Login() should fail when context is cancelled")
	}
}

// =============================================================================
// Scopes Tests
// =============================================================================

func TestLogin_WithScopes(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")
	testScopes := map[string]string{
		"profile":  "edit",
		"projects": "delete",
	}

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	mockRepo.getUserScopesFunc = func(ctx context.Context, userID int64) (map[string]string, error) {
		return testScopes, nil
	}

	result, err := service.Login(context.Background(), "testuser", "testpassword")

	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// Validate access token contains scopes
	claims, err := service.jwtService.ValidateToken(result.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if len(claims.Scopes) != 2 {
		t.Errorf("Access token scopes count = %d, want 2", len(claims.Scopes))
	}

	if claims.Scopes["profile"] != "edit" {
		t.Errorf("Access token scopes[profile] = %s, want edit", claims.Scopes["profile"])
	}

	if claims.Scopes["projects"] != "delete" {
		t.Errorf("Access token scopes[projects] = %s, want delete", claims.Scopes["projects"])
	}
}

func TestLogin_WithNilScopes(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	// getUserScopesFunc returns nil by default (user without role)

	result, err := service.Login(context.Background(), "testuser", "testpassword")

	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// Validate access token has nil/empty scopes
	claims, err := service.jwtService.ValidateToken(result.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if len(claims.Scopes) != 0 {
		t.Errorf("Access token scopes = %v, want nil or empty", claims.Scopes)
	}
}

func TestLogin_GetUserScopesError(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	mockRepo.getUserScopesFunc = func(ctx context.Context, userID int64) (map[string]string, error) {
		return nil, errors.New("database error")
	}

	_, err := service.Login(context.Background(), "testuser", "testpassword")

	if err == nil {
		t.Error("Login() should fail when GetUserScopes fails")
	}
}

func TestRefreshToken_PreservesScopes(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")
	testScopes := map[string]string{
		"profile":  "edit",
		"projects": "read",
	}

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	mockRepo.getUserScopesFunc = func(ctx context.Context, userID int64) (map[string]string, error) {
		return testScopes, nil
	}

	// Login to get tokens with scopes
	loginResult, err := service.Login(context.Background(), "testuser", "testpassword")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// Sleep to ensure different IssuedAt timestamp
	time.Sleep(jwtTimestampBuffer)

	// Refresh token
	refreshResult, err := service.RefreshToken(context.Background(), loginResult.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	// Validate new access token preserves scopes
	claims, err := service.jwtService.ValidateToken(refreshResult.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if len(claims.Scopes) != 2 {
		t.Errorf("Refreshed access token scopes count = %d, want 2", len(claims.Scopes))
	}

	if claims.Scopes["profile"] != "edit" {
		t.Errorf("Refreshed access token scopes[profile] = %s, want edit", claims.Scopes["profile"])
	}

	if claims.Scopes["projects"] != "read" {
		t.Errorf("Refreshed access token scopes[projects] = %s, want read", claims.Scopes["projects"])
	}
}

// =============================================================================
// Logout Tests
// =============================================================================

func TestLogout_Success(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	// Login first to get a valid token
	loginResult, err := service.Login(context.Background(), "testuser", "testpassword")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// Verify token exists in Redis
	if !mr.Exists("refresh_token:1") {
		t.Fatal("Refresh token should exist in Redis before logout")
	}

	// Logout
	err = service.Logout(context.Background(), loginResult.AccessToken)

	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	// Verify token was removed from Redis
	if mr.Exists("refresh_token:1") {
		t.Error("Logout() should remove refresh token from Redis")
	}
}

func TestLogout_InvalidToken(t *testing.T) {
	service, mr, _ := setupTestAuthService(t)
	defer mr.Close()

	err := service.Logout(context.Background(), "invalid-token")

	if err == nil {
		t.Error("Logout() should fail for invalid token")
	}
}

func TestLogout_ExpiredToken(t *testing.T) {
	// Create service with very short expiry
	redisClient, mr := setupTestRedis(t)
	defer mr.Close()

	shortExpiry := 1 * time.Second
	jwtService, _ := jwt.NewService(testSecret, shortExpiry, testRefreshExpiry)
	mockRepo := &mockUserRepository{}
	service := NewAuthService(mockRepo, jwtService, redisClient).(*authService)

	// Generate token
	token, err := jwtService.GenerateAccessToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Wait for expiry
	time.Sleep(shortExpiry + 100*time.Millisecond)

	// Try to logout with expired token
	err = service.Logout(context.Background(), token)

	if err == nil {
		t.Error("Logout() should fail for expired token")
	}
}

func TestLogout_RedisFailure(t *testing.T) {
	service, mr, _ := setupTestAuthService(t)

	// Generate valid token
	token, err := service.jwtService.GenerateAccessToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Close Redis to simulate failure
	mr.Close()

	err = service.Logout(context.Background(), token)

	if err == nil {
		t.Error("Logout() should fail when Redis is unavailable")
	}
}

// =============================================================================
// RefreshToken Tests
// =============================================================================

func TestRefreshToken_Success(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	// Login to get refresh token
	loginResult, err := service.Login(context.Background(), "testuser", "testpassword")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	oldRefreshToken := loginResult.RefreshToken

	// Sleep to ensure different IssuedAt timestamp (JWT timestamps are in seconds)
	time.Sleep(jwtTimestampBuffer)

	// Refresh token
	result, err := service.RefreshToken(context.Background(), loginResult.RefreshToken)

	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	if result.AccessToken == "" {
		t.Error("RefreshToken() should return new access token")
	}

	if result.RefreshToken == "" {
		t.Error("RefreshToken() should return new refresh token")
	}

	if result.RefreshToken == oldRefreshToken {
		t.Error("RefreshToken() should return different refresh token")
	}

	// Verify new refresh token is stored in Redis
	stored, err := mr.Get("refresh_token:1")
	if err != nil || stored != result.RefreshToken {
		t.Error("RefreshToken() should update refresh token in Redis")
	}
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	service, mr, _ := setupTestAuthService(t)
	defer mr.Close()

	_, err := service.RefreshToken(context.Background(), "invalid-token")

	if err == nil {
		t.Error("RefreshToken() should fail for invalid token")
	}
}

func TestRefreshToken_ExpiredToken(t *testing.T) {
	// Create service with very short refresh expiry
	redisClient, mr := setupTestRedis(t)
	defer mr.Close()

	shortExpiry := 1 * time.Second
	jwtService, _ := jwt.NewService(testSecret, testAccessExpiry, shortExpiry)
	mockRepo := &mockUserRepository{}
	service := NewAuthService(mockRepo, jwtService, redisClient).(*authService)

	// Generate refresh token
	token, err := jwtService.GenerateRefreshToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}

	// Store in Redis
	_ = mr.Set("refresh_token:1", token)

	// Wait for expiry
	time.Sleep(shortExpiry + 100*time.Millisecond)

	// Try to refresh with expired token
	_, err = service.RefreshToken(context.Background(), token)

	if err == nil {
		t.Error("RefreshToken() should fail for expired token")
	}
}

func TestRefreshToken_NotInRedis(t *testing.T) {
	service, mr, _ := setupTestAuthService(t)
	defer mr.Close()

	// Generate valid token but don't store in Redis
	token, err := service.jwtService.GenerateRefreshToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}

	_, err = service.RefreshToken(context.Background(), token)

	if err == nil {
		t.Error("RefreshToken() should fail if token not in Redis")
	}
}

func TestRefreshToken_TokenMismatch(t *testing.T) {
	service, mr, _ := setupTestAuthService(t)
	defer mr.Close()

	// Generate two different tokens
	token1, err := service.jwtService.GenerateRefreshToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}
	time.Sleep(jwtTimestampBuffer) // Ensure different IssuedAt
	token2, err := service.jwtService.GenerateRefreshToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}

	// Store token1 in Redis but try to refresh with token2
	_ = mr.Set("refresh_token:1", token1)

	_, err = service.RefreshToken(context.Background(), token2)

	if err == nil {
		t.Error("RefreshToken() should fail if token doesn't match stored token")
	}
}

func TestRefreshToken_RedisFailure(t *testing.T) {
	service, mr, _ := setupTestAuthService(t)

	// Generate valid token and store in Redis
	token, err := service.jwtService.GenerateRefreshToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}
	_ = mr.Set("refresh_token:1", token)

	// Close Redis to simulate failure
	mr.Close()

	_, err = service.RefreshToken(context.Background(), token)

	if err == nil {
		t.Error("RefreshToken() should fail when Redis is unavailable")
	}
}

// =============================================================================
// ValidateToken Tests
// =============================================================================

func TestAuthValidateToken_ValidToken(t *testing.T) {
	service, mr, _ := setupTestAuthService(t)
	defer mr.Close()

	token, err := service.jwtService.GenerateAccessToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	ttl, err := service.ValidateToken(token)

	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if ttl <= 0 {
		t.Error("ValidateToken() should return positive TTL for valid token")
	}

	// TTL should be close to access expiry
	expectedTTL := int64(testAccessExpiry.Seconds())
	if ttl > expectedTTL || ttl < expectedTTL-5 {
		t.Errorf("ValidateToken() TTL = %d, want close to %d", ttl, expectedTTL)
	}
}

func TestAuthValidateToken_InvalidToken(t *testing.T) {
	service, mr, _ := setupTestAuthService(t)
	defer mr.Close()

	_, err := service.ValidateToken("invalid-token")

	if err == nil {
		t.Error("ValidateToken() should fail for invalid token")
	}
}

func TestAuthValidateToken_ExpiredToken(t *testing.T) {
	// Create service with very short expiry
	redisClient, mr := setupTestRedis(t)
	defer mr.Close()

	shortExpiry := 1 * time.Second
	jwtService, err := jwt.NewService(testSecret, shortExpiry, testRefreshExpiry)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	mockRepo := &mockUserRepository{}
	service := NewAuthService(mockRepo, jwtService, redisClient).(*authService)

	// Generate token
	token, err := jwtService.GenerateAccessToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Wait for expiry
	time.Sleep(shortExpiry + 100*time.Millisecond)

	// Validate expired token
	_, err = service.ValidateToken(token)

	if err == nil {
		t.Error("ValidateToken() should fail for expired token")
	}
}

func TestValidateToken_AlmostExpired(t *testing.T) {
	// Create service with short expiry
	redisClient, mr := setupTestRedis(t)
	defer mr.Close()

	shortExpiry := 2 * time.Second
	jwtService, err := jwt.NewService(testSecret, shortExpiry, testRefreshExpiry)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	mockRepo := &mockUserRepository{}
	service := NewAuthService(mockRepo, jwtService, redisClient).(*authService)

	// Generate token
	token, err := jwtService.GenerateAccessToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Wait for most of the expiry
	time.Sleep(1 * time.Second)

	// Validate almost-expired token
	ttl, err := service.ValidateToken(token)

	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	// TTL should be around 1 second (maybe less due to JWT precision)
	if ttl < 0 || ttl > 2 {
		t.Errorf("ValidateToken() TTL = %d, want 0-2 for almost-expired token", ttl)
	}
}

// =============================================================================
// Concurrency Tests
// =============================================================================

func TestConcurrentLogins(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     username,
			PasswordHash: passwordHash,
		}, nil
	}

	const numGoroutines = 10
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			_, err := service.Login(context.Background(), "testuser", "testpassword")
			errors <- err
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		if err := <-errors; err != nil {
			t.Errorf("Concurrent login %d failed: %v", i, err)
		}
	}
}

func TestConcurrentRefreshToken(t *testing.T) {
	service, mr, mockRepo := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	// Login to get refresh token
	loginResult, err := service.Login(context.Background(), "testuser", "testpassword")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	const numGoroutines = 5
	errors := make(chan error, numGoroutines)
	results := make(chan *LoginResponse, numGoroutines)

	// Multiple concurrent refresh attempts with same token
	for i := 0; i < numGoroutines; i++ {
		go func() {
			result, err := service.RefreshToken(context.Background(), loginResult.RefreshToken)
			errors <- err
			results <- result
		}()
	}

	successCount := 0
	for i := 0; i < numGoroutines; i++ {
		err := <-errors
		result := <-results
		if err == nil && result != nil {
			successCount++
		}
	}

	// At least one should succeed (due to race conditions, others might fail)
	if successCount == 0 {
		t.Error("At least one concurrent RefreshToken() should succeed")
	}
}
