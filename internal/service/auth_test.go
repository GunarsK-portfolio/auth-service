package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
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
	findRoleByCodeFunc func(ctx context.Context, code string) (*models.Role, error)
}

// =============================================================================
// Mock VerificationTokenRepository
// =============================================================================

type mockVerifyRepo struct {
	createFunc              func(ctx context.Context, token *models.VerificationToken) error
	findByTokenFunc         func(ctx context.Context, token string) (*models.VerificationToken, error)
	findByUserIDFunc        func(ctx context.Context, userID int64) (*models.VerificationToken, error)
	findByTokenAndTypeFunc  func(ctx context.Context, tokenHash, tokenType string) (*models.VerificationToken, error)
	findByUserIDAndTypeFunc func(ctx context.Context, userID int64, tokenType string) (*models.VerificationToken, error)
	deleteByUserFunc        func(ctx context.Context, userID int64) error
	deleteByUserAndTypeFunc func(ctx context.Context, userID int64, tokenType string) error
	markUsedFunc            func(ctx context.Context, id int64) error
}

func (m *mockVerifyRepo) Create(ctx context.Context, token *models.VerificationToken) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, token)
	}
	return nil
}

func (m *mockVerifyRepo) FindByToken(ctx context.Context, token string) (*models.VerificationToken, error) {
	if m.findByTokenFunc != nil {
		return m.findByTokenFunc(ctx, token)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVerifyRepo) FindByUserID(ctx context.Context, userID int64) (*models.VerificationToken, error) {
	if m.findByUserIDFunc != nil {
		return m.findByUserIDFunc(ctx, userID)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVerifyRepo) FindByTokenAndType(ctx context.Context, tokenHash, tokenType string) (*models.VerificationToken, error) {
	if m.findByTokenAndTypeFunc != nil {
		return m.findByTokenAndTypeFunc(ctx, tokenHash, tokenType)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVerifyRepo) FindByUserIDAndType(ctx context.Context, userID int64, tokenType string) (*models.VerificationToken, error) {
	if m.findByUserIDAndTypeFunc != nil {
		return m.findByUserIDAndTypeFunc(ctx, userID, tokenType)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVerifyRepo) DeleteByUserID(ctx context.Context, userID int64) error {
	if m.deleteByUserFunc != nil {
		return m.deleteByUserFunc(ctx, userID)
	}
	return nil
}

func (m *mockVerifyRepo) DeleteByUserIDAndType(ctx context.Context, userID int64, tokenType string) error {
	if m.deleteByUserAndTypeFunc != nil {
		return m.deleteByUserAndTypeFunc(ctx, userID, tokenType)
	}
	return nil
}

func (m *mockVerifyRepo) MarkUsed(ctx context.Context, id int64) error {
	if m.markUsedFunc != nil {
		return m.markUsedFunc(ctx, id)
	}
	return nil
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

func (m *mockUserRepository) FindRoleByCode(ctx context.Context, code string) (*models.Role, error) {
	if m.findRoleByCodeFunc != nil {
		return m.findRoleByCodeFunc(ctx, code)
	}
	return nil, errors.New("not implemented")
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

func setupTestAuthService(t *testing.T) (*authService, *miniredis.Miniredis, *mockUserRepository, *mockVerifyRepo) {
	t.Helper()

	redisClient, mr := setupTestRedis(t)
	jwtService, err := jwt.NewService(testSecret, testAccessExpiry, testRefreshExpiry)
	if err != nil {
		t.Fatalf("Failed to create JWT service: %v", err)
	}
	mockRepo := &mockUserRepository{}
	mockVerify := &mockVerifyRepo{}

	// Default FindByID returns a basic user so refresh tests work out of the box.
	// Individual tests can override this.
	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:            id,
			Username:      "testuser",
			Email:         "test@example.com",
			EmailVerified: false,
		}, nil
	}
	mockRepo.getUserScopesFunc = func(ctx context.Context, userID int64) (map[string]string, error) {
		return nil, nil
	}

	svc := NewAuthService(
		nil, mockRepo, mockVerify, jwtService, testSecret,
		redisClient, nil, slog.Default(), []string{"admin", "rpg-admin"}, 3, time.Hour,
	).(*authService)
	return svc, mr, mockRepo, mockVerify
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
	mockVerify := &mockVerifyRepo{}

	svc := NewAuthService(nil, mockRepo, mockVerify, jwtService, testSecret, redisClient, nil, slog.Default(), []string{"admin"}, 3, time.Hour)

	if svc == nil {
		t.Error("NewAuthService() should return non-nil service")
	}
}

func TestAuthServiceInterfaceCompliance(t *testing.T) {
	redisClient, mr := setupTestRedis(t)
	defer mr.Close()

	jwtService, _ := jwt.NewService(testSecret, testAccessExpiry, testRefreshExpiry)
	mockRepo := &mockUserRepository{}
	mockVerify := &mockVerifyRepo{}

	var _ = NewAuthService(nil, mockRepo, mockVerify, jwtService, testSecret, redisClient, nil, slog.Default(), []string{"admin"}, 3, time.Hour)
}

// =============================================================================
// Login Tests
// =============================================================================

func TestLogin_Success(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
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

	result, err := service.Login(context.Background(), "testuser", "testpassword", false)

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

	if result.SessionID == "" {
		t.Error("Login() should return a session ID")
	}

	// Verify refresh token was stored in Redis with session ID
	stored, err := mr.Get("refresh_token:1:" + result.SessionID)
	if err != nil || stored != result.RefreshToken {
		t.Error("Login() should store refresh token in Redis")
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	_, err := service.Login(context.Background(), "nonexistent", "password", false)

	if err == nil {
		t.Error("Login() should fail for non-existent user")
	}

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login() error = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "correctpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	_, err := service.Login(context.Background(), "testuser", "wrongpassword", false)

	if err == nil {
		t.Error("Login() should fail for wrong password")
	}

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login() error = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestLogin_EmptyCredentials(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
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
			_, err := service.Login(context.Background(), tt.username, tt.password, false)
			if err == nil {
				t.Error("Login() should fail for empty credentials")
			}
		})
	}
}

func TestLogin_RedisFailure(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)

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

	_, err := service.Login(context.Background(), "testuser", "testpassword", false)

	if err == nil {
		t.Error("Login() should fail when Redis is unavailable")
	}
}

func TestLogin_ContextCancellation(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
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

	_, err := service.Login(ctx, "testuser", "password", false)

	if err == nil {
		t.Error("Login() should fail when context is cancelled")
	}
}

// =============================================================================
// Remember Me Tests
// =============================================================================

func TestLogin_RememberMe_StoresInRedis(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	result, err := service.Login(context.Background(), "testuser", "testpassword", true)

	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if !result.RememberMe {
		t.Error("Login() RememberMe should be true")
	}

	// Verify remember_me was stored in Redis with session ID
	val, err := mr.Get("remember_me:1:" + result.SessionID)
	if err != nil {
		t.Fatal("remember_me should exist in Redis")
	}
	if val != "1" {
		t.Errorf("remember_me = %s, want 1", val)
	}
}

func TestLogin_NoRememberMe_StoresFalseInRedis(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	result, err := service.Login(context.Background(), "testuser", "testpassword", false)

	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if result.RememberMe {
		t.Error("Login() RememberMe should be false")
	}

	val, err := mr.Get("remember_me:1:" + result.SessionID)
	if err != nil {
		t.Fatal("remember_me should exist in Redis")
	}
	if val != "0" {
		t.Errorf("remember_me = %s, want 0", val)
	}
}

func TestRefreshToken_PreservesRememberMe(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	// Login with remember_me=true
	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", true)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	time.Sleep(jwtTimestampBuffer)

	// Refresh should preserve remember_me=true
	refreshResult, err := service.RefreshToken(context.Background(), loginResult.RefreshToken, loginResult.SessionID)
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	if !refreshResult.RememberMe {
		t.Error("RefreshToken() should preserve RememberMe=true")
	}

	if refreshResult.SessionID != loginResult.SessionID {
		t.Errorf("RefreshToken() SessionID = %q, want %q", refreshResult.SessionID, loginResult.SessionID)
	}

	// Verify remember_me key still exists with value "1"
	val, err := mr.Get("remember_me:1:" + loginResult.SessionID)
	if err != nil {
		t.Fatal("remember_me should still exist after refresh")
	}
	if val != "1" {
		t.Errorf("remember_me = %s, want 1 after refresh", val)
	}
}

func TestRefreshToken_RememberMeFalsePreserved(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	// Login with remember_me=false
	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", false)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	time.Sleep(jwtTimestampBuffer)

	// Refresh should preserve remember_me=false
	refreshResult, err := service.RefreshToken(context.Background(), loginResult.RefreshToken, loginResult.SessionID)
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	if refreshResult.RememberMe {
		t.Error("RefreshToken() should preserve RememberMe=false")
	}
}

func TestRefreshToken_RememberMeDefaultsFalseOnMiss(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	// Login to get a valid refresh token
	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", true)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// Manually delete the remember_me key to simulate a miss
	mr.Del("remember_me:1:" + loginResult.SessionID)

	time.Sleep(jwtTimestampBuffer)

	refreshResult, err := service.RefreshToken(context.Background(), loginResult.RefreshToken, loginResult.SessionID)
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	if refreshResult.RememberMe {
		t.Error("RefreshToken() should default RememberMe=false on Redis miss")
	}
}

func TestLogout_CleansUpRememberMe(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	// Login with remember_me=true
	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", true)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// Verify both keys exist
	rtKey := "refresh_token:1:" + loginResult.SessionID
	rmKey := "remember_me:1:" + loginResult.SessionID
	if !mr.Exists(rtKey) {
		t.Fatal("refresh_token should exist before logout")
	}
	if !mr.Exists(rmKey) {
		t.Fatal("remember_me should exist before logout")
	}

	// Logout
	err = service.Logout(context.Background(), loginResult.AccessToken, loginResult.SessionID)
	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	// Verify both keys are deleted
	if mr.Exists(rtKey) {
		t.Error("Logout() should remove refresh_token from Redis")
	}
	if mr.Exists(rmKey) {
		t.Error("Logout() should remove remember_me from Redis")
	}
}

// =============================================================================
// Scopes Tests
// =============================================================================

func TestLogin_WithScopes(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
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

	result, err := service.Login(context.Background(), "testuser", "testpassword", false)

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
	service, mr, mockRepo, _ := setupTestAuthService(t)
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

	result, err := service.Login(context.Background(), "testuser", "testpassword", false)

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
	service, mr, mockRepo, _ := setupTestAuthService(t)
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

	_, err := service.Login(context.Background(), "testuser", "testpassword", false)

	if err == nil {
		t.Error("Login() should fail when GetUserScopes fails")
	}
}

func TestRefreshToken_PreservesScopes(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
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
	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", false)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// Sleep to ensure different IssuedAt timestamp
	time.Sleep(jwtTimestampBuffer)

	// Refresh token
	refreshResult, err := service.RefreshToken(context.Background(), loginResult.RefreshToken, loginResult.SessionID)
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

// TestRefreshToken_ScopesRefreshedFromDB verifies that role/scope changes
// take effect on the next token refresh without requiring re-login.
func TestRefreshToken_ScopesRefreshedFromDB(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
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
		return map[string]string{
			"profile":  "read",
			"projects": "read",
		}, nil
	}

	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", false)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// Simulate role change in DB
	mockRepo.getUserScopesFunc = func(ctx context.Context, userID int64) (map[string]string, error) {
		return map[string]string{
			"profile":  "delete",
			"projects": "delete",
		}, nil
	}

	time.Sleep(jwtTimestampBuffer)

	refreshResult, err := service.RefreshToken(context.Background(), loginResult.RefreshToken, loginResult.SessionID)
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	claims, err := service.jwtService.ValidateToken(refreshResult.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	// Scopes should reflect the updated DB values
	if claims.Scopes["profile"] != "delete" {
		t.Errorf("Scopes[profile] = %s, want delete (refreshed from DB)", claims.Scopes["profile"])
	}

	if claims.Scopes["projects"] != "delete" {
		t.Errorf("Scopes[projects] = %s, want delete (refreshed from DB)", claims.Scopes["projects"])
	}
}

// =============================================================================
// Logout Tests
// =============================================================================

func TestLogout_Success(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
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
	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", false)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// Verify token exists in Redis
	rtKey := "refresh_token:1:" + loginResult.SessionID
	if !mr.Exists(rtKey) {
		t.Fatal("Refresh token should exist in Redis before logout")
	}

	// Logout
	err = service.Logout(context.Background(), loginResult.AccessToken, loginResult.SessionID)

	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	// Verify token was removed from Redis
	if mr.Exists(rtKey) {
		t.Error("Logout() should remove refresh token from Redis")
	}
}

func TestLogout_InvalidToken(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	err := service.Logout(context.Background(), "invalid-token", "any-session")

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
	service := NewAuthService(nil, mockRepo, &mockVerifyRepo{}, jwtService, testSecret, redisClient, nil, slog.Default(), []string{"admin", "rpg-admin"}, 3, time.Hour).(*authService)

	// Generate token
	token, err := jwtService.GenerateAccessToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Wait for expiry
	time.Sleep(shortExpiry + 100*time.Millisecond)

	// Try to logout with expired token
	err = service.Logout(context.Background(), token, "any-session")

	if err == nil {
		t.Error("Logout() should fail for expired token")
	}
}

func TestLogout_SessionNotFound(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	// Generate valid token but don't create a session in Redis
	token, err := service.jwtService.GenerateAccessToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	err = service.Logout(context.Background(), token, "nonexistent-session")

	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Logout() error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestLogout_RedisFailure(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)

	// Generate valid token
	token, err := service.jwtService.GenerateAccessToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Close Redis to simulate failure
	mr.Close()

	err = service.Logout(context.Background(), token, "any-session")

	if err == nil {
		t.Error("Logout() should fail when Redis is unavailable")
	}
}

// =============================================================================
// RefreshToken Tests
// =============================================================================

func TestRefreshToken_Success(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
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
	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", false)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	oldRefreshToken := loginResult.RefreshToken

	// Sleep to ensure different IssuedAt timestamp (JWT timestamps are in seconds)
	time.Sleep(jwtTimestampBuffer)

	// Refresh token
	result, err := service.RefreshToken(context.Background(), loginResult.RefreshToken, loginResult.SessionID)

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
	stored, err := mr.Get("refresh_token:1:" + loginResult.SessionID)
	if err != nil || stored != result.RefreshToken {
		t.Error("RefreshToken() should update refresh token in Redis")
	}
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	_, err := service.RefreshToken(context.Background(), "invalid-token", "a1b2c3d4-e5f6-7890-abcd-ef1234567890")

	if err == nil {
		t.Error("RefreshToken() should fail for invalid token")
	}
}

func TestRefreshToken_MalformedSessionID(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	_, err := service.RefreshToken(context.Background(), "any-token", "not-a-uuid")
	if err == nil {
		t.Error("RefreshToken() should reject malformed sessionID")
	}
	if err.Error() != "invalid refresh token" {
		t.Errorf("RefreshToken() error = %q, want %q", err.Error(), "invalid refresh token")
	}
}

func TestRefreshToken_ExpiredToken(t *testing.T) {
	// Create service with very short refresh expiry
	redisClient, mr := setupTestRedis(t)
	defer mr.Close()

	shortExpiry := 1 * time.Second
	jwtService, _ := jwt.NewService(testSecret, testAccessExpiry, shortExpiry)
	mockRepo := &mockUserRepository{}
	service := NewAuthService(nil, mockRepo, &mockVerifyRepo{}, jwtService, testSecret, redisClient, nil, slog.Default(), []string{"admin", "rpg-admin"}, 3, time.Hour).(*authService)

	// Generate refresh token
	token, err := jwtService.GenerateRefreshToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}

	// Store in Redis
	testSessionID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	_ = mr.Set("refresh_token:1:"+testSessionID, token)

	// Wait for expiry
	time.Sleep(shortExpiry + 100*time.Millisecond)

	// Try to refresh with expired token
	_, err = service.RefreshToken(context.Background(), token, testSessionID)

	if err == nil {
		t.Error("RefreshToken() should fail for expired token")
	}
}

func TestRefreshToken_NotInRedis(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	// Generate valid token but don't store in Redis
	token, err := service.jwtService.GenerateRefreshToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}

	_, err = service.RefreshToken(context.Background(), token, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")

	if err == nil {
		t.Error("RefreshToken() should fail if token not in Redis")
	}
}

func TestRefreshToken_TokenMismatch(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
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
	testSessionID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	_ = mr.Set("refresh_token:1:"+testSessionID, token1)

	_, err = service.RefreshToken(context.Background(), token2, testSessionID)

	if err == nil {
		t.Error("RefreshToken() should fail if token doesn't match stored token")
	}
}

func TestRefreshToken_RedisFailure(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)

	// Generate valid token and store in Redis
	token, err := service.jwtService.GenerateRefreshToken(1, "testuser", nil)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}
	testSessionID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	_ = mr.Set("refresh_token:1:"+testSessionID, token)

	// Close Redis to simulate failure
	mr.Close()

	_, err = service.RefreshToken(context.Background(), token, testSessionID)

	if err == nil {
		t.Error("RefreshToken() should fail when Redis is unavailable")
	}
	if errors.Is(err, ErrInvalidRefreshToken) {
		t.Error("RefreshToken() should return internal error, not ErrInvalidRefreshToken, on Redis failure")
	}
}

// =============================================================================
// ValidateToken Tests
// =============================================================================

func TestAuthValidateToken_ValidToken(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
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
	service, mr, _, _ := setupTestAuthService(t)
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
	service := NewAuthService(nil, mockRepo, &mockVerifyRepo{}, jwtService, testSecret, redisClient, nil, slog.Default(), []string{"admin", "rpg-admin"}, 3, time.Hour).(*authService)

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
	service := NewAuthService(nil, mockRepo, &mockVerifyRepo{}, jwtService, testSecret, redisClient, nil, slog.Default(), []string{"admin", "rpg-admin"}, 3, time.Hour).(*authService)

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
	service, mr, mockRepo, _ := setupTestAuthService(t)
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
			_, err := service.Login(context.Background(), "testuser", "testpassword", false)
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
	service, mr, mockRepo, _ := setupTestAuthService(t)
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
	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", false)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	const numGoroutines = 5
	errors := make(chan error, numGoroutines)
	results := make(chan *LoginResponse, numGoroutines)

	// Multiple concurrent refresh attempts with same token
	for i := 0; i < numGoroutines; i++ {
		go func() {
			result, err := service.RefreshToken(context.Background(), loginResult.RefreshToken, loginResult.SessionID)
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

// =============================================================================
// Register Tests
// =============================================================================

func TestRegister_Success(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	mockRepo.findByEmailFunc = func(ctx context.Context, email string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	var createdUser *models.User
	mockRepo.createFunc = func(ctx context.Context, user *models.User) error {
		createdUser = user
		user.ID = 3
		return nil
	}

	result, err := service.Register(context.Background(), RegisterRequest{
		Username: "newuser",
		Email:    "new@example.com",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if result.UserID != 3 {
		t.Errorf("Register() UserID = %d, want 3", result.UserID)
	}

	if result.Username != "newuser" {
		t.Errorf("Register() Username = %s, want newuser", result.Username)
	}

	if result.Email != "new@example.com" {
		t.Errorf("Register() Email = %s, want new@example.com", result.Email)
	}

	// Verify password was hashed with bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(createdUser.PasswordHash), []byte("password123")); err != nil {
		t.Error("Register() should store a valid bcrypt hash")
	}

	// Verify no role was assigned
	if createdUser.RoleID != nil {
		t.Error("Register() should not assign a role when role_code is empty")
	}
}

func TestRegister_Success_WithRoleCode(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	mockRepo.findByEmailFunc = func(ctx context.Context, email string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	mockRepo.findRoleByCodeFunc = func(ctx context.Context, code string) (*models.Role, error) {
		return &models.Role{ID: 2, Code: "read-only", Name: "Read Only"}, nil
	}

	var createdUser *models.User
	mockRepo.createFunc = func(ctx context.Context, user *models.User) error {
		createdUser = user
		user.ID = 4
		return nil
	}

	result, err := service.Register(context.Background(), RegisterRequest{
		Username: "viewer",
		Email:    "viewer@example.com",
		Password: "password123",
		RoleCode: "read-only",
	})

	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if result.UserID != 4 {
		t.Errorf("Register() UserID = %d, want 4", result.UserID)
	}

	if createdUser.RoleID == nil {
		t.Fatal("Register() should assign role when role_code is provided")
	}

	if *createdUser.RoleID != 2 {
		t.Errorf("Register() RoleID = %d, want 2", *createdUser.RoleID)
	}
}

func TestRegister_UsernameTaken(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{ID: 1, Username: "existing"}, nil
	}

	_, err := service.Register(context.Background(), RegisterRequest{
		Username: "existing",
		Email:    "new@example.com",
		Password: "password123",
	})

	if !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("Register() error = %v, want %v", err, ErrUsernameTaken)
	}
}

func TestRegister_EmailTaken(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	mockRepo.findByEmailFunc = func(ctx context.Context, email string) (*models.User, error) {
		return &models.User{ID: 1, Email: "taken@example.com"}, nil
	}

	_, err := service.Register(context.Background(), RegisterRequest{
		Username: "newuser",
		Email:    "taken@example.com",
		Password: "password123",
	})

	if !errors.Is(err, ErrEmailTaken) {
		t.Errorf("Register() error = %v, want %v", err, ErrEmailTaken)
	}
}

func TestRegister_RoleNotAllowed(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	mockRepo.findByEmailFunc = func(ctx context.Context, email string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	_, err := service.Register(context.Background(), RegisterRequest{
		Username: "newuser",
		Email:    "new@example.com",
		Password: "password123",
		RoleCode: "admin",
	})

	if !errors.Is(err, ErrRoleNotAllowed) {
		t.Errorf("Register() error = %v, want %v", err, ErrRoleNotAllowed)
	}
}

func TestRegister_RpgAdminNotAllowed(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	_, err := service.Register(context.Background(), RegisterRequest{
		Username: "newuser",
		Email:    "new@example.com",
		Password: "password123",
		RoleCode: "rpg-admin",
	})

	if !errors.Is(err, ErrRoleNotAllowed) {
		t.Errorf("Register() error = %v, want %v", err, ErrRoleNotAllowed)
	}
}

func TestRegister_InvalidRoleCode(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	mockRepo.findByEmailFunc = func(ctx context.Context, email string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	mockRepo.findRoleByCodeFunc = func(ctx context.Context, code string) (*models.Role, error) {
		return nil, gorm.ErrRecordNotFound
	}

	// Use an allowed role code that doesn't exist in the database
	_, err := service.Register(context.Background(), RegisterRequest{
		Username: "newuser",
		Email:    "new@example.com",
		Password: "password123",
		RoleCode: "demo-user",
	})

	if !errors.Is(err, ErrInvalidRoleCode) {
		t.Errorf("Register() error = %v, want %v", err, ErrInvalidRoleCode)
	}
}

func TestRegister_PasswordTooLongBytes(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	// 73 ASCII bytes exceeds bcrypt's 72-byte limit
	_, err := service.Register(context.Background(), RegisterRequest{
		Username: "newuser",
		Email:    "new@example.com",
		Password: strings.Repeat("a", 73),
	})

	if !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("Register() error = %v, want ErrPasswordTooLong", err)
	}
}

func TestRegister_PasswordExactly72Bytes(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	mockRepo.findByEmailFunc = func(ctx context.Context, email string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	mockRepo.createFunc = func(ctx context.Context, user *models.User) error {
		user.ID = 1
		return nil
	}

	// Exactly 72 bytes should succeed
	result, err := service.Register(context.Background(), RegisterRequest{
		Username: "newuser",
		Email:    "new@example.com",
		Password: strings.Repeat("a", 72),
	})

	if err != nil {
		t.Errorf("Register() unexpected error: %v", err)
	}
	if result == nil {
		t.Error("Register() result should not be nil")
	}
}

func TestRegister_CreateFails(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	mockRepo.findByEmailFunc = func(ctx context.Context, email string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	mockRepo.createFunc = func(ctx context.Context, user *models.User) error {
		return errors.New("database error")
	}

	_, err := service.Register(context.Background(), RegisterRequest{
		Username: "newuser",
		Email:    "new@example.com",
		Password: "password123",
	})

	if err == nil {
		t.Error("Register() should fail when Create fails")
	}
}

func TestRegister_CreatesVerificationToken(t *testing.T) {
	service, mr, mockRepo, mockVerify := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}
	mockRepo.findByEmailFunc = func(ctx context.Context, email string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}
	mockRepo.createFunc = func(ctx context.Context, user *models.User) error {
		user.ID = 5
		return nil
	}

	var createdToken *models.VerificationToken
	mockVerify.createFunc = func(ctx context.Context, token *models.VerificationToken) error {
		createdToken = token
		return nil
	}

	_, err := service.Register(context.Background(), RegisterRequest{
		Username: "newuser",
		Email:    "new@example.com",
		Password: "password123",
	})

	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if createdToken == nil {
		t.Fatal("Register() should create a verification token")
	}

	if createdToken.UserID != 5 {
		t.Errorf("VerificationToken.UserID = %d, want 5", createdToken.UserID)
	}

	if createdToken.Email != "new@example.com" {
		t.Errorf("VerificationToken.Email = %s, want new@example.com", createdToken.Email)
	}

	if len(createdToken.Token) != 64 {
		t.Errorf("VerificationToken.Token length = %d, want 64 hex chars", len(createdToken.Token))
	}
}

// =============================================================================
// VerifyEmail Tests
// =============================================================================

func TestVerifyEmail_Success(t *testing.T) {
	service, mr, mockRepo, mockVerify := setupTestAuthService(t)
	defer mr.Close()

	rawToken := "abc123"
	hashedToken := models.HashToken(rawToken)

	mockVerify.findByTokenFunc = func(ctx context.Context, token string) (*models.VerificationToken, error) {
		if token != hashedToken {
			t.Errorf("FindByToken called with unhashed token %q, want hash", token)
		}
		return &models.VerificationToken{
			ID:     1,
			UserID: 1,
			Email:  "test@example.com",
			Token:  hashedToken,
		}, nil
	}

	var updatedUser *models.User
	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:            1,
			Username:      "testuser",
			Email:         "test@example.com",
			EmailVerified: false,
		}, nil
	}
	mockRepo.updateFunc = func(ctx context.Context, user *models.User) error {
		updatedUser = user
		return nil
	}
	markUsedCalled := false
	mockVerify.markUsedFunc = func(ctx context.Context, id int64) error {
		markUsedCalled = true
		return nil
	}

	err := service.VerifyEmail(context.Background(), rawToken)

	if err != nil {
		t.Fatalf("VerifyEmail() error = %v", err)
	}

	if updatedUser == nil || !updatedUser.EmailVerified {
		t.Error("VerifyEmail() should set EmailVerified to true")
	}
	if !markUsedCalled {
		t.Error("VerifyEmail() should call MarkUsed, not DeleteByUserID")
	}
}

func TestVerifyEmail_TokenNotFound(t *testing.T) {
	service, mr, _, mockVerify := setupTestAuthService(t)
	defer mr.Close()

	mockVerify.findByTokenFunc = func(ctx context.Context, token string) (*models.VerificationToken, error) {
		return nil, gorm.ErrRecordNotFound
	}

	err := service.VerifyEmail(context.Background(), "nonexistent")

	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("VerifyEmail() error = %v, want %v", err, ErrTokenNotFound)
	}
}

func TestVerifyEmail_EmailMismatch(t *testing.T) {
	service, mr, mockRepo, mockVerify := setupTestAuthService(t)
	defer mr.Close()

	rawToken := "abc123"
	hashedToken := models.HashToken(rawToken)

	mockVerify.findByTokenFunc = func(ctx context.Context, token string) (*models.VerificationToken, error) {
		return &models.VerificationToken{
			UserID: 1,
			Email:  "old@example.com",
			Token:  hashedToken,
		}, nil
	}

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:    1,
			Email: "new@example.com",
		}, nil
	}

	err := service.VerifyEmail(context.Background(), rawToken)

	if !errors.Is(err, ErrTokenEmailMismatch) {
		t.Errorf("VerifyEmail() error = %v, want %v", err, ErrTokenEmailMismatch)
	}
}

// =============================================================================
// UpdateProfile Tests
// =============================================================================

func TestUpdateProfile_ChangeDisplayName(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:       1,
			Username: "testuser",
			Email:    "test@example.com",
		}, nil
	}
	mockRepo.updateFunc = func(ctx context.Context, user *models.User) error {
		return nil
	}

	name := "John Doe"
	result, err := service.UpdateProfile(context.Background(), 1, ProfileUpdateRequest{
		DisplayName: &name,
	})

	if err != nil {
		t.Fatalf("UpdateProfile() error = %v", err)
	}

	if result.DisplayName == nil || *result.DisplayName != "John Doe" {
		t.Error("UpdateProfile() should update display name")
	}
}

func TestUpdateProfile_ChangeEmail_ResetsVerification(t *testing.T) {
	service, mr, mockRepo, mockVerify := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:            1,
			Username:      "testuser",
			Email:         "old@example.com",
			EmailVerified: true,
		}, nil
	}
	mockRepo.findByEmailFunc = func(ctx context.Context, email string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	var updatedUser *models.User
	mockRepo.updateFunc = func(ctx context.Context, user *models.User) error {
		updatedUser = user
		return nil
	}

	var createdToken *models.VerificationToken
	mockVerify.createFunc = func(ctx context.Context, token *models.VerificationToken) error {
		createdToken = token
		return nil
	}

	newEmail := "new@example.com"
	result, err := service.UpdateProfile(context.Background(), 1, ProfileUpdateRequest{
		Email: &newEmail,
	})

	if err != nil {
		t.Fatalf("UpdateProfile() error = %v", err)
	}

	if result.Email != "new@example.com" {
		t.Errorf("UpdateProfile() Email = %s, want new@example.com", result.Email)
	}

	if updatedUser.EmailVerified {
		t.Error("UpdateProfile() should reset EmailVerified when email changes")
	}

	if createdToken == nil {
		t.Error("UpdateProfile() should create new verification token when email changes")
	}
}

func TestUpdateProfile_EmailTaken(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:    1,
			Email: "old@example.com",
		}, nil
	}
	mockRepo.findByEmailFunc = func(ctx context.Context, email string) (*models.User, error) {
		return &models.User{ID: 2, Email: "taken@example.com"}, nil
	}

	takenEmail := "taken@example.com"
	_, err := service.UpdateProfile(context.Background(), 1, ProfileUpdateRequest{
		Email: &takenEmail,
	})

	if !errors.Is(err, ErrEmailTaken) {
		t.Errorf("UpdateProfile() error = %v, want %v", err, ErrEmailTaken)
	}
}

// =============================================================================
// ChangePassword Tests
// =============================================================================

func TestChangePassword_Success(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "oldpassword")

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: passwordHash,
		}, nil
	}

	var updatedUser *models.User
	mockRepo.updateFunc = func(ctx context.Context, user *models.User) error {
		updatedUser = user
		return nil
	}

	err := service.ChangePassword(context.Background(), 1, ChangePasswordRequest{
		CurrentPassword: "oldpassword",
		NewPassword:     "newpassword123",
	})

	if err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}

	if updatedUser == nil {
		t.Fatal("ChangePassword() should update user")
	}

	// Verify new password was hashed
	if err := bcrypt.CompareHashAndPassword([]byte(updatedUser.PasswordHash), []byte("newpassword123")); err != nil {
		t.Error("ChangePassword() should store valid bcrypt hash of new password")
	}
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "correctpassword")

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:           1,
			PasswordHash: passwordHash,
		}, nil
	}

	err := service.ChangePassword(context.Background(), 1, ChangePasswordRequest{
		CurrentPassword: "wrongpassword",
		NewPassword:     "newpassword123",
	})

	if !errors.Is(err, ErrPasswordMismatch) {
		t.Errorf("ChangePassword() error = %v, want %v", err, ErrPasswordMismatch)
	}
}

func TestChangePassword_TooShort(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	err := service.ChangePassword(context.Background(), 1, ChangePasswordRequest{
		CurrentPassword: "old",
		NewPassword:     "short",
	})

	if err == nil {
		t.Error("ChangePassword() should reject passwords shorter than 8 characters")
	}
}

func TestChangePassword_TooLong(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	err := service.ChangePassword(context.Background(), 1, ChangePasswordRequest{
		CurrentPassword: "old",
		NewPassword:     strings.Repeat("a", 73),
	})

	if !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("ChangePassword() error = %v, want %v", err, ErrPasswordTooLong)
	}
}

// =============================================================================
// Login Email Claims Tests
// =============================================================================

func TestLogin_TokenContainsEmailClaims(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{
			ID:            1,
			Username:      "testuser",
			Email:         "test@example.com",
			EmailVerified: true,
			PasswordHash:  passwordHash,
		}, nil
	}

	result, err := service.Login(context.Background(), "testuser", "testpassword", false)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	claims, err := service.jwtService.ValidateToken(result.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if claims.Email != "test@example.com" {
		t.Errorf("Access token Email = %s, want test@example.com", claims.Email)
	}

	if !claims.EmailVerified {
		t.Error("Access token EmailVerified should be true")
	}
}

// =============================================================================
// SendVerification Tests
// =============================================================================

func TestSendVerification_AlreadyVerified(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:            1,
			Email:         "test@example.com",
			EmailVerified: true,
		}, nil
	}

	err := service.SendVerification(context.Background(), 1, "test@example.com", "https://example.com")

	if !errors.Is(err, ErrAlreadyVerified) {
		t.Errorf("SendVerification() error = %v, want %v", err, ErrAlreadyVerified)
	}
}

func TestSendVerification_EmailNotConfigured(t *testing.T) {
	// Service is created without email client (nil) by default in setupTestAuthService
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:            1,
			Email:         "test@example.com",
			EmailVerified: false,
		}, nil
	}

	err := service.SendVerification(context.Background(), 1, "test@example.com", "https://example.com")

	if !errors.Is(err, ErrEmailNotConfigured) {
		t.Errorf("SendVerification() error = %v, want %v", err, ErrEmailNotConfigured)
	}
}

func TestSendVerification_RateLimit(t *testing.T) {
	// Rate limiting check happens after the nil email client check,
	// so this requires a mock HTTP server for the email client.
	// Covered by integration tests.
	t.Skip("Rate limiting requires email client; covered by integration tests")
}

// =============================================================================
// ForgotPassword Tests
// =============================================================================

func TestForgotPassword_UserNotFound(t *testing.T) {
	// ForgotPassword checks emailClient != nil before reaching FindByEmail.
	// Testing enumeration safety requires email client setup.
	t.Skip("Requires email client; covered by integration tests")
}

func TestForgotPassword_EmailNotVerified(t *testing.T) {
	// ForgotPassword checks emailClient != nil before reaching FindByEmail.
	t.Skip("Requires email client; covered by integration tests")
}

func TestForgotPassword_EmailNotConfigured(t *testing.T) {
	svc, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	// Default setup has nil email client
	err := svc.ForgotPassword(context.Background(), "test@example.com", "https://example.com")

	if !errors.Is(err, ErrEmailNotConfigured) {
		t.Errorf("ForgotPassword() error = %v, want %v", err, ErrEmailNotConfigured)
	}
}

func TestForgotPassword_RateLimit(t *testing.T) {
	// Rate limit check happens after email client nil check,
	// so this requires email client setup.
	t.Skip("Requires email client; covered by integration tests")
}

func TestForgotPassword_DBError_Propagates(t *testing.T) {
	// DB error propagation requires email client setup (nil client check
	// happens before FindByEmail). Covered by integration tests.
	t.Skip("Requires email client; covered by integration tests")
}

// =============================================================================
// ResetPassword Tests
// =============================================================================

func TestResetPassword_Success(t *testing.T) {
	svc, mr, mockRepo, mockVerify := setupTestAuthService(t)
	defer mr.Close()

	rawToken := "abc123def456"
	tokenHash := models.HashToken(rawToken)

	mockVerify.findByTokenAndTypeFunc = func(ctx context.Context, hash, tokenType string) (*models.VerificationToken, error) {
		if hash != tokenHash || tokenType != models.TokenTypePasswordReset {
			return nil, gorm.ErrRecordNotFound
		}
		return &models.VerificationToken{
			ID:     1,
			UserID: 1,
			Email:  "test@example.com",
			Token:  tokenHash,
			Type:   models.TokenTypePasswordReset,
		}, nil
	}

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			Email:        "test@example.com",
			PasswordHash: hashPassword(t, "oldpassword"),
		}, nil
	}

	var updatedUser *models.User
	mockRepo.updateFunc = func(ctx context.Context, user *models.User) error {
		updatedUser = user
		return nil
	}

	markUsedCalled := false
	mockVerify.markUsedFunc = func(ctx context.Context, id int64) error {
		markUsedCalled = true
		if id != 1 {
			t.Errorf("MarkUsed called with id %d, want 1", id)
		}
		return nil
	}

	err := svc.ResetPassword(context.Background(), rawToken, "newpassword123")

	if err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}
	if updatedUser == nil {
		t.Fatal("ResetPassword() should update user")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(updatedUser.PasswordHash), []byte("newpassword123")); err != nil {
		t.Error("ResetPassword() should hash the new password correctly")
	}
	if !markUsedCalled {
		t.Error("ResetPassword() should call MarkUsed")
	}
}

func TestResetPassword_TokenNotFound(t *testing.T) {
	svc, mr, _, mockVerify := setupTestAuthService(t)
	defer mr.Close()

	mockVerify.findByTokenAndTypeFunc = func(ctx context.Context, hash, tokenType string) (*models.VerificationToken, error) {
		return nil, gorm.ErrRecordNotFound
	}

	err := svc.ResetPassword(context.Background(), "nonexistent", "newpassword123")

	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("ResetPassword() error = %v, want %v", err, ErrTokenNotFound)
	}
}

func TestResetPassword_TokenExpired(t *testing.T) {
	svc, mr, _, mockVerify := setupTestAuthService(t)
	defer mr.Close()

	rawToken := "expired_token"
	tokenHash := models.HashToken(rawToken)
	expiredAt := time.Now().Add(-1 * time.Hour)

	mockVerify.findByTokenAndTypeFunc = func(ctx context.Context, hash, tokenType string) (*models.VerificationToken, error) {
		return &models.VerificationToken{
			ID:        1,
			UserID:    1,
			Token:     tokenHash,
			Type:      models.TokenTypePasswordReset,
			ExpiresAt: &expiredAt,
		}, nil
	}

	markUsedCalled := false
	mockVerify.markUsedFunc = func(ctx context.Context, id int64) error {
		markUsedCalled = true
		return nil
	}

	err := svc.ResetPassword(context.Background(), rawToken, "newpassword123")

	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("ResetPassword() error = %v, want %v", err, ErrTokenExpired)
	}
	if !markUsedCalled {
		t.Error("ResetPassword() should mark expired token as used")
	}
}

func TestResetPassword_PasswordTooShort(t *testing.T) {
	svc, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	err := svc.ResetPassword(context.Background(), "token", "short")

	if err == nil || err.Error() != "password must be at least 8 characters" {
		t.Errorf("ResetPassword() error = %v, want password too short error", err)
	}
}

func TestResetPassword_PasswordTooLong(t *testing.T) {
	svc, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	err := svc.ResetPassword(context.Background(), "token", strings.Repeat("a", 73))

	if !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("ResetPassword() error = %v, want %v", err, ErrPasswordTooLong)
	}
}

func TestResetPassword_DBError_Propagates(t *testing.T) {
	svc, mr, _, mockVerify := setupTestAuthService(t)
	defer mr.Close()

	mockVerify.findByTokenAndTypeFunc = func(ctx context.Context, hash, tokenType string) (*models.VerificationToken, error) {
		return nil, errors.New("database connection refused")
	}

	err := svc.ResetPassword(context.Background(), "token", "newpassword123")

	// Should propagate DB errors, not wrap as ErrTokenNotFound
	if errors.Is(err, ErrTokenNotFound) {
		t.Error("ResetPassword() should propagate DB errors, not mask as ErrTokenNotFound")
	}
	if err == nil {
		t.Error("ResetPassword() should return error on DB failure")
	}
}

func TestResetPassword_InvalidatesAllSessions(t *testing.T) {
	svc, mr, mockRepo, mockVerify := setupTestAuthService(t)
	defer mr.Close()

	rawToken := "valid_token"
	tokenHash := models.HashToken(rawToken)

	mockVerify.findByTokenAndTypeFunc = func(ctx context.Context, hash, tokenType string) (*models.VerificationToken, error) {
		return &models.VerificationToken{
			ID:     1,
			UserID: 1,
			Token:  tokenHash,
			Type:   models.TokenTypePasswordReset,
		}, nil
	}

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: hashPassword(t, "oldpassword"),
		}, nil
	}
	mockRepo.updateFunc = func(ctx context.Context, user *models.User) error {
		return nil
	}
	mockVerify.markUsedFunc = func(ctx context.Context, id int64) error {
		return nil
	}

	// Store a session in Redis to verify it gets invalidated
	_ = mr.Set("refresh_token:1:session1", "token_value")
	_ = mr.Set("remember_me:1:session1", "1")

	err := svc.ResetPassword(context.Background(), rawToken, "newpassword123")

	if err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}

	// Verify session was invalidated
	if mr.Exists("refresh_token:1:session1") {
		t.Error("ResetPassword() should invalidate all sessions")
	}
}
