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
	findByUsernameFunc        func(ctx context.Context, username string) (*models.User, error)
	findByEmailFunc           func(ctx context.Context, email string) (*models.User, error)
	findByUsernameOrEmailFunc func(ctx context.Context, identifier string) (*models.User, error)
	findByIDFunc              func(ctx context.Context, id int64) (*models.User, error)
	createFunc                func(ctx context.Context, user *models.User) error
	updateFunc                func(ctx context.Context, user *models.User) error
	getUserScopesFunc         func(ctx context.Context, userID int64) (map[string]string, error)
	findRoleByCodeFunc        func(ctx context.Context, code string) (*models.Role, error)
}

// =============================================================================
// Mock OAuthAccountRepository
// =============================================================================

type mockOAuthRepo struct {
	findByProviderAndIDFunc func(ctx context.Context, provider, providerUserID string) (*models.OAuthAccount, error)
	findByUserIDFunc        func(ctx context.Context, userID int64) ([]models.OAuthAccount, error)
	createFunc              func(ctx context.Context, account *models.OAuthAccount) error
}

func (m *mockOAuthRepo) FindByProviderAndID(ctx context.Context, provider, providerUserID string) (*models.OAuthAccount, error) {
	if m.findByProviderAndIDFunc != nil {
		return m.findByProviderAndIDFunc(ctx, provider, providerUserID)
	}
	return nil, gorm.ErrRecordNotFound
}

func (m *mockOAuthRepo) FindByUserID(ctx context.Context, userID int64) ([]models.OAuthAccount, error) {
	if m.findByUserIDFunc != nil {
		return m.findByUserIDFunc(ctx, userID)
	}
	return nil, nil
}

func (m *mockOAuthRepo) Create(ctx context.Context, account *models.OAuthAccount) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, account)
	}
	return nil
}

// =============================================================================
// Mock UserRoleRepository
// =============================================================================

type mockUserRoleRepo struct {
	assignRoleFunc func(ctx context.Context, userID int64, roleCode string) error
}

func (m *mockUserRoleRepo) AssignRole(ctx context.Context, userID int64, roleCode string) error {
	if m.assignRoleFunc != nil {
		return m.assignRoleFunc(ctx, userID, roleCode)
	}
	return nil
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

func (m *mockUserRepository) FindByUsernameOrEmail(ctx context.Context, identifier string) (*models.User, error) {
	if m.findByUsernameOrEmailFunc != nil {
		return m.findByUsernameOrEmailFunc(ctx, identifier)
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

	mockUserRole := &mockUserRoleRepo{}

	svc := NewAuthService(
		nil, mockRepo, mockVerify, nil, mockUserRole, jwtService, testSecret,
		redisClient, nil, slog.Default(), []string{"admin", "rpg-admin"}, 3, time.Hour,
		nil,
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

	svc := NewAuthService(nil, mockRepo, mockVerify, nil, nil, jwtService, testSecret, redisClient, nil, slog.Default(), []string{"admin"}, 3, time.Hour, nil)

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

	var _ = NewAuthService(nil, mockRepo, mockVerify, nil, nil, jwtService, testSecret, redisClient, nil, slog.Default(), []string{"admin"}, 3, time.Hour, nil)
}

// =============================================================================
// Login Tests
// =============================================================================

func TestLogin_Success(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			Email:        "test@example.com",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		if identifier == "" {
			return nil, gorm.ErrRecordNotFound
		}
		return &models.User{
			ID:           1,
			Username:     identifier,
			PasswordHash: ptrString(hashPassword(t, "password")),
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: ptrString(hashPassword(t, "password")),
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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
	service := NewAuthService(nil, mockRepo, &mockVerifyRepo{}, nil, nil, jwtService, testSecret, redisClient, nil, slog.Default(), []string{"admin", "rpg-admin"}, 3, time.Hour, nil).(*authService)

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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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
	service := NewAuthService(nil, mockRepo, &mockVerifyRepo{}, nil, nil, jwtService, testSecret, redisClient, nil, slog.Default(), []string{"admin", "rpg-admin"}, 3, time.Hour, nil).(*authService)

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
// Grace Period Tests
// =============================================================================

func TestRefreshToken_GraceTokenAccepted(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")
	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{ID: 1, Username: "testuser", PasswordHash: &passwordHash}, nil
	}

	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", false)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	oldRefreshToken := loginResult.RefreshToken
	time.Sleep(jwtTimestampBuffer)

	// First refresh rotates the token, old token goes to grace key
	result1, err := service.RefreshToken(context.Background(), oldRefreshToken, loginResult.SessionID)
	if err != nil {
		t.Fatalf("First RefreshToken() error = %v", err)
	}

	// Verify grace key contains old token
	graceKey := "refresh_token_grace:1:" + loginResult.SessionID
	graceVal, err := mr.Get(graceKey)
	if err != nil {
		t.Fatalf("Grace key not found in Redis: %v", err)
	}
	if graceVal != oldRefreshToken {
		t.Error("Grace key should contain the old refresh token")
	}

	time.Sleep(jwtTimestampBuffer)

	// Second refresh with old token should succeed via grace key
	result2, err := service.RefreshToken(context.Background(), oldRefreshToken, loginResult.SessionID)
	if err != nil {
		t.Fatalf("Grace refresh should succeed, got error: %v", err)
	}
	if result2.RefreshToken == result1.RefreshToken {
		t.Error("Grace refresh should issue a new token")
	}
}

func TestRefreshToken_GraceTokenExpires(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")
	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{ID: 1, Username: "testuser", PasswordHash: &passwordHash}, nil
	}

	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", false)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	oldRefreshToken := loginResult.RefreshToken
	time.Sleep(jwtTimestampBuffer)

	// Rotate token
	_, err = service.RefreshToken(context.Background(), oldRefreshToken, loginResult.SessionID)
	if err != nil {
		t.Fatalf("First RefreshToken() error = %v", err)
	}

	// Fast-forward past grace period
	mr.FastForward(refreshGracePeriod + time.Second)

	// Old token should now be rejected
	_, err = service.RefreshToken(context.Background(), oldRefreshToken, loginResult.SessionID)
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Errorf("Expected ErrInvalidRefreshToken after grace expiry, got: %v", err)
	}
}

func TestRefreshToken_DoubleRotationGrace(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")
	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{ID: 1, Username: "testuser", PasswordHash: &passwordHash}, nil
	}

	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", false)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	originalToken := loginResult.RefreshToken
	time.Sleep(jwtTimestampBuffer)

	// Tab A refreshes: original → tokenA (grace has original)
	resultA, err := service.RefreshToken(context.Background(), originalToken, loginResult.SessionID)
	if err != nil {
		t.Fatalf("Tab A refresh error = %v", err)
	}

	time.Sleep(jwtTimestampBuffer)

	// Tab B refreshes with original via grace: original → tokenB (grace has tokenA)
	resultB, err := service.RefreshToken(context.Background(), originalToken, loginResult.SessionID)
	if err != nil {
		t.Fatalf("Tab B refresh error = %v", err)
	}

	time.Sleep(jwtTimestampBuffer)

	// Tab C tries with original — should fail (grace has tokenA, primary has tokenB)
	_, err = service.RefreshToken(context.Background(), originalToken, loginResult.SessionID)
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Errorf("Tab C should fail with ErrInvalidRefreshToken, got: %v", err)
	}

	// But Tab A's token should still work via grace
	_, err = service.RefreshToken(context.Background(), resultA.RefreshToken, loginResult.SessionID)
	if err != nil {
		t.Errorf("Tab A's token should still work via grace, got: %v", err)
	}

	_ = resultB // used by the rotation above
}

func TestLogout_CleansGraceKey(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")
	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{ID: 1, Username: "testuser", PasswordHash: &passwordHash}, nil
	}

	loginResult, err := service.Login(context.Background(), "testuser", "testpassword", false)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	time.Sleep(jwtTimestampBuffer)

	// Refresh to create a grace key
	_, err = service.RefreshToken(context.Background(), loginResult.RefreshToken, loginResult.SessionID)
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	graceKey := "refresh_token_grace:1:" + loginResult.SessionID
	if !mr.Exists(graceKey) {
		t.Fatal("Grace key should exist after refresh")
	}

	// Logout with access token
	err = service.Logout(context.Background(), loginResult.AccessToken, loginResult.SessionID)
	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	if mr.Exists(graceKey) {
		t.Error("Logout should delete the grace key")
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
	service := NewAuthService(nil, mockRepo, &mockVerifyRepo{}, nil, nil, jwtService, testSecret, redisClient, nil, slog.Default(), []string{"admin", "rpg-admin"}, 3, time.Hour, nil).(*authService)

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
	service := NewAuthService(nil, mockRepo, &mockVerifyRepo{}, nil, nil, jwtService, testSecret, redisClient, nil, slog.Default(), []string{"admin", "rpg-admin"}, 3, time.Hour, nil).(*authService)

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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     identifier,
			PasswordHash: &passwordHash,
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

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "testuser",
			PasswordHash: &passwordHash,
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

	// Primary refresh + at least one grace refresh should succeed
	if successCount < 2 {
		t.Errorf("Expected at least 2 concurrent RefreshToken() to succeed (primary + grace), got %d/%d", successCount, numGoroutines)
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
	if err := bcrypt.CompareHashAndPassword([]byte(*createdUser.PasswordHash), []byte("password123")); err != nil {
		t.Error("Register() should store a valid bcrypt hash")
	}

}

func TestRegister_Success_WithRoleCode(t *testing.T) {
	svc, mr, mockRepo, _ := setupTestAuthService(t)
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

	mockRepo.createFunc = func(ctx context.Context, user *models.User) error {
		user.ID = 4
		return nil
	}

	var assignedRole string
	svc.userRoleRepo = &mockUserRoleRepo{
		assignRoleFunc: func(ctx context.Context, userID int64, roleCode string) error {
			assignedRole = roleCode
			return nil
		},
	}

	result, err := svc.Register(context.Background(), RegisterRequest{
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

	if assignedRole != "read-only" {
		t.Errorf("Register() assigned role = %s, want read-only", assignedRole)
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

	mockVerify.findByTokenAndTypeFunc = func(ctx context.Context, token, tokenType string) (*models.VerificationToken, error) {
		if token != hashedToken {
			t.Errorf("FindByTokenAndType called with unhashed token %q, want hash", token)
		}
		if tokenType != models.TokenTypeEmailVerification {
			t.Errorf("FindByTokenAndType called with type %q, want %q", tokenType, models.TokenTypeEmailVerification)
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

	mockVerify.findByTokenAndTypeFunc = func(ctx context.Context, token, tokenType string) (*models.VerificationToken, error) {
		return nil, gorm.ErrRecordNotFound
	}

	err := service.VerifyEmail(context.Background(), "nonexistent")

	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("VerifyEmail() error = %v, want %v", err, ErrTokenNotFound)
	}
}

func TestVerifyEmail_RejectsPasswordResetToken(t *testing.T) {
	service, mr, _, mockVerify := setupTestAuthService(t)
	defer mr.Close()

	rawToken := "reset_token_123"

	// Simulate: token exists as password_reset but not as email_verification
	mockVerify.findByTokenAndTypeFunc = func(ctx context.Context, token, tokenType string) (*models.VerificationToken, error) {
		if tokenType == models.TokenTypeEmailVerification {
			return nil, gorm.ErrRecordNotFound
		}
		return &models.VerificationToken{
			ID:     1,
			UserID: 1,
			Email:  "test@example.com",
			Token:  models.HashToken(rawToken),
			Type:   models.TokenTypePasswordReset,
		}, nil
	}

	err := service.VerifyEmail(context.Background(), rawToken)

	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("VerifyEmail() should reject password reset tokens, got %v", err)
	}
}

func TestVerifyEmail_EmailMismatch(t *testing.T) {
	service, mr, mockRepo, mockVerify := setupTestAuthService(t)
	defer mr.Close()

	rawToken := "abc123"
	hashedToken := models.HashToken(rawToken)

	mockVerify.findByTokenAndTypeFunc = func(ctx context.Context, token, tokenType string) (*models.VerificationToken, error) {
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

	existingHash := hashPassword(t, "password")
	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:            1,
			Username:      "testuser",
			Email:         "old@example.com",
			EmailVerified: true,
			PasswordHash:  &existingHash,
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

	takenHash := hashPassword(t, "password")
	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:           1,
			Email:        "old@example.com",
			PasswordHash: &takenHash,
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
			PasswordHash: &passwordHash,
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
	if err := bcrypt.CompareHashAndPassword([]byte(*updatedUser.PasswordHash), []byte("newpassword123")); err != nil {
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
			PasswordHash: &passwordHash,
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

	user := &models.User{
		ID:            1,
		Username:      "testuser",
		Email:         "test@example.com",
		EmailVerified: true,
		PasswordHash:  &passwordHash,
	}

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return user, nil
	}
	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return user, nil
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

type mockEmailSender struct {
	sendVerificationFunc  func(ctx context.Context, recipientEmail, username, verifyURL string) error
	sendPasswordResetFunc func(ctx context.Context, recipientEmail, username, resetURL string) error
}

func (m *mockEmailSender) SendVerificationEmail(ctx context.Context, recipientEmail, username, verifyURL string) error {
	if m.sendVerificationFunc != nil {
		return m.sendVerificationFunc(ctx, recipientEmail, username, verifyURL)
	}
	return nil
}

func (m *mockEmailSender) SendPasswordResetEmail(ctx context.Context, recipientEmail, username, resetURL string) error {
	if m.sendPasswordResetFunc != nil {
		return m.sendPasswordResetFunc(ctx, recipientEmail, username, resetURL)
	}
	return nil
}

func setupTestAuthServiceWithEmail(t *testing.T) (*authService, *miniredis.Miniredis, *mockUserRepository, *mockVerifyRepo, *mockEmailSender) {
	t.Helper()

	redisClient, mr := setupTestRedis(t)
	jwtService, err := jwt.NewService(testSecret, testAccessExpiry, testRefreshExpiry)
	if err != nil {
		t.Fatalf("Failed to create JWT service: %v", err)
	}
	mockRepo := &mockUserRepository{}
	mockVerify := &mockVerifyRepo{}
	mockEmail := &mockEmailSender{}

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
		nil, mockRepo, mockVerify, nil, nil, jwtService, testSecret,
		redisClient, mockEmail, slog.Default(), []string{"admin", "rpg-admin"}, 3, time.Hour,
		nil,
	).(*authService)
	return svc, mr, mockRepo, mockVerify, mockEmail
}

func TestForgotPassword_UserNotFound(t *testing.T) {
	svc, mr, mockRepo, _, _ := setupTestAuthServiceWithEmail(t)
	defer mr.Close()

	mockRepo.findByEmailFunc = func(ctx context.Context, emailAddr string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}

	err := svc.ForgotPassword(context.Background(), "nonexistent@example.com", "https://example.com")

	if err != nil {
		t.Errorf("ForgotPassword() should return nil for unknown email, got %v", err)
	}
}

func TestForgotPassword_EmailNotVerified(t *testing.T) {
	svc, mr, mockRepo, _, _ := setupTestAuthServiceWithEmail(t)
	defer mr.Close()

	mockRepo.findByEmailFunc = func(ctx context.Context, emailAddr string) (*models.User, error) {
		return &models.User{
			ID:            1,
			Email:         emailAddr,
			EmailVerified: false,
		}, nil
	}

	err := svc.ForgotPassword(context.Background(), "unverified@example.com", "https://example.com")

	if err != nil {
		t.Errorf("ForgotPassword() should return nil for unverified email, got %v", err)
	}
}

func TestForgotPassword_EmailNotConfigured(t *testing.T) {
	svc, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	err := svc.ForgotPassword(context.Background(), "test@example.com", "https://example.com")

	if !errors.Is(err, ErrEmailNotConfigured) {
		t.Errorf("ForgotPassword() error = %v, want %v", err, ErrEmailNotConfigured)
	}
}

func TestForgotPassword_RateLimit(t *testing.T) {
	svc, mr, _, _, _ := setupTestAuthServiceWithEmail(t)
	defer mr.Close()

	// Exhaust rate limit (max 3)
	for i := 0; i < 3; i++ {
		_ = svc.ForgotPassword(context.Background(), "test@example.com", "https://example.com")
	}

	err := svc.ForgotPassword(context.Background(), "test@example.com", "https://example.com")

	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("ForgotPassword() error = %v, want %v", err, ErrRateLimited)
	}
}

func TestForgotPassword_DBError_Propagates(t *testing.T) {
	svc, mr, mockRepo, _, _ := setupTestAuthServiceWithEmail(t)
	defer mr.Close()

	mockRepo.findByEmailFunc = func(ctx context.Context, emailAddr string) (*models.User, error) {
		return nil, errors.New("database connection refused")
	}

	err := svc.ForgotPassword(context.Background(), "test@example.com", "https://example.com")

	if err == nil {
		t.Error("ForgotPassword() should propagate DB errors")
	}
	if errors.Is(err, ErrEmailNotConfigured) {
		t.Error("ForgotPassword() should not return ErrEmailNotConfigured for DB errors")
	}
}

func TestForgotPassword_Success(t *testing.T) {
	svc, mr, mockRepo, mockVerify, _ := setupTestAuthServiceWithEmail(t)
	defer mr.Close()

	mockRepo.findByEmailFunc = func(ctx context.Context, emailAddr string) (*models.User, error) {
		return &models.User{
			ID:            1,
			Username:      "testuser",
			Email:         emailAddr,
			EmailVerified: true,
		}, nil
	}

	deleteCalled := false
	mockVerify.deleteByUserAndTypeFunc = func(ctx context.Context, userID int64, tokenType string) error {
		if userID != 1 || tokenType != models.TokenTypePasswordReset {
			t.Errorf("DeleteByUserIDAndType() called with userID=%d, type=%s", userID, tokenType)
		}
		deleteCalled = true
		return nil
	}

	var createdToken *models.VerificationToken
	mockVerify.createFunc = func(ctx context.Context, token *models.VerificationToken) error {
		createdToken = token
		return nil
	}

	err := svc.ForgotPassword(context.Background(), "test@example.com", "https://example.com")

	if err != nil {
		t.Fatalf("ForgotPassword() unexpected error: %v", err)
	}
	if !deleteCalled {
		t.Error("ForgotPassword() should delete existing reset tokens")
	}
	if createdToken == nil {
		t.Fatal("ForgotPassword() should create a new token")
	}
	if createdToken.Type != models.TokenTypePasswordReset {
		t.Errorf("Created token type = %s, want %s", createdToken.Type, models.TokenTypePasswordReset)
	}
	if createdToken.UserID != 1 {
		t.Errorf("Created token userID = %d, want 1", createdToken.UserID)
	}
	if createdToken.ExpiresAt == nil {
		t.Error("Created token should have ExpiresAt set")
	}
	if len(createdToken.Token) != 64 {
		t.Errorf("Created token should be SHA-256 hash (64 hex chars), got %d chars", len(createdToken.Token))
	}
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
			PasswordHash: ptrString(hashPassword(t, "oldpassword")),
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
	if err := bcrypt.CompareHashAndPassword([]byte(*updatedUser.PasswordHash), []byte("newpassword123")); err != nil {
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
			PasswordHash: ptrString(hashPassword(t, "oldpassword")),
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

// =============================================================================
// OAuth / Nullable PasswordHash Tests
// =============================================================================

func TestLogin_NilPasswordHash_ReturnsInvalidCredentials(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "googleuser",
			Email:        "google@example.com",
			PasswordHash: nil,
		}, nil
	}

	_, err := service.Login(context.Background(), "googleuser", "anypassword", false)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login() error = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestUpdateProfile_OAuthUserCannotChangeEmail(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "googleuser",
			Email:        "old@example.com",
			PasswordHash: nil,
		}, nil
	}

	newEmail := "new@example.com"
	_, err := service.UpdateProfile(context.Background(), 1, ProfileUpdateRequest{
		Email: &newEmail,
	})

	if !errors.Is(err, ErrOAuthUserCannotChangeEmail) {
		t.Errorf("UpdateProfile() error = %v, want %v", err, ErrOAuthUserCannotChangeEmail)
	}
}

func TestUpdateProfile_OAuthUserCanChangeDisplayName(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:           1,
			Username:     "googleuser",
			Email:        "user@example.com",
			PasswordHash: nil,
		}, nil
	}
	mockRepo.updateFunc = func(ctx context.Context, user *models.User) error {
		return nil
	}

	name := "New Name"
	result, err := service.UpdateProfile(context.Background(), 1, ProfileUpdateRequest{
		DisplayName: &name,
	})

	if err != nil {
		t.Fatalf("UpdateProfile() error = %v", err)
	}
	if *result.DisplayName != "New Name" {
		t.Errorf("UpdateProfile() display_name = %v, want New Name", *result.DisplayName)
	}
}

func TestHasPassword_True(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	hash := hashPassword(t, "password")
	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{ID: 1, PasswordHash: &hash}, nil
	}

	has, err := service.HasPassword(context.Background(), 1)
	if err != nil {
		t.Fatalf("HasPassword() error = %v", err)
	}
	if !has {
		t.Error("HasPassword() = false, want true")
	}
}

func TestHasPassword_False(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{ID: 1, PasswordHash: nil}, nil
	}

	has, err := service.HasPassword(context.Background(), 1)
	if err != nil {
		t.Fatalf("HasPassword() error = %v", err)
	}
	if has {
		t.Error("HasPassword() = true, want false")
	}
}

func TestSetPassword_Success(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{ID: 1, PasswordHash: nil}, nil
	}

	var updatedUser *models.User
	mockRepo.updateFunc = func(ctx context.Context, user *models.User) error {
		updatedUser = user
		return nil
	}

	err := service.SetPassword(context.Background(), 1, "newpassword123")
	if err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}

	if updatedUser.PasswordHash == nil {
		t.Fatal("SetPassword() should set password hash")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*updatedUser.PasswordHash), []byte("newpassword123")); err != nil {
		t.Error("SetPassword() password hash does not match")
	}
}

func TestSetPassword_TooShort(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{ID: 1, PasswordHash: nil}, nil
	}

	err := service.SetPassword(context.Background(), 1, "short")
	if err == nil {
		t.Error("SetPassword() should return error for short password")
	}
}

func TestSetPassword_TooLong(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	longPassword := strings.Repeat("a", 73)
	err := service.SetPassword(context.Background(), 1, longPassword)
	if !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("SetPassword() error = %v, want %v", err, ErrPasswordTooLong)
	}
}

func TestGoogleAuthURL_Disabled(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	_, err := service.GoogleAuthURL("somestate")
	if !errors.Is(err, ErrGoogleOAuthDisabled) {
		t.Errorf("GoogleAuthURL() error = %v, want %v", err, ErrGoogleOAuthDisabled)
	}
}

func TestGoogleCallback_Disabled(t *testing.T) {
	service, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	_, err := service.GoogleCallback(context.Background(), "somecode", false)
	if !errors.Is(err, ErrGoogleOAuthDisabled) {
		t.Errorf("GoogleCallback() error = %v, want %v", err, ErrGoogleOAuthDisabled)
	}
}

func TestGetLinkedProviders_Empty(t *testing.T) {
	svc, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	// oauthRepo is nil in test setup, so we need a service with a mock
	mockOAuth := &mockOAuthRepo{}
	svc.oauthRepo = mockOAuth

	providers, err := svc.GetLinkedProviders(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetLinkedProviders() error = %v", err)
	}
	if len(providers) != 0 {
		t.Errorf("GetLinkedProviders() = %v, want empty", providers)
	}
}

func TestGetLinkedProviders_WithGoogle(t *testing.T) {
	svc, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	mockOAuth := &mockOAuthRepo{
		findByUserIDFunc: func(ctx context.Context, userID int64) ([]models.OAuthAccount, error) {
			return []models.OAuthAccount{
				{Provider: "google", ProviderUserID: "123", UserID: userID, Email: "test@gmail.com"},
			}, nil
		},
	}
	svc.oauthRepo = mockOAuth

	providers, err := svc.GetLinkedProviders(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetLinkedProviders() error = %v", err)
	}
	if len(providers) != 1 || providers[0] != "google" {
		t.Errorf("GetLinkedProviders() = %v, want [google]", providers)
	}
}

func TestChangePassword_NilPasswordHash_ReturnsMismatch(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{ID: 1, PasswordHash: nil}, nil
	}

	err := service.ChangePassword(context.Background(), 1, ChangePasswordRequest{
		CurrentPassword: "anything",
		NewPassword:     "newpassword123",
	})

	if !errors.Is(err, ErrPasswordMismatch) {
		t.Errorf("ChangePassword() error = %v, want %v", err, ErrPasswordMismatch)
	}
}

func TestSetPassword_AlreadySet_ReturnsError(t *testing.T) {
	svc, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	hash := hashPassword(t, "existing")
	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{ID: 1, PasswordHash: &hash}, nil
	}

	err := svc.SetPassword(context.Background(), 1, "newpassword123")
	if !errors.Is(err, ErrPasswordAlreadySet) {
		t.Errorf("SetPassword() error = %v, want %v", err, ErrPasswordAlreadySet)
	}
}

func TestSetPassword_TooShort_ReturnsSentinel(t *testing.T) {
	svc, mr, _, _ := setupTestAuthService(t)
	defer mr.Close()

	err := svc.SetPassword(context.Background(), 1, "short")
	if !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("SetPassword() error = %v, want %v", err, ErrPasswordTooShort)
	}
}

func TestOAuthUsername_TruncatesLongEmail(t *testing.T) {
	longPrefix := strings.Repeat("a", 60)
	username := oauthUsername(longPrefix + "@example.com")

	if len(username) > 50 {
		t.Errorf("oauthUsername() length = %d, want <= 50", len(username))
	}
	if len(username) != 50 {
		t.Errorf("oauthUsername() length = %d, want 50 for long prefix", len(username))
	}
}

func TestOAuthUsername_ShortEmail(t *testing.T) {
	username := oauthUsername("alice@example.com")

	if len(username) > 50 {
		t.Errorf("oauthUsername() length = %d, want <= 50", len(username))
	}
	if !strings.HasPrefix(username, "alice-") {
		t.Errorf("oauthUsername() = %s, want prefix alice-", username)
	}
	// alice(5) + dash(1) + hex(8) = 14
	if len(username) != 14 {
		t.Errorf("oauthUsername() length = %d, want 14", len(username))
	}
}

func TestOAuthUsername_Uniqueness(t *testing.T) {
	u1 := oauthUsername("same@example.com")
	u2 := oauthUsername("same@example.com")

	if u1 == u2 {
		t.Error("oauthUsername() should generate unique usernames for same email")
	}
}

// =============================================================================
// Login with Email Tests
// =============================================================================

func TestLogin_WithEmail(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	passwordHash := hashPassword(t, "testpassword")

	mockRepo.findByUsernameOrEmailFunc = func(ctx context.Context, identifier string) (*models.User, error) {
		if identifier == "test@example.com" {
			return &models.User{
				ID:           1,
				Username:     "testuser",
				Email:        "test@example.com",
				PasswordHash: &passwordHash,
			}, nil
		}
		return nil, gorm.ErrRecordNotFound
	}

	result, err := service.Login(context.Background(), "test@example.com", "testpassword", false)

	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if result.AccessToken == "" {
		t.Error("Login() should return access token when logging in with email")
	}
}

// =============================================================================
// Username Change via UpdateProfile Tests
// =============================================================================

func TestUpdateProfile_ChangeUsername(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:       1,
			Username: "olduser",
			Email:    "test@example.com",
		}, nil
	}
	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return nil, gorm.ErrRecordNotFound
	}
	mockRepo.updateFunc = func(ctx context.Context, user *models.User) error {
		return nil
	}

	newUsername := "newuser"
	result, err := service.UpdateProfile(context.Background(), 1, ProfileUpdateRequest{
		Username: &newUsername,
	})

	if err != nil {
		t.Fatalf("UpdateProfile() error = %v", err)
	}

	if result.Username != "newuser" {
		t.Errorf("UpdateProfile() Username = %s, want newuser", result.Username)
	}
}

func TestUpdateProfile_UsernameTaken(t *testing.T) {
	service, mr, mockRepo, _ := setupTestAuthService(t)
	defer mr.Close()

	mockRepo.findByIDFunc = func(ctx context.Context, id int64) (*models.User, error) {
		return &models.User{
			ID:       1,
			Username: "olduser",
			Email:    "test@example.com",
		}, nil
	}
	mockRepo.findByUsernameFunc = func(ctx context.Context, username string) (*models.User, error) {
		return &models.User{ID: 2, Username: "taken"}, nil
	}

	takenUsername := "taken"
	_, err := service.UpdateProfile(context.Background(), 1, ProfileUpdateRequest{
		Username: &takenUsername,
	})

	if !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("UpdateProfile() error = %v, want %v", err, ErrUsernameTaken)
	}
}
