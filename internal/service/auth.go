// Package service contains business logic for the auth service.
package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/GunarsK-portfolio/auth-service/internal/email"
	"github.com/GunarsK-portfolio/auth-service/internal/models"
	"github.com/GunarsK-portfolio/auth-service/internal/repository"
	"github.com/GunarsK-portfolio/portfolio-common/jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrUserNotFound        = errors.New("user not found")
	ErrUsernameTaken       = errors.New("username already taken")
	ErrEmailTaken          = errors.New("email already taken")
	ErrInvalidRoleCode     = errors.New("invalid role code")
	ErrRoleNotAllowed      = errors.New("role not allowed for self-registration")
	ErrPasswordTooLong     = errors.New("password exceeds 72 bytes")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrSessionNotFound     = errors.New("session not found")
	ErrInvalidToken        = errors.New("invalid or expired token")
	ErrAlreadyVerified     = errors.New("email already verified")
	ErrTokenNotFound       = errors.New("verification token not found")
	ErrTokenEmailMismatch  = errors.New("verification token email does not match current email")
	ErrRateLimited         = errors.New("rate limit exceeded")
	ErrPasswordMismatch    = errors.New("current password is incorrect")
	ErrEmailNotConfigured  = errors.New("email service not configured")
	ErrTokenExpired        = errors.New("token has expired")
)

// LoginRequest contains credentials for user login.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse contains JWT tokens returned after successful login.
type LoginResponse struct {
	AccessToken   string            `json:"access_token"`
	RefreshToken  string            `json:"refresh_token"`
	ExpiresIn     int64             `json:"expires_in"`
	UserID        int64             `json:"-"`
	Username      string            `json:"-"`
	Email         string            `json:"-"`
	EmailVerified bool              `json:"-"`
	DisplayName   string            `json:"-"`
	Scopes        map[string]string `json:"-"`
	RememberMe    bool              `json:"-"`
	SessionID     string            `json:"-"`
}

// RegisterRequest contains data for user registration.
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	RoleCode string `json:"role_code"`
}

// RegisterResponse contains the newly created user data.
type RegisterResponse struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// ProfileUpdateRequest contains fields for updating user profile.
type ProfileUpdateRequest struct {
	Email       *string `json:"email"`
	DisplayName *string `json:"display_name"`
}

// ProfileResponse contains user profile data.
type ProfileResponse struct {
	UserID        int64   `json:"user_id"`
	Username      string  `json:"username"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	DisplayName   *string `json:"display_name"`
}

// ChangePasswordRequest contains data for changing password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// AuthService defines authentication operations.
type AuthService interface {
	Login(ctx context.Context, username, password string, rememberMe bool) (*LoginResponse, error)
	Logout(ctx context.Context, token, sessionID string) error
	RefreshToken(ctx context.Context, refreshToken, sessionID string) (*LoginResponse, error)
	ValidateToken(token string) (int64, error)
	ValidateTokenWithClaims(token string) (int64, *jwt.Claims, error)
	Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error)
	SendVerification(ctx context.Context, userID int64, emailFromClaims, origin string) error
	VerifyEmail(ctx context.Context, token string) error
	UpdateProfile(ctx context.Context, userID int64, req ProfileUpdateRequest) (*ProfileResponse, error)
	ChangePassword(ctx context.Context, userID int64, req ChangePasswordRequest) error
	ForgotPassword(ctx context.Context, email, origin string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
}

type authService struct {
	db                    *gorm.DB
	userRepo              repository.UserRepository
	verifyRepo            repository.VerificationTokenRepository
	jwtService            jwt.Service
	jwtSecret             string
	redis                 *redis.Client
	emailClient           *email.Client
	deniedSelfAssignRoles map[string]bool
	verifyRateLimitMax    int64
	verifyRateLimitWindow time.Duration
}

// NewAuthService creates a new AuthService instance.
func NewAuthService(
	db *gorm.DB,
	userRepo repository.UserRepository,
	verifyRepo repository.VerificationTokenRepository,
	jwtService jwt.Service,
	jwtSecret string,
	redisClient *redis.Client,
	emailClient *email.Client,
	deniedRoles []string,
	verifyRateLimitMax int64,
	verifyRateLimitWindow time.Duration,
) AuthService {
	denied := make(map[string]bool, len(deniedRoles))
	for _, r := range deniedRoles {
		denied[r] = true
	}
	return &authService{
		db:                    db,
		userRepo:              userRepo,
		verifyRepo:            verifyRepo,
		jwtService:            jwtService,
		jwtSecret:             jwtSecret,
		redis:                 redisClient,
		emailClient:           emailClient,
		deniedSelfAssignRoles: denied,
		verifyRateLimitMax:    verifyRateLimitMax,
		verifyRateLimitWindow: verifyRateLimitWindow,
	}
}

// runInTx executes fn inside a database transaction when a DB handle is
// available. In test environments where db is nil the callback receives nil
// (callers must guard repo construction accordingly).
func (s *authService) runInTx(ctx context.Context, fn func(tx *gorm.DB) error) error {
	if s.db == nil {
		return fn(nil)
	}
	return s.db.WithContext(ctx).Transaction(fn)
}

func (s *authService) Login(ctx context.Context, username, password string, rememberMe bool) (*LoginResponse, error) {
	user, err := s.userRepo.FindByUsername(ctx, username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	scopes, err := s.userRepo.GetUserScopes(ctx, user.ID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	displayName := ""
	if user.DisplayName != nil {
		displayName = *user.DisplayName
	}

	accessToken, err := s.signToken(user.ID, user.Username, user.Email, user.EmailVerified, displayName, scopes, s.jwtService.GetAccessExpiry())
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.signToken(user.ID, user.Username, user.Email, user.EmailVerified, displayName, scopes, s.jwtService.GetRefreshExpiry())
	if err != nil {
		return nil, err
	}

	refreshExpiry := s.jwtService.GetRefreshExpiry()
	sessionID := uuid.New().String()

	rememberVal := "0"
	if rememberMe {
		rememberVal = "1"
	}
	if _, err := s.redis.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, fmt.Sprintf("refresh_token:%d:%s", user.ID, sessionID), refreshToken, refreshExpiry)
		pipe.Set(ctx, fmt.Sprintf("remember_me:%d:%s", user.ID, sessionID), rememberVal, refreshExpiry)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	return &LoginResponse{
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		ExpiresIn:     int64(s.jwtService.GetAccessExpiry().Seconds()),
		UserID:        user.ID,
		Username:      user.Username,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		DisplayName:   displayName,
		Scopes:        scopes,
		RememberMe:    rememberMe,
		SessionID:     sessionID,
	}, nil
}

func (s *authService) Logout(ctx context.Context, token, sessionID string) error {
	claims, err := s.jwtService.ValidateToken(token)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	deleted, err := s.redis.Del(ctx,
		fmt.Sprintf("refresh_token:%d:%s", claims.UserID, sessionID),
		fmt.Sprintf("remember_me:%d:%s", claims.UserID, sessionID),
	).Result()
	if err != nil {
		return fmt.Errorf("failed to invalidate session: %w", err)
	}
	if deleted == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (s *authService) RefreshToken(ctx context.Context, refreshToken, sessionID string) (*LoginResponse, error) {
	if _, err := uuid.Parse(sessionID); err != nil {
		return nil, ErrInvalidRefreshToken
	}

	claims, err := s.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}

	storedToken, err := s.redis.Get(ctx, fmt.Sprintf("refresh_token:%d:%s", claims.UserID, sessionID)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh token: %w", err)
	}
	if storedToken != refreshToken {
		return nil, ErrInvalidRefreshToken
	}

	rememberMe := false
	if val, err := s.redis.Get(ctx, fmt.Sprintf("remember_me:%d:%s", claims.UserID, sessionID)).Result(); errors.Is(err, redis.Nil) {
		// Key not found, keep default false
	} else if err != nil {
		return nil, fmt.Errorf("failed to read remember_me preference: %w", err)
	} else {
		rememberMe = val == "1"
	}

	// Fetch fresh user data from DB so profile changes (email, display_name,
	// email_verified) are picked up immediately on token refresh.
	user, err := s.userRepo.FindByID(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user for refresh: %w", err)
	}

	// Re-fetch scopes so role changes are also picked up
	freshScopes, err := s.userRepo.GetUserScopes(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch scopes for refresh: %w", err)
	}

	displayName := ""
	if user.DisplayName != nil {
		displayName = *user.DisplayName
	}

	accessToken, err := s.signToken(user.ID, user.Username, user.Email, user.EmailVerified, displayName, freshScopes, s.jwtService.GetAccessExpiry())
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := s.signToken(user.ID, user.Username, user.Email, user.EmailVerified, displayName, freshScopes, s.jwtService.GetRefreshExpiry())
	if err != nil {
		return nil, err
	}

	refreshExpiry := s.jwtService.GetRefreshExpiry()

	rememberVal := "0"
	if rememberMe {
		rememberVal = "1"
	}
	if _, err := s.redis.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, fmt.Sprintf("refresh_token:%d:%s", claims.UserID, sessionID), newRefreshToken, refreshExpiry)
		pipe.Set(ctx, fmt.Sprintf("remember_me:%d:%s", claims.UserID, sessionID), rememberVal, refreshExpiry)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.jwtService.GetAccessExpiry().Seconds()),
		RememberMe:   rememberMe,
		SessionID:    sessionID,
	}, nil
}

func (s *authService) ValidateToken(token string) (int64, error) {
	claims, err := s.jwtService.ValidateToken(token)
	if err != nil {
		return 0, err
	}

	ttl := int64(time.Until(claims.ExpiresAt.Time).Seconds())
	if ttl < 0 {
		ttl = 0
	}

	return ttl, nil
}

func (s *authService) ValidateTokenWithClaims(token string) (int64, *jwt.Claims, error) {
	claims, err := s.jwtService.ValidateToken(token)
	if err != nil {
		return 0, nil, err
	}

	ttl := int64(time.Until(claims.ExpiresAt.Time).Seconds())
	if ttl < 0 {
		ttl = 0
	}

	return ttl, claims, nil
}

func (s *authService) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	if len([]byte(req.Password)) > 72 {
		return nil, ErrPasswordTooLong
	}

	if _, err := s.userRepo.FindByUsername(ctx, req.Username); err == nil {
		return nil, ErrUsernameTaken
	}

	if _, err := s.userRepo.FindByEmail(ctx, req.Email); err == nil {
		return nil, ErrEmailTaken
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hash),
	}

	if req.RoleCode != "" {
		if s.deniedSelfAssignRoles[req.RoleCode] {
			return nil, ErrRoleNotAllowed
		}
		role, err := s.userRepo.FindRoleByCode(ctx, req.RoleCode)
		if err != nil {
			return nil, ErrInvalidRoleCode
		}
		roleID := int(role.ID)
		user.RoleID = &roleID
	}

	token, err := generateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	if err := s.runInTx(ctx, func(tx *gorm.DB) error {
		userRepo := s.userRepo
		verifyRepo := s.verifyRepo
		if tx != nil {
			userRepo = repository.NewUserRepository(tx)
			verifyRepo = repository.NewVerificationTokenRepository(tx)
		}

		if err := userRepo.Create(ctx, user); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		vt := &models.VerificationToken{
			UserID: user.ID,
			Email:  user.Email,
			Token:  models.HashToken(token),
			Type:   models.TokenTypeEmailVerification,
		}
		if err := verifyRepo.Create(ctx, vt); err != nil {
			return fmt.Errorf("failed to store verification token: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &RegisterResponse{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
	}, nil
}

func (s *authService) SendVerification(ctx context.Context, userID int64, emailFromClaims, origin string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to find user: %w", err)
	}

	if user.EmailVerified {
		return ErrAlreadyVerified
	}

	if s.emailClient == nil {
		return ErrEmailNotConfigured
	}

	rateLimitKey := fmt.Sprintf("verify_ratelimit:%d", userID)
	count, err := s.redis.Incr(ctx, rateLimitKey).Result()
	if err != nil {
		return fmt.Errorf("failed to check rate limit: %w", err)
	}
	if count == 1 {
		if err := s.redis.Expire(ctx, rateLimitKey, s.verifyRateLimitWindow).Err(); err != nil {
			s.redis.Del(ctx, rateLimitKey)
			return fmt.Errorf("failed to set rate limit expiry: %w", err)
		}
	}
	if count > s.verifyRateLimitMax {
		return ErrRateLimited
	}

	// Always generate a fresh token since we can't recover raw from hash.
	// Delete any existing unused verification token first.
	if delErr := s.verifyRepo.DeleteByUserIDAndType(ctx, userID, models.TokenTypeEmailVerification); delErr != nil {
		return fmt.Errorf("failed to delete old verification token: %w", delErr)
	}

	rawToken, err := generateVerificationToken()
	if err != nil {
		return fmt.Errorf("failed to generate verification token: %w", err)
	}
	vt := &models.VerificationToken{
		UserID: userID,
		Email:  user.Email,
		Token:  models.HashToken(rawToken),
		Type:   models.TokenTypeEmailVerification,
	}
	if createErr := s.verifyRepo.Create(ctx, vt); createErr != nil {
		return fmt.Errorf("failed to store verification token: %w", createErr)
	}

	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", origin, rawToken)

	return s.emailClient.SendVerificationEmail(ctx, user.Email, user.Username, verifyURL)
}

func (s *authService) VerifyEmail(ctx context.Context, token string) error {
	tokenHash := models.HashToken(token)
	vt, err := s.verifyRepo.FindByToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrTokenNotFound
		}
		return fmt.Errorf("failed to find verification token: %w", err)
	}

	// Defense-in-depth: constant-time compare after DB lookup
	if subtle.ConstantTimeCompare([]byte(tokenHash), []byte(vt.Token)) != 1 {
		return ErrTokenNotFound
	}

	user, err := s.userRepo.FindByID(ctx, vt.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to find user: %w", err)
	}

	// Reject if user changed email since token was created
	if user.Email != vt.Email {
		return ErrTokenEmailMismatch
	}

	user.EmailVerified = true
	return s.runInTx(ctx, func(tx *gorm.DB) error {
		userRepo := s.userRepo
		verifyRepo := s.verifyRepo
		if tx != nil {
			userRepo = repository.NewUserRepository(tx)
			verifyRepo = repository.NewVerificationTokenRepository(tx)
		}

		if err := userRepo.Update(ctx, user); err != nil {
			return fmt.Errorf("failed to update email verified status: %w", err)
		}
		if err := verifyRepo.MarkUsed(ctx, vt.ID); err != nil {
			return fmt.Errorf("failed to mark verification token as used: %w", err)
		}
		return nil
	})
}

func (s *authService) UpdateProfile(ctx context.Context, userID int64, req ProfileUpdateRequest) (*ProfileResponse, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	emailChanged := req.Email != nil && *req.Email != user.Email
	if emailChanged {
		existing, err := s.userRepo.FindByEmail(ctx, *req.Email)
		if err == nil && existing != nil {
			return nil, ErrEmailTaken
		}
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("failed to check email uniqueness: %w", err)
		}

		user.Email = *req.Email
		user.EmailVerified = false
	}

	if req.DisplayName != nil {
		user.DisplayName = req.DisplayName
	}

	if err := s.runInTx(ctx, func(tx *gorm.DB) error {
		userRepo := s.userRepo
		verifyRepo := s.verifyRepo
		if tx != nil {
			userRepo = repository.NewUserRepository(tx)
			verifyRepo = repository.NewVerificationTokenRepository(tx)
		}

		if err := userRepo.Update(ctx, user); err != nil {
			return fmt.Errorf("failed to update profile: %w", err)
		}

		if emailChanged {
			if err := verifyRepo.DeleteByUserID(ctx, userID); err != nil {
				return fmt.Errorf("failed to delete old verification token: %w", err)
			}
			token, err := generateVerificationToken()
			if err != nil {
				return fmt.Errorf("failed to generate verification token: %w", err)
			}
			vt := &models.VerificationToken{
				UserID: userID,
				Email:  *req.Email,
				Token:  models.HashToken(token),
				Type:   models.TokenTypeEmailVerification,
			}
			if err := verifyRepo.Create(ctx, vt); err != nil {
				return fmt.Errorf("failed to store verification token: %w", err)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &ProfileResponse{
		UserID:        user.ID,
		Username:      user.Username,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		DisplayName:   user.DisplayName,
	}, nil
}

func (s *authService) ChangePassword(ctx context.Context, userID int64, req ChangePasswordRequest) error {
	if len([]byte(req.NewPassword)) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if len([]byte(req.NewPassword)) > 72 {
		return ErrPasswordTooLong
	}

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to find user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		return ErrPasswordMismatch
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user.PasswordHash = string(hash)
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	if err := s.invalidateAllSessions(ctx, userID); err != nil {
		return fmt.Errorf("failed to invalidate sessions: %w", err)
	}

	return nil
}

func (s *authService) ForgotPassword(ctx context.Context, emailAddr, origin string) error {
	if s.emailClient == nil {
		return ErrEmailNotConfigured
	}

	// Rate limit by email address
	rateLimitKey := fmt.Sprintf("reset_ratelimit:%s", emailAddr)
	count, err := s.redis.Incr(ctx, rateLimitKey).Result()
	if err != nil {
		return fmt.Errorf("failed to check rate limit: %w", err)
	}
	if count == 1 {
		if err := s.redis.Expire(ctx, rateLimitKey, s.verifyRateLimitWindow).Err(); err != nil {
			s.redis.Del(ctx, rateLimitKey)
			return fmt.Errorf("failed to set rate limit expiry: %w", err)
		}
	}
	if count > s.verifyRateLimitMax {
		return ErrRateLimited
	}

	user, err := s.userRepo.FindByEmail(ctx, emailAddr)
	if err != nil {
		return nil // Don't leak whether email exists
	}

	if !user.EmailVerified {
		return nil // Only allow reset for verified emails
	}

	// Delete any existing unused password reset tokens for this user
	if err := s.verifyRepo.DeleteByUserIDAndType(ctx, user.ID, models.TokenTypePasswordReset); err != nil {
		return fmt.Errorf("failed to delete existing reset token: %w", err)
	}

	rawToken, err := generateVerificationToken()
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	vt := &models.VerificationToken{
		UserID:    user.ID,
		Email:     user.Email,
		Token:     models.HashToken(rawToken),
		Type:      models.TokenTypePasswordReset,
		ExpiresAt: &expiresAt,
	}
	if err := s.verifyRepo.Create(ctx, vt); err != nil {
		return fmt.Errorf("failed to store reset token: %w", err)
	}

	resetURL := fmt.Sprintf("%s/reset-password?token=%s", origin, rawToken)
	return s.emailClient.SendPasswordResetEmail(ctx, user.Email, user.Username, resetURL)
}

func (s *authService) ResetPassword(ctx context.Context, token, newPassword string) error {
	if len([]byte(newPassword)) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if len([]byte(newPassword)) > 72 {
		return ErrPasswordTooLong
	}

	tokenHash := models.HashToken(token)
	vt, err := s.verifyRepo.FindByTokenAndType(ctx, tokenHash, models.TokenTypePasswordReset)
	if err != nil {
		return ErrTokenNotFound
	}

	// Defense-in-depth: constant-time compare after DB lookup
	if subtle.ConstantTimeCompare([]byte(tokenHash), []byte(vt.Token)) != 1 {
		return ErrTokenNotFound
	}

	if vt.ExpiresAt != nil && time.Now().After(*vt.ExpiresAt) {
		_ = s.verifyRepo.MarkUsed(ctx, vt.ID)
		return ErrTokenExpired
	}

	user, err := s.userRepo.FindByID(ctx, vt.UserID)
	if err != nil {
		return ErrUserNotFound
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user.PasswordHash = string(hash)

	if err := s.runInTx(ctx, func(tx *gorm.DB) error {
		userRepo := s.userRepo
		verifyRepo := s.verifyRepo
		if tx != nil {
			userRepo = repository.NewUserRepository(tx)
			verifyRepo = repository.NewVerificationTokenRepository(tx)
		}

		if err := userRepo.Update(ctx, user); err != nil {
			return fmt.Errorf("failed to update password: %w", err)
		}
		if err := verifyRepo.MarkUsed(ctx, vt.ID); err != nil {
			return fmt.Errorf("failed to mark reset token as used: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	return s.invalidateAllSessions(ctx, vt.UserID)
}

// signToken creates a JWT with email fields populated. Uses golang-jwt directly
// because portfolio-common's GenerateAccessToken/GenerateRefreshToken don't
// support email/emailVerified claims.
func (s *authService) signToken(userID int64, username, userEmail string, emailVerified bool, displayName string, scopes map[string]string, expiry time.Duration) (string, error) {
	if userID <= 0 {
		return "", fmt.Errorf("user ID must be positive")
	}
	if username == "" {
		return "", fmt.Errorf("username cannot be empty")
	}

	var scopesCopy map[string]string
	if scopes != nil {
		scopesCopy = make(map[string]string, len(scopes))
		for k, v := range scopes {
			scopesCopy[k] = v
		}
	}

	now := time.Now()
	claims := jwt.Claims{
		UserID:        userID,
		Username:      username,
		Email:         userEmail,
		EmailVerified: emailVerified,
		DisplayName:   displayName,
		Scopes:        scopesCopy,
		RegisteredClaims: jwtlib.RegisteredClaims{
			ExpiresAt: jwtlib.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwtlib.NewNumericDate(now),
		},
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *authService) invalidateAllSessions(ctx context.Context, userID int64) error {
	pattern := fmt.Sprintf("refresh_token:%d:*", userID)
	iter := s.redis.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		if err := s.redis.Del(ctx, iter.Val()).Err(); err != nil {
			return fmt.Errorf("failed to delete session key: %w", err)
		}
		sessionID := iter.Val()[len(fmt.Sprintf("refresh_token:%d:", userID)):]
		if err := s.redis.Del(ctx, fmt.Sprintf("remember_me:%d:%s", userID, sessionID)).Err(); err != nil {
			return fmt.Errorf("failed to delete remember_me key: %w", err)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan sessions: %w", err)
	}
	return nil
}

func generateVerificationToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
