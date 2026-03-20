// Package service contains business logic for the auth service.
package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/GunarsK-portfolio/auth-service/internal/email"
	"github.com/GunarsK-portfolio/auth-service/internal/models"
	"github.com/GunarsK-portfolio/auth-service/internal/repository"
	"github.com/GunarsK-portfolio/portfolio-common/jwt"
	"github.com/GunarsK-portfolio/portfolio-common/logger"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

var ErrGoogleOAuthDisabled = errors.New("google oauth is not configured")

const (
	redisRefreshTokenPrefix = "refresh_token:%d:%s"
	redisRememberMePrefix   = "remember_me:%d:%s"
)

var (
	ErrInvalidCredentials         = errors.New("invalid credentials")
	ErrUserNotFound               = errors.New("user not found")
	ErrUsernameTaken              = errors.New("username already taken")
	ErrEmailTaken                 = errors.New("email already taken")
	ErrInvalidRoleCode            = errors.New("invalid role code")
	ErrRoleNotAllowed             = errors.New("role not allowed for self-registration")
	ErrPasswordTooLong            = errors.New("password exceeds 72 bytes")
	ErrInvalidRefreshToken        = errors.New("invalid refresh token")
	ErrSessionNotFound            = errors.New("session not found")
	ErrInvalidToken               = errors.New("invalid or expired token")
	ErrAlreadyVerified            = errors.New("email already verified")
	ErrTokenNotFound              = errors.New("verification token not found")
	ErrTokenEmailMismatch         = errors.New("verification token email does not match current email")
	ErrRateLimited                = errors.New("rate limit exceeded")
	ErrPasswordMismatch           = errors.New("current password is incorrect")
	ErrEmailNotConfigured         = errors.New("email service not configured")
	ErrTokenExpired               = errors.New("token has expired")
	ErrOAuthUserCannotChangeEmail = errors.New("oauth-only users cannot change email")
	ErrPasswordAlreadySet         = errors.New("password already set")
	ErrPasswordTooShort           = errors.New("password must be at least 8 characters")
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
	GoogleAuthURL(state string) (string, error)
	GoogleCallback(ctx context.Context, code string, rememberMe bool) (*LoginResponse, error)
	HasPassword(ctx context.Context, userID int64) (bool, error)
	GetLinkedProviders(ctx context.Context, userID int64) ([]string, error)
	SetPassword(ctx context.Context, userID int64, newPassword string) error
}

type authService struct {
	db                    *gorm.DB
	userRepo              repository.UserRepository
	verifyRepo            repository.VerificationTokenRepository
	jwtService            jwt.Service
	jwtSecret             string
	redis                 *redis.Client
	emailClient           email.Sender
	log                   *slog.Logger
	deniedSelfAssignRoles map[string]bool
	verifyRateLimitMax    int64
	verifyRateLimitWindow time.Duration
	oauthRepo             repository.OAuthAccountRepository
	userRoleRepo          repository.UserRoleRepository
	googleOAuth           *oauth2.Config
}

// NewAuthService creates a new AuthService instance.
func NewAuthService(
	db *gorm.DB,
	userRepo repository.UserRepository,
	verifyRepo repository.VerificationTokenRepository,
	oauthRepo repository.OAuthAccountRepository,
	userRoleRepo repository.UserRoleRepository,
	jwtService jwt.Service,
	jwtSecret string,
	redisClient *redis.Client,
	emailClient email.Sender,
	log *slog.Logger,
	deniedRoles []string,
	verifyRateLimitMax int64,
	verifyRateLimitWindow time.Duration,
	googleOAuth *oauth2.Config,
) AuthService {
	denied := make(map[string]bool, len(deniedRoles))
	for _, r := range deniedRoles {
		denied[r] = true
	}

	return &authService{
		db:                    db,
		userRepo:              userRepo,
		verifyRepo:            verifyRepo,
		oauthRepo:             oauthRepo,
		userRoleRepo:          userRoleRepo,
		jwtService:            jwtService,
		jwtSecret:             jwtSecret,
		redis:                 redisClient,
		emailClient:           emailClient,
		log:                   log,
		deniedSelfAssignRoles: denied,
		verifyRateLimitMax:    verifyRateLimitMax,
		verifyRateLimitWindow: verifyRateLimitWindow,
		googleOAuth:           googleOAuth,
	}
}

func ptrString(s string) *string { return &s }

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

	if user.PasswordHash == nil {
		return nil, ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return s.issueTokensForUser(ctx, user.ID, rememberMe)
}

func (s *authService) Logout(ctx context.Context, token, sessionID string) error {
	claims, err := s.jwtService.ValidateToken(token)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	deleted, err := s.redis.Del(ctx,
		fmt.Sprintf(redisRefreshTokenPrefix, claims.UserID, sessionID),
		fmt.Sprintf(redisRememberMePrefix, claims.UserID, sessionID),
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

	storedToken, err := s.redis.Get(ctx, fmt.Sprintf(redisRefreshTokenPrefix, claims.UserID, sessionID)).Result()
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
	if val, err := s.redis.Get(ctx, fmt.Sprintf(redisRememberMePrefix, claims.UserID, sessionID)).Result(); errors.Is(err, redis.Nil) {
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
		pipe.Set(ctx, fmt.Sprintf(redisRefreshTokenPrefix, claims.UserID, sessionID), newRefreshToken, refreshExpiry)
		pipe.Set(ctx, fmt.Sprintf(redisRememberMePrefix, claims.UserID, sessionID), rememberVal, refreshExpiry)
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
		PasswordHash: ptrString(string(hash)),
	}

	if req.RoleCode != "" {
		if s.deniedSelfAssignRoles[req.RoleCode] {
			return nil, ErrRoleNotAllowed
		}
		if _, err := s.userRepo.FindRoleByCode(ctx, req.RoleCode); err != nil {
			return nil, ErrInvalidRoleCode
		}
	}

	token, err := generateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	if err := s.runInTx(ctx, func(tx *gorm.DB) error {
		userRepo := s.userRepo
		verifyRepo := s.verifyRepo
		userRoleRepo := s.userRoleRepo
		if tx != nil {
			userRepo = repository.NewUserRepository(tx)
			verifyRepo = repository.NewVerificationTokenRepository(tx)
			userRoleRepo = repository.NewUserRoleRepository(tx)
		}

		if err := userRepo.Create(ctx, user); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		if req.RoleCode != "" {
			if err := userRoleRepo.AssignRole(ctx, user.ID, req.RoleCode); err != nil {
				return fmt.Errorf("failed to assign role: %w", err)
			}
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

	if err := s.checkRateLimit(ctx, fmt.Sprintf("verify_ratelimit:%d", userID)); err != nil {
		return err
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
	vt, err := s.verifyRepo.FindByTokenAndType(ctx, tokenHash, models.TokenTypeEmailVerification)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrTokenNotFound
		}
		return fmt.Errorf("failed to find verification token: %w", err)
	}

	// Defense-in-depth: constant-time compare after DB lookup.
	// Redundant with the WHERE clause but guards against future refactors
	// that might change lookup semantics (e.g. removing the hash filter).
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
			if errors.Is(err, repository.ErrTokenAlreadyUsed) {
				return ErrTokenNotFound
			}
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
	if emailChanged && user.PasswordHash == nil {
		return nil, ErrOAuthUserCannotChangeEmail
	}
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

	if user.PasswordHash == nil {
		return ErrPasswordMismatch
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		return ErrPasswordMismatch
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user.PasswordHash = ptrString(string(hash))
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

	if err := s.checkRateLimit(ctx, fmt.Sprintf("reset_ratelimit:%s", emailAddr)); err != nil {
		return err
	}

	user, err := s.userRepo.FindByEmail(ctx, emailAddr)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil // Don't leak whether email exists
		}
		return fmt.Errorf("failed to find user: %w", err)
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
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrTokenNotFound
		}
		return fmt.Errorf("failed to find reset token: %w", err)
	}

	// Defense-in-depth: constant-time compare after DB lookup.
	// Redundant with the WHERE clause but guards against future refactors
	// that might change lookup semantics (e.g. removing the hash filter).
	if subtle.ConstantTimeCompare([]byte(tokenHash), []byte(vt.Token)) != 1 {
		return ErrTokenNotFound
	}

	if vt.ExpiresAt != nil && time.Now().After(*vt.ExpiresAt) {
		_ = s.verifyRepo.MarkUsed(ctx, vt.ID)
		return ErrTokenExpired
	}

	user, err := s.userRepo.FindByID(ctx, vt.UserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to find user: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user.PasswordHash = ptrString(string(hash))

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
			if errors.Is(err, repository.ErrTokenAlreadyUsed) {
				return ErrTokenNotFound
			}
			return fmt.Errorf("failed to mark reset token as used: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	// Best-effort: password is already changed, don't fail the operation
	// if session invalidation has issues (e.g. Redis outage)
	if err := s.invalidateAllSessions(ctx, vt.UserID); err != nil {
		logger.FromContext(ctx, s.log).Error("failed to invalidate sessions after password reset", "user_id", vt.UserID, "error", err)
	}

	return nil
}

func (s *authService) GoogleAuthURL(state string) (string, error) {
	if s.googleOAuth == nil {
		return "", ErrGoogleOAuthDisabled
	}
	return s.googleOAuth.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

// oauthUsername generates a username from an email address, truncated to fit
// the 50-char DB limit with a random suffix to avoid collisions.
func oauthUsername(email string) string {
	prefix := strings.SplitN(email, "@", 2)[0]
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b) // 8 hex chars

	// 50 max - 1 dash - 8 suffix = 41 max prefix
	if len(prefix) > 41 {
		prefix = prefix[:41]
	}
	return prefix + "-" + suffix
}

// googleUserInfo holds the response from Google's OIDC userinfo endpoint.
type googleUserInfo struct {
	ID            string `json:"sub"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"email_verified"`
	Name          string `json:"name"`
}

func (s *authService) fetchGoogleUser(ctx context.Context, code string) (*googleUserInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	token, err := s.googleOAuth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange oauth code: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch google userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read google userinfo response: %w", err)
	}

	var info googleUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to parse google userinfo: %w", err)
	}

	if !info.VerifiedEmail {
		return nil, fmt.Errorf("google email is not verified")
	}

	return &info, nil
}

func (s *authService) GoogleCallback(ctx context.Context, code string, rememberMe bool) (*LoginResponse, error) {
	if s.googleOAuth == nil {
		return nil, ErrGoogleOAuthDisabled
	}

	info, err := s.fetchGoogleUser(ctx, code)
	if err != nil {
		return nil, err
	}

	// Check if oauth account already linked
	oauthAccount, err := s.oauthRepo.FindByProviderAndID(ctx, "google", info.ID)
	if err == nil {
		// Existing linked user — log in directly
		return s.issueTokensForUser(ctx, oauthAccount.UserID, rememberMe)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to look up oauth account: %w", err)
	}

	// Not linked — check if a verified user exists with the same email
	existingUser, err := s.userRepo.FindByEmail(ctx, info.Email)
	if err == nil && existingUser.EmailVerified {
		// Link to existing verified user
		if err := s.oauthRepo.Create(ctx, &models.OAuthAccount{
			Provider:       "google",
			ProviderUserID: info.ID,
			UserID:         existingUser.ID,
			Email:          info.Email,
		}); err != nil {
			return nil, fmt.Errorf("failed to link oauth account: %w", err)
		}
		return s.issueTokensForUser(ctx, existingUser.ID, rememberMe)
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to look up user by email: %w", err)
	}

	// New user — create account + oauth link + role atomically
	var userID int64
	if err := s.runInTx(ctx, func(tx *gorm.DB) error {
		userRepo := s.userRepo
		oauthRepo := s.oauthRepo
		userRoleRepo := s.userRoleRepo
		if tx != nil {
			userRepo = repository.NewUserRepository(tx)
			oauthRepo = repository.NewOAuthAccountRepository(tx)
			userRoleRepo = repository.NewUserRoleRepository(tx)
		}

		user := &models.User{
			Username:      oauthUsername(info.Email),
			Email:         info.Email,
			EmailVerified: true,
		}
		if err := userRepo.Create(ctx, user); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
		userID = user.ID

		if err := userRoleRepo.AssignRole(ctx, userID, "rpg-player"); err != nil {
			return fmt.Errorf("failed to assign role: %w", err)
		}

		return oauthRepo.Create(ctx, &models.OAuthAccount{
			Provider:       "google",
			ProviderUserID: info.ID,
			UserID:         user.ID,
			Email:          info.Email,
		})
	}); err != nil {
		// Concurrent request may have created the same oauth link — retry lookup
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			oauthAccount, retryErr := s.oauthRepo.FindByProviderAndID(ctx, "google", info.ID)
			if retryErr != nil {
				return nil, fmt.Errorf("failed to recover from duplicate: %w", err)
			}
			return s.issueTokensForUser(ctx, oauthAccount.UserID, rememberMe)
		}
		return nil, err
	}

	return s.issueTokensForUser(ctx, userID, rememberMe)
}

func (s *authService) issueTokensForUser(ctx context.Context, userID int64, rememberMe ...bool) (*LoginResponse, error) {
	remember := len(rememberMe) > 0 && rememberMe[0]
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	scopes, err := s.userRepo.GetUserScopes(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user scopes: %w", err)
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

	if _, err := s.redis.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, fmt.Sprintf(redisRefreshTokenPrefix, user.ID, sessionID), refreshToken, refreshExpiry)
		rememberVal := "0"
		if remember {
			rememberVal = "1"
		}
		pipe.Set(ctx, fmt.Sprintf(redisRememberMePrefix, user.ID, sessionID), rememberVal, refreshExpiry)
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
		RememberMe:    remember,
		SessionID:     sessionID,
	}, nil
}

func (s *authService) HasPassword(ctx context.Context, userID int64) (bool, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to find user: %w", err)
	}
	return user.PasswordHash != nil, nil
}

func (s *authService) GetLinkedProviders(ctx context.Context, userID int64) ([]string, error) {
	accounts, err := s.oauthRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get linked providers: %w", err)
	}
	providers := make([]string, len(accounts))
	for i, a := range accounts {
		providers[i] = a.Provider
	}
	return providers, nil
}

func (s *authService) SetPassword(ctx context.Context, userID int64, newPassword string) error {
	if len([]byte(newPassword)) < 8 {
		return ErrPasswordTooShort
	}
	if len([]byte(newPassword)) > 72 {
		return ErrPasswordTooLong
	}

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	if user.PasswordHash != nil {
		return ErrPasswordAlreadySet
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user.PasswordHash = ptrString(string(hash))
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	if err := s.invalidateAllSessions(ctx, userID); err != nil {
		return fmt.Errorf("failed to invalidate sessions: %w", err)
	}

	return nil
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

func (s *authService) checkRateLimit(ctx context.Context, key string) error {
	count, err := s.redis.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check rate limit: %w", err)
	}
	if count == 1 {
		if err := s.redis.Expire(ctx, key, s.verifyRateLimitWindow).Err(); err != nil {
			s.redis.Del(ctx, key)
			return fmt.Errorf("failed to set rate limit expiry: %w", err)
		}
	}
	if count > s.verifyRateLimitMax {
		return ErrRateLimited
	}
	return nil
}

func (s *authService) invalidateAllSessions(ctx context.Context, userID int64) error {
	pattern := fmt.Sprintf("refresh_token:%d:*", userID)
	iter := s.redis.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		if err := s.redis.Del(ctx, iter.Val()).Err(); err != nil {
			return fmt.Errorf("failed to delete session key: %w", err)
		}
		sessionID := iter.Val()[len(fmt.Sprintf("refresh_token:%d:", userID)):]
		if err := s.redis.Del(ctx, fmt.Sprintf(redisRememberMePrefix, userID, sessionID)).Err(); err != nil {
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
