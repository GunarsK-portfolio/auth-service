// Package service contains business logic for the auth service.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GunarsK-portfolio/auth-service/internal/models"
	"github.com/GunarsK-portfolio/auth-service/internal/repository"
	"github.com/GunarsK-portfolio/portfolio-common/jwt"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrInvalidCredentials is returned when login credentials are invalid.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUserNotFound is returned when user is not found.
	ErrUserNotFound = errors.New("user not found")
	// ErrUsernameTaken is returned when the username is already in use.
	ErrUsernameTaken = errors.New("username already taken")
	// ErrEmailTaken is returned when the email is already in use.
	ErrEmailTaken = errors.New("email already taken")
	// ErrInvalidRoleCode is returned when the provided role code doesn't exist.
	ErrInvalidRoleCode = errors.New("invalid role code")
	// ErrRoleNotAllowed is returned when the role code is not permitted for self-registration.
	ErrRoleNotAllowed      = errors.New("role not allowed for self-registration")
	ErrPasswordTooLong     = errors.New("password exceeds 72 bytes")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

// LoginRequest contains credentials for user login.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse contains JWT tokens returned after successful login.
type LoginResponse struct {
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	ExpiresIn    int64             `json:"expires_in"`
	UserID       int64             `json:"-"` // Not exposed in JSON, only for internal use
	Username     string            `json:"-"` // Not exposed in JSON, only for internal use
	Scopes       map[string]string `json:"-"` // Not exposed in JSON, only for internal use
	RememberMe   bool              `json:"-"` // Not exposed in JSON, only for internal use
	SessionID    string            `json:"-"` // Not exposed in JSON, only for internal use
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

// AuthService defines authentication operations.
type AuthService interface {
	Login(ctx context.Context, username, password string, rememberMe bool) (*LoginResponse, error)
	Logout(ctx context.Context, token, sessionID string) error
	RefreshToken(ctx context.Context, refreshToken, sessionID string) (*LoginResponse, error)
	ValidateToken(token string) (int64, error)
	ValidateTokenWithClaims(token string) (int64, *jwt.Claims, error)
	Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error)
}

type authService struct {
	userRepo              repository.UserRepository
	jwtService            jwt.Service
	redis                 *redis.Client
	deniedSelfAssignRoles map[string]bool
}

// NewAuthService creates a new AuthService instance.
func NewAuthService(userRepo repository.UserRepository, jwtService jwt.Service, redisClient *redis.Client, deniedRoles []string) AuthService {
	denied := make(map[string]bool, len(deniedRoles))
	for _, r := range deniedRoles {
		denied[r] = true
	}
	return &authService{
		userRepo:              userRepo,
		jwtService:            jwtService,
		redis:                 redisClient,
		deniedSelfAssignRoles: denied,
	}
}

func (s *authService) Login(ctx context.Context, username, password string, rememberMe bool) (*LoginResponse, error) {
	user, err := s.userRepo.FindByUsername(ctx, username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Get user scopes from role
	scopes, err := s.userRepo.GetUserScopes(ctx, user.ID)
	if err != nil {
		// Return generic error to prevent user enumeration
		return nil, ErrInvalidCredentials
	}

	accessToken, err := s.jwtService.GenerateAccessToken(user.ID, user.Username, scopes)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.jwtService.GenerateRefreshToken(user.ID, user.Username, scopes)
	if err != nil {
		return nil, err
	}

	refreshExpiry := s.jwtService.GetRefreshExpiry()
	sessionID := uuid.New().String()

	// Store refresh token and remember_me atomically (per-session keys)
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
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.jwtService.GetAccessExpiry().Seconds()),
		UserID:       user.ID,
		Username:     user.Username,
		Scopes:       scopes,
		RememberMe:   rememberMe,
		SessionID:    sessionID,
	}, nil
}

func (s *authService) Logout(ctx context.Context, token, sessionID string) error {
	claims, err := s.jwtService.ValidateToken(token)
	if err != nil {
		return err
	}

	// Remove only this session's refresh token and remember_me from Redis
	if err := s.redis.Del(ctx,
		fmt.Sprintf("refresh_token:%d:%s", claims.UserID, sessionID),
		fmt.Sprintf("remember_me:%d:%s", claims.UserID, sessionID),
	).Err(); err != nil {
		return fmt.Errorf("failed to invalidate session: %w", err)
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

	// Check if refresh token exists in Redis for this session
	storedToken, err := s.redis.Get(ctx, fmt.Sprintf("refresh_token:%d:%s", claims.UserID, sessionID)).Result()
	if err != nil || storedToken != refreshToken {
		return nil, ErrInvalidRefreshToken
	}

	// Read remember_me preference from Redis (default false on key miss)
	rememberMe := false
	if val, err := s.redis.Get(ctx, fmt.Sprintf("remember_me:%d:%s", claims.UserID, sessionID)).Result(); errors.Is(err, redis.Nil) {
		// Key not found, keep default false
	} else if err != nil {
		return nil, fmt.Errorf("failed to read remember_me preference: %w", err)
	} else {
		rememberMe = val == "1"
	}

	// Generate new tokens using scopes from refresh token.
	// Note: Scopes may become stale if user's role changes between refreshes.
	// This is an intentional trade-off to avoid a database lookup on every refresh.
	// Users must re-login to get updated scopes after role changes.
	accessToken, err := s.jwtService.GenerateAccessToken(claims.UserID, claims.Username, claims.Scopes)
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := s.jwtService.GenerateRefreshToken(claims.UserID, claims.Username, claims.Scopes)
	if err != nil {
		return nil, err
	}

	refreshExpiry := s.jwtService.GetRefreshExpiry()

	// Update refresh token and remember_me atomically
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

	// Calculate TTL from expiry time
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

	// Calculate TTL from expiry time
	ttl := int64(time.Until(claims.ExpiresAt.Time).Seconds())
	if ttl < 0 {
		ttl = 0
	}

	return ttl, claims, nil
}

func (s *authService) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	// bcrypt silently truncates passwords longer than 72 bytes
	if len([]byte(req.Password)) > 72 {
		return nil, ErrPasswordTooLong
	}

	// Check if username is taken
	if _, err := s.userRepo.FindByUsername(ctx, req.Username); err == nil {
		return nil, ErrUsernameTaken
	}

	// Check if email is taken
	if _, err := s.userRepo.FindByEmail(ctx, req.Email); err == nil {
		return nil, ErrEmailTaken
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hash),
	}

	// Resolve role if provided (privileged roles are blocked)
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

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &RegisterResponse{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
	}, nil
}
