// Package service contains business logic for the auth service.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GunarsK-portfolio/auth-service/internal/repository"
	"github.com/GunarsK-portfolio/portfolio-common/jwt"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrInvalidCredentials is returned when login credentials are invalid.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUserNotFound is returned when user is not found.
	ErrUserNotFound = errors.New("user not found")
)

// LoginRequest contains credentials for user login.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse contains JWT tokens returned after successful login.
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	UserID       int64  `json:"-"` // Not exposed in JSON, only for internal use
	Username     string `json:"-"` // Not exposed in JSON, only for internal use
}

// AuthService defines authentication operations.
type AuthService interface {
	Login(ctx context.Context, username, password string) (*LoginResponse, error)
	Logout(ctx context.Context, token string) error
	RefreshToken(ctx context.Context, refreshToken string) (*LoginResponse, error)
	ValidateToken(token string) (int64, error)
	ValidateTokenWithClaims(token string) (int64, *jwt.Claims, error)
}

type authService struct {
	userRepo   repository.UserRepository
	jwtService jwt.Service
	redis      *redis.Client
}

// NewAuthService creates a new AuthService instance.
func NewAuthService(userRepo repository.UserRepository, jwtService jwt.Service, redisClient *redis.Client) AuthService {
	return &authService{
		userRepo:   userRepo,
		jwtService: jwtService,
		redis:      redisClient,
	}
}

func (s *authService) Login(ctx context.Context, username, password string) (*LoginResponse, error) {
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

	// Store refresh token in Redis with same expiry as JWT refresh token
	if err := s.redis.Set(ctx, fmt.Sprintf("refresh_token:%d", user.ID), refreshToken, s.jwtService.GetRefreshExpiry()).Err(); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.jwtService.GetAccessExpiry().Seconds()),
		UserID:       user.ID,
		Username:     user.Username,
	}, nil
}

func (s *authService) Logout(ctx context.Context, token string) error {
	claims, err := s.jwtService.ValidateToken(token)
	if err != nil {
		return err
	}

	// Remove refresh token from Redis
	if err := s.redis.Del(ctx, fmt.Sprintf("refresh_token:%d", claims.UserID)).Err(); err != nil {
		return fmt.Errorf("failed to invalidate refresh token: %w", err)
	}

	return nil
}

func (s *authService) RefreshToken(ctx context.Context, refreshToken string) (*LoginResponse, error) {
	claims, err := s.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Check if refresh token exists in Redis
	storedToken, err := s.redis.Get(ctx, fmt.Sprintf("refresh_token:%d", claims.UserID)).Result()
	if err != nil || storedToken != refreshToken {
		return nil, errors.New("invalid refresh token")
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

	// Update refresh token in Redis with same expiry as JWT refresh token
	if err := s.redis.Set(ctx, fmt.Sprintf("refresh_token:%d", claims.UserID), newRefreshToken, s.jwtService.GetRefreshExpiry()).Err(); err != nil {
		return nil, fmt.Errorf("failed to update refresh token: %w", err)
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.jwtService.GetAccessExpiry().Seconds()),
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
