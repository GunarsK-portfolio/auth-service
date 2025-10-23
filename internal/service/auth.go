// Package service contains business logic for the auth service.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GunarsK-portfolio/auth-service/internal/repository"
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
}

// AuthService defines authentication operations.
type AuthService interface {
	Login(username, password string) (*LoginResponse, error)
	Logout(token string) error
	RefreshToken(refreshToken string) (*LoginResponse, error)
	ValidateToken(token string) (int64, error)
}

type authService struct {
	userRepo   repository.UserRepository
	jwtService JWTService
	redis      *redis.Client
}

// NewAuthService creates a new AuthService instance.
func NewAuthService(userRepo repository.UserRepository, jwtService JWTService, redisClient *redis.Client) AuthService {
	return &authService{
		userRepo:   userRepo,
		jwtService: jwtService,
		redis:      redisClient,
	}
}

func (s *authService) Login(username, password string) (*LoginResponse, error) {
	user, err := s.userRepo.FindByUsername(username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	accessToken, err := s.jwtService.GenerateAccessToken(user.ID, user.Username)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.jwtService.GenerateRefreshToken(user.ID, user.Username)
	if err != nil {
		return nil, err
	}

	// Store refresh token in Redis with same expiry as JWT refresh token
	ctx := context.Background()
	s.redis.Set(ctx, fmt.Sprintf("refresh_token:%d", user.ID), refreshToken, s.jwtService.GetRefreshExpiry())

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.jwtService.GetAccessExpiry().Seconds()),
	}, nil
}

func (s *authService) Logout(token string) error {
	claims, err := s.jwtService.ValidateToken(token)
	if err != nil {
		return err
	}

	// Remove refresh token from Redis
	ctx := context.Background()
	s.redis.Del(ctx, fmt.Sprintf("refresh_token:%d", claims.UserID))

	return nil
}

func (s *authService) RefreshToken(refreshToken string) (*LoginResponse, error) {
	claims, err := s.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Check if refresh token exists in Redis
	ctx := context.Background()
	storedToken, err := s.redis.Get(ctx, fmt.Sprintf("refresh_token:%d", claims.UserID)).Result()
	if err != nil || storedToken != refreshToken {
		return nil, errors.New("invalid refresh token")
	}

	// Generate new tokens
	accessToken, err := s.jwtService.GenerateAccessToken(claims.UserID, claims.Username)
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := s.jwtService.GenerateRefreshToken(claims.UserID, claims.Username)
	if err != nil {
		return nil, err
	}

	// Update refresh token in Redis with same expiry as JWT refresh token
	s.redis.Set(ctx, fmt.Sprintf("refresh_token:%d", claims.UserID), newRefreshToken, s.jwtService.GetRefreshExpiry())

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
