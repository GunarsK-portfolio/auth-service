package service

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents JWT token claims.
type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// JWTService defines JWT token operations.
type JWTService interface {
	GenerateAccessToken(userID int64, username string) (string, error)
	GenerateRefreshToken(userID int64, username string) (string, error)
	ValidateToken(tokenString string) (*Claims, error)
}

type jwtService struct {
	secret        string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

// NewJWTService creates a new JWTService instance.
func NewJWTService(secret string, accessExpiry, refreshExpiry time.Duration) JWTService {
	return &jwtService{
		secret:        secret,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
	}
}

func (s *jwtService) GenerateAccessToken(userID int64, username string) (string, error) {
	return s.generateToken(userID, username, s.accessExpiry)
}

func (s *jwtService) GenerateRefreshToken(userID int64, username string) (string, error) {
	return s.generateToken(userID, username, s.refreshExpiry)
}

func (s *jwtService) generateToken(userID int64, username string, expiry time.Duration) (string, error) {
	claims := Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.secret))
}

func (s *jwtService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(s.secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
