package service

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testSecret        = "test-secret-key-at-least-32-chars-long"
	testAccessExpiry  = 15 * time.Minute
	testRefreshExpiry = 168 * time.Hour
)

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewJWTService(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)
	if service == nil {
		t.Fatal("NewJWTService returned nil")
	}

	if got := service.GetAccessExpiry(); got != testAccessExpiry {
		t.Errorf("GetAccessExpiry() = %v, want %v", got, testAccessExpiry)
	}

	if got := service.GetRefreshExpiry(); got != testRefreshExpiry {
		t.Errorf("GetRefreshExpiry() = %v, want %v", got, testRefreshExpiry)
	}
}

func TestNewJWTService_EmptySecret(t *testing.T) {
	service := NewJWTService("", testAccessExpiry, testRefreshExpiry)

	if service != nil {
		t.Error("NewJWTService() should return nil for empty secret")
	}
}

func TestNewJWTService_ShortSecret(t *testing.T) {
	service := NewJWTService("short", testAccessExpiry, testRefreshExpiry)

	if service != nil {
		t.Error("NewJWTService() should return nil for secret less than 32 bytes")
	}
}

func TestServiceInterfaceCompliance(t *testing.T) {
	// Verify that jwtService implements JWTService interface
	var _ = NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)
}

// =============================================================================
// GenerateAccessToken Tests
// =============================================================================

func TestGenerateAccessToken(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	tests := []struct {
		name     string
		userID   int64
		username string
		wantErr  bool
	}{
		{
			name:     "valid user",
			userID:   1,
			username: "testuser",
			wantErr:  false,
		},
		{
			name:     "valid user with long username",
			userID:   999,
			username: "very_long_username_with_special_chars_123",
			wantErr:  false,
		},
		{
			name:     "zero user ID",
			userID:   0,
			username: "testuser",
			wantErr:  false,
		},
		{
			name:     "empty username",
			userID:   1,
			username: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := service.GenerateAccessToken(tt.userID, tt.username)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateAccessToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if token == "" {
					t.Error("Generated token is empty")
				}

				// Verify token can be validated
				claims, err := service.ValidateToken(token)
				if err != nil {
					t.Fatalf("ValidateToken() error = %v", err)
				}
				if claims.UserID != tt.userID {
					t.Errorf("Claims.UserID = %v, want %v", claims.UserID, tt.userID)
				}
				if claims.Username != tt.username {
					t.Errorf("Claims.Username = %v, want %v", claims.Username, tt.username)
				}
			}
		})
	}
}

func TestGenerateAccessToken_NegativeUserID(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	token, err := service.GenerateAccessToken(-1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if claims.UserID != -1 {
		t.Errorf("Claims.UserID = %v, want -1", claims.UserID)
	}
}

func TestGenerateAccessToken_VeryLargeUserID(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	largeID := int64(9223372036854775807) // Max int64

	token, err := service.GenerateAccessToken(largeID, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if claims.UserID != largeID {
		t.Errorf("Claims.UserID = %v, want %v", claims.UserID, largeID)
	}
}

func TestGenerateAccessToken_SpecialCharactersInUsername(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	tests := []struct {
		name     string
		username string
	}{
		{
			name:     "unicode characters",
			username: "用户名_123",
		},
		{
			name:     "special symbols",
			username: "user@example.com",
		},
		{
			name:     "spaces and punctuation",
			username: "John Doe Jr.",
		},
		{
			name:     "quotes",
			username: `user"with'quotes`,
		},
		{
			name:     "newlines and tabs",
			username: "user\nwith\ttabs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := service.GenerateAccessToken(1, tt.username)
			if err != nil {
				t.Fatalf("GenerateAccessToken() error = %v", err)
			}

			claims, err := service.ValidateToken(token)
			if err != nil {
				t.Fatalf("ValidateToken() error = %v", err)
			}

			if claims.Username != tt.username {
				t.Errorf("Claims.Username = %v, want %v", claims.Username, tt.username)
			}
		})
	}
}

func TestGenerateAccessToken_TokensAreDifferent(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	// Generate multiple tokens for same user
	token1, err := service.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Sleep to ensure different IssuedAt timestamp (JWT timestamps are in seconds)
	time.Sleep(1001 * time.Millisecond)

	token2, err := service.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Tokens should be different due to different IssuedAt times
	if token1 == token2 {
		t.Error("Sequential tokens for same user should be different")
	}

	// But both should be valid
	claims1, err := service.ValidateToken(token1)
	if err != nil {
		t.Fatalf("ValidateToken(token1) error = %v", err)
	}
	if claims1.UserID != 1 {
		t.Errorf("Claims1.UserID = %v, want 1", claims1.UserID)
	}

	claims2, err := service.ValidateToken(token2)
	if err != nil {
		t.Fatalf("ValidateToken(token2) error = %v", err)
	}
	if claims2.UserID != 1 {
		t.Errorf("Claims2.UserID = %v, want 1", claims2.UserID)
	}
}

func TestGenerateAccessToken_ClaimsStructure(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	userID := int64(42)
	username := "testuser"
	beforeGeneration := time.Now()

	token, err := service.GenerateAccessToken(userID, username)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	afterGeneration := time.Now()

	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	// Verify custom claims
	if claims.UserID != userID {
		t.Errorf("Claims.UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.Username != username {
		t.Errorf("Claims.Username = %v, want %v", claims.Username, username)
	}

	// Verify registered claims
	if claims.ExpiresAt == nil {
		t.Error("Claims.ExpiresAt is nil")
	}
	if claims.IssuedAt == nil {
		t.Error("Claims.IssuedAt is nil")
	}

	// IssuedAt should be between before and after generation
	issuedAt := claims.IssuedAt.Time
	if issuedAt.Before(beforeGeneration.Add(-time.Second)) || issuedAt.After(afterGeneration.Add(time.Second)) {
		t.Errorf("IssuedAt %v not within expected range [%v, %v]", issuedAt, beforeGeneration, afterGeneration)
	}

	// ExpiresAt should be IssuedAt + expiry
	expectedExpiry := issuedAt.Add(testAccessExpiry)
	expiresAt := claims.ExpiresAt.Time
	diff := expiresAt.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("ExpiresAt difference = %v, want within 1 second", diff)
	}
}

func TestGenerateAccessToken_SigningMethod(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	// Generate valid token
	validToken, err := service.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Parse and verify it uses HMAC
	token, err := jwt.ParseWithClaims(validToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Errorf("Token uses %v, want *jwt.SigningMethodHMAC", token.Method)
		}
		return []byte(testSecret), nil
	})

	if err != nil {
		t.Fatalf("ParseWithClaims() error = %v", err)
	}
	if !token.Valid {
		t.Error("Token should be valid")
	}
}

// =============================================================================
// GenerateRefreshToken Tests
// =============================================================================

func TestGenerateRefreshToken(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	userID := int64(123)
	username := "testuser"

	token, err := service.GenerateRefreshToken(userID, username)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}
	if token == "" {
		t.Fatal("Generated refresh token is empty")
	}

	// Verify token contains correct claims
	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("Claims.UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.Username != username {
		t.Errorf("Claims.Username = %v, want %v", claims.Username, username)
	}
}

// =============================================================================
// ValidateToken Tests
// =============================================================================

func TestValidateToken_ValidToken(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	userID := int64(1)
	username := "testuser"

	token, err := service.GenerateAccessToken(userID, username)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}
	if claims == nil {
		t.Fatal("ValidateToken() returned nil claims")
	}

	if claims.UserID != userID {
		t.Errorf("Claims.UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.Username != username {
		t.Errorf("Claims.Username = %v, want %v", claims.Username, username)
	}
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	// Create service with very short expiry
	shortExpiry := 1 * time.Millisecond
	service := NewJWTService(testSecret, shortExpiry, testRefreshExpiry)

	token, err := service.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	_, err = service.ValidateToken(token)
	if err == nil {
		t.Error("ValidateToken() should fail for expired token")
	}
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	service1 := NewJWTService("secret1-at-least-32-chars-long-11111", testAccessExpiry, testRefreshExpiry)
	service2 := NewJWTService("secret2-at-least-32-chars-long-22222", testAccessExpiry, testRefreshExpiry)

	// Generate token with service1
	token, err := service1.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Try to validate with service2 (different secret)
	_, err = service2.ValidateToken(token)
	if err == nil {
		t.Error("ValidateToken() should fail for token signed with different secret")
	}
}

func TestValidateToken_MalformedToken(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "empty token",
			token: "",
		},
		{
			name:  "random string",
			token: "not-a-jwt-token",
		},
		{
			name:  "incomplete token",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			name:  "token with invalid parts",
			token: "header.payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.ValidateToken(tt.token)
			if err == nil {
				t.Error("ValidateToken() should fail for malformed token")
			}
		})
	}
}

func TestValidateToken_TamperedToken(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	token, err := service.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Tamper with the token by changing a character
	tamperedToken := token[:len(token)-5] + "XXXXX"

	_, err = service.ValidateToken(tamperedToken)
	if err == nil {
		t.Error("ValidateToken() should fail for tampered token")
	}
}

func TestValidateToken_WrongSigningMethod(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	// Create a token header claiming RS256 (RSA) instead of HS256 (HMAC)
	// This JWT has a valid structure with RS256 in the header, which will trigger
	// the signing method validation in ValidateToken
	// #nosec G101 - This is a test token, not actual credentials
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6InRlc3R1c2VyIiwiZXhwIjoxNzAwMDAwMDAwfQ.invalid_signature"

	_, err := service.ValidateToken(tokenString)
	if err == nil {
		t.Error("ValidateToken() should fail for token with wrong signing method")
	}
}

func TestValidateToken_InvalidClaimsStructure(t *testing.T) {
	// Create a service to sign tokens
	service1 := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	// Generate a valid token
	validToken, err := service1.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Parse the token to get its parts
	parts := strings.Split(validToken, ".")
	if len(parts) != 3 {
		t.Fatalf("Expected 3 parts in JWT, got %d", len(parts))
	}

	// Create a token with corrupted payload but valid signature structure
	// This represents a token where ParseWithClaims succeeds but claims assertion fails
	corruptedPayload := "eyJpbnZhbGlkIjoiY2xhaW1zIn0" // {"invalid":"claims"}
	corruptedToken := parts[0] + "." + corruptedPayload + "." + parts[2]

	_, err = service1.ValidateToken(corruptedToken)
	if err == nil {
		t.Error("ValidateToken() should fail for token with invalid claims structure")
	}
}

func TestValidateToken_ExpiryBoundary(t *testing.T) {
	// Test token validation exactly at expiry boundary
	// JWT timestamps are truncated to seconds, so use multi-second expiry
	shortExpiry := 3 * time.Second
	service := NewJWTService(testSecret, shortExpiry, testRefreshExpiry)

	token, err := service.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Should be valid immediately
	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}
	if claims == nil {
		t.Fatal("Claims should not be nil")
	}

	// Wait 1 second - should still be valid
	time.Sleep(1 * time.Second)

	// Should still be valid
	claims, err = service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}
	if claims == nil {
		t.Fatal("Claims should not be nil")
	}

	// Wait past expiry (3+ seconds total)
	time.Sleep(2500 * time.Millisecond)

	// Should now be invalid
	_, err = service.ValidateToken(token)
	if err == nil {
		t.Error("ValidateToken() should fail for expired token")
	}
}

func TestValidateToken_RemainingTime(t *testing.T) {
	service := NewJWTService(testSecret, 10*time.Second, testRefreshExpiry)

	token, err := service.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Validate immediately and check remaining time
	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	remaining := time.Until(claims.ExpiresAt.Time)

	// Should be close to 10 seconds (within 1 second tolerance)
	if remaining < 9*time.Second || remaining > 11*time.Second {
		t.Errorf("Remaining time = %v, want ~10s", remaining)
	}

	// Wait 2 seconds
	time.Sleep(2 * time.Second)

	// Check remaining time again
	claims, err = service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	remaining = time.Until(claims.ExpiresAt.Time)

	// Should be close to 8 seconds (within 1 second tolerance)
	if remaining < 7*time.Second || remaining > 9*time.Second {
		t.Errorf("Remaining time = %v, want ~8s", remaining)
	}
}

// =============================================================================
// Expiry Tests
// =============================================================================

func TestGetExpiryMethods(t *testing.T) {
	customAccess := 30 * time.Minute
	customRefresh := 720 * time.Hour

	service := NewJWTService(testSecret, customAccess, customRefresh)

	if got := service.GetAccessExpiry(); got != customAccess {
		t.Errorf("GetAccessExpiry() = %v, want %v", got, customAccess)
	}
	if got := service.GetRefreshExpiry(); got != customRefresh {
		t.Errorf("GetRefreshExpiry() = %v, want %v", got, customRefresh)
	}
}

func TestAccessTokenExpiry(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	token, err := service.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	// Calculate expected expiry
	expectedExpiry := claims.IssuedAt.Add(testAccessExpiry)
	actualExpiry := claims.ExpiresAt.Time

	// Should be within 1 second due to timing
	diff := actualExpiry.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("Expiry difference = %v, want within 1 second", diff)
	}
}

func TestRefreshTokenExpiry(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	token, err := service.GenerateRefreshToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}

	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	// Calculate expected expiry
	expectedExpiry := claims.IssuedAt.Add(testRefreshExpiry)
	actualExpiry := claims.ExpiresAt.Time

	// Should be within 1 second due to timing
	diff := actualExpiry.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("Expiry difference = %v, want within 1 second", diff)
	}

	// Refresh token should expire much later than access token
	accessToken, err := service.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	accessClaims, err := service.ValidateToken(accessToken)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if !claims.ExpiresAt.After(accessClaims.ExpiresAt.Time) {
		t.Error("Refresh token should expire after access token")
	}
}

func TestVeryShortExpiry(t *testing.T) {
	service := NewJWTService(testSecret, 1*time.Nanosecond, testRefreshExpiry)

	token, err := service.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	// Token should be expired almost immediately due to JWT second precision
	time.Sleep(100 * time.Millisecond)

	_, err = service.ValidateToken(token)
	if err == nil {
		t.Error("ValidateToken() should fail for token with nanosecond expiry")
	}
}

func TestVeryLongExpiry(t *testing.T) {
	longExpiry := 8760 * time.Hour // 1 year
	service := NewJWTService(testSecret, longExpiry, testRefreshExpiry)

	token, err := service.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	// Verify expiry is approximately 1 year from now
	expectedExpiry := claims.IssuedAt.Add(longExpiry)
	diff := claims.ExpiresAt.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("Expiry difference = %v, want within 1 second", diff)
	}
}

// =============================================================================
// Concurrency Tests
// =============================================================================

func TestConcurrentTokenGeneration(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	concurrency := 10
	done := make(chan bool, concurrency)
	tokens := make(chan string, concurrency)

	// Generate tokens concurrently
	for i := range concurrency {
		go func(userID int64) {
			token, err := service.GenerateAccessToken(userID, "testuser")
			if err != nil {
				t.Errorf("GenerateAccessToken() error = %v", err)
			}
			tokens <- token
			done <- true
		}(int64(i + 1))
	}

	// Wait for all goroutines
	for range concurrency {
		<-done
	}
	close(tokens)

	// Verify all tokens are valid and unique
	seen := make(map[string]bool)
	count := 0
	for token := range tokens {
		if token == "" {
			t.Error("Generated token is empty")
			continue
		}

		if seen[token] {
			t.Errorf("Duplicate token generated: %s", token)
		}
		seen[token] = true

		claims, err := service.ValidateToken(token)
		if err != nil {
			t.Errorf("ValidateToken() error = %v", err)
		}
		if claims == nil {
			t.Error("Claims should not be nil")
		}
		count++
	}

	if count != concurrency {
		t.Errorf("Expected %d tokens, got %d", concurrency, count)
	}
}

func TestConcurrentTokenValidation(t *testing.T) {
	service := NewJWTService(testSecret, testAccessExpiry, testRefreshExpiry)

	// Generate a single token
	token, err := service.GenerateAccessToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	concurrency := 20
	done := make(chan bool, concurrency)
	errors := make(chan error, concurrency)

	// Validate token concurrently
	for range concurrency {
		go func() {
			claims, err := service.ValidateToken(token)
			if err != nil {
				errors <- err
			} else if claims == nil {
				errors <- jwt.ErrTokenInvalidClaims
			} else if claims.UserID != 1 {
				errors <- jwt.ErrTokenInvalidClaims
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for range concurrency {
		<-done
	}
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent validation error: %v", err)
	}
}
