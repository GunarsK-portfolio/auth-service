# Testing Guide

## Overview

The auth-service uses Go's standard `testing` package for unit tests.
This is a JWT authentication service that handles user login, token refresh,
logout, and session management via Redis.

Current coverage: 74% on service, 100% on handlers, 97% on middleware

## Quick Commands

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run service tests only
go test -v ./internal/service/

# Run handler tests only
go test -v ./internal/handlers/

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Run specific test
go test -v -run TestLogin_Success ./internal/service/

# Run all Login tests
go test -v -run TestLogin ./internal/service/
```

## Test Files

**`internal/service/auth_test.go`** - 23 tests

| Category | Tests | Coverage |
| -------- | ----- | -------- |
| Constructor | 2 | Service initialization, interface compliance |
| Login | 7 | Success, user not found, wrong password, empty credentials, Redis/context errors |
| Logout | 4 | Success, invalid/expired token, Redis failure |
| Refresh Token | 6 | Success, invalid/expired token, not in Redis, mismatch, Redis failure |
| Validate Token | 4 | Valid token, invalid token, expired token, almost-expired |
| Concurrency | 2 | Concurrent logins, concurrent refresh |

**`internal/handlers/auth_test.go`** - 25 tests

| Category | Tests | Coverage |
| -------- | ----- | -------- |
| Login | 5 | Success with cookies, invalid credentials, missing username/password, invalid JSON |
| Logout | 4 | Success (cookie), success (header), no token, service error |
| Refresh | 3 | Success with new cookies, no token, invalid token |
| Validate | 3 | Success with claims, invalid token, missing token |
| TokenStatus | 5 | Success (cookie), success (header), no token, invalid token, expired token |
| extractToken | 4 | Valid bearer, no header, invalid format, multiple spaces |
| Constructor | 1 | NewAuthHandler initialization |
| Cookie Priority | 2 | Cookie preferred over header for logout/token-status |

**`internal/handlers/cookie_test.go`** - 5 tests

| Category | Tests | Coverage |
| -------- | ----- | -------- |
| SetAuthCookies | 2 | Dev/prod config, HttpOnly, Secure, SameSite, Path, Domain |
| ClearAuthCookies | 1 | Cookie expiration (MaxAge=-1) |
| GetAccessToken | 1 | Extract access_token from cookie |
| GetRefreshToken | 1 | Extract refresh_token from cookie |
| Missing Cookie | 1 | Returns empty string for missing cookie |

**`internal/middleware/csrf_test.go`** - 18 tests

| Category | Tests | Coverage |
| -------- | ----- | -------- |
| Safe Methods | 3 | GET, HEAD, OPTIONS pass without validation |
| Valid Origin | 3 | Valid origin, trailing slash, case insensitive |
| Invalid Origin | 2 | Invalid origin blocked, wrong port blocked |
| Referer Fallback | 2 | Valid referer passes, invalid referer blocked |
| Missing Headers | 1 | No origin or referer blocked (CSRF protection) |
| State-Changing | 3 | PUT, DELETE, PATCH validated |
| Helper Functions | 4 | extractOrigin URL parsing |

Tests are organized in: `auth_test.go` (service), `auth_test.go` (handlers),
`cookie_test.go`, `csrf_test.go`.

**Note**: JWT tests are in portfolio-common. See `portfolio-common/TESTING.md`.

## Key Testing Patterns

**Mock Repository**: Function fields allow per-test behavior customization

```go
mockRepo := &mockUserRepository{
    findByUsernameFunc: func(
        ctx context.Context, username string,
    ) (*models.User, error) {
        return &models.User{
            ID:           1,
            Username:     "testuser",
            PasswordHash: hashedPassword,
        }, nil
    },
}
```

**Mock Redis**: Uses miniredis for in-memory Redis simulation

```go
func setupTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
    mr, err := miniredis.Run()
    if err != nil {
        t.Fatalf("Failed to create miniredis: %v", err)
    }
    client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
    return client, mr
}
```

**Cookie Testing**: Uses httptest.NewRecorder and gin.CreateTestContext

```go
w := httptest.NewRecorder()
c, _ := gin.CreateTestContext(w)
c.Request = httptest.NewRequest("GET", "/", nil)
c.Request.AddCookie(&http.Cookie{Name: "access_token", Value: "test"})

helper := NewCookieHelper(config)
token := helper.GetAccessToken(c)
```

**Test Helpers**: Factory functions for consistent test data

```go
service, mr, mockRepo := setupTestAuthService(t)
defer mr.Close()

passwordHash := hashPassword(t, "testpassword")
```

## Test Categories

### Success Cases

- Full login flow with token generation and Redis storage
- Logout with token removal from Redis
- Token refresh with rotation (old token invalidated)
- Token validation with TTL calculation

### Error Cases

- User not found in database
- Wrong password (bcrypt mismatch)
- Empty username or password
- Invalid/malformed JWT tokens
- Expired tokens (access and refresh)
- Token not stored in Redis
- Token mismatch (different token in Redis)
- Redis unavailable
- Context cancellation

### Edge Cases

- Concurrent login attempts (thread safety)
- Concurrent refresh with same token (race conditions)
- Almost-expired tokens (boundary TTL)
- Cookie extraction from missing cookies

## Service Characteristics

The auth-service is an HTTP API (not a worker):

- **Input**: HTTP requests with credentials or cookies
- **Processing**: Validate credentials → Generate JWT → Store in Redis → Set cookies
- **Output**: HTTP response with auth cookies

### Authentication Flow

1. **Login**: Validate credentials → Generate tokens → Store in Redis → Set cookies
2. **Refresh**: Validate cookie → Check Redis → Rotate tokens → Set cookies
3. **Logout**: Parse token → Delete from Redis → Clear cookies
4. **Validate**: Parse token → Verify signature → Return TTL

### Token Management

- Access tokens: Short-lived (15m default), httpOnly cookie
- Refresh tokens: Long-lived (7d default), stored in Redis
- Token rotation: Refresh generates new pair, invalidates old

## Contributing Tests

1. Follow naming: `Test<FunctionName>_<Scenario>`
2. Use section markers for organization
3. Mock only the repository/Redis methods needed for each test
4. Verify coverage: `go test -cover ./...`
5. Run CI: `task ci:all`
