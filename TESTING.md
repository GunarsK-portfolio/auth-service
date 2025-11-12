# Testing Guide

## Overview

The auth-service uses Go's standard `testing` package for unit tests.
Current coverage: **25% overall** (90%+ for JWT service, 0% for auth
service with database dependencies).

## Quick Commands

```bash
# Run all tests
go test ./internal/service/

# Run with coverage
go test -cover ./internal/service/

# Generate coverage report
go test -coverprofile=coverage.out ./internal/service/
go tool cover -html=coverage.out -o coverage.html

# Run specific test
go test -v -run TestValidateToken_ExpiredToken ./internal/service/

# Run all ValidateToken tests
go test -v -run TestValidateToken ./internal/service/
```

## Test Organization

Tests are organized by function with clear section markers in
`jwt_test.go` (818 lines, 27 tests).

### Constructor Tests (3 tests)

| Test | Description |
|------|-------------|
| `TestNewJWTService` | Basic constructor and expiry getters |
| `TestNewJWTService_EmptySecret` | Empty secret edge case (insecure) |
| `TestServiceInterfaceCompliance` | Verify interface |

### GenerateAccessToken Tests (7 tests)

| Test | Description |
|------|-------------|
| `TestGenerateAccessToken` | Table-driven: valid, zero ID, empty user |
| `TestGenerateAccessToken_NegativeUserID` | Negative user ID (-1) |
| `TestGenerateAccessToken_VeryLargeUserID` | Max int64 |
| `TestGenerateAccessToken_SpecialCharacters...` | Unicode, quotes, tabs |
| `TestGenerateAccessToken_TokensAreDifferent` | Unique IssuedAt |
| `TestGenerateAccessToken_ClaimsStructure` | Verify claims |
| `TestGenerateAccessToken_SigningMethod` | Verify HS256 |

### GenerateRefreshToken Tests (1 test)

| Test | Description |
|------|-------------|
| `TestGenerateRefreshToken` | Basic refresh token generation and claims |

### ValidateToken Tests (9 tests)

| Test | Description |
|------|-------------|
| `TestValidateToken_ValidToken` | Happy path |
| `TestValidateToken_ExpiredToken` | Expired token |
| `TestValidateToken_InvalidSignature` | Different secret |
| `TestValidateToken_MalformedToken` | Empty, incomplete, invalid |
| `TestValidateToken_TamperedToken` | Modified signature |
| `TestValidateToken_WrongSigningMethod` | RS256 rejected |
| `TestValidateToken_InvalidClaimsStructure` | Corrupted payload |
| `TestValidateToken_ExpiryBoundary` | Expiry boundaries |
| `TestValidateToken_RemainingTime` | TTL accuracy |

### Expiry Tests (5 tests)

| Test | Description |
|------|-------------|
| `TestGetExpiryMethods` | Expiry getters |
| `TestAccessTokenExpiry` | Access expiry accuracy |
| `TestRefreshTokenExpiry` | Refresh expiry comparison |
| `TestVeryShortExpiry` | 1ns expiry (JWT precision) |
| `TestVeryLongExpiry` | 1 year expiry |

### Concurrency Tests (2 tests)

| Test | Description |
|------|-------------|
| `TestConcurrentTokenGeneration` | 10 concurrent generations |
| `TestConcurrentTokenValidation` | 20 concurrent validations |

## Important Notes

### JWT Timestamp Precision

JWT timestamps use **second precision**, not milliseconds.
When generating a token at `13:14:31.937...` with 500ms expiry:

- `IssuedAt` becomes `13:14:31`
- `ExpiresAt` becomes `13:14:32`
- Actual validity: ~63ms (not 500ms)

**Tests use multi-second expiries** to account for this truncation.

### Test Constants

```go
testSecret        = "test-secret-key-at-least-32-chars-long"
testAccessExpiry  = 15 * time.Minute
testRefreshExpiry = 168 * time.Hour  // 7 days
```

### Edge Cases Covered

**User IDs**: Negative (-1), zero (0), max int64
**Usernames**: Empty, unicode, emails, quotes, newlines, tabs
**Expiry**: 1 nanosecond, 1 year, boundary testing
**Security**: Empty secret, invalid signatures, tampered tokens,
wrong signing method, malformed tokens

### Unreachable Code

Line 79 in `jwt.go` (`return nil, errors.New("invalid token")`)
may be unreachable because the JWT library returns errors during
parsing rather than allowing invalid tokens through.

## Coverage Files

Generated files (gitignored):

- `coverage.out` - Raw coverage data
- `coverage.html` - HTML coverage report
- `coverage.txt` - Alternative format

## Contributing Tests

When adding new functionality:

1. Follow naming convention: `Test<FunctionName>_<Scenario>`
2. Add tests to appropriate section in `jwt_test.go`
3. Use table-driven tests for multiple similar scenarios
4. Account for JWT second precision in timing tests
5. Verify: `go test -cover ./internal/service/`

## Test Patterns

**Table-driven**: Multiple scenarios with `tests := []struct{...}`
and `t.Run()`

**Timing tests**: Use 1+ second delays for JWT timestamp precision

**Concurrency**: Use goroutines + channels to verify thread-safety
