# Testing Guide

## Overview

The auth-service uses Go's standard `testing` package for unit tests.
**Current coverage: 87.1% overall**

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
go test -v -run TestLogin_Success ./internal/service/

# Run all Login tests
go test -v -run TestLogin ./internal/service/
```

## Test Files

**`jwt_test.go`** - 28 tests
- Constructor validation (3)
- Token generation (8)
- Token validation (9)
- Expiry handling (5)
- Concurrency (2)
- Security testing (signatures, tampering, algorithm confusion)

**`auth_test.go`** - 31 tests
- Login flow (7)
- Logout flow (4)
- Token refresh (6)
- Token validation (4)
- Concurrency (2)
- Redis integration with miniredis
- Mock UserRepository pattern

## Key Testing Patterns

**JWT Timestamp Precision**: JWT uses second precision, not milliseconds.
Tests use multi-second delays (1001ms) to ensure different timestamps.

**Table-driven tests**: Multiple scenarios with `tests := []struct{...}`

**Mocking**: Manual mocks for repositories, miniredis for Redis

**Concurrency**: Goroutines + channels for thread-safety verification

## Test Constants

```go
testSecret        = "test-secret-key-at-least-32-chars-long"
testAccessExpiry  = 15 * time.Minute
testRefreshExpiry = 168 * time.Hour  // 7 days
```

## Contributing Tests

1. Follow naming: `Test<FunctionName>_<Scenario>`
2. Organize by function with section markers
3. Use table-driven tests for multiple scenarios
4. Account for JWT second precision in timing tests
5. Clean up resources with `defer` or `t.Cleanup()`
6. Verify: `go test -cover ./internal/service/`
