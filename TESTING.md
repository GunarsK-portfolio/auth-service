# Testing Guide

## Overview

The auth-service uses Go's standard `testing` package for unit tests.

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

**`auth_test.go`** - 31 tests

- Login flow (7)
- Logout flow (4)
- Token refresh (6)
- Token validation (4)
- Concurrency (2)
- Redis integration with miniredis
- Mock UserRepository pattern

**Note**: JWT tests are in portfolio-common. See `portfolio-common/TESTING.md`.

## Key Testing Patterns

**Table-driven tests**: Multiple scenarios with `tests := []struct{...}`

**Mocking**: Manual mocks for repositories, miniredis for Redis

**Concurrency**: Goroutines + channels for thread-safety verification

## Contributing Tests

1. Follow naming: `Test<FunctionName>_<Scenario>`
2. Organize by function with section markers
3. Use table-driven tests for multiple scenarios
4. Clean up resources with `defer` or `t.Cleanup()`
5. Verify: `go test -cover ./internal/service/`
