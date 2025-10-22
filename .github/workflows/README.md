# GitHub Actions CI/CD

## Workflows

### CI Pipeline (`ci.yml`)

Comprehensive continuous integration pipeline that runs on:
- Pull requests to `main` or `develop`
- Pushes to `main` or `develop`
- Manual workflow dispatch

**Jobs:**

1. **Lint** - Code quality checks with golangci-lint
2. **Test** - Unit tests with race detection and coverage reporting
3. **Vulnerability Scan** - Dependency security scanning with govulncheck
4. **Docker Build & Scan** - Build image and scan with Trivy for vulnerabilities
5. **Security Analysis** - Static security analysis with gosec
6. **Code Quality** - Format checks, go vet, and ineffassign detection

**Security Features:**
- Results uploaded to GitHub Security tab (SARIF format)
- Fails on CRITICAL/HIGH vulnerabilities
- Codecov integration for coverage tracking

## Status Badges

Add these to your README.md:

```markdown
![CI](https://github.com/GunarsK-portfolio/auth-service/workflows/CI/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/GunarsK-portfolio/auth-service)](https://goreportcard.com/report/github.com/GunarsK-portfolio/auth-service)
[![codecov](https://codecov.io/gh/GunarsK-portfolio/auth-service/branch/main/graph/badge.svg)](https://codecov.io/gh/GunarsK-portfolio/auth-service)
```

## Local Testing

Run the same checks locally before pushing:

```bash
# Install tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Run linter
golangci-lint run

# Run tests with coverage
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Check for vulnerabilities
govulncheck ./...

# Security scan
gosec ./...

# Check formatting
gofmt -l .
go vet ./...
go mod tidy
```

## Configuration Files

- `.golangci.yml` - golangci-lint configuration
- `.dockerignore` - Files excluded from Docker builds
