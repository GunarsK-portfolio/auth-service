# Auth Service

![CI](https://github.com/GunarsK-portfolio/auth-service/workflows/CI/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/GunarsK-portfolio/auth-service)](https://goreportcard.com/report/github.com/GunarsK-portfolio/auth-service)
[![codecov](https://codecov.io/gh/GunarsK-portfolio/auth-service/graph/badge.svg?token=2AMRCW3LB7)](https://codecov.io/gh/GunarsK-portfolio/auth-service)
[![CodeRabbit](https://img.shields.io/coderabbit/prs/github/GunarsK-portfolio/auth-service?label=CodeRabbit&color=2ea44f)](https://coderabbit.ai)

JWT-based authentication service with refresh token support.

## Features

- User registration and login
- JWT access and refresh tokens
- Token refresh endpoint
- Redis-based session management
- Password hashing with bcrypt
- RESTful API with Swagger documentation

## Tech Stack

- **Language**: Go 1.25.3
- **Framework**: Gin
- **Database**: PostgreSQL (GORM)
- **Cache**: Redis
- **Documentation**: Swagger/OpenAPI

## Prerequisites

- Go 1.25+
- Node.js 22+ and npm 11+
- PostgreSQL (or use Docker Compose)
- Redis (or use Docker Compose)

## Project Structure

```text
auth-service/
├── cmd/
│   └── api/              # Application entrypoint
├── internal/
│   ├── config/           # Configuration
│   ├── database/         # Database connection
│   ├── handlers/         # HTTP handlers
│   ├── middleware/       # HTTP middleware
│   ├── models/           # Data models
│   ├── repository/       # Data access layer
│   └── service/          # Business logic
├── pkg/
│   └── redis/            # Redis utilities
└── docs/                 # Swagger documentation
```

## Quick Start

### Using Docker Compose

```bash
docker-compose up -d
```

### Local Development

1. Copy environment file:

```bash
cp .env.example .env
```

1. Update `.env` with your configuration:

```env
PORT=8084
DB_HOST=localhost
DB_PORT=5432
DB_USER=portfolio_user
DB_PASSWORD=portfolio_pass
DB_NAME=portfolio
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
ENVIRONMENT=development
JWT_SECRET=your-secret-key-change-in-production
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h
```

1. Start infrastructure (if not running):

```bash
# From infrastructure directory
docker-compose up -d postgres redis flyway
```

1. Run the service:

```bash
go run cmd/api/main.go
```

## Available Commands

Using Task:

```bash
# Development
task dev:swagger         # Generate Swagger documentation
task dev:install-tools   # Install dev tools (golangci-lint, govulncheck, etc.)

# Build and run
task build               # Build binary
task test                # Run tests
task test:coverage       # Run tests with coverage report
task clean               # Clean build artifacts

# Code quality
task format              # Format code with gofmt
task tidy                # Tidy and verify go.mod
task lint                # Run golangci-lint
task vet                 # Run go vet

# Security
task security:scan       # Run gosec security scanner
task security:vuln       # Check for vulnerabilities with govulncheck

# Docker
task docker:build        # Build Docker image
task docker:run          # Run service in Docker container
task docker:stop         # Stop running Docker container
task docker:logs         # View Docker container logs

# CI/CD
task ci:all              # Run all CI checks
                         # test, vuln)
```

Using Go directly:

```bash
go run cmd/api/main.go                   # Run
go build -o bin/auth cmd/api/main.go     # Build
go test ./...                             # Test
```

## API Endpoints

Base URL: `http://localhost:8084/api/v1/auth`

### Health Check

- `GET /health` - Service health status

### Authentication

- `POST /register` - Register new user
- `POST /login` - Login and receive tokens
- `POST /refresh` - Refresh access token
- `POST /logout` - Logout and invalidate tokens

### Example: Register

```bash
curl -X POST http://localhost:8084/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword"
  }'
```

### Example: Login

```bash
curl -X POST http://localhost:8084/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword"
  }'
```

Response:

```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "expires_in": 900
}
```

## Swagger Documentation

When running, Swagger UI is available at:

- `http://localhost:8084/swagger/index.html`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8084` |
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_USER` | Database user | `portfolio_user` |
| `DB_PASSWORD` | Database password | `portfolio_pass` |
| `DB_NAME` | Database name | `portfolio` |
| `DB_SSLMODE` | PostgreSQL SSL mode | `disable` |
| `REDIS_HOST` | Redis host | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `REDIS_PASSWORD` | Redis password (optional) | `""` (empty) |
| `ENVIRONMENT` | Environment type | `development` |
| `JWT_SECRET` | JWT signing secret | **required** |
| `JWT_ACCESS_EXPIRY` | Access token expiry | `15m` |
| `JWT_REFRESH_EXPIRY` | Refresh token expiry | `168h` |

**Note:** `ENVIRONMENT` accepts: `development`, `staging`, `production`

## Security

### Redis TLS

- **Production**: TLS encryption is **enabled** for Redis connections when
  `ENVIRONMENT=production`
- **Development/Staging**: TLS is **disabled** for local Redis connections

**Important**: Production Redis servers must support TLS when
`ENVIRONMENT=production`.

## Development

### Running Tests

```bash
task test
# or
go test ./...
```

### Generating Swagger Docs

```bash
task swagger
# or
swag init -g cmd/api/main.go -o docs
```

### Building

```bash
task build
# or
go build -o bin/auth cmd/api/main.go
```

## Integration

This service is used by the admin-api for authentication. Protected
endpoints in admin-api validate JWT tokens issued by this service.

## License

[MIT](LICENSE)
