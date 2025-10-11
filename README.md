# Auth Service

JWT-based authentication service with refresh token support.

## Features

- User registration and login
- JWT access and refresh tokens
- Token refresh endpoint
- Redis-based session management
- Password hashing with bcrypt
- RESTful API with Swagger documentation

## Tech Stack

- **Language**: Go 1.25
- **Framework**: Gin
- **Database**: PostgreSQL (GORM)
- **Cache**: Redis
- **Documentation**: Swagger/OpenAPI

## Prerequisites

- Go 1.25+
- PostgreSQL (or use Docker Compose)
- Redis (or use Docker Compose)

## Project Structure

```
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

2. Update `.env` with your configuration:
```env
PORT=8084
DB_HOST=localhost
DB_PORT=5432
DB_USER=portfolio_user
DB_PASSWORD=portfolio_pass
DB_NAME=portfolio
REDIS_HOST=localhost
REDIS_PORT=6379
JWT_SECRET=your-secret-key-change-in-production
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h
```

3. Start infrastructure (if not running):
```bash
# From infrastructure directory
docker-compose up -d postgres redis flyway
```

4. Run the service:
```bash
task run
# or
go run cmd/api/main.go
```

## Available Commands

Using Task:
```bash
task run           # Run the service
task build         # Build binary
task test          # Run tests
task swagger       # Generate Swagger docs
task clean         # Clean build artifacts
task docker-build  # Build Docker image
task docker-run    # Run with docker-compose
task docker-logs   # View logs
```

Using Go directly:
```bash
go run cmd/api/main.go       # Run
go build -o bin/auth cmd/api/main.go  # Build
go test ./...                # Test
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
| `REDIS_HOST` | Redis host | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `JWT_SECRET` | JWT signing secret | **required** |
| `JWT_ACCESS_EXPIRY` | Access token expiry | `15m` |
| `JWT_REFRESH_EXPIRY` | Refresh token expiry | `168h` |

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

This service is used by the admin-api for authentication. Protected endpoints in admin-api validate JWT tokens issued by this service.

## License

MIT
