# Portfolio Auth Service

Authentication and authorization microservice for the portfolio system. Provides JWT-based authentication with Redis session management.

## Features

- JWT token-based authentication
- Access and refresh tokens
- Redis session storage
- Password hashing with bcrypt
- Swagger API documentation
- Docker support

## API Endpoints

### Health Check
- `GET /api/v1/health` - Service health check

### Authentication
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/validate` - Validate token

### API Documentation
- `GET /swagger/index.html` - Swagger UI

## Quick Start

### Prerequisites

- Go 1.25+
- PostgreSQL 18+
- Redis 7.4+
- [Task](https://taskfile.dev/installation/) (task runner)
- Docker (optional)

### Local Development (without Docker)

```bash
# Install dependencies
go mod download

# Copy environment file
cp .env.example .env

# Edit .env with your local settings
# (Defaults should work if you have postgres/redis running locally)

# Generate Swagger docs
task swagger

# Run the service
task run

# Or debug in VS Code (F5)
```

### Local Development (with Docker)

```bash
# Start all services (PostgreSQL, Redis, Auth Service)
docker-compose up -d

# View logs
docker-compose logs -f auth-service

# Stop services
docker-compose down
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | Service port | 8084 |
| DB_HOST | PostgreSQL host | localhost |
| DB_PORT | PostgreSQL port | 5432 |
| DB_USER | Database user | portfolio_user |
| DB_PASSWORD | Database password | portfolio_pass |
| DB_NAME | Database name | portfolio |
| REDIS_HOST | Redis host | localhost |
| REDIS_PORT | Redis port | 6379 |
| JWT_SECRET | JWT signing secret | your-secret-key-change-in-production |
| JWT_ACCESS_EXPIRY | Access token expiry | 15m |
| JWT_REFRESH_EXPIRY | Refresh token expiry | 168h (7 days) |

## Project Structure

```
auth-service/
├── cmd/
│   └── api/
│       └── main.go              # Application entry point
├── internal/
│   ├── config/
│   │   └── config.go            # Configuration loading
│   ├── database/
│   │   └── database.go          # Database connection
│   ├── handlers/
│   │   ├── auth.go              # Auth handlers
│   │   └── health.go            # Health check handler
│   ├── models/
│   │   └── user.go              # User model
│   ├── repository/
│   │   └── user.go              # User repository
│   ├── service/
│   │   ├── auth.go              # Auth business logic
│   │   └── jwt.go               # JWT service
│   └── middleware/
│       └── auth.go              # Auth middleware (future)
├── pkg/
│   └── redis/
│       └── client.go            # Redis client
├── docs/                        # Swagger documentation
├── Dockerfile
├── docker-compose.yml
├── Taskfile.yml
├── go.mod
└── README.md
```

## API Usage Examples

### Login

```bash
# Direct access (standalone)
curl -X POST http://localhost:8084/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'

# Via Traefik (infrastructure setup)
curl -X POST http://localhost:81/auth/v1/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 900
}
```

### Validate Token

```bash
# Direct access (standalone)
curl -X POST http://localhost:8084/api/v1/auth/validate \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIs..."
  }'

# Via Traefik (infrastructure setup)
curl -X POST http://localhost:81/auth/v1/validate \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIs..."
  }'
```

Response:
```json
{
  "valid": true
}
```

### Refresh Token

```bash
# Direct access (standalone)
curl -X POST http://localhost:8084/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
  }'

# Via Traefik (infrastructure setup)
curl -X POST http://localhost:81/auth/v1/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
  }'
```

### Logout

```bash
# Direct access (standalone)
curl -X POST http://localhost:8084/api/v1/auth/logout \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."

# Via Traefik (infrastructure setup)
curl -X POST http://localhost:81/auth/v1/logout \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

## Development

### Generate Swagger Documentation

```bash
# Install swag
go install github.com/swaggo/swag/cmd/swag@latest

# Generate docs
task swagger
```

### Run Tests

```bash
task test
```

### Build Binary

```bash
task build
```

## Docker

### Build Image

```bash
task docker-build
```

### Run with Docker Compose

```bash
task docker-run
```

### View Logs

```bash
task docker-logs
```

## Security Considerations

1. **JWT Secret**: Change `JWT_SECRET` in production
2. **HTTPS**: Use HTTPS in production
3. **Password**: Passwords are hashed using bcrypt (cost 10)
4. **Token Expiry**: Access tokens expire in 15 minutes
5. **Refresh Tokens**: Stored in Redis with 7-day TTL
6. **Database**: Use strong credentials in production

## Integration with Other Services

Other services can validate tokens by calling the `/auth/validate` endpoint:

```go
// Example from another service
func validateToken(token string) (bool, error) {
    resp, err := http.Post(
        "http://auth-service:8084/api/v1/auth/validate",
        "application/json",
        strings.NewReader(fmt.Sprintf(`{"token":"%s"}`, token)),
    )
    // ... handle response
}
```

## Troubleshooting

### Database Connection Failed

```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check connection
psql postgresql://portfolio_user:portfolio_pass@localhost:5432/portfolio
```

### Redis Connection Failed

```bash
# Check Redis is running
docker-compose ps redis

# Test connection
redis-cli -h localhost -p 6379 ping
```

### Port Already in Use

```bash
# Find process using port 8084
lsof -i :8084

# Kill process
kill -9 <PID>
```

## Related Repositories

- [infrastructure](https://github.com/GunarsK-portfolio/infrastructure)
- [database](https://github.com/GunarsK-portfolio/database)
- [admin-api](https://github.com/GunarsK-portfolio/admin-api)
- [public-api](https://github.com/GunarsK-portfolio/public-api)

## License

MIT
