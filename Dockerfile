# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy source code
COPY . .

# Download dependencies and build
RUN go mod tidy && go mod download
RUN go build -o auth-service ./cmd/api

# Production stage
FROM alpine:3.22

RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 app && \
    adduser -D -u 1000 -G app app

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/auth-service .

# Change ownership to app user
RUN chown -R app:app /app

USER app

EXPOSE 8084

CMD ["./auth-service"]
