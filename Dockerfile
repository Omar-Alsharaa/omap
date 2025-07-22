# Dockerfile for OMAP - Advanced Network Scanner
FROM golang:1.21-alpine AS builder

# Install required packages
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o omap .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN adduser -D -s /bin/sh omap

# Set working directory
WORKDIR /home/omap

# Copy binary from builder stage
COPY --from=builder /app/omap .

# Copy plugins and examples
COPY --from=builder /app/plugins ./plugins

# Change ownership
RUN chown -R omap:omap /home/omap

# Switch to non-root user
USER omap

# Expose port for web interface
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ./omap -t 127.0.0.1 -p 80 --timeout 1s || exit 1

# Default command
ENTRYPOINT ["./omap"]
CMD ["--help"]

# Labels
LABEL maintainer="OMAP Contributors"
LABEL description="OMAP - Advanced Network Scanner"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/yourusername/omap"
