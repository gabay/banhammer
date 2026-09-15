# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Leverage layer caching for Go dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build static binary
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/banhammer ./cmd/banhammer

# Final runtime stage
FROM alpine:latest

# Install required firewall utilities for backends, CA certificates, and tzdata
RUN apk add --no-cache \
    ca-certificates \
    iptables \
    ip6tables \
    ipset \
    nftables \
    tzdata

# Copy compiled binary from builder
COPY --from=builder /bin/banhammer /usr/local/bin/banhammer

# Set up default directories for state and configuration
RUN mkdir -p /var/lib/banhammer /etc/banhammer

ENTRYPOINT ["banhammer"]
CMD ["run", "-c", "/etc/banhammer/config.yaml"]
