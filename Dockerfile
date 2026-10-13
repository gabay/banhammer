# Build stage.
#
# The tag is pinned to a patch release, not the floating 1.26-alpine: that tag
# can resolve to a toolchain older than the `go 1.26.6` directive in go.mod,
# which fails the build with a version error that looks nothing like a tag
# problem.
FROM golang:1.26.6-alpine AS builder

WORKDIR /src

# Leverage layer caching for Go dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build static binary
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/banhammer ./cmd/banhammer

# Final runtime stage
FROM alpine:3.22

LABEL org.opencontainers.image.title="banhammer" \
      org.opencontainers.image.description="Single-binary intrusion prevention daemon: tails logs, bans offenders via iptables/nft/ipset." \
      org.opencontainers.image.source="https://github.com/gabay/banhammer"

# Install required firewall utilities for backends, CA certificates, and tzdata
RUN apk add --no-cache \
    ca-certificates \
    iptables \
    ip6tables \
    ipset \
    nftables \
    tzdata \
    wget

# Copy compiled binary from builder
COPY --from=builder /bin/banhammer /usr/local/bin/banhammer

# Ship a config so `docker run <image>` starts instead of exiting immediately
# on a missing file. Mount your own over /etc/banhammer/config.yaml.
COPY config.example.yaml /etc/banhammer/config.yaml

# Set up default directories for state and configuration
RUN mkdir -p /var/lib/banhammer /run/banhammer \
    && chmod 750 /var/lib/banhammer /run/banhammer

# Runs as root by default — see the Docker section of README.md for why and
# how to drop privileges.

# 9777 is the Prometheus endpoint (metrics.listen), 7980 the read-only status
# page (web.enabled). Both default to loopback in config.example.yaml; set
# listen: 0.0.0.0:<port> in the mounted config to reach them from the host.
EXPOSE 9777 7980

# /healthz is only served when metrics.listen is configured; the check is a
# no-op signal ("unhealthy") otherwise.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD banhammer status

ENTRYPOINT ["banhammer"]
CMD ["run", "-c", "/etc/banhammer/config.yaml", "--socket", "/run/banhammer/control.sock"]
