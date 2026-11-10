FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/banhammer ./cmd/banhammer

FROM alpine:3

LABEL org.opencontainers.image.title="banhammer" \
      org.opencontainers.image.description="Single-binary intrusion prevention daemon: tails logs, bans offenders via iptables/nft/ipset." \
      org.opencontainers.image.source="https://github.com/gabay/banhammer"

RUN apk add --no-cache \
    ca-certificates \
    iptables \
    ip6tables \
    ipset \
    nftables \
    tzdata \
    wget

COPY --from=builder /bin/banhammer /usr/local/bin/banhammer

# Ship a config so `docker run <image>` starts instead of exiting immediately
# on a missing file. Mount your own over /etc/banhammer/config.yaml.
COPY config.example.yaml /etc/banhammer/banhammer.yaml

# Set up default directories for state and configuration
RUN mkdir -p /var/lib/banhammer /run/banhammer \
    && chmod 750 /var/lib/banhammer /run/banhammer

# Runs as root by default — see the Docker section of README.md for why and
# how to drop privileges.

# 9777 is the Prometheus endpoint (metrics.listen), 7890 the read-only status
# page (web.enabled). Both default to loopback in config.example.yaml; set
# listen: 0.0.0.0:<port> in the mounted config to reach them from the host.
EXPOSE 9777 7890

# /healthz is only served when metrics.listen is configured; the check is a
# no-op signal ("unhealthy") otherwise.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD banhammer status

ENV CONFIG=/etc/banhammer/banhammer.yaml
ENTRYPOINT ["banhammer"]
CMD ["run"]
