# syntax=docker/dockerfile:1.7

##############################
# Builder stage
##############################
FROM golang:1.25-alpine AS builder

ARG PUBKEY_B64=""
ENV CGO_ENABLED=0

RUN apk add --no-cache ca-certificates upx && update-ca-certificates

WORKDIR /src

# Cache dependencies first
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
	go mod download

# Copy the rest of the source
COPY . .

# Build encrypt (optionally with embedded public key) and decrypt
RUN --mount=type=cache,target=/root/.cache/go-build \
	set -eux; \
	LDFLAGS_BASE="-s -w"; \
	if [ -n "$PUBKEY_B64" ]; then \
		LDFLAGS="$LDFLAGS_BASE -X file-crypto/internal/crypto.EmbeddedPublicKeyBase64=$PUBKEY_B64"; \
		go build -trimpath -ldflags "$LDFLAGS" -o /out/encrypt ./cmd/encrypt; \
	else \
		go build -trimpath -ldflags "$LDFLAGS_BASE" -o /out/encrypt ./cmd/encrypt; \
	fi; \
	go build -trimpath -ldflags "$LDFLAGS_BASE" -o /out/decrypt ./cmd/decrypt; \
	upx -9 /out/encrypt /out/decrypt || true

##############################
# Runtime stage
##############################
FROM alpine:3.20

# Labels help document safe testing usage
LABEL org.opencontainers.image.title="file-crypto test container" \
      org.opencontainers.image.description="Run encrypt/decrypt in a sandbox. Use /data as the only writable dir. Recommended: run with --read-only, --cap-drop ALL, --security-opt no-new-privileges, and tmpfs /tmp." \
      org.opencontainers.image.source="https://example.invalid/repo"

RUN apk add --no-cache ca-certificates tzdata && update-ca-certificates

# Create non-root user and group
RUN addgroup -S app && adduser -S -G app app

# Copy binaries
COPY --from=builder /out/encrypt /usr/local/bin/encrypt
COPY --from=builder /out/decrypt /usr/local/bin/decrypt

# Set permissions and create a dedicated writable workspace
RUN chmod 0555 /usr/local/bin/encrypt /usr/local/bin/decrypt \
	&& mkdir -p /data \
	&& chown -R app:app /data

# Use a non-root user by default
USER app:app

# Working directory for tests; mount your test data here as a volume
WORKDIR /data
VOLUME ["/data"]

# Default to an interactive shell for exploratory testing
# Example safe runs:
#   docker run --rm -it --read-only --cap-drop ALL \
#     --security-opt no-new-privileges \
#     --pids-limit 256 --memory=512m \
#     --tmpfs /tmp:rw,noexec,nosuid,size=64m \
#     -v $(pwd)/testdata:/data:rw file-crypto:dev sh
# Inside container:
#   encrypt -dir /data -key /data/decryption_key.txt -benchmark -verbose
# If built with PUBKEY_B64 (embedded-key mode), omit -key.
# To inspect system paths safely, mount host root read-only:
#   -v /:/host:ro  (then test -dir /host; writes will fail due to ro mount)
ENTRYPOINT ["/bin/sh"]
CMD ["-l"]
