# ── Stage 1: Build (hermetic — no network after go mod download) ──
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

ARG BUILD_COMMIT=unknown
ARG BUILD_TIME=unknown
ARG APP_VERSION=1.0.0

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s \
      -X main.BuildCommit=${BUILD_COMMIT} \
      -X main.BuildTime=${BUILD_TIME} \
      -X main.AppVersion=${APP_VERSION} \
      -X main.SLSALevel=3" \
    -o /build/cnd-app ./...

# ── Stage 2: Runtime (distroless for minimal attack surface) ──
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/ghantotcon-cpu/cnd-project"
LABEL org.opencontainers.image.description="CND Project Demo Microservice (Go)"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/cnd-app /cnd-app

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/cnd-app"]
