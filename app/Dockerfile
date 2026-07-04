FROM golang:1.26-alpine AS builder

  RUN apk add --no-cache ca-certificates tzdata

  WORKDIR /build

  COPY . .

  ARG BUILD_COMMIT=unknown
  ARG BUILD_TIME=unknown
  ARG APP_VERSION=1.0.0

  # Works with both build contexts:
  # - context=./app  → main.go is at /build/main.go
  # - context=.      → main.go is at /build/app/main.go
  RUN SRCDIR=$(dirname $(find /build -name "main.go" | head -1)) && \
      cd "$SRCDIR" && \
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
      -ldflags="-w -s \
        -X main.BuildCommit=${BUILD_COMMIT} \
        -X main.BuildTime=${BUILD_TIME} \
        -X main.AppVersion=${APP_VERSION} \
        -X main.SLSALevel=3" \
      -o /build/cnd-app .

  FROM gcr.io/distroless/static-debian12:nonroot

  LABEL org.opencontainers.image.source="https://github.com/ghantotcon-cpu/cnd-project"
  LABEL org.opencontainers.image.description="CND Project — Supply Chain Security Microservice (Go)"
  LABEL org.opencontainers.image.licenses="MIT"

  COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
  COPY --from=builder /build/cnd-app /cnd-app

  USER nonroot:nonroot

  EXPOSE 8080

  ENTRYPOINT ["/cnd-app"]
  