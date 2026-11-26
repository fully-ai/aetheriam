# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/aetheriam ./cmd/aetheriam

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -S aether && adduser -S aether -G aether

WORKDIR /app
COPY --from=builder /out/aetheriam /app/aetheriam
RUN mkdir -p /app/data && chown -R aether:aether /app

USER aether
EXPOSE 8080
VOLUME ["/app/data"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/app/aetheriam"]
CMD ["-addr", ":8080", "-data-dir", "/app/data", "-seed-demo"]
