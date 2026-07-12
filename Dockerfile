# ── Builder stage ──────────────────────────────────────────────
FROM golang:1.25-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN GOPROXY=https://goproxy.cn,direct go mod download

COPY . .
RUN CGO_ENABLED=0 GOPROXY=https://goproxy.cn,direct go build -ldflags="-s -w" -o alterhive .

# ── Runtime stage ──────────────────────────────────────────────
FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata curl docker-cli docker-cli-compose && \
    addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder /app/alterhive .
COPY --from=builder /app/configs ./configs
RUN chown -R app:app /app
EXPOSE 2222 8000
CMD ["./alterhive"]
