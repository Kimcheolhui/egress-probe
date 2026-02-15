# ── Build stage ──────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /egress-probe .

# ── Runtime stage (distroless, ~5MB) ─────────────────────
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /egress-probe /egress-probe

USER nonroot:nonroot
ENTRYPOINT ["/egress-probe"]
