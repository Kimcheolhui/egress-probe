# ── Build stage ──────────────────────────────────────────
FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod ./
# COPY go.sum ./ # uncomment when dependencies are added
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /fqdn-filter-tester .

# ── Runtime stage (distroless, ~5MB) ─────────────────────
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /fqdn-filter-tester /fqdn-filter-tester

USER nonroot:nonroot
ENTRYPOINT ["/fqdn-filter-tester"]
