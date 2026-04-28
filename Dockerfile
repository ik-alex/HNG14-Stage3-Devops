FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /build

COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true

COPY . .
RUN CGO_ENABLED=0 go build -o detector .

FROM alpine:3.19

RUN apk add --no-cache iptables procps

WORKDIR /app

COPY --from=builder /build/detector .
COPY --from=builder /build/config.yaml .

RUN mkdir -p /var/log/detector

CMD ["./detector"]