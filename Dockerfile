# Stage 1: Build
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache make git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /bin/ephyr-broker ./cmd/broker && \
    CGO_ENABLED=0 go build -trimpath -o /bin/ephyr-signer ./cmd/signer && \
    CGO_ENABLED=0 go build -trimpath -o /bin/ephyr ./cmd/ephyr

# Stage 2: Runtime
FROM alpine:3.20
RUN apk add --no-cache openssh-client ca-certificates && \
    addgroup -S ephyr && adduser -S -G ephyr ephyr
COPY --from=builder /bin/ephyr-broker /bin/ephyr-signer /bin/ephyr /usr/local/bin/
COPY dashboard/ /opt/ephyr/dashboard/
RUN mkdir -p /etc/ephyr /var/log/ephyr /var/lib/ephyr /run/ephyr && \
    chown -R ephyr:ephyr /var/log/ephyr /var/lib/ephyr /run/ephyr
EXPOSE 8553 8554
USER ephyr
