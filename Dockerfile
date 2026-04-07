FROM golang:1.26.1-alpine AS builder

WORKDIR /app

# Download Go modules first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the Go application normally
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o core-auth ./cmd/server

FROM alpine:latest

WORKDIR /app

# Copy the built binary
COPY --from=builder /app/core-auth .

# Expose ports
EXPOSE 8080 50051

# Run the application
CMD ["./core-auth"]
