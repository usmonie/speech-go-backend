# Build stage
FROM golang:1.22-alpine AS builder

# Install necessary build tools
RUN apk add --no-cache git

# Set the working directory
WORKDIR /app

# Copy the entire project
COPY . .

# Download all dependencies
RUN go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Final stage
FROM alpine:latest

# Install necessary runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Set the working directory
WORKDIR /root/

# Copy the pre-built binary file from the previous stage
COPY --from=builder /app/main .

# Copy SSL certificates
COPY speech_wtf.crt speech_wtf.key ./

# Copy any additional configuration files if needed
COPY --from=builder /app/config ./config

# Expose the application ports
EXPOSE 8080
EXPOSE 50051

# Command to run the executable
CMD ["./main"]