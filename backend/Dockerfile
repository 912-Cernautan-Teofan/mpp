# Use the official Golang image to create a build artifact.
FROM golang:1.22.2 AS build

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code from the current directory to the Working Directory inside the container
COPY *.go ./

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -o /backend

# Start a new stage from scratch
FROM debian:bullseye-slim

# Copy the Pre-built binary file from the previous stage
COPY --from=build /backend /backend

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["/backend"]
