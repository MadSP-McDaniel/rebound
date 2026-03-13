# Build stage
FROM golang:1.24-bookworm AS build
WORKDIR /app

# Copy only the needed modules to keep replace paths valid
COPY cmd/prod-server/ cmd/prod-server/
COPY librebound/ librebound/
COPY tessera/ tessera/

# Build the prod server using workspace context
ENV CGO_ENABLED=0
WORKDIR /app/cmd/prod-server
# Ensure module graph is resolved (local replaces point to ../.. paths which exist)
RUN go mod download
RUN go build -trimpath -ldflags "-s -w" -o /bin/prod-server .

# Runtime stage
FROM debian:bookworm-slim
ENV PORT=8080
EXPOSE 8080
RUN mkdir -p /data
COPY --from=build /bin/prod-server /usr/local/bin/prod-server
# Run server as root (research prototype)
USER root
ENTRYPOINT ["/usr/local/bin/prod-server"]
