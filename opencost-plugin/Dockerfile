FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY opencost-plugin/ ./opencost-plugin/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /opencost-plugin ./opencost-plugin/

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /opencost-plugin /opencost-plugin
EXPOSE 9992
ENTRYPOINT ["/opencost-plugin"]
