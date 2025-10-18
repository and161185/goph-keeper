# build
FROM golang:1.24.5-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${GIT_COMMIT:-dev} -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o /out/gk-server ./cmd/server

# run
FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=build /out/gk-server /gk-server
# certs монтируем томом (см. compose)
EXPOSE 8443
ENTRYPOINT ["/gk-server"]
