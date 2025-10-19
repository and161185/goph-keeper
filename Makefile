PKGS := $(shell go list ./internal/... | grep -v '/gen/')
COVERPKG := $(shell echo $(PKGS) | tr ' ' ',')
BIN ?= bin

VER  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VER) -X main.buildDate=$(DATE)

OSARCHES := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

BUILDENV := CGO_ENABLED=0
BUILDFLAGS := -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"

APP_SERVER ?= gk-server
APP_CLI    ?= gk
DIST       ?= dist

.PHONY: build build-cli build-server clean release release-cli release-server sums

cover:
	go test $(PKGS) -covermode=atomic -coverprofile=coverage.out -coverpkg=$(COVERPKG)
	go tool cover -func=coverage.out

build: build-server build-cli

build-server:
	@mkdir -p $(BIN)
	$(BUILDENV) go build $(BUILDFLAGS) -o $(BIN)/$(APP_SERVER) ./cmd/server

build-cli:
	@mkdir -p $(BIN)
	$(BUILDENV) go build $(BUILDFLAGS) -o $(BIN)/$(APP_CLI) ./cmd/cli

test:
	go test $(PKGS) -race -count=1

lint: 
	golangci-lint run

clean:
	rm -rf $(BIN) $(DIST) coverage.* *.out

release-local: clean
	@mkdir -p $(DIST)
	$(BUILDENV) go build $(BUILDFLAGS) -o $(DIST)/$(APP_SERVER) ./cmd/server
	$(BUILDENV) go build $(BUILDFLAGS) -o $(DIST)/$(APP_CLI)    ./cmd/cli