# obscure Makefile

VERSION := 0.1.0
GO_VERSION := 1.27
BINARY := doit
PREFIX := /usr/local
BINDIR := $(PREFIX)/bin
MANDIR := $(PREFIX)/share/man/man1
STATEDIR := /var/lib/obscure
RUNDIR := /run/obscure
CONFIGDIR := /etc/obscure
SANDBOXDIR := $(CONFIGDIR)/sandbox
UNITDIR := /etc/systemd/system

# Go toolchain (adjust if using a different Go installation)
GO := go
GOFLAGS := -trimpath -ldflags="-s -w -X main.version=$(VERSION)"

# Build tags
BUILD_TAGS :=

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build: $(BINARY)

$(BINARY): go.mod go.sum cmd/obscure/main.go $(shell find internal -name '*.go')
	$(GO) build $(GOFLAGS) -tags "$(BUILD_TAGS)" -o $(BINARY) ./cmd/obscure

# Cross-compile for Linux (static, CGO-free)
.PHONY: build-linux
build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "$(BUILD_TAGS)" -o $(BINARY)-linux-amd64 ./cmd/obscure
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -tags "$(BUILD_TAGS)" -o $(BINARY)-linux-arm64 ./cmd/obscure

# Install the binary, man page, and create required directories
.PHONY: install
install: build
	install -Dm755 $(BINARY) $(DESTDIR)$(BINDIR)/$(BINARY)
	install -Dm644 obscure.1 $(DESTDIR)$(MANDIR)/obscure.1
	install -d -m755 $(DESTDIR)$(CONFIGDIR)
	install -d -m755 $(DESTDIR)$(SANDBOXDIR)
	install -d -m700 $(DESTDIR)$(STATEDIR)
	install -d -m700 $(DESTDIR)$(RUNDIR)
	install -d -m755 $(DESTDIR)$(UNITDIR)
	@echo "Installed $(BINARY) to $(DESTDIR)$(BINDIR)/$(BINARY)"
	@echo "Man page installed to $(DESTDIR)$(MANDIR)/obscure.1"
	@echo "Created directories: $(CONFIGDIR), $(SANDBOXDIR), $(STATEDIR), $(RUNDIR)"

# Uninstall
.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BINARY)
	rm -f $(DESTDIR)$(MANDIR)/obscure.1
	@echo "Removed $(BINARY) and man page"

# Run tests
.PHONY: test
test:
	$(GO) test -v ./...

# Run tests with race detector (requires CGO)
.PHONY: test-race
test-race:
	CGO_ENABLED=1 $(GO) test -race -v ./...

# Lint
.PHONY: lint
lint:
	$(GO) vet ./...
	golangci-lint run ./... 2>/dev/null || echo "golangci-lint not installed, skipping"

# Format code
.PHONY: fmt
fmt:
	$(GO) fmt ./...

# Tidy dependencies
.PHONY: tidy
tidy:
	$(GO) mod tidy

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64 $(BINARY)-linux-arm64
	$(GO) clean -cache -testcache

# Vendor dependencies (for offline builds)
.PHONY: vendor
vendor:
	$(GO) mod vendor

# Generate go.mod checksum
.PHONY: mod
mod:
	$(GO) mod verify

# Check for outdated dependencies
.PHONY: outdated
outdated:
	@$(GO) list -u -m -json all | grep -E '(Path|Version|Update)' | paste - - - | column -t

# Install policy example
.PHONY: install-example
install-example:
	install -d -m755 $(DESTDIR)$(CONFIGDIR)
	install -m644 examples/web-server.toml $(DESTDIR)$(CONFIGDIR)/policy.toml.example
	@echo "Example policy installed to $(DESTDIR)$(CONFIGDIR)/policy.toml.example"

# Development: run with local policy
.PHONY: dev-plan
dev-plan: build
	sudo ./$(BINARY) --config examples/web-server.toml plan

.PHONY: dev-apply
dev-apply: build
	sudo ./$(BINARY) --config examples/web-server.toml apply

.PHONY: dev-verify
dev-verify: build
	sudo ./$(BINARY) --config examples/web-server.toml verify

.PHONY: dev-status
dev-status: build
	sudo ./$(BINARY) --config examples/web-server.toml status

.PHONY: dev-rollback
dev-rollback: build
	sudo ./$(BINARY) --config examples/web-server.toml rollback

# Help
.PHONY: help
help:
	@echo "Targets:"
	@echo "  build         - Build the binary"
	@echo "  build-linux   - Cross-compile static Linux binaries (amd64, arm64)"
	@echo "  install       - Install binary, man page, and create directories"
	@echo "  uninstall     - Remove binary and man page"
	@echo "  test          - Run tests"
	@echo "  test-race     - Run tests with race detector"
	@echo "  lint          - Run go vet and golangci-lint"
	@echo "  fmt           - Format code with gofmt"
	@echo "  tidy          - Tidy go modules"
	@echo "  clean         - Clean build artifacts"
	@echo "  vendor        - Vendor dependencies"
	@echo "  install-example - Install example policy"
	@echo "  dev-plan      - Run plan with example policy"
	@echo "  dev-apply     - Run apply with example policy"
	@echo "  dev-verify    - Run verify with example policy"
	@echo "  dev-status    - Run status with example policy"
	@echo "  dev-rollback  - Run rollback with example policy"
