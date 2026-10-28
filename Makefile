# pinscan — local gate. `make` runs fmt + lint + test + build.
GO       ?= go
GOBIN    := $(shell $(GO) env GOPATH)/bin
GOLANGCI := $(GOBIN)/golangci-lint
BINARY   := pinscan
PKG      := ./...
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Reproducible-build inputs: pin the build path and strip local paths.
LDFLAGS  := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all fmt lint test cover build install dist repro tools clean help

all: fmt lint test build ## Run the full local gate.

fmt: ## Format all Go sources.
	gofmt -w .

lint: ## Run the strict linter suite.
	$(GOLANGCI) run $(PKG)

test: ## Run tests with the race detector and atomic coverage.
	$(GO) test -race -covermode=atomic -coverprofile=coverage.out $(PKG)

cover: test ## Print per-function coverage.
	$(GO) tool cover -func=coverage.out

build: ## Build the CLI (reproducibly) into ./bin.
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/pinscan

install: ## Install pinscan onto PATH (into `go env GOBIN`).
	$(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/pinscan
	@echo "installed to $(GOBIN)/$(BINARY) — ensure $(GOBIN) is on your PATH"

dist: ## Cross-build release binaries + SHA256SUMS into ./dist.
	@rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
		out=dist/$(BINARY)-$(VERSION)-$$os-$$arch$$ext; \
		echo "build $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$out ./cmd/pinscan || exit 1; \
	done
	@cd dist && { if command -v sha256sum >/dev/null 2>&1; then sha256sum *; else shasum -a 256 *; fi; } > SHA256SUMS && echo "wrote dist/SHA256SUMS"

repro: ## Prove the build is reproducible: build twice and byte-compare.
	@CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY).a ./cmd/pinscan
	@CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY).b ./cmd/pinscan
	@if cmp -s bin/$(BINARY).a bin/$(BINARY).b; then \
		echo "reproducible: both builds are byte-identical"; rm -f bin/$(BINARY).a bin/$(BINARY).b; \
	else \
		echo "NOT reproducible: builds differ"; exit 1; \
	fi

tools: ## Install pinned dev tooling.
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.2

clean: ## Remove build artefacts.
	rm -rf bin dist coverage.out

help: ## Show this help.
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'
