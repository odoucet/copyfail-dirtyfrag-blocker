# Makefile for copy-fail-blocker

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
REVISION ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")

BINARY_NAME := copyfail

REGISTRY ?= <your-registry>
TAG      ?= latest

BUILDX_ARGS := --provenance=false --load \
  --label org.opencontainers.image.source=https://github.com/odoucet/copyfail-dirtyfrag-blocker

GO      := go
GOFLAGS := -trimpath
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.Revision=$(REVISION)

##@ Build

.PHONY: generate
generate: ## Run bpf2go and other go generate hooks
	$(GO) generate ./...

.PHONY: build
build: generate ## Build the daemon binary
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) .

##@ Container

.PHONY: image
image: ## Build container image locally (then run: docker push REGISTRY/BINARY_NAME:TAG)
	docker buildx build . \
		--file Containerfile \
		--tag $(REGISTRY)/$(BINARY_NAME):$(TAG) \
		--build-arg VERSION=$(VERSION) \
		--build-arg REVISION=$(REVISION) \
		$(BUILDX_ARGS)
	@echo ""
	@echo "Image built. To push:"
	@echo "  docker push $(REGISTRY)/$(BINARY_NAME):$(TAG)"

##@ Misc

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin/ *.tgz .build-metadata.json
	rm -f bpf/blocker_*.go bpf/blocker_*.o bpf/vmlinux.h

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
