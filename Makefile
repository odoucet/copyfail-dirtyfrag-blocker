# Makefile for copy-fail-blocker

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
REVISION ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")

BINARY_NAME := copyfail
CHART_NAME  := copy-fail-blocker
NAMESPACE   ?= kube-system

REGISTRY ?= docker.io/oxeva
TAG      ?= latest
PUSH     := 1
LOAD     := 0
BUILDER  ?=
PLATFORM ?=
BUILDX_EXTRA_ARGS ?=

BUILDX_ARGS := --provenance=false --push=$(PUSH) --load=$(LOAD) \
  --label org.opencontainers.image.source=https://github.com/odoucet/copyfail-dirtyfrag-blocker \
  $(if $(strip $(BUILDER)),--builder=$(BUILDER)) \
  $(if $(strip $(PLATFORM)),--platform=$(PLATFORM)) \
  $(BUILDX_EXTRA_ARGS)

GO        := go
GOFLAGS   := -trimpath
LDFLAGS   := -s -w -X main.Version=$(VERSION) -X main.Revision=$(REVISION)
HELM      := helm
KUBECTL   := kubectl

##@ Build

.PHONY: generate
generate: ## Run bpf2go and other go generate hooks
	$(GO) generate ./...

.PHONY: build
build: generate ## Build the daemon binary
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) .

##@ Container

.PHONY: image
image: ## Build container image, push, update chart values.yaml and rendered manifest
	docker buildx build . \
		--file Containerfile \
		--tag $(REGISTRY)/$(BINARY_NAME):$(TAG) \
		--build-arg VERSION=$(VERSION) \
		--build-arg REVISION=$(REVISION) \
		--cache-from type=registry,ref=$(REGISTRY)/$(BINARY_NAME):latest \
		--cache-to type=inline \
		--metadata-file .build-metadata.json \
		$(BUILDX_ARGS)
	@REPOSITORY="$(REGISTRY)/$(BINARY_NAME)" \
		yq -i '.image.repository = strenv(REPOSITORY)' charts/$(CHART_NAME)/values.yaml
	@TAG=$(TAG)@$$(yq e '."containerimage.digest"' .build-metadata.json -o json -r 2>/dev/null || echo $(TAG)) \
		yq -i '.image.tag = strenv(TAG)' charts/$(CHART_NAME)/values.yaml
	@rm -f .build-metadata.json
	@$(MAKE) --no-print-directory manifest

.PHONY: manifest
manifest: ## Render Helm chart to manifests/copy-fail-blocker.yaml
	@mkdir -p manifests
	$(HELM) template $(CHART_NAME) charts/$(CHART_NAME) --namespace $(NAMESPACE) \
		> manifests/$(CHART_NAME).yaml

##@ Helm

.PHONY: helm-lint
helm-lint: ## Lint Helm chart
	$(HELM) lint charts/$(CHART_NAME)

.PHONY: helm-package
helm-package: ## Package Helm chart
	$(HELM) package charts/$(CHART_NAME)

.PHONY: show
show: ## Show rendered Helm templates
	$(HELM) template $(CHART_NAME) charts/$(CHART_NAME) --namespace $(NAMESPACE)

##@ Deploy

.PHONY: apply
apply: ## Install/upgrade Helm release on the current Kubernetes cluster
	$(HELM) upgrade --install $(CHART_NAME) charts/$(CHART_NAME) \
		--namespace $(NAMESPACE) --create-namespace

.PHONY: diff
diff: ## Diff Helm release against objects in the cluster
	$(HELM) diff upgrade $(CHART_NAME) charts/$(CHART_NAME) \
		--namespace $(NAMESPACE) --allow-unreleased

.PHONY: delete
delete: ## Uninstall Helm release
	$(HELM) uninstall $(CHART_NAME) --namespace $(NAMESPACE)

##@ Misc

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin/ *.tgz .build-metadata.json
	rm -f bpf/blocker_*.go bpf/blocker_*.o bpf/vmlinux.h

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
