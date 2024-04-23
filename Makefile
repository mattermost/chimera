.PHONY: build test build-image build-image-with-tag

DOCKER_BUILDER_IMAGE = golang:1.21
DOCKER_BASE_IMAGE = gcr.io/distroless/static:nonroot

IMAGE ?= mattermost/chimera:test
IMAGE_REPO ?=mattermost/chimera

################################################################################

GO ?= $(shell command -v go 2> /dev/null)
GO_INSTALL = ./scripts/go_install.sh
PACKAGES=$(shell go list ./...)
TOOLS_BIN_DIR := $(abspath bin)

ARCH ?= amd64

BUILD_TIME := $(shell date -u +%Y%m%d.%H%M%S)
BUILD_HASH := $(shell git rev-parse HEAD)
LDFLAGS += -X github.com/mattermost/chimera.BuildHash=$(BUILD_HASH)

OUTDATED_VER := master
OUTDATED_BIN := go-mod-outdated
OUTDATED_GEN := $(TOOLS_BIN_DIR)/$(OUTDATED_BIN)
################################################################################

run-server: ## Starts Chimera server
	go run ./cmd/chimera server

test: ## Runs unit tests
	go test ./...

build: ## Build binary
	@echo Building binary
	@if [ "$(ARCH)" = "amd64" ]; then \
		export GOARCH="amd64"; \
	elif [ "$(ARCH)" = "arm64" ]; then \
		export GOARCH="arm64"; \
	elif [ "$(ARCH)" = "arm" ]; then \
		export GOARCH="arm"; \
	else \
		echo "Unknown architecture $(ARCH)"; \
		exit 1; \
	fi; \
	GOOS=linux CGO_ENABLED=0 $(GO) build -gcflags all=-trimpath=$(PWD) -asmflags all=-trimpath=$(PWD) -a -installsuffix cgo -o build/_output/bin/chimera -ldflags "$(LDFLAGS)" ./cmd/chimera

.PHONY: build-image
build-image: ## Build Chimera docker image
	@echo Building Docker image
	@if [ -z "$(DOCKER_USERNAME)" ] || [ -z "$(DOCKER_PASSWORD)" ]; then \
		echo "DOCKER_USERNAME and/or DOCKER_PASSWORD not set. Skipping Docker login."; \
	else \
		echo $(DOCKER_PASSWORD) | docker login --username $(DOCKER_USERNAME) --password-stdin; \
	fi
	docker buildx build \
	--platform linux/arm64,linux/amd64 \
	--build-arg DOCKER_BUILD_IMAGE=$(DOCKER_BUILDER_IMAGE) \
	--build-arg DOCKER_BASE_IMAGE=$(DOCKER_BASE_IMAGE) \
	. -f Dockerfile -t $(IMAGE) \
	--no-cache \
	--push

.PHONY: build-image-locally
build-image-locally: ## Build Chimera docker image
	@echo Building Docker image
	@if [ -z "$(DOCKER_USERNAME)" ] || [ -z "$(DOCKER_PASSWORD)" ]; then \
		echo "DOCKER_USERNAME and/or DOCKER_PASSWORD not set. Skipping Docker login."; \
	else \
		echo $(DOCKER_PASSWORD) | docker login --username $(DOCKER_USERNAME) --password-stdin; \
	fi
	docker buildx build \
	--platform linux/arm64 \
	--build-arg DOCKER_BUILD_IMAGE=$(DOCKER_BUILDER_IMAGE) \
	--build-arg DOCKER_BASE_IMAGE=$(DOCKER_BASE_IMAGE) \
	. -f Dockerfile -t $(IMAGE) \
	--no-cache \
	--load
.PHONY: build-image-with-tag
build-image-with-tag:   ## Build the docker image for the Chimera
	@echo Building Docker Image with TAG
	@if [ -z "$(DOCKER_USERNAME)" ] || [ -z "$(DOCKER_PASSWORD)" ]; then \
		echo "DOCKER_USERNAME and/or DOCKER_PASSWORD not set. Skipping Docker login."; \
	else \
		echo $(DOCKER_PASSWORD) | docker login --username $(DOCKER_USERNAME) --password-stdin; \
	fi
	: $${TAG:?}
	docker buildx build \
	--platform linux/arm64,linux/amd64 \
	--build-arg DOCKER_BUILD_IMAGE=$(DOCKER_BUILDER_IMAGE) \
	--build-arg DOCKER_BASE_IMAGE=$(DOCKER_BASE_IMAGE) \
	. -f Dockerfile -t $(IMAGE) -t $(IMAGE_REPO):${TAG} -t $(IMAGE_REPO):test-${BUILD_TIME} \
	--no-cache \
	--push

check-style: gofmt govet  ## Runs govet and gofmt against all packages.
	@echo Checking for style guide compliance
	$(GO) fmt ./...

gofmt: ## Verifies code is formatted with gofmt
	@echo Checking if code is formated
	@for package in $(PACKAGES); do \
		echo "Checking "$$package; \
		files=$$(go list -f '{{range .GoFiles}}{{$$.Dir}}/{{.}} {{end}}' $$package); \
		if [ "$$files" ]; then \
			gofmt_output=$$(gofmt -d -s $$files 2>&1); \
			if [ "$$gofmt_output" ]; then \
				echo "$$gofmt_output"; \
				echo "gofmt failure"; \
				exit 1; \
			fi; \
		fi; \
	done
	@echo "gofmt success"; \

govet: ## Runs govet against all packages.
	@echo Running govet
	$(GO) vet ./...
	@echo Govet success

format: ## Formats code with go fmt and goimports
	@echo Running go fmt
	$(GO) fmt ./...
	@echo Running goimports
	@for package in $(PACKAGES); do \
		files=$$(go list -f '{{range .GoFiles}}{{$$.Dir}}/{{.}} {{end}}' $$package); \
		if [ "$$files" ]; then \
		  	echo $$files; \
			goimports -w $$files; \
		fi; \
	done

.PHONY: push-image-pr
push-image-pr:
	@echo Push Image PR
	./scripts/push-image-pr.sh

.PHONY: push-image
push-image:
	@echo Push Image
	./scripts/push-image.sh

.PHONY: get-goimports
get-goimports: ## Install goimports
	$(GO) install golang.org/x/tools/cmd/goimports

.PHONY: check-modules
check-modules: $(OUTDATED_GEN) ## Check outdated modules
	@echo Checking outdated modules
	$(GO) list -mod=mod -u -m -json all | $(OUTDATED_GEN) -update -direct

.PHONY: scan
scan:
	docker scout cves ${IMAGE}

# Draft a release
.PHONY: release
release:
	@if [[ -z "${NEXT_VER}" ]]; then \
		echo "Error: NEXT_VER must be defined, e.g. \"make release NEXT_VER=v1.0.1\""; \
		exit -1; \
	else \
		if [[ "${TAG_EXISTS}" -eq 0 ]]; then \
		  echo "Error: tag ${NEXT_VER} already exists"; \
			exit -1; \
		else \
			if ! [ -x "$$(command -v goreleaser)" ]; then \
			echo "goreleaser is not installed, do you want to download it? [y/N] " && read ans && [ $${ans:-N} = y ]; \
				if [ $$ans = y ] || [ $$ans = Y ]  ; then \
					curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | sh; \
				else \
					echo "aborting make release."; \
					exit -1; \
				fi; \
			fi; \
			git commit -a -m 'Releasing $(NEXT_VER)'; \
			git tag $(NEXT_VER); \
			goreleaser --rm-dist; \
		fi; \
	fi;\

## Help documentation à la https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' ./Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

## --------------------------------------
## Tooling Binaries
## --------------------------------------
$(OUTDATED_GEN): ## Build go-mod-outdated.
	GOBIN=$(TOOLS_BIN_DIR) $(GO_INSTALL) github.com/psampaz/go-mod-outdated $(OUTDATED_BIN) $(OUTDATED_VER)
