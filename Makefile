.PHONY: build test

DOCKER_BUILDER_IMAGE = golang:1.16
DOCKER_BASE_IMAGE = gcr.io/distroless/static:nonroot

IMAGE ?= mattermost/chimera:test

################################################################################

GO ?= $(shell command -v go 2> /dev/null)
PACKAGES=$(shell go list ./...)

BUILD_TIME := $(shell date -u +%Y%m%d.%H%M%S)
BUILD_HASH := $(shell git rev-parse HEAD)
LDFLAGS += "-X github.com/mattermost/chimera.BuildHash=$(BUILD_HASH)"

################################################################################

run-server: ## Starts Chimera server
	go run ./cmd/chimera server

test: ## Runs unit tests
	go test ./...

build: ## Build binary
	@echo Building binary
	GO111MODULE=on GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -gcflags all=-trimpath=$(PWD) -asmflags all=-trimpath=$(PWD) -a -installsuffix cgo -o build/_output/bin/chimera -ldflags '$(LDFLAGS)' ./cmd/chimera

build-image: ## Build Chimera docker image
	@echo Building Docker image
	docker build . -t $(IMAGE) \
	--build-arg DOCKER_BUILDER_IMAGE=$(DOCKER_BUILDER_IMAGE) \
	--build-arg DOCKER_BASE_IMAGE=$(DOCKER_BASE_IMAGE) \
	--no-cache

check-style: gofmt govet goimports ## Runs govet and gofmt against all packages.
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

goimports: get-goimports ## Runs goimports against all packages.
	@echo Checking imports are sorted
	@for package in $(PACKAGES); do \
		echo "Checking "$$package; \
		files=$$(go list -f '{{range .GoFiles}}{{$$.Dir}}/{{.}} {{end}}' $$package); \
		if [ "$$files" ]; then \
			goimports_output=$$(goimports -d $$files 2>&1); \
			if [ "$$goimports_output" ]; then \
				echo "$$goimports_output"; \
				echo "goimports failure"; \
				exit 1; \
			fi; \
		fi; \
	done
	@echo "goimports success"; \

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


get-goimports: ## Install goimports
	$(GO) install golang.org/x/tools/cmd/goimports

## Help documentation à la https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' ./Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
