# The image that docker-build makes, and the version that the collector reports in GetInfo. vexplain stores evidence
# at the version, so a new version replaces what an old one delivered.
IMG ?= collector-template:latest
VERSION ?= 0.1.0

# CONTAINER_TOOL defines the container tool to be used for building images.
CONTAINER_TOOL ?= docker

.PHONY: all
all: build

.PHONY: fmt
fmt: ## Run go fmt against the code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against the code.
	go vet ./...

.PHONY: test
test: fmt vet ## Run the tests, which include the conformance suite of the SDK.
	go test ./...

.PHONY: build
build: fmt vet ## Build the collector.
	go build -ldflags "-X main.version=$(VERSION)" -o bin/collector .

# The image builds from this directory, with the replace line of go.mod dropped: see the README.
.PHONY: docker-build
docker-build: ## Build the image of the collector.
	$(CONTAINER_TOOL) build --build-arg VERSION=$(VERSION) -t $(IMG) .

.PHONY: docker-push
docker-push: ## Push the image of the collector.
	$(CONTAINER_TOOL) push $(IMG)
