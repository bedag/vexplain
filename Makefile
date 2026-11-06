# Image URL to use all building/pushing image targets
IMG ?= controller:latest
# Each built-in collector is an image of its own, which its Collector installs as its package (decision 0029). The
# scanner's image also runs its scan Jobs.
MATCHER_IMG ?= matcher:latest
SCANNER_IMG ?= scanner:latest
WORKLOADS_IMG ?= workloads:latest
# MATCHER_DB=true bakes the vulnerability database into the matcher image, as the build argument WITH_DB.
# A cluster whose pods have no internet, such as the kind cluster of the e2e tests, needs it. The image
# then weighs about 3.5 GB.
MATCHER_DB ?= false
# VERSION is the version that each built-in collector reports in GetInfo: docker-build gives it to their builds.
# vexplain stores a collector's evidence at its version, so a rebuilt collector replaces what the build before it
# delivered only under a new version. It is the commit that the images are built from, as git describe names it, and
# a working tree with changes builds as that commit with -dirty, whatever the changes.
VERSION ?= $(shell git describe --tags --always --dirty)
# YEAR defines the year value used for substituting the YEAR placeholder in the boilerplate header.
YEAR ?= $(shell date +%Y)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

# The operator is the module of the root. The SDK and, with them, the collectors are modules of their
# own, which go.work lists next to it. SUBMODULES holds the directories of all of them but the
# operator, and the targets below run their commands in each. The operator's own commands stay as
# they were: they need more, such as envtest.
ROOT_MODULE = $(shell sed -n 's/^module //p' go.mod)
SUBMODULES = $(shell go list -m -f '{{if ne .Path "$(ROOT_MODULE)"}}{{.Dir}}{{end}}')

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt",year=$(YEAR) paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against the code of every module.
	go fmt ./...
	@for dir in $(SUBMODULES); do (cd "$$dir" && go fmt ./...) || exit 1; done

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(ENVTEST_ASSETS)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out
	@for dir in $(SUBMODULES); do (cd "$$dir" && KUBEBUILDER_ASSETS="$(ENVTEST_ASSETS)" go test ./...) || exit 1; done

# TODO(user): To use a different vendor for e2e tests, modify the setup under 'tests/e2e'.
# The default setup assumes Kind is pre-installed and builds/loads the images of the manager, the scanner
# and the matcher locally. The matcher image is built with its database (MATCHER_DB=true), because nothing in
# the cluster reaches the internet.
# kubectl kuberc is disabled by default for test isolation; enable with:
# - KUBECTL_KUBERC=true
# CertManager is installed by default; skip with:
# - CERT_MANAGER_INSTALL_SKIP=true
KIND_CLUSTER ?= vexplain-test-e2e
# The e2e targets work on a kubeconfig of their own, so that a developer's ~/.kube/config is neither used nor
# changed (AGENTS.md). The other targets keep using the one of the shell.
E2E_KUBECONFIG ?= $(LOCALBIN)/kind-e2e.kubeconfig
setup-test-e2e test-e2e cleanup-test-e2e: export KUBECONFIG = $(E2E_KUBECONFIG)
# The local registry of the e2e cluster follows https://kind.sigs.k8s.io/docs/user/local-registry/. It listens
# on localhost:5001, which test/e2e/e2e_suite_test.go and test/e2e/config use as well. Its name is not kind's
# default, so that cleanup can only remove the registry that this setup made.
E2E_REGISTRY ?= vexplain-e2e-registry
E2E_REGISTRY_PORT ?= 5001
E2E_REGISTRY_IMAGE ?= registry:3.1.2@sha256:d4032d4cc323c1731c707931ecada07a53076eac38e3b61ae57533f170f2c6c3

.PHONY: setup-test-e2e
setup-test-e2e: ## Set up a Kind cluster and a local registry for e2e tests if they do not exist
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@if ! $(CONTAINER_TOOL) container inspect $(E2E_REGISTRY) >/dev/null 2>&1; then \
		echo "Starting the local registry '$(E2E_REGISTRY)' on localhost:$(E2E_REGISTRY_PORT)..."; \
		$(CONTAINER_TOOL) run -d -p 127.0.0.1:$(E2E_REGISTRY_PORT):5000 --network bridge \
			--name $(E2E_REGISTRY) $(E2E_REGISTRY_IMAGE) >/dev/null; \
	elif [ "$$($(CONTAINER_TOOL) container inspect -f '{{.State.Running}}' $(E2E_REGISTRY))" != true ]; then \
		$(CONTAINER_TOOL) start $(E2E_REGISTRY) >/dev/null; \
	fi
	@# kind copies the proxy variables of the shell that creates the cluster into its nodes, where a proxy on
	@# localhost would be the node itself. Nothing in the e2e cluster needs the internet, so it gets none.
	@if $(KIND) get clusters | grep -qx "$(KIND_CLUSTER)"; then \
		echo "Kind cluster '$(KIND_CLUSTER)' already exists. Skipping creation."; \
		$(KIND) export kubeconfig --name $(KIND_CLUSTER) --kubeconfig $(E2E_KUBECONFIG); \
	else \
		echo "Creating Kind cluster '$(KIND_CLUSTER)'..."; \
		env -u HTTP_PROXY -u HTTPS_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u no_proxy \
			$(KIND) create cluster --name $(KIND_CLUSTER) --config test/e2e/kind-config.yaml \
			--kubeconfig $(E2E_KUBECONFIG) --wait 120s; \
	fi
	@# The nodes pull localhost:$(E2E_REGISTRY_PORT) from the registry container, which they reach by its name on the
	@# kind network.
	@for node in $$($(KIND) get nodes --name $(KIND_CLUSTER)); do \
		$(CONTAINER_TOOL) exec $$node mkdir -p /etc/containerd/certs.d/localhost:$(E2E_REGISTRY_PORT); \
		printf '[host."http://%s:5000"]\n' $(E2E_REGISTRY) | \
			$(CONTAINER_TOOL) exec -i $$node tee /etc/containerd/certs.d/localhost:$(E2E_REGISTRY_PORT)/hosts.toml >/dev/null; \
	done
	@if [ "$$($(CONTAINER_TOOL) container inspect -f '{{json .NetworkSettings.Networks.kind}}' $(E2E_REGISTRY))" = null ]; then \
		$(CONTAINER_TOOL) network connect kind $(E2E_REGISTRY); \
	fi

.PHONY: test-e2e
test-e2e: setup-test-e2e manifests generate fmt vet ## Run the e2e tests. Expected an isolated environment using Kind.
	KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) go test -tags=e2e ./test/e2e/ -v -ginkgo.v -timeout 60m
	$(MAKE) cleanup-test-e2e

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## Tear down the Kind cluster and the local registry used for e2e tests
	@$(KIND) delete cluster --name $(KIND_CLUSTER) --kubeconfig $(E2E_KUBECONFIG)
	@if $(CONTAINER_TOOL) container inspect $(E2E_REGISTRY) >/dev/null 2>&1; then \
		$(CONTAINER_TOOL) rm -f -v $(E2E_REGISTRY) >/dev/null; \
	fi
	@rm -f $(E2E_KUBECONFIG)

.PHONY: lint
lint: check-comments golangci-lint ## Run golangci-lint linter and the comment check
	"$(GOLANGCI_LINT)" run
	@for dir in $(SUBMODULES); do (cd "$$dir" && "$(GOLANGCI_LINT)" run) || exit 1; done

# A comment states its reason itself. This fails on one that cites a decision kept outside the
# repository, such as a numbered decision of an agent's development ledger. See the script.
.PHONY: check-comments
check-comments: ## Check that no Go comment cites a decision kept outside the repository
	hack/check-comments.sh

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix
	@for dir in $(SUBMODULES); do (cd "$$dir" && "$(GOLANGCI_LINT)" run --fix) || exit 1; done

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Collector API

# The collector API's Go code is generated from sdk/proto, committed under sdk/api, and checked in CI.
# buf finds the two plugins through PATH, and the Makefile pins them like the other tools.
.PHONY: proto
proto: buf protoc-gen-go protoc-gen-go-grpc ## Generate the Go code of the collector API (sdk/api) from sdk/proto.
	cd sdk && PATH="$(LOCALBIN):$$PATH" "$(BUF)" generate

# The check generates into a temporary directory and compares, so that it also fails for code that
# `make proto` made and that isn't committed yet, and for generated files that no proto makes any more.
# The tests that sit next to the generated code are not compared.
.PHONY: proto-check
proto-check: buf protoc-gen-go protoc-gen-go-grpc ## Fail when sdk/api is not what sdk/proto generates.
	@set -e; tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	(cd sdk && PATH="$(LOCALBIN):$$PATH" "$(BUF)" generate --output "$$tmp"); \
	diff -ru -x '*_test.go' sdk/api "$$tmp/api" || { \
		echo "sdk/api is not what sdk/proto generates. Run 'make proto', and commit the result." >&2; \
		exit 1; \
	}

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# A collector's image builds from the root of the repository, since the collector's module replaces the SDK with
# the directory sdk. Each collector reports VERSION as its version.
.PHONY: docker-build
docker-build: ## Build docker images with the manager and every built-in collector.
	$(CONTAINER_TOOL) build -t ${IMG} .
	$(CONTAINER_TOOL) build -f collectors/matcher/Dockerfile --build-arg VERSION=${VERSION} \
		--build-arg WITH_DB=${MATCHER_DB} -t ${MATCHER_IMG} .
	$(CONTAINER_TOOL) build -f collectors/scanner/Dockerfile --build-arg VERSION=${VERSION} -t ${SCANNER_IMG} .
	$(CONTAINER_TOOL) build -f collectors/workloads/Dockerfile --build-arg VERSION=${VERSION} -t ${WORKLOADS_IMG} .

.PHONY: docker-push
docker-push: ## Push docker images with the manager and every built-in collector.
	$(CONTAINER_TOOL) push ${IMG}
	$(CONTAINER_TOOL) push ${MATCHER_IMG}
	$(CONTAINER_TOOL) push ${SCANNER_IMG}
	$(CONTAINER_TOOL) push ${WORKLOADS_IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name vexplain-builder
	$(CONTAINER_TOOL) buildx use vexplain-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm vexplain-builder
	rm Dockerfile.cross

# set-images points the manifests at the manager's image. It edits the kustomization.yaml of config/manager in place,
# as kubebuilder's deploy always has. Don't commit the edit. The e2e tests put the file back.
define set-images
cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
endef

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	$(set-images)
	"$(KUSTOMIZE)" build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" apply -f -; else echo "No CRDs to install; skipping."; fi

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -; else echo "No CRDs to delete; skipping."; fi

# DEPLOY_CONFIG is the kustomization that deploy and undeploy build. The e2e tests deploy their own, which adds
# the settings of a cluster without internet to config/default.
DEPLOY_CONFIG ?= config/default

.PHONY: deploy
deploy: manifests kustomize ## Deploy the controller to the K8s cluster specified in ~/.kube/config.
	$(set-images)
	"$(KUSTOMIZE)" build $(DEPLOY_CONFIG) | "$(KUBECTL)" apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy the controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build $(DEPLOY_CONFIG) | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
KUBECTL ?= kubectl
KIND ?= kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
BUF ?= $(LOCALBIN)/buf
PROTOC_GEN_GO ?= $(LOCALBIN)/protoc-gen-go
PROTOC_GEN_GO_GRPC ?= $(LOCALBIN)/protoc-gen-go-grpc

## Tool Versions
KUSTOMIZE_VERSION ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.21.0
BUF_VERSION ?= v1.75.0
# The generated code needs at least this version of google.golang.org/protobuf, which sdk/go.mod requires.
PROTOC_GEN_GO_VERSION ?= v1.36.12
PROTOC_GEN_GO_GRPC_VERSION ?= v1.6.2

#ENVTEST_VERSION is the controller-runtime version to use for setup-envtest, derived from go.mod
ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually (controller-runtime replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v")

# ENVTEST_ASSETS is the directory of the ENVTEST binaries, which the tests of every module get as
# KUBEBUILDER_ASSETS: the operator's, and those of the SDK, whose conformance suite starts an API server for its
# presence check. Expanding it needs setup-envtest, which `make test` runs first.
ENVTEST_ASSETS = $(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)

#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell v='$(call gomodver,k8s.io/api)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_K8S_VERSION manually (k8s.io/api replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

GOLANGCI_LINT_VERSION ?= v2.12.2
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: buf
buf: $(BUF) ## Download buf locally if necessary.
$(BUF): $(LOCALBIN)
	$(call go-install-tool,$(BUF),github.com/bufbuild/buf/cmd/buf,$(BUF_VERSION))

.PHONY: protoc-gen-go
protoc-gen-go: $(PROTOC_GEN_GO) ## Download protoc-gen-go locally if necessary.
$(PROTOC_GEN_GO): $(LOCALBIN)
	$(call go-install-tool,$(PROTOC_GEN_GO),google.golang.org/protobuf/cmd/protoc-gen-go,$(PROTOC_GEN_GO_VERSION))

.PHONY: protoc-gen-go-grpc
protoc-gen-go-grpc: $(PROTOC_GEN_GO_GRPC) ## Download protoc-gen-go-grpc locally if necessary.
$(PROTOC_GEN_GO_GRPC): $(LOCALBIN)
	$(call go-install-tool,$(PROTOC_GEN_GO_GRPC),google.golang.org/grpc/cmd/protoc-gen-go-grpc,$(PROTOC_GEN_GO_GRPC_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
	@test -f .custom-gcl.yml && { \
		echo "Building custom golangci-lint with plugins..." && \
		$(GOLANGCI_LINT) custom --destination $(LOCALBIN) --name golangci-lint-custom && \
		mv -f $(LOCALBIN)/golangci-lint-custom $(GOLANGCI_LINT); \
	} || true

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef
