#################################################################################
#
# Go build settings
#
#################################################################################

BINARY := bin/bomify

VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
DATE       := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_VERSION := $(shell go version | cut -d' ' -f3)

LDFLAGS := -X github.com/alejandro-velasco/bomify/internal/buildinfo.version=$(VERSION) \
		   -X github.com/alejandro-velasco/bomify/internal/buildinfo.commit=$(COMMIT)   \
		   -X github.com/alejandro-velasco/bomify/internal/buildinfo.date=$(DATE)       \
		   -X github.com/alejandro-velasco/bomify/internal/buildinfo.goVersion=$(GO_VERSION)

################################################################################
#
# Container build settings
#
################################################################################

CONTAINER_TOOL ?= docker
CONTAINER_REGISTRY ?= docker.io
CONTAINER_REPO ?= avelasco1423/bomify
CONTAINER_TAG ?= latest
CONTAINER_REF ?= $(CONTAINER_REGISTRY)/$(CONTAINER_REPO):$(CONTAINER_TAG)

################################################################################
#
# Release build settings
#
################################################################################

DIST_DIR := dist

# GOOS/GOARCH pairs to cross-compile release archives for.
RELEASE_PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

################################################################################
#
# Build recipes
#
################################################################################

.PHONY: build build-container push-container plugins dist docs diagrams test run tidy clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

build-container:
	$(CONTAINER_TOOL) build -f Containerfile -t $(CONTAINER_REF) .

push-container:
	$(CONTAINER_TOOL) push $(CONTAINER_REF)

plugins:
	go build -o bin/ ./plugins/...

# dist cross-compiles bomify and its plugins for each of RELEASE_PLATFORMS and
# packages them into per-platform archives under $(DIST_DIR), alongside a
# checksums.txt covering all of them. See hack/dist.sh.
dist: clean
	VERSION=$(VERSION) LDFLAGS="$(LDFLAGS)" DIST_DIR=$(DIST_DIR) RELEASE_PLATFORMS="$(RELEASE_PLATFORMS)" hack/dist.sh

# docs regenerates the CLI reference (see the --docs-dir flag in cmd/root.go).
docs:
	mkdir -p docs/reference
	go run . --docs-dir docs/reference

# diagrams renders every docs/diagrams/*.mmd source to an .svg file
# alongside it. See hack/diagrams.sh.
diagrams:
	hack/diagrams.sh

install: build plugins
	install -Dm755 $(BINARY) /usr/local/bin/$(notdir $(BINARY))
	install -Dm755 bin/bomify-plugin-* /usr/local/bin/
	# Alias bomify-plugin-oci to bomify-plugin-docker for backward compatibility
	ln -sf /usr/local/bin/bomify-plugin-oci /usr/local/bin/bomify-plugin-docker

test:
	go test ./...

run: build
	./$(BINARY)

tidy:
	go mod tidy

clean:
	rm -rf bin dist
