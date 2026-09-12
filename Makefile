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

LDFLAGS := -X bomify/internal/buildinfo.version=$(VERSION) \
		   -X bomify/internal/buildinfo.commit=$(COMMIT)   \
		   -X bomify/internal/buildinfo.date=$(DATE)       \
		   -X bomify/internal/buildinfo.goVersion=$(GO_VERSION)

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
# Build recipes
#
################################################################################

.PHONY: build build-container plugins test run tidy clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

build-container:
	$(CONTAINER_TOOL) build -f Containerfile -t $(CONTAINER_REF) .

plugins:
	go build -o bin/ ./plugins/...

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
