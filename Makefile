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
CONTAINER_REGISTRY ?= ghcr.io
CONTAINER_REPO ?= alejandro-velasco/bomify
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

.PHONY: build build-container push-container plugins dist docs diagrams docs-site-sync docs-site docs-site-serve test run tidy clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

build-container:
	$(CONTAINER_TOOL) build -f Containerfile -t $(CONTAINER_REF) .

push-container:
	$(CONTAINER_TOOL) push $(CONTAINER_REF)

# bomify-plugin-grype is built separately: unlike the other first-party
# plugins, it's its own Go module (see plugins/bomify-plugin-grype/go.mod)
# rather than part of this one, since the grype SDK's transitive
# dependency tree (syft, stereoscope, cloud SDKs, ...) is large enough
# that pulling it into the root module's go.mod/go.sum would bloat every
# other build in this repo. "./plugins/..." from the root module can't
# see across that module boundary, so it needs its own build step.
plugins:
	go build -o bin/ ./plugins/...
	cd plugins/bomify-plugin-grype && go build -o ../../bin/ .

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

# docs-site-sync copies the generated CLI reference into docsite/docs, so
# there's exactly one source of truth for it, never hand-edited under
# docsite/. Depends on docs so it's always fresh. (plugins/README.md is
# included live into docsite/docs/getting-started/installing-plugins.md via
# a pymdownx.snippets directive instead — no copy needed for that one.)
docs-site-sync: docs
	rm -rf docsite/docs/usage/reference
	mkdir -p docsite/docs/usage/reference
	cp docs/reference/*.md docsite/docs/usage/reference/

# docs-site builds the docsite/ Zensical site into docsite/site. Requires
# zensical (`pip install zensical`).
docs-site: docs-site-sync
	cd docsite && zensical build --clean

# docs-site-serve is docs-site, but for local preview via zensical's
# built-in dev server instead of a one-shot build.
docs-site-serve: docs-site-sync
	cd docsite && zensical serve

install: build plugins
	install -Dm755 $(BINARY) /usr/local/bin/$(notdir $(BINARY))
	install -Dm755 bin/bomify-plugin-* /usr/local/bin/
	# Alias bomify-plugin-oci to bomify-plugin-docker for backward compatibility
	ln -sf /usr/local/bin/bomify-plugin-oci /usr/local/bin/bomify-plugin-docker

test:
	go test ./...
	cd plugins/bomify-plugin-grype && go test ./...

run: build
	./$(BINARY)

tidy:
	go mod tidy
	cd plugins/bomify-plugin-grype && go mod tidy

clean:
	rm -rf bin dist
