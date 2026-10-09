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

# A release image installs the plugins its release published, from
# PLUGIN_REGISTRY, rather than building them (see Containerfile): set
# CONTAINER_PLUGIN_VERSION to the release's version and
# CONTAINER_SIGSTORE_DIGEST to its sigstore digest from plugin-digests.txt.
# CONTAINER_PLUGIN_SIGNER is the identity that signed them.
CONTAINER_PLUGIN_VERSION ?=
CONTAINER_SIGSTORE_DIGEST ?=
CONTAINER_PLUGIN_SIGNER ?= https://github.com/alejandro-velasco/bomify/.github/workflows/release.yml@refs/heads/main

################################################################################
#
# Release build settings
#
################################################################################

DIST_DIR := dist

# GOOS/GOARCH pairs to cross-compile release binaries (and plugin packages) for.
RELEASE_PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

################################################################################
#
# Build recipes
#
################################################################################

.PHONY: build build-container push-container plugins dist plugin-packages push-plugin-packages docs diagrams docs-site-sync docs-site docs-site-serve install install-bin install-plugins test run tidy clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

build-container:
	$(CONTAINER_TOOL) build -f Containerfile \
		--build-arg PLUGIN_VERSION=$(CONTAINER_PLUGIN_VERSION) \
		--build-arg PLUGIN_REGISTRY=$(PLUGIN_REGISTRY) \
		--build-arg SIGSTORE_DIGEST=$(CONTAINER_SIGSTORE_DIGEST) \
		--build-arg PLUGIN_SIGNER=$(CONTAINER_PLUGIN_SIGNER) \
		-t $(CONTAINER_REF) .

push-container:
	$(CONTAINER_TOOL) push $(CONTAINER_REF)

# bomify-plugin-grype and bomify-plugin-sigstore are built separately:
# unlike the other first-party plugins, each is its own Go module (see
# plugins/bomify-plugin-grype/go.mod, plugins/bomify-plugin-sigstore/go.mod)
# rather than part of this one, since the grype SDK's and sigstore-go's
# transitive dependency trees (syft, stereoscope, TUF, cloud SDKs, ...)
# are large enough that pulling them into the root module's go.mod/go.sum
# would bloat every other build in this repo. "./plugins/..." from the
# root module can't see across that module boundary, so each needs its
# own build step.
SEPARATE_MODULE_PLUGINS := plugins/bomify-plugin-grype plugins/bomify-plugin-sigstore

plugins:
	go build -o bin/ ./plugins/...
	for dir in $(SEPARATE_MODULE_PLUGINS); do (cd $$dir && go build -o ../../bin/ .) || exit 1; done

# dist cross-compiles bomify (not its plugins — see plugin-packages) for
# each of RELEASE_PLATFORMS, as a bare binary per platform,
# $(DIST_DIR)/bomify-<version>-<os>-<arch>[.exe], alongside a checksums.txt
# covering all of them. See hack/dist.sh.
dist: clean
	VERSION=$(VERSION) LDFLAGS="$(LDFLAGS)" DIST_DIR=$(DIST_DIR) RELEASE_PLATFORMS="$(RELEASE_PLATFORMS)" hack/dist.sh

# PLUGIN_REGISTRY is where push-plugin-packages publishes, and "bomify
# plugin install" installs from by default: <registry>/<kind>:<version>.
PLUGIN_REGISTRY ?= ghcr.io/alejandro-velasco/bomify/plugins
PLUGIN_PACKAGES_DIR := $(DIST_DIR)/plugin-packages

# plugin-packages cross-compiles every first-party plugin for each of
# RELEASE_PLATFORMS and writes, per plugin, the binaries plus an SBOM
# describing them as pkg:bomify-plugin components under
# $(PLUGIN_PACKAGES_DIR)/<kind>/. See hack/pluginpackages.
plugin-packages:
	go run ./hack/pluginpackages -version $(VERSION) -platforms "$(RELEASE_PLATFORMS)" -out $(PLUGIN_PACKAGES_DIR)

# push-plugin-packages builds each SBOM plugin-packages wrote into a bomify
# package and pushes it as $(PLUGIN_REGISTRY)/<kind>:$(VERSION) (and
# :latest, for a release version), with its build provenance attached, and
# both signed with bomify-plugin-sigstore when
# PLUGIN_SIGN_KEYLESS=true (keyless, as the running GitHub Actions workflow)
# or PLUGIN_SIGN_KEY names a private key. Run plugin-packages first (with the
# same VERSION): it's not a dependency, so a release can build everything
# in its prepare step and only push in its publish step. Needs registry
# credentials from "bomify login" or "docker login". See
# hack/push-plugin-packages.sh.
push-plugin-packages: build
	BOMIFY=$(BINARY) VERSION=$(VERSION) PACKAGES_DIR=$(PLUGIN_PACKAGES_DIR) PLUGIN_REGISTRY=$(PLUGIN_REGISTRY) hack/push-plugin-packages.sh

# docs regenerates the CLI reference (see the --docs-dir flag in cmd/root.go).
docs:
	mkdir -p docs/reference
	go run . --docs-dir docs/reference

# diagrams renders every docs/diagrams/*.mmd source to an .svg file
# alongside it. See hack/diagrams.sh.
diagrams:
	hack/diagrams.sh

# docs-site-sync copies generated files into docsite/docs: the CLI
# reference, and the rendered diagrams the architecture pages embed (at the
# same relative path, ../diagrams/, they have in docs/). Depends on docs so
# the reference is always fresh. Hand-written docs are included live via
# pymdownx.snippets instead, never copied.
docs-site-sync: docs
	rm -rf docsite/docs/usage/reference docsite/docs/development/diagrams
	mkdir -p docsite/docs/usage/reference docsite/docs/development/diagrams
	cp docs/reference/*.md docsite/docs/usage/reference/
	cp docs/diagrams/*.svg docsite/docs/development/diagrams/

# docs-site builds the docsite/ Zensical site into docsite/site. Requires
# zensical (`pip install zensical`).
docs-site: docs-site-sync
	cd docsite && zensical build --clean

# docs-site-serve is docs-site, but for local preview via zensical's
# built-in dev server instead of a one-shot build.
docs-site-serve: docs-site-sync
	cd docsite && zensical serve

# PLUGIN_DIR is where install puts the first-party plugins: bomify only
# ever looks for plugins in <data-dir>/plugins, never on PATH, so this must
# be the plugins directory of whichever data directory bomify will run
# with (~/.bomify by default). install-plugins starts that data directory,
# versioned, if it's new (see hack/common.sh's init_data_dir).
PLUGIN_DIR ?= $(HOME)/.bomify/plugins

# install is install-bin plus install-plugins. They're separate targets so
# only install-bin (which writes to /usr/local/bin) needs sudo: running
# install-plugins as root would leave the data directory root-owned.
install: install-bin install-plugins

install-bin: build
	install -Dm755 $(BINARY) /usr/local/bin/$(notdir $(BINARY))

install-plugins: plugins
	. ./hack/common.sh && init_data_dir "$(dir $(patsubst %/,%,$(PLUGIN_DIR)))"
	install -d $(PLUGIN_DIR)
	install -m755 bin/bomify-plugin-* $(PLUGIN_DIR)/
	# Alias bomify-plugin-oci to bomify-plugin-docker for backward compatibility
	ln -sf bomify-plugin-oci $(PLUGIN_DIR)/bomify-plugin-docker

test:
	go test ./...
	for dir in $(SEPARATE_MODULE_PLUGINS); do (cd $$dir && go test ./...) || exit 1; done

run: build
	./$(BINARY)

tidy:
	go mod tidy
	for dir in $(SEPARATE_MODULE_PLUGINS); do (cd $$dir && go mod tidy) || exit 1; done

clean:
	rm -rf bin dist
