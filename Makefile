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

# The platform the image is built for, and its prebuilt bomify and plugins
# (see container-prebuilt).
CONTAINER_PLATFORM ?= linux/amd64

# CONTAINER_BOMIFY_DIR holds the bomify binary the image takes (see
# container-bomify).
CONTAINER_BOMIFY_DIR ?= $(DIST_DIR)/container

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

.PHONY: build build-container container-prebuilt container-bomify container-plugins push-container plugins go-plugins dist prebuilt-plugins prebuilt-go-plugins plugin-packages push-plugin-packages docs diagrams docs-site-sync docs-site docs-site-serve install install-bin install-plugins test test-go tidy clean

# build builds bomify for this machine, statically (CGO_ENABLED=0), as a
# release does (see dist), so it runs anywhere a release's does, the
# container image included (see .github/workflows/build.yml).
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

# build-container builds the image, compiling nothing: bomify from
# CONTAINER_BOMIFY_DIR, and plugins that are the ones a release published,
# given CONTAINER_PLUGIN_VERSION, otherwise this checkout's, from
# PREBUILT_PLUGINS_DIR. Run container-prebuilt first (CI downloads what
# its build and build-plugins jobs built instead).
build-container:
	$(CONTAINER_TOOL) build -f Containerfile \
		--platform $(CONTAINER_PLATFORM) \
		--build-context bomify=$(CONTAINER_BOMIFY_DIR) \
		--build-arg PLUGINS=$(if $(CONTAINER_PLUGIN_VERSION),release,prebuilt) \
		$(if $(CONTAINER_PLUGIN_VERSION),,--build-context prebuilt-plugins=$(PREBUILT_PLUGINS_DIR)) \
		--build-arg PLUGIN_VERSION=$(CONTAINER_PLUGIN_VERSION) \
		--build-arg PLUGIN_REGISTRY=$(PLUGIN_REGISTRY) \
		--build-arg SIGSTORE_DIGEST=$(CONTAINER_SIGSTORE_DIGEST) \
		--build-arg PLUGIN_SIGNER=$(CONTAINER_PLUGIN_SIGNER) \
		-t $(CONTAINER_REF) .

# container-prebuilt builds what build-container takes for an image of
# this checkout: container-bomify and container-plugins.
container-prebuilt: container-bomify container-plugins

# container-bomify builds bomify for CONTAINER_PLATFORM into
# CONTAINER_BOMIFY_DIR, statically, as build does, but for the image's
# platform, which this machine's may not be. CI uses build's binary instead,
# built on a linux/amd64 runner.
container-bomify:
	GOOS=$(word 1,$(subst /, ,$(CONTAINER_PLATFORM))) GOARCH=$(word 2,$(subst /, ,$(CONTAINER_PLATFORM))) CGO_ENABLED=0 \
		go build -ldflags "$(LDFLAGS)" -o $(CONTAINER_BOMIFY_DIR)/bomify .

# container-plugins builds every plugin for CONTAINER_PLATFORM into
# PREBUILT_PLUGINS_DIR, statically, for build-container.
container-plugins:
	$(MAKE) prebuilt-plugins RELEASE_PLATFORMS=$(CONTAINER_PLATFORM)

push-container:
	$(CONTAINER_TOOL) push $(CONTAINER_REF)

# A plugin's language is named by the manifest in its directory, and each
# language's plugins are found, built, and tested by it, built by a
# hack/build-<lang>-plugins.sh script into the layout
# <dir>/<kind>/<os>-<arch>/bomify-plugin-<kind>[.exe]. A plugin in a new
# language adds its own <LANG>_PLUGINS, script, and targets here, and a job
# in .github/workflows/plugins.yml (see plugins/README.md#plugin-languages).
#
# Go: each plugin is its own module (a go.mod of its own), using this
# one's pkg/ through a replace directive, so its dependencies (the Helm
# SDK, syft, sigstore-go, ...) stay out of bomify's go.mod and every
# other plugin's.
GO_PLUGINS := $(patsubst %/,%,$(dir $(wildcard plugins/bomify-plugin-*/go.mod)))

# This machine's platform, and where plugins builds its plugins for it.
HOST_PLATFORM := $(shell go env GOOS)/$(shell go env GOARCH)
PLUGIN_BUILD_DIR := $(DIST_DIR)/plugins

# plugins builds every plugin for this machine into bin/, one target per
# plugin (plugin-<kind>), so `make -j plugins` builds them in parallel.
GO_PLUGIN_TARGETS := $(patsubst plugins/bomify-plugin-%,plugin-%,$(GO_PLUGINS))
.PHONY: $(GO_PLUGIN_TARGETS)

plugins: go-plugins
go-plugins: $(GO_PLUGIN_TARGETS)

$(GO_PLUGIN_TARGETS): plugin-%:
	OUT_DIR=$(PLUGIN_BUILD_DIR) PLUGINS=plugins/bomify-plugin-$* hack/build-go-plugins.sh
	mkdir -p bin && cp $(PLUGIN_BUILD_DIR)/$*/$(subst /,-,$(HOST_PLATFORM))/* bin/

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

# PREBUILT_PLUGINS_DIR holds every first-party plugin's release binaries
# (static) for each of RELEASE_PLATFORMS, as
# <kind>/<os>-<arch>/bomify-plugin-<kind>[.exe], for plugin-packages.
PREBUILT_PLUGINS_DIR ?= $(DIST_DIR)/prebuilt-plugins

# prebuilt-plugins builds every plugin's release binaries into
# PREBUILT_PLUGINS_DIR: each Go plugin for each of RELEASE_PLATFORMS.
# GO_PLUGINS set on the command line builds only those; set empty, none.
prebuilt-plugins: prebuilt-go-plugins

prebuilt-go-plugins:
	$(if $(GO_PLUGINS),OUT_DIR=$(PREBUILT_PLUGINS_DIR) PLATFORMS="$(RELEASE_PLATFORMS)" PLUGINS="$(GO_PLUGINS)" hack/build-go-plugins.sh)

# plugin-packages writes, per plugin, its binaries from PREBUILT_PLUGINS_DIR
# plus an SBOM describing them as pkg:bomify-plugin components under
# $(PLUGIN_PACKAGES_DIR)/<kind>/, compiling nothing. See hack/pluginpackages.
plugin-packages:
	go run ./hack/pluginpackages -version $(VERSION) -platforms "$(RELEASE_PLATFORMS)" -prebuilt $(PREBUILT_PLUGINS_DIR) -out $(PLUGIN_PACKAGES_DIR)

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

# BOMIFY_DATA_DIR is the data directory install puts the first-party
# plugins into, as bomify only ever looks for plugins in <data-dir>/plugins,
# never on PATH: the one bomify itself uses, ~/.bomify unless
# BOMIFY_DATA_DIR is set (see hack/install-plugins.sh).
BOMIFY_DATA_DIR ?= $(HOME)/.bomify

# install is install-bin plus install-plugins. They're separate targets so
# only install-bin (which writes to /usr/local/bin) needs sudo: running
# install-plugins as root would leave the data directory root-owned.
install: install-bin install-plugins

install-bin: build
	install -Dm755 $(BINARY) /usr/local/bin/$(notdir $(BINARY))

install-plugins: plugins
	BOMIFY_DATA_DIR="$(BOMIFY_DATA_DIR)" bash hack/install-plugins.sh

test: test-go

test-go:
	go test ./...
	for dir in $(GO_PLUGINS); do (cd $$dir && go test ./...) || exit 1; done

tidy:
	go mod tidy
	for dir in $(GO_PLUGINS); do (cd $$dir && go mod tidy) || exit 1; done

clean:
	rm -rf bin dist
