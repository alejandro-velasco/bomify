# Plugins

This directory holds bomify's first-party plugins. Each one is a
standalone `bomify-plugin-<kind>` binary that implements one or more
contracts:

- **Component** (`component pull|pack`,
  [`contracts/component/v1`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/CONTRACT.md)):
  fetches the components an SBOM describes, and describes each one in its
  kind's registry format for a package's index.
- **SBOM generation** (`sbom generate`,
  [`contracts/sbom/v1`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/sbom/v1/CONTRACT.md)):
  builds an SBOM for a deployment medium, such as a Helm chart.
- **Security scanning** (`security scan|supported-components`,
  [`contracts/security/v1`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/security/v1/CONTRACT.md)):
  reports the vulnerabilities that affect a purl.
- **Signing** (`signature sign|attest|verify|verify-attestation|supported-types`,
  [`contracts/signing/v1`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/signing/v1/CONTRACT.md)):
  signs and verifies whole packages and their build provenance.
- **Deployment** (`deployment generate`,
  [`contracts/deployment/v1`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/deployment/v1/CONTRACT.md)):
  turns a package in a registry into what a deployment tool deploys,
  such as Helm values pinning its images by digest.

| Plugin | Handles | Built on | Contracts |
| --- | --- | --- | --- |
| [`bomify-plugin-oci`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-oci) | Images and other OCI artifacts (`pkg:oci`, `pkg:docker`) | [go-containerregistry](https://github.com/google/go-containerregistry) | Component |
| [`bomify-plugin-helm`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-helm) | Helm charts (`pkg:helm`) | [Helm SDK](https://pkg.go.dev/helm.sh/helm/v4/pkg/action) | Component, SBOM generation, deployment |
| [`bomify-plugin-generic`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-generic) | Files downloaded from a URL (`pkg:generic`) | `net/http` | Component |
| [`bomify-plugin-huggingface`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-huggingface) | Hugging Face Hub models (`pkg:huggingface`) | [hf-hub](https://github.com/huggingface/hf-hub), Hugging Face's Rust client for the Hub and [Xet](https://huggingface.co/docs/xet) | Component, SBOM generation |
| [`bomify-plugin-grype`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-grype) | Most purl types, images, and `generic` files | [grype](https://github.com/anchore/grype) | Security scanning |
| [`bomify-plugin-sigstore`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-sigstore) | Sigstore bundles, in cosign's format | [sigstore-go](https://github.com/sigstore/sigstore-go) | Signing |

## Contract versions

Each contract has a major version, shown in its spec's title (for
example, "Signing plugin contract v1"). Every first-party plugin speaks
version 1 of the contracts it implements. The contracts are stable
since the beta, and change only where they must:

- **Compatible:** adding an optional result field, or a command bomify
  only calls on a plugin that offers it, keeps the version. Plugins and
  bomify releases written before the change ignore it.
- **Breaking:** anything else, including a new flag bomify passes every
  plugin, which a plugin written before it rejects as unknown. It keeps
  the version too, every first-party plugin is updated in the same
  change, and the release notes call it out. A new major version is for
  a change bomify must tell apart: bomify refuses a plugin that doesn't
  speak the version it needs (see below).

Each version has its own folder, holding its spec and the JSON Schemas
of its results:

```
plugins/contracts/
├── contract-result.schema.json    the "contract" command's result, below
├── component/v1/                  CONTRACT.md, result, pack-result
├── sbom/v1/                       CONTRACT.md, generate-output
├── security/v1/                   CONTRACT.md, security-result, supported-components-result
├── signing/v1/                    CONTRACT.md, sign-result, verify-result,
│                                  verify-attestation-result, supported-signature-types-result
└── deployment/v1/                 CONTRACT.md, package, deployment-result
```

A new major version gets a new folder (`v2/`) next to the old one. The
old folder stays as the spec for plugins that still speak it.

Every plugin reports the versions it speaks when asked:

```
bomify-plugin-<kind> contract
```

The command takes no flags. It prints one JSON object to stdout, exits
`0`, and always reports the same thing. bomify asks before it first
calls a plugin, and refuses a plugin that can't answer or doesn't speak
the version it needs.

```json
{ "contracts": { "component": 1, "sbom": 1 } }
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `contracts` | object | yes | Each contract the plugin implements (`component`, `sbom`, `security`, or `signing`), mapped to the major version it speaks. Contracts it doesn't implement are left out. |

Schema: [`contract-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/contract-result.schema.json).

A Go plugin gets this for free: `pkg/plugin`'s `NewRootCommand` adds the
`contract` command and reports the version `pkg/plugin` implements for
each contract subcommand (`component`, `sbom`, `security`, `signature`)
the plugin registers. Plugins in other languages implement it
themselves.

## Installing plugins

bomify looks for plugins only in `<data-dir>/plugins`
(`~/.bomify/plugins` by default), never on your `PATH`. Plugins are
published as bomify packages, and you install them with `bomify plugin
install`:

```sh
bomify plugin install oci             # the latest version
bomify plugin install grype:1.12.0    # a specific version
bomify plugin list                    # what's installed, and where it came from
```

`install <name>` pulls `ghcr.io/alejandro-velasco/bomify/plugins/<name>`
(use `--registry` to change the prefix) and installs the binary for your
OS and architecture, replacing any earlier install.

bomify only installs a plugin it can vouch for, and it checks before
downloading anything. The plugin needs one of:

- **A signature** that `bomify-plugin-sigstore` verifies against a
  signer you trust, from a matching
  [`bomify trust`](https://alejandro-velasco.github.io/bomify/usage/reference/bomify_trust_create/)
  rule or from `--verify-option` (`key=<public key>`, or
  `certificate-identity=...` plus `certificate-oidc-issuer=...`).
- **A digest pin**, `<name>@sha256:<digest>`, which every downloaded
  blob is checked against.

Anything else is refused. Each binary must also match the SHA-256 its
SBOM declares; that checks integrity, not who published it.
`--verify=false` skips the signature check.

bomify's own plugins are signed keyless by its release workflow, and
each release's `plugin-digests.txt` lists their pinned references.
Nothing can verify `bomify-plugin-sigstore` before it's installed, so
install it by digest first, then trust the workflow for everything
else:

```sh
# The .../plugins/sigstore@sha256:... line from the release's plugin-digests.txt
bomify plugin install sigstore@sha256:<digest>

bomify trust create sigstore --match ghcr.io/alejandro-velasco/bomify/plugins \
  --option certificate-identity=https://github.com/alejandro-velasco/bomify/.github/workflows/release.yml@refs/heads/main \
  --option certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

From then on, every install from that registry, including upgrades of
`sigstore` itself, fails unless that workflow signed it.

Each package also carries its
[build provenance](https://alejandro-velasco.github.io/bomify/development/architecture/provenance/),
signed by the same workflow.

## Publishing a plugin

A plugin package is an ordinary bomify package whose SBOM lists the
plugin's binaries, one component per platform:

- **Purl:** `pkg:bomify-plugin/<kind>@<version>`, with `os` and `arch`
  qualifiers in Go's `GOOS`/`GOARCH` terms.
- **Binary:** the path (or `file://` URL) in its `distribution` external
  reference, relative to the SBOM. `bomify build` copies it from there.
- **Hash:** the binary's SHA-256. `build` checks it, and `install`
  requires it.
- **Contracts:** the `contracts` object from the binary's `contract`
  output, recorded as its `land.bomify.plugin.contracts` property.
  `install` refuses a binary that records none, or a version bomify
  doesn't speak.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "bomify-plugin-mykind",
      "version": "v1.0.0",
      "purl": "pkg:bomify-plugin/mykind@v1.0.0?os=linux&arch=amd64",
      "hashes": [{ "alg": "SHA-256", "content": "<sha256 of the binary>" }],
      "properties": [{ "name": "land.bomify.plugin.contracts", "value": "{\"component\":1}" }],
      "externalReferences": [{ "type": "distribution", "url": "dist/linux-amd64/bomify-plugin-mykind" }]
    }
  ]
}
```

```sh
bomify build plugin.cdx.json --tag registry.example.com/plugins/mykind:v1.0.0
bomify push registry.example.com/plugins/mykind:v1.0.0 --sign sigstore --sign-option key=signing.key
bomify plugin install mykind:v1.0.0 --registry registry.example.com/plugins --verify-option key=signing.pub
```

`install` downloads only the binary for the machine it runs on, so one
package can carry every platform. The first-party plugins are published
this way, by `make plugin-packages` and `make push-plugin-packages` (see
[`hack/pluginpackages`](https://github.com/alejandro-velasco/bomify/tree/main/hack/pluginpackages)).

## bomify-plugin-oci

Pulls images, `pkg:oci/...` and `pkg:docker/...`. It builds the
reference from the purl, using the first of these it has:

1. the `tag` qualifier;
2. a version that's a digest (`sha256:...`);
3. a version, as a tag;
4. otherwise, just the repository.

A `repository_url` qualifier overrides the registry address. `pack`
describes the image exactly as it was pulled, so it keeps its digest in
a package.

Models published as OCI artifacts rather than images work the same way,
as `pkg:oci` components:

- [ModelPack](https://github.com/modelpack/model-spec) artifacts;
- [KitOps](https://kitops.org) ModelKits;
- Docker Model Runner models.

Their manifests are kept as they are, whatever their config, so the
model's own tool, such as `modctl` or `kit`, pulls it from the package's
component repository. See
[packaging a model with its serving stack](https://alejandro-velasco.github.io/bomify/how-to/packaging-a-model-with-its-serving-stack/).

## bomify-plugin-helm

- **Component:** pulls charts from HTTP(S) chart repositories
  (`pkg:helm/<name>@<version>?repository_url=https://...`) and from OCI
  registries (`repository_url=oci://...`), and packs each chart the way
  `helm push` stores one.
- **SBOM generation:** renders a chart locally, as `helm template` does,
  and reports the chart plus every image it references. See
  [its README](https://github.com/alejandro-velasco/bomify/blob/main/plugins/bomify-plugin-helm/README.md)
  for flags and examples.

The Helm SDK pulls in much of `k8s.io/client-go`, so this binary is
larger than the others.

## bomify-plugin-generic

Handles `pkg:generic/<name>@<version>?download_url=<url>`: `pull`
downloads the file at `download_url`. A plain file has no registry
format of its own, so a package holds it in bomify's own format.

## bomify-plugin-huggingface

- **Component:** pulls a [Hugging Face Hub](https://huggingface.co)
  model repository at a commit
  (`pkg:huggingface/<namespace>/<name>@<commit>`; a `repository_url`
  qualifier points at another hub). It doesn't pack anything itself:
  bomify packages the model as
  [ModelPack](https://github.com/modelpack/model-spec).
- **SBOM generation:** describes a model as a `machine-learning-model`
  component pinned to a commit, with its hash and a model card built
  from the Hub's metadata, without downloading the weights. See
  [its README](https://github.com/alejandro-velasco/bomify/blob/main/plugins/bomify-plugin-huggingface/README.md)
  for options, authentication, and examples.

It's written in Rust, on Hugging Face's own
[hf-hub](https://github.com/huggingface/hf-hub) client (see
[Plugin languages](#plugin-languages)).

## bomify-plugin-grype

Scans with [grype](https://github.com/anchore/grype), used as a library:

- **A purl that names one package**, as most types do, is matched
  directly.
- **An image** (an `oci` or `docker` purl) is cataloged with
  [syft](https://github.com/anchore/syft) first, and every package in it
  is matched. Each comes back as a component, with
  `evidence.occurrences` showing where syft found it.

Matches come from grype's vulnerability database, cached where the
`grype` CLI caches it, and the plugin converts them to CycloneDX. Where
available, `ratings` include the [EPSS](https://www.first.org/epss/)
score and a
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
flag.

`supported-components` lists what it can scan:

- **By purl:** `oci`, `docker`, and the types grype has a matcher for:
  `apk`, `deb`, `rpm`, `alpm`, `bitnami`, `npm`, `golang`, `maven`,
  `pypi`, `gem`, `cargo`, `nuget`, and `hex`.
- **From pulled files:** `generic`. syft catalogs the file, finding:
    - a Go or Rust binary's modules;
    - a Java archive's contents;
    - a known binary's version.

    A file it finds nothing in is reported `unscanned`.

## bomify-plugin-sigstore

Signs and verifies with
[sigstore-go](https://github.com/sigstore/sigstore-go), in the same
format cosign 3 uses. That means `cosign verify` accepts the signatures
this plugin makes, and this plugin accepts the ones `cosign sign` makes.

A signature is a v0.3 Sigstore bundle
(`application/vnd.dev.sigstore.bundle.v0.3+json`) holding a DSSE
envelope. The envelope signs an in-toto statement whose subject is the
signed manifest's digest, with cosign's predicate type,
`https://sigstore.dev/cosign/sign/v1`. Verifying requires that
predicate type, so no other attestation counts as a signature.

It signs in one of two ways:

- **With a key pair:**
    - `--sign-option key=signing.key` signs, and `--verify-option
      key=signing.pub` verifies.
    - Any PEM pair works: OpenSSL, plain or encrypted PKCS#8, or
      `cosign generate-key-pair`.
    - An encrypted key's password comes from `SIGSTORE_PASSWORD`.
    - Nothing goes over the network, which suits private registries and
      air-gapped `save`/`load`.

    See the
    [signing how-to](https://alejandro-velasco.github.io/bomify/how-to/signing-and-verifying-packages/).
- **Keyless,** with no `key`:
    - The plugin trades an OIDC token for a short-lived
      [Fulcio](https://github.com/sigstore/fulcio) certificate, and logs
      the signature to [Rekor](https://github.com/sigstore/rekor).
    - The token comes from `SIGSTORE_ID_TOKEN` or `--sign-option
      identity-token=...`, with the audience `sigstore`. Tokens last only
      minutes, so fetch one right before signing.
    - In GitHub Actions, `permissions: id-token: write` lets a workflow
      sign as itself.
    - Verifying needs `certificate-identity` (or `-regexp`),
      `certificate-oidc-issuer` (or `-regexp`), and network access to
      Sigstore's trusted root.

`signature attest` (see the
[contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/signing/v1/CONTRACT.md#signature-attest))
signs a DSSE envelope of the statement it's given, in the bundle format
cosign and `gh attestation verify` read. `signature verify-attestation`
verifies one, with the same options as `signature verify`.

`key` can't be combined with keyless options, and unknown options are
rejected.

## Plugin languages

The manifest in a first-party plugin's directory (`go.mod` or
`Cargo.toml`) says what language it's written in. Everything that
builds plugins goes by that:

- the `Makefile` (`GO_PLUGINS`, `RUST_PLUGINS`);
- [`plugins.yml`](https://github.com/alejandro-velasco/bomify/blob/main/.github/workflows/plugins.yml);
- CodeQL and Dependabot.

Each language has a build script, `hack/build-<lang>-plugins.sh`. It
writes binaries laid out as
`<dir>/<kind>/<os>-<arch>/bomify-plugin-<kind>[.exe]`: for this machine
by default, or statically for a release when given `PLATFORMS`. CI and
the `Makefile` both build through it, and it works the same locally.

- **Go** (a `go.mod`): every Go plugin is its own module. It uses this
  repo's `pkg/` through a `replace` directive, so its dependencies stay
  out of bomify's `go.mod` and every other plugin's.
- **Rust** (a `Cargo.toml`): `bomify-plugin-huggingface` is a Rust
  crate, because Hugging Face's own client for the Hub and Xet storage,
  [hf-hub](https://github.com/huggingface/hf-hub), is written in Rust.
  Without `pkg/plugin`, it does itself what Go plugins get for free:
    - its contracts' flags, results, and logging;
    - reading `bomify login`'s credentials from bomify's `auth.json` and
      Docker's credential helpers.

    So a contract change has to be made there too. Its
    `rust-toolchain.toml` pins the toolchain, and a static Linux build
    needs `musl-tools`.

| Target | What it does |
| --- | --- |
| `make plugins` (or `make plugin-<kind>`) | Builds every plugin (or one) for this machine into `bin/`; `-j` builds them in parallel. |
| `make test` | `test-go` runs each Go module's tests; `test-rust` checks each crate's formatting and lints, and runs its tests. |
| `make prebuilt-plugins` | Builds release binaries into `PREBUILT_PLUGINS_DIR`: each Go plugin for every platform, and each Rust one for `RUST_PLATFORMS` (this machine's by default, since Rust can't cross-compile to every platform from one). |
| `make plugin-packages` | Packages them all from `PREBUILT_PLUGINS_DIR`, compiling nothing. |

Every plugin is built before it's packaged:

- **CI:** `plugins.yml` builds each plugin in a job of its own, the Rust
  ones on each platform's own runner. Outside a release, Rust builds
  only for `linux/amd64`, unless something Rust-related changed.
- **Release:** it packages what those jobs built, so the job that signs
  compiles nothing.
- **Container image:** it takes the plugins prebuilt too. CI gives it
  the `linux/amd64` binaries `build-plugins` built, and locally `make
  container-prebuilt` builds them (see the
  [README](https://github.com/alejandro-velasco/bomify/blob/main/README.md#container)).

Adding a plugin in another language takes:

- a `hack/build-<lang>-plugins.sh` that writes the same layout;
- `<LANG>_PLUGINS`, build, and test targets in the `Makefile`;
- a job in `plugins.yml` that uploads `plugins-<lang>-...` artifacts;
- CodeQL and Dependabot entries, where they support the language.

Packaging and the container image need nothing new.
