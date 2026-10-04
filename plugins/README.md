# Plugins

The first-party plugins. Each directory is a standalone
`bomify-plugin-<kind>` binary implementing one or more contracts:

- **Component** (`component pull|push|remote`,
  [`contracts/component/v1`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/CONTRACT.md)):
  fetches and publishes the components an SBOM describes.
- **SBOM generation** (`sbom generate`,
  [`contracts/sbom/v1`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/sbom/v1/CONTRACT.md)):
  builds an SBOM for a deployment medium.
- **Security scanning** (`security scan|supported-components`,
  [`contracts/security/v1`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/security/v1/CONTRACT.md)):
  reports the vulnerabilities a purl is affected by.
- **Signing** (`signature sign|attest|verify|verify-attestation|supported-types`,
  [`contracts/signing/v1`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/signing/v1/CONTRACT.md)):
  signs and verifies whole packages and their build provenance.

| Plugin | Handles | Built on | Contracts |
| --- | --- | --- | --- |
| [`bomify-plugin-oci`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-oci) | `pkg:oci`, `pkg:docker` | [go-containerregistry](https://github.com/google/go-containerregistry) | Component |
| [`bomify-plugin-helm`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-helm) | `pkg:helm`; Helm charts | [Helm SDK](https://pkg.go.dev/helm.sh/helm/v4/pkg/action) | Component, SBOM generation |
| [`bomify-plugin-generic`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-generic) | `pkg:generic` | `net/http` | Component |
| [`bomify-plugin-grype`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-grype) | most purl types, images, and `generic` files | [grype](https://github.com/anchore/grype) | Security scanning |
| [`bomify-plugin-sigstore`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-sigstore) | Sigstore bundles | [sigstore-go](https://github.com/sigstore/sigstore-go) | Signing |

## Contract versions

Each contract has a major version, in its spec's title (e.g. "Signing
plugin contract v1"), bumped by any change that a plugin or bomify
written for the previous version would break on. Every first-party
plugin speaks version 1 of the contracts it implements.

Each version has its own folder, holding its spec and the JSON Schemas
of its results:

```
plugins/contracts/
├── contract-result.schema.json    the "contract" command's result, below
├── component/v1/                  CONTRACT.md, result, remote-result
├── sbom/v1/                       CONTRACT.md (no results to validate)
├── security/v1/                   CONTRACT.md, security-result, supported-components-result
└── signing/v1/                    CONTRACT.md, sign-result, verify-result,
                                   verify-attestation-result, supported-signature-types-result
```

A new version is a new folder (`v2/`) alongside the old one, which
stays as the spec of what plugins speaking it still do.

Every plugin reports the versions it speaks:

```
bomify-plugin-<kind> contract
```

No flags. Print one JSON object to stdout and exit `0`; it must always
report the same thing. bomify asks before it first calls a plugin, and
refuses one that doesn't speak the version it needs, or can't answer.

```json
{ "contracts": { "component": 1, "sbom": 1 } }
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `contracts` | object | yes | Each contract the plugin implements (`component`, `sbom`, `security`, or `signing`), mapped to the major version it speaks. Contracts it doesn't implement are absent. |

Schema: [`contract-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/contract-result.schema.json).

A Go plugin gets this for free: `pkg/plugin`'s `NewRootCommand` adds
`contract`, reporting the version `pkg/plugin` implements for each
contract subcommand (`component`, `sbom`, `security`, `signature`) the
plugin registers. Other plugins implement it themselves.

## Installing plugins

bomify only looks for plugins in `<data-dir>/plugins`
(`~/.bomify/plugins` by default), never on `PATH`. Plugins are
published as bomify packages and installed with `bomify plugin install`:

```sh
bomify plugin install oci             # latest
bomify plugin install grype:1.12.0    # a specific version
bomify plugin list                    # what's installed, and from where
```

`install <name>` pulls `ghcr.io/alejandro-velasco/bomify/plugins/<name>`
(change the prefix with `--registry`) and installs the binary for your
OS and architecture, replacing any earlier install.

It only installs a plugin something vouches for, checked before
downloading:

- **A signature** verified by `bomify-plugin-sigstore` against a signer
  you trust, from a matching
  [`bomify trust`](https://alejandro-velasco.github.io/bomify/usage/reference/bomify_trust_create/)
  rule or `--verify-option` (`key=<public key>`, or
  `certificate-identity=...` plus `certificate-oidc-issuer=...`).
- **Or a digest pin**, `<name>@sha256:<digest>`, which every pulled blob
  is checked against.

Anything else is refused. Each binary must also match the SHA-256 its
SBOM declares (integrity, not authenticity). `--verify=false` skips the
signature check.

bomify's own plugins are signed keyless by its release workflow, and
each release's `plugin-digests.txt` lists their pinned references. Since
nothing can verify `bomify-plugin-sigstore` before it's installed,
install it by digest, then trust the workflow for everything else:

```sh
# The .../plugins/sigstore@sha256:... line from the release's plugin-digests.txt
bomify plugin install sigstore@sha256:<digest>

bomify trust create sigstore --match ghcr.io/alejandro-velasco/bomify/plugins \
  --option certificate-identity=https://github.com/alejandro-velasco/bomify/.github/workflows/release.yml@refs/heads/main \
  --option certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

From then on, installs from that registry, including upgrades of
`sigstore`, fail unless that workflow signed them.

Each package also carries its
[build provenance](https://alejandro-velasco.github.io/bomify/development/architecture/provenance/),
signed by the same workflow.

## Publishing a plugin

A plugin package is a bomify package whose SBOM lists the binaries as
`pkg:bomify-plugin/<kind>` components, one per platform, with `os`/`arch`
qualifiers in `GOOS`/`GOARCH` terms. `bomify build` copies each binary
from the path (or `file://` URL) in its `distribution` external
reference, relative to the SBOM. Declare each binary's SHA-256: `build`
checks it and `install` requires it. Record the contract versions it
speaks, its `contract` output's `contracts` object, as the
`land.bomify.plugin.contracts` property: `install` refuses a binary that
records none, or a version bomify doesn't speak.

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

`install` downloads only the installing machine's binary, so one package
can carry every platform. The first-party plugins are published this
way by `make plugin-packages` and `make push-plugin-packages` (see
[`hack/pluginpackages`](https://github.com/alejandro-velasco/bomify/tree/main/hack/pluginpackages)).

## bomify-plugin-oci

Pulls and pushes `pkg:oci/...` and `pkg:docker/...` images. The
reference comes from the purl's `tag` qualifier, else a digest-shaped
version, else a plain tag, else the bare repository; `repository_url`
overrides the registry address.

## bomify-plugin-helm

- **Component**: pulls from HTTP(S) chart repositories
  (`pkg:helm/<name>@<version>?repository_url=https://...`) and OCI
  registries (`repository_url=oci://...`). `push` and `push --check`
  support OCI only, since classic repositories are read-only.
- **SBOM generation**: renders a chart locally, as `helm template` does,
  and reports every image it references plus the chart itself. See
  [its README](https://github.com/alejandro-velasco/bomify/blob/main/plugins/bomify-plugin-helm/README.md)
  for flags and examples.

The Helm SDK pulls in much of `k8s.io/client-go`, so this binary is
larger than the others.

## bomify-plugin-generic

Handles `pkg:generic/<name>@<version>?download_url=<url>`: `pull` GETs
`download_url`; `push` PUTs the file to `--remote` exactly as given
(with a real `Content-Length`), which suits presigned upload URLs.
`push --check` only tries a HEAD, since a presigned URL can't be checked
without writing to it.

## bomify-plugin-grype

Scans with [grype](https://github.com/anchore/grype) as a library. Most
purl types name one package and are matched directly. An `oci`/`docker`
purl is an image, so it's cataloged with
[syft](https://github.com/anchore/syft) first and every package in it is
matched; each is returned as a component, with `evidence.occurrences`
showing where syft found it.

Matches come from grype's vulnerability database (cached where the
`grype` CLI caches it) and are converted to CycloneDX by hand. When
available, `ratings` include the [EPSS](https://www.first.org/epss/)
score and a [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
flag.

`supported-components` lists, scanned by purl, the types grype has a
matcher for (`apk`, `deb`, `rpm`, `alpm`, `bitnami`, `npm`, `golang`,
`maven`, `pypi`, `gem`, `cargo`, `nuget`, `hex`) plus `oci`/`docker`; and
`generic`, scanned from its pulled files: syft catalogs the file (a Go
or Rust binary's modules, a Java archive, a known binary's version), and
a file it finds nothing in is reported `unscanned`.

## bomify-plugin-sigstore

Signs and verifies with [sigstore-go](https://github.com/sigstore/sigstore-go),
producing v0.3 Sigstore bundles
(`application/vnd.dev.sigstore.bundle.v0.3+json`):

- **Key pair**: `--sign-option key=signing.key`, `--verify-option
  key=signing.pub`. Any PEM pair works (OpenSSL, plain or encrypted
  PKCS#8, or `cosign generate-key-pair`); an encrypted key's password
  comes from `SIGSTORE_PASSWORD`. Fully offline, which suits private
  registries and air-gapped `save`/`load`. See the
  [signing how-to](https://alejandro-velasco.github.io/bomify/how-to/signing-and-verifying-packages/).
- **Keyless**: with no `key`, signing trades an OIDC token
  (`SIGSTORE_ID_TOKEN` or `--sign-option identity-token=...`, audience
  `sigstore`) for a short-lived [Fulcio](https://github.com/sigstore/fulcio)
  certificate and logs to [Rekor](https://github.com/sigstore/rekor).
  In GitHub Actions, `permissions: id-token: write` lets a workflow sign
  as itself. Tokens last minutes, so fetch one right before signing.
  Verifying needs `certificate-identity` (or `-regexp`) and
  `certificate-oidc-issuer` (or `-regexp`), and network access to
  Sigstore's trusted root.

`signature attest` (see the
[contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/signing/v1/CONTRACT.md#signature-attest))
signs a DSSE envelope instead, in the bundle format cosign and `gh
attestation verify` read; `signature verify-attestation` verifies one
with the same options as `signature verify`.

`key` can't be combined with keyless options, and unknown options are
rejected.

## Separate Go modules

`bomify-plugin-grype` and `bomify-plugin-sigstore` are their own Go
modules, since their dependency trees would bloat every other build. They
use this repo's `pkg/plugin` through a `replace` directive, and the
`Makefile` builds, tests, and tidies them separately. A plugin with
similarly heavy dependencies should do the same.
