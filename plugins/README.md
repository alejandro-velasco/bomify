# Plugins

The following are plugins created and supported by the bomify project itself, as opposed to
third-party plugins a user might install separately. Each subdirectory here
is a standalone `bomify-plugin-<kind>` binary implementing at least one of the following plugin classes:

- **Component plugins**
(`component push|pull|remote`, specified in
[`COMPONENT-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/COMPONENT-CONTRACT.md))
- **SBOM generation plugins**
(`sbom generate`, specified in
[`SBOM-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SBOM-CONTRACT.md))
inspect a deployment medium and build a fresh SBOM for it. 
- **Security scanning plugins** (`security scan|supported-components`, specified in
[`SECURITY-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SECURITY-CONTRACT.md))
report the vulnerabilities one component's purl is affected by; `bomify
security scan` calls the same plugin once per component in a built
package (concurrently, like `bomify build`/`bomify distribute`) and
records each result as that component's own vulnerability report.
- **Signing plugins** (`signature sign|verify|supported-types`, specified in
[`SIGNING-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SIGNING-CONTRACT.md))
sign a whole package on `bomify push --sign`/`bomify save --sign`, and
verify it on `bomify pull --verify`/`bomify load --verify` (or when a
`bomify trust` rule requires it); bomify stores each signature as an OCI
referrer of the package, so the plugin never touches a registry.

| Plugin                                        | Kind     | Backing library                                                                   | Contracts Implemented |
|------------------------------------------------|----------|-------------------------------------------------------------------------------------|-------------------------|
| [`bomify-plugin-oci`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-oci)     | `oci`    | [Crane Golang SDK](https://github.com/google/go-containerregistry)   | <ul><li>COMPONENT-CONTRACT.md</li></ul> |
| [`bomify-plugin-helm`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-helm)   | `helm`   | [Helm Golang SDK](https://pkg.go.dev/helm.sh/helm/v4/pkg/action) (Pull/Push, the same code behind the `helm` CLI) | <ul><li>COMPONENT-CONTRACT.md</li><li>SBOM-CONTRACT</li></ul> |
| [`bomify-plugin-generic`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-generic) | `generic` | stdlib `net/http` only — a plain GET on pull, PUT on push | <ul><li>COMPONENT-CONTRACT.md</li></ul> |
| [`bomify-plugin-grype`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-grype) | see `security supported-components` | [https://github.com/anchore/grype](Grype Golang SDK) | <ul><li>SECURITY-CONTRACT.md</li></ul> |
| [`bomify-plugin-sigstore`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-sigstore) | `sigstore` | [sigstore-go](https://github.com/sigstore/sigstore-go) (Sigstore bundle v0.3) | <ul><li>SIGNING-CONTRACT.md</li></ul> |

## Installing plugins

bomify only ever looks for a plugin in its plugins directory,
`<data-dir>/plugins` (`~/.bomify/plugins` by default) — never on `PATH`.
Plugins are distributed as bomify packages in an OCI registry, and
`bomify plugin install` puts them there:

```sh
# Install the latest bomify-plugin-oci
bomify plugin install oci

# Install a specific version
bomify plugin install grype:1.12.0

# See what's installed, and where each plugin came from
bomify plugin list
```

`bomify plugin install <name>` pulls
`ghcr.io/alejandro-velasco/bomify/plugins/<name>:latest` (`--registry`
points it at another repository prefix; `<name>:<version>` or
`<name>@sha256:...` picks a specific one) and installs the plugin binary
built for your OS and architecture, replacing any earlier install of the
same plugin.

By default every install is verified: each binary must match the SHA-256
the package's SBOM declares for it, and the package's signature is
checked by `bomify-plugin-sigstore` against a public key you trust —
from a matching [`bomify trust`](https://alejandro-velasco.github.io/bomify/usage/reference/bomify_trust_create/)
rule, or given directly with `--verify-option key=<public key>`. With
no key configured (and always for the very first install of
`bomify-plugin-sigstore` itself, which has nothing to verify it yet),
only checksums are verified, with a warning. `--verify=false` skips
verification altogether.

## Publishing a plugin

A plugin package is an ordinary bomify package whose SBOM describes
the plugin's binaries as `pkg:bomify-plugin/<kind>` components — one per
platform, told apart by `os`/`arch` qualifiers (in `GOOS`/`GOARCH`
terms). `bomify build` handles these itself rather than through a
plugin: it copies each binary from the local path (or `file://` URL) in
the component's `distribution` external reference, resolved against the
SBOM's own directory. Declare each binary's SHA-256 too — `bomify build`
checks it, and `bomify plugin install` requires it by default:

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
      "externalReferences": [{ "type": "distribution", "url": "dist/linux-amd64/bomify-plugin-mykind" }]
    }
  ]
}
```

Then build, push, and (ideally) sign it like any other package:

```sh
bomify build plugin.cdx.json --tag registry.example.com/plugins/mykind:v1.0.0
bomify push registry.example.com/plugins/mykind:v1.0.0 --sign sigstore --sign-option key=signing.key
```

and install it with
`bomify plugin install mykind:v1.0.0 --registry registry.example.com/plugins --verify-option key=signing.pub`.
`install` downloads only the binaries built for the installing
machine, so one package carrying every platform's build costs nothing
extra to install.

The first-party plugins are published exactly this way on every
release, one package per plugin, by `make plugin-packages` (cross-compile
every plugin and write its SBOM, under `dist/plugin-packages/<kind>/`)
followed by `make push-plugin-packages` (build and push each, as
`<version>` and `latest`); see
[`hack/pluginpackages`](https://github.com/alejandro-velasco/bomify/tree/main/hack/pluginpackages).

## bomify-plugin-oci

[`bomify-plugin-oci`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-oci)
implements the component contract's `component pull`/`push`/`remote` for
`pkg:oci/...`/`pkg:docker/...` purls, using the
[Crane Golang SDK](https://github.com/google/go-containerregistry) to talk
to OCI registries. It resolves a purl's reference by preferring its `tag`
qualifier, then a digest-shaped version, then a plain tag, and finally the
bare repository when there's no version at all; `repository_url` (if
present) overrides the purl's own namespace/name as the registry address.

## bomify-plugin-helm

[`bomify-plugin-helm`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-helm)
implements both the component contract and the independent SBOM
generation contract.

### Component Pull/Push

`component pull` supports both classic HTTP(S)
chart repositories (`pkg:helm/<name>@<version>?repository_url=https://...`)
and OCI registries (`repository_url=oci://...`). Its `component push`
only supports OCI — Helm's SDK has no upload path for a classic chart
repository, since those are just static, read-only `index.yaml` listings.
Its `component push --check` is OCI-only for the same reason, same as
`push` itself (see
[`COMPONENT-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/COMPONENT-CONTRACT.md#check-mode)).

### SBOM Generation

`sbom generate` renders a chart's templates locally via the Helm SDK
(the same code path as `helm template`, never touching a real cluster)
and reports every container image it references — plus the chart
itself — as a CycloneDX SBOM. See
[its own README](bomify-plugin-helm/README.md) for its flags, manifest
file, and worked examples, and
[`SBOM-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SBOM-CONTRACT.md)
for the contract this and any other SBOM generation plugin must follow.

Note `helm.sh/helm/v4` is a very large dependency (it pulls in most of
`k8s.io/client-go` transitively), so this plugin's binary is
correspondingly larger than the others.

## bomify-plugin-generic

[`bomify-plugin-generic`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-generic)
handles the package-url spec's own catch-all
`generic` type: `pkg:generic/<name>@<version>?download_url=<url>`. `pull`
GETs `download_url` as-is; `push` PUTs the file a prior pull wrote,
sending it to `--remote` exactly as given (with a correct
`Content-Length`, not chunked) — useful for destinations like a presigned
upload URL, where appending anything to `--remote` would invalidate it.
Its `component push --check` is best-effort only (a HEAD, never a real
PUT — see its own doc comment on `CheckPush`), since a presigned upload
URL can't be verified without actually writing to it (see
[`COMPONENT-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/COMPONENT-CONTRACT.md#check-mode)).

## bomify-plugin-grype

[`bomify-plugin-grype`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-grype)
implements the [security scanning contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SECURITY-CONTRACT.md)
(`security scan --purl <purl>` / `security supported-components`) using
[Anchore's grype](https://github.com/anchore/grype) as a Go library. Most
purl types (`npm`, `maven`, `apk`, ...) name one specific package, so
`grype/pkg.Provide` resolves it directly with no cataloging. An
`oci`/`docker` purl names a whole image instead, so for those two types
only, the plugin first catalogs it via [Anchore's syft](https://github.com/anchore/syft)
(the same code path `grype <image>` itself uses), then matches every
package found.

### Vulnerability Matching/Conversion

Matches are checked against grype's own vulnerability database (cached
the same way and location the `grype` CLI uses) and hand-converted into
CycloneDX `vulnerability` objects — never via grype's own deprecated
CycloneDX presenter. Each vulnerability's `ratings` also include, when
grype's database has them, [FIRST's EPSS score](https://www.first.org/epss/)
and a [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
flag, as extra `ratings` entries with a free-text `method`
(`"EPSS"`/`"other"`), the same way grype's own presenter reports them.

### Nested Component Reporting

For `oci`/`docker` scans, every cataloged package is reported as a
`SecurityResult` component — `bomify security scan` only keeps the ones
some `affects` actually names as top-level components of the image's
vulnerability report (the image itself being the report's metadata
component); a cataloged package nothing was found in doesn't make it
into the report — with `affects` pointing at the specific package and
`evidence.occurrences` tracing back to where syft found it — an
apk/dpkg entry, a `package.json`, a jar on disk, ...

### Supported Components

`security supported-components` lists the purl types grype has a
dedicated matcher for (`apk`, `deb`, `rpm`, `alpm`, `bitnami`, `npm`,
`golang`, `maven`, `pypi`, `gem`, `cargo`, `nuget`, `hex`) plus
`oci`/`docker` — notably not `generic`. 

### Standalone Go Module

Unlike most other plugins here, `bomify-plugin-grype` is **its own Go
module** ([`plugins/bomify-plugin-grype/go.mod`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/bomify-plugin-grype/go.mod)) —
grype's transitive dependency tree (syft, stereoscope, several cloud
SDKs, ...) is large enough that folding it into the root `go.mod`/`go.sum`
would bloat every other build in this repo. It depends on this module's
own [`pkg/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/plugin)
via a `replace` directive. `make build`/`test`/`tidy`/`plugins` already
know to step into this directory separately; see the `plugins` target in
the [`Makefile`](https://github.com/alejandro-velasco/bomify/blob/main/Makefile).
A future plugin with a similarly heavy dependency should consider the
same pattern.

## bomify-plugin-sigstore

[`bomify-plugin-sigstore`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-sigstore)
implements the [signing contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SIGNING-CONTRACT.md)
using [sigstore-go](https://github.com/sigstore/sigstore-go), producing
standard v0.3 Sigstore bundles (artifact type
`application/vnd.dev.sigstore.bundle.v0.3+json`), signed with a key
pair: `--sign-option key=signing.key` to sign,
`--verify-option key=signing.pub` to verify. Any PEM key pair works —
one from OpenSSL (plain or password-protected PKCS#8) or from
`cosign generate-key-pair` — with an encrypted key's password read from
`SIGSTORE_PASSWORD`. See the
[signing how-to](https://alejandro-velasco.github.io/bomify/how-to/signing-and-verifying-packages/)
for the commands. Nothing is uploaded to a transparency log and no
network access is needed, which suits private registries and air-gapped
`save`/`load` transfers.

`key` is the only option, and it's required; any other option is
rejected rather than ignored. Like
`bomify-plugin-grype`, it's its own Go module
([`plugins/bomify-plugin-sigstore/go.mod`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/bomify-plugin-sigstore/go.mod)),
since sigstore-go's dependency tree (TUF, protobuf specs, cloud
credential providers, ...) is too heavy for the root module.
