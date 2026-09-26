# Plugins

Plugins created and supported by the bomify project itself, as opposed to
third-party plugins a user might install separately. Each subdirectory here
is a standalone `bomify-plugin-<kind>` binary implementing the
**component plugin** contract's `component pull`/`component push`/
`component remote` subcommands, specified in
[`COMPONENT-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/COMPONENT-CONTRACT.md).

Component plugins are one of three entirely independent plugin classes a
`bomify-plugin-<kind>` binary can implement. **SBOM generation plugins**
(`sbom generate`, specified in
[`SBOM-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SBOM-CONTRACT.md))
inspect a deployment medium and build a fresh SBOM for it.
`bomify-plugin-helm` is the one plugin below that implements both this
and the component contract — see its own row and the paragraph
following the table. **Security scanning plugins** (`security scan
--purl <purl>`, specified in
[`SECURITY-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SECURITY-CONTRACT.md))
report the vulnerabilities one component's purl is affected by; `bomify
security scan` calls the same plugin once per component in an existing
SBOM (concurrently, like `bomify build`/`bomify distribute`) and merges
their results into the SBOM's own vulnerabilities.
[`bomify-plugin-grype`](#bomify-plugin-grype-security-scanning) below
implements this contract, independently of the three component plugins.

| Plugin                                        | Kind     | Backing library                                                                   |
|------------------------------------------------|----------|-------------------------------------------------------------------------------------|
| [`bomify-plugin-oci`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-oci)     | `oci`    | [go-containerregistry/pkg/crane](https://github.com/google/go-containerregistry)   |
| [`bomify-plugin-helm`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-helm)   | `helm`   | [helm.sh/helm/v3/pkg/action](https://pkg.go.dev/helm.sh/helm/v3/pkg/action) (Pull/Push, the same code behind the `helm` CLI) |
| [`bomify-plugin-generic`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-generic) | `generic` | stdlib `net/http` only — a plain GET on pull, PUT on push |

`bomify-plugin-helm`'s `component pull` supports both classic HTTP(S)
chart repositories (`pkg:helm/<name>@<version>?repository_url=https://...`)
and OCI registries (`repository_url=oci://...`). Its `component push`
only supports OCI — Helm's SDK has no upload path for a classic chart
repository, since those are just static, read-only `index.yaml` listings.

`bomify-plugin-helm` also implements the independent SBOM generation
contract's `sbom generate`, rendering a chart's templates locally via the
Helm SDK (the same code path as `helm template`, never touching a real
cluster) and reporting every container image it references — plus the
chart itself — as a CycloneDX SBOM. See
[its own README](bomify-plugin-helm/README.md) for its flags, manifest
file, and worked examples, and
[`SBOM-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SBOM-CONTRACT.md)
for the contract this and any other SBOM generation plugin must follow.

Note `helm.sh/helm/v3` is a very large dependency (it pulls in most of
`k8s.io/client-go` transitively), so this plugin's binary is
correspondingly larger than the others.

`bomify-plugin-generic` handles the package-url spec's own catch-all
`generic` type: `pkg:generic/<name>@<version>?download_url=<url>`. `pull`
GETs `download_url` as-is; `push` PUTs the file a prior pull wrote,
sending it to `--remote` exactly as given (with a correct
`Content-Length`, not chunked) — useful for destinations like a presigned
upload URL, where appending anything to `--remote` would invalidate it.

All three support `component pull --check`/`component push --check` (see
[`COMPONENT-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/COMPONENT-CONTRACT.md#check-mode)), with the same per-plugin limits
their real `pull`/`push` have: `bomify-plugin-helm`'s `push --check` is
OCI-only, same as `push` itself, and `bomify-plugin-generic`'s
`push --check` is best-effort only (a HEAD, never a real PUT — see its
own doc comment on `CheckPush`), since a presigned upload URL can't be
verified without actually writing to it.

To add a new component plugin, create `plugins/bomify-plugin-<kind>`,
implement `component pull`, `component push`, and `component remote` per
[`COMPONENT-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/COMPONENT-CONTRACT.md),
and add a row above.

## `bomify-plugin-grype`: security scanning

[`bomify-plugin-grype`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-grype)
implements the [security scanning contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SECURITY-CONTRACT.md)
(`security scan --purl <purl>` / `security supported-components`) using
[Anchore's grype](https://github.com/anchore/grype) as a Go library. Most
purl types (`npm`, `maven`, `apk`, ...) already name one specific
package, so `grype/pkg.Provide` resolves the purl directly into a
package with no cataloging involved. An `oci`/`docker` purl names a
whole container image instead, which has no packages of its own until
something looks inside it — for those two types only, the plugin pulls
in [Anchore's syft](https://github.com/anchore/syft) (via grype's own
syft-backed provider, the same code path `grype <image>` itself uses)
to catalog the image first, then matches every package it finds. Either
way, matches are checked against grype's own vulnerability database
(downloaded and cached the same way, and to the same location, the real
`grype` CLI uses, so an existing local grype install's DB is reused
rather than downloaded twice), and converted into CycloneDX
`vulnerability` objects by hand — this plugin never uses grype's own
(deprecated) CycloneDX presenter. For an `oci`/`docker` scan, every
cataloged package is also reported back as a `SecurityResult` component
— which `bomify security scan` embeds as that image's own nested
components in the SBOM — with each vulnerability's `affects` pointing at
the specific package(s) actually affected, never the image itself.

`security supported-components` reports exactly the purl types grype has
a dedicated, ecosystem-specific matcher for (`apk`, `deb`, `rpm`, `alpm`,
`bitnami`, `npm`, `golang`, `maven`, `pypi`, `gem`, `cargo`, `nuget`,
`hex`), plus `oci`/`docker` (scanned via syft cataloging, as above) —
notably **not** `generic`: there's no image or package to catalog or
look up for it. `bomify security scan` skips components of unsupported
types before ever calling this plugin. Image pulling for `oci`/`docker`
purls uses syft's own default source resolution (the local Docker/Podman
daemon if present, otherwise the registry directly via the credentials
`docker login`/`crane auth login` populate) — not bomify's own `bomify
login` credential store, which only `bomify-plugin-oci` reads.

Unlike every other plugin here, `bomify-plugin-grype` is **its own Go
module** ([`plugins/bomify-plugin-grype/go.mod`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/bomify-plugin-grype/go.mod)),
not part of this repository's root module — the grype SDK's transitive
dependency tree (syft, stereoscope, several cloud SDKs, ...) is large
enough that folding it into the root `go.mod`/`go.sum` would bloat every
other build in this repo. It depends on this module's own
[`pkg/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/plugin)
via a `replace` directive pointing at the local checkout. `make
build`/`test`/`tidy`/`plugins` all already know to step into this
directory separately; see the `plugins` target in the
[`Makefile`](https://github.com/alejandro-velasco/bomify/blob/main/Makefile)
for why. A future plugin with a similarly heavy dependency should
consider the same pattern.
