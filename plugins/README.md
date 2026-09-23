# Plugins

Plugins created and supported by the bomify project itself, as opposed to
third-party plugins a user might install separately. Each subdirectory here
is a standalone `bomify-plugin-<kind>` binary implementing the
**component plugin** contract's `component pull`/`component push`/
`component remote` subcommands, specified in
[`CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/CONTRACT.md).

Component plugins are one of two entirely independent plugin classes a
`bomify-plugin-<kind>` binary can implement. The other, **SBOM generation
plugins** (`sbom generate`, specified in
[`SBOM-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SBOM-CONTRACT.md)),
inspect a deployment medium and build a fresh SBOM for it.
`bomify-plugin-helm` is the one plugin below that implements both classes
— see its own row and the paragraph following the table.

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
contract's `sbom generate` (`--chart`/`--repo`/`--version`/`--values`/
`--namespace`/`--release-name`/`--kube-version`/`--output`, its own
plugin-defined flags — see
[`SBOM-CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SBOM-CONTRACT.md)):
it renders the chart's templates locally via the Helm SDK (the same code
path as `helm template`, never touching a real cluster), then walks the
rendered manifests' `Deployment`/`StatefulSet`/`DaemonSet`/`Job`/
`CronJob`/`Pod` resources for every container image their pod specs
reference, and reports them as a CycloneDX SBOM (to stdout by default,
or to `--output`'s file) — with the chart itself as the first entry in
`components` (not just `metadata.component`), so `bomify build` can
pull the chart, not only the images it references. This is unrelated to
its `component` subcommands above — it doesn't fetch or verify the
chart itself, just its templated output — and currently only looks at
those built-in kinds' well-known pod-spec locations; a custom resource
isn't inspected yet. Every flag can instead be set in a YAML manifest
(`--manifest`,
default `bomify-helm-sbom.yaml`, read if present in the working
directory and otherwise skipped silently) — a flag given explicitly on
the command line always takes precedence over the same key there.

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
[`CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/CONTRACT.md#check-mode)), with the same per-plugin limits
their real `pull`/`push` have: `bomify-plugin-helm`'s `push --check` is
OCI-only, same as `push` itself, and `bomify-plugin-generic`'s
`push --check` is best-effort only (a HEAD, never a real PUT — see its
own doc comment on `CheckPush`), since a presigned upload URL can't be
verified without actually writing to it.

To add a new component plugin, create `plugins/bomify-plugin-<kind>`,
implement `component pull`, `component push`, and `component remote` per
[`CONTRACT.md`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/CONTRACT.md),
and add a row above.
