# bomify plugins

Plugins created and supported by the bomify project itself, as opposed to
third-party plugins a user might install separately. Each subdirectory here
is a standalone `bomify-plugin-<kind>` binary implementing the pull/push
contract specified in [`CONTRACT.md`](CONTRACT.md).

| Plugin                                        | Kind     | Backing library                                                                   |
|------------------------------------------------|----------|-------------------------------------------------------------------------------------|
| [`bomify-plugin-oci`](./bomify-plugin-oci)     | `oci`    | [go-containerregistry/pkg/crane](https://github.com/google/go-containerregistry)   |
| [`bomify-plugin-helm`](./bomify-plugin-helm)   | `helm`   | [helm.sh/helm/v3/pkg/action](https://pkg.go.dev/helm.sh/helm/v3/pkg/action) (Pull/Push, the same code behind the `helm` CLI) |
| [`bomify-plugin-generic`](./bomify-plugin-generic) | `generic` | stdlib `net/http` only — a plain GET on pull, PUT on push |

`bomify-plugin-helm`'s `pull` supports both classic HTTP(S) chart
repositories (`pkg:helm/<name>@<version>?repository_url=https://...`) and
OCI registries (`repository_url=oci://...`). Its `push` only supports OCI
— Helm's SDK has no upload path for a classic chart repository, since
those are just static, read-only `index.yaml` listings.

Note `helm.sh/helm/v3` is a very large dependency (it pulls in most of
`k8s.io/client-go` transitively, even though bomify only uses its
chart-registry pull/push actions), so this plugin's binary is
correspondingly larger than the others.

`bomify-plugin-generic` handles the package-url spec's own catch-all
`generic` type: `pkg:generic/<name>@<version>?download_url=<url>`. `pull`
GETs `download_url` as-is; `push` PUTs the file a prior pull wrote,
sending it to `--remote` exactly as given (with a correct
`Content-Length`, not chunked) — useful for destinations like a presigned
upload URL, where appending anything to `--remote` would invalidate it.

To add a new one, create `plugins/bomify-plugin-<kind>`, implement `pull`
and `push` per [`CONTRACT.md`](CONTRACT.md), and add a row above.
