# Component plugin contract v1

A plugin reports the contract versions it speaks with
`bomify-plugin-<kind> contract` (see
[contract versions](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#contract-versions)).

The authoritative spec for a `bomify-plugin-<kind>` binary's **component
plugin** subcommands (`component pull`, `component pack`), which `bomify
build` and `bomify push`/`save` call. It's independent of the
[SBOM generation](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/sbom/v1/CONTRACT.md),
[security scanning](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/security/v1/CONTRACT.md),
and [signing](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/signing/v1/CONTRACT.md)
contracts; a binary can implement any combination.

Go plugins should use
[`pkg/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/plugin):
implement its `ComponentPlugin` interface and `plugin.ComponentCommand`
provides every flag, the `--check` rules, the `--log` logger, the
`--progress` reporter, and the output rules below.

A plugin is a standalone executable. Every input is a command-line flag;
every output is stdout, stderr, the exit code, or the files it's told to
write.

## Naming and discovery

A plugin for purl type `<kind>` (e.g. `oci`, `helm`, `npm`) is named
`bomify-plugin-<kind>` (`.exe` on Windows) and installed in
`<data-dir>/plugins` (`~/.bomify/plugins` by default), usually with
`bomify plugin install` (see
[plugins/README.md](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#installing-plugins)).
bomify never searches `PATH`.

`<kind>` is the component purl's type: `pkg:oci/nginx@1.27` needs
`bomify-plugin-oci`. The exception is `pkg:bomify-plugin/...`, a plugin
binary bomify handles itself (see
[publishing a plugin](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#publishing-a-plugin)).

## Commands

Every subcommand takes `--purl`, `--log`, and `--log-color` (see
[Logging](#logging)).

### `component pull`

```
bomify-plugin-<kind> component pull --purl <purl> --output <dir> --progress <path> --log <path> --log-color <bool>
```

Fetch or build the component `--purl` identifies into `--output`.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--purl` | yes | The component's package URL. Everything the plugin needs to know comes from it. |
| `--output` | unless `--check` | Directory to write the artifact into. bomify creates it, empty, beforehand. Write a single file or a tree, whatever suits the artifact, of regular files only: bomify pushes each file as a blob of its own, and refuses a symlink. Not passed with `--check=true`. |
| `--check` | no | See [Check mode](#check-mode). Default `false`. |
| `--progress` | no | File to report the pull's progress to (see [Progress](#progress)). Not passed with `--check=true`. |

On success, print one [`Result`](#result) and exit `0`.

### `component pack`

```
bomify-plugin-<kind> component pack --purl <purl> --input <dir> --log <path> --log-color <bool>
```

Describe what a prior `pull` wrote into `--input` as an OCI artifact in
the kind's own registry format, the one its ecosystem's tools pull (an
image `docker pull` runs, a chart `helm pull` reads). `bomify push` puts
it in the package's index as it is, so it keeps its digest and can be
fetched from the package's repository by it.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--purl` | yes | Same purl as the `pull` that filled `--input`. |
| `--input` | yes | Directory a successful `pull` for the same purl wrote into, exactly as it left it. Read it; don't change it. |

On success, print one [`PackResult`](#packresult) and exit `0`. A kind
with no format of its own prints `{}`, and bomify packages the
component in its own format (a model as
[ModelPack](https://github.com/modelpack/model-spec)). That's also what
a plugin built with `pkg/plugin` prints unless it implements
`ComponentPacker`.

`bomify pull` doesn't call the plugin: it rebuilds `--input` from the
package, each file that's a blob from that blob, and the rest from
copies bomify keeps beside the artifact. So a blob's file in `--input`
must hold exactly its bytes, as pulled, and `--input` may hold only
regular files.

`pack` works only from `--input`: no network or registry. Given the
same `--input`, it must describe the same artifact, byte for byte, so
pushing an unchanged component gives the same digest. Leave out
anything that changes from one pack to the next, such as the time it
ran.

## Check mode

`--check=true` on `pull` asks the plugin to confirm a real pull would
succeed (the artifact exists and is readable) without transferring
content. `--output` isn't passed; don't require it.

Use the cheapest check available: a manifest HEAD, a resolve, a small
index fetch. A full pull is an acceptable last resort.

Print one `Result` on success, or exit non-zero with a one-line stderr
message. `hash` may be set if the check learns it for free (e.g. a
registry HEAD returning a digest).

## Standard streams

| Stream | Reserved for |
| --- | --- |
| stdout | Exactly one `Result` or `PackResult`, only on success. Nothing else, ever: bomify fails if stdout isn't that one JSON object. |
| stderr | One short fatal error message, only on failure. bomify appends it to its own error. |
| exit code | `0` on success; non-zero on failure. |

Progress goes to the `--progress` file, and everything else to the
`--log` file.

## Result

Printed by `pull`. A missing key and a zero value are equivalent, so
`hash` may be absent, `{}`, or fully set.

```json
{
  "outputPath": "path/to/artifact",
  "message": "optional human-readable summary",
  "hash": { "algorithm": "SHA-256", "value": "9d5aec50e4ace532e44f5459f1f4d9c17180c96318103a6f64b765864967d31" }
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `outputPath` | string | yes | The path written (normally `--output`). With `--check`: whatever identifies what was checked (a resolved reference, a download URL). |
| `message` | string | no | Short human-readable summary. Logged, never parsed. |
| `hash` | object | no | The pulled artifact's SHA-256 (see [Hashes](#hashes)). Unset when it can't be computed. Never guess. |
| `hash.algorithm` | string | with `hash.value` | Always `SHA-256`. |
| `hash.value` | string | with `hash.algorithm` | Hex digest. Compared case-insensitively; lowercase by convention. |

Schema: [`result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/result.schema.json).

### Hashes

bomify checks every pulled component against the SHA-256 its SBOM
declares and keys its data directory by SHA-256, so that's the only
algorithm a plugin reports (`plugin.NewHash` builds one from a hex
digest). If a plugin can't compute it, it omits `hash` rather than
failing.

## PackResult

Printed by `pack`: the artifact's manifest, and every blob it refers to,
each either a file in `--input` holding exactly its bytes or, for a blob
the plugin builds, its bytes inline.

```json
{
  "manifest": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:...", "size": 712, "data": "eyJzY2hlbWFWZXJzaW9uIjoy..." },
  "blobs": [
    { "mediaType": "application/vnd.cncf.helm.config.v1+json", "digest": "sha256:...", "size": 301, "data": "eyJuYW1lIjoibXljaGFydCIs..." },
    { "mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip", "digest": "sha256:...", "size": 4410, "path": "<input>/mychart-1.2.3.tgz" }
  ]
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `manifest` | blob | with `blobs` | The artifact's manifest, or an index of several. Absent, as is `blobs`, for a kind with no format of its own. |
| `blobs` | array of blobs | no | Every other blob `manifest` refers to: its config and layers, and through an index, each manifest it names and theirs. Any order. |
| `*.mediaType` | string | yes | The blob's OCI media type, as the descriptor that names it has it. |
| `*.digest` | string | yes | The blob's OCI digest, `sha256:<hex>`. |
| `*.size` | integer | yes | The blob's size in bytes. |
| `*.path` | string | one of `path` and `data` | A file within `--input` holding exactly the blob's bytes. Use it for every blob that's a file there: those are what pull restores `--input` from (see [`component pack`](#component-pack)), and bomify reads a large one, such as an image layer, straight from it. |
| `*.data` | string | one of `path` and `data` | The blob's bytes, base64, for a blob the plugin builds, such as a config or a manifest; at most 4 MiB, as large as a registry commonly allows a manifest. `pack` writes no files, so a plugin can build only blobs that fit. `plugin.InlineBlob` builds one. |

Schema: [`pack-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/pack-result.schema.json).

## Progress

`--progress <path>` is a file bomify creates empty right before a
`pull`, shows as the plugin appends to it, and deletes when the plugin
exits. Append one JSON object per line, written whole, for each part of
the component as it downloads, such as a file or a layer:

```json
{"name": "model.safetensors", "current": 1048576, "total": 269060552}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | string | yes | The part, which bomify shows as a bar of its own. Keep it short: a file's path, or a layer's short digest. |
| `current` | integer | yes | Bytes of it pulled so far, in all; not since the last line. |
| `total` | integer | no | Its size in bytes. Absent or `0` when unknown. |

Report each part at most ten times a second, and once more when it's
done. A part whose `current` reaches its `total`, or that's still
going when the plugin exits, is done. bomify skips a line it can't
parse rather than failing the pull.

Reporting is optional: until a plugin reports a part, bomify shows the
component as pulling, until it exits. `plugin.PullRequest` hands each
call a `Progress` for this (`plugin.OpenProgress` opens one directly),
whose `Writer` counts what's written through it.

Schema: [`progress.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/progress.schema.json), one line.

## Logging

- `--log <path>`: a file bomify creates empty right before the call.
  Append your log lines to it unconditionally. bomify prints it with its
  own log under `--verbose` and deletes it when the plugin exits, so
  it's not a durable log.
- `--log-color <bool>`: whether ANSI colors are allowed in the log.
  bomify decides from where it logs; don't detect it yourself.

`plugin.ComponentCommand` hands each call a ready-made `*slog.Logger` for
this (`plugin.OpenLog` opens one directly), in bomify's own log format.

## What bomify handles

Caching, concurrency, and state are bomify's job:

- Each invocation is fresh; nothing needs remembering between calls.
- bomify decides when a `pull` can be skipped and prevents concurrent
  pulls of the same purl.
- `--output` (`pull`) and `--input` (`pack`) are always in the state
  described above.

Given the same flags, a plugin should do the same thing.
