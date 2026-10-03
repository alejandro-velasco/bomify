# Component plugin contract v1

A plugin reports the contract versions it speaks with
`bomify-plugin-<kind> contract` (see
[contract versions](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#contract-versions)).

The authoritative spec for a `bomify-plugin-<kind>` binary's **component
plugin** subcommands (`component pull`, `component push`, `component
remote`), which `bomify build` and `bomify distribute` call. It's
independent of the
[SBOM generation](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/sbom/v1/CONTRACT.md),
[security scanning](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/security/v1/CONTRACT.md),
and [signing](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/signing/v1/CONTRACT.md)
contracts; a binary can implement any combination.

Go plugins should use
[`pkg/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/plugin):
implement its `ComponentPlugin` interface and `plugin.ComponentCommand`
provides every flag, the `--check` rules, the `--log` logger, and the
output rules below.

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

All three subcommands take `--purl`, `--log`, and `--log-color` (see
[Logging](#logging)).

### `component pull`

```
bomify-plugin-<kind> component pull --purl <purl> --output <dir> --log <path> --log-color <bool>
```

Fetch or build the component `--purl` identifies into `--output`.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--purl` | yes | The component's package URL. Everything the plugin needs to know comes from it. |
| `--output` | unless `--check` | Directory to write the artifact into. bomify creates it, empty, beforehand. Write a single file or a tree, whatever suits the artifact. Not passed with `--check=true`. |
| `--check` | no | See [Check mode](#check-mode). Default `false`. |

On success, print one [`Result`](#result) and exit `0`.

### `component push`

```
bomify-plugin-<kind> component push --purl <purl> --input <dir> --remote <endpoint> --log <path> --log-color <bool>
```

Publish what a prior `pull` wrote into `--input` to `--remote`.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--purl` | yes | Same purl as the `pull` that filled `--input`. |
| `--input` | unless `--check` | Directory a successful `pull` for the same purl wrote into, exactly as it left it. Not passed with `--check=true`, and no prior `pull` is needed then. |
| `--remote` | yes | Where to publish. Its shape is up to the plugin (a registry prefix, a URL, ...); document it in `--help`. |
| `--check` | no | See [Check mode](#check-mode). Default `false`. |

On success, print one [`Result`](#result) and exit `0`. Leave `hash`
unset.

### `component remote`

```
bomify-plugin-<kind> component remote --purl <purl> --log <path> --log-color <bool>
```

Report where the component comes from or is published under, without
fetching or publishing anything. `bomify distribute` matches this against
a rule's `--match` and, for a non-empty match, keeps whatever follows
the matched prefix when building the `--remote` it passes to `push`, so
a mirror rule preserves each component's path.

On success, print one [`RemoteResult`](#remoteresult) and exit `0`.

`remote` must be a pure function of `--purl`: no network, registry, or
files. bomify may call it any number of times and never caches it.

## Check mode

`--check=true` on `pull`/`push` asks the plugin to confirm a real
transfer would succeed (the artifact exists and is readable, or the
destination is reachable and writable) without transferring content.
`--output`/`--input` aren't passed; don't require them.

Use the cheapest check available: a manifest HEAD, a resolve, a small
index fetch. For `pull --check`, a full pull is an acceptable last
resort. For `push --check`, a real write never is, since it can have
side effects (consuming a single-use presigned URL, overwriting
something); report whatever partial check was possible instead, as
`bomify-plugin-generic` does.

Print one `Result` on success, or exit non-zero with a one-line stderr
message. `hash` may be set if the check learns it for free (e.g. a
registry HEAD returning a digest).

## Standard streams

| Stream | Reserved for |
| --- | --- |
| stdout | Exactly one `Result` or `RemoteResult`, only on success. Nothing else, ever: bomify fails if stdout isn't that one JSON object. |
| stderr | One short fatal error message, only on failure. bomify appends it to its own error. |
| exit code | `0` on success; non-zero on failure. |

Everything else goes to the `--log` file.

## Result

Printed by `pull` and `push`. A missing key and a zero value are
equivalent, so `hash` may be absent, `{}`, or fully set.

```json
{
  "outputPath": "path/to/artifact/or/remote/reference",
  "message": "optional human-readable summary",
  "hash": { "algorithm": "SHA-256", "value": "9d5aec50e4ace532e44f5459f1f4d9c17180c96318103a6f64b765864967d31" }
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `outputPath` | string | yes | `pull`: the path written (normally `--output`). `push`: the reference published (e.g. `<remote>/<name>:<version>`). `--check`: whatever identifies what was checked (a resolved reference, a download URL). |
| `message` | string | no | Short human-readable summary. Logged, never parsed. |
| `hash` | object | no | The pulled artifact's SHA-256 (see [Hashes](#hashes)). `pull` only; unset for `push`, and when it can't be computed. Never guess. |
| `hash.algorithm` | string | with `hash.value` | Always `SHA-256`. |
| `hash.value` | string | with `hash.algorithm` | Hex digest. Compared case-insensitively; lowercase by convention. |

Schema: [`result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/result.schema.json).

### Hashes

bomify checks every pulled component against the SHA-256 its SBOM
declares and keys its data directory by SHA-256, so that's the only
algorithm a plugin reports (`plugin.NewHash` builds one from a hex
digest). If a plugin can't compute it, it omits `hash` rather than
failing.

## RemoteResult

Printed by `remote`:

```json
{ "remote": "docker.io/library" }
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `remote` | string | yes | Where the component comes from or is published under, in the plugin's own shape (registry namespace, URL, ...). |

Report `remote` in the shape your `push` expects `--remote` in, since a
distribution rule can hand it back as `--remote`:

- If `push` appends the component's name/tag to `--remote` (as the OCI
  and Helm plugins do), leave that off: `docker.io/library`, not
  `docker.io/library/nginx`.
- If `push` uses `--remote` as the complete destination (as
  `bomify-plugin-generic` does, since a presigned URL can't be appended
  to), report the complete address.

Components with a common origin must report values sharing a common
`/`-separated prefix; that's what rules match and substitute.

Schema: [`remote-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/remote-result.schema.json).

## Logging

- `--log <path>`: a file bomify creates empty right before the call.
  Append your log lines to it unconditionally. bomify streams it to its
  stdout under `--verbose` and deletes it when the plugin exits, so it's
  not a durable log.
- `--log-color <bool>`: whether ANSI colors are allowed in the log.
  bomify decides from its own stdout; don't detect it yourself.

`plugin.ComponentCommand` hands each call a ready-made `*slog.Logger` for
this (`plugin.OpenLog` opens one directly), in bomify's own log format.

## What bomify handles

Caching, concurrency, and state are bomify's job:

- Each invocation is fresh; nothing needs remembering between calls.
- bomify decides when a `pull` can be skipped and prevents concurrent
  pulls of the same purl.
- `--output`/`--input` are always in the state described above.

Given the same flags, a plugin should do the same thing. `remote` in
particular must always report the same value for the same `--purl`.
