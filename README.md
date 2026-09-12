# bomify

`bomify` is a CLI that builds packages from [CycloneDX](https://cyclonedx.org/) Software Bills of Materials (SBOMs).

Give it an SBOM and `bomify build`/`bomify mirror` walk its components and delegate each one to an external plugin binary that knows how to pull or push it.

## Status

Early Development

## Build

```sh
make build
```

## Usage

```sh
bomify login registry.example.com
bomify build path/to/bom.cdx.json --tag registry.example.com/myapp:1.0
bomify mirror path/to/bom.cdx.json --remote registry.example.com/mirror
bomify packages
bomify tag registry.example.com/myapp:1.0 registry.example.com/myapp:latest
bomify pull registry.example.com/myapp:1.0
bomify push registry.example.com/myapp:1.0
bomify logout registry.example.com
```

- `login`/`logout` authenticate against a registry (default `docker.io`) and store or remove credentials, exactly like `docker login`/`docker logout` — literally the same credential store, so logging in with either tool covers both. Every other command below, and every first-party plugin, draws on whatever's stored here; see [`internal/auth`](internal/auth).
- `build` pulls each component a CycloneDX SBOM describes and records the SBOM itself as a manifest; `--tag` (repeatable) points a name at that manifest, Docker-style.
- `mirror` pushes each component to a remote endpoint instead of pulling it locally.
- `packages` lists built packages by tag, similar to `docker images`.
- `tag` points a new tag at whatever an existing tag currently resolves to, similar to `docker tag`.
- `pull` downloads a previously published bomify package (its manifest and component layers) from an OCI registry.
- `push` publishes a build's manifest and component layers as an OCI artifact under `<tag>`, exactly like `docker push` — `<tag>` doubles as both the local bookkeeping key and the destination reference.

All of these read and write bomify's data directory — built components, manifests, and tags — which defaults to `~/.bomify` and can be overridden with `--data-dir`.

## Container

[`Containerfile`](Containerfile) builds a minimal image (multi-stage, running as `nobody`) with `bomify` and its first-party plugins already on `PATH`, buildable with either Docker or Podman:

```sh
make build-container
```

which by default builds `avelasco1423/bomify:latest` using `docker`; override `CONTAINER_TOOL`, `CONTAINER_REGISTRY`, `CONTAINER_REPO`, or `CONTAINER_TAG` (e.g. `make build-container CONTAINER_TOOL=podman`) to build elsewhere.

Its entrypoint is `bomify`, so `docker run`/`podman run` arguments are just the CLI arguments you'd otherwise pass locally. For example, to build the `helm.cdx.json` fixture from this repo and tag it, mounting the SBOM in and bomify's data directory out:

```sh
docker run -v "${HOME}/.bomify:/tmp/.bomify" -v `pwd`/testdata/helm.cdx.json:/tmp/helm.cdx.json --rm --user $(id -u):$(id -g)  -it avelasco1423/bomify:latest build -t registry.com/container-test:1.0.0 /tmp/helm.cdx.json
```

`--user $(id -u):$(id -g)` overrides the image's default `nobody` user with
yours, so files written under the mounted volumes end up owned by you.
Since the container's `$HOME` is `/tmp` (see [`Containerfile`](Containerfile)),
bomify's default data directory resolves to `/tmp/.bomify` inside the
container, hence mounting your own `~/.bomify` there.

## Testing locally

[`deploy/registry/`](deploy/registry) spins up a throwaway, TLS-enabled OCI registry (self-signed cert generated and trusted for you) for exercising `build`/`mirror`/`pull` against a real registry without needing an account anywhere — see its [README](deploy/registry/README.md).

## Plugins

Neither `bomify build` nor `bomify mirror` build or publish anything
themselves — they detect a "kind" for each SBOM component and delegate to an
external `bomify-plugin-<kind>` binary on `PATH`.

[`plugins/`](plugins) holds the plugins bomify creates and supports itself
(see [`plugins/README.md`](plugins/README.md) for the list), starting with
[`bomify-plugin-oci`](plugins/bomify-plugin-oci), which pulls and pushes
container images using [crane](https://github.com/google/go-containerregistry).
Anyone can also write and install their own third-party
`bomify-plugin-<kind>` binary for a kind bomify doesn't ship.

The kind is taken directly from the component's purl type (parsed with
[package-url/packageurl-go](https://github.com/package-url/packageurl-go)):
a component with purl `pkg:oci/nginx@1.27` has kind `oci` and needs a
`bomify-plugin-oci` binary; `pkg:npm/left-pad@1.3.0` needs `bomify-plugin-npm`;
`pkg:docker/postgres@16` needs `bomify-plugin-docker`. A component with no
purl, or an unparseable one, makes the whole run fail immediately.

Each plugin must implement two subcommands:

```sh
bomify-plugin-<kind> pull --purl <purl> --output <dir> --hash <algorithm>
bomify-plugin-<kind> push --purl <purl> --input <dir> --remote <endpoint>
```

`bomify build` invokes `pull`, which should fetch or build the component
identified by `--purl` and write it into the local directory `dir` (bomify's
data directory; see `--data-dir` above). `bomify mirror` invokes `push`,
which should publish the component found in `dir` to `remote` (bomify's
`--remote`).

For either subcommand, the plugin must print a single JSON object to stdout
on success and exit 0:

```json
{
  "outputPath": "path/to/artifact/or/remote/ref",
  "message": "optional human-readable summary",
  "hash": { "algorithm": "SHA-256", "value": "<hex-digest>" }
}
```

`hash` matters only for `pull`: it's the content hash of the pulled
artifact, using the algorithm `bomify build` requested via `--hash`, and
bomify uses it to verify the artifact against the SBOM's declared hash. A
plugin that can't compute it (or is handling `push`) should leave it out.
