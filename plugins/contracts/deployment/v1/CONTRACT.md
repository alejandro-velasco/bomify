# Deployment plugin contract v1

> **In progress.** bomify implements all of this but
> [packaged deployments](#packaged-with-the-package) and
> [starting a deployment file from `sbom compose`](#starting-one-from-sbom-compose),
> which are still to come: until then, `bomify deploy generate` takes
> the deployments from `--file` alone, written by hand.

A plugin reports the contract versions it speaks with
`bomify-plugin-<type> contract` (see
[contract versions](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#contract-versions)).

The spec for a `bomify-plugin-<type>` binary's **deployment** subcommand,
`deployment generate`, which `bomify deploy generate` calls. It turns a
package pushed to the registry it'll be deployed from into what a
deployment tool deploys: Helm values pinning every image to the
package's copy by digest, a Compose file, and, later, a Flux
`HelmRelease`, an Argo CD `Application`, or Terraform. It's independent
of the
[component](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/CONTRACT.md),
[SBOM generation](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/sbom/v1/CONTRACT.md),
[security scanning](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/security/v1/CONTRACT.md),
and [signing](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/signing/v1/CONTRACT.md)
contracts.

Here `<type>` names a deployment medium (e.g. `helm`, `compose`), the
same names `bomify sbom compose` gives a package's sources, not a purl
type. A plugin generates files; it never deploys them.

Go plugins should implement `pkg/plugin`'s `DeploymentPlugin` interface
and use `plugin.DeploymentCommand`, which provides the subcommand, its
flags, the `--log` logger, and output.

## Naming and discovery

As for the [component contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/CONTRACT.md#naming-and-discovery):
`bomify-plugin-<type>` (`.exe` on Windows), installed in
`<data-dir>/plugins`. One binary may implement this alongside other
contracts, as `bomify-plugin-helm` would.

## What bomify does

```sh
bomify deploy generate registry.example.com/team/app:1.0 --file deploy.yaml --output deploy/
```

1. Reads the package from the registry `<reference>` names: its index,
   SBOM, and files map, but no component. The package must already be
   there, since that's where the cluster pulls it from.
2. Verifies it as `bomify pull` would: a signature `--verify` names, or
   one a matching `bomify trust` rule requires.
3. Works out where each component is (see [Locations](#locations)), and
   writes the [package description](#package-description).
4. Takes the deployments to generate from the package's own
   [deployment file](#deployment-file), with any `--file` of the user's
   laid over it.
5. Finds every enabled deployment's plugin, before running any.
6. For each deployment, in the file's order, creates `<output>/<name>/`,
   empty, calls that deployment's plugin's `deployment generate` once,
   and checks it wrote exactly the regular files it reports.
7. Writes [`<output>/deployments.json`](#deploymentsjson), and prints
   each deployment's files and `instructions`, if any. It deploys
   nothing.

All of it is written aside and moved into `--output` only once every
deployment has generated, so a failed one leaves `--output` as it was.

## Deployment file

What to generate: one or more named deployments, each of one medium.

```yaml
deployments:
  - name: infra
    type: terraform
    config: infra.tf.tmpl
  - name: backend
    type: helm
    options:
      chart: chart-b
    config: backend-values.yaml.tmpl
    dependsOn:
      - infra
  - name: frontend
    type: helm
    options:
      chart: chart-a
    config: frontend-values.yaml.tmpl
    dependsOn:
      - backend
```

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Unique in the file, and usable as a file name (see `transfer.IsSafeFilename`): its output directory, and the plugin's `--name`. |
| `type` | yes | The plugin: `bomify-plugin-<type>`. |
| `options` | no | `key: value` settings, passed as `--option key=value`. |
| `config` | no | A file, relative to the deployment file, passed as `--config`. |
| `overlays` | no | Files, relative to the deployment file, passed as `--overlay`, in order (see [Overriding the package's](#overriding-the-packages)). |
| `dependsOn` | no | Names of deployments to apply before this one. bomify checks they exist and form no cycle, and records them in `deployments.json`, for whatever applies the output. Generating doesn't wait on them. |

### Packaged with the package

A package's author knows how its components wire together, so the
deployment file, and every `config` it names, travel with the package:

- `bomify build --deployments deploy.yaml` records them with the build,
  and `push` and `save` put them in the package's index as one more
  manifest, of artifact type
  `application/vnd.bomify.deployments.v1+json`, whose layers are the
  deployment file and its configs, each titled with its path. They're
  part of the package's digest, so its signature covers them.
- `bomify deploy generate <reference>` then needs no file of the user's.

### Starting one from `sbom compose`

`bomify sbom compose bomify.yaml --output app.cdx.json
--deployments-output deploy.yaml` also writes a starting deployment
file, for the author to finish and pass to `build --deployments`. It
names one deployment per source of a medium, of that medium's type, and
nothing it can't know:

```yaml
# Written by bomify sbom compose from bomify.yaml: add each deployment's
# config, and dependsOn where order matters.
deployments:
  - name: web
    type: helm
    options:
      chart: web
  - name: db
    type: helm
    options:
      chart: db
```

A source that's an SBOM file, rather than a medium, gets none. Compose
won't overwrite a deployment file that exists: once written, it's the
author's, and recomposing leaves it alone. Neither the SBOM nor `build`
learns about compose.

### Overriding the package's

A user's `--file` is laid over the package's, deployment by deployment,
matched by `name`, so they change only what they need. A new name adds a
deployment. For one the package has:

| Field | Effect |
| --- | --- |
| `type` | Must match the package's, if given: a deployment can't change medium. |
| `options` | Merged key by key over the package's, theirs winning. `null` removes the package's. |
| `config` | Replaces the package's template. |
| `overlays` | Templates of theirs, rendered like `config` and laid over its output, in order, as the medium layers its own files: Helm values merge as `-f` merges them, a Compose override file as Compose does, Terraform variables as later `.tfvars` do. Each plugin documents how it merges. |
| `dependsOn` | Replaces the package's. |
| `enabled` | `false` skips the deployment. |

```yaml
# Keep the author's frontend template; pin another release name and
# raise the replica count.
deployments:
  - name: frontend
    options:
      release: web
    overlays:
      - frontend-overrides.yaml.tmpl
  - name: infra
    enabled: false
```

Paths in a user's file are relative to it.

Pull ignores an index entry it doesn't know, so an older bomify pulls a
package with deployments as if it had none: adding them needs no new
version of the registry format.

## Commands

```
bomify-plugin-<type> deployment generate --name <name> --package <path> --output <dir> [--config <path>] [--overlay <path>]... [--option <key>=<value>]... --log <path> --log-color <bool>
```

| Flag | Required | Meaning |
| --- | --- | --- |
| `--name` | yes | The deployment's name, from the deployment file: for what the plugin generates, such as a Helm release name in its `instructions`. |
| `--package` | yes | The [package description](#package-description), a JSON file. Everything the plugin knows about the package comes from it. |
| `--output` | yes | The directory to write into. bomify creates it, empty, beforehand. |
| `--config` | no | The deployment's `config`: a values template, for example. Its format is the plugin's to define and document. bomify passes it as given and never reads it. |
| `--overlay` | no | One of the deployment's `overlays` (repeatable, in order): a file in the same format as `--config`, rendered the same way, and laid over its output as the medium layers files. Without `--config`, the first overlay is the base. |
| `--option` | no | One of the deployment's `options` (repeatable). The plugin defines its keys, and fails on one it doesn't know. |
| `--log`, `--log-color` | yes | As for the [component contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/CONTRACT.md#logging). |

On success, write the files into `--output`, print one
[`DeploymentResult`](#deploymentresult), and exit `0`.

### Rules

- **Offline.** Generate from `--package` and `--config` alone, never a
  registry, a cluster, or any other network service. bomify has already
  read the registry; the result can be reviewed before anything changes.
- **Reproducible.** The same inputs give the same files, byte for byte:
  no timestamps, no random names, keys in a stable order. So generated
  files diff cleanly in version control.
- **Contained.** Write only regular files, only inside `--output`.
- **Pinned.** Refer to a component by its `reference`, by digest, unless
  a tool needs a tag; then use `tagged`, and fail with a clear message if
  it's absent (see [Locations](#locations)).
- **No credentials.** bomify passes none, and a plugin needs none.

## Standard streams

| Stream | Reserved for |
| --- | --- |
| stdout | Exactly one `DeploymentResult`, only on success. Nothing else, ever. |
| stderr | One short fatal message, only on failure. bomify appends it to its own error. |
| exit code | `0` on success; non-zero on failure. |

Everything else goes to the `--log` file.

## Package description

```json
{
  "reference": "registry.example.com/team/app:1.0",
  "repository": "registry.example.com/team/app",
  "digest": "sha256:3ce400ec7f2a...",
  "components": [
    {
      "name": "chart-a",
      "version": "1.2.0",
      "purl": "pkg:helm/chart-a@1.2.0",
      "artifactType": "application/vnd.cncf.helm.config.v1+json",
      "digest": "sha256:52dc0a93db3f...",
      "reference": "registry.example.com/team/app@sha256:52dc0a93db3f...",
      "tagged": {
        "registry": "registry.example.com",
        "repository": "team/app/helm/chart-a",
        "tag": "1.2.0",
        "reference": "registry.example.com/team/app/helm/chart-a:1.2.0"
      }
    },
    {
      "name": "image-a",
      "version": "2.4.1",
      "purl": "pkg:oci/image-a@2.4.1",
      "digest": "sha256:7a9927810272...",
      "reference": "registry.example.com/team/app@sha256:7a9927810272..."
    }
  ]
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `reference` | string | The package, as given to `bomify deploy generate`. |
| `repository` | string | Its repository, where every component is. |
| `digest` | string | The package index's digest: what was verified. |
| `components` | array | Every component, in the SBOM's order. |
| `components[].name`, `.version`, `.purl` | string | As the SBOM gives them. |
| `components[].artifactType` | string | Its manifest's artifact type, if it has one, e.g. a Helm chart's config media type. Absent for an image. |
| `components[].digest` | string | Its manifest's digest. |
| `components[].reference` | string | `<repository>@<digest>`: it, pinned, where it always is. |
| `components[].tagged` | object | Where it's tagged, only if it is (see [Locations](#locations)): `registry`, `repository`, and `tag` apart, for values that take them so, and `reference` whole. |

A plugin ignores fields it doesn't know, so bomify can add some.

Schema: [`package.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/deployment/v1/package.schema.json).

### Locations

Every component is in the package's repository, by digest: push puts it
there, and any copy of the package carries it. That's `reference`.

The package's index also names where each component is tagged, relative
to the package's repository (`helm/chart-a:1.2.0`, see the
[registry format](https://github.com/alejandro-velasco/bomify/blob/main/docs/architecture/registry-format.md#component-repositories)).
bomify resolves it against the repository `<reference>` names, so a
mirror under another name resolves to the mirror. The tag exists only
if `bomify push` put the package there without
`--skip-component-repositories`: copying an index with another tool
copies no tags. So bomify checks each one, and sets `tagged` only for a
tag that exists and points at the component's digest.

### Naming components

A plugin that lets users name a component, in an option or a template,
should accept what `bomify component pull` does, so names work alike
everywhere:

- its purl, whole, or without its qualifiers;
- its purl's type, namespace if it has one, and name, with or without
  `@<version>`: `oci/podinfo`, `helm/podinfo@6.7.1`,
  `huggingface/org/model`;
- its name, alone or as `<name>@<version>`.

One that names several components fails, listing their purls.
`pkg/plugin`'s `SelectComponent` and `MatchesSelector` implement this.

## DeploymentResult

```json
{
  "files": ["values.yaml"],
  "instructions": "helm upgrade --install frontend oci://registry.example.com/team/app/helm/chart-a@sha256:52dc0a93db3f... --values values.yaml"
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `files` | array of strings | yes, non-empty | Every file the plugin wrote, `/`-separated, relative to `--output`. |
| `instructions` | string | no | What to do with them, one short paragraph or command, run from `--output`, which bomify prints. Informational. |

Schema: [`deployment-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/deployment/v1/deployment-result.schema.json).

## deployments.json

What bomify generated, for a script or tool that applies the output:

```json
{
  "package": "registry.example.com/team/app@sha256:3ce400ec7f2a...",
  "deployments": [
    { "name": "infra", "type": "terraform", "files": ["infra/main.tf"] },
    { "name": "backend", "type": "helm", "files": ["backend/values.yaml"], "dependsOn": ["infra"],
      "instructions": "helm upgrade --install backend oci://registry.example.com/team/app/helm/chart-b@sha256:... --values values.yaml" }
  ]
}
```

Each deployment's `files` are relative to `<output>`, in the deployment
file's order.

## What bomify handles

Reading and verifying the package, working out where its components
are, running each deployment, and creating its output directory are
bomify's job. Each call is fresh: the plugin needs no state, network,
or credentials, and is asked only to generate. Deploying what it wrote
is the user's, or their tools'.

## Example: `bomify-plugin-helm`

*Not part of the contract: what the first plugin might do.*

For a `helm` deployment, `chart` [names](#naming-components) the chart,
among the package's charts alone, so a chart named like one of its
images, as `podinfo` often is, needs nothing more than its name. The plugin renders `--config`, a Go
template, into `values.yaml`, failing on a missing key rather than
writing an empty value. Its `instructions` install the chart from the
registry by digest: from its own repository if it's `tagged`, else the
package's.

```yaml
image:
  registry: {{ (component "image-a").tagged.registry }}
  repository: {{ (component "image-a").tagged.repository }}
  digest: {{ (component "image-a").digest }}
sidecar:
  image: {{ (component "oci/podinfo@6.7.1").reference }}
```

`component` takes the same selectors as `chart`, since names like
`image-a` can't be template field names. `.Package` is the whole
description. Each `--overlay` is rendered the same way and merged into
`values.yaml` as `helm -f` merges values files: maps key by key, a list
replaced whole, and `null` deleting a key. So `values.yaml` is the one
file to review. `release` names the Helm release, `--name` by default.

## Changes elsewhere

- `contract-result.schema.json` gains a `deployment` key.
- The [registry format](https://github.com/alejandro-velasco/bomify/blob/main/docs/architecture/registry-format.md)
  gains the deployments manifest, and the
  [data directory](https://github.com/alejandro-velasco/bomify/blob/main/docs/architecture/data-directory.md)
  a place for a build's deployment files.
- `bomify sbom compose` gains `--deployments-output`, and `bomify build`
  `--deployments`.

## Open questions

None, for now.
