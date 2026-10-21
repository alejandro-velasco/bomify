---
icon: lucide/cloud-upload
---

# Publishing and pulling packages with an OCI registry

`bomify push` publishes a whole package as one OCI image index: the
SBOM, and each component in its own registry format where it has one
(an image as itself, a chart as Helm stores one, a model as ModelPack),
all in one repository, with any vulnerability reports attached
alongside. `bomify pull` restores it into another data directory. Any
OCI registry works.

## 1. Log in

Needed for pushes, and for pulls from private registries:

```sh
bomify login registry.example.com
echo "$REGISTRY_TOKEN" | bomify login registry.example.com -u myuser --password-stdin   # CI
```

Credentials are checked, then stored through bomify's own
`~/.bomify/conf/auth.json` (in the OS credential store when there is
one). Registries you haven't logged into with bomify fall back to your
`docker login` credentials.

!!! note "TLS only"
    bomify only uses HTTPS. Trust a self-signed certificate in the OS
    first, or use the throwaway registry in
    [`deploy/registry/`](https://github.com/alejandro-velasco/bomify/tree/main/deploy/registry).

## 2. Tag with the destination

`push` publishes under the package's local tag, so the tag must be a
full reference (`<registry>/<repository>:<tag>`):

```sh
bomify build sbom.json --tag registry.example.com/myapp:1.0
# or, for an existing package:
bomify tag myapp:1.0 registry.example.com/myapp:1.0
```

## 3. Push

```sh
bomify push registry.example.com/myapp:1.0 --concurrency 6
```

![bomify push uploading a signed package and tagging each component in its own repository](../assets/demo/push.gif)

Each component's plugin describes it in its registry format, so the
plugins that built the package must be installed (see
[installing plugins](../getting-started/installing-plugins.md)). Blobs the
registry already has are skipped, so a new version uploads only what
changed. To add a tag like `latest`, tag and push again; only
the tag is written.

```sh
bomify tag registry.example.com/myapp:1.0 registry.example.com/myapp:latest
bomify push registry.example.com/myapp:latest
```

## 4. Pull components with their own tools

Push also tags each component by name in a repository beside the
package's, `<repository>/<purl type>/<namespace>/<name>:<version>`, so
the tools that run it pull it directly. For a package with an image, a
chart, a model, and a file:

```sh
docker pull registry.example.com/myapp/oci/alpine:3.20
helm pull oci://registry.example.com/myapp/helm/podinfo --version 6.7.1
oras pull registry.example.com/myapp/huggingface/sshleifer/tiny-gpt2:<commit>   # or modctl
oras pull registry.example.com/myapp/generic/license:1.0                        # writes LICENSE
```

![helm pull, docker pull, and modctl pulling the chart, the image, and the model from the package's registry](../assets/demo/pull.gif)

A chart can be a dependency the same way: `repository:
oci://registry.example.com/myapp/helm`. Each is the same manifest the
package holds, its blobs stored once. `oras pull` writes a model's, or
any other component's, files out as `bomify build` pulled them. The
naming rules are in the
[registry format](../development/architecture/registry-format.md#component-repositories).
On a registry without nested repositories, push only the package with
`--skip-component-repositories`.

## 5. Inspect without pulling

```sh
bomify package manifest registry.example.com/myapp:1.0 | jq '.components[].purl'
```

The index (artifact type `application/vnd.bomify.package.v1+json`) also
works with generic tools. Copying it copies the whole package, though
not the components' own tags, and each component can be fetched from
the package's repository by its digest:

```sh
oras cp -r registry.example.com/myapp:1.0 mirror.example.com/myapp:1.0
oras manifest fetch registry.example.com/myapp:1.0 \
  | jq '.manifests[] | {purl: .annotations["land.bomify.purl"], tagged: .annotations["land.bomify.component.reference"], digest}'
docker pull registry.example.com/myapp@sha256:<an image component's digest>
```

## 6. Pull

```sh
bomify pull registry.example.com/myapp:1.0
bomify pull registry.example.com/myapp@sha256:abcdef...   # exact content, no local tag
```

This restores the SBOM, every component, and the newest vulnerability
reports, and records the tag, just as if the package had been built
there.

## Refreshing reports

Re-scan and push again to update a published package's reports:

```sh
bomify security scan grype registry.example.com/myapp:1.0
bomify push registry.example.com/myapp:1.0
```

The package digest, and any signature over it, don't change. Older
report referrers are deleted (`--keep-reports` sets how many stay).
Registries that refuse deletes, like GHCR, keep them; `pull` always uses
the newest, and `bomify security prune` retries the cleanup.
