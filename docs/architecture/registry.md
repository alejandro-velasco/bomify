# Push and pull

[`internal/oci/push`](https://github.com/alejandro-velasco/bomify/tree/main/internal/oci/push) and
[`internal/oci/pull`](https://github.com/alejandro-velasco/bomify/tree/main/internal/oci/pull) store a package as an ordinary
OCI artifact (artifact type `application/vnd.bomify.package.v1+json`;
every type and annotation is listed in [Registry format](registry-format.md)):

![Bomify package to OCI artifact mapping](../diagrams/oci-artifact.svg)

*Source: [`docs/diagrams/oci-artifact.mmd`](https://github.com/alejandro-velasco/bomify/blob/main/docs/diagrams/oci-artifact.mmd)*

- The **config** is the SBOM (`application/vnd.cyclonedx+json` or
  `+xml`, sniffed).
- Each **layer** is a tar of a component's layer directory, annotated
  `land.bomify.purl`. `transfer.WriteTar` zeroes mtimes and uid/gid, so
  the digest depends only on names, modes, and content; otherwise
  re-pushing a component bomify had pulled would re-upload it.
- **Signatures**, the **report referrer**, **VEX referrers**, and the
  **provenance attestation** (see [Build provenance](provenance.md)) are
  OCI referrers, so none changes the package digest.

![Package layout in a registry](../diagrams/registry-layout.svg)

*Source: [`docs/diagrams/registry-layout.mmd`](https://github.com/alejandro-velasco/bomify/blob/main/docs/diagrams/registry-layout.mmd)*

![Signature referrers in a registry](../diagrams/registry-signatures.svg)

*Source: [`docs/diagrams/registry-signatures.mmd`](https://github.com/alejandro-velasco/bomify/blob/main/docs/diagrams/registry-signatures.mmd)*

Layers transfer concurrently (`--concurrency`), each verified against
its digest and size as it streams, with a progress bar per blob. `push`
skips blobs the target already has. That's required, not an
optimization: a local `content/oci.Store` rejects re-pushing a digest,
which `save` hits when tags share a component.

## Save and load

`bomify save`/`load` ([`internal/oci/save`](https://github.com/alejandro-velasco/bomify/tree/main/internal/oci/save)) run
`push`/`pull` unchanged against a local OCI image layout instead of a
registry, then tar or untar it. Shared components are stored once, and
signatures and report referrers travel inside the tarball, so `load`
verifies and restores exactly as `pull` does.

![Save and load flow](../diagrams/save-load.svg)

*Source: [`docs/diagrams/save-load.mmd`](https://github.com/alejandro-velasco/bomify/blob/main/docs/diagrams/save-load.mmd)*

## Credentials

[`internal/auth`](https://github.com/alejandro-velasco/bomify/tree/main/internal/auth) is the one source of registry
credentials, for `login`/`logout`, `push`/`pull`, and plugins through
[`pkg/auth`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/auth). `login`/`logout` write only
`<dataDir>/conf/auth.json`, a Docker-format config backed by the native
credential store as Docker's is. Reads try it first, then Docker's own
`config.json`, so an existing `docker login` still works and `bomify
logout` never removes it. Native helpers key secrets by host alone, so
both tools share one secret for a host logged into with both.

`Login` verifies a credential before storing it, and falls back to
plaintext in `auth.json` (with a warning) only when no credential helper
exists, as `docker login` does. bomify exports the data directory in use
as `BOMIFY_DATA_DIR` to the plugins it runs, so `pkg/auth` finds the
same `auth.json` under `--data-dir`.
