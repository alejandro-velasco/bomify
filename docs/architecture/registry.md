# Push and pull

[`internal/oci/push`](https://github.com/alejandro-velasco/bomify/tree/main/internal/oci/push) and
[`internal/oci/pull`](https://github.com/alejandro-velasco/bomify/tree/main/internal/oci/pull) store a package as an ordinary
OCI artifact (artifact type `application/vnd.bomify.package.v1+json`;
every type and annotation is listed in [Registry format](registry-format.md)):

![Bomify package to OCI artifact mapping](../diagrams/oci-artifact.svg)

*Source: [`docs/diagrams/oci-artifact.mmd`](https://github.com/alejandro-velasco/bomify/blob/main/docs/diagrams/oci-artifact.mmd)*

- The **config** is the SBOM (`application/vnd.cyclonedx+json` or
  `+xml`, sniffed).
- A component's **layers**, annotated `land.bomify.purl`, are tars of
  its files under `transfer.LargeFileSize` (64 MiB), and each larger
  file as one raw layer, its own bytes, so an unchanged large file is
  the same blob in every package, and uploads once. Only a file past
  `transfer.MaxLayerSize` (8 GiB) is split, into parts, so no layer
  outgrows a registry's limit. `transfer.WriteTar` zeroes mtimes and
  uid/gid, so a tar's digest depends only on names, modes, and content;
  otherwise re-pushing a component bomify had pulled would re-upload it.
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
which `save` hits when tags share a component. A part streams straight
from its file, read once to hash and once to upload, so a large file is
never copied; tars go through a temporary file.

`pull` restores a component from all its layers into a temporary
directory and swaps it into place only once every layer verifies (see
`pull.restoreComponent`). It checks the parts' annotations before
downloading anything, creates each large file at full size, then
unpacks the tars, refusing any entry naming a file that exists, and
writes each part at its offset.

`push` then publishes each component at its own repository beside the
package's (see `push.componentPublisher`, and
[Registry format](registry-format.md#component-repositories) for what's
published), unless `--skip-component-repositories`. A large file's layer
there is the package's own blob, re-uploaded, since registries don't
share blobs across repositories without a mount. Each artifact is signed
and tagged before the package's tag moves, so a failure leaves the
package's tag where it was.

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
exists, as `docker login` does. `login --verify=false` (`Save`) stores
one unverified instead, the same way, for a host that isn't an OCI
registry and so can't be checked: a Hugging Face hub
`bomify-plugin-huggingface` pulls from and pushes to, or an HTTPS server
`bomify-plugin-generic` downloads from. bomify exports the data
directory in use as `BOMIFY_DATA_DIR` to the plugins it runs, so
`pkg/auth` finds the same `auth.json` under `--data-dir`.
