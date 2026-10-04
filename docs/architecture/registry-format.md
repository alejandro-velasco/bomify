# Registry format

What bomify writes to an OCI registry, or to a `bomify save` tarball (an
OCI image layout), is what other tools, and older and newer bomify
releases, have to read. From bomify's last alpha release on, this format
is a public interface: it changes only as [Versioning](#versioning)
describes. [Push and pull](registry.md) covers how bomify reads and
writes it.

Everything below is an OCI 1.1 image manifest. bomify's own types and
annotations are named `application/vnd.bomify.*` and `land.bomify.*`.

## Package

The package is the one manifest a tag points at. Every other artifact is
a referrer of it, so none changes its digest.

| Part | Type | Holds |
| --- | --- | --- |
| Manifest | artifact type `application/vnd.bomify.package.v1+json` | Annotated `org.opencontainers.image.created` with the SBOM's `metadata.timestamp` in UTC (RFC 3339), or the Unix epoch without one, so pushing an unchanged package gives the same digest. |
| Config | `application/vnd.cyclonedx+json` or `application/vnd.cyclonedx+xml` | The package's CycloneDX SBOM, as `bomify build` assembled it. |
| Layers | `application/vnd.bomify.component.layer.v1.tar` | One per component with content: a tar of what `build` pulled for it, a single file or a directory tree. mtimes, uid, and gid are zeroed, so the digest depends only on names, modes, and content. Annotated `land.bomify.purl` (the component's purl) and `org.opencontainers.image.title` (`<purl hash>.tar`). |

## Referrers

Each referrer's `subject` is the package manifest. Those bomify builds
itself have an empty config (`application/vnd.oci.empty.v1+json`) and
an `org.opencontainers.image.created` annotation.

| Referrer | Artifact type | Layers | Pushed by |
| --- | --- | --- | --- |
| Vulnerability reports | `application/vnd.bomify.vulnerabilities.v1+json` | One `application/vnd.bomify.component.vulnerabilities.v1+json` per scanner per component: the CycloneDX report that scanner wrote. | `push`/`save`, from the local reports |
| VEX | `application/vnd.bomify.vex.v1+json` | Exactly one `application/vnd.bomify.vex.document.v1`: an OpenVEX, CSAF, or CycloneDX VEX document, told apart by content. One referrer per document. | `push`/`save --vex`, signed like the package |
| Signature | the signing plugin's (e.g. `application/vnd.dev.sigstore.bundle.v0.3+json`) | One: the plugin's envelope, of its media type. | `push`/`save --sign` |
| Provenance, signed | the signing plugin's | One: the plugin's DSSE envelope of the in-toto statement. | `push`/`save` of a package built with `--provenance`, when signing |
| Provenance, unsigned | `application/vnd.in-toto+json` | One `application/vnd.in-toto+json`: the in-toto statement. | the same, without signing |

A signed referrer takes the signing plugin's artifact and media types,
its ecosystem's standard ones, so that ecosystem's own tools (e.g.
`cosign`) find it; see the signing contract's
[`artifactType`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/signing/v1/CONTRACT.md).
bomify tells a provenance attestation apart by its
`land.bomify.attestation.predicateType` annotation instead.

The vulnerability reports referrer's `created` is its newest report's
time. A re-scan pushes a new one rather than changing the package, and a
pull restores only the newest.

## Annotations

| Annotation | On | Value |
| --- | --- | --- |
| `land.bomify.purl` | package layers, report layers | The component's purl. |
| `land.bomify.scan.plugin` | report layers, the reports referrer | On a layer, the scanner whose report it is; a pull restores it under that name. On the referrer, every scanner it carries reports of, sorted, comma-separated, informational only. |
| `land.bomify.signature.plugin` | signature and signed attestation referrers | The kind of signing plugin that made it. Informational. |
| `land.bomify.attestation.predicateType` | provenance referrers | The in-toto predicate type, `https://slsa.dev/provenance/v1`. Marks the referrer as an attestation, which signature verification skips. |
| `land.bomify.provenance.statement` | provenance referrers | The SHA-256 of the statement, so pushing the same provenance again attaches nothing new. |
| `org.opencontainers.image.created` | the package and bomify's referrers | See above; orders referrers, newest first. |
| `org.opencontainers.image.title` | package layers, report layers, VEX layers | A filename. A report's is its path under the data directory's `vulnerabilities/` (`<purl hash>/<scanner>.json`), so `oras pull` lays reports out as bomify keeps them. |

A signing plugin may add annotations of its own to its referrers.

## Plugin packages

A package `bomify plugin install` installs from is an ordinary package
whose SBOM describes each binary as a `pkg:bomify-plugin/<kind>@<version>`
component, with `os` and `arch` qualifiers in Go's `GOOS`/`GOARCH` terms.
Its `land.bomify.plugin.contracts` property holds the contract versions
the binary speaks, as its `contract` command prints them (e.g.
`{"component":1}`). See [Plugin installation](plugin-installation.md).

## Finding referrers

bomify lists a package's referrers with the registry's Referrers API.
Where the registry lacks it (e.g. ghcr.io), it falls back to the OCI
referrers tag schema: an index tagged `sha256-<package digest>` that
lists them, rewritten on every push of a referrer. bomify leaves the
superseded index untagged for the registry to collect, rather than
deleting it, since many such registries refuse deletes.

Either way, bomify filters by artifact type itself, since some registries
ignore the filter, and orders by `org.opencontainers.image.created`.
Referrers are untrusted: bomify reads at most 4 MiB of a referrer
manifest, VEX document, or signature envelope.

## Versioning

Each bomify media and artifact type carries a version (`v1`). A change
that a reader of the current version would misread, such as removing or
renaming an annotation or changing what a blob holds, gets a new version
(`v2`). Adding an optional annotation doesn't.

What this bomify does with a type it doesn't know:

- **Package:** pull doesn't check the manifest's artifact type, and
  reads its config as an SBOM.
- **Package layer** of another media type: written as-is, as a single
  file named by its title, rather than unpacked.
- **Reports and VEX referrers** of another artifact type, and their
  layers of another media type: ignored. A VEX referrer without exactly
  one VEX layer is skipped with a warning.
- **Signatures:** only referrers of an artifact type the signing plugin
  lists in `signature supported-types` are verified.
