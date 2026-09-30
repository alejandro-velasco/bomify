# Architecture

How bomify works internally, for anyone changing it. For using the CLI,
see the [README](https://github.com/alejandro-velasco/bomify/blob/main/README.md) and [`docs/reference`](https://github.com/alejandro-velasco/bomify/tree/main/docs/reference).

## Mental model

bomify mirrors Docker: a **package** is built from a CycloneDX SBOM the
way an image is built from a Dockerfile, a **tag** names one, and
`packages`/`tag`/`package rm`/`save`/`load` map onto
`images`/`tag`/`rmi`/`save`/`load`. Docker's layers are bomify's
**components**, each pulled, cached, and reused independently by
content hash.

bomify only orchestrates. Fetching, publishing, scanning, and signing
are done by external `bomify-plugin-<kind>` binaries.

## Contents

- [Data directory](data-directory.md): the on-disk layout and
  how everything in it is keyed.
- [Plugins](plugins.md): the four plugin contracts, component
  dispatch, SBOM generation, and concurrent pulls.
- [Security scanning](security-scanning.md): scans, gating,
  VEX, scanning on pull, and reports and VEX in a registry.
- [Signing and verification](signing.md).
- [Build provenance](provenance.md): SLSA provenance, recorded by `build`
  and attached as an in-toto attestation.
- [Plugin installation](plugin-installation.md), and how
  releases publish and sign the first-party plugins.
- [Builds and tagging](builds.md), and pruning.
- [Push and pull](registry.md): the OCI artifact format,
  save/load, and credentials.

Diagrams are rendered from the Mermaid sources in
[`docs/diagrams`](https://github.com/alejandro-velasco/bomify/tree/main/docs/diagrams); after editing a `.mmd`, run `make
diagrams`.

## Design principles

- **Content-addressing everywhere.** Paths are keyed by SBOM hash, purl
  hash, or digest, so the path is the cache key. That makes builds,
  pulls, and pushes idempotent and safe to run concurrently without a
  lock file or database.
- **Atomic writes.** A final path appears only once its content is
  complete and verified, so a missing path always means "not done yet".
- **bomify orchestrates, plugins do the work.** The core has no
  ecosystem-specific code. Each plugin contract is kept minimal. bomify
  owns everything around it: dispatch, concurrency, caching, reports,
  referrers, and trust policy.
