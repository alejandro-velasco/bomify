# bomify Roadmap

Possible directions for bomify, building on what it does today: it builds packages from CycloneDX SBOMs through plugins (oci, helm, generic), moves them with push/pull/save/load/distribute, generates SBOMs for Helm charts and scans for vulnerabilities with grype.

## 1. Supply-chain trust

- **Signing and verification:** sign the package's OCI artifact on `push` (Sigstore/cosign or Notation) and check the signature on `pull`/`load`. The SBOM is already the artifact's config blob, so this fits cleanly.
- **Hash checking on build:** SBOM components already carry `hashes`. A `--verify-hashes` flag could fail the build when pulled content doesn't match.
- **Provenance:** attach a SLSA-style record of how each package was built to its artifact in the registry.

## 2. Offline (air-gapped) delivery

`save`/`load` plus `distribute`, which already rewrites paths to point at mirrors, cover most of this.

- **Incremental tarballs:** `save --since <tag>` ships only the components that changed.
- **`bomify diff <tagA> <tagB>`:** show components added, removed or changed, and how vulnerabilities changed between the two.
- **Rewritten SBOM after `distribute`:** output an SBOM that points at the internal mirror.

## 3. Deeper security

- **VEX support:** read and write CycloneDX VEX statements so known false positives stay suppressed across scans.
- **CI gate:** `--fail-on high` on `security scan`, or a `bomify policy check` command, to block a build or push.
- **More scanners:** Trivy and OSV-Scanner plugins; the security plugin contract already supports this.
- **Scan a built package by tag**, not just an SBOM file.

## 4. More ecosystems through plugins

- **Component plugins:** npm, PyPI, Maven, Go modules, git, deb/rpm, S3 and Artifactory.
- **SBOM generation:** OCI images (via syft), Kustomize, Docker Compose and Terraform modules.
- **License compliance:** as a new plugin class or a built-in command.

## 5. Product and UX

- **Plugin management:** `bomify plugin install/list`, with plugins themselves distributed through OCI registries.
- **Ready-made CI pipeline:** a GitHub Action for generate → scan → build → sign → push.
- **SPDX conversion:** read and write SPDX as well as CycloneDX.
- **Deploying from packages:** a Kubernetes operator or Flux/Argo integration.
- **Versioned plugin contract:** so third-party plugins can rely on it before bomify leaves pre-alpha.

## Where to start

1. **Signing and verification**, because it builds directly on the existing registry format.
2. **CI gate plus VEX**, so grype results become something a pipeline can act on.
3. **`diff` and incremental save**, to sharpen the offline-delivery story.
