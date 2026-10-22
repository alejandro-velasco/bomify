---
icon: lucide/package
title: bomify
---

<p align="center">
  <img src="assets/logo.svg" alt="bomify logo" width="360">
</p>

# Overview

`bomify` packages an entire platform (container images, Helm charts,
models, and files) as one signed, scanned OCI artifact, and delivers it
through any registry or air gap to the tools that deploy it.

It starts from a [CycloneDX](https://cyclonedx.org/) SBOM, the
platform's bill of materials, and pins every part by digest. The proof
travels with the package: signatures in cosign's format, vulnerability
reports with VEX, and SLSA provenance, all checked before a pull writes
anything. Each part is also tagged where its own tool expects it, so
`docker pull`, `helm pull`, and `modctl` fetch it directly.

![helm pull, docker pull, and modctl pulling the chart, the image, and the model from the package's registry](assets/demo/pull.gif)

bomify orchestrates; plugins (`bomify-plugin-<kind>`) do the
type-specific work of fetching, publishing, scanning, and signing.

If you know Docker or Podman:

- A **package** is built from an SBOM the way an image is built from a
  Dockerfile, and a **tag** names one.
- `bomify package` works much like `docker image`.
- Docker's **layers** are bomify's **components**, each pulled, cached,
  and reused independently by content hash.

!!! info "Beta"

    These are stable: the commands and their flags, the
    [registry format](development/architecture/registry-format.md), the
    [plugin contracts](getting-started/installing-plugins.md#contract-versions),
    and the [data directory](development/architecture/data-directory.md).
    They change only where they must, and the release notes call out any
    change that breaks what's built on them. Data and packages from alpha
    releases aren't guaranteed to carry over.

<div class="grid cards" markdown>

- :material-rocket-launch:{ .lg .middle } **New here?**

    ---

    Install bomify and its plugins, then build a package.

    [:octicons-arrow-right-24: Getting started](getting-started/index.md)

- :material-console:{ .lg .middle } **Looking for a flag?**

    ---

    The reference for every command.

    [:octicons-arrow-right-24: Usage](usage/index.md)

- :material-puzzle-outline:{ .lg .middle } **Building a plugin?**

    ---

    Extend bomify with your own plugin.

    [:octicons-arrow-right-24: Building a plugin](development/building-a-plugin.md)

</div>
