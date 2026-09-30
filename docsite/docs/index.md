---
icon: lucide/package
title: bomify
---

<p align="center">
  <img src="assets/logo.svg" alt="bomify logo" width="360">
</p>

# Overview

`bomify` builds OCI packages from [CycloneDX](https://cyclonedx.org/)
SBOMs. It orchestrates; plugins (`bomify-plugin-<kind>`) do the
type-specific work of fetching, publishing, scanning, and signing.

It mirrors Docker and Podman:

- A **package** is built from an SBOM the way an image is built from a
  Dockerfile, and a **tag** names one.
- `bomify package` works much like `docker image`.
- Docker's **layers** are bomify's **components**, each pulled, cached,
  and reused independently by content hash.

!!! warning "Pre-alpha"

    Flags, the data directory layout, and the plugin contracts may change
    without notice.

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
